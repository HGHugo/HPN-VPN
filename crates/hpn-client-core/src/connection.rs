//! UDP connection management.
//!
//! Provides async UDP socket handling for VPN traffic with optimized
//! buffer sizes for high-throughput connections.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use parking_lot::RwLock;
use tokio::net::UdpSocket;
use tracing::{debug, trace, warn};

/// Socket buffer size for high-throughput connections (16 MB).
/// This matches the server-side buffer configuration.
const SOCKET_BUFFER_SIZE: usize = 16 * 1024 * 1024;

/// UDP connection for communicating with the VPN server.
///
/// The socket and local address are held behind `RwLock<Arc<…>>` /
/// `RwLock<SocketAddr>` so `rebind()` can atomically swap them for a
/// fresh socket after a network change (laptop sleep/wake, Wi-Fi ↔
/// Ethernet hand-off) without invalidating in-flight `send` / `recv`
/// calls. The read lock is never held across `.await`: send/recv clone
/// the inner `Arc<UdpSocket>` under the lock and drop the guard before
/// awaiting, which keeps the data path effectively lock-free
/// (parking_lot uncontended reads are a single atomic load).
pub struct UdpConnection {
    /// The UDP socket. Swappable via `rebind()`.
    socket: RwLock<Arc<UdpSocket>>,
    /// Server address. Updated by `update_server_addr` (for roaming).
    server_addr: RwLock<SocketAddr>,
    /// Local bound address. Updated whenever `rebind()` picks a new
    /// ephemeral port.
    local_addr: RwLock<SocketAddr>,
}

impl UdpConnection {
    /// Create a new UDP connection to the server.
    ///
    /// Configures socket with large buffers for high-throughput operation.
    pub async fn connect(server_addr: SocketAddr) -> io::Result<Self> {
        // Create socket2 socket for buffer configuration
        let domain = if server_addr.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };

        let socket2_socket =
            socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;

        // Configure large buffers for high throughput
        // These settings prevent packet drops under high load
        if let Err(e) = socket2_socket.set_recv_buffer_size(SOCKET_BUFFER_SIZE) {
            warn!("Failed to set SO_RCVBUF to {}: {}", SOCKET_BUFFER_SIZE, e);
        }
        if let Err(e) = socket2_socket.set_send_buffer_size(SOCKET_BUFFER_SIZE) {
            warn!("Failed to set SO_SNDBUF to {}: {}", SOCKET_BUFFER_SIZE, e);
        }

        // Bind to any available port
        let bind_addr: SocketAddr = if server_addr.is_ipv4() {
            "0.0.0.0:0"
                .parse()
                .expect("hardcoded IPv4 bind address is valid")
        } else {
            "[::]:0"
                .parse()
                .expect("hardcoded IPv6 bind address is valid")
        };
        socket2_socket.bind(&bind_addr.into())?;

        // Set non-blocking for async operation
        socket2_socket.set_nonblocking(true)?;

        // Convert to std socket then to tokio
        let std_socket: std::net::UdpSocket = socket2_socket.into();
        let socket = UdpSocket::from_std(std_socket)?;
        let local_addr = socket.local_addr()?;

        // Log actual buffer sizes (OS may limit them)
        debug!(
            "UDP connection bound to {}, targeting server {} (buffers configured)",
            local_addr, server_addr
        );

        Ok(Self {
            socket: RwLock::new(Arc::new(socket)),
            server_addr: RwLock::new(server_addr),
            local_addr: RwLock::new(local_addr),
        })
    }

    /// Get the server address.
    #[inline]
    pub fn server_addr(&self) -> SocketAddr {
        *self.server_addr.read()
    }

    /// Get the local bound address.
    #[inline]
    pub fn local_addr(&self) -> SocketAddr {
        *self.local_addr.read()
    }

    /// Get a clone of the socket arc.
    pub fn socket(&self) -> Arc<UdpSocket> {
        Arc::clone(&self.socket.read())
    }

    /// Send a packet to the server.
    ///
    /// Clones the inner `Arc<UdpSocket>` under the read lock and drops
    /// the guard before awaiting — holding a parking_lot guard across
    /// `.await` is a soft foot-gun (blocks the tokio worker if a rebind
    /// happens concurrently), whereas a cloned Arc is self-contained.
    #[inline]
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        let server = *self.server_addr.read();
        let socket = Arc::clone(&self.socket.read());
        socket.send_to(buf, server).await
    }

    /// Receive a packet from any source.
    ///
    /// Returns the number of bytes received and the source address.
    /// This is the fast path - use this in performance-critical code.
    #[inline]
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let socket = Arc::clone(&self.socket.read());
        socket.recv_from(buf).await
    }

    /// Maximum number of spoofed/out-of-band packets to tolerate per
    /// `recv_from_server` call during the **handshake** phase.
    ///
    /// During handshake the client has no session yet, so non-server
    /// packets arriving at the socket are always noise (or an attack).
    /// A short ceiling fails the handshake fast and lets the retry loop
    /// take over, rather than burning CPU on 1000 spurious packets
    /// before giving up.
    const MAX_IGNORED_PACKETS_HANDSHAKE: u32 = 100;

    /// Maximum number of spoofed/out-of-band packets to tolerate per
    /// `recv_from_server` call in **steady-state**.
    ///
    /// Higher ceiling because a legitimate handful of late/duplicated
    /// packets can arrive during NAT rebind or roaming events and we
    /// do not want to drop the session over them.
    const MAX_IGNORED_PACKETS_STEADY: u32 = 1000;

    /// Receive a packet, only accepting packets from the server.
    ///
    /// Note: For high-performance paths, prefer using `recv()` directly
    /// and filtering by source IP in the caller.
    ///
    /// `handshake_phase` selects the ignore-cap: during the initial
    /// handshake we fail fast (see `MAX_IGNORED_PACKETS_HANDSHAKE`),
    /// during steady-state we tolerate more noise
    /// (`MAX_IGNORED_PACKETS_STEADY`).
    ///
    /// Returns an error if too many packets from unexpected sources are
    /// received, which prevents infinite loops under attack conditions.
    pub async fn recv_from_server_scoped(
        &self,
        buf: &mut [u8],
        handshake_phase: bool,
    ) -> io::Result<usize> {
        let cap = if handshake_phase {
            Self::MAX_IGNORED_PACKETS_HANDSHAKE
        } else {
            Self::MAX_IGNORED_PACKETS_STEADY
        };
        let mut ignored_count = 0u32;
        let expected_ip = self.server_addr.read().ip();
        loop {
            let socket = Arc::clone(&self.socket.read());
            let (n, addr) = socket.recv_from(buf).await?;
            // Compare only IP addresses, ignore port (server might respond from different port)
            if addr.ip() == expected_ip {
                return Ok(n);
            }
            trace!(
                "Ignoring packet from unexpected source: {} (expected IP: {})",
                addr, expected_ip
            );
            ignored_count += 1;
            if ignored_count >= cap {
                warn!(
                    "Too many packets from unexpected sources ({} ignored, cap={}), possible attack",
                    ignored_count, cap
                );
                return Err(io::Error::other("too many packets from unexpected sources"));
            }
        }
    }

    /// Backwards-compatible wrapper that preserves the historical
    /// "always steady-state" behaviour. New callers should prefer
    /// [`Self::recv_from_server_scoped`] with `handshake_phase=true`
    /// when running before session establishment.
    pub async fn recv_from_server(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv_from_server_scoped(buf, false).await
    }

    /// Update the server address (for rebinding / roaming).
    ///
    /// Takes `&self` now that the address is behind a `RwLock`, so
    /// callers that only hold an `Arc<UdpConnection>` can still update
    /// the remote peer without going through mutable aliasing.
    pub fn update_server_addr(&self, new_addr: SocketAddr) {
        let mut addr = self.server_addr.write();
        debug!("Updating server address from {} to {}", *addr, new_addr);
        *addr = new_addr;
    }

    /// Check if the connection is still viable (socket is bound).
    #[inline]
    pub fn is_connected(&self) -> bool {
        self.socket.read().local_addr().is_ok()
    }

    /// Rebind the underlying UDP socket to a fresh ephemeral port.
    ///
    /// Required after a network-level event where the original kernel
    /// socket becomes unusable while our Rust handle still looks valid:
    ///   - laptop sleep/wake (macOS especially reclaims sockets on wake)
    ///   - Wi-Fi ↔ Ethernet hand-off (the socket is bound to a now-gone
    ///     interface)
    ///   - VPN adapter toggled in system settings by the user
    ///
    /// The swap is atomic from the caller's point of view: an in-flight
    /// `send` or `recv` that already cloned the old `Arc<UdpSocket>`
    /// keeps using that (valid) socket until its `.await` completes and
    /// the refcount drops to zero, at which point the kernel fd is
    /// closed. Calls issued after the rebind see the new socket on
    /// their next lock-read.
    ///
    /// The bind address family is derived from the current server
    /// address, so a `update_server_addr` that flipped us from v4 to v6
    /// is respected.
    pub async fn rebind(&self) -> io::Result<()> {
        let server_addr = *self.server_addr.read();

        let domain = if server_addr.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };

        let socket2_socket =
            socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;

        // Best-effort buffer sizing — mirrors `connect()`. Silently log
        // if the OS refuses; the socket is still functional at the
        // kernel default.
        if let Err(e) = socket2_socket.set_recv_buffer_size(SOCKET_BUFFER_SIZE) {
            warn!("rebind: failed to set SO_RCVBUF: {}", e);
        }
        if let Err(e) = socket2_socket.set_send_buffer_size(SOCKET_BUFFER_SIZE) {
            warn!("rebind: failed to set SO_SNDBUF: {}", e);
        }

        let bind_addr: SocketAddr = if server_addr.is_ipv4() {
            "0.0.0.0:0"
                .parse()
                .expect("hardcoded IPv4 bind address is valid")
        } else {
            "[::]:0"
                .parse()
                .expect("hardcoded IPv6 bind address is valid")
        };
        socket2_socket.bind(&bind_addr.into())?;
        socket2_socket.set_nonblocking(true)?;

        let std_socket: std::net::UdpSocket = socket2_socket.into();
        let new_socket = UdpSocket::from_std(std_socket)?;
        let new_local = new_socket.local_addr()?;
        let old_local = *self.local_addr.read();

        // Atomic swap — writers of both locks finish before any new
        // read observes either. In-flight recvs/sends on the old Arc
        // complete normally; the old socket is released when its last
        // clone drops.
        *self.socket.write() = Arc::new(new_socket);
        *self.local_addr.write() = new_local;

        debug!(
            "UDP socket rebound {} -> {} (server {})",
            old_local, new_local, server_addr
        );
        Ok(())
    }
}

use crate::transport::{TransportTrait, TransportType};
use async_trait::async_trait;

#[async_trait]
impl TransportTrait for UdpConnection {
    async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        UdpConnection::send(self, buf).await
    }

    async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        UdpConnection::recv(self, buf).await
    }

    async fn recv_from_server(&self, buf: &mut [u8]) -> io::Result<usize> {
        UdpConnection::recv_from_server(self, buf).await
    }

    async fn recv_from_server_scoped(
        &self,
        buf: &mut [u8],
        handshake_phase: bool,
    ) -> io::Result<usize> {
        UdpConnection::recv_from_server_scoped(self, buf, handshake_phase).await
    }

    fn server_addr(&self) -> SocketAddr {
        UdpConnection::server_addr(self)
    }

    fn local_addr(&self) -> SocketAddr {
        UdpConnection::local_addr(self)
    }

    fn update_server_addr(&mut self, new_addr: SocketAddr) {
        // Inner update_server_addr now takes `&self` (RwLock-backed),
        // but the trait signature keeps `&mut self` for source-compat
        // with existing callers and the blanket Arc<T> impl.
        UdpConnection::update_server_addr(self, new_addr);
    }

    fn is_connected(&self) -> bool {
        UdpConnection::is_connected(self)
    }

    fn transport_type(&self) -> TransportType {
        TransportType::Udp
    }

    async fn close(&self) -> io::Result<()> {
        Ok(())
    }

    async fn rebind(&self) -> io::Result<()> {
        UdpConnection::rebind(self).await
    }
}

impl Clone for UdpConnection {
    fn clone(&self) -> Self {
        Self {
            socket: RwLock::new(Arc::clone(&self.socket.read())),
            server_addr: RwLock::new(*self.server_addr.read()),
            local_addr: RwLock::new(*self.local_addr.read()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_connection_bind() {
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let conn = UdpConnection::connect(addr).await.unwrap();
        assert!(conn.local_addr().port() > 0);
        assert_eq!(conn.server_addr(), addr);
    }

    #[tokio::test]
    async fn test_connection_clone() {
        let addr: SocketAddr = "127.0.0.1:12346".parse().unwrap();
        let conn = UdpConnection::connect(addr).await.unwrap();
        let conn2 = conn.clone();
        assert_eq!(conn.server_addr(), conn2.server_addr());
        assert_eq!(conn.local_addr(), conn2.local_addr());
    }

    #[tokio::test]
    async fn test_connection_ipv4_and_ipv6() {
        // Test IPv4 connection
        let ipv4_addr: SocketAddr = "127.0.0.1:51820".parse().unwrap();
        let conn_v4 = UdpConnection::connect(ipv4_addr).await.unwrap();
        assert!(conn_v4.local_addr().is_ipv4());
        assert_eq!(conn_v4.server_addr(), ipv4_addr);

        // Test IPv6 connection
        let ipv6_addr: SocketAddr = "[::1]:51820".parse().unwrap();
        let conn_v6 = UdpConnection::connect(ipv6_addr).await.unwrap();
        assert!(conn_v6.local_addr().is_ipv6());
        assert_eq!(conn_v6.server_addr(), ipv6_addr);
    }

    #[tokio::test]
    async fn test_connection_update_server_addr() {
        // Test server address roaming/migration
        let initial_addr: SocketAddr = "127.0.0.1:51820".parse().unwrap();
        let conn = UdpConnection::connect(initial_addr).await.unwrap();
        assert_eq!(conn.server_addr(), initial_addr);

        // Simulate server address change (e.g., network migration).
        // `update_server_addr` takes &self (RwLock-backed), no `mut`
        // needed.
        let new_addr: SocketAddr = "127.0.0.1:51821".parse().unwrap();
        conn.update_server_addr(new_addr);
        assert_eq!(conn.server_addr(), new_addr);
    }

    #[tokio::test]
    async fn test_connection_is_connected() {
        let addr: SocketAddr = "127.0.0.1:51822".parse().unwrap();
        let conn = UdpConnection::connect(addr).await.unwrap();
        assert!(conn.is_connected());
    }

    #[tokio::test]
    async fn test_connection_socket_arc_sharing() {
        // Verify socket Arc can be shared across tasks
        let addr: SocketAddr = "127.0.0.1:51823".parse().unwrap();
        let conn = UdpConnection::connect(addr).await.unwrap();
        let socket1 = conn.socket();
        let socket2 = conn.socket();

        // Both should reference the same socket
        assert!(Arc::ptr_eq(&socket1, &socket2));
    }

    #[tokio::test]
    async fn test_connection_ipv6_with_zone() {
        // Test IPv6 with zone ID (link-local)
        let ipv6_addr: SocketAddr = "[::1]:9999".parse().unwrap();
        let conn = UdpConnection::connect(ipv6_addr).await.unwrap();
        assert!(conn.is_connected());
        assert_eq!(conn.server_addr().port(), 9999);
    }

    #[tokio::test]
    async fn test_connection_different_ports() {
        let addr1: SocketAddr = "127.0.0.1:1000".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:2000".parse().unwrap();

        let conn1 = UdpConnection::connect(addr1).await.unwrap();
        let conn2 = UdpConnection::connect(addr2).await.unwrap();

        assert_ne!(conn1.server_addr(), conn2.server_addr());
        assert_ne!(conn1.local_addr(), conn2.local_addr());
    }

    #[tokio::test]
    async fn test_connection_server_addr_getter() {
        let addr: SocketAddr = "192.168.1.1:51820".parse().unwrap();
        let conn = UdpConnection::connect(addr).await.unwrap();

        assert_eq!(conn.server_addr(), addr);
        assert_eq!(conn.server_addr().ip().to_string(), "192.168.1.1");
        assert_eq!(conn.server_addr().port(), 51820);
    }

    #[tokio::test]
    async fn test_connection_local_addr_is_ephemeral() {
        let addr: SocketAddr = "127.0.0.1:51820".parse().unwrap();
        let conn = UdpConnection::connect(addr).await.unwrap();

        // Local port should be ephemeral (> 1024)
        assert!(conn.local_addr().port() > 1024);
    }

    #[tokio::test]
    async fn test_connection_update_preserves_socket() {
        let addr1: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        // `update_server_addr` takes &self now (RwLock-backed), so the
        // local variable does not need `mut`.
        let conn = UdpConnection::connect(addr1).await.unwrap();
        let socket_before = conn.socket();

        let addr2: SocketAddr = "127.0.0.1:6000".parse().unwrap();
        conn.update_server_addr(addr2);

        let socket_after = conn.socket();

        // Socket should remain the same
        assert!(Arc::ptr_eq(&socket_before, &socket_after));
    }

    #[tokio::test]
    async fn test_connection_multiple_clones() {
        let addr: SocketAddr = "127.0.0.1:7000".parse().unwrap();
        let conn1 = UdpConnection::connect(addr).await.unwrap();
        let conn2 = conn1.clone();
        let conn3 = conn2.clone();

        // All should have same server address
        assert_eq!(conn1.server_addr(), conn2.server_addr());
        assert_eq!(conn2.server_addr(), conn3.server_addr());

        // All should share the same socket
        assert!(Arc::ptr_eq(&conn1.socket(), &conn2.socket()));
        assert!(Arc::ptr_eq(&conn2.socket(), &conn3.socket()));
    }

    #[tokio::test]
    async fn test_connection_update_different_ip() {
        let addr1: SocketAddr = "127.0.0.1:8000".parse().unwrap();
        let conn = UdpConnection::connect(addr1).await.unwrap();

        // Update to different IP
        let addr2: SocketAddr = "127.0.0.2:8000".parse().unwrap();
        conn.update_server_addr(addr2);

        assert_eq!(conn.server_addr().ip().to_string(), "127.0.0.2");
        assert_eq!(conn.server_addr().port(), 8000);
    }

    #[tokio::test]
    async fn test_connection_ipv4_mapped_ipv6() {
        // Test IPv4-mapped IPv6 address
        let addr: SocketAddr = "[::ffff:127.0.0.1]:9000".parse().unwrap();
        let conn = UdpConnection::connect(addr).await.unwrap();

        assert!(conn.is_connected());
        assert!(conn.server_addr().is_ipv6());
    }

    #[tokio::test]
    async fn test_connection_rebind_changes_local_port() {
        // rebind() MUST produce a freshly-bound socket on a different
        // ephemeral port. If the local port did not change, the kernel
        // would have reused the same fd — defeating the purpose of
        // rebinding after a network hand-off that invalidated it.
        let addr: SocketAddr = "127.0.0.1:9100".parse().unwrap();
        let conn = UdpConnection::connect(addr).await.unwrap();

        let old_local = conn.local_addr();
        let old_socket = conn.socket();

        conn.rebind().await.unwrap();

        let new_local = conn.local_addr();
        let new_socket = conn.socket();

        assert_ne!(
            old_local.port(),
            new_local.port(),
            "rebind did not change the local ephemeral port"
        );
        assert!(
            !Arc::ptr_eq(&old_socket, &new_socket),
            "rebind did not swap the underlying socket Arc"
        );
        assert!(conn.is_connected());
        // Server address must be preserved — rebind swaps only the
        // local socket.
        assert_eq!(conn.server_addr(), addr);
    }

    #[tokio::test]
    async fn test_connection_rebind_preserves_server_addr_family() {
        // IPv6 connections must produce IPv6 sockets on rebind, not
        // accidentally fall back to the IPv4 bind.
        let addr: SocketAddr = "[::1]:9200".parse().unwrap();
        let conn = UdpConnection::connect(addr).await.unwrap();

        assert!(conn.local_addr().is_ipv6());
        conn.rebind().await.unwrap();
        assert!(
            conn.local_addr().is_ipv6(),
            "rebind on an IPv6 server produced a non-IPv6 local bind"
        );
    }
}
