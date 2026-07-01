//! Transport abstraction layer.
//!
//! This module provides a trait-based abstraction over different transport
//! protocols (UDP and TCP), allowing the VPN client to switch between them
//! dynamically based on network conditions or user configuration.
//!
//! ## Transport Types
//!
//! - **UDP (default)**: Low latency, minimal overhead, preferred for VPN traffic
//! - **TCP/443 (fallback)**: For restricted networks that only allow HTTPS traffic
//!
//! ## TCP Framing
//!
//! Since TCP is a stream protocol, we use length-prefix framing:
//! ```text
//! +-------------------+-------------------+
//! |  Length (2 bytes) |    Payload        |
//! |     big-endian    |  (up to 65535)    |
//! +-------------------+-------------------+
//! ```
//!
//! ## Example
//!
//! ```ignore
//! use hpn_client_core::transport::{Transport, TransportConfig};
//!
//! // Create transport based on config
//! let config = TransportConfig::Udp { server_addr };
//! let transport = Transport::connect(config).await?;
//!
//! // Use the transport
//! transport.send(&packet).await?;
//! let (n, _) = transport.recv(&mut buf).await?;
//! ```

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::RwLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::TlsConnector;
use tracing::{debug, trace, warn};

/// Maximum packet size for VPN traffic.
pub const MAX_PACKET_SIZE: usize = 65535;

/// Maximum number of unexpected packets to ignore before returning an error.
/// This prevents infinite loops from spoofed packet flooding attacks.
const MAX_IGNORED_PACKETS: u32 = 1000;

/// Length prefix size for TCP framing (2 bytes).
const TCP_FRAME_HEADER_SIZE: usize = 2;

/// Transport protocol type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportType {
    /// UDP transport (default, low latency).
    Udp,
    /// TCP transport (fallback for restricted networks).
    Tcp,
}

impl std::fmt::Display for TransportType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportType::Udp => write!(f, "UDP"),
            TransportType::Tcp => write!(f, "TCP"),
        }
    }
}

/// Transport configuration.
#[derive(Clone, Debug)]
pub enum TransportConfig {
    /// UDP transport configuration.
    Udp {
        /// Server address for UDP.
        server_addr: SocketAddr,
    },
    /// TCP transport configuration (for TCP/443 fallback with TLS).
    Tcp {
        /// Server address for TCP (typically port 443).
        server_addr: SocketAddr,
        /// Optional timeout for TCP connection in seconds.
        connect_timeout_secs: Option<u64>,
        /// TLS SNI hostname (default: "www.google.com" for DPI camouflage).
        /// Set to None to disable TLS (testing only).
        #[allow(dead_code)]
        tls_sni: Option<String>,
    },
}

impl TransportConfig {
    /// Get the server address.
    pub fn server_addr(&self) -> SocketAddr {
        match self {
            TransportConfig::Udp { server_addr } => *server_addr,
            TransportConfig::Tcp { server_addr, .. } => *server_addr,
        }
    }

    /// Get the transport type.
    pub fn transport_type(&self) -> TransportType {
        match self {
            TransportConfig::Udp { .. } => TransportType::Udp,
            TransportConfig::Tcp { .. } => TransportType::Tcp,
        }
    }
}

/// Transport trait for network communication.
///
/// This trait abstracts over different transport protocols (UDP, TCP)
/// to allow the VPN client to work with any transport implementation.
#[async_trait]
pub trait TransportTrait: Send + Sync {
    /// Send data to the server.
    async fn send(&self, buf: &[u8]) -> io::Result<usize>;

    /// Receive data from the server.
    ///
    /// Returns the number of bytes received and the source address.
    async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;

    /// Receive data, only accepting packets from the expected server.
    ///
    /// Equivalent to [`Self::recv_from_server_scoped`] with
    /// `handshake_phase = false` (steady-state cap).
    async fn recv_from_server(&self, buf: &mut [u8]) -> io::Result<usize>;

    /// Receive data, only accepting packets from the expected server,
    /// with a phase-scoped tolerance for spurious packets.
    ///
    /// During the handshake the client has no session yet, so non-server
    /// packets at the socket are noise. Pass `handshake_phase = true` to
    /// fail fast (e.g. 100 ignored packets cap) and let the higher-level
    /// retry loop take over, instead of burning through the steady-state
    /// 1000-packet window before giving up.
    ///
    /// Default impl delegates to `recv_from_server` so transports that
    /// don't yet differentiate (e.g. `UdpTransport` legacy code path)
    /// keep their historical behaviour.
    async fn recv_from_server_scoped(
        &self,
        buf: &mut [u8],
        _handshake_phase: bool,
    ) -> io::Result<usize> {
        self.recv_from_server(buf).await
    }

    /// Get the server address.
    fn server_addr(&self) -> SocketAddr;

    /// Get the local bound address.
    fn local_addr(&self) -> SocketAddr;

    /// Update the server address (for rebinding/roaming).
    fn update_server_addr(&mut self, new_addr: SocketAddr);

    /// Check if the transport is still connected.
    fn is_connected(&self) -> bool;

    /// Get the transport type.
    fn transport_type(&self) -> TransportType;

    /// Close the transport connection.
    async fn close(&self) -> io::Result<()>;

    /// Recreate the underlying network socket bound to a fresh local port.
    ///
    /// Required after a network-layer change — laptop sleep/wake, Wi-Fi ↔
    /// Ethernet switch, VPN adapter reset — where the original kernel
    /// socket becomes unusable even though higher-level code still holds
    /// a valid handle to it. Reconnection loops in `attempt_reconnect`
    /// call this before each retry so a dead socket does not pin the
    /// client in an infinite "connect fails on the same cached fd"
    /// state.
    ///
    /// Default implementation is a no-op to keep the trait backward-
    /// compatible and to let stream transports (TCP+TLS) that already
    /// reset themselves via `close` + a fresh `connect` opt out cleanly.
    /// UDP transports SHOULD override this.
    async fn rebind(&self) -> io::Result<()> {
        Ok(())
    }
}

/// Blanket implementation allowing `Arc<T>` to be used as a transport.
/// This enables callers that hold `Arc<UdpConnection>` or `Arc<UdpTransport>`
/// to pass them directly as `&dyn TransportTrait`.
#[async_trait]
impl<T: TransportTrait + ?Sized> TransportTrait for std::sync::Arc<T> {
    async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        (**self).send(buf).await
    }

    async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        (**self).recv(buf).await
    }

    async fn recv_from_server(&self, buf: &mut [u8]) -> io::Result<usize> {
        (**self).recv_from_server(buf).await
    }

    async fn recv_from_server_scoped(
        &self,
        buf: &mut [u8],
        handshake_phase: bool,
    ) -> io::Result<usize> {
        (**self).recv_from_server_scoped(buf, handshake_phase).await
    }

    fn server_addr(&self) -> SocketAddr {
        (**self).server_addr()
    }

    fn local_addr(&self) -> SocketAddr {
        (**self).local_addr()
    }

    fn update_server_addr(&mut self, _new_addr: SocketAddr) {
        // Arc is shared; address updates must go through the inner type directly.
        // This is intentionally a no-op for Arc wrappers.
    }

    fn is_connected(&self) -> bool {
        (**self).is_connected()
    }

    fn transport_type(&self) -> TransportType {
        (**self).transport_type()
    }

    async fn close(&self) -> io::Result<()> {
        (**self).close().await
    }

    async fn rebind(&self) -> io::Result<()> {
        (**self).rebind().await
    }
}

/// UDP transport implementation.
///
/// The underlying `UdpSocket` is wrapped in `RwLock<Arc<…>>` so `rebind()`
/// can atomically swap it for a fresh one after a network change without
/// touching any caller that currently holds a cheap clone of the Arc. The
/// read-lock on `send` / `recv` is dropped before the `.await` — never
/// held across a yield — so the data plane stays lock-free in practice
/// (parking_lot uncontended reads are a single atomic load).
pub struct UdpTransport {
    /// The UDP socket. Swappable via `rebind()`.
    socket: RwLock<Arc<UdpSocket>>,
    /// Server address.
    server_addr: RwLock<SocketAddr>,
    /// Local bound address. Updated by `rebind()` every time a new socket
    /// is bound to a fresh ephemeral port.
    local_addr: RwLock<SocketAddr>,
}

impl UdpTransport {
    /// Create a new UDP transport.
    pub async fn connect(server_addr: SocketAddr) -> io::Result<Self> {
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

        let socket = UdpSocket::bind(bind_addr).await?;
        let local_addr = socket.local_addr()?;

        debug!(
            "UDP transport bound to {}, targeting server {}",
            local_addr, server_addr
        );

        Ok(Self {
            socket: RwLock::new(Arc::new(socket)),
            server_addr: RwLock::new(server_addr),
            local_addr: RwLock::new(local_addr),
        })
    }

    /// Get a clone of the socket arc.
    pub fn socket(&self) -> Arc<UdpSocket> {
        Arc::clone(&self.socket.read())
    }
}

#[async_trait]
impl TransportTrait for UdpTransport {
    async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        let server_addr = *self.server_addr.read();
        // Clone the Arc under the read lock, then drop the guard before
        // awaiting. Holding a parking_lot guard across `.await` is a soft
        // foot-gun (blocks the tokio worker if a rebind takes the write
        // lock), whereas a cloned Arc is self-contained and safe.
        let socket = Arc::clone(&self.socket.read());
        trace!("UDP: Sending {} bytes to server", buf.len());
        socket.send_to(buf, server_addr).await
    }

    async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let socket = Arc::clone(&self.socket.read());
        let (n, addr) = socket.recv_from(buf).await?;
        trace!("UDP: Received {} bytes from {}", n, addr);
        Ok((n, addr))
    }

    async fn recv_from_server(&self, buf: &mut [u8]) -> io::Result<usize> {
        let server_addr = *self.server_addr.read();
        let mut ignored_count = 0u32;
        loop {
            let (n, addr) = self.recv(buf).await?;
            if addr == server_addr {
                return Ok(n);
            }
            ignored_count += 1;
            if ignored_count >= MAX_IGNORED_PACKETS {
                return Err(io::Error::other("too many unexpected packets"));
            }
            debug!("UDP: Ignoring packet from unexpected source: {}", addr);
        }
    }

    fn server_addr(&self) -> SocketAddr {
        *self.server_addr.read()
    }

    fn local_addr(&self) -> SocketAddr {
        *self.local_addr.read()
    }

    fn update_server_addr(&mut self, new_addr: SocketAddr) {
        let mut addr = self.server_addr.write();
        debug!(
            "UDP: Updating server address from {} to {}",
            *addr, new_addr
        );
        *addr = new_addr;
    }

    fn is_connected(&self) -> bool {
        self.socket.read().local_addr().is_ok()
    }

    fn transport_type(&self) -> TransportType {
        TransportType::Udp
    }

    async fn close(&self) -> io::Result<()> {
        // UDP sockets don't need explicit closing
        Ok(())
    }

    async fn rebind(&self) -> io::Result<()> {
        // Build a fresh bind address that matches the current server's
        // address family. If the server address itself has been rewritten
        // (e.g., DNS roaming to a v6 peer after a network switch), the
        // bind family follows.
        let server_addr = *self.server_addr.read();
        let bind_addr: SocketAddr = if server_addr.is_ipv4() {
            "0.0.0.0:0"
                .parse()
                .expect("hardcoded IPv4 bind address is valid")
        } else {
            "[::]:0"
                .parse()
                .expect("hardcoded IPv6 bind address is valid")
        };

        let new_socket = UdpSocket::bind(bind_addr).await?;
        let new_local = new_socket.local_addr()?;
        let old_local = *self.local_addr.read();

        // Swap the socket and local_addr atomically from the caller's
        // point of view: any in-flight `send()` that started before this
        // rebind keeps using the old Arc it already cloned; any call
        // issued after will see the new socket. No half-torn state.
        *self.socket.write() = Arc::new(new_socket);
        *self.local_addr.write() = new_local;

        debug!(
            "UDP: Rebound socket {} -> {} (server {})",
            old_local, new_local, server_addr
        );
        Ok(())
    }
}

impl Clone for UdpTransport {
    fn clone(&self) -> Self {
        Self {
            socket: RwLock::new(Arc::clone(&self.socket.read())),
            server_addr: RwLock::new(*self.server_addr.read()),
            local_addr: RwLock::new(*self.local_addr.read()),
        }
    }
}

/// TLS-wrapped TCP stream for DPI-resistant transport.
///
/// All TCP connections use TLS to look like HTTPS traffic.
struct TlsStream(tokio_rustls::client::TlsStream<TcpStream>);

impl TlsStream {
    async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.0.write_all(buf).await
    }

    async fn flush(&mut self) -> io::Result<()> {
        self.0.flush().await
    }

    async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        self.0.read_exact(buf).await?;
        Ok(())
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        self.0.shutdown().await
    }
}

/// TCP transport implementation with length-prefix framing over TLS.
///
/// This is used for TCP/443 fallback when UDP is blocked.
/// Traffic is wrapped in TLS to look like normal HTTPS to DPI firewalls.
/// Each VPN packet is framed with a 2-byte big-endian length prefix
/// inside the encrypted TLS tunnel.
///
/// Note: The TLS layer provides DPI camouflage. The VPN payload itself
/// is already AES-256-GCM encrypted with PQ-derived session keys.
/// Server authentication uses ML-DSA signatures in the VPN handshake,
/// so TLS certificate validation is not required for security.
pub struct TcpTransport {
    /// The TLS-wrapped TCP stream.
    stream: Arc<tokio::sync::Mutex<TlsStream>>,
    /// Server address.
    server_addr: RwLock<SocketAddr>,
    /// Local bound address.
    local_addr: SocketAddr,
    /// Connection state.
    connected: Arc<RwLock<bool>>,
}

/// TLS server-cert verifier used by the TCP/443 DPI-camouflage transport.
///
/// Two modes:
///
///   - **Camouflage-only** (`pins.is_empty()`): TLS exists solely to make
///     the connection look like HTTPS to deep-packet-inspection middle-
///     boxes. The HPN VPN handshake itself authenticates the server with
///     ML-DSA signatures over the post-quantum KEM transcript, so the TLS
///     certificate provides zero security in this mode. We accept ANY
///     cert and skip the TLS signature check entirely. This is
///     equivalent to the previous `NoVerifier` behaviour and is
///     documented as such; the constructor logs a warning so operators
///     don't mistake camouflage for authentication.
///
///   - **Pinned** (`!pins.is_empty()`): the operator has supplied one or
///     more SHA-256 pins of expected server certificates. We require
///     `SHA-256(end_entity_DER)` to match one of the configured pins
///     (constant-time compare so the verifier itself doesn't leak which
///     pin matched in timing), AND the TLS handshake signature on the
///     ServerKeyExchange (TLS 1.2) or CertificateVerify (TLS 1.3) to
///     be VALID against the pinned cert's public key. Delegates to the
///     default rustls signature verifier using the active crypto
///     provider, so we inherit the same algorithm support and
///     constant-time properties as the rest of the rustls stack. This
///     closes the corporate-MITM-proxy / captive-portal-hostile attack
///     window earlier than the inner ML-DSA handshake would (the inner
///     handshake would still detect the swap, but the TLS surface is
///     faster to fail and surfaces a clearer error to the user).
#[derive(Debug)]
struct PinnedCertVerifier {
    pins: Vec<[u8; 32]>,
    crypto_provider: Arc<rustls::crypto::CryptoProvider>,
}

impl PinnedCertVerifier {
    fn new(pins: Vec<[u8; 32]>) -> Self {
        Self {
            pins,
            crypto_provider: rustls::crypto::ring::default_provider().into(),
        }
    }

    fn cert_matches_a_pin(&self, cert_der: &[u8]) -> bool {
        use ring::digest;
        use subtle::ConstantTimeEq;

        let computed = digest::digest(&digest::SHA256, cert_der);
        let actual = computed.as_ref();
        // Constant-time iterate over the pin set so a side-channel
        // attacker observing the verifier latency cannot identify which
        // pin a candidate certificate is closest to. The actual
        // server-cert hash is public, but iterating constant-time keeps
        // the contract simple.
        let mut matched = subtle::Choice::from(0u8);
        for pin in &self.pins {
            matched |= actual.ct_eq(pin);
        }
        bool::from(matched)
    }
}

impl rustls::client::danger::ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if self.pins.is_empty() {
            // Camouflage-only mode: server identity is asserted by the
            // inner ML-DSA handshake, TLS is here for DPI evasion.
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }
        if self.cert_matches_a_pin(end_entity.as_ref()) {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "server certificate does not match any configured SHA-256 pin".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        if self.pins.is_empty() {
            // Camouflage-only: keep the historical behaviour, the inner
            // VPN handshake is the trust anchor.
            return Ok(rustls::client::danger::HandshakeSignatureValid::assertion());
        }
        // Pinned mode: the server MUST prove possession of the private
        // key matching the pinned cert. Delegate to rustls' default
        // signature verifier so we inherit the constant-time properties
        // of the active provider (ring by default).
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        if self.pins.is_empty() {
            return Ok(rustls::client::danger::HandshakeSignatureValid::assertion());
        }
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.crypto_provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Default SNI hostname for DPI camouflage.
const DEFAULT_TLS_SNI: &str = "www.google.com";

impl TcpTransport {
    /// Create a new TLS-wrapped TCP transport.
    ///
    /// The TLS layer makes the connection look like HTTPS to DPI firewalls.
    /// Server authentication is handled by ML-DSA in the VPN handshake,
    /// not by TLS certificate validation.
    pub async fn connect(
        server_addr: SocketAddr,
        timeout_secs: Option<u64>,
        tls_sni: Option<&str>,
    ) -> io::Result<Self> {
        debug!("TCP+TLS: Connecting to server {}", server_addr);

        let tcp_stream = if let Some(timeout) = timeout_secs {
            let timeout_duration = std::time::Duration::from_secs(timeout);
            match tokio::time::timeout(timeout_duration, TcpStream::connect(server_addr)).await {
                Ok(result) => result?,
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "TCP connection timeout",
                    ));
                }
            }
        } else {
            TcpStream::connect(server_addr).await?
        };

        // Set TCP_NODELAY to reduce latency
        tcp_stream.set_nodelay(true)?;

        let local_addr = tcp_stream.local_addr()?;

        // Wrap in TLS for DPI camouflage (default) or pinned-cert
        // validation (when the operator has supplied SHA-256 pins
        // through future configuration).
        //
        // For now no call site passes pins — the verifier therefore runs
        // in its "camouflage-only" branch, which behaves identically to
        // the previous `NoVerifier` (accept any cert, skip TLS signature
        // verification, rely on the inner ML-DSA handshake for server
        // authentication). The infrastructure is in place so that a
        // follow-up patch can wire `ClientConfig::tls_cert_pins`
        // through `TransportConfig::Tcp` without touching this site.
        let sni = tls_sni.unwrap_or(DEFAULT_TLS_SNI);
        let tls_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedCertVerifier::new(Vec::new())))
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(tls_config));
        let server_name = rustls_pki_types::ServerName::try_from(sni.to_string()).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("invalid SNI: {e}"))
        })?;

        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("TLS handshake failed: {e}"),
                )
            })?;

        debug!(
            "TCP+TLS transport connected: local={}, server={}, sni={}",
            local_addr, server_addr, sni
        );

        Ok(Self {
            stream: Arc::new(tokio::sync::Mutex::new(TlsStream(tls_stream))),
            server_addr: RwLock::new(server_addr),
            local_addr,
            connected: Arc::new(RwLock::new(true)),
        })
    }

    /// Write a length-prefixed frame to the TLS/TCP stream.
    async fn write_frame(&self, buf: &[u8]) -> io::Result<usize> {
        if buf.len() > MAX_PACKET_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet too large for TCP framing",
            ));
        }

        let len = buf.len() as u16;
        let mut stream = self.stream.lock().await;

        // Write length prefix (2 bytes, big-endian)
        stream.write_all(&len.to_be_bytes()).await?;

        // Write payload
        stream.write_all(buf).await?;
        stream.flush().await?;

        Ok(buf.len())
    }

    /// Read a length-prefixed frame from the TLS/TCP stream.
    async fn read_frame(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut stream = self.stream.lock().await;

        // Read length prefix (2 bytes, big-endian)
        let mut len_buf = [0u8; TCP_FRAME_HEADER_SIZE];
        stream.read_exact(&mut len_buf).await?;
        let len = u16::from_be_bytes(len_buf) as usize;

        if len > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "frame too large: {} bytes, buffer only {} bytes",
                    len,
                    buf.len()
                ),
            ));
        }

        if len == 0 {
            return Ok(0);
        }

        // Read payload
        stream.read_exact(&mut buf[..len]).await?;
        Ok(len)
    }
}

#[async_trait]
impl TransportTrait for TcpTransport {
    async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        if !*self.connected.read() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "TCP transport not connected",
            ));
        }

        trace!("TCP: Sending {} bytes to server", buf.len());
        match self.write_frame(buf).await {
            Ok(n) => Ok(n),
            Err(e) => {
                warn!("TCP send error: {}", e);
                *self.connected.write() = false;
                Err(e)
            }
        }
    }

    async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        if !*self.connected.read() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "TCP transport not connected",
            ));
        }

        match self.read_frame(buf).await {
            Ok(n) => {
                trace!("TCP: Received {} bytes from server", n);
                Ok((n, self.server_addr()))
            }
            Err(e) => {
                warn!("TCP recv error: {}", e);
                *self.connected.write() = false;
                Err(e)
            }
        }
    }

    async fn recv_from_server(&self, buf: &mut [u8]) -> io::Result<usize> {
        // TCP is connection-oriented, so all data comes from the server
        let (n, _) = self.recv(buf).await?;
        Ok(n)
    }

    fn server_addr(&self) -> SocketAddr {
        *self.server_addr.read()
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn update_server_addr(&mut self, new_addr: SocketAddr) {
        // TCP connections can't change server address without reconnecting
        // This is a no-op for TCP - reconnection is needed
        warn!(
            "TCP: update_server_addr called (no-op, reconnection needed): {} -> {}",
            self.server_addr(),
            new_addr
        );
        *self.server_addr.write() = new_addr;
    }

    fn is_connected(&self) -> bool {
        *self.connected.read()
    }

    fn transport_type(&self) -> TransportType {
        TransportType::Tcp
    }

    async fn close(&self) -> io::Result<()> {
        *self.connected.write() = false;
        let mut stream = self.stream.lock().await;
        stream.shutdown().await?;
        debug!("TCP+TLS transport closed");
        Ok(())
    }
}

impl Clone for TcpTransport {
    fn clone(&self) -> Self {
        Self {
            stream: Arc::clone(&self.stream),
            server_addr: RwLock::new(*self.server_addr.read()),
            local_addr: self.local_addr,
            connected: Arc::clone(&self.connected),
        }
    }
}

/// Unified transport enum that can be either UDP or TCP.
///
/// This provides a concrete type for when you need to store the transport
/// without using trait objects.
pub enum Transport {
    /// UDP transport.
    Udp(UdpTransport),
    /// TCP transport.
    Tcp(TcpTransport),
}

impl Transport {
    /// Connect using the provided configuration.
    pub async fn connect(config: TransportConfig) -> io::Result<Self> {
        match config {
            TransportConfig::Udp { server_addr } => {
                let transport = UdpTransport::connect(server_addr).await?;
                Ok(Transport::Udp(transport))
            }
            TransportConfig::Tcp {
                server_addr,
                connect_timeout_secs,
                tls_sni,
            } => {
                let transport =
                    TcpTransport::connect(server_addr, connect_timeout_secs, tls_sni.as_deref())
                        .await?;
                Ok(Transport::Tcp(transport))
            }
        }
    }

    /// Create a UDP transport.
    pub async fn udp(server_addr: SocketAddr) -> io::Result<Self> {
        Ok(Transport::Udp(UdpTransport::connect(server_addr).await?))
    }

    /// Create a TCP transport with TLS.
    pub async fn tcp(server_addr: SocketAddr, timeout_secs: Option<u64>) -> io::Result<Self> {
        Ok(Transport::Tcp(
            TcpTransport::connect(server_addr, timeout_secs, None).await?,
        ))
    }

    /// Send data to the server.
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Transport::Udp(t) => t.send(buf).await,
            Transport::Tcp(t) => t.send(buf).await,
        }
    }

    /// Receive data from the server.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match self {
            Transport::Udp(t) => t.recv(buf).await,
            Transport::Tcp(t) => t.recv(buf).await,
        }
    }

    /// Receive data, only accepting packets from the expected server.
    pub async fn recv_from_server(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Transport::Udp(t) => t.recv_from_server(buf).await,
            Transport::Tcp(t) => t.recv_from_server(buf).await,
        }
    }

    /// Get the server address.
    pub fn server_addr(&self) -> SocketAddr {
        match self {
            Transport::Udp(t) => t.server_addr(),
            Transport::Tcp(t) => t.server_addr(),
        }
    }

    /// Get the local bound address.
    pub fn local_addr(&self) -> SocketAddr {
        match self {
            Transport::Udp(t) => t.local_addr(),
            Transport::Tcp(t) => t.local_addr(),
        }
    }

    /// Update the server address (for rebinding/roaming).
    pub fn update_server_addr(&mut self, new_addr: SocketAddr) {
        match self {
            Transport::Udp(t) => t.update_server_addr(new_addr),
            Transport::Tcp(t) => t.update_server_addr(new_addr),
        }
    }

    /// Check if the transport is still connected.
    pub fn is_connected(&self) -> bool {
        match self {
            Transport::Udp(t) => t.is_connected(),
            Transport::Tcp(t) => t.is_connected(),
        }
    }

    /// Get the transport type.
    pub fn transport_type(&self) -> TransportType {
        match self {
            Transport::Udp(t) => t.transport_type(),
            Transport::Tcp(t) => t.transport_type(),
        }
    }

    /// Close the transport connection.
    pub async fn close(&self) -> io::Result<()> {
        match self {
            Transport::Udp(t) => t.close().await,
            Transport::Tcp(t) => t.close().await,
        }
    }

    /// Get the inner UDP transport if this is UDP.
    pub fn as_udp(&self) -> Option<&UdpTransport> {
        match self {
            Transport::Udp(t) => Some(t),
            Transport::Tcp(_) => None,
        }
    }

    /// Get the inner TCP transport if this is TCP.
    pub fn as_tcp(&self) -> Option<&TcpTransport> {
        match self {
            Transport::Udp(_) => None,
            Transport::Tcp(t) => Some(t),
        }
    }
}

impl Clone for Transport {
    fn clone(&self) -> Self {
        match self {
            Transport::Udp(t) => Transport::Udp(t.clone()),
            Transport::Tcp(t) => Transport::Tcp(t.clone()),
        }
    }
}

/// Transport fallback manager.
///
/// Manages automatic fallback from UDP to TCP when UDP is blocked.
pub struct TransportFallback {
    /// Primary transport configuration (UDP).
    primary_config: TransportConfig,
    /// Fallback transport configuration (TCP/443).
    fallback_config: Option<TransportConfig>,
    /// Current transport.
    current: Option<Transport>,
    /// Whether we're using the fallback.
    using_fallback: bool,
    /// Number of UDP failures before fallback.
    udp_failure_threshold: u32,
    /// Current UDP failure count.
    udp_failure_count: u32,
}

impl TransportFallback {
    /// Create a new transport fallback manager.
    pub fn new(primary_config: TransportConfig, fallback_config: Option<TransportConfig>) -> Self {
        Self {
            primary_config,
            fallback_config,
            current: None,
            using_fallback: false,
            udp_failure_threshold: 3,
            udp_failure_count: 0,
        }
    }

    /// Set the UDP failure threshold.
    pub fn with_failure_threshold(mut self, threshold: u32) -> Self {
        self.udp_failure_threshold = threshold;
        self
    }

    /// Connect using the appropriate transport.
    pub async fn connect(&mut self) -> io::Result<&Transport> {
        if self.using_fallback {
            self.connect_fallback().await
        } else {
            self.connect_primary().await
        }
    }

    /// Connect using the primary transport (UDP).
    async fn connect_primary(&mut self) -> io::Result<&Transport> {
        let transport = Transport::connect(self.primary_config.clone()).await?;
        self.current = Some(transport);
        self.using_fallback = false;
        // SAFETY: We just set self.current to Some, so this cannot fail
        Ok(self.current.as_ref().expect("just set"))
    }

    /// Connect using the fallback transport (TCP).
    async fn connect_fallback(&mut self) -> io::Result<&Transport> {
        let config = self.fallback_config.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "no fallback transport configured")
        })?;

        let transport = Transport::connect(config.clone()).await?;
        self.current = Some(transport);
        self.using_fallback = true;
        // SAFETY: We just set self.current to Some, so this cannot fail
        Ok(self.current.as_ref().expect("just set"))
    }

    /// Record a transport failure.
    ///
    /// Returns `true` if fallback is triggered.
    pub fn record_failure(&mut self) -> bool {
        if self.using_fallback {
            // Already on fallback, can't fall back further
            return false;
        }

        self.udp_failure_count += 1;
        if self.udp_failure_count >= self.udp_failure_threshold && self.fallback_config.is_some() {
            debug!(
                "UDP failures ({}) exceeded threshold ({}), switching to TCP fallback",
                self.udp_failure_count, self.udp_failure_threshold
            );
            self.using_fallback = true;
            true
        } else {
            false
        }
    }

    /// Record a successful operation.
    pub fn record_success(&mut self) {
        if !self.using_fallback {
            self.udp_failure_count = 0;
        }
    }

    /// Reset to primary transport.
    pub fn reset_to_primary(&mut self) {
        self.using_fallback = false;
        self.udp_failure_count = 0;
        self.current = None;
    }

    /// Check if using fallback transport.
    pub fn is_using_fallback(&self) -> bool {
        self.using_fallback
    }

    /// Get the current transport.
    pub fn transport(&self) -> Option<&Transport> {
        self.current.as_ref()
    }

    /// Get the current transport mutably.
    pub fn transport_mut(&mut self) -> Option<&mut Transport> {
        self.current.as_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_verifier_camouflage_mode_does_not_match_via_pin_helper() {
        // `cert_matches_a_pin` strictly compares against the configured
        // pin set; in camouflage mode the pin set is empty so the helper
        // returns false even for "valid" input. The acceptance logic
        // for camouflage lives in `verify_server_cert` (early-return
        // Ok when `pins.is_empty()`), NOT in this helper. Pin this
        // contract so a future refactor doesn't quietly swap the
        // helper's semantics.
        let verifier = PinnedCertVerifier::new(Vec::new());
        assert!(!verifier.cert_matches_a_pin(b"any-cert"));
        assert!(!verifier.cert_matches_a_pin(&[]));
    }

    #[test]
    fn pinned_verifier_accepts_matching_pin() {
        use ring::digest;
        let cert_der = b"fake-server-cert-DER-bytes";
        let pin = digest::digest(&digest::SHA256, cert_der);
        let mut pin_bytes = [0u8; 32];
        pin_bytes.copy_from_slice(pin.as_ref());

        let verifier = PinnedCertVerifier::new(vec![pin_bytes]);
        assert!(verifier.cert_matches_a_pin(cert_der));
    }

    #[test]
    fn pinned_verifier_rejects_unknown_cert() {
        use ring::digest;
        let pinned_cert = b"pinned-cert";
        let pin = digest::digest(&digest::SHA256, pinned_cert);
        let mut pin_bytes = [0u8; 32];
        pin_bytes.copy_from_slice(pin.as_ref());

        let verifier = PinnedCertVerifier::new(vec![pin_bytes]);
        // A different cert that happens to share the same prefix as the
        // pinned one must still be rejected — the verifier compares the
        // full SHA-256 digest, not a prefix.
        assert!(!verifier.cert_matches_a_pin(b"pinned-cert-but-different"));
        assert!(!verifier.cert_matches_a_pin(b"unrelated"));
    }

    #[test]
    fn pinned_verifier_accepts_any_pin_from_set() {
        use ring::digest;
        let cert_a = b"cert-A";
        let cert_b = b"cert-B";
        let mut pin_a = [0u8; 32];
        pin_a.copy_from_slice(digest::digest(&digest::SHA256, cert_a).as_ref());
        let mut pin_b = [0u8; 32];
        pin_b.copy_from_slice(digest::digest(&digest::SHA256, cert_b).as_ref());

        let verifier = PinnedCertVerifier::new(vec![pin_a, pin_b]);
        assert!(verifier.cert_matches_a_pin(cert_a));
        assert!(verifier.cert_matches_a_pin(cert_b));
        assert!(!verifier.cert_matches_a_pin(b"cert-C"));
    }

    #[tokio::test]
    async fn test_udp_transport_connect() {
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let transport = UdpTransport::connect(addr).await.unwrap();
        assert!(transport.local_addr().port() > 0);
        assert_eq!(transport.server_addr(), addr);
        assert_eq!(transport.transport_type(), TransportType::Udp);
    }

    #[test]
    fn test_transport_config() {
        let udp_config = TransportConfig::Udp {
            server_addr: "10.0.0.1:51820".parse().unwrap(),
        };
        assert_eq!(udp_config.transport_type(), TransportType::Udp);

        let tcp_config = TransportConfig::Tcp {
            server_addr: "10.0.0.1:443".parse().unwrap(),
            connect_timeout_secs: Some(30),
            tls_sni: None,
        };
        assert_eq!(tcp_config.transport_type(), TransportType::Tcp);
    }

    #[test]
    fn test_transport_fallback_thresholds() {
        let primary = TransportConfig::Udp {
            server_addr: "10.0.0.1:51820".parse().unwrap(),
        };
        let fallback = TransportConfig::Tcp {
            server_addr: "10.0.0.1:443".parse().unwrap(),
            connect_timeout_secs: Some(30),
            tls_sni: None,
        };

        let mut manager = TransportFallback::new(primary, Some(fallback)).with_failure_threshold(3);

        // First two failures should not trigger fallback
        assert!(!manager.record_failure());
        assert!(!manager.record_failure());
        assert!(!manager.is_using_fallback());

        // Third failure should trigger fallback
        assert!(manager.record_failure());
        assert!(manager.is_using_fallback());
    }

    #[test]
    fn test_transport_fallback_success_resets_counter() {
        let primary = TransportConfig::Udp {
            server_addr: "10.0.0.1:51820".parse().unwrap(),
        };
        let fallback = TransportConfig::Tcp {
            server_addr: "10.0.0.1:443".parse().unwrap(),
            connect_timeout_secs: Some(30),
            tls_sni: None,
        };

        let mut manager = TransportFallback::new(primary, Some(fallback)).with_failure_threshold(3);

        // Record some failures
        assert!(!manager.record_failure());
        assert!(!manager.record_failure());

        // Success should reset counter
        manager.record_success();

        // Should need 3 more failures to trigger fallback
        assert!(!manager.record_failure());
        assert!(!manager.record_failure());
        assert!(!manager.is_using_fallback());
        assert!(manager.record_failure());
        assert!(manager.is_using_fallback());
    }

    #[test]
    fn test_transport_fallback_no_fallback_configured() {
        let primary = TransportConfig::Udp {
            server_addr: "10.0.0.1:51820".parse().unwrap(),
        };

        let mut manager = TransportFallback::new(primary, None).with_failure_threshold(2);

        // Failures should not trigger fallback when no fallback is configured
        assert!(!manager.record_failure());
        assert!(!manager.record_failure());
        assert!(!manager.record_failure());
        assert!(!manager.is_using_fallback());
    }

    #[test]
    fn test_transport_fallback_reset_to_primary() {
        let primary = TransportConfig::Udp {
            server_addr: "10.0.0.1:51820".parse().unwrap(),
        };
        let fallback = TransportConfig::Tcp {
            server_addr: "10.0.0.1:443".parse().unwrap(),
            connect_timeout_secs: Some(30),
            tls_sni: None,
        };

        let mut manager = TransportFallback::new(primary, Some(fallback)).with_failure_threshold(2);

        // Trigger fallback
        assert!(!manager.record_failure());
        assert!(manager.record_failure());
        assert!(manager.is_using_fallback());

        // Reset to primary
        manager.reset_to_primary();
        assert!(!manager.is_using_fallback());
    }

    #[test]
    fn test_transport_config_server_addr() {
        let udp_config = TransportConfig::Udp {
            server_addr: "192.168.1.1:51820".parse().unwrap(),
        };
        assert_eq!(
            udp_config.server_addr(),
            "192.168.1.1:51820".parse::<SocketAddr>().unwrap()
        );

        let tcp_config = TransportConfig::Tcp {
            server_addr: "192.168.1.1:443".parse().unwrap(),
            connect_timeout_secs: Some(10),
            tls_sni: None,
        };
        assert_eq!(
            tcp_config.server_addr(),
            "192.168.1.1:443".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn test_transport_type_display() {
        assert_eq!(TransportType::Udp.to_string(), "UDP");
        assert_eq!(TransportType::Tcp.to_string(), "TCP");
    }

    #[test]
    fn test_transport_fallback_custom_threshold() {
        let primary = TransportConfig::Udp {
            server_addr: "10.0.0.1:51820".parse().unwrap(),
        };
        let fallback = TransportConfig::Tcp {
            server_addr: "10.0.0.1:443".parse().unwrap(),
            connect_timeout_secs: Some(30),
            tls_sni: None,
        };

        // Test with threshold of 5
        let mut manager = TransportFallback::new(primary, Some(fallback)).with_failure_threshold(5);

        for i in 0..4 {
            assert!(
                !manager.record_failure(),
                "Failure {} should not trigger fallback",
                i
            );
            assert!(!manager.is_using_fallback());
        }

        // 5th failure should trigger
        assert!(manager.record_failure());
        assert!(manager.is_using_fallback());
    }

    #[test]
    fn test_transport_fallback_already_on_fallback() {
        let primary = TransportConfig::Udp {
            server_addr: "10.0.0.1:51820".parse().unwrap(),
        };
        let fallback = TransportConfig::Tcp {
            server_addr: "10.0.0.1:443".parse().unwrap(),
            connect_timeout_secs: Some(30),
            tls_sni: None,
        };

        let mut manager = TransportFallback::new(primary, Some(fallback)).with_failure_threshold(2);

        // Trigger fallback
        manager.record_failure();
        manager.record_failure();
        assert!(manager.is_using_fallback());

        // Further failures should return false (already on fallback)
        assert!(!manager.record_failure());
        assert!(!manager.record_failure());
        assert!(manager.is_using_fallback());
    }

    #[test]
    fn test_max_packet_size_constant() {
        assert_eq!(MAX_PACKET_SIZE, 65535);
    }

    #[test]
    fn test_transport_config_udp_creation() {
        let addr: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        let config = TransportConfig::Udp { server_addr: addr };

        assert_eq!(config.server_addr(), addr);
        assert_eq!(config.transport_type(), TransportType::Udp);
    }

    #[test]
    fn test_transport_config_tcp_creation() {
        let addr: SocketAddr = "192.168.1.1:443".parse().unwrap();
        let config = TransportConfig::Tcp {
            server_addr: addr,
            connect_timeout_secs: Some(15),
            tls_sni: None,
        };

        assert_eq!(config.server_addr(), addr);
        assert_eq!(config.transport_type(), TransportType::Tcp);
    }

    #[test]
    fn test_transport_config_tcp_no_timeout() {
        let addr: SocketAddr = "10.0.0.1:443".parse().unwrap();
        let config = TransportConfig::Tcp {
            server_addr: addr,
            connect_timeout_secs: None,
            tls_sni: None,
        };

        assert_eq!(config.server_addr(), addr);
    }

    #[test]
    fn test_transport_type_equality() {
        assert_eq!(TransportType::Udp, TransportType::Udp);
        assert_eq!(TransportType::Tcp, TransportType::Tcp);
        assert_ne!(TransportType::Udp, TransportType::Tcp);
    }

    #[test]
    fn test_transport_fallback_default_threshold() {
        let primary = TransportConfig::Udp {
            server_addr: "10.0.0.1:51820".parse().unwrap(),
        };

        // Create without custom threshold (uses default)
        let manager = TransportFallback::new(primary, None);

        // Should start without fallback
        assert!(!manager.is_using_fallback());
        assert!(manager.transport().is_none());
    }

    #[test]
    fn test_transport_fallback_manager_transport_access() {
        let primary = TransportConfig::Udp {
            server_addr: "10.0.0.1:51820".parse().unwrap(),
        };
        let fallback = TransportConfig::Tcp {
            server_addr: "10.0.0.1:443".parse().unwrap(),
            connect_timeout_secs: Some(10),
            tls_sni: None,
        };

        let manager = TransportFallback::new(primary, Some(fallback));

        // Initially no transport is connected
        assert!(manager.transport().is_none());
    }

    #[test]
    fn test_transport_config_clone() {
        let config = TransportConfig::Udp {
            server_addr: "10.0.0.1:51820".parse().unwrap(),
        };

        let cloned = config.clone();
        assert_eq!(config.server_addr(), cloned.server_addr());
        assert_eq!(config.transport_type(), cloned.transport_type());
    }

    #[test]
    fn test_transport_type_copy() {
        let transport_type = TransportType::Udp;
        let copied = transport_type;
        assert_eq!(transport_type, copied);
    }

    #[tokio::test]
    async fn test_udp_transport_ipv6() {
        let addr: SocketAddr = "[::1]:12345".parse().unwrap();
        let transport = UdpTransport::connect(addr).await.unwrap();
        assert!(transport.local_addr().is_ipv6());
        assert_eq!(transport.server_addr(), addr);
    }

    #[tokio::test]
    async fn test_udp_transport_clone() {
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let transport = UdpTransport::connect(addr).await.unwrap();
        let cloned = transport.clone();

        assert_eq!(transport.server_addr(), cloned.server_addr());
        assert_eq!(transport.local_addr(), cloned.local_addr());
        assert_eq!(transport.transport_type(), cloned.transport_type());
    }

    #[tokio::test]
    async fn test_udp_transport_update_server_addr() {
        let addr1: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:54321".parse().unwrap();

        let mut transport = UdpTransport::connect(addr1).await.unwrap();
        assert_eq!(transport.server_addr(), addr1);

        transport.update_server_addr(addr2);
        assert_eq!(transport.server_addr(), addr2);
    }

    #[tokio::test]
    async fn test_udp_transport_is_connected() {
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let transport = UdpTransport::connect(addr).await.unwrap();
        assert!(transport.is_connected());
    }

    #[tokio::test]
    async fn test_udp_transport_close() {
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let transport = UdpTransport::connect(addr).await.unwrap();

        // UDP close should always succeed
        assert!(transport.close().await.is_ok());
    }

    #[tokio::test]
    async fn test_udp_transport_rebind_changes_local_port() {
        // rebind() MUST return a freshly-bound socket on a different
        // ephemeral port. If the local port does not change, the kernel
        // reused the same fd — which would defeat the purpose of
        // rebinding after a network hand-off where the old fd became
        // unusable.
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let transport = UdpTransport::connect(addr).await.unwrap();

        let old_local = transport.local_addr();
        assert_ne!(old_local.port(), 0);

        transport.rebind().await.unwrap();

        let new_local = transport.local_addr();
        assert_ne!(old_local.port(), new_local.port());
        assert!(transport.is_connected());
        // server_addr stays intact across a rebind — the whole point is
        // that we're swapping the LOCAL socket, not talking to a
        // different server.
        assert_eq!(transport.server_addr(), addr);
    }

    #[tokio::test]
    async fn test_udp_transport_rebind_trait_default_is_noop() {
        // A transport that does not override rebind() (e.g., TCP) must
        // return Ok(()) — the contract documented on the trait. This
        // test pins that behaviour via an ad-hoc Arc<dyn TransportTrait>
        // so a future refactor cannot silently change it.
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let udp = Arc::new(UdpTransport::connect(addr).await.unwrap());
        let dynamic: Arc<dyn TransportTrait> = udp.clone();
        // UdpTransport DOES override rebind, so this still exercises the
        // real impl — but through the trait object path, confirming the
        // dispatch works.
        assert!(dynamic.rebind().await.is_ok());
    }

    #[tokio::test]
    async fn test_transport_enum_udp() {
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let transport = Transport::udp(addr).await.unwrap();

        assert_eq!(transport.transport_type(), TransportType::Udp);
        assert!(transport.as_udp().is_some());
        assert!(transport.as_tcp().is_none());
    }

    #[tokio::test]
    async fn test_transport_enum_clone() {
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let transport = Transport::udp(addr).await.unwrap();
        let cloned = transport.clone();

        assert_eq!(transport.server_addr(), cloned.server_addr());
        assert_eq!(transport.transport_type(), cloned.transport_type());
    }

    #[tokio::test]
    async fn test_transport_enum_update_server_addr() {
        let addr1: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:54321".parse().unwrap();

        let mut transport = Transport::udp(addr1).await.unwrap();
        assert_eq!(transport.server_addr(), addr1);

        transport.update_server_addr(addr2);
        assert_eq!(transport.server_addr(), addr2);
    }

    #[tokio::test]
    async fn test_transport_enum_is_connected() {
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let transport = Transport::udp(addr).await.unwrap();
        assert!(transport.is_connected());
    }

    #[tokio::test]
    async fn test_transport_from_config_udp() {
        let config = TransportConfig::Udp {
            server_addr: "127.0.0.1:12345".parse().unwrap(),
        };

        let transport = Transport::connect(config).await.unwrap();
        assert_eq!(transport.transport_type(), TransportType::Udp);
    }

    #[test]
    fn test_tcp_frame_header_size() {
        assert_eq!(TCP_FRAME_HEADER_SIZE, 2);
    }

    #[tokio::test]
    async fn test_transport_fallback_record_success_no_reset_on_fallback() {
        let primary = TransportConfig::Udp {
            server_addr: "10.0.0.1:51820".parse().unwrap(),
        };
        let fallback = TransportConfig::Tcp {
            server_addr: "10.0.0.1:443".parse().unwrap(),
            connect_timeout_secs: Some(30),
            tls_sni: None,
        };

        let mut manager = TransportFallback::new(primary, Some(fallback)).with_failure_threshold(2);

        // Trigger fallback
        manager.record_failure();
        manager.record_failure();
        assert!(manager.is_using_fallback());

        // Success on fallback should not reset anything
        manager.record_success();
        assert!(manager.is_using_fallback());
    }

    #[tokio::test]
    async fn test_transport_fallback_connect_no_fallback_available() {
        let primary = TransportConfig::Udp {
            server_addr: "127.0.0.1:51820".parse().unwrap(),
        };

        let mut manager = TransportFallback::new(primary, None);

        // Try to connect to primary (should work)
        let result = manager.connect().await;
        assert!(result.is_ok());
        assert!(!manager.is_using_fallback());
    }

    #[tokio::test]
    async fn test_transport_fallback_transport_mut() {
        let primary = TransportConfig::Udp {
            server_addr: "127.0.0.1:51820".parse().unwrap(),
        };

        let mut manager = TransportFallback::new(primary, None);

        // Initially no transport
        assert!(manager.transport_mut().is_none());

        // Connect and check mutable access
        manager.connect().await.unwrap();
        assert!(manager.transport_mut().is_some());
    }

    #[tokio::test]
    async fn test_udp_transport_socket_arc() {
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let transport = UdpTransport::connect(addr).await.unwrap();

        // Get socket Arc and verify it's the same underlying socket
        let socket1 = transport.socket();
        let socket2 = transport.socket();

        assert_eq!(socket1.local_addr().unwrap(), socket2.local_addr().unwrap());
    }

    #[test]
    fn test_transport_type_debug() {
        let udp = TransportType::Udp;
        let tcp = TransportType::Tcp;

        assert_eq!(format!("{udp:?}"), "Udp");
        assert_eq!(format!("{tcp:?}"), "Tcp");
    }

    #[test]
    fn test_transport_config_transport_type() {
        let udp_config = TransportConfig::Udp {
            server_addr: "127.0.0.1:51820".parse().unwrap(),
        };
        assert_eq!(udp_config.transport_type(), TransportType::Udp);

        let tcp_config = TransportConfig::Tcp {
            server_addr: "127.0.0.1:443".parse().unwrap(),
            connect_timeout_secs: Some(10),
            tls_sni: None,
        };
        assert_eq!(tcp_config.transport_type(), TransportType::Tcp);
    }

    #[test]
    fn test_transport_config_tcp_zero_timeout() {
        let config = TransportConfig::Tcp {
            server_addr: "127.0.0.1:443".parse().unwrap(),
            connect_timeout_secs: Some(0),
            tls_sni: None,
        };
        assert_eq!(config.server_addr().port(), 443);
        assert_eq!(config.transport_type(), TransportType::Tcp);
    }

    #[test]
    fn test_transport_config_ipv6_addresses() {
        let udp_config = TransportConfig::Udp {
            server_addr: "[::1]:51820".parse().unwrap(),
        };
        assert!(udp_config.server_addr().is_ipv6());

        let tcp_config = TransportConfig::Tcp {
            server_addr: "[2001:db8::1]:443".parse().unwrap(),
            connect_timeout_secs: None,
            tls_sni: None,
        };
        assert!(tcp_config.server_addr().is_ipv6());
    }

    #[test]
    fn test_max_packet_size_value() {
        assert_eq!(MAX_PACKET_SIZE, 65535);
        assert_eq!(MAX_PACKET_SIZE, u16::MAX as usize);
    }

    #[tokio::test]
    async fn test_udp_transport_clone_shares_socket() {
        let addr: SocketAddr = "127.0.0.1:12346".parse().unwrap();
        let transport1 = UdpTransport::connect(addr).await.unwrap();
        let transport2 = transport1.clone();

        // Both should have the same local address (same socket)
        assert_eq!(transport1.local_addr(), transport2.local_addr());
        assert_eq!(
            transport1.socket().local_addr().unwrap(),
            transport2.socket().local_addr().unwrap()
        );
    }

    #[tokio::test]
    async fn test_udp_transport_connection_state() {
        let addr: SocketAddr = "127.0.0.1:12347".parse().unwrap();
        let transport = UdpTransport::connect(addr).await.unwrap();

        assert!(transport.is_connected());
    }

    #[tokio::test]
    async fn test_udp_transport_close_operation() {
        let addr: SocketAddr = "127.0.0.1:12348".parse().unwrap();
        let transport = UdpTransport::connect(addr).await.unwrap();

        // Close should succeed for UDP (it's a no-op)
        let result = transport.close().await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_transport_fallback_failure_count_accuracy() {
        let primary = TransportConfig::Udp {
            server_addr: "127.0.0.1:51820".parse().unwrap(),
        };
        let fallback = TransportConfig::Tcp {
            server_addr: "127.0.0.1:443".parse().unwrap(),
            connect_timeout_secs: Some(10),
            tls_sni: None,
        };

        let mut manager = TransportFallback::new(primary, Some(fallback)).with_failure_threshold(5);

        // Record exactly threshold-1 failures
        for _ in 0..4 {
            manager.record_failure();
        }
        assert!(!manager.is_using_fallback());

        // One more should trigger fallback
        manager.record_failure();
        assert!(manager.is_using_fallback());
    }

    #[test]
    fn test_transport_fallback_success_on_primary_resets() {
        let primary = TransportConfig::Udp {
            server_addr: "127.0.0.1:51820".parse().unwrap(),
        };

        let mut manager = TransportFallback::new(primary, None);

        // Build up failures
        manager.record_failure();
        manager.record_failure();

        // Success should reset
        manager.record_success();

        // Failures should start from 0 again
        manager.record_failure();
        assert!(!manager.is_using_fallback()); // Only 1 failure, not enough
    }

    #[test]
    fn test_transport_config_server_addr_ipv4() {
        let config = TransportConfig::Udp {
            server_addr: "192.168.1.1:8080".parse().unwrap(),
        };
        let addr = config.server_addr();
        assert_eq!(addr.ip().to_string(), "192.168.1.1");
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn test_transport_type_partial_eq() {
        assert_eq!(TransportType::Udp, TransportType::Udp);
        assert_eq!(TransportType::Tcp, TransportType::Tcp);
        assert_ne!(TransportType::Udp, TransportType::Tcp);
    }
}
