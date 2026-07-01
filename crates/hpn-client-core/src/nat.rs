//! NAT traversal support for HPN client.
//!
//! Implements STUN (RFC 5389) client for discovering public IP and port,
//! and UDP hole punching utilities for peer-to-peer scenarios.
//!
//! # Privacy / IP-leak considerations
//!
//! STUN binding requests are sent **in clear text over UDP** to the STUN
//! servers. They expose the client's *real* IP address to those servers,
//! which is exactly the property a VPN is supposed to hide. This module
//! therefore ships with [`DEFAULT_STUN_SERVERS`] **empty** — STUN is
//! strictly opt-in and the operator must call [`StunClient::with_servers`]
//! to inject a list of trusted servers (ideally self-hosted, ideally
//! reached *through* the established VPN tunnel).
//!
//! Earlier versions of HPN defaulted to Google's public STUN servers,
//! which leaked the user's real IP to a third party at every NAT
//! discovery / rebind check. The audit closed this as CRITICAL #5.
//! See `ClientConfig::stun_servers` for the operator-facing knob.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use tracing::{debug, trace, warn};

use crate::error::ClientError;

/// Default STUN servers used by [`StunClient::new`].
///
/// **Empty by design.** STUN is opt-in: the operator must call
/// [`StunClient::with_servers`] (or set `ClientConfig::stun_servers`) with
/// a list of *trusted* servers — preferably self-hosted, ideally reached
/// through the VPN tunnel after the handshake completes. A non-empty
/// default would leak the user's real IP to whatever third party owns
/// the listed STUN servers (Google, Cloudflare, …) at every NAT-discovery
/// or rebind check, defeating the entire VPN.
///
/// Use [`StunClient::is_enabled`] to detect misconfiguration before
/// wiring `discover()` into a production code path.
pub const DEFAULT_STUN_SERVERS: &[&str] = &[];

/// STUN message types.
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_RESPONSE: u16 = 0x0101;
const STUN_BINDING_ERROR_RESPONSE: u16 = 0x0111;

/// STUN attributes.
const STUN_ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const STUN_ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// STUN magic cookie (RFC 5389).
const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

/// STUN header size (20 bytes: type(2) + length(2) + magic(4) + transaction_id(12)).
const STUN_HEADER_SIZE: usize = 20;

/// Result of a STUN binding request.
#[derive(Clone, Debug)]
pub struct StunResult {
    /// Discovered public IP address.
    pub public_ip: IpAddr,
    /// Discovered public port.
    pub public_port: u16,
    /// The STUN server used.
    pub server: String,
}

impl StunResult {
    /// Get as a socket address.
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.public_ip, self.public_port)
    }
}

/// STUN client for NAT discovery.
///
/// **Disabled by default.** A freshly-constructed `StunClient` has an
/// empty server list (see [`DEFAULT_STUN_SERVERS`]) and every call to
/// [`Self::discover`] / [`Self::discover_with_socket`] returns
/// `ClientError::Network("STUN disabled: no servers configured")`. To
/// enable STUN you must inject a server list with [`Self::with_servers`].
///
/// Pre-tunnel STUN traffic leaks the user's real IP to the configured
/// servers; only enable STUN with servers you trust **and** that the VPN
/// operator deems acceptable to receive that information. The safest
/// pattern is to enable STUN only *after* the VPN tunnel is up and to
/// route the queries through the tunnel.
pub struct StunClient {
    /// List of STUN servers to try.
    servers: Vec<String>,
    /// Timeout for STUN requests.
    timeout: Duration,
    /// Number of retries per server.
    retries: u8,
}

impl Default for StunClient {
    fn default() -> Self {
        Self::new()
    }
}

impl StunClient {
    /// Create a new STUN client.
    ///
    /// The returned client is **disabled** (empty server list). Call
    /// [`Self::with_servers`] to enable it.
    pub fn new() -> Self {
        Self {
            servers: DEFAULT_STUN_SERVERS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            timeout: Duration::from_secs(3),
            retries: 2,
        }
    }

    /// Set the list of STUN servers and **enable** the client.
    ///
    /// Each server should be a `host:port` string. A typical value is a
    /// self-hosted STUN endpoint reached through the VPN tunnel after the
    /// handshake completes; for legacy compatibility the caller may also
    /// pass public servers (e.g. Google's `stun.l.google.com:19302`) but
    /// must accept that the STUN packets are sent in clear text and
    /// expose the client's real IP to the server operator before the
    /// tunnel is up.
    pub fn with_servers(mut self, servers: Vec<String>) -> Self {
        self.servers = servers;
        self
    }

    /// Set request timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set number of retries per server.
    pub fn with_retries(mut self, retries: u8) -> Self {
        self.retries = retries;
        self
    }

    /// Returns `true` if at least one STUN server is configured.
    ///
    /// Callers should branch on this before invoking [`Self::discover`]
    /// in code paths that need a graceful no-op when STUN is disabled
    /// (logging, optimistic NAT detection, etc.). `discover()` itself
    /// also fails closed with a clear error when called on an empty
    /// client, so the check is pure defensive coding.
    pub fn is_enabled(&self) -> bool {
        !self.servers.is_empty()
    }

    /// Discover public IP and port using STUN.
    ///
    /// Tries each configured STUN server in order until one succeeds.
    ///
    /// Returns `ClientError::Network` immediately when no servers are
    /// configured (the default state) — see [`Self::with_servers`].
    pub fn discover(&self) -> Result<StunResult, ClientError> {
        if self.servers.is_empty() {
            return Err(ClientError::Network(
                "STUN disabled: no servers configured (call with_servers to enable)".to_string(),
            ));
        }

        // Bind to any available port
        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| ClientError::Network(format!("Failed to bind UDP socket: {}", e)))?;

        socket
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| ClientError::Network(format!("Failed to set socket timeout: {}", e)))?;

        for server in &self.servers {
            for attempt in 0..=self.retries {
                match self.stun_request(&socket, server) {
                    Ok(result) => {
                        debug!(
                            "STUN discovery succeeded: {}:{} via {}",
                            result.public_ip, result.public_port, server
                        );
                        return Ok(result);
                    }
                    Err(e) => {
                        if attempt < self.retries {
                            trace!(
                                "STUN request to {} failed (attempt {}): {}, retrying",
                                server,
                                attempt + 1,
                                e
                            );
                        } else {
                            warn!(
                                "STUN request to {} failed after {} attempts: {}",
                                server,
                                self.retries + 1,
                                e
                            );
                        }
                    }
                }
            }
        }

        Err(ClientError::Network(
            "All STUN servers failed to respond".to_string(),
        ))
    }

    /// Discover public IP and port using an existing socket.
    ///
    /// This is useful when you want to discover the public address
    /// that would be used for a specific connection.
    ///
    /// Returns `ClientError::Network` immediately when no servers are
    /// configured (the default state).
    pub fn discover_with_socket(&self, socket: &UdpSocket) -> Result<StunResult, ClientError> {
        if self.servers.is_empty() {
            return Err(ClientError::Network(
                "STUN disabled: no servers configured (call with_servers to enable)".to_string(),
            ));
        }

        // Save original timeout
        let original_timeout = socket.read_timeout().ok().flatten();

        socket
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| ClientError::Network(format!("Failed to set socket timeout: {}", e)))?;

        let result = self.servers.iter().find_map(|server| {
            for attempt in 0..=self.retries {
                match self.stun_request(socket, server) {
                    Ok(result) => return Some(result),
                    Err(e) => {
                        trace!(
                            "STUN request to {} failed (attempt {}): {}",
                            server,
                            attempt + 1,
                            e
                        );
                    }
                }
            }
            None
        });

        // Restore original timeout
        if let Some(timeout) = original_timeout {
            let _ = socket.set_read_timeout(Some(timeout));
        } else {
            let _ = socket.set_read_timeout(None);
        }

        result.ok_or_else(|| ClientError::Network("All STUN servers failed to respond".to_string()))
    }

    /// Send a STUN binding request and parse the response.
    ///
    /// FIX-035: when the caller's socket is IPv4, refuse to talk to an
    /// IPv6 STUN server (and vice-versa). `ToSocketAddrs` happily returns
    /// the first address of either family for hostnames like
    /// `stun.l.google.com:19302` (often IPv6 first on modern hosts), and
    /// the kernel-level `send_to` then fails with a confusing
    /// `AddressNotSupported`. Filtering at the resolver matches what the
    /// kernel will accept and gives a cleaner error trail.
    fn stun_request(&self, socket: &UdpSocket, server: &str) -> Result<StunResult, ClientError> {
        let local_is_v4 = socket.local_addr().map(|a| a.is_ipv4()).unwrap_or(true);

        // Resolve server address, filtering by the socket's address family
        // so the send_to syscall does not bomb out on a v4↔v6 mismatch.
        let server_addr: SocketAddr = if let Ok(direct) = server.parse() {
            direct
        } else {
            let mut iter = std::net::ToSocketAddrs::to_socket_addrs(server).map_err(|e| {
                ClientError::Network(format!("Failed to resolve {}: {}", server, e))
            })?;
            iter.find(|addr| addr.is_ipv4() == local_is_v4)
                .ok_or_else(|| {
                    ClientError::Network(format!(
                        "No address-family-compatible STUN address found for {} (socket is {})",
                        server,
                        if local_is_v4 { "IPv4" } else { "IPv6" }
                    ))
                })?
        };

        if server_addr.is_ipv4() != local_is_v4 {
            return Err(ClientError::Network(format!(
                "STUN server {} resolved to {} but the local socket is {}",
                server,
                if server_addr.is_ipv4() {
                    "IPv4"
                } else {
                    "IPv6"
                },
                if local_is_v4 { "IPv4" } else { "IPv6" }
            )));
        }

        // Build STUN binding request
        let request = self.build_binding_request();

        // Send request
        socket
            .send_to(&request, server_addr)
            .map_err(|e| ClientError::Network(format!("Failed to send STUN request: {}", e)))?;

        // Receive response
        let mut buf = [0u8; 1024];
        let (len, _) = socket
            .recv_from(&mut buf)
            .map_err(|e| ClientError::Network(format!("Failed to receive STUN response: {}", e)))?;

        // Parse response
        self.parse_binding_response(&buf[..len], &request[8..20], server)
    }

    /// Build a STUN binding request.
    fn build_binding_request(&self) -> Vec<u8> {
        let mut request = Vec::with_capacity(STUN_HEADER_SIZE);

        // Message type: Binding Request
        request.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());

        // Message length: 0 (no attributes)
        request.extend_from_slice(&0u16.to_be_bytes());

        // Magic cookie
        request.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());

        // Transaction ID (96 bits = 12 bytes of random data)
        let mut transaction_id = [0u8; 12];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut transaction_id);
        request.extend_from_slice(&transaction_id);

        request
    }

    /// Parse a STUN binding response.
    fn parse_binding_response(
        &self,
        data: &[u8],
        transaction_id: &[u8],
        server: &str,
    ) -> Result<StunResult, ClientError> {
        if data.len() < STUN_HEADER_SIZE {
            return Err(ClientError::Network("STUN response too short".to_string()));
        }

        // Parse header
        let msg_type = u16::from_be_bytes([data[0], data[1]]);
        let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        let magic = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        // Verify magic cookie
        if magic != STUN_MAGIC_COOKIE {
            return Err(ClientError::Network(
                "Invalid STUN magic cookie".to_string(),
            ));
        }

        // Verify transaction ID
        if &data[8..20] != transaction_id {
            return Err(ClientError::Network(
                "STUN transaction ID mismatch".to_string(),
            ));
        }

        // Check message type
        match msg_type {
            STUN_BINDING_RESPONSE => {}
            STUN_BINDING_ERROR_RESPONSE => {
                return Err(ClientError::Network(
                    "STUN server returned error response".to_string(),
                ));
            }
            _ => {
                return Err(ClientError::Network(format!(
                    "Unexpected STUN message type: 0x{:04x}",
                    msg_type
                )));
            }
        }

        // Parse attributes
        let attrs_end = STUN_HEADER_SIZE + msg_len;
        if data.len() < attrs_end {
            return Err(ClientError::Network("STUN response truncated".to_string()));
        }

        let mut offset = STUN_HEADER_SIZE;
        while offset + 4 <= attrs_end {
            let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;

            if offset + attr_len > attrs_end {
                break;
            }

            match attr_type {
                STUN_ATTR_XOR_MAPPED_ADDRESS => {
                    // XOR-MAPPED-ADDRESS (preferred, RFC 5389)
                    // Pass magic cookie (4 bytes) + transaction ID (12 bytes) for IPv6 XOR
                    if let Some((ip, port)) = self
                        .parse_xor_mapped_address(&data[offset..offset + attr_len], &data[4..20])
                    {
                        return Ok(StunResult {
                            public_ip: ip,
                            public_port: port,
                            server: server.to_string(),
                        });
                    }
                }
                STUN_ATTR_MAPPED_ADDRESS => {
                    // MAPPED-ADDRESS (fallback, RFC 3489)
                    if let Some((ip, port)) =
                        self.parse_mapped_address(&data[offset..offset + attr_len])
                    {
                        return Ok(StunResult {
                            public_ip: ip,
                            public_port: port,
                            server: server.to_string(),
                        });
                    }
                }
                _ => {
                    // Skip unknown attributes
                }
            }

            // Attributes are padded to 4-byte boundary
            offset += (attr_len + 3) & !3;
        }

        Err(ClientError::Network(
            "No mapped address in STUN response".to_string(),
        ))
    }

    /// Parse XOR-MAPPED-ADDRESS attribute (RFC 5389).
    ///
    /// `xor_key` must be 16 bytes: magic cookie (4 bytes) + transaction ID (12 bytes).
    fn parse_xor_mapped_address(&self, data: &[u8], xor_key: &[u8]) -> Option<(IpAddr, u16)> {
        if data.len() < 8 || xor_key.len() < 16 {
            return None;
        }

        let family = data[1];
        let xor_port = u16::from_be_bytes([data[2], data[3]]);
        let port = xor_port ^ ((STUN_MAGIC_COOKIE >> 16) as u16);

        match family {
            0x01 => {
                // IPv4: XOR with magic cookie only
                let xor_ip = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                let ip = xor_ip ^ STUN_MAGIC_COOKIE;
                Some((IpAddr::V4(Ipv4Addr::from(ip)), port))
            }
            0x02 => {
                // IPv6: XOR with magic cookie (4 bytes) + transaction ID (12 bytes)
                // RFC 5389 Section 15.2: X-Address is computed by XOR'ing the
                // mapped IP address with the concatenation of the magic cookie and
                // the 96-bit transaction ID.
                if data.len() < 20 {
                    return None;
                }
                let mut ip_bytes = [0u8; 16];
                for i in 0..16 {
                    ip_bytes[i] = data[4 + i] ^ xor_key[i];
                }
                Some((IpAddr::V6(Ipv6Addr::from(ip_bytes)), port))
            }
            _ => None,
        }
    }

    /// Parse MAPPED-ADDRESS attribute (RFC 3489).
    fn parse_mapped_address(&self, data: &[u8]) -> Option<(IpAddr, u16)> {
        if data.len() < 8 {
            return None;
        }

        let family = data[1];
        let port = u16::from_be_bytes([data[2], data[3]]);

        match family {
            0x01 => {
                // IPv4
                let ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
                Some((IpAddr::V4(ip), port))
            }
            0x02 => {
                // IPv6
                if data.len() < 20 {
                    return None;
                }
                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&data[4..20]);
                Some((IpAddr::V6(Ipv6Addr::from(ip_bytes)), port))
            }
            _ => None,
        }
    }
}

/// NAT type detection result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatType {
    /// No NAT detected (public IP).
    None,
    /// Full cone NAT (any external host can send packets).
    FullCone,
    /// Address-restricted cone NAT.
    AddressRestrictedCone,
    /// Port-restricted cone NAT.
    PortRestrictedCone,
    /// Symmetric NAT (hardest to traverse).
    Symmetric,
    /// Detection failed or unknown.
    Unknown,
}

impl std::fmt::Display for NatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatType::None => write!(f, "No NAT"),
            NatType::FullCone => write!(f, "Full Cone"),
            NatType::AddressRestrictedCone => write!(f, "Address-Restricted Cone"),
            NatType::PortRestrictedCone => write!(f, "Port-Restricted Cone"),
            NatType::Symmetric => write!(f, "Symmetric"),
            NatType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Information about the client's NAT environment.
#[derive(Clone, Debug)]
pub struct NatInfo {
    /// Discovered public endpoint.
    pub public_endpoint: Option<StunResult>,
    /// Detected NAT type.
    pub nat_type: NatType,
    /// Local address used for discovery.
    pub local_addr: Option<SocketAddr>,
}

impl NatInfo {
    /// Check if NAT traversal is likely to succeed for P2P.
    pub fn can_hole_punch(&self) -> bool {
        matches!(
            self.nat_type,
            NatType::None
                | NatType::FullCone
                | NatType::AddressRestrictedCone
                | NatType::PortRestrictedCone
        )
    }

    /// Check if we're behind symmetric NAT (hardest case).
    pub fn is_symmetric(&self) -> bool {
        self.nat_type == NatType::Symmetric
    }
}

/// Discover NAT information including public IP and NAT type.
///
/// **No-op by default.** [`StunClient::new`] yields an empty server list
/// (see the module-level docs and `DEFAULT_STUN_SERVERS`), so this
/// function returns a `NatInfo { public_endpoint: None, nat_type:
/// Unknown, local_addr: None }` without sending any packet. To make it
/// do real STUN work, callers should construct a `StunClient` with
/// [`StunClient::with_servers`] and a trusted server list (typically
/// reached through the established VPN tunnel) and call `discover()`
/// directly.
pub fn discover_nat_info() -> NatInfo {
    let client = StunClient::new();

    if !client.is_enabled() {
        debug!(
            "discover_nat_info called with no STUN servers configured; \
             returning empty NatInfo (this is the default — see nat.rs module docs)"
        );
        return NatInfo {
            public_endpoint: None,
            nat_type: NatType::Unknown,
            local_addr: None,
        };
    }

    match client.discover() {
        Ok(result) => NatInfo {
            public_endpoint: Some(result),
            nat_type: NatType::Unknown, // Full NAT type detection requires multiple servers
            local_addr: None,
        },
        Err(e) => {
            warn!("NAT discovery failed: {}", e);
            NatInfo {
                public_endpoint: None,
                nat_type: NatType::Unknown,
                local_addr: None,
            }
        }
    }
}

// ============================================================================
// UDP Hole Punching
// ============================================================================

/// UDP hole punching configuration.
#[derive(Clone, Debug)]
pub struct HolePunchConfig {
    /// Number of punch attempts.
    pub attempts: u32,
    /// Delay between punch attempts.
    pub attempt_delay: Duration,
    /// Timeout waiting for response.
    pub timeout: Duration,
    /// Port prediction range for symmetric NAT.
    pub port_prediction_range: u16,
}

impl Default for HolePunchConfig {
    fn default() -> Self {
        Self {
            attempts: 10,
            attempt_delay: Duration::from_millis(100),
            timeout: Duration::from_secs(5),
            port_prediction_range: 10,
        }
    }
}

/// Result of a hole punch attempt.
#[derive(Clone, Debug)]
pub struct HolePunchResult {
    /// Whether the hole punch succeeded.
    pub success: bool,
    /// The remote endpoint that was reached.
    pub remote_endpoint: Option<SocketAddr>,
    /// Number of attempts made.
    pub attempts_made: u32,
    /// Round-trip time if successful.
    pub rtt: Option<Duration>,
}

/// Peer information for hole punching.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    /// Peer's public endpoint (from STUN).
    pub public_endpoint: SocketAddr,
    /// Peer's local/private endpoint (for LAN scenarios).
    pub private_endpoint: Option<SocketAddr>,
    /// Peer's NAT type.
    pub nat_type: NatType,
    /// Unique peer identifier.
    pub peer_id: [u8; 16],
}

impl PeerInfo {
    /// Create new peer info.
    pub fn new(public_endpoint: SocketAddr, peer_id: [u8; 16]) -> Self {
        Self {
            public_endpoint,
            private_endpoint: None,
            nat_type: NatType::Unknown,
            peer_id,
        }
    }

    /// Create with full information.
    pub fn with_details(
        public_endpoint: SocketAddr,
        private_endpoint: Option<SocketAddr>,
        nat_type: NatType,
        peer_id: [u8; 16],
    ) -> Self {
        Self {
            public_endpoint,
            private_endpoint,
            nat_type,
            peer_id,
        }
    }
}

/// Hole punch message types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HolePunchMessageType {
    /// Initial punch packet.
    Punch = 1,
    /// Acknowledgment of received punch.
    PunchAck = 2,
    /// Keepalive to maintain the hole.
    Keepalive = 3,
}

/// A hole punch message.
#[derive(Clone, Debug)]
pub struct HolePunchMessage {
    /// Message type.
    pub msg_type: HolePunchMessageType,
    /// Sender's peer ID.
    pub peer_id: [u8; 16],
    /// Sequence number.
    pub sequence: u32,
    /// Timestamp (for RTT calculation).
    pub timestamp: u64,
}

impl HolePunchMessage {
    /// Create a new punch message.
    pub fn punch(peer_id: [u8; 16], sequence: u32) -> Self {
        Self {
            msg_type: HolePunchMessageType::Punch,
            peer_id,
            sequence,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        }
    }

    /// Create an acknowledgment message.
    pub fn ack(peer_id: [u8; 16], sequence: u32, original_timestamp: u64) -> Self {
        Self {
            msg_type: HolePunchMessageType::PunchAck,
            peer_id,
            sequence,
            timestamp: original_timestamp,
        }
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(29);
        buf.push(self.msg_type as u8);
        buf.extend_from_slice(&self.peer_id);
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf
    }

    /// Parse from bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 29 {
            return None;
        }

        let msg_type = match data[0] {
            1 => HolePunchMessageType::Punch,
            2 => HolePunchMessageType::PunchAck,
            3 => HolePunchMessageType::Keepalive,
            _ => return None,
        };

        let mut peer_id = [0u8; 16];
        peer_id.copy_from_slice(&data[1..17]);

        let sequence = u32::from_be_bytes([data[17], data[18], data[19], data[20]]);
        let timestamp = u64::from_be_bytes([
            data[21], data[22], data[23], data[24], data[25], data[26], data[27], data[28],
        ]);

        Some(Self {
            msg_type,
            peer_id,
            sequence,
            timestamp,
        })
    }
}

/// UDP hole puncher for establishing P2P connections.
pub struct HolePuncher {
    /// Configuration.
    config: HolePunchConfig,
    /// Our peer ID.
    our_peer_id: [u8; 16],
    /// Our NAT info.
    our_nat_info: Option<NatInfo>,
}

impl HolePuncher {
    /// Create a new hole puncher.
    pub fn new(our_peer_id: [u8; 16]) -> Self {
        Self {
            config: HolePunchConfig::default(),
            our_peer_id,
            our_nat_info: None,
        }
    }

    /// Create with custom configuration.
    pub fn with_config(our_peer_id: [u8; 16], config: HolePunchConfig) -> Self {
        Self {
            config,
            our_peer_id,
            our_nat_info: None,
        }
    }

    /// Discover our NAT info.
    pub fn discover_nat(&mut self) -> &NatInfo {
        // Use get_or_insert_with for idiomatic lazy initialization
        self.our_nat_info.get_or_insert_with(discover_nat_info)
    }

    /// Get our NAT info if already discovered.
    pub fn nat_info(&self) -> Option<&NatInfo> {
        self.our_nat_info.as_ref()
    }

    /// Attempt to punch a hole to a peer.
    ///
    /// This performs simultaneous hole punching:
    /// 1. Both peers should call this at roughly the same time (coordinated via rendezvous)
    /// 2. Sends punch packets to the peer's public endpoint
    /// 3. Waits for acknowledgment
    ///
    /// For symmetric NAT, also tries port prediction.
    pub fn punch(&self, socket: &UdpSocket, peer: &PeerInfo) -> HolePunchResult {
        debug!(
            "Starting hole punch to peer {:02x}{:02x}{:02x}{:02x}... at {}",
            peer.peer_id[0],
            peer.peer_id[1],
            peer.peer_id[2],
            peer.peer_id[3],
            peer.public_endpoint
        );

        // Set socket timeout
        let _ = socket.set_read_timeout(Some(self.config.timeout));
        let _ = socket.set_write_timeout(Some(Duration::from_secs(1)));

        let mut attempts_made = 0;
        let start_time = std::time::Instant::now();

        // Generate target endpoints (for symmetric NAT, try port prediction)
        let endpoints = self.generate_punch_endpoints(peer);

        for attempt in 0..self.config.attempts {
            attempts_made = attempt + 1;

            // Send punch to all candidate endpoints
            for (idx, endpoint) in endpoints.iter().enumerate() {
                let msg = HolePunchMessage::punch(self.our_peer_id, attempt);
                let data = msg.to_bytes();

                if let Err(e) = socket.send_to(&data, endpoint) {
                    trace!("Failed to send punch to {}: {}", endpoint, e);
                    continue;
                }

                if idx == 0 {
                    debug!(
                        "Sent punch {} to {} (+{} candidates)",
                        attempt,
                        endpoint,
                        endpoints.len() - 1
                    );
                }
            }

            // Wait for response
            let mut buf = [0u8; 64];
            let deadline = std::time::Instant::now() + self.config.attempt_delay;

            while std::time::Instant::now() < deadline {
                match socket.recv_from(&mut buf) {
                    Ok((len, from)) => {
                        if let Some(msg) = HolePunchMessage::from_bytes(&buf[..len]) {
                            // Check if it's from our target peer
                            if msg.peer_id == peer.peer_id {
                                match msg.msg_type {
                                    HolePunchMessageType::Punch => {
                                        // Received a punch from peer, send ack
                                        debug!("Received punch from peer at {}", from);
                                        let ack = HolePunchMessage::ack(
                                            self.our_peer_id,
                                            msg.sequence,
                                            msg.timestamp,
                                        );
                                        let _ = socket.send_to(&ack.to_bytes(), from);
                                    }
                                    HolePunchMessageType::PunchAck => {
                                        // Success! Calculate RTT
                                        let now_ms = std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_millis()
                                            as u64;
                                        let rtt_ms = now_ms.saturating_sub(msg.timestamp);

                                        debug!(
                                            "Hole punch succeeded! Remote: {}, RTT: {}ms",
                                            from, rtt_ms
                                        );

                                        return HolePunchResult {
                                            success: true,
                                            remote_endpoint: Some(from),
                                            attempts_made,
                                            rtt: Some(Duration::from_millis(rtt_ms)),
                                        };
                                    }
                                    HolePunchMessageType::Keepalive => {
                                        trace!("Received keepalive from {}", from);
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        if e.kind() != std::io::ErrorKind::WouldBlock
                            && e.kind() != std::io::ErrorKind::TimedOut
                        {
                            trace!("Receive error: {}", e);
                        }
                    }
                }

                // Small sleep to avoid busy loop
                std::thread::sleep(Duration::from_millis(10));
            }

            // Check total timeout
            if start_time.elapsed() >= self.config.timeout {
                break;
            }
        }

        debug!("Hole punch failed after {} attempts", attempts_made);

        HolePunchResult {
            success: false,
            remote_endpoint: None,
            attempts_made,
            rtt: None,
        }
    }

    /// Generate candidate endpoints for hole punching.
    ///
    /// For symmetric NAT, includes port predictions.
    fn generate_punch_endpoints(&self, peer: &PeerInfo) -> Vec<SocketAddr> {
        let mut endpoints = Vec::new();

        // Always try the reported public endpoint
        endpoints.push(peer.public_endpoint);

        // If peer is behind symmetric NAT, try port prediction
        if peer.nat_type == NatType::Symmetric {
            let base_port = peer.public_endpoint.port();
            let ip = peer.public_endpoint.ip();

            // Try ports around the known port (common for sequential allocation)
            for offset in 1..=self.config.port_prediction_range {
                if let Some(port) = base_port.checked_add(offset) {
                    endpoints.push(SocketAddr::new(ip, port));
                }
                if let Some(port) = base_port.checked_sub(offset) {
                    endpoints.push(SocketAddr::new(ip, port));
                }
            }
        }

        // If private endpoint is provided (same LAN), try it
        if let Some(private) = peer.private_endpoint {
            endpoints.push(private);
        }

        endpoints
    }

    /// Send a keepalive to maintain the punched hole.
    pub fn send_keepalive(&self, socket: &UdpSocket, remote: SocketAddr) -> bool {
        let msg = HolePunchMessage {
            msg_type: HolePunchMessageType::Keepalive,
            peer_id: self.our_peer_id,
            sequence: 0,
            timestamp: 0,
        };

        socket.send_to(&msg.to_bytes(), remote).is_ok()
    }
}

/// Rendezvous information exchanged between peers.
#[derive(Clone, Debug)]
pub struct RendezvousInfo {
    /// Our peer ID.
    pub peer_id: [u8; 16],
    /// Our public endpoint.
    pub public_endpoint: SocketAddr,
    /// Our private/local endpoint.
    pub private_endpoint: Option<SocketAddr>,
    /// Our NAT type.
    pub nat_type: NatType,
    /// Timestamp when this info was generated.
    pub timestamp: u64,
}

impl RendezvousInfo {
    /// Create rendezvous info from NAT discovery.
    pub fn from_nat_info(peer_id: [u8; 16], nat_info: &NatInfo) -> Option<Self> {
        let public_endpoint = nat_info.public_endpoint.as_ref()?.socket_addr();

        Some(Self {
            peer_id,
            public_endpoint,
            private_endpoint: nat_info.local_addr,
            nat_type: nat_info.nat_type,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        })
    }

    /// Convert to peer info for hole punching.
    pub fn to_peer_info(&self) -> PeerInfo {
        PeerInfo::with_details(
            self.public_endpoint,
            self.private_endpoint,
            self.nat_type,
            self.peer_id,
        )
    }

    /// Serialize to bytes for transmission.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);

        // Peer ID (16 bytes)
        buf.extend_from_slice(&self.peer_id);

        // Public endpoint
        match self.public_endpoint {
            SocketAddr::V4(addr) => {
                buf.push(4); // IPv4
                buf.extend_from_slice(&addr.ip().octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
            SocketAddr::V6(addr) => {
                buf.push(6); // IPv6
                buf.extend_from_slice(&addr.ip().octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
        }

        // Private endpoint (optional)
        if let Some(private) = self.private_endpoint {
            buf.push(1); // Has private endpoint
            match private {
                SocketAddr::V4(addr) => {
                    buf.push(4);
                    buf.extend_from_slice(&addr.ip().octets());
                    buf.extend_from_slice(&addr.port().to_be_bytes());
                }
                SocketAddr::V6(addr) => {
                    buf.push(6);
                    buf.extend_from_slice(&addr.ip().octets());
                    buf.extend_from_slice(&addr.port().to_be_bytes());
                }
            }
        } else {
            buf.push(0); // No private endpoint
        }

        // NAT type
        buf.push(self.nat_type as u8);

        // Timestamp
        buf.extend_from_slice(&self.timestamp.to_be_bytes());

        buf
    }

    /// Parse from bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 24 {
            return None;
        }

        let mut offset = 0;

        // Peer ID
        let mut peer_id = [0u8; 16];
        peer_id.copy_from_slice(&data[offset..offset + 16]);
        offset += 16;

        // Public endpoint
        let public_endpoint = Self::parse_endpoint(data, &mut offset)?;

        // Private endpoint
        let private_endpoint = if data[offset] == 1 {
            offset += 1;
            Some(Self::parse_endpoint(data, &mut offset)?)
        } else {
            offset += 1;
            None
        };

        // NAT type
        if offset >= data.len() {
            return None;
        }
        let nat_type = match data[offset] {
            0 => NatType::None,
            1 => NatType::FullCone,
            2 => NatType::AddressRestrictedCone,
            3 => NatType::PortRestrictedCone,
            4 => NatType::Symmetric,
            _ => NatType::Unknown,
        };
        offset += 1;

        // Timestamp
        if offset + 8 > data.len() {
            return None;
        }
        let timestamp = u64::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);

        Some(Self {
            peer_id,
            public_endpoint,
            private_endpoint,
            nat_type,
            timestamp,
        })
    }

    fn parse_endpoint(data: &[u8], offset: &mut usize) -> Option<SocketAddr> {
        if *offset >= data.len() {
            return None;
        }

        let ip_version = data[*offset];
        *offset += 1;

        match ip_version {
            4 => {
                if *offset + 6 > data.len() {
                    return None;
                }
                let ip = Ipv4Addr::new(
                    data[*offset],
                    data[*offset + 1],
                    data[*offset + 2],
                    data[*offset + 3],
                );
                let port = u16::from_be_bytes([data[*offset + 4], data[*offset + 5]]);
                *offset += 6;
                Some(SocketAddr::new(IpAddr::V4(ip), port))
            }
            6 => {
                if *offset + 18 > data.len() {
                    return None;
                }
                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&data[*offset..*offset + 16]);
                let ip = Ipv6Addr::from(ip_bytes);
                let port = u16::from_be_bytes([data[*offset + 16], data[*offset + 17]]);
                *offset += 18;
                Some(SocketAddr::new(IpAddr::V6(ip), port))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stun_client_creation() {
        // Default state is *disabled*: empty server list, discover()
        // fails fast without sending any packet. See
        // `DEFAULT_STUN_SERVERS` for the rationale.
        let client = StunClient::new();
        assert!(client.servers.is_empty(), "default must be disabled");
        assert!(!client.is_enabled());
        assert_eq!(client.timeout, Duration::from_secs(3));
        assert_eq!(client.retries, 2);
    }

    #[test]
    fn test_stun_client_default_discover_returns_disabled_error() {
        let client = StunClient::new();
        let err = client.discover().expect_err("must fail closed");
        let msg = err.to_string();
        assert!(
            msg.contains("STUN disabled"),
            "error must mention disabled state, got: {msg}"
        );
    }

    #[test]
    fn test_stun_client_builder() {
        let client = StunClient::new()
            .with_servers(vec!["custom.stun.server:3478".to_string()])
            .with_timeout(Duration::from_secs(5))
            .with_retries(3);

        assert_eq!(client.servers.len(), 1);
        assert!(client.is_enabled());
        assert_eq!(client.timeout, Duration::from_secs(5));
        assert_eq!(client.retries, 3);
    }

    #[test]
    fn test_build_binding_request() {
        let client = StunClient::new();
        let request = client.build_binding_request();

        assert_eq!(request.len(), STUN_HEADER_SIZE);

        // Verify message type
        let msg_type = u16::from_be_bytes([request[0], request[1]]);
        assert_eq!(msg_type, STUN_BINDING_REQUEST);

        // Verify message length
        let msg_len = u16::from_be_bytes([request[2], request[3]]);
        assert_eq!(msg_len, 0);

        // Verify magic cookie
        let magic = u32::from_be_bytes([request[4], request[5], request[6], request[7]]);
        assert_eq!(magic, STUN_MAGIC_COOKIE);
    }

    #[test]
    fn test_nat_type_display() {
        assert_eq!(format!("{}", NatType::None), "No NAT");
        assert_eq!(format!("{}", NatType::Symmetric), "Symmetric");
    }

    #[test]
    fn test_nat_info_can_hole_punch() {
        let info = NatInfo {
            public_endpoint: None,
            nat_type: NatType::FullCone,
            local_addr: None,
        };
        assert!(info.can_hole_punch());

        let info_symmetric = NatInfo {
            public_endpoint: None,
            nat_type: NatType::Symmetric,
            local_addr: None,
        };
        assert!(!info_symmetric.can_hole_punch());
    }

    // Note: Live STUN tests are skipped in CI as they require network access
    #[test]
    #[ignore = "requires network access to STUN servers"]
    fn test_stun_discovery_live() {
        let client = StunClient::new();
        let result = client.discover();
        assert!(result.is_ok(), "STUN discovery should succeed");

        let result = result.unwrap();
        println!(
            "Public endpoint: {}:{}",
            result.public_ip, result.public_port
        );
        assert!(result.public_port > 0);
    }

    // ============================================================================
    // Hole Punching Tests
    // ============================================================================

    #[test]
    fn test_hole_punch_config_default() {
        let config = HolePunchConfig::default();
        assert_eq!(config.attempts, 10);
        assert_eq!(config.timeout, Duration::from_secs(5));
        assert_eq!(config.attempt_delay, Duration::from_millis(100));
        assert_eq!(config.port_prediction_range, 10);
    }

    #[test]
    fn test_hole_punch_config_builder() {
        let config = HolePunchConfig {
            attempts: 5,
            timeout: Duration::from_secs(10),
            attempt_delay: Duration::from_millis(200),
            port_prediction_range: 5,
        };
        assert_eq!(config.attempts, 5);
        assert_eq!(config.timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_hole_punch_result_success() {
        let result = HolePunchResult {
            success: true,
            remote_endpoint: Some("192.168.1.1:12345".parse().unwrap()),
            attempts_made: 3,
            rtt: Some(Duration::from_millis(50)),
        };
        assert!(result.success);
        assert_eq!(result.attempts_made, 3);
        assert_eq!(result.rtt, Some(Duration::from_millis(50)));
    }

    #[test]
    fn test_hole_punch_result_failure() {
        let result = HolePunchResult {
            success: false,
            remote_endpoint: None,
            attempts_made: 10,
            rtt: None,
        };
        assert!(!result.success);
        assert!(result.remote_endpoint.is_none());
    }

    #[test]
    fn test_peer_info_new() {
        let peer_id = [1u8; 16];
        let endpoint: SocketAddr = "203.0.113.50:51820".parse().unwrap();
        let peer = PeerInfo::new(endpoint, peer_id);

        assert_eq!(peer.public_endpoint, endpoint);
        assert_eq!(peer.peer_id, peer_id);
        assert!(peer.private_endpoint.is_none());
        assert_eq!(peer.nat_type, NatType::Unknown);
    }

    #[test]
    fn test_peer_info_with_details() {
        let peer_id = [2u8; 16];
        let public: SocketAddr = "203.0.113.50:51820".parse().unwrap();
        let private: SocketAddr = "192.168.1.100:51820".parse().unwrap();

        let peer = PeerInfo::with_details(public, Some(private), NatType::FullCone, peer_id);

        assert_eq!(peer.public_endpoint, public);
        assert_eq!(peer.private_endpoint, Some(private));
        assert_eq!(peer.nat_type, NatType::FullCone);
        assert_eq!(peer.peer_id, peer_id);
    }

    #[test]
    fn test_hole_punch_message_punch() {
        let peer_id = [3u8; 16];
        let msg = HolePunchMessage::punch(peer_id, 5);

        assert_eq!(msg.msg_type, HolePunchMessageType::Punch);
        assert_eq!(msg.peer_id, peer_id);
        assert_eq!(msg.sequence, 5);
        assert!(msg.timestamp > 0);
    }

    #[test]
    fn test_hole_punch_message_ack() {
        let peer_id = [4u8; 16];
        let original_ts = 1234567890u64;
        let msg = HolePunchMessage::ack(peer_id, 10, original_ts);

        assert_eq!(msg.msg_type, HolePunchMessageType::PunchAck);
        assert_eq!(msg.peer_id, peer_id);
        assert_eq!(msg.sequence, 10);
        assert_eq!(msg.timestamp, original_ts);
    }

    #[test]
    fn test_hole_punch_message_serialization() {
        let peer_id = [5u8; 16];
        let original = HolePunchMessage::punch(peer_id, 42);
        let bytes = original.to_bytes();

        assert_eq!(bytes.len(), 29);
        assert_eq!(bytes[0], HolePunchMessageType::Punch as u8);

        let parsed = HolePunchMessage::from_bytes(&bytes).expect("Should parse");
        assert_eq!(parsed.msg_type, original.msg_type);
        assert_eq!(parsed.peer_id, original.peer_id);
        assert_eq!(parsed.sequence, original.sequence);
        assert_eq!(parsed.timestamp, original.timestamp);
    }

    #[test]
    fn test_hole_punch_message_parse_invalid() {
        // Too short
        let short = vec![1u8; 10];
        assert!(HolePunchMessage::from_bytes(&short).is_none());

        // Invalid message type
        let mut invalid = vec![0u8; 29];
        invalid[0] = 99; // Invalid type
        assert!(HolePunchMessage::from_bytes(&invalid).is_none());
    }

    #[test]
    fn test_hole_puncher_creation() {
        let peer_id = [6u8; 16];
        let puncher = HolePuncher::new(peer_id);

        assert!(puncher.nat_info().is_none());
    }

    #[test]
    fn test_hole_puncher_with_config() {
        let peer_id = [7u8; 16];
        let config = HolePunchConfig {
            attempts: 3,
            timeout: Duration::from_secs(5),
            attempt_delay: Duration::from_millis(100),
            port_prediction_range: 5,
        };
        let puncher = HolePuncher::with_config(peer_id, config);

        assert!(puncher.nat_info().is_none());
    }

    #[test]
    fn test_rendezvous_info_serialization_ipv4() {
        let peer_id = [8u8; 16];
        let public: SocketAddr = "203.0.113.50:51820".parse().unwrap();
        let private: SocketAddr = "192.168.1.100:51820".parse().unwrap();

        let info = RendezvousInfo {
            peer_id,
            public_endpoint: public,
            private_endpoint: Some(private),
            nat_type: NatType::FullCone,
            timestamp: 1234567890,
        };

        let bytes = info.to_bytes();
        let parsed = RendezvousInfo::from_bytes(&bytes).expect("Should parse");

        assert_eq!(parsed.peer_id, peer_id);
        assert_eq!(parsed.public_endpoint, public);
        assert_eq!(parsed.private_endpoint, Some(private));
        assert_eq!(parsed.nat_type, NatType::FullCone);
        assert_eq!(parsed.timestamp, 1234567890);
    }

    #[test]
    fn test_rendezvous_info_serialization_ipv6() {
        let peer_id = [9u8; 16];
        let public: SocketAddr = "[2001:db8::1]:51820".parse().unwrap();

        let info = RendezvousInfo {
            peer_id,
            public_endpoint: public,
            private_endpoint: None,
            nat_type: NatType::None,
            timestamp: 9876543210,
        };

        let bytes = info.to_bytes();
        let parsed = RendezvousInfo::from_bytes(&bytes).expect("Should parse");

        assert_eq!(parsed.peer_id, peer_id);
        assert_eq!(parsed.public_endpoint, public);
        assert!(parsed.private_endpoint.is_none());
        assert_eq!(parsed.nat_type, NatType::None);
    }

    #[test]
    fn test_rendezvous_info_to_peer_info() {
        let peer_id = [10u8; 16];
        let public: SocketAddr = "203.0.113.50:51820".parse().unwrap();
        let private: SocketAddr = "10.0.0.5:51820".parse().unwrap();

        let info = RendezvousInfo {
            peer_id,
            public_endpoint: public,
            private_endpoint: Some(private),
            nat_type: NatType::AddressRestrictedCone,
            timestamp: 0,
        };

        let peer = info.to_peer_info();
        assert_eq!(peer.peer_id, peer_id);
        assert_eq!(peer.public_endpoint, public);
        assert_eq!(peer.private_endpoint, Some(private));
        assert_eq!(peer.nat_type, NatType::AddressRestrictedCone);
    }

    #[test]
    fn test_rendezvous_info_from_nat_info() {
        let peer_id = [11u8; 16];
        let stun_result = StunResult {
            public_ip: "203.0.113.100".parse().unwrap(),
            public_port: 12345,
            server: "stun.example.com".to_string(),
        };
        let nat_info = NatInfo {
            public_endpoint: Some(stun_result),
            nat_type: NatType::PortRestrictedCone,
            local_addr: Some("192.168.1.50:54321".parse().unwrap()),
        };

        let rendezvous = RendezvousInfo::from_nat_info(peer_id, &nat_info).expect("Should create");

        assert_eq!(rendezvous.peer_id, peer_id);
        assert_eq!(
            rendezvous.public_endpoint,
            "203.0.113.100:12345".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            rendezvous.private_endpoint,
            Some("192.168.1.50:54321".parse().unwrap())
        );
        assert_eq!(rendezvous.nat_type, NatType::PortRestrictedCone);
    }

    #[test]
    fn test_rendezvous_info_from_nat_info_no_endpoint() {
        let peer_id = [12u8; 16];
        let nat_info = NatInfo {
            public_endpoint: None,
            nat_type: NatType::Unknown,
            local_addr: None,
        };

        let result = RendezvousInfo::from_nat_info(peer_id, &nat_info);
        assert!(result.is_none());
    }

    #[test]
    fn test_all_nat_types_serialization() {
        let peer_id = [13u8; 16];
        let public: SocketAddr = "1.2.3.4:5000".parse().unwrap();

        for nat_type in [
            NatType::None,
            NatType::FullCone,
            NatType::AddressRestrictedCone,
            NatType::PortRestrictedCone,
            NatType::Symmetric,
            NatType::Unknown,
        ] {
            let info = RendezvousInfo {
                peer_id,
                public_endpoint: public,
                private_endpoint: None,
                nat_type,
                timestamp: 0,
            };

            let bytes = info.to_bytes();
            let parsed = RendezvousInfo::from_bytes(&bytes).expect("Should parse");
            assert_eq!(
                parsed.nat_type, nat_type,
                "NAT type {:?} roundtrip failed",
                nat_type
            );
        }
    }

    // Note: Live hole punching test requires two networked peers
    #[test]
    #[ignore = "requires two networked peers for hole punching"]
    fn test_hole_punch_live() {
        let peer_id = [14u8; 16];
        let mut puncher = HolePuncher::new(peer_id);

        // Discover our NAT first
        let nat_info = puncher.discover_nat();
        println!("Our NAT type: {}", nat_info.nat_type);

        if let Some(endpoint) = &nat_info.public_endpoint {
            println!(
                "Our public endpoint: {}:{}",
                endpoint.public_ip, endpoint.public_port
            );
        }
    }

    // ============================================================================
    // STUN Parsing Tests
    // ============================================================================

    #[test]
    fn test_parse_xor_mapped_address_ipv4() {
        let client = StunClient::new();

        // Build IPv4 XOR-MAPPED-ADDRESS attribute
        // Family: 0x01 (IPv4), Port: 12345 XOR'd with magic cookie
        let port = 12345u16;
        let xor_port = port ^ ((STUN_MAGIC_COOKIE >> 16) as u16);

        let ip = Ipv4Addr::new(192, 0, 2, 1);
        let ip_u32: u32 = u32::from(ip);
        let xor_ip = ip_u32 ^ STUN_MAGIC_COOKIE;

        let mut data = vec![0u8, 0x01]; // Reserved, Family
        data.extend_from_slice(&xor_port.to_be_bytes());
        data.extend_from_slice(&xor_ip.to_be_bytes());

        let xor_key = [0u8; 16]; // Not used for IPv4
        let result = client.parse_xor_mapped_address(&data, &xor_key);

        assert!(result.is_some());
        let (parsed_ip, parsed_port) = result.unwrap();
        assert_eq!(parsed_ip, IpAddr::V4(ip));
        assert_eq!(parsed_port, port);
    }

    #[test]
    fn test_parse_xor_mapped_address_ipv6() {
        let client = StunClient::new();

        let port = 54321u16;
        let xor_port = port ^ ((STUN_MAGIC_COOKIE >> 16) as u16);

        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

        // XOR key: magic cookie + transaction ID
        let mut xor_key = vec![];
        xor_key.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        xor_key.extend_from_slice(&[0u8; 12]); // Transaction ID

        // XOR the IPv6 address
        let ip_bytes = ip.octets();
        let mut xor_ip = [0u8; 16];
        for i in 0..16 {
            xor_ip[i] = ip_bytes[i] ^ xor_key[i];
        }

        let mut data = vec![0u8, 0x02]; // Reserved, Family (IPv6)
        data.extend_from_slice(&xor_port.to_be_bytes());
        data.extend_from_slice(&xor_ip);

        let result = client.parse_xor_mapped_address(&data, &xor_key);

        assert!(result.is_some());
        let (parsed_ip, parsed_port) = result.unwrap();
        assert_eq!(parsed_ip, IpAddr::V6(ip));
        assert_eq!(parsed_port, port);
    }

    #[test]
    fn test_parse_xor_mapped_address_invalid() {
        let client = StunClient::new();
        let xor_key = [0u8; 16];

        // Too short
        assert!(
            client
                .parse_xor_mapped_address(&[0u8; 4], &xor_key)
                .is_none()
        );

        // Invalid family
        let data = vec![0u8, 0x99, 0, 0, 0, 0, 0, 0];
        assert!(client.parse_xor_mapped_address(&data, &xor_key).is_none());

        // IPv6 but data too short
        let data = vec![0u8, 0x02, 0, 0, 1, 2, 3, 4];
        assert!(client.parse_xor_mapped_address(&data, &xor_key).is_none());

        // XOR key too short
        assert!(
            client
                .parse_xor_mapped_address(&[0u8; 8], &[0u8; 8])
                .is_none()
        );
    }

    #[test]
    fn test_parse_mapped_address_ipv4() {
        let client = StunClient::new();

        let port = 8080u16;
        let ip = Ipv4Addr::new(198, 51, 100, 42);

        let mut data = vec![0u8, 0x01]; // Reserved, Family (IPv4)
        data.extend_from_slice(&port.to_be_bytes());
        data.extend_from_slice(&ip.octets());

        let result = client.parse_mapped_address(&data);
        assert!(result.is_some());

        let (parsed_ip, parsed_port) = result.unwrap();
        assert_eq!(parsed_ip, IpAddr::V4(ip));
        assert_eq!(parsed_port, port);
    }

    #[test]
    fn test_parse_mapped_address_ipv6() {
        let client = StunClient::new();

        let port = 9090u16;
        let ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

        let mut data = vec![0u8, 0x02]; // Reserved, Family (IPv6)
        data.extend_from_slice(&port.to_be_bytes());
        data.extend_from_slice(&ip.octets());

        let result = client.parse_mapped_address(&data);
        assert!(result.is_some());

        let (parsed_ip, parsed_port) = result.unwrap();
        assert_eq!(parsed_ip, IpAddr::V6(ip));
        assert_eq!(parsed_port, port);
    }

    #[test]
    fn test_parse_mapped_address_invalid() {
        let client = StunClient::new();

        // Too short
        assert!(client.parse_mapped_address(&[0u8; 4]).is_none());

        // Invalid family
        let data = vec![0u8, 0x03, 0, 0, 0, 0, 0, 0];
        assert!(client.parse_mapped_address(&data).is_none());

        // IPv6 but too short
        let data = vec![0u8, 0x02, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8];
        assert!(client.parse_mapped_address(&data).is_none());
    }

    #[test]
    fn test_parse_binding_response_too_short() {
        let client = StunClient::new();
        let transaction_id = [0u8; 12];

        let short_data = [0u8; 10];
        let result = client.parse_binding_response(&short_data, &transaction_id, "test");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn test_parse_binding_response_invalid_magic() {
        let client = StunClient::new();
        let transaction_id = [0u8; 12];

        let mut data = vec![0u8; STUN_HEADER_SIZE];
        // Set wrong magic cookie
        data[4..8].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
        data[8..20].copy_from_slice(&transaction_id);

        let result = client.parse_binding_response(&data, &transaction_id, "test");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("magic cookie"));
    }

    #[test]
    fn test_parse_binding_response_transaction_id_mismatch() {
        let client = StunClient::new();
        let transaction_id = [1u8; 12];
        let wrong_id = [2u8; 12];

        let mut data = vec![0u8; STUN_HEADER_SIZE];
        data[0..2].copy_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        data[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        data[8..20].copy_from_slice(&wrong_id);

        let result = client.parse_binding_response(&data, &transaction_id, "test");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("transaction ID mismatch")
        );
    }

    #[test]
    fn test_parse_binding_response_error_response() {
        let client = StunClient::new();
        let transaction_id = [0u8; 12];

        let mut data = vec![0u8; STUN_HEADER_SIZE];
        data[0..2].copy_from_slice(&STUN_BINDING_ERROR_RESPONSE.to_be_bytes());
        data[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        data[8..20].copy_from_slice(&transaction_id);

        let result = client.parse_binding_response(&data, &transaction_id, "test");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("error response"));
    }

    #[test]
    fn test_parse_binding_response_unexpected_type() {
        let client = StunClient::new();
        let transaction_id = [0u8; 12];

        let mut data = vec![0u8; STUN_HEADER_SIZE];
        data[0..2].copy_from_slice(&0x9999u16.to_be_bytes());
        data[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        data[8..20].copy_from_slice(&transaction_id);

        let result = client.parse_binding_response(&data, &transaction_id, "test");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unexpected"));
    }

    #[test]
    fn test_parse_binding_response_truncated() {
        let client = StunClient::new();
        let transaction_id = [0u8; 12];

        let mut data = vec![0u8; STUN_HEADER_SIZE];
        data[0..2].copy_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        data[2..4].copy_from_slice(&100u16.to_be_bytes()); // Claim 100 bytes of attributes
        data[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        data[8..20].copy_from_slice(&transaction_id);
        // But don't provide the 100 bytes

        let result = client.parse_binding_response(&data, &transaction_id, "test");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("truncated"));
    }

    #[test]
    fn test_parse_binding_response_no_mapped_address() {
        let client = StunClient::new();
        let transaction_id = [0u8; 12];

        let mut data = vec![0u8; STUN_HEADER_SIZE];
        data[0..2].copy_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        data[2..4].copy_from_slice(&0u16.to_be_bytes()); // No attributes
        data[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        data[8..20].copy_from_slice(&transaction_id);

        let result = client.parse_binding_response(&data, &transaction_id, "test");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("No mapped address")
        );
    }

    #[test]
    fn test_stun_result_socket_addr() {
        let result = StunResult {
            public_ip: "203.0.113.5".parse().unwrap(),
            public_port: 12345,
            server: "stun.example.com".to_string(),
        };

        let addr = result.socket_addr();
        assert_eq!(addr.ip(), "203.0.113.5".parse::<IpAddr>().unwrap());
        assert_eq!(addr.port(), 12345);
    }

    #[test]
    fn test_stun_result_socket_addr_ipv6() {
        let result = StunResult {
            public_ip: "2001:db8::1".parse().unwrap(),
            public_port: 54321,
            server: "stun.example.com".to_string(),
        };

        let addr = result.socket_addr();
        assert_eq!(addr.ip(), "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(addr.port(), 54321);
    }

    // ============================================================================
    // NAT Info Tests
    // ============================================================================

    #[test]
    fn test_nat_info_is_symmetric() {
        let info = NatInfo {
            public_endpoint: None,
            nat_type: NatType::Symmetric,
            local_addr: None,
        };
        assert!(info.is_symmetric());
        assert!(!info.can_hole_punch());
    }

    #[test]
    fn test_nat_info_not_symmetric() {
        for nat_type in [
            NatType::None,
            NatType::FullCone,
            NatType::AddressRestrictedCone,
            NatType::PortRestrictedCone,
            NatType::Unknown,
        ] {
            let info = NatInfo {
                public_endpoint: None,
                nat_type,
                local_addr: None,
            };
            assert!(!info.is_symmetric());
        }
    }

    #[test]
    fn test_nat_type_display_all() {
        assert_eq!(format!("{}", NatType::None), "No NAT");
        assert_eq!(format!("{}", NatType::FullCone), "Full Cone");
        assert_eq!(
            format!("{}", NatType::AddressRestrictedCone),
            "Address-Restricted Cone"
        );
        assert_eq!(
            format!("{}", NatType::PortRestrictedCone),
            "Port-Restricted Cone"
        );
        assert_eq!(format!("{}", NatType::Symmetric), "Symmetric");
        assert_eq!(format!("{}", NatType::Unknown), "Unknown");
    }

    #[test]
    fn test_discover_nat_info() {
        // This will fail to connect but should return Unknown NAT
        let info = discover_nat_info();
        // Should have unknown NAT type when discovery fails
        assert_eq!(info.nat_type, NatType::Unknown);
    }

    #[test]
    fn test_stun_client_default() {
        let client1 = StunClient::default();
        let client2 = StunClient::new();

        assert_eq!(client1.servers.len(), client2.servers.len());
        assert_eq!(client1.timeout, client2.timeout);
        assert_eq!(client1.retries, client2.retries);
    }

    #[test]
    fn test_stun_constants() {
        assert_eq!(STUN_BINDING_REQUEST, 0x0001);
        assert_eq!(STUN_BINDING_RESPONSE, 0x0101);
        assert_eq!(STUN_BINDING_ERROR_RESPONSE, 0x0111);
        assert_eq!(STUN_ATTR_MAPPED_ADDRESS, 0x0001);
        assert_eq!(STUN_ATTR_XOR_MAPPED_ADDRESS, 0x0020);
        assert_eq!(STUN_MAGIC_COOKIE, 0x2112A442);
        assert_eq!(STUN_HEADER_SIZE, 20);
    }

    #[test]
    fn test_default_stun_servers_is_empty() {
        // Audit CRITICAL #5: STUN must be opt-in. The default list MUST
        // remain empty so a freshly-built `StunClient` (or
        // `discover_nat_info()`) cannot leak the user's real IP to a
        // third party. If you find yourself adding servers here to "make
        // tests pass", you are reintroducing the vulnerability — instead
        // populate `ClientConfig::stun_servers` from the operator's
        // configuration.
        assert!(
            DEFAULT_STUN_SERVERS.is_empty(),
            "DEFAULT_STUN_SERVERS must remain empty (see audit CRITICAL #5)"
        );
    }
}
