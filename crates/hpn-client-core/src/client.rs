//! Main VPN client implementation.
//!
//! The VPN client handles:
//! - Connection establishment via handshake
//! - Encrypted tunnel traffic
//! - Keepalive management
//! - Session rekey
//! - Clean disconnection

use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use parking_lot::RwLock;
use tokio::sync::mpsc;
use tokio::time;
use tracing::{debug, error, info, trace, warn};

use hpn_core::crypto::aead;
use hpn_core::crypto::{MlDsaPublicKey, SessionKeys};
use hpn_core::protocol::{
    ClientHandshake, ClientRekey, ControlMessage, EncryptedHandshakeInit, HEADER_SIZE,
    HandshakeFragment, HandshakeResponse, KeepaliveMessage, KeepaliveReplyMessage, PacketHeader,
    ReassemblerConfig, Reassembly, RekeyResponse, Session, TunnelConfig, build_handshake_fragments,
    fragment::FRAGMENTATION_THRESHOLD,
};
use hpn_core::types::{ControlType, MessageType, SessionId};

use crate::buffer_pool::{BufferPool, BytesPool, SharedBufferPool};
use crate::config::ClientConfig;
use crate::error::{ClientError, ClientResult};
use crate::nat::{NatInfo, StunClient};
use crate::stats::{ConnectionStats, StatsTracker};
use crate::transport::TransportTrait;
use crate::tunnel::TunnelInfo;

/// Maximum packet size for VPN traffic.
const MAX_PACKET_SIZE: usize = 65535;

/// Client state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientState {
    /// Client is disconnected.
    Disconnected,
    /// Client is connecting (handshake in progress).
    Connecting,
    /// Client is connected and tunnel is active.
    Connected,
    /// Client is reconnecting after a failure.
    Reconnecting,
    /// Client is disconnecting.
    Disconnecting,
}

/// Events emitted by the client.
#[derive(Clone, Debug)]
pub enum ClientEvent {
    /// State changed.
    StateChanged(ClientState),
    /// Connection established with tunnel info.
    Connected(TunnelInfo),
    /// Disconnected with optional reason.
    Disconnected(Option<String>),
    /// Keepalive received with RTT in milliseconds.
    Keepalive { sequence: u32, rtt_ms: u64 },
    /// Error occurred.
    Error(String),
    /// Bytes transferred (sent, received).
    BytesTransferred { sent: u64, received: u64 },
    /// Rekey completed successfully with new key ID.
    RekeyComplete { new_key_id: u32 },
    /// Control message received from server.
    ControlReceived {
        control_type: ControlType,
        message: Option<String>,
    },
    /// Keepalive timeout - no response received.
    KeepaliveTimeout { missed_count: u32 },
    /// Reconnecting after connection loss.
    Reconnecting { attempt: u32, max_attempts: u32 },
    /// Reconnection failed.
    ReconnectionFailed { reason: String },
    /// Server endpoint changed (roaming).
    EndpointChanged { new_addr: std::net::SocketAddr },
    /// NAT discovery completed.
    NatDiscovered(NatInfo),
    /// Rebind request sent to server.
    RebindRequested { new_endpoint: std::net::SocketAddr },
    /// Rebind acknowledged by server.
    RebindAcknowledged,
}

/// Session snapshot for external status queries.
pub struct SessionSnapshot {
    /// Current session ID.
    pub session_id: hpn_core::types::SessionId,
    /// Current key ID (changes on rekey).
    pub key_id: hpn_core::types::KeyId,
}

/// VPN client.
pub struct VpnClient {
    /// Client configuration.
    config: ClientConfig,
    /// Server's ML-DSA public key.
    server_public_key: MlDsaPublicKey,
    /// Current client state.
    state: Arc<RwLock<ClientState>>,
    /// Active session (if connected).
    session: Arc<RwLock<Option<Session>>>,
    /// Tunnel configuration.
    tunnel_info: Arc<RwLock<Option<TunnelInfo>>>,
    /// Event sender.
    event_tx: mpsc::UnboundedSender<ClientEvent>,
    /// Shutdown signal.
    shutdown: Arc<RwLock<bool>>,
    /// Last keepalive sent time.
    last_keepalive_sent: Arc<RwLock<Option<Instant>>>,
    /// Last keepalive reply received time.
    last_keepalive_received: Arc<RwLock<Option<Instant>>>,
    /// Keepalive sequence counter.
    keepalive_seq: Arc<RwLock<u32>>,
    /// Pending keepalive sequence (awaiting reply). None if no pending keepalive.
    pending_keepalive_seq: Arc<RwLock<Option<u32>>>,
    /// Number of missed keepalives (no reply received).
    missed_keepalives: Arc<RwLock<u32>>,
    /// Active rekey handler (if rekeying in progress).
    rekey_handler: Arc<RwLock<Option<ClientRekey>>>,
    /// Whether a rekey is in progress.
    rekey_in_progress: Arc<RwLock<bool>>,
    /// When the current rekey attempt started.
    rekey_started_at: Arc<RwLock<Option<Instant>>>,
    /// Connection statistics tracker.
    stats: Arc<RwLock<StatsTracker>>,
    /// Reconnection attempt counter.
    reconnect_attempts: Arc<RwLock<u32>>,
    /// NAT information (discovered public endpoint).
    nat_info: Arc<RwLock<Option<NatInfo>>>,
    /// Whether a rebind is pending acknowledgment.
    rebind_pending: Arc<RwLock<bool>>,
    /// Buffer pool for zero-allocation send path.
    buffer_pool: SharedBufferPool,
    /// Bytes pool for receive-path handoff to outbound channel.
    bytes_pool: Arc<BytesPool>,
    /// Atomic guard preventing concurrent connect() calls.
    connect_in_progress: Arc<std::sync::atomic::AtomicBool>,
}

impl VpnClient {
    /// Create a new VPN client.
    pub fn new(config: ClientConfig) -> ClientResult<(Self, mpsc::UnboundedReceiver<ClientEvent>)> {
        // Validate config (checks key sizes match security level, etc.)
        config.validate()?;

        // Decode server public key
        let pk_bytes = config.decode_server_public_key()?;
        let server_public_key = MlDsaPublicKey::from_bytes(&pk_bytes)
            .map_err(|e| ClientError::Config(format!("invalid server public key: {}", e)))?;

        let (event_tx, event_rx) = mpsc::unbounded_channel();

        let client = Self {
            config,
            server_public_key,
            state: Arc::new(RwLock::new(ClientState::Disconnected)),
            session: Arc::new(RwLock::new(None)),
            tunnel_info: Arc::new(RwLock::new(None)),
            event_tx,
            shutdown: Arc::new(RwLock::new(false)),
            last_keepalive_sent: Arc::new(RwLock::new(None)),
            last_keepalive_received: Arc::new(RwLock::new(None)),
            keepalive_seq: Arc::new(RwLock::new(0)),
            pending_keepalive_seq: Arc::new(RwLock::new(None)),
            missed_keepalives: Arc::new(RwLock::new(0)),
            rekey_handler: Arc::new(RwLock::new(None)),
            rekey_in_progress: Arc::new(RwLock::new(false)),
            rekey_started_at: Arc::new(RwLock::new(None)),
            stats: Arc::new(RwLock::new(StatsTracker::new())),
            reconnect_attempts: Arc::new(RwLock::new(0)),
            nat_info: Arc::new(RwLock::new(None)),
            rebind_pending: Arc::new(RwLock::new(false)),
            buffer_pool: Arc::new(BufferPool::with_default_size()),
            bytes_pool: Arc::new(BytesPool::with_default_size()),
            connect_in_progress: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        Ok((client, event_rx))
    }

    /// Get current connection statistics.
    pub fn stats(&self) -> ConnectionStats {
        self.stats.read().snapshot()
    }

    /// Get the current client state.
    pub fn state(&self) -> ClientState {
        *self.state.read()
    }

    /// Check if the client is connected.
    pub fn is_connected(&self) -> bool {
        self.state() == ClientState::Connected
    }

    /// Get the tunnel info (if connected).
    pub fn tunnel_info(&self) -> Option<TunnelInfo> {
        self.tunnel_info.read().clone()
    }

    /// Set the client state and emit event.
    fn set_state(&self, new_state: ClientState) {
        {
            let mut state = self.state.write();
            if *state == new_state {
                return;
            }
            debug!("Client state: {:?} -> {:?}", *state, new_state);
            *state = new_state;
        }
        let _ = self.event_tx.send(ClientEvent::StateChanged(new_state));
    }

    /// Emit an error event.
    fn emit_error(&self, msg: impl Into<String>) {
        let msg = msg.into();
        error!("Client error: {}", msg);
        let _ = self.event_tx.send(ClientEvent::Error(msg));
    }

    /// Connect to the VPN server without authentication.
    ///
    /// Use [`connect_with_credentials`] if the server requires authentication.
    pub async fn connect(&self, connection: &dyn TransportTrait) -> ClientResult<TunnelInfo> {
        self.connect_with_credentials(connection, None).await
    }

    /// Connect to the VPN server with optional credentials.
    ///
    /// If the server requires authentication, credentials must be provided.
    /// The credentials are encrypted using the server's KEM public key before
    /// being sent, ensuring they cannot be intercepted by network observers.
    ///
    /// # Arguments
    ///
    /// * `connection` - The UDP connection to the server
    /// * `credentials` - Optional username/password for authentication
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Client is already connected
    /// - Credentials are invalid (validation fails)
    /// - Credentials are provided but identity hiding is not enabled
    /// - Handshake fails (including authentication failure)
    pub async fn connect_with_credentials(
        &self,
        connection: &dyn TransportTrait,
        credentials: Option<crate::config::Credentials>,
    ) -> ClientResult<TunnelInfo> {
        if self.state() == ClientState::Connected {
            return self
                .tunnel_info()
                .ok_or_else(|| ClientError::InvalidState("already connected".into()));
        }

        // Atomic guard: prevent concurrent connect() calls.
        // compare_exchange ensures only one thread proceeds past this point.
        if self
            .connect_in_progress
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            )
            .is_err()
        {
            return Err(ClientError::InvalidState(
                "connection already in progress".into(),
            ));
        }

        // Validate credentials if provided
        if let Some(ref creds) = credentials
            && let Err(e) = creds.validate()
        {
            self.connect_in_progress
                .store(false, std::sync::atomic::Ordering::SeqCst);
            return Err(e);
        }

        self.set_state(ClientState::Connecting);

        // Perform handshake with optional credentials
        let had_credentials = credentials.is_some();
        match self.perform_handshake(connection, credentials).await {
            Ok((session_id, keys, config)) => {
                info!("Handshake successful, session ID: {}", session_id);
                // Note: Never log key material, even partially

                // Create session
                let session = Session::new(session_id, keys).map_err(|e| {
                    ClientError::Handshake(format!("Failed to create session: {}", e))
                })?;
                *self.session.write() = Some(session);

                // Store tunnel info
                let tunnel_info = TunnelInfo::from(config);
                *self.tunnel_info.write() = Some(tunnel_info.clone());

                // Initialize stats tracking
                self.stats.write().on_connected(session_id.0);

                self.set_state(ClientState::Connected);
                self.connect_in_progress
                    .store(false, std::sync::atomic::Ordering::SeqCst);
                let _ = self
                    .event_tx
                    .send(ClientEvent::Connected(tunnel_info.clone()));

                Ok(tunnel_info)
            }
            Err(e) => {
                self.connect_in_progress
                    .store(false, std::sync::atomic::Ordering::SeqCst);
                self.set_state(ClientState::Disconnected);
                if matches!(e, ClientError::Auth(_)) {
                    self.emit_error(format!("Authentication failed: {}", e));
                } else {
                    self.emit_error(format!("Handshake failed: {}", e));
                }
                if had_credentials {
                    debug!("Handshake failed with credentials");
                }
                Err(e)
            }
        }
    }

    /// Perform the cryptographic handshake.
    async fn perform_handshake(
        &self,
        connection: &dyn TransportTrait,
        credentials: Option<crate::config::Credentials>,
    ) -> ClientResult<(SessionId, SessionKeys, TunnelConfig)> {
        // Check if identity hiding is enabled
        let server_kem_pk = self.config.decode_server_kem_public_key()?;

        // Credentials require identity hiding (KEM public key) to be encrypted
        if credentials.is_some() && server_kem_pk.is_none() {
            return Err(ClientError::Config(
                "credentials require identity hiding (server_kem_public_key) to be configured"
                    .into(),
            ));
        }

        // Use security level from config to ensure correct ML-KEM and ML-DSA variants
        let mut handshake = if let Some(ref kem_pk) = server_kem_pk {
            // Use identity hiding handshake
            ClientHandshake::with_identity_hiding(
                self.server_public_key.clone(),
                kem_pk.clone(),
                self.config.security_level(),
            )
        } else {
            ClientHandshake::with_server_pk_and_level(
                self.server_public_key.clone(),
                self.config.security_level(),
            )
        };

        // Create and send handshake init
        let mut init = handshake.create_init().map_err(|e| {
            ClientError::Handshake(format!("failed to create handshake init: {}", e))
        })?;

        // Add credentials if provided
        if let Some(ref creds) = credentials {
            let kem_pk = server_kem_pk.as_ref().expect("already validated");
            init.add_credentials(&creds.username, &creds.password, kem_pk)
                .map_err(|e| {
                    ClientError::Handshake(format!("failed to encrypt credentials: {}", e))
                })?;
            debug!("Added encrypted credentials to handshake init");
        }

        // Build the init payload WITHOUT the outer PacketHeader so we
        // can decide between a single-packet send and an app-layer
        // fragmented send. `init_payload_msg_type` is the `MessageType`
        // that would normally appear in the PacketHeader for an
        // un-fragmented send; when we fragment, it is carried in each
        // fragment's `inner_msg_type` field instead.
        let (init_payload_msg_type, init_payload) = if let Some(ref kem_pk) = server_kem_pk {
            let encrypted = EncryptedHandshakeInit::encrypt(&init, kem_pk).map_err(|e| {
                ClientError::Handshake(format!("failed to encode encrypted handshake init: {}", e))
            })?;
            (MessageType::EncryptedHandshakeInit, encrypted.to_bytes())
        } else {
            (MessageType::HandshakeInit, init.to_bytes())
        };

        debug!(
            "Sending handshake init ({} bytes, identity_hiding={}, type={:?})",
            init_payload.len(),
            server_kem_pk.is_some(),
            init_payload_msg_type,
        );

        // Post-quantum handshakes (Level 5 + identity hiding + creds)
        // exceed a typical UDP MTU and get dropped by some hosters'
        // anti-DDoS filters. Split into `HandshakeFragment` packets
        // whenever the payload would require IP-level fragmentation.
        if init_payload.len() > FRAGMENTATION_THRESHOLD {
            let frag_id: u32 = rand::random();
            let fragment_bodies =
                build_handshake_fragments(init_payload_msg_type, frag_id, &init_payload).map_err(
                    |e| ClientError::Handshake(format!("handshake fragmentation failed: {}", e)),
                )?;
            debug!(
                "Fragmenting handshake init into {} packets (frag_id={:#010x})",
                fragment_bodies.len(),
                frag_id,
            );
            for (index, body) in fragment_bodies.iter().enumerate() {
                let header = PacketHeader::new(
                    MessageType::HandshakeFragment,
                    SessionId(0),
                    hpn_core::types::KeyId::initial(),
                    hpn_core::types::Counter::initial(),
                );
                let mut pkt = Vec::with_capacity(HEADER_SIZE + body.len());
                let mut hdr_buf = [0u8; HEADER_SIZE];
                header.encode(&mut hdr_buf).map_err(|e| {
                    ClientError::Handshake(format!(
                        "failed to encode fragment header {}: {}",
                        index, e
                    ))
                })?;
                pkt.extend_from_slice(&hdr_buf);
                pkt.extend_from_slice(body);
                connection.send(&pkt).await?;
            }
        } else {
            // Small enough to fit in one UDP datagram — send as a
            // single HandshakeInit / EncryptedHandshakeInit packet.
            let header = PacketHeader::new(
                init_payload_msg_type,
                SessionId(0),
                hpn_core::types::KeyId::initial(),
                hpn_core::types::Counter::initial(),
            );
            let mut pkt = Vec::with_capacity(HEADER_SIZE + init_payload.len());
            let mut hdr_buf = [0u8; HEADER_SIZE];
            header.encode(&mut hdr_buf).map_err(|e| {
                ClientError::Handshake(format!("failed to encode packet header: {}", e))
            })?;
            pkt.extend_from_slice(&hdr_buf);
            pkt.extend_from_slice(&init_payload);
            connection.send(&pkt).await?;
        }

        // Wait for response with timeout
        let mut recv_buf = vec![0u8; MAX_PACKET_SIZE];
        let timeout = if credentials.is_some() {
            self.config
                .connection_timeout()
                .min(std::time::Duration::from_secs(5))
        } else {
            self.config.connection_timeout()
        };
        info!("Waiting for handshake response with timeout: {:?}", timeout);

        // Maximum non-handshake packets to receive before giving up.
        // Prevents tight loop if server sends many non-handshake packets.
        const MAX_IGNORED_DURING_HANDSHAKE: u32 = 100;

        // The server's HandshakeResponse at Level 5 is ~9 KB and is
        // always fragmented when identity hiding or auth is on. We
        // reassemble here using a tiny client-side buffer (at most one
        // in-flight reassembly since `UdpConnection` is bound to a
        // single peer).
        let response_result = time::timeout(timeout, async {
            let mut ignored_count = 0u32;
            // Use a dummy peer address as the reassembler key; the
            // UdpConnection is pinned to the one server we care about
            // so collisions are impossible.
            let peer_key: std::net::SocketAddr = "0.0.0.0:0".parse().expect("valid SocketAddr");
            let mut reassembler = Reassembly::new(ReassemblerConfig::client_default());

            loop {
                debug!("Waiting for packet from server...");
                // We are still in the handshake phase: pass `true` so the
                // transport's own ignore-cap fails fast on spurious noise
                // (100 packets) rather than the steady-state 1000-packet
                // window. The outer MAX_IGNORED_DURING_HANDSHAKE counter
                // bounds non-handshake packets that DO come from the
                // server's IP; the inner cap bounds packets that don't.
                let n = connection
                    .recv_from_server_scoped(&mut recv_buf, true)
                    .await?;
                debug!("Received {} bytes", n);

                if n < HEADER_SIZE {
                    ignored_count += 1;
                    if ignored_count >= MAX_IGNORED_DURING_HANDSHAKE {
                        return Err(ClientError::Handshake(
                            "too many non-handshake packets during handshake".into(),
                        ));
                    }
                    continue;
                }

                let header = PacketHeader::decode(&recv_buf[..n])?;
                trace!("Packet type: {:?}", header.msg_type);

                match header.msg_type {
                    MessageType::HandshakeResponse => {
                        return Ok::<_, ClientError>(recv_buf[..n].to_vec());
                    }
                    MessageType::HandshakeFragment => {
                        let body = &recv_buf[HEADER_SIZE..n];
                        let fragment = match HandshakeFragment::from_bytes(body) {
                            Ok(f) => f,
                            Err(e) => {
                                debug!("Dropping malformed HandshakeFragment: {}", e);
                                ignored_count += 1;
                                if ignored_count >= MAX_IGNORED_DURING_HANDSHAKE {
                                    return Err(ClientError::Handshake(
                                        "too many malformed packets during handshake".into(),
                                    ));
                                }
                                continue;
                            }
                        };
                        // Accept only fragments that claim to be a
                        // HandshakeResponse; ignore (but don't penalise)
                        // anything else — the server may also send
                        // cookie replies or control messages wrapped in
                        // fragments in the future.
                        if fragment.inner_msg_type != MessageType::HandshakeResponse {
                            trace!(
                                "Ignoring HandshakeFragment with unexpected inner type {:?}",
                                fragment.inner_msg_type
                            );
                            continue;
                        }
                        if let Some((inner_type, payload)) = reassembler.insert(peer_key, fragment)
                        {
                            debug!(
                                "Reassembled {:?} from fragments ({} bytes)",
                                inner_type,
                                payload.len()
                            );
                            // Rebuild a synthetic HandshakeResponse packet
                            // (header + reassembled payload) so the rest
                            // of `perform_handshake` can keep using
                            // `decode_handshake_response`.
                            let synth_header = PacketHeader::new(
                                MessageType::HandshakeResponse,
                                SessionId(0),
                                hpn_core::types::KeyId::initial(),
                                hpn_core::types::Counter::initial(),
                            );
                            let mut synth = Vec::with_capacity(HEADER_SIZE + payload.len());
                            let mut hdr_buf = [0u8; HEADER_SIZE];
                            synth_header.encode(&mut hdr_buf).map_err(|e| {
                                ClientError::Handshake(format!(
                                    "failed to encode reassembled header: {}",
                                    e
                                ))
                            })?;
                            synth.extend_from_slice(&hdr_buf);
                            synth.extend_from_slice(&payload);
                            return Ok::<_, ClientError>(synth);
                        }
                    }
                    _ => {
                        // Anything else is ignored (non-handshake traffic).
                    }
                }

                ignored_count += 1;
                if ignored_count >= MAX_IGNORED_DURING_HANDSHAKE {
                    return Err(ClientError::Handshake(
                        "too many non-handshake packets during handshake".into(),
                    ));
                }
            }
        })
        .await;

        let response_bytes = match response_result {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                error!("Handshake timeout after {:?}", timeout);
                if credentials.is_some() {
                    return Err(ClientError::Auth(
                        "authentication rejected by server (invalid username/password or account not allowed)"
                            .into(),
                    ));
                }
                return Err(ClientError::Timeout("handshake response timeout".into()));
            }
        };

        // Decode and process response
        let response = self.decode_handshake_response(&response_bytes)?;
        debug!(
            "Received handshake response, session ID: {}",
            response.session_id
        );

        // Complete handshake
        let (session_id, keys, config) = handshake.process_response(&response)?;

        Ok((session_id, keys, config))
    }

    /// Decode a handshake response message.
    fn decode_handshake_response(&self, data: &[u8]) -> ClientResult<HandshakeResponse> {
        if data.len() < HEADER_SIZE {
            return Err(ClientError::Handshake("response too short".into()));
        }

        let _header = PacketHeader::decode(data)?;
        let payload = &data[HEADER_SIZE..];

        HandshakeResponse::from_bytes_with_level(payload, self.config.security_level())
            .map_err(|e| ClientError::Handshake(format!("failed to decode response: {}", e)))
    }

    /// Send encrypted data through the tunnel.
    ///
    /// Uses buffer pool for zero-allocation packet handling.
    /// Uses read lock instead of write lock since encrypt_packet uses atomic
    /// counters internally and is safe for concurrent access.
    pub async fn send_data(
        &self,
        connection: &dyn TransportTrait,
        payload: &[u8],
    ) -> ClientResult<()> {
        // Get buffer from pool (zero-allocation in hot path)
        let mut pooled_buf = self.buffer_pool.get();

        // Encrypt with read lock (encrypt_packet is &self, uses atomics internally)
        let packet_len = {
            let session = self.session.read();
            let session = session.as_ref().ok_or(ClientError::NotConnected)?;

            session.encrypt_packet(MessageType::Data, payload, pooled_buf.buffer_mut())?
        }; // Lock released here

        // Send without holding the lock
        connection.send(&pooled_buf.buffer()[..packet_len]).await?;

        // Track bytes sent (lock-free atomic)
        self.stats.read().atomic.on_bytes_sent(payload.len() as u64);

        trace!("Sent {} bytes of encrypted data", packet_len);

        // Buffer automatically returned to pool when pooled_buf is dropped
        Ok(())
    }

    /// Process a received packet.
    ///
    /// Uses read lock for decrypt_packet since it uses atomic counters and
    /// internal mutability (anti-replay window has its own mutex).
    pub async fn process_packet(
        &self,
        data: &[u8],
        output: &mut [u8],
    ) -> ClientResult<Option<(MessageType, usize)>> {
        if data.len() < HEADER_SIZE {
            return Ok(None);
        }

        let header = PacketHeader::decode(data)?;

        match header.msg_type {
            MessageType::Data => {
                let len = {
                    let session = self.session.read();
                    let session = session.as_ref().ok_or(ClientError::NotConnected)?;
                    let (_, len) = session.decrypt_packet(data, output)?;
                    len
                }; // Read lock released here

                // Track bytes received (lock-free atomic)
                self.stats.read().atomic.on_bytes_received(len as u64);

                Ok(Some((MessageType::Data, len)))
            }
            MessageType::KeepaliveReply => {
                let len = {
                    let session = self.session.read();
                    let session = session.as_ref().ok_or(ClientError::NotConnected)?;
                    let (_, len) = session.decrypt_packet(data, output)?;
                    len
                };
                self.process_keepalive_reply(&output[..len])?;
                Ok(Some((MessageType::KeepaliveReply, 0)))
            }
            MessageType::Control => {
                let len = {
                    let session = self.session.read();
                    let session = session.as_ref().ok_or(ClientError::NotConnected)?;
                    let (_, len) = session.decrypt_packet(data, output)?;
                    len
                };
                self.process_control_message(&output[..len])?;
                Ok(Some((MessageType::Control, 0)))
            }
            MessageType::RekeyResponse => {
                let len = {
                    let session = self.session.read();
                    let session = session.as_ref().ok_or(ClientError::NotConnected)?;
                    let (_, len) = session.decrypt_packet(data, output)?;
                    len
                };
                self.process_rekey_response(&output[..len])?;
                Ok(Some((MessageType::RekeyResponse, 0)))
            }
            _ => {
                warn!("Unexpected message type: {:?}", header.msg_type);
                // Track dropped packet (lock-free atomic)
                self.stats.read().atomic.on_packet_dropped();
                Ok(None)
            }
        }
    }

    /// Process a decrypted control message payload from the server.
    fn process_control_message(&self, payload: &[u8]) -> ClientResult<()> {
        let control = ControlMessage::from_bytes(payload)?;

        debug!("Received control message: {:?}", control.control_type);

        info!(
            "Control message: type={:?}, error_code={:?}, message={:?}",
            control.control_type, control.error_code, control.message
        );

        // Emit event
        let _ = self.event_tx.send(ClientEvent::ControlReceived {
            control_type: control.control_type,
            message: control.message.clone(),
        });

        // Handle specific control types
        match control.control_type {
            ControlType::Close => {
                info!("Server requested disconnect");
                self.set_state(ClientState::Disconnected);
                let _ = self.event_tx.send(ClientEvent::Disconnected(
                    control
                        .message
                        .or_else(|| Some("server closed connection".into())),
                ));
            }
            ControlType::Error => {
                let msg = control.message.unwrap_or_else(|| "unknown error".into());
                self.emit_error(format!("Server error: {}", msg));
            }
            ControlType::RebindAck => {
                // Audit H11: verify the optional ML-DSA-signed payload
                // BEFORE clearing rebind_pending. This is defence in
                // depth against a session-key-only attacker forging an
                // ack to redirect the client off the legitimate server.
                //
                // Three outcomes:
                //   1. signed_payload Some + verifies -> accept (best path)
                //   2. signed_payload Some + fails verification ->
                //      reject AND keep rebind_pending; surface error
                //   3. signed_payload None + require_signed=true ->
                //      reject (fleet should be fully upgraded)
                //   3'. signed_payload None + require_signed=false ->
                //      accept with WARN log (legacy compat)
                let session_id = match self.session.read().as_ref() {
                    Some(s) => s.session_id(),
                    None => {
                        warn!("RebindAck received without active session — ignoring");
                        return Ok(());
                    }
                };
                match control.signed_payload.as_ref() {
                    Some(signed) => match signed.verify(&self.server_public_key, session_id) {
                        Ok(()) => {
                            info!(
                                "Server acknowledged endpoint rebind (ML-DSA-{:?} verified, endpoint={})",
                                signed.security_level, signed.endpoint
                            );
                            *self.rebind_pending.write() = false;
                            let _ = self.event_tx.send(ClientEvent::RebindAcknowledged);
                        }
                        Err(e) => {
                            error!(
                                "Refusing to accept RebindAck — signed payload failed verification: {}",
                                e
                            );
                            // Keep rebind_pending = true; the client
                            // will retry on next NAT-rebind detection
                            // tick. Do NOT emit RebindAcknowledged to
                            // avoid downstream code treating the
                            // forged ack as success.
                            self.emit_error(format!("Server rebind ack signature invalid: {}", e));
                        }
                    },
                    None => {
                        if self.config.require_signed_rebind_ack {
                            error!(
                                "Refusing unsigned RebindAck (require_signed_rebind_ack=true). \
                                 Server must roll out audit-H11 signed acks before this client \
                                 can accept rebinds."
                            );
                            self.emit_error(
                                "Server rebind ack rejected: signature required but missing",
                            );
                        } else {
                            warn!(
                                "Server acknowledged endpoint rebind without ML-DSA signature \
                                 (legacy compat mode — set require_signed_rebind_ack=true once \
                                 the fleet is upgraded)"
                            );
                            *self.rebind_pending.write() = false;
                            let _ = self.event_tx.send(ClientEvent::RebindAcknowledged);
                        }
                    }
                }
            }
            ControlType::Rebind => {
                // Server is asking us to rebind (unusual, but handle it)
                debug!("Server requested rebind, ignoring (client-initiated only)");
            }
            ControlType::Config => {
                // Server sent configuration update
                debug!("Server sent config update: {:?}", control.message);
            }
        }

        Ok(())
    }

    /// Process a decrypted rekey response payload from the server.
    fn process_rekey_response(&self, payload: &[u8]) -> ClientResult<()> {
        let response = RekeyResponse::from_bytes_with_level(payload, self.config.security_level())?;

        // Process with rekey handler
        let new_keys = {
            let mut handler = self.rekey_handler.write();
            let handler = handler.as_mut().ok_or_else(|| {
                ClientError::InvalidState("received rekey response without pending rekey".into())
            })?;
            handler.process_response(&response)?
        };

        // Update session keys
        {
            let mut session = self.session.write();
            let session = session.as_mut().ok_or(ClientError::NotConnected)?;
            session
                .update_keys(new_keys)
                .map_err(|e| ClientError::Handshake(format!("Rekey failed: {}", e)))?;
        }

        // Clear rekey state
        self.clear_rekey_state();

        // Track rekey
        self.stats.write().on_rekey(response.new_key_id);

        info!("Rekey completed, new key ID: {}", response.new_key_id);
        let _ = self.event_tx.send(ClientEvent::RekeyComplete {
            new_key_id: response.new_key_id,
        });

        Ok(())
    }

    /// Send a keepalive packet.
    ///
    /// Uses buffer pool for zero-allocation packet handling.
    pub async fn send_keepalive(&self, connection: &dyn TransportTrait) -> ClientResult<()> {
        trace!("send_keepalive() called");

        // Check if we have a pending keepalive that wasn't acknowledged
        let had_pending = self.pending_keepalive_seq.read().is_some();
        if had_pending {
            // Sending new keepalive without reply to previous one - increment missed count
            let missed = {
                let mut missed = self.missed_keepalives.write();
                *missed += 1;
                *missed
            };
            debug!(
                "Previous keepalive not acknowledged, missed count now: {}",
                missed
            );
        }

        let sequence = {
            let mut seq = self.keepalive_seq.write();
            let current = *seq;
            *seq = seq.wrapping_add(1);
            current
        };

        let keepalive = KeepaliveMessage { sequence };
        let payload = keepalive.to_bytes();

        // Get buffer from pool (zero-allocation)
        let mut pooled_buf = self.buffer_pool.get();

        // Encrypt with read lock (encrypt_packet is &self, uses atomics)
        let packet_len = {
            let session = self.session.read();
            let session = session.as_ref().ok_or(ClientError::NotConnected)?;

            session.encrypt_packet(MessageType::Keepalive, &payload, pooled_buf.buffer_mut())?
        }; // Lock released here

        trace!(
            "Sending keepalive packet ({} bytes) to {}",
            packet_len,
            connection.server_addr()
        );

        // Send without holding any locks
        connection.send(&pooled_buf.buffer()[..packet_len]).await?;

        // Track the pending keepalive and send time
        *self.pending_keepalive_seq.write() = Some(sequence);
        *self.last_keepalive_sent.write() = Some(Instant::now());

        trace!("Keepalive packet sent successfully");

        // Track keepalive sent
        self.stats.write().on_keepalive_sent();

        trace!("Sent keepalive seq={}", sequence);
        Ok(())
    }

    /// Process a keepalive reply.
    fn process_keepalive_reply(&self, data: &[u8]) -> ClientResult<()> {
        // Parse the reply to get the sequence number
        let reply = KeepaliveReplyMessage::from_bytes(data)?;

        // Check if this reply matches our pending keepalive
        let pending_seq = *self.pending_keepalive_seq.read();
        if let Some(expected_seq) = pending_seq
            && reply.sequence != expected_seq
        {
            // Sequence mismatch - could be a delayed reply from an older keepalive
            // Log but don't treat as error (network can reorder packets)
            warn!(
                "Keepalive reply sequence mismatch: expected {}, got {} (may be delayed reply)",
                expected_seq, reply.sequence
            );
        }

        let rtt_ms = self
            .last_keepalive_sent
            .read()
            .map(|t| t.elapsed().as_millis() as u64)
            .unwrap_or(0);

        // Clear pending keepalive and reset missed counter on successful reply
        *self.pending_keepalive_seq.write() = None;
        *self.missed_keepalives.write() = 0;
        *self.last_keepalive_received.write() = Some(Instant::now());

        // Track keepalive RTT
        self.stats.write().on_keepalive_received(rtt_ms);

        debug!(
            "Keepalive reply: seq={}, server_ts={}, RTT={}ms",
            reply.sequence, reply.server_timestamp, rtt_ms
        );
        let _ = self.event_tx.send(ClientEvent::Keepalive {
            sequence: reply.sequence,
            rtt_ms,
        });

        Ok(())
    }

    /// Check if keepalive should be sent.
    pub fn should_send_keepalive(&self) -> bool {
        let interval = self.config.keepalive_interval();
        let should_send = self
            .last_keepalive_sent
            .read()
            .map(|t| t.elapsed() >= interval)
            .unwrap_or(true);

        if should_send {
            trace!("should_send_keepalive = TRUE (will send keepalive now)");
        }
        should_send
    }

    /// Check if keepalive has timed out (no reply received).
    pub fn check_keepalive_timeout(&self) -> Option<u32> {
        let timeout = self.config.keepalive_timeout();
        let last_received = *self.last_keepalive_received.read();
        let last_sent = *self.last_keepalive_sent.read();

        // If we haven't sent any keepalive yet, no timeout
        if last_sent.is_none() {
            return None;
        }

        // Check if we're past the timeout threshold
        let since_last_response = match last_received {
            Some(t) => t.elapsed(),
            // SAFETY: We checked last_sent.is_none() above and returned early
            None => last_sent.expect("checked above").elapsed(),
        };

        if since_last_response > timeout {
            let missed = *self.missed_keepalives.read();
            Some(missed)
        } else {
            None
        }
    }

    /// Get current missed keepalive count.
    pub fn missed_keepalive_count(&self) -> u32 {
        *self.missed_keepalives.read()
    }

    /// Check if connection should be considered dead.
    pub fn is_connection_dead(&self) -> bool {
        *self.missed_keepalives.read() >= self.config.keepalive_timeout_count
    }

    /// Get the last measured RTT in milliseconds.
    pub fn last_rtt_ms(&self) -> u64 {
        self.stats.read().snapshot().rtt_ms
    }

    /// Get a snapshot of the current session info (session ID, key ID).
    pub fn get_session_snapshot(&self) -> Option<SessionSnapshot> {
        let session = self.session.read();
        session.as_ref().map(|s| SessionSnapshot {
            session_id: s.session_id(),
            key_id: s.key_id(),
        })
    }

    /// Check if rekey should be initiated.
    pub fn should_rekey(&self) -> bool {
        let session = self.session.read();
        if let Some(ref session) = *session {
            session.age().as_secs() >= self.config.rekey_interval_secs
        } else {
            false
        }
    }

    /// Reset keepalive tracking (call on reconnection).
    fn reset_keepalive_state(&self) {
        *self.last_keepalive_sent.write() = None;
        *self.last_keepalive_received.write() = None;
        *self.pending_keepalive_seq.write() = None;
        *self.missed_keepalives.write() = 0;
        *self.keepalive_seq.write() = 0;
    }

    /// Get the configuration.
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// Check if session needs rekey.
    pub fn needs_rekey(&self) -> bool {
        // Don't trigger rekey if one is already in progress
        if *self.rekey_in_progress.read() {
            return false;
        }
        self.session
            .read()
            .as_ref()
            .map(|s| s.needs_rekey(self.config.rekey_after_bytes, self.config.rekey_interval()))
            .unwrap_or(false)
    }

    /// Initiate a key rotation (rekey).
    ///
    /// This starts the rekey process by sending a rekey request to the server.
    /// The process completes when the server responds (handled in `process_packet`).
    pub async fn initiate_rekey(&self, connection: &dyn TransportTrait) -> ClientResult<()> {
        if *self.rekey_in_progress.read() {
            return Err(ClientError::InvalidState(
                "rekey already in progress".into(),
            ));
        }

        info!("Initiating key rotation");

        // Create rekey handler with the session's security level and session ID
        let session_id = {
            let session = self.session.read();
            session
                .as_ref()
                .ok_or(ClientError::NotConnected)?
                .session_id()
        };
        let mut handler = ClientRekey::with_security_level(
            self.server_public_key.clone(),
            session_id,
            self.config.security_level(),
        );
        let rekey_request = handler.create_request()?;

        // Encrypt rekey request with read lock (drop lock before sending)
        let packet_data = {
            let payload = rekey_request.to_bytes();
            let session = self.session.read();
            let session = session.as_ref().ok_or(ClientError::NotConnected)?;

            let mut output = vec![0u8; HEADER_SIZE + payload.len() + aead::TAG_SIZE + 32];
            let packet_len = session.encrypt_packet(MessageType::Rekey, &payload, &mut output)?;
            output.truncate(packet_len);
            output
        };

        // Store handler for later response processing
        *self.rekey_handler.write() = Some(handler);
        *self.rekey_in_progress.write() = true;
        *self.rekey_started_at.write() = Some(Instant::now());

        // Send without holding any locks
        if let Err(e) = connection.send(&packet_data).await {
            self.clear_rekey_state();
            return Err(ClientError::ConnectionIo(e));
        }
        debug!("Sent rekey request ({} bytes)", packet_data.len());

        Ok(())
    }

    /// Check if a rekey is currently in progress.
    pub fn is_rekey_in_progress(&self) -> bool {
        *self.rekey_in_progress.read()
    }

    /// Disconnect from the VPN server.
    pub async fn disconnect(&self, connection: &dyn TransportTrait) -> ClientResult<()> {
        if self.state() == ClientState::Disconnected {
            return Ok(());
        }

        self.set_state(ClientState::Disconnecting);
        info!("Disconnecting from VPN server");

        // Prepare close message: encrypt with read lock, then close with write lock
        let packet_data = {
            let session_guard = self.session.read();
            if let Some(ref session) = *session_guard {
                let close_msg = hpn_core::protocol::ControlMessage::close();
                let payload = close_msg.to_bytes();

                let mut output = vec![0u8; HEADER_SIZE + payload.len() + aead::TAG_SIZE + 32];
                if let Ok(len) = session.encrypt_packet(MessageType::Control, &payload, &mut output)
                {
                    output.truncate(len);
                    Some(output)
                } else {
                    None
                }
            } else {
                None
            }
        };

        // Close session with write lock (needs &mut self)
        if let Some(ref mut session) = *self.session.write() {
            session.close();
        }

        // Send without holding any locks
        if let Some(data) = packet_data {
            let _ = connection.send(&data).await;
        }

        // Clear rekey state BEFORE dropping the session. Otherwise a
        // concurrent in-flight rekey would race with `session = None` and
        // `rekey_in_progress` would remain `true` until the stuck-rekey
        // timeout fires, holding the client in an apparent half-rekeyed
        // state long after `disconnect()` has returned.
        self.clear_rekey_state();

        // Clear session state
        *self.session.write() = None;
        *self.tunnel_info.write() = None;

        // Reset stats tracker
        self.stats.write().reset();

        self.set_state(ClientState::Disconnected);
        let _ = self
            .event_tx
            .send(ClientEvent::Disconnected(Some("user requested".into())));

        Ok(())
    }

    /// Signal shutdown.
    pub fn shutdown(&self) {
        *self.shutdown.write() = true;
    }

    /// Check if shutdown was requested.
    pub fn is_shutdown(&self) -> bool {
        *self.shutdown.read()
    }

    /// Get bytes transferred statistics.
    pub fn bytes_transferred(&self) -> (u64, u64) {
        self.session
            .read()
            .as_ref()
            .map(|s| (s.bytes_sent(), s.bytes_received()))
            .unwrap_or((0, 0))
    }

    /// Run the receive loop (call from an async context).
    ///
    /// This handles:
    /// - Receiving packets from the server
    /// - Sending keepalives
    /// - Keepalive timeout detection
    /// - Automatic rekeying when needed
    /// - Decrypting and returning tunnel traffic via channel
    ///
    /// Use in conjunction with `start_tunnel_reader` for full tunnel operation.
    ///
    /// Returns `Err(ClientError::KeepaliveTimeout)` if connection is considered dead.
    pub async fn run_receive_loop(
        &self,
        connection: &dyn TransportTrait,
        outbound_tx: mpsc::Sender<Bytes>,
    ) -> ClientResult<()> {
        info!("Starting VPN receive loop");

        let mut recv_buf = vec![0u8; MAX_PACKET_SIZE];
        let keepalive_interval = self.config.keepalive_interval();
        let rekey_check_interval = std::time::Duration::from_secs(60);
        let timeout_check_interval = std::time::Duration::from_secs(5);

        let mut keepalive_timer = time::interval(keepalive_interval);
        let mut rekey_timer = time::interval(rekey_check_interval);
        let mut timeout_timer = time::interval(timeout_check_interval);

        loop {
            if self.is_shutdown() {
                break;
            }

            // Check for disconnected state (e.g., server sent close)
            if self.state() == ClientState::Disconnected {
                info!("Client disconnected, exiting receive loop");
                break;
            }

            tokio::select! {
                // Receive from server
                result = connection.recv(&mut recv_buf) => {
                    match result {
                        Ok((n, _addr)) if n > 0 => {
                            let inbound_msg_type = PacketHeader::decode(&recv_buf[..n]).ok().map(|h| h.msg_type);
                            let mut pooled = self.bytes_pool.get();
                            match self.process_packet(&recv_buf[..n], pooled.buffer_mut()).await {
                                Ok(Some((MessageType::Data, len))) if len > 0 => {
                                    let bytes = pooled.split_to_bytes(len);
                                    match outbound_tx.try_send(bytes) {
                                        Ok(()) => {}
                                        Err(mpsc::error::TrySendError::Full(_)) => {
                                            trace!("Dropping outbound packet: channel full");
                                            self.stats.read().atomic.on_packet_dropped();
                                        }
                                        Err(mpsc::error::TrySendError::Closed(_)) => {
                                            return Err(ClientError::Connection(
                                                "outbound channel closed".to_string(),
                                            ));
                                        }
                                    }
                                }
                                Ok(_) => {}
                                Err(e) => {
                                    if inbound_msg_type == Some(MessageType::RekeyResponse) {
                                        warn!("Rekey response processing failed, clearing rekey state: {}", e);
                                        self.clear_rekey_state();
                                    }
                                    warn!("Packet processing error: {}", e);
                                }
                            }
                        }
                        Ok(_) => {}
                        Err(e) => {
                            error!("Connection error: {}", e);
                            return Err(ClientError::Connection(format!("recv error: {}", e)));
                        }
                    }
                }

                // Send keepalive
                _ = keepalive_timer.tick() => {
                    if self.should_send_keepalive()
                        && let Err(e) = self.send_keepalive(connection).await {
                            warn!("Failed to send keepalive: {}", e);
                        }
                }

                // Check for keepalive timeout (connection dead)
                _ = timeout_timer.tick() => {
                    // check_keepalive_timeout returns the current missed count if we're past the timeout threshold
                    if let Some(missed) = self.check_keepalive_timeout() {
                        // Only emit event/check for dead connection, don't increment missed here
                        // (missed count is incremented in send_keepalive when we send without getting a reply)
                        if missed > 0 {
                            warn!("Keepalive timeout detected, missed count: {}", missed);
                            let _ = self.event_tx.send(ClientEvent::KeepaliveTimeout { missed_count: missed });
                        }

                        if self.is_connection_dead() {
                            error!("Connection dead after {} missed keepalives", missed);
                            return Err(ClientError::KeepaliveTimeout(format!(
                                "no keepalive reply after {} attempts",
                                missed
                            )));
                        }
                    }

                    // Clear stuck rekey attempts if response never arrives.
                    let rekey_timeout = self.config.connection_timeout();
                    if let Some(started_at) = *self.rekey_started_at.read()
                        && started_at.elapsed() > rekey_timeout {
                            warn!(
                                "Rekey timed out after {:?}, clearing rekey state",
                                started_at.elapsed()
                            );
                            self.clear_rekey_state();
                        }
                }

                // Check for rekey
                _ = rekey_timer.tick() => {
                    if self.needs_rekey() {
                        info!("Session needs rekey, initiating key rotation");
                        if let Err(e) = self.initiate_rekey(connection).await {
                            warn!("Failed to initiate rekey: {}", e);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Reset connection state for reconnection.
    pub fn reset_for_reconnect(&self) {
        self.reset_keepalive_state();
        self.clear_rekey_state();
    }

    /// Clear all in-memory rekey tracking state.
    fn clear_rekey_state(&self) {
        *self.rekey_handler.write() = None;
        *self.rekey_in_progress.write() = false;
        *self.rekey_started_at.write() = None;
    }

    /// Get and increment reconnect attempts counter.
    pub fn get_reconnect_attempt(&self) -> u32 {
        let mut attempts = self.reconnect_attempts.write();
        *attempts += 1;
        *attempts
    }

    /// Reset reconnect attempts counter.
    pub fn reset_reconnect_attempts(&self) {
        *self.reconnect_attempts.write() = 0;
    }

    /// Check if we should attempt reconnection.
    pub fn should_reconnect(&self) -> bool {
        if !self.config.auto_reconnect {
            return false;
        }
        let attempts = *self.reconnect_attempts.read();
        self.config.max_reconnect_attempts == 0 || attempts < self.config.max_reconnect_attempts
    }

    /// Discover NAT information using STUN.
    ///
    /// This method queries STUN servers to discover the client's public IP and port,
    /// which is useful for NAT traversal and roaming scenarios.
    ///
    /// # Privacy
    ///
    /// STUN packets are sent in clear text over UDP and expose the
    /// client's real IP to the configured servers. The list comes from
    /// [`ClientConfig::stun_servers`] and is **empty by default** —
    /// without explicit operator opt-in this method returns
    /// `ClientError::Network("STUN disabled: ...")` immediately and
    /// performs no network I/O. See `crates/hpn-client-core/src/nat.rs`
    /// for the rationale (audit CRITICAL #5: pre-tunnel STUN is a VPN
    /// bypass).
    pub fn discover_nat(&self) -> ClientResult<NatInfo> {
        if self.config.stun_servers.is_empty() {
            return Err(ClientError::Network(
                "STUN disabled: ClientConfig.stun_servers is empty (real-IP \
                 leak prevention — populate with trusted endpoints to enable)"
                    .to_string(),
            ));
        }

        let client = StunClient::new().with_servers(self.config.stun_servers.clone());
        let result = client.discover()?;

        let nat_info = NatInfo {
            public_endpoint: Some(result),
            nat_type: crate::nat::NatType::Unknown,
            local_addr: None,
        };

        *self.nat_info.write() = Some(nat_info.clone());
        let _ = self
            .event_tx
            .send(ClientEvent::NatDiscovered(nat_info.clone()));

        Ok(nat_info)
    }

    /// Get cached NAT information.
    pub fn nat_info(&self) -> Option<NatInfo> {
        self.nat_info.read().clone()
    }

    /// Send a rebind request to the server.
    ///
    /// This notifies the server that our public endpoint has changed (e.g., due to
    /// NAT rebinding or network switch). The server should update its records for
    /// this session.
    pub async fn send_rebind(
        &self,
        connection: &dyn TransportTrait,
        new_endpoint: std::net::SocketAddr,
    ) -> ClientResult<()> {
        if *self.rebind_pending.read() {
            return Err(ClientError::InvalidState("rebind already pending".into()));
        }

        info!(
            "Sending rebind notification to server for new endpoint: {}",
            new_endpoint
        );

        // Create rebind control message with the new endpoint info
        let rebind_msg = ControlMessage {
            control_type: ControlType::Rebind,
            error_code: None,
            message: Some(new_endpoint.to_string()),
            signed_payload: None,
        };

        let payload = rebind_msg.to_bytes();

        // Encrypt with read lock (encrypt_packet is &self), then release before await
        let (output, packet_len) = {
            let session = self.session.read();
            let session = session.as_ref().ok_or(ClientError::NotConnected)?;

            let mut output = vec![0u8; HEADER_SIZE + payload.len() + aead::TAG_SIZE + 32];
            let packet_len = session.encrypt_packet(MessageType::Control, &payload, &mut output)?;
            (output, packet_len)
        }; // Lock released here

        // Send without holding any locks
        connection.send(&output[..packet_len]).await?;
        *self.rebind_pending.write() = true;

        let _ = self
            .event_tx
            .send(ClientEvent::RebindRequested { new_endpoint });

        debug!("Sent rebind request ({} bytes)", packet_len);
        Ok(())
    }

    /// Check if a rebind is pending acknowledgment.
    pub fn is_rebind_pending(&self) -> bool {
        *self.rebind_pending.read()
    }

    /// Automatically detect and handle NAT rebinding.
    ///
    /// Call this periodically or after network changes to detect if our public
    /// endpoint has changed and notify the server if needed.
    pub async fn check_and_rebind(&self, connection: &dyn TransportTrait) -> ClientResult<bool> {
        // Get current NAT info
        let old_endpoint = self
            .nat_info
            .read()
            .as_ref()
            .and_then(|info| info.public_endpoint.as_ref())
            .map(|e| e.socket_addr());

        // Discover current endpoint
        let new_info = self.discover_nat()?;
        let new_endpoint = new_info.public_endpoint.as_ref().map(|e| e.socket_addr());

        // Check if endpoint changed
        match (old_endpoint, new_endpoint) {
            (Some(old), Some(new)) if old != new => {
                info!("NAT rebind detected: {} -> {}", old, new);
                self.send_rebind(connection, new).await?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Process inbound tunnel data and send encrypted to server.
    ///
    /// Call this for each packet read from the tunnel device.
    pub async fn process_tunnel_packet(
        &self,
        connection: &dyn TransportTrait,
        data: &[u8],
    ) -> ClientResult<()> {
        self.send_data(connection, data).await
    }

    /// Attempt to reconnect to the server.
    ///
    /// This method:
    /// 1. Resets the client state for reconnection
    /// 2. Attempts to reconnect with exponential backoff
    /// 3. Emits reconnection events
    ///
    /// Returns `Ok(TunnelInfo)` on successful reconnection, or an error after
    /// all attempts are exhausted.
    pub async fn attempt_reconnect(
        &self,
        connection: &dyn TransportTrait,
    ) -> ClientResult<TunnelInfo> {
        if !self.should_reconnect() {
            return Err(ClientError::ReconnectionFailed(
                "auto-reconnect disabled or max attempts reached".into(),
            ));
        }

        self.set_state(ClientState::Reconnecting);

        loop {
            let attempt = self.get_reconnect_attempt();
            let max_attempts = self.config.max_reconnect_attempts;

            // Emit reconnecting event
            let _ = self.event_tx.send(ClientEvent::Reconnecting {
                attempt,
                max_attempts,
            });

            info!(
                "Reconnection attempt {}/{}",
                attempt,
                if max_attempts == 0 {
                    "∞".to_string()
                } else {
                    max_attempts.to_string()
                }
            );

            // Calculate delay with exponential backoff
            let delay = self
                .config
                .reconnect_delay_with_backoff(attempt.saturating_sub(1));
            info!("Waiting {:?} before reconnection attempt", delay);
            time::sleep(delay).await;

            // Check if we should stop
            if self.is_shutdown() {
                return Err(ClientError::Shutdown);
            }

            // Reset state for reconnection
            self.reset_for_reconnect();
            *self.session.write() = None;
            *self.tunnel_info.write() = None;
            self.stats.write().reset();

            // Refresh the underlying network socket before reconnecting.
            //
            // On laptops that wake from sleep, on Wi-Fi ↔ Ethernet
            // hand-off, or after the physical network adapter was
            // toggled, the original kernel UDP socket can be silently
            // dead: `send_to` fails with ENETUNREACH / EBADF, yet every
            // retry uses the same stale handle and loops forever on the
            // same failure. `rebind()` swaps in a fresh socket bound to
            // the current egress interface; TCP transports override it
            // to a no-op since they reconnect via `close` + `connect`.
            //
            // Failures here are logged but non-fatal: if the network is
            // still down, the next `connect()` below will fail with a
            // clearer error and the backoff loop will retry — at least
            // on a socket the kernel hasn't disowned.
            if let Err(e) = connection.rebind().await {
                warn!(
                    "Failed to rebind transport before reconnection attempt {}: {}. \
                     Continuing with existing socket.",
                    attempt, e
                );
            }

            // Attempt to connect
            match self.connect(connection).await {
                Ok(tunnel_info) => {
                    info!("Reconnection successful after {} attempts", attempt);
                    self.reset_reconnect_attempts();
                    return Ok(tunnel_info);
                }
                Err(e) => {
                    warn!("Reconnection attempt {} failed: {}", attempt, e);

                    // Check if we've exhausted attempts
                    if !self.should_reconnect() {
                        let msg = format!("reconnection failed after {} attempts: {}", attempt, e);
                        self.set_state(ClientState::Disconnected);
                        let _ = self.event_tx.send(ClientEvent::ReconnectionFailed {
                            reason: msg.clone(),
                        });
                        return Err(ClientError::ReconnectionFailed(msg));
                    }
                }
            }
        }
    }

    /// Run the VPN connection with automatic reconnection.
    ///
    /// This is a high-level helper that:
    /// 1. Connects to the server
    /// 2. Runs the receive loop
    /// 3. Automatically reconnects on connection loss (if enabled)
    ///
    /// The `on_connected` callback is called each time a connection is established
    /// (including reconnections). Use it to set up routing, etc.
    ///
    /// This function returns when:
    /// - Shutdown is requested
    /// - Reconnection fails permanently
    /// - A fatal error occurs
    pub async fn run_with_reconnect<F, Fut>(
        &self,
        connection: &dyn TransportTrait,
        outbound_tx: mpsc::Sender<Bytes>,
        mut on_connected: F,
    ) -> ClientResult<()>
    where
        F: FnMut(&TunnelInfo) -> Fut,
        Fut: std::future::Future<Output = ClientResult<()>>,
    {
        // Initial connection
        let mut tunnel_info = self.connect(connection).await?;
        on_connected(&tunnel_info).await?;

        loop {
            // Run the receive loop
            let result = self.run_receive_loop(connection, outbound_tx.clone()).await;

            match result {
                Ok(()) => {
                    // Clean exit (shutdown or explicit disconnect)
                    if self.is_shutdown() || self.state() == ClientState::Disconnected {
                        info!("VPN connection ended normally");
                        return Ok(());
                    }
                }
                Err(ClientError::KeepaliveTimeout(_))
                | Err(ClientError::Connection(_))
                | Err(ClientError::ConnectionIo(_)) => {
                    // Connection lost - try to reconnect
                    warn!("Connection lost, attempting to reconnect");

                    if self.config.auto_reconnect && self.should_reconnect() {
                        match self.attempt_reconnect(connection).await {
                            Ok(info) => {
                                tunnel_info = info;
                                on_connected(&tunnel_info).await?;
                                // Continue the loop
                            }
                            Err(e) => {
                                return Err(e);
                            }
                        }
                    } else {
                        return Err(ClientError::ReconnectionFailed(
                            "connection lost and auto-reconnect disabled".into(),
                        ));
                    }
                }
                Err(ClientError::Shutdown) => {
                    info!("VPN connection shutdown requested");
                    return Ok(());
                }
                Err(e) => {
                    // Other errors - don't reconnect
                    error!("Fatal VPN error: {}", e);
                    return Err(e);
                }
            }
        }
    }
}

impl Drop for VpnClient {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_state_default() {
        // Cannot easily test without a valid config, but we can test the state enum
        assert_ne!(ClientState::Connected, ClientState::Disconnected);
    }
}
