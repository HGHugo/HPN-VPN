//! High-performance data path for AF_XDP.
//!
//! This module provides the fast path for packet processing with AF_XDP,
//! including encryption/decryption using AES-256-GCM.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use parking_lot::RwLock;
use tracing::warn;

use hpn_core::crypto::aead::{PrecomputedKey, TAG_SIZE};
use hpn_core::protocol::header::{HEADER_SIZE, PacketHeader};
use hpn_core::types::{Counter, KeyId, MessageType, SessionId};

use crate::error::{AfXdpError, Result};
use crate::socket::XskSocket;

// ============================================================================
// Session State
// ============================================================================

/// Session encryption state.
///
/// Contains all cryptographic material needed for a single VPN session.
const DEFAULT_SESSION_RATE_LIMIT_PPS: u32 = 2_000_000;
const DEFAULT_SESSION_RATE_LIMIT_BPS: u64 = 0;

/// Global start instant for efficient timestamps (no syscall in hot path).
static START_INSTANT: OnceLock<Instant> = OnceLock::new();

#[inline]
fn now_us() -> u64 {
    let start = START_INSTANT.get_or_init(Instant::now);
    start.elapsed().as_micros() as u64
}

pub struct SessionCrypto {
    /// Session identifier.
    pub session_id: SessionId,
    /// Current encryption key (pre-computed for performance).
    tx_key: PrecomputedKey,
    /// Current decryption key (pre-computed for performance).
    rx_key: PrecomputedKey,
    /// Nonce prefix for this session (4 bytes, derived from handshake).
    nonce_prefix: [u8; 4],
    /// Current TX counter (atomic for thread safety).
    tx_counter: AtomicU64,
    /// Current RX anti-replay window base.
    rx_window_base: AtomicU64,
    /// Anti-replay bitmap (64 packets sliding window).
    rx_bitmap: AtomicU64,
    /// Current key ID.
    pub key_id: KeyId,
    /// Maximum packets per second (0 = unlimited).
    rate_limit_pps: u32,
    /// Maximum bytes per second (0 = unlimited).
    rate_limit_bps: u64,
    /// Token bucket for packet rate limiting.
    packet_tokens: AtomicU64,
    /// Token bucket for byte rate limiting.
    byte_tokens: AtomicU64,
    /// Last token refill timestamp.
    last_refill_us: AtomicU64,
}

impl SessionCrypto {
    /// Create a new session crypto state.
    pub fn new(
        session_id: SessionId,
        tx_key: [u8; 32],
        rx_key: [u8; 32],
        nonce_prefix: [u8; 4],
        key_id: KeyId,
    ) -> Result<Self> {
        Self::new_with_rate_limit(
            session_id,
            tx_key,
            rx_key,
            nonce_prefix,
            key_id,
            DEFAULT_SESSION_RATE_LIMIT_PPS,
            DEFAULT_SESSION_RATE_LIMIT_BPS,
        )
    }

    /// Create a new session crypto state with custom rate limits.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_rate_limit(
        session_id: SessionId,
        tx_key: [u8; 32],
        rx_key: [u8; 32],
        nonce_prefix: [u8; 4],
        key_id: KeyId,
        rate_limit_pps: u32,
        rate_limit_bps: u64,
    ) -> Result<Self> {
        let tx_precomputed = PrecomputedKey::new(&tx_key).map_err(AfXdpError::Crypto)?;
        let rx_precomputed = PrecomputedKey::new(&rx_key).map_err(AfXdpError::Crypto)?;

        let now = now_us();

        Ok(Self {
            session_id,
            tx_key: tx_precomputed,
            rx_key: rx_precomputed,
            nonce_prefix,
            tx_counter: AtomicU64::new(0),
            rx_window_base: AtomicU64::new(0),
            rx_bitmap: AtomicU64::new(0),
            key_id,
            rate_limit_pps,
            rate_limit_bps,
            packet_tokens: AtomicU64::new(rate_limit_pps as u64 * 2),
            byte_tokens: AtomicU64::new(rate_limit_bps.saturating_mul(2)),
            last_refill_us: AtomicU64::new(now),
        })
    }

    /// Get and increment the TX counter.
    #[inline]
    pub fn next_tx_counter(&self) -> u64 {
        self.tx_counter.fetch_add(1, Ordering::Relaxed)
    }

    /// Check if a counter value is valid (anti-replay).
    ///
    /// Returns true if the packet should be accepted.
    #[inline]
    pub fn check_replay(&self, counter: u64) -> bool {
        let base = self.rx_window_base.load(Ordering::Acquire);

        if counter < base {
            // Too old
            return false;
        }

        if counter >= base + 64 {
            // Far in the future - accept and update window
            let new_base = counter.saturating_sub(63);
            self.rx_window_base.store(new_base, Ordering::Release);
            self.rx_bitmap
                .store(1 << (counter - new_base), Ordering::Release);
            return true;
        }

        // Within window - check bitmap
        let bit_pos = counter - base;
        let bit = 1u64 << bit_pos;
        let old_bitmap = self.rx_bitmap.fetch_or(bit, Ordering::AcqRel);

        // Accept only if bit wasn't already set (first time seeing this packet)
        old_bitmap & bit == 0
    }

    /// Check if a packet is allowed by this session's rate limiter.
    #[inline]
    pub fn check_rate_limit(&self, bytes: usize) -> bool {
        if self.rate_limit_pps == 0 && self.rate_limit_bps == 0 {
            return true;
        }

        self.refill_rate_tokens();

        if self.rate_limit_pps > 0
            && self
                .packet_tokens
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |tokens| {
                    if tokens > 0 { Some(tokens - 1) } else { None }
                })
                .is_err()
        {
            return false;
        }

        if self.rate_limit_bps > 0 {
            let bytes_u64 = bytes as u64;
            if self
                .byte_tokens
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |tokens| {
                    if tokens >= bytes_u64 {
                        Some(tokens - bytes_u64)
                    } else {
                        None
                    }
                })
                .is_err()
            {
                if self.rate_limit_pps > 0 {
                    self.packet_tokens.fetch_add(1, Ordering::Relaxed);
                }
                return false;
            }
        }

        true
    }

    #[inline]
    fn refill_rate_tokens(&self) {
        let now = now_us();
        let last = self.last_refill_us.load(Ordering::Relaxed);
        let elapsed_us = now.saturating_sub(last);

        if elapsed_us < 1000 {
            return;
        }

        if self
            .last_refill_us
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        if self.rate_limit_pps > 0 {
            let add_packets =
                ((elapsed_us as u128 * self.rate_limit_pps as u128) / 1_000_000) as u64;
            let max_packets = self.rate_limit_pps as u64 * 2;
            let _ =
                self.packet_tokens
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                        Some(current.saturating_add(add_packets).min(max_packets))
                    });
        }

        if self.rate_limit_bps > 0 {
            let add_bytes = ((elapsed_us as u128 * self.rate_limit_bps as u128) / 1_000_000) as u64;
            let max_bytes = self.rate_limit_bps.saturating_mul(2);
            let _ =
                self.byte_tokens
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                        Some(current.saturating_add(add_bytes).min(max_bytes))
                    });
        }
    }

    /// Encrypt data using this session's TX key.
    #[inline]
    pub fn encrypt(
        &self,
        counter: u64,
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> std::result::Result<usize, hpn_core::error::CryptoError> {
        self.tx_key
            .encrypt(&self.nonce_prefix, counter, aad, plaintext, ciphertext)
    }

    /// Decrypt data using this session's RX key.
    #[inline]
    pub fn decrypt(
        &self,
        counter: u64,
        aad: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> std::result::Result<usize, hpn_core::error::CryptoError> {
        self.rx_key
            .decrypt(&self.nonce_prefix, counter, aad, ciphertext, plaintext)
    }
}

/// Shared session crypto handle.
pub type SharedSessionCrypto = Arc<SessionCrypto>;

// ============================================================================
// Session Table
// ============================================================================

/// Session lookup table.
///
/// Maps session IDs to their cryptographic state for fast lookup during
/// packet processing.
pub struct SessionTable {
    /// Map of session ID to session crypto.
    sessions: RwLock<HashMap<u64, SharedSessionCrypto>>,
}

impl SessionTable {
    /// Create a new empty session table.
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }

    /// Add a session.
    pub fn add(&self, session: SharedSessionCrypto) {
        let mut sessions = self.sessions.write();
        sessions.insert(session.session_id.0, session);
    }

    /// Remove a session.
    pub fn remove(&self, session_id: SessionId) -> Option<SharedSessionCrypto> {
        let mut sessions = self.sessions.write();
        sessions.remove(&session_id.0)
    }

    /// Look up a session by ID.
    #[inline]
    pub fn get(&self, session_id: u64) -> Option<SharedSessionCrypto> {
        let sessions = self.sessions.read();
        sessions.get(&session_id).cloned()
    }

    /// Number of active sessions.
    pub fn len(&self) -> usize {
        self.sessions.read().len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.sessions.read().is_empty()
    }
}

impl Default for SessionTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared session table handle.
pub type SharedSessionTable = Arc<SessionTable>;

// ============================================================================
// Data Path Processor
// ============================================================================

/// Batch processing statistics.
#[derive(Debug, Default, Clone)]
pub struct BatchStats {
    /// Packets received.
    pub rx_packets: u64,
    /// Packets transmitted.
    pub tx_packets: u64,
    /// Bytes received (after decryption).
    pub rx_bytes: u64,
    /// Bytes transmitted (before encryption).
    pub tx_bytes: u64,
    /// Packets dropped (decryption failure).
    pub decrypt_errors: u64,
    /// Packets dropped (unknown session).
    pub unknown_session: u64,
    /// Packets dropped (replay detected).
    pub replay_drops: u64,
    /// Packets dropped (invalid header).
    pub header_errors: u64,
}

/// Data path processor for AF_XDP.
///
/// Handles high-performance packet encryption and decryption using
/// zero-copy AF_XDP sockets.
pub struct DataPath {
    /// Session table for crypto lookups.
    sessions: SharedSessionTable,
    /// Processing statistics.
    stats: BatchStats,
}

impl DataPath {
    /// Create a new data path processor.
    pub fn new(sessions: SharedSessionTable) -> Self {
        Self {
            sessions,
            stats: BatchStats::default(),
        }
    }

    /// Process received packets (decrypt).
    ///
    /// Returns the number of successfully processed packets.
    pub fn process_rx<F>(&mut self, socket: &mut XskSocket, mut handler: F) -> Result<u32>
    where
        F: FnMut(SessionId, &[u8]),
    {
        let mut processed = 0;
        let sessions = Arc::clone(&self.sessions);
        let stats = &mut self.stats;

        socket.recv_batch(64, |encrypted_packet| {
            stats.rx_packets += 1;

            // Parse header - minimum size check
            if encrypted_packet.len() < HEADER_SIZE + TAG_SIZE {
                stats.header_errors += 1;
                return true; // Continue processing
            }

            let header = match PacketHeader::decode(encrypted_packet) {
                Ok(h) => h,
                Err(_) => {
                    stats.header_errors += 1;
                    return true;
                }
            };

            // Only process data packets
            if header.msg_type != MessageType::Data {
                return true;
            }

            // Look up session
            let session = match sessions.get(header.session_id.0) {
                Some(s) => s,
                None => {
                    stats.unknown_session += 1;
                    return true;
                }
            };

            // Check replay
            if !session.check_replay(header.counter.0) {
                stats.replay_drops += 1;
                return true;
            }

            // Decrypt
            let header_size = header.encoded_size();
            let ciphertext = &encrypted_packet[header_size..];

            // Allocate buffer for decryption
            let mut plaintext = vec![0u8; ciphertext.len()];

            match session.decrypt(
                header.counter.0,
                &encrypted_packet[..header_size], // AAD is the header
                ciphertext,
                &mut plaintext,
            ) {
                Ok(pt_len) => {
                    stats.rx_bytes += pt_len as u64;
                    handler(header.session_id, &plaintext[..pt_len]);
                    processed += 1;
                }
                Err(_) => {
                    stats.decrypt_errors += 1;
                }
            }

            true // Continue processing
        })?;

        Ok(processed)
    }

    /// Encrypt and transmit a packet.
    ///
    /// # Arguments
    /// * `socket` - The XSK socket to transmit on
    /// * `session_id` - Session to use for encryption
    /// * `plaintext` - The plaintext data to encrypt and send
    pub fn process_tx(
        &mut self,
        socket: &mut XskSocket,
        session_id: SessionId,
        plaintext: &[u8],
    ) -> Result<()> {
        // Look up session
        let session = self
            .sessions
            .get(session_id.0)
            .ok_or(AfXdpError::SessionNotFound(session_id.0))?;

        // Get next counter
        let counter = session.next_tx_counter();

        // Build header
        let header = PacketHeader::new(
            MessageType::Data,
            session_id,
            session.key_id,
            Counter(counter),
        );

        let header_size = header.encoded_size();
        let total_size = header_size + plaintext.len() + TAG_SIZE;

        // Reserve frame from socket
        let (addr, buf) = socket
            .send_reserve(total_size as u32)
            .ok_or(AfXdpError::UmemExhausted)?;

        // Encode header
        header
            .encode(&mut buf[..header_size])
            .map_err(AfXdpError::Protocol)?;

        // Encrypt payload directly into the buffer after header
        let ct_len = session
            .encrypt(
                counter,
                &buf[..header_size], // AAD is the header
                plaintext,
                &mut buf[header_size..],
            )
            .map_err(AfXdpError::Crypto)?;

        // Submit for transmission
        socket.send_submit(addr, (header_size + ct_len) as u32);

        self.stats.tx_packets += 1;
        self.stats.tx_bytes += plaintext.len() as u64;

        Ok(())
    }

    /// Encrypt and transmit multiple packets in a batch.
    ///
    /// Returns the number of successfully transmitted packets.
    pub fn process_tx_batch(
        &mut self,
        socket: &mut XskSocket,
        packets: &[(SessionId, &[u8])],
    ) -> Result<u32> {
        let mut sent = 0;

        for (session_id, plaintext) in packets {
            match self.process_tx(socket, *session_id, plaintext) {
                Ok(()) => sent += 1,
                Err(AfXdpError::UmemExhausted) => break, // TX ring full
                Err(e) => {
                    warn!("TX error for session {}: {}", session_id.0, e);
                }
            }
        }

        if sent > 0 {
            socket.flush()?;
        }

        Ok(sent)
    }

    /// Get processing statistics.
    pub fn stats(&self) -> &BatchStats {
        &self.stats
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = BatchStats::default();
    }

    /// Get the session table.
    pub fn sessions(&self) -> &SharedSessionTable {
        &self.sessions
    }
}

// ============================================================================
// Fast Path Worker
// ============================================================================

/// Configuration for the data path worker.
#[derive(Debug, Clone)]
pub struct WorkerConfig {
    /// Maximum batch size for RX processing.
    pub rx_batch_size: u32,
    /// Maximum batch size for TX processing.
    pub tx_batch_size: u32,
    /// Whether to use busy polling (lower latency, higher CPU).
    pub busy_poll: bool,
    /// Poll timeout in milliseconds (if not busy polling).
    pub poll_timeout_ms: i32,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            rx_batch_size: 64,
            tx_batch_size: 64,
            busy_poll: false,
            poll_timeout_ms: 1,
        }
    }
}

/// High-performance worker for data path processing.
///
/// Runs a tight loop processing RX and TX packets using AF_XDP.
pub struct DataPathWorker {
    /// XSK socket for this worker.
    socket: XskSocket,
    /// Data path processor.
    datapath: DataPath,
    /// Worker configuration.
    config: WorkerConfig,
    /// Worker ID (for logging).
    id: u32,
}

impl DataPathWorker {
    /// Create a new data path worker.
    pub fn new(
        socket: XskSocket,
        sessions: SharedSessionTable,
        config: WorkerConfig,
        id: u32,
    ) -> Self {
        Self {
            socket,
            datapath: DataPath::new(sessions),
            config,
            id,
        }
    }

    /// Run one iteration of the processing loop.
    ///
    /// Returns the number of packets processed.
    pub fn poll_once<F>(&mut self, rx_handler: F) -> Result<u32>
    where
        F: FnMut(SessionId, &[u8]),
    {
        // Poll socket if not busy polling
        if !self.config.busy_poll {
            let (can_rx, _) = self.socket.poll(self.config.poll_timeout_ms)?;
            if !can_rx {
                return Ok(0);
            }
        }

        // Process RX
        self.datapath.process_rx(&mut self.socket, rx_handler)
    }

    /// Send a packet through this worker.
    pub fn send(&mut self, session_id: SessionId, data: &[u8]) -> Result<()> {
        self.datapath.process_tx(&mut self.socket, session_id, data)
    }

    /// Send multiple packets in a batch.
    pub fn send_batch(&mut self, packets: &[(SessionId, &[u8])]) -> Result<u32> {
        self.datapath.process_tx_batch(&mut self.socket, packets)
    }

    /// Flush pending TX packets.
    pub fn flush(&mut self) -> Result<()> {
        self.socket.flush()
    }

    /// Get worker ID.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Get processing statistics.
    pub fn stats(&self) -> &BatchStats {
        self.datapath.stats()
    }

    /// Get the XSK socket.
    pub fn socket(&self) -> &XskSocket {
        &self.socket
    }

    /// Get mutable reference to the XSK socket.
    pub fn socket_mut(&mut self) -> &mut XskSocket {
        &mut self.socket
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_table_basic() {
        let table = SessionTable::new();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn test_session_table_default() {
        let table = SessionTable::default();
        assert!(table.is_empty());
    }

    #[test]
    fn test_session_crypto_counter() {
        let session = SessionCrypto::new(
            SessionId(1),
            [0x42u8; 32],
            [0x43u8; 32],
            [1, 2, 3, 4],
            KeyId(0),
        )
        .unwrap();

        assert_eq!(session.next_tx_counter(), 0);
        assert_eq!(session.next_tx_counter(), 1);
        assert_eq!(session.next_tx_counter(), 2);
    }

    #[test]
    fn test_session_replay_protection() {
        let session = SessionCrypto::new(
            SessionId(1),
            [0x42u8; 32],
            [0x43u8; 32],
            [1, 2, 3, 4],
            KeyId(0),
        )
        .unwrap();

        // First packet should be accepted
        assert!(session.check_replay(0));

        // Same counter should be rejected (replay)
        assert!(!session.check_replay(0));

        // Next counter should be accepted
        assert!(session.check_replay(1));

        // Skip some counters
        assert!(session.check_replay(10));
        assert!(session.check_replay(5)); // Still in window

        // Replay of 5 should be rejected
        assert!(!session.check_replay(5));
    }

    #[test]
    fn test_session_replay_window_advance() {
        let session = SessionCrypto::new(
            SessionId(1),
            [0x42u8; 32],
            [0x43u8; 32],
            [1, 2, 3, 4],
            KeyId(0),
        )
        .unwrap();

        // Accept first packet
        assert!(session.check_replay(0));

        // Jump far ahead (beyond window)
        assert!(session.check_replay(100));

        // Old packets should now be rejected
        assert!(!session.check_replay(0));
        assert!(!session.check_replay(30));

        // Packets in new window should work
        assert!(session.check_replay(99));
        assert!(session.check_replay(98));
    }

    #[test]
    fn test_session_rate_limit_pps() {
        let session = SessionCrypto::new_with_rate_limit(
            SessionId(1),
            [0x42u8; 32],
            [0x43u8; 32],
            [1, 2, 3, 4],
            KeyId(0),
            2,
            0,
        )
        .unwrap();

        // Initial burst allows up to 2x max_pps tokens
        assert!(session.check_rate_limit(100));
        assert!(session.check_rate_limit(100));
        assert!(session.check_rate_limit(100));
        assert!(session.check_rate_limit(100));
        assert!(!session.check_rate_limit(100));
    }

    #[test]
    fn test_batch_stats_default() {
        let stats = BatchStats::default();
        assert_eq!(stats.rx_packets, 0);
        assert_eq!(stats.tx_packets, 0);
        assert_eq!(stats.rx_bytes, 0);
        assert_eq!(stats.tx_bytes, 0);
    }

    #[test]
    fn test_worker_config_default() {
        let config = WorkerConfig::default();
        assert_eq!(config.rx_batch_size, 64);
        assert_eq!(config.tx_batch_size, 64);
        assert!(!config.busy_poll);
        assert_eq!(config.poll_timeout_ms, 1);
    }
}
