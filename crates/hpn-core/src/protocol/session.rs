//! Session state management and anti-replay protection.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

/// Coarse monotonic clock for lock-free last-activity tracking.
/// Stores milliseconds since an epoch (process start) as AtomicU64.
/// Avoids mutex per-packet for `touch()`.
struct AtomicInstant {
    /// Milliseconds since `epoch`.
    millis: AtomicU64,
    /// Reference point (set once at creation).
    epoch: Instant,
}

impl AtomicInstant {
    fn new() -> Self {
        Self {
            millis: AtomicU64::new(0),
            epoch: Instant::now(),
        }
    }

    #[inline]
    fn touch(&self) {
        let now = self.epoch.elapsed().as_millis() as u64;
        self.millis.store(now, Ordering::Relaxed);
    }

    #[inline]
    fn elapsed(&self) -> Duration {
        let stored = self.millis.load(Ordering::Relaxed);
        let now = self.epoch.elapsed().as_millis() as u64;
        Duration::from_millis(now.saturating_sub(stored))
    }
}

use crate::crypto::{PrecomputedKey, SessionKeys, aead};
use crate::error::{CryptoError, ProtocolError, SessionError};
use crate::protocol::header::{HEADER_SIZE, PacketHeader};
use crate::types::{Counter, KeyId, MessageType, SessionId};

/// Anti-replay window size in bits.
/// - At 1 Gbps (1500-byte packets): ~25ms tolerance
/// - At 2.5 Gbps: ~10ms tolerance
///
/// Memory cost: 1024 bytes per session (64 × u128)
/// Must be large enough for multi-worker reordering at high throughput.
/// At 1200 Mbps (~100K pps), 8192 gives ~82ms reordering tolerance.
const REPLAY_WINDOW_SIZE: u64 = 8192;

/// Session state enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    /// Session is being established (handshake in progress).
    Handshaking,
    /// Session is active and can send/receive data.
    Active,
    /// Session is being rekeyed.
    Rekeying,
    /// Session has been closed.
    Closed,
}

/// Number of u128 words in the bitmap (8192 / 128 = 64).
const BITMAP_WORDS: usize = (REPLAY_WINDOW_SIZE as usize) / 128;

/// Anti-replay sliding window.
///
/// Tracks seen packet counters to prevent replay attacks.
/// Thread-safe: uses atomic operations and mutex for concurrent access.
pub struct AntiReplayWindow {
    /// Highest counter seen (atomic for lock-free reads).
    last_counter: AtomicU64,
    /// Bitmap of seen counters within the window (mutex-protected).
    /// bitmap[0] = bits 0-127 (most recent), bitmap[3] = bits 384-511 (oldest)
    bitmap: Mutex<[u128; BITMAP_WORDS]>,
}

impl AntiReplayWindow {
    /// Create a new anti-replay window.
    #[must_use]
    pub fn new() -> Self {
        Self {
            last_counter: AtomicU64::new(0),
            bitmap: Mutex::new([0u128; BITMAP_WORDS]),
        }
    }

    /// Check if a counter is valid (not a replay) and update the window.
    ///
    /// Thread-safe: can be called from multiple threads concurrently.
    /// Returns `true` if the counter is valid, `false` if it's a replay.
    pub fn check_and_update(&self, counter: Counter) -> bool {
        let counter_val = counter.0;

        // Lock the bitmap for the entire operation to ensure atomicity
        let mut bitmap = self.bitmap.lock();
        let last = self.last_counter.load(Ordering::Acquire);

        if counter_val > last {
            // New highest counter - shift window and set bit
            let shift = counter_val - last;
            Self::shift_bitmap(&mut bitmap, shift);
            bitmap[0] |= 1;
            self.last_counter.store(counter_val, Ordering::Release);
            true
        } else {
            // Counter is <= highest - check bitmap for replay
            let diff = last - counter_val;
            if diff >= REPLAY_WINDOW_SIZE {
                // Too old - outside window
                return false;
            }

            // Check if already seen in bitmap
            let word_idx = (diff as usize) / 128;
            let bit_idx = (diff as usize) % 128;

            if word_idx >= BITMAP_WORDS {
                return false;
            }

            let mask = 1u128 << bit_idx;
            if bitmap[word_idx] & mask != 0 {
                // Already seen
                false
            } else {
                // Mark as seen
                bitmap[word_idx] |= mask;
                true
            }
        }
    }

    /// Check if a counter would be valid without updating.
    /// Thread-safe: can be called from multiple threads concurrently.
    #[must_use]
    pub fn check(&self, counter: Counter) -> bool {
        let counter_val = counter.0;
        let bitmap = self.bitmap.lock();
        let last = self.last_counter.load(Ordering::Relaxed);

        if counter_val > last {
            // New counter - would be valid
            true
        } else {
            // Counter is <= highest - check bitmap for replay
            let diff = last - counter_val;
            if diff >= REPLAY_WINDOW_SIZE {
                return false;
            }

            let word_idx = (diff as usize) / 128;
            let bit_idx = (diff as usize) % 128;

            if word_idx >= BITMAP_WORDS {
                return false;
            }

            let mask = 1u128 << bit_idx;
            bitmap[word_idx] & mask == 0
        }
    }

    /// Reset the anti-replay window (for rekey operations).
    pub fn reset(&self) {
        self.last_counter.store(0, Ordering::SeqCst);
        let mut bitmap = self.bitmap.lock();
        for word in bitmap.iter_mut() {
            *word = 0;
        }
    }

    /// Shift bitmap left by n positions.
    #[inline]
    fn shift_bitmap(bitmap: &mut [u128; BITMAP_WORDS], shift: u64) {
        if shift >= REPLAY_WINDOW_SIZE {
            // Clear entire bitmap
            for word in bitmap.iter_mut() {
                *word = 0;
            }
            return;
        }

        let shift = shift as usize;
        let word_shift = shift / 128;
        let bit_shift = shift % 128;

        // Shift by whole words first (from high index to low)
        if word_shift > 0 {
            for i in (word_shift..BITMAP_WORDS).rev() {
                bitmap[i] = bitmap[i - word_shift];
            }
            for word in bitmap.iter_mut().take(word_shift) {
                *word = 0;
            }
        }

        // Shift remaining bits within words
        if bit_shift > 0 {
            for i in (1..BITMAP_WORDS).rev() {
                bitmap[i] = (bitmap[i] << bit_shift) | (bitmap[i - 1] >> (128 - bit_shift));
            }
            bitmap[0] <<= bit_shift;
        }
    }
}

impl Default for AntiReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for AntiReplayWindow {
    fn clone(&self) -> Self {
        let bitmap_guard = self.bitmap.lock();
        Self {
            last_counter: AtomicU64::new(self.last_counter.load(Ordering::SeqCst)),
            bitmap: Mutex::new(*bitmap_guard),
        }
    }
}

impl std::fmt::Debug for AntiReplayWindow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AntiReplayWindow")
            .field("last_counter", &self.last_counter.load(Ordering::Relaxed))
            .finish()
    }
}

/// VPN session state.
///
/// Thread-safe: supports parallel encryption and decryption.
/// Uses atomic counters and mutex-protected state for concurrent access.
pub struct Session {
    /// Session identifier.
    session_id: SessionId,
    /// Current key identifier.
    key_id: KeyId,
    /// Session state.
    state: SessionState,
    /// Current session keys.
    keys: SessionKeys,
    /// Pre-computed send key (avoids per-packet key schedule overhead).
    send_key: PrecomputedKey,
    /// Pre-computed receive key (avoids per-packet key schedule overhead).
    recv_key: PrecomputedKey,
    /// Send counter (monotonically increasing, atomic for parallel encryption).
    send_counter: AtomicU64,
    /// Anti-replay window for received packets (thread-safe).
    recv_window: AntiReplayWindow,
    /// Time of last activity (lock-free atomic tracking).
    last_activity: AtomicInstant,
    /// Session creation time.
    created_at: Instant,
    /// Total bytes sent (atomic for parallel updates).
    bytes_sent: AtomicU64,
    /// Total bytes received (atomic for parallel updates).
    bytes_received: AtomicU64,
}

impl Session {
    /// Create a new session.
    ///
    /// Pre-computes AES-GCM keys for high-performance encryption/decryption.
    /// This avoids ~200 CPU cycles per packet for key schedule computation.
    ///
    /// Returns `Err(CryptoError)` if key material is invalid.
    pub fn new(
        session_id: SessionId,
        keys: SessionKeys,
    ) -> Result<Self, crate::error::CryptoError> {
        let now = Instant::now();
        // Pre-compute keys once at session creation
        let send_key = PrecomputedKey::new(&keys.send_key)?;
        let recv_key = PrecomputedKey::new(&keys.recv_key)?;
        let last_activity = AtomicInstant::new();
        last_activity.touch(); // Mark as active now
        Ok(Self {
            session_id,
            key_id: KeyId::initial(),
            state: SessionState::Active,
            keys,
            send_key,
            recv_key,
            send_counter: AtomicU64::new(0),
            recv_window: AntiReplayWindow::new(),
            last_activity,
            created_at: now,
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
        })
    }

    /// Get the session ID.
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Get a reference to the session keys (for debugging only).
    #[must_use]
    pub fn keys(&self) -> &SessionKeys {
        &self.keys
    }

    /// Get the current key ID.
    #[must_use]
    pub const fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// Get the session state.
    #[must_use]
    pub const fn state(&self) -> SessionState {
        self.state
    }

    /// Check if the session is active.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.state, SessionState::Active)
    }

    /// Get the next send counter and increment it atomically.
    /// Thread-safe: can be called from multiple threads concurrently.
    ///
    /// Uses compare-and-swap (CAS) loop to prevent counter exhaustion race conditions.
    /// This ensures the counter never exceeds MAX_SAFE, even under high concurrency.
    ///
    /// # Errors
    ///
    /// Returns `SessionError::CounterExhausted` if the counter exceeds MAX_SAFE.
    /// This prevents nonce reuse which would break AEAD security.
    /// The session MUST be rekeyed before this point.
    #[inline]
    pub fn next_send_counter(&self) -> Result<Counter, SessionError> {
        loop {
            let current = self.send_counter.load(Ordering::Acquire);

            // Check if we've already exceeded the safety threshold
            if current >= Counter::MAX_SAFE {
                return Err(SessionError::CounterExhausted);
            }

            // Try to atomically increment the counter
            if self
                .send_counter
                .compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return Ok(Counter(current));
            }

            // CAS failed, another thread incremented - retry
            std::hint::spin_loop();
        }
    }

    /// Check if a received counter is valid (not a replay).
    #[must_use]
    pub fn is_valid_counter(&self, counter: Counter) -> bool {
        self.recv_window.check(counter)
    }

    /// Update the receive window with a validated counter.
    ///
    /// Thread-safe: can be called from multiple threads concurrently.
    /// Call this after successfully decrypting a packet.
    pub fn update_recv_counter(&self, counter: Counter) -> bool {
        self.recv_window.check_and_update(counter)
    }

    /// Update last activity time.
    /// Thread-safe: lock-free atomic store.
    #[inline]
    pub fn touch(&self) {
        self.last_activity.touch();
    }

    /// Get the time since last activity.
    #[must_use]
    #[inline]
    pub fn idle_duration(&self) -> Duration {
        self.last_activity.elapsed()
    }

    /// Get session age.
    #[must_use]
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Check if the session has timed out.
    #[must_use]
    pub fn is_timed_out(&self, timeout: Duration) -> bool {
        self.idle_duration() > timeout
    }

    /// Add to bytes sent counter atomically.
    /// Thread-safe: can be called from multiple threads concurrently.
    pub fn add_bytes_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Add to bytes received counter atomically.
    /// Thread-safe: can be called from multiple threads concurrently.
    pub fn add_bytes_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Get total bytes sent.
    #[must_use]
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// Get total bytes received.
    #[must_use]
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }

    /// Get current send counter value (for diagnostics/logging).
    #[must_use]
    pub fn send_counter(&self) -> u64 {
        self.send_counter.load(Ordering::Relaxed)
    }

    /// Check if rekey is needed based on volume or time.
    #[must_use]
    pub fn needs_rekey(&self, max_bytes: u64, max_duration: Duration) -> bool {
        let sent = self.bytes_sent.load(Ordering::Relaxed);
        let received = self.bytes_received.load(Ordering::Relaxed);
        let total_bytes = sent.saturating_add(received);
        total_bytes >= max_bytes || self.age() >= max_duration
    }

    /// Update keys for rekey operation.
    ///
    /// Pre-computes new AES-GCM keys for high-performance encryption/decryption.
    ///
    /// Returns `Err(CryptoError)` if key material is invalid.
    pub fn update_keys(&mut self, new_keys: SessionKeys) -> Result<(), crate::error::CryptoError> {
        // Pre-compute new keys
        self.send_key = PrecomputedKey::new(&new_keys.send_key)?;
        self.recv_key = PrecomputedKey::new(&new_keys.recv_key)?;
        self.keys = new_keys;
        self.key_id = self.key_id.next();
        self.send_counter.store(0, Ordering::SeqCst);
        self.recv_window.reset();
        self.bytes_sent.store(0, Ordering::Relaxed);
        self.bytes_received.store(0, Ordering::Relaxed);
        Ok(())
    }

    /// Close the session.
    pub fn close(&mut self) {
        self.state = SessionState::Closed;
    }

    /// Encrypt a packet.
    ///
    /// Thread-safe: can be called from multiple threads concurrently.
    /// Uses atomic counter for sequence numbers.
    ///
    /// # Arguments
    ///
    /// * `msg_type` - Message type
    /// * `payload` - Plaintext payload
    /// * `output` - Output buffer (must be large enough for header + payload + tag)
    ///
    /// # Returns
    ///
    /// Total packet size written to output.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails.
    #[inline]
    pub fn encrypt_packet(
        &self,
        msg_type: MessageType,
        payload: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let counter = self
            .next_send_counter()
            .map_err(|_| CryptoError::Encryption)?;

        let header = PacketHeader::new(msg_type, self.session_id, self.key_id, counter);

        let header_size = header.encoded_size();
        let total_size = header_size + payload.len() + aead::TAG_SIZE;

        if output.len() < total_size {
            return Err(CryptoError::BufferTooSmall {
                needed: total_size,
                available: output.len(),
            });
        }

        // Encode header
        header
            .encode(&mut output[..header_size])
            .map_err(|_| CryptoError::Encryption)?;

        // Copy header for AAD (to avoid borrow issues)
        let mut aad = [0u8; 32]; // Max header size is 32 bytes
        aad[..header_size].copy_from_slice(&output[..header_size]);

        // Build nonce from session-specific prefix and counter
        let nonce = aead::build_nonce(&self.keys.send_nonce_prefix, counter.0);

        // Copy payload and encrypt in place using pre-computed key
        output[header_size..header_size + payload.len()].copy_from_slice(payload);

        let ciphertext_len = self.send_key.encrypt_in_place(
            &nonce,
            &aad[..header_size], // AAD is the header
            &mut output[header_size..total_size],
            payload.len(),
        )?;

        self.add_bytes_sent((header_size + ciphertext_len) as u64);

        Ok(header_size + ciphertext_len)
    }

    /// Decrypt a packet.
    ///
    /// Thread-safe: can be called from multiple threads concurrently.
    /// Uses thread-safe anti-replay window and activity tracking.
    ///
    /// # Arguments
    ///
    /// * `packet` - Full packet including header
    /// * `output` - Output buffer for decrypted payload
    ///
    /// # Returns
    ///
    /// Tuple of (header, payload length).
    ///
    /// # Errors
    ///
    /// Returns an error if decryption fails or packet is a replay.
    #[inline]
    pub fn decrypt_packet(
        &self,
        packet: &[u8],
        output: &mut [u8],
    ) -> Result<(PacketHeader, usize), ProtocolError> {
        if packet.len() < HEADER_SIZE + aead::TAG_SIZE {
            return Err(ProtocolError::PacketTooShort {
                needed: HEADER_SIZE + aead::TAG_SIZE,
                available: packet.len(),
            });
        }

        // Decode header
        let header = PacketHeader::decode(packet)?;
        let header_size = header.encoded_size();

        // Verify session ID
        if header.session_id != self.session_id {
            return Err(ProtocolError::HandshakeFailed("session ID mismatch".into()));
        }

        // Verify key ID
        if header.key_id != self.key_id {
            return Err(ProtocolError::HandshakeFailed(format!(
                "key ID mismatch: expected {}, got {}",
                self.key_id.0, header.key_id.0
            )));
        }

        // Decrypt FIRST before touching anti-replay state
        // This prevents DoS attacks where corrupted packets consume counter space
        let ciphertext = &packet[header_size..];

        // Need output buffer >= ciphertext.len() for in-place decryption
        if output.len() < ciphertext.len() {
            return Err(ProtocolError::PacketTooShort {
                needed: ciphertext.len(),
                available: output.len(),
            });
        }

        // Copy ciphertext into output buffer once, then decrypt in-place.
        // This saves one memcpy compared to recv_key.decrypt() which also copies.
        let ct_len = ciphertext.len();
        output[..ct_len].copy_from_slice(ciphertext);

        let nonce = aead::build_nonce(&self.keys.recv_nonce_prefix, header.counter.0);

        let decrypted_len = self
            .recv_key
            .decrypt_in_place(
                &nonce,
                &packet[..header_size], // AAD - authenticates counter
                &mut output[..ct_len],
            )
            .map_err(|_| ProtocolError::HandshakeFailed("decryption failed".into()))?;

        // ANTI-REPLAY: only mark the counter as used AFTER a successful AEAD
        // decryption so an attacker spraying invalid ciphertexts cannot
        // exhaust the replay-window space and DoS the legitimate sender.
        //
        // Concurrency: `update_recv_counter` is mutex-protected inside
        // `AntiReplayWindow::check_and_update`, so two workers receiving the
        // same packet (a real network duplicate, or the same buffer fanned
        // out to two UDP receivers) are serialised by the bitmap lock. One
        // wins the update, the other gets `ReplayDetected`. The duplicate
        // is dropped instead of being injected twice into the TUN, which is
        // the correct fail-closed behaviour. There is NO "decrypt-vs-update"
        // race that lets the same counter pass through twice; the previous
        // comment claiming a "small race window is acceptable" was
        // imprecise and misled future readers — see the AntiReplayWindow
        // doc for the actual contract.
        if !self.update_recv_counter(header.counter) {
            return Err(ProtocolError::ReplayDetected(header.counter.0));
        }

        self.add_bytes_received(packet.len() as u64);
        self.touch();

        Ok((header, decrypted_len))
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("session_id", &self.session_id)
            .field("key_id", &self.key_id)
            .field("state", &self.state)
            .field("send_counter", &self.send_counter.load(Ordering::Relaxed))
            .field("bytes_sent", &self.bytes_sent.load(Ordering::Relaxed))
            .field(
                "bytes_received",
                &self.bytes_received.load(Ordering::Relaxed),
            )
            .field("age_secs", &self.age().as_secs())
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::expect_fun_call)]
#[allow(clippy::needless_collect)]
#[allow(clippy::cast_sign_loss)]
mod tests {
    use super::*;
    use crate::crypto::derive_session_keys;
    use crate::crypto::keys::{HandshakeSecret, SharedSecret};

    fn test_session_keys() -> SessionKeys {
        let x25519 = SharedSecret::from_bytes([0x11u8; 32]);
        let mlkem = SharedSecret::from_bytes([0x22u8; 32]);
        let hs = HandshakeSecret::combine(&x25519, &mlkem);
        derive_session_keys(&hs).unwrap()
    }

    #[test]
    fn test_anti_replay_window_basic() {
        let window = AntiReplayWindow::new();

        // First packet should be accepted
        assert!(window.check_and_update(Counter(1)));

        // Replay should be rejected
        assert!(!window.check_and_update(Counter(1)));

        // Next packet should be accepted
        assert!(window.check_and_update(Counter(2)));

        // Out of order within window should work
        assert!(window.check_and_update(Counter(100)));
        assert!(window.check_and_update(Counter(99)));
        assert!(window.check_and_update(Counter(50)));

        // Replays still rejected
        assert!(!window.check_and_update(Counter(99)));
        assert!(!window.check_and_update(Counter(50)));
    }

    #[test]
    fn test_anti_replay_window_too_old() {
        let window = AntiReplayWindow::new();

        // Accept counter 10000
        assert!(window.check_and_update(Counter(10000)));

        // Counter 1 is now too old (outside 8192-packet window: 10000 - 1 = 9999 >= 8192)
        assert!(!window.check_and_update(Counter(1)));

        // Counter 1808 is at window boundary (10000 - 1808 = 8192, which is >= REPLAY_WINDOW_SIZE, so rejected)
        assert!(!window.check_and_update(Counter(1808)));

        // Counter 1809 is within window (10000 - 1809 = 8191 < 8192)
        assert!(window.check_and_update(Counter(1809)));
    }

    #[test]
    fn test_session_encrypt_decrypt_roundtrip() {
        let keys = test_session_keys();
        let client_session = Session::new(SessionId::generate(), keys.clone()).unwrap();
        let server_session = Session::new(client_session.session_id(), keys.swap()).unwrap();

        let payload = b"Hello, HPN VPN!";
        let mut packet = vec![0u8; HEADER_SIZE + payload.len() + aead::TAG_SIZE + 100];

        // Client encrypts
        let packet_len = client_session
            .encrypt_packet(MessageType::Data, payload, &mut packet)
            .unwrap();

        // Server decrypts (buffer needs space for ciphertext during in-place decryption)
        let mut decrypted = vec![0u8; payload.len() + aead::TAG_SIZE];
        let (header, decrypted_len) = server_session
            .decrypt_packet(&packet[..packet_len], &mut decrypted)
            .unwrap();

        assert_eq!(header.msg_type, MessageType::Data);
        assert_eq!(decrypted_len, payload.len());
        assert_eq!(&decrypted[..decrypted_len], payload);
    }

    #[test]
    fn test_session_replay_rejected() {
        let keys = test_session_keys();
        let client_session = Session::new(SessionId::generate(), keys.clone()).unwrap();
        let server_session = Session::new(client_session.session_id(), keys.swap()).unwrap();

        let payload = b"Test message";
        let mut packet = vec![0u8; HEADER_SIZE + payload.len() + aead::TAG_SIZE + 100];

        // Client sends
        let packet_len = client_session
            .encrypt_packet(MessageType::Data, payload, &mut packet)
            .unwrap();

        // Server receives first time - OK (buffer needs space for in-place decryption)
        let mut decrypted = vec![0u8; payload.len() + aead::TAG_SIZE];
        assert!(
            server_session
                .decrypt_packet(&packet[..packet_len], &mut decrypted)
                .is_ok()
        );

        // Server receives same packet again - REPLAY
        let result = server_session.decrypt_packet(&packet[..packet_len], &mut decrypted);
        assert!(matches!(result, Err(ProtocolError::ReplayDetected(_))));
    }

    #[test]
    fn test_session_multiple_packets_varying_sizes() {
        // This test replicates the production scenario where counter=0 works
        // but counter>=1 fails decryption
        let keys = test_session_keys();
        let client_session = Session::new(SessionId::generate(), keys.clone()).unwrap();
        let server_session = Session::new(client_session.session_id(), keys.swap()).unwrap();

        // Test with varying payload sizes like in production:
        // - First packet (counter=0): 40 bytes (small, like key confirmation)
        // - Second packet (counter=1): 844 bytes (larger, like IP packet)
        // - Third packet (counter=2): 1500 bytes (MTU-sized)
        let payloads: &[&[u8]] = &[
            &[0x42u8; 40],   // Small packet (counter=0)
            &[0x55u8; 844],  // Medium packet (counter=1)
            &[0xAAu8; 1500], // Large packet (counter=2)
            &[0x11u8; 64],   // Another small one (counter=3)
        ];

        for (i, payload) in payloads.iter().enumerate() {
            let mut packet = vec![0u8; HEADER_SIZE + payload.len() + aead::TAG_SIZE + 32];

            // Client encrypts
            let packet_len = client_session
                .encrypt_packet(MessageType::Data, payload, &mut packet)
                .expect(&format!("Failed to encrypt packet {}", i));

            // Log for debugging
            println!(
                "Packet {}: payload_len={}, encrypted_len={}, counter={}",
                i,
                payload.len(),
                packet_len,
                i
            );

            // Server decrypts
            let mut decrypted = vec![0u8; payload.len() + aead::TAG_SIZE];
            let (header, decrypted_len) = server_session
                .decrypt_packet(&packet[..packet_len], &mut decrypted)
                .expect(&format!("Failed to decrypt packet {} (counter={})", i, i));

            assert_eq!(header.msg_type, MessageType::Data);
            assert_eq!(
                decrypted_len,
                payload.len(),
                "Packet {} decrypted length mismatch",
                i
            );
            assert_eq!(
                &decrypted[..decrypted_len],
                *payload,
                "Packet {} content mismatch",
                i
            );
        }
    }

    #[test]
    fn test_session_counters() {
        let keys = test_session_keys();
        let session = Session::new(SessionId::generate(), keys).unwrap();

        // Atomic counter - no mut needed
        assert_eq!(session.next_send_counter().unwrap().0, 0);
        assert_eq!(session.next_send_counter().unwrap().0, 1);
        assert_eq!(session.next_send_counter().unwrap().0, 2);
    }

    #[test]
    fn test_session_bytes_tracking() {
        let keys = test_session_keys();
        let session = Session::new(SessionId::generate(), keys).unwrap();

        // Atomic operations - no mut needed
        session.add_bytes_sent(100);
        session.add_bytes_received(200);

        assert_eq!(session.bytes_sent(), 100);
        assert_eq!(session.bytes_received(), 200);
    }

    #[test]
    fn test_needs_rekey() {
        let keys = test_session_keys();
        let session = Session::new(SessionId::generate(), keys).unwrap();

        // Should not need rekey initially
        assert!(!session.needs_rekey(1024 * 1024, Duration::from_secs(300)));

        // Should need rekey after exceeding byte limit
        session.add_bytes_sent(1024 * 1024);
        assert!(session.needs_rekey(1024 * 1024, Duration::from_secs(300)));
    }

    #[test]
    fn test_parallel_encryption() {
        use std::sync::Arc;
        use std::thread;

        let keys = test_session_keys();
        let session = Arc::new(Session::new(SessionId::generate(), keys).unwrap());

        // Spawn multiple threads encrypting in parallel
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let session = Arc::clone(&session);
                thread::spawn(move || {
                    let payload = b"test data";
                    let mut output = vec![0u8; 128];
                    for _ in 0..100 {
                        let _ = session.encrypt_packet(MessageType::Data, payload, &mut output);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        // 4 threads * 100 packets = 400 unique counters
        // Counter should now be 400
        assert_eq!(session.next_send_counter().unwrap().0, 400);
    }

    #[test]
    fn test_counter_exhaustion() {
        use std::sync::atomic::Ordering;

        let keys = test_session_keys();
        let session = Session::new(SessionId::generate(), keys).unwrap();

        // Simulate counter near exhaustion by setting it close to MAX_SAFE
        session
            .send_counter
            .store(Counter::MAX_SAFE - 1, Ordering::SeqCst);

        // This should still work (one below limit)
        assert!(session.next_send_counter().is_ok());

        // This should fail (at limit)
        let result = session.next_send_counter();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SessionError::CounterExhausted
        ));
    }

    #[test]
    fn test_counter_concurrent_exhaustion() {
        use std::sync::Arc;
        use std::sync::atomic::Ordering;
        use std::thread;

        // SECURITY TEST: Verify CAS prevents counter from exceeding MAX_SAFE in concurrent scenario
        let keys = test_session_keys();
        let session = Arc::new(Session::new(SessionId::generate(), keys).unwrap());

        // Set counter very close to limit
        session
            .send_counter
            .store(Counter::MAX_SAFE - 10, Ordering::SeqCst);

        // Spawn multiple threads trying to allocate counters concurrently
        let results: Vec<_> = (0..20)
            .map(|_| {
                let session = Arc::clone(&session);
                thread::spawn(move || session.next_send_counter())
            })
            .map(|h| h.join().unwrap())
            .collect();

        // Some should succeed (up to MAX_SAFE)
        let success_count = results.iter().filter(|r| r.is_ok()).count();

        // Some should fail (beyond MAX_SAFE)
        let failure_count = results.iter().filter(|r| r.is_err()).count();

        // We had 10 counters available (MAX_SAFE-10 to MAX_SAFE-1)
        // Exactly 10 threads should succeed, 10 should fail
        assert_eq!(
            success_count, 10,
            "Expected 10 successful counter allocations"
        );
        assert_eq!(failure_count, 10, "Expected 10 failed counter allocations");

        // Verify counter never exceeded MAX_SAFE
        let final_counter = session.send_counter.load(Ordering::SeqCst);
        assert!(
            final_counter <= Counter::MAX_SAFE,
            "Counter exceeded MAX_SAFE: {}",
            final_counter
        );
    }

    #[test]
    fn test_counter_overflow_protection() {
        use std::sync::Arc;
        use std::thread;

        // SECURITY TEST P0-2: Counter overflow protection under extreme load
        // This test validates multiple overflow scenarios:
        // 1. Sequential exhaustion
        // 2. Concurrent exhaustion with high contention
        // 3. Graceful failure with proper error signaling

        let keys = test_session_keys();
        let session = Arc::new(Session::new(SessionId::generate(), keys).unwrap());

        // Test 1: Sequential exhaustion near limit
        session
            .send_counter
            .store(Counter::MAX_SAFE - 5, Ordering::SeqCst);

        for _ in 0..5 {
            let result = session.next_send_counter();
            assert!(result.is_ok(), "Counter should succeed before MAX_SAFE");
        }

        // Next one should fail
        let result = session.next_send_counter();
        assert!(result.is_err(), "Counter should fail after exhaustion");
        match result.unwrap_err() {
            SessionError::CounterExhausted => {} // Expected
            other => panic!("Expected CounterExhausted, got {:?}", other),
        }

        // Test 2: High-contention concurrent exhaustion (100 threads)
        let session2 = Arc::new(Session::new(SessionId::generate(), test_session_keys()).unwrap());
        session2
            .send_counter
            .store(Counter::MAX_SAFE - 50, Ordering::SeqCst);

        let handles: Vec<_> = (0..100)
            .map(|_| {
                let sess = Arc::clone(&session2);
                thread::spawn(move || sess.next_send_counter())
            })
            .collect();

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // Exactly 50 should succeed, 50 should fail
        let success = results.iter().filter(|r| r.is_ok()).count();
        let failures = results.iter().filter(|r| r.is_err()).count();

        assert_eq!(success, 50, "Expected 50 successful allocations");
        assert_eq!(failures, 50, "Expected 50 failed allocations");

        // Test 3: Verify needs_rekey triggers appropriately with bytes
        let session3 = Arc::new(Session::new(SessionId::generate(), test_session_keys()).unwrap());
        // Simulate sending 65GB of data (exceeds 64GB rekey threshold)
        let bytes_65gb = 65 * 1024 * 1024 * 1024u64;
        session3.bytes_sent.store(bytes_65gb, Ordering::Relaxed);

        assert!(
            session3.needs_rekey(64 * 1024 * 1024 * 1024, Duration::from_secs(3600)),
            "Should need rekey after 64GB threshold"
        );

        // Test 4: Verify counter never wraps around
        let session4 = Arc::new(Session::new(SessionId::generate(), test_session_keys()).unwrap());
        session4
            .send_counter
            .store(u64::MAX - 1000, Ordering::SeqCst);

        // Try to allocate counters - all should fail (way beyond MAX_SAFE)
        let result = session4.next_send_counter();
        assert!(
            result.is_err(),
            "Counter at u64::MAX should be rejected (beyond MAX_SAFE)"
        );

        // Test 5: Verify REKEY_WARNING detection
        let session5 = Arc::new(Session::new(SessionId::generate(), test_session_keys()).unwrap());
        session5
            .send_counter
            .store(Counter::REKEY_WARNING + 100, Ordering::SeqCst);

        let counter = session5.next_send_counter().unwrap();
        assert!(
            counter.should_rekey(),
            "Counter beyond REKEY_WARNING should trigger rekey"
        );
    }

    // Property-based tests using proptest
    #[cfg(test)]
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn prop_counter_always_increases(increments in prop::collection::vec(1u64..=100, 1..1000)) {
                // PROPERTY TEST: Counter monotonicity
                // Property: For any sequence of increments, counter values are strictly increasing
                let keys = test_session_keys();
                let session = Session::new(SessionId::generate(), keys).unwrap();

                let mut prev: Option<u64> = None;
                for _ in increments {
                    match session.next_send_counter() {
                        Ok(counter) => {
                            let current = counter.0; // Counter is a tuple struct
                            if let Some(prev_val) = prev {
                                prop_assert!(current > prev_val, "Counter should strictly increase");
                            }
                            prev = Some(current);
                        }
                        Err(_) => {
                            // Counter exhausted - acceptable terminal state
                            break;
                        }
                    }
                }
            }

            #[test]
            fn prop_session_id_uniqueness(count in 1usize..100) {
                // PROPERTY TEST: Session ID uniqueness
                // Property: Generated session IDs should be unique (probabilistically)
                use std::collections::HashSet;

                let mut ids = HashSet::new();
                for _ in 0..count {
                    let id = SessionId::generate();
                    prop_assert!(ids.insert(id), "Session IDs should be unique");
                }
            }

            #[test]
            fn prop_bytes_sent_accumulates_correctly(sends in prop::collection::vec(1u64..=10000, 1..100)) {
                // PROPERTY TEST: Byte counter accumulation
                // Property: Total bytes sent equals sum of all individual sends
                let keys = test_session_keys();
                let session = Session::new(SessionId::generate(), keys).unwrap();

                let expected_total: u64 = sends.iter().sum();
                for &bytes in &sends {
                    session.add_bytes_sent(bytes);
                }

                let actual_total = session.bytes_sent();
                prop_assert_eq!(actual_total, expected_total, "Bytes sent should equal sum of all sends");
            }

            #[test]
            fn prop_nonce_construction_deterministic(
                counter in 0u64..1_000_000,
                prefix in prop::array::uniform4(any::<u8>())
            ) {
                // PROPERTY TEST: Nonce construction determinism
                // Property: Same counter + prefix always produces same nonce
                use crate::crypto::aead::build_nonce;

                let nonce1 = build_nonce(&prefix, counter);
                let nonce2 = build_nonce(&prefix, counter);

                prop_assert_eq!(nonce1, nonce2, "Nonce construction should be deterministic");

                // Verify structure: first 4 bytes = prefix, last 8 bytes = counter (big-endian)
                prop_assert_eq!(&nonce1[..4], &prefix, "First 4 bytes should be prefix");

                let counter_bytes = counter.to_be_bytes();
                prop_assert_eq!(&nonce1[4..], &counter_bytes, "Last 8 bytes should be counter");
            }

            #[test]
            fn prop_counter_never_wraps(
                start in 0u64..(Counter::MAX_SAFE - 1000),
                increments in 1usize..100
            ) {
                // PROPERTY TEST: Counter wrap protection
                // Property: Counter never wraps around u64::MAX, always fails before overflow
                let keys = test_session_keys();
                let session = Session::new(SessionId::generate(), keys).unwrap();
                session.send_counter.store(start, Ordering::SeqCst);

                for _ in 0..increments {
                    match session.next_send_counter() {
                        Ok(counter) => {
                            let current = counter.0; // Counter is a tuple struct
                            // Counter should be greater than where we started
                            prop_assert!(current >= start, "Counter should not go backwards");
                            prop_assert!(current <= Counter::MAX_SAFE, "Counter should not exceed MAX_SAFE");
                        }
                        Err(SessionError::CounterExhausted) => {
                            // Expected behavior when approaching limit
                            let final_val = session.send_counter.load(Ordering::SeqCst);
                            prop_assert!(final_val >= Counter::MAX_SAFE, "Should fail at or after MAX_SAFE");
                            break;
                        }
                        Err(e) => {
                            return Err(proptest::test_runner::TestCaseError::fail(
                                format!("Unexpected error: {:?}", e)
                            ));
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_anti_replay_packet_loss_simulation() {
        // E2E NETWORKING TEST: UDP packet loss with anti-replay
        // This test simulates:
        // - Random packet loss (30% drop rate)
        // - Out-of-order delivery (packets arriving in random order)
        // - Duplicate packets (replay attacks)
        // - Large gaps in counter sequence (burst losses)
        // Validates that anti-replay window correctly handles real-world UDP conditions

        let window = AntiReplayWindow::new();
        let mut delivered_packets = vec![];

        // Simulate sending 1000 packets with 30% random loss
        let total_packets = 1000u64;
        let loss_rate = 0.3;

        // Deterministic "random" for reproducible tests
        let mut pseudo_random = 12345u64;
        let next_random = |state: &mut u64| {
            *state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *state
        };

        for counter in 1..=total_packets {
            // Simulate packet loss
            let rand_val = next_random(&mut pseudo_random);
            let is_lost = (rand_val % 100) < (loss_rate * 100.0) as u64;

            if !is_lost {
                delivered_packets.push(counter);
            }
        }

        // Shuffle delivered packets to simulate out-of-order delivery
        // Fisher-Yates shuffle with deterministic random
        for i in (1..delivered_packets.len()).rev() {
            let j = (next_random(&mut pseudo_random) as usize) % (i + 1);
            delivered_packets.swap(i, j);
        }

        // Process delivered packets through anti-replay window
        let mut accepted = 0;
        let mut rejected = 0;

        for &counter in &delivered_packets {
            if window.check_and_update(Counter(counter)) {
                accepted += 1;
            } else {
                rejected += 1;
            }
        }

        // All delivered packets should be accepted (no duplicates yet)
        assert_eq!(accepted, delivered_packets.len());
        assert_eq!(
            rejected, 0,
            "No packets should be rejected on first delivery"
        );

        // Simulate replay attacks - resend all delivered packets
        let mut replay_rejected = 0;
        for &counter in &delivered_packets {
            if !window.check_and_update(Counter(counter)) {
                replay_rejected += 1;
            }
        }

        // All replayed packets should be rejected
        assert_eq!(
            replay_rejected,
            delivered_packets.len(),
            "All replay packets should be rejected"
        );

        // Simulate late arrival of lost packets (outside window)
        // Find a packet that was lost early on
        let late_packet = (1..100).find(|&c| !delivered_packets.contains(&c)).unwrap();

        // If last packet is > 2048 ahead, late packet is outside window
        let last_counter = *delivered_packets.iter().max().unwrap();
        if last_counter - late_packet >= REPLAY_WINDOW_SIZE {
            assert!(
                !window.check_and_update(Counter(late_packet)),
                "Late packet outside window should be rejected"
            );
        }
    }

    #[test]
    fn test_anti_replay_burst_loss() {
        // E2E NETWORKING TEST: Burst packet loss scenarios
        // This test simulates:
        // - Large burst losses (100+ consecutive packets lost)
        // - Recovery after burst
        // - Window state after large gaps

        let window = AntiReplayWindow::new();

        // Accept packets 1-100
        for i in 1..=100 {
            assert!(
                window.check_and_update(Counter(i)),
                "Packet {} should be accepted",
                i
            );
        }

        // Simulate burst loss: packets 101-500 are lost
        // Jump directly to packet 501
        assert!(
            window.check_and_update(Counter(501)),
            "Packet 501 should be accepted"
        );

        // Try to deliver some packets from the lost burst
        // Packets 101-300 are outside window (501 - 101 = 400 >= 2048 is false, but let's check boundary)
        // Window is 2048, so 501 - 2048 = -1547, meaning we can accept down to counter 1
        // Actually, window from 501 goes back to 501 - 2047 = -1546, but counters are unsigned
        // So we can accept counters in range [max(1, 501-2047), 501] = [1, 501]

        // Packet 100 is within window
        assert!(
            !window.check_and_update(Counter(100)),
            "Packet 100 already seen, should be rejected"
        );

        // Packet 250 (from burst) is within window and should be accepted (first time)
        assert!(
            window.check_and_update(Counter(250)),
            "Packet 250 within window should be accepted"
        );

        // Continue with more packets
        for i in 502..=600 {
            assert!(
                window.check_and_update(Counter(i)),
                "Packet {} should be accepted",
                i
            );
        }

        // Now packet 100 is outside window (600 - 100 = 500 < 2048, so still inside!)
        // Let's push further
        assert!(window.check_and_update(Counter(3000)));

        // Now packet 100 is definitely outside (3000 - 100 = 2900 >= 2048)
        assert!(
            !window.check_and_update(Counter(100)),
            "Packet 100 outside window should be rejected"
        );
    }

    #[test]
    fn test_anti_replay_concurrent_processing() {
        // E2E NETWORKING TEST: Concurrent packet processing
        // This test simulates:
        // - Multiple threads processing packets simultaneously
        // - Race conditions in anti-replay checking
        // - Thread-safe window updates

        use std::sync::Arc;
        use std::thread;

        let window = Arc::new(AntiReplayWindow::new());
        let num_threads = 10;
        let packets_per_thread = 100;

        // Each thread processes a different range of counters
        let handles: Vec<_> = (0..num_threads)
            .map(|thread_id| {
                let window_clone = Arc::clone(&window);
                thread::spawn(move || {
                    let base = thread_id * packets_per_thread;
                    let mut accepted = 0;
                    for i in 0..packets_per_thread {
                        let counter = base + i + 1; // Start from 1
                        if window_clone.check_and_update(Counter(counter as u64)) {
                            accepted += 1;
                        }
                    }
                    accepted
                })
            })
            .collect();

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // All packets should be accepted (unique counters per thread)
        let total_accepted: usize = results.iter().sum();
        assert_eq!(
            total_accepted,
            (num_threads * packets_per_thread) as usize,
            "All unique packets should be accepted"
        );

        // Try to replay all packets from multiple threads
        let replay_handles: Vec<_> = (0..num_threads)
            .map(|thread_id| {
                let window_clone = Arc::clone(&window);
                thread::spawn(move || {
                    let base = thread_id * packets_per_thread;
                    let mut rejected = 0;
                    for i in 0..packets_per_thread {
                        let counter = base + i + 1;
                        if !window_clone.check_and_update(Counter(counter as u64)) {
                            rejected += 1;
                        }
                    }
                    rejected
                })
            })
            .collect();

        let replay_results: Vec<_> = replay_handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect();

        // All replay packets should be rejected
        let total_rejected: usize = replay_results.iter().sum();
        assert_eq!(
            total_rejected,
            (num_threads * packets_per_thread) as usize,
            "All replay packets should be rejected"
        );
    }

    #[test]
    fn test_anti_replay_window_boundary() {
        // EDGE CASE TEST: Anti-replay window boundary conditions
        // This test validates:
        // - Exact window boundary (2048 packets)
        // - Off-by-one errors in window calculations
        // - Bitmap word boundaries (128-bit words)

        let window = AntiReplayWindow::new();

        // Set highest counter
        let highest = 10000u64;
        assert!(window.check_and_update(Counter(highest)));

        // Test exact boundary: highest - 2047 (inside window)
        let inside_boundary = highest - 2047;
        assert!(
            window.check_and_update(Counter(inside_boundary)),
            "Counter at inside boundary should be accepted (diff = 2047 < 2048)"
        );

        // Test outside boundary: highest - 2048 (at window size, should be rejected)
        let at_boundary = highest - REPLAY_WINDOW_SIZE;
        assert!(
            !window.check_and_update(Counter(at_boundary)),
            "Counter at boundary (diff >= REPLAY_WINDOW_SIZE) should be rejected"
        );

        // Test word boundaries (128-bit word boundaries)
        // Word 0: bits 0-127
        // Word 1: bits 128-255
        // etc.

        // Test at word boundary (counter 128 behind highest)
        assert!(window.check_and_update(Counter(highest - 128)));

        // Test across word boundary
        assert!(window.check_and_update(Counter(highest - 127)));
        assert!(window.check_and_update(Counter(highest - 129)));

        // Test at last word boundary (word 15: bits 1920-2047)
        // Counter at highest - 2046 (not yet tested)
        assert!(window.check_and_update(Counter(highest - 2046)));
        assert!(!window.check_and_update(Counter(highest - 2046))); // Replay
    }

    #[test]
    fn test_anti_replay_window_check_without_update() {
        let window = AntiReplayWindow::new();

        // Counter 100 should be valid
        assert!(window.check(Counter(100)));

        // Actually update with counter 100
        assert!(window.check_and_update(Counter(100)));

        // Check again - should show as invalid (already seen)
        assert!(!window.check(Counter(100)));

        // Counter 101 should be valid
        assert!(window.check(Counter(101)));
    }

    #[test]
    fn test_anti_replay_window_reset() {
        let window = AntiReplayWindow::new();

        // Accept some counters
        for i in 1..=100 {
            assert!(window.check_and_update(Counter(i)));
        }

        // Reset the window
        window.reset();

        // Should be able to accept the same counters again
        for i in 1..=100 {
            assert!(
                window.check_and_update(Counter(i)),
                "Counter {} should be accepted after reset",
                i
            );
        }
    }

    #[test]
    fn test_session_state_transitions() {
        use super::SessionState;

        assert_eq!(SessionState::Handshaking, SessionState::Handshaking);
        assert_ne!(SessionState::Handshaking, SessionState::Active);
        assert_ne!(SessionState::Active, SessionState::Rekeying);
        assert_ne!(SessionState::Rekeying, SessionState::Closed);
    }

    #[test]
    fn test_session_counter_increment() {
        use crate::crypto::kdf::derive_session_keys;
        use crate::crypto::keys::{HandshakeSecret, SharedSecret};

        // Create session with test keys
        let x25519 = SharedSecret::from_bytes([0x11u8; 32]);
        let mlkem = SharedSecret::from_bytes([0x22u8; 32]);
        let handshake_secret = HandshakeSecret::combine(&x25519, &mlkem);
        let keys = derive_session_keys(&handshake_secret).unwrap();

        let session = Session::new(SessionId(1), keys).unwrap();

        // Get counters - should increment from initial value
        let c1 = session.next_send_counter().unwrap();
        let c2 = session.next_send_counter().unwrap();
        let c3 = session.next_send_counter().unwrap();

        assert_eq!(c1.0, 0);
        assert_eq!(c2.0, 1);
        assert_eq!(c3.0, 2);
    }

    #[test]
    fn test_session_idle_and_age() {
        use crate::crypto::kdf::derive_session_keys;
        use crate::crypto::keys::{HandshakeSecret, SharedSecret};
        use std::thread;

        let x25519 = SharedSecret::from_bytes([0x11u8; 32]);
        let mlkem = SharedSecret::from_bytes([0x22u8; 32]);
        let handshake_secret = HandshakeSecret::combine(&x25519, &mlkem);
        let keys = derive_session_keys(&handshake_secret).unwrap();

        let session = Session::new(SessionId(1), keys).unwrap();

        // Age should be nearly zero initially
        assert!(session.age() < Duration::from_millis(100));

        // Idle duration should also be nearly zero
        assert!(session.idle_duration() < Duration::from_millis(100));

        // Sleep a bit
        thread::sleep(Duration::from_millis(50));

        // Age should have increased
        assert!(session.age() >= Duration::from_millis(50));

        // Idle duration should have increased
        assert!(session.idle_duration() >= Duration::from_millis(50));

        // Touch the session
        session.touch();

        // Idle duration should reset
        assert!(session.idle_duration() < Duration::from_millis(10));

        // But age should still be >= 50ms
        assert!(session.age() >= Duration::from_millis(50));
    }

    #[test]
    fn test_session_timeout() {
        use crate::crypto::kdf::derive_session_keys;
        use crate::crypto::keys::{HandshakeSecret, SharedSecret};
        use std::thread;

        let x25519 = SharedSecret::from_bytes([0x11u8; 32]);
        let mlkem = SharedSecret::from_bytes([0x22u8; 32]);
        let handshake_secret = HandshakeSecret::combine(&x25519, &mlkem);
        let keys = derive_session_keys(&handshake_secret).unwrap();

        let session = Session::new(SessionId(1), keys).unwrap();

        // Should not be timed out with a 10-second timeout (generous for slow CI)
        assert!(!session.is_timed_out(Duration::from_secs(10)));

        // Sleep 100ms
        thread::sleep(Duration::from_millis(100));

        // Should be timed out with a 50ms timeout (we slept 100ms)
        assert!(session.is_timed_out(Duration::from_millis(50)));

        // Should not be timed out with a 5-second timeout
        // Use a large margin to avoid flakiness on slow CI runners
        assert!(!session.is_timed_out(Duration::from_secs(5)));
    }

    #[test]
    fn test_session_traffic_counters() {
        use crate::crypto::kdf::derive_session_keys;
        use crate::crypto::keys::{HandshakeSecret, SharedSecret};

        let x25519 = SharedSecret::from_bytes([0x11u8; 32]);
        let mlkem = SharedSecret::from_bytes([0x22u8; 32]);
        let handshake_secret = HandshakeSecret::combine(&x25519, &mlkem);
        let keys = derive_session_keys(&handshake_secret).unwrap();

        let session = Session::new(SessionId(1), keys).unwrap();

        // Initial counters should be zero
        assert_eq!(session.bytes_sent(), 0);
        assert_eq!(session.bytes_received(), 0);

        // Add sent bytes
        session.add_bytes_sent(1500);
        assert_eq!(session.bytes_sent(), 1500);
        assert_eq!(session.bytes_received(), 0);

        // Add received bytes
        session.add_bytes_received(3000);
        assert_eq!(session.bytes_sent(), 1500);
        assert_eq!(session.bytes_received(), 3000);

        // Add more
        session.add_bytes_sent(500);
        session.add_bytes_received(1000);

        assert_eq!(session.bytes_sent(), 2000);
        assert_eq!(session.bytes_received(), 4000);
    }

    #[test]
    fn test_session_needs_rekey() {
        use crate::crypto::kdf::derive_session_keys;
        use crate::crypto::keys::{HandshakeSecret, SharedSecret};
        use std::thread;

        let x25519 = SharedSecret::from_bytes([0x11u8; 32]);
        let mlkem = SharedSecret::from_bytes([0x22u8; 32]);
        let handshake_secret = HandshakeSecret::combine(&x25519, &mlkem);
        let keys = derive_session_keys(&handshake_secret).unwrap();

        let session = Session::new(SessionId(1), keys).unwrap();

        // Should not need rekey initially
        assert!(!session.needs_rekey(1_000_000, Duration::from_secs(60)));

        // Add bytes to trigger byte-based rekey
        session.add_bytes_sent(1_500_000);
        assert!(session.needs_rekey(1_000_000, Duration::from_secs(60)));

        // Create new session for time-based rekey test
        let session2 = Session::new(
            SessionId(2),
            derive_session_keys(&handshake_secret).unwrap(),
        )
        .unwrap();

        thread::sleep(Duration::from_millis(100));

        // Should need rekey if max_duration is 50ms
        assert!(session2.needs_rekey(1_000_000_000, Duration::from_millis(50)));
    }

    #[test]
    fn test_session_update_keys() {
        use crate::crypto::kdf::derive_session_keys;
        use crate::crypto::keys::{HandshakeSecret, SharedSecret};

        let x25519_old = SharedSecret::from_bytes([0x11u8; 32]);
        let mlkem_old = SharedSecret::from_bytes([0x22u8; 32]);
        let handshake_secret_old = HandshakeSecret::combine(&x25519_old, &mlkem_old);
        let keys_old = derive_session_keys(&handshake_secret_old).unwrap();

        let mut session = Session::new(SessionId(1), keys_old).unwrap();

        // Update to new keys
        let x25519_new = SharedSecret::from_bytes([0x33u8; 32]);
        let mlkem_new = SharedSecret::from_bytes([0x44u8; 32]);
        let handshake_secret_new = HandshakeSecret::combine(&x25519_new, &mlkem_new);
        let keys_new = derive_session_keys(&handshake_secret_new).unwrap();

        session.update_keys(keys_new).unwrap();

        // Session should still be functional
        assert!(session.next_send_counter().is_ok());
    }

    #[test]
    fn test_session_close() {
        use crate::crypto::kdf::derive_session_keys;
        use crate::crypto::keys::{HandshakeSecret, SharedSecret};

        let x25519 = SharedSecret::from_bytes([0x11u8; 32]);
        let mlkem = SharedSecret::from_bytes([0x22u8; 32]);
        let handshake_secret = HandshakeSecret::combine(&x25519, &mlkem);
        let keys = derive_session_keys(&handshake_secret).unwrap();

        let mut session = Session::new(SessionId(1), keys).unwrap();

        // Close the session
        session.close();

        // Session should still be functional for queries
        assert_eq!(session.bytes_sent(), 0);
        assert_eq!(session.bytes_received(), 0);
    }

    #[test]
    fn test_session_is_valid_counter() {
        use crate::crypto::kdf::derive_session_keys;
        use crate::crypto::keys::{HandshakeSecret, SharedSecret};

        let x25519 = SharedSecret::from_bytes([0x11u8; 32]);
        let mlkem = SharedSecret::from_bytes([0x22u8; 32]);
        let handshake_secret = HandshakeSecret::combine(&x25519, &mlkem);
        let keys = derive_session_keys(&handshake_secret).unwrap();

        let session = Session::new(SessionId(1), keys).unwrap();

        // Counter 1 should be valid
        assert!(session.is_valid_counter(Counter(1)));

        // Update with counter 100
        assert!(session.update_recv_counter(Counter(100)));

        // Counter 100 should now be invalid (replay)
        assert!(!session.is_valid_counter(Counter(100)));

        // Counter 50 should be valid (within window, not seen)
        assert!(session.is_valid_counter(Counter(50)));
    }

    #[test]
    fn test_session_update_recv_counter() {
        use crate::crypto::kdf::derive_session_keys;
        use crate::crypto::keys::{HandshakeSecret, SharedSecret};

        let x25519 = SharedSecret::from_bytes([0x11u8; 32]);
        let mlkem = SharedSecret::from_bytes([0x22u8; 32]);
        let handshake_secret = HandshakeSecret::combine(&x25519, &mlkem);
        let keys = derive_session_keys(&handshake_secret).unwrap();

        let session = Session::new(SessionId(1), keys).unwrap();

        // Accept counter 100
        assert!(session.update_recv_counter(Counter(100)));

        // Try to replay counter 100
        assert!(!session.update_recv_counter(Counter(100)));

        // Accept counter 101
        assert!(session.update_recv_counter(Counter(101)));

        // Accept counter 99 (within window, not seen)
        assert!(session.update_recv_counter(Counter(99)));
    }
}
