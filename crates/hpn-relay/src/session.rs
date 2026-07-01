//! Relay session management.
//!
//! Maintains state for forwarding packets between clients and upstream.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Global start instant for efficient timestamps (avoids SystemTime syscalls).
static START_INSTANT: OnceLock<Instant> = OnceLock::new();

use hpn_core::types::SessionId;
use parking_lot::RwLock;

/// A relay session tracking client-to-upstream mapping.
#[derive(Debug)]
pub struct RelaySession {
    /// Session ID (from HPN header).
    pub session_id: SessionId,
    /// Client's address.
    pub client_addr: SocketAddr,
    /// Last activity timestamp (atomic: milliseconds since epoch for lock-free updates).
    last_activity_ms: AtomicU64,
    /// Creation time for calculating session age.
    created_at: Instant,
    /// Bytes forwarded client -> upstream.
    pub bytes_sent: AtomicU64,
    /// Bytes forwarded upstream -> client.
    pub bytes_received: AtomicU64,
    /// Packets forwarded client -> upstream.
    pub packets_sent: AtomicU64,
    /// Packets forwarded upstream -> client.
    pub packets_received: AtomicU64,
    /// Rate limiter for client -> upstream direction.
    client_rate_limiter: RateLimiter,
    /// Rate limiter for upstream -> client direction.
    upstream_rate_limiter: RateLimiter,
}

/// Token bucket rate limiter.
#[derive(Debug)]
pub struct RateLimiter {
    /// Maximum packets per second (0 = unlimited).
    max_pps: u32,
    /// Maximum bytes per second (0 = unlimited).
    max_bps: u64,
    /// Token bucket for packets.
    packet_tokens: AtomicU64,
    /// Token bucket for bytes.
    byte_tokens: AtomicU64,
    /// Last refill timestamp (microseconds since start instant).
    last_refill: AtomicU64,
}

impl RateLimiter {
    /// Create a new rate limiter.
    pub fn new(max_pps: u32, max_bps: u64) -> Self {
        Self {
            max_pps,
            max_bps,
            packet_tokens: AtomicU64::new(max_pps as u64),
            byte_tokens: AtomicU64::new(max_bps),
            last_refill: AtomicU64::new(now_us()),
        }
    }

    /// Create an unlimited rate limiter.
    pub fn unlimited() -> Self {
        Self::new(0, 0)
    }

    /// Maximum CAS spin iterations before yielding to scheduler.
    const SPIN_LIMIT: u32 = 4;
    /// Maximum total retries before falling back (prevents infinite loop).
    const MAX_RETRIES: u32 = 32;

    /// Check if a packet of the given size is allowed.
    /// Returns true if allowed, false if rate limited.
    /// Uses CAS loops with exponential backoff to prevent TOCTOU race conditions
    /// while avoiding excessive CPU usage under high contention.
    pub fn check(&self, bytes: usize) -> bool {
        // Unlimited
        if self.max_pps == 0 && self.max_bps == 0 {
            return true;
        }

        // Refill tokens based on elapsed time
        self.refill();

        // Check and atomically decrement packet rate (CAS loop with backoff)
        if self.max_pps > 0 {
            let mut retries = 0u32;
            loop {
                let tokens = self.packet_tokens.load(Ordering::Relaxed);
                if tokens == 0 {
                    return false;
                }
                // Atomically try to decrement - retry if another thread raced us
                if self
                    .packet_tokens
                    .compare_exchange_weak(tokens, tokens - 1, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    break;
                }
                // Exponential backoff to reduce contention
                retries += 1;
                if retries >= Self::MAX_RETRIES {
                    // Extreme contention - fail safe by rejecting to avoid CPU starvation
                    return false;
                }
                Self::backoff(retries);
            }
        }

        // Check and atomically decrement byte rate (CAS loop with backoff)
        if self.max_bps > 0 {
            let mut retries = 0u32;
            loop {
                let tokens = self.byte_tokens.load(Ordering::Relaxed);
                if tokens < bytes as u64 {
                    // Rollback packet token if we already consumed it
                    if self.max_pps > 0 {
                        self.packet_tokens.fetch_add(1, Ordering::Relaxed);
                    }
                    return false;
                }
                // Atomically try to decrement - retry if another thread raced us
                if self
                    .byte_tokens
                    .compare_exchange_weak(
                        tokens,
                        tokens - bytes as u64,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    )
                    .is_ok()
                {
                    break;
                }
                // Exponential backoff to reduce contention
                retries += 1;
                if retries >= Self::MAX_RETRIES {
                    // Extreme contention - rollback and fail safe
                    if self.max_pps > 0 {
                        self.packet_tokens.fetch_add(1, Ordering::Relaxed);
                    }
                    return false;
                }
                Self::backoff(retries);
            }
        }

        true
    }

    /// Exponential backoff strategy for CAS contention.
    /// - First few retries: CPU spin hint (very fast)
    /// - Beyond that: yield to OS scheduler (avoids blocking async runtime)
    #[inline]
    fn backoff(retries: u32) {
        if retries <= Self::SPIN_LIMIT {
            // Light spinning - just hint to CPU
            for _ in 0..(1 << retries) {
                std::hint::spin_loop();
            }
        } else {
            // Higher contention - yield to scheduler
            // NOTE: We use yield instead of sleep to avoid blocking tokio executor threads
            std::thread::yield_now();
        }
    }

    /// Refill tokens based on elapsed time.
    fn refill(&self) {
        let now = now_us();
        let last = self.last_refill.load(Ordering::Relaxed);
        let elapsed_us = now.saturating_sub(last);

        // Only refill if at least 1ms has passed
        if elapsed_us < 1000 {
            return;
        }

        // Try to update last_refill (CAS to handle races)
        if self
            .last_refill
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return; // Another thread already refilled
        }

        // Calculate tokens to add
        let elapsed_secs = elapsed_us as f64 / 1_000_000.0;

        // Use fetch_update for atomic read-modify-write (prevents TOCTOU race)
        if self.max_pps > 0 {
            let add_packets = (self.max_pps as f64 * elapsed_secs) as u64;
            let max_burst = self.max_pps as u64 * 2; // 2 second burst
            // Atomically: load current, add tokens, cap at burst, store back
            let _ =
                self.packet_tokens
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                        Some((current.saturating_add(add_packets)).min(max_burst))
                    });
        }

        if self.max_bps > 0 {
            let add_bytes = (self.max_bps as f64 * elapsed_secs) as u64;
            let max_burst = self.max_bps * 2; // 2 second burst
            // Atomically: load current, add tokens, cap at burst, store back
            let _ =
                self.byte_tokens
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                        Some((current.saturating_add(add_bytes)).min(max_burst))
                    });
        }
    }
}

/// Get milliseconds since the global start instant (no syscall in hot path).
#[inline]
fn now_ms() -> u64 {
    let start = START_INSTANT.get_or_init(Instant::now);
    start.elapsed().as_millis() as u64
}

/// Get microseconds since the global start instant (no syscall in hot path).
#[inline]
fn now_us() -> u64 {
    let start = START_INSTANT.get_or_init(Instant::now);
    start.elapsed().as_micros() as u64
}

impl RelaySession {
    /// Create a new relay session.
    pub fn new(session_id: SessionId, client_addr: SocketAddr) -> Self {
        Self::with_rate_limit(session_id, client_addr, 0, 0)
    }

    /// Create a new relay session with rate limits.
    ///
    /// - `max_pps`: Maximum packets per second (0 = unlimited)
    /// - `max_bps`: Maximum bytes per second (0 = unlimited)
    pub fn with_rate_limit(
        session_id: SessionId,
        client_addr: SocketAddr,
        max_pps: u32,
        max_bps: u64,
    ) -> Self {
        Self {
            session_id,
            client_addr,
            last_activity_ms: AtomicU64::new(now_ms()),
            created_at: Instant::now(),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            client_rate_limiter: RateLimiter::new(max_pps, max_bps),
            upstream_rate_limiter: RateLimiter::new(max_pps, max_bps),
        }
    }

    /// Check if a client -> upstream packet is allowed by rate limits.
    pub fn check_rate_limit(&self, bytes: usize) -> bool {
        self.client_rate_limiter.check(bytes)
    }

    /// Check if an upstream -> client packet is allowed by rate limits.
    pub fn check_upstream_rate_limit(&self, bytes: usize) -> bool {
        self.upstream_rate_limiter.check(bytes)
    }

    /// Update last activity timestamp (lock-free, uses atomic store).
    #[inline]
    pub fn touch(&self) {
        self.last_activity_ms.store(now_ms(), Ordering::Relaxed);
    }

    /// Check if session has expired.
    pub fn is_expired(&self, timeout: Duration) -> bool {
        let now = now_ms();
        let last = self.last_activity_ms.load(Ordering::Relaxed);
        now.saturating_sub(last) > timeout.as_millis() as u64
    }

    /// Record bytes sent (client -> upstream).
    pub fn record_sent(&self, bytes: usize) {
        self.bytes_sent.fetch_add(bytes as u64, Ordering::Relaxed);
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Record bytes received (upstream -> client).
    pub fn record_received(&self, bytes: usize) {
        self.bytes_received
            .fetch_add(bytes as u64, Ordering::Relaxed);
        self.packets_received.fetch_add(1, Ordering::Relaxed);
    }

    /// Get session statistics.
    pub fn stats(&self) -> SessionStats {
        SessionStats {
            session_id: self.session_id,
            client_addr: self.client_addr,
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            packets_received: self.packets_received.load(Ordering::Relaxed),
            age: self.created_at.elapsed(),
        }
    }
}

/// Session statistics snapshot.
#[derive(Clone, Debug)]
pub struct SessionStats {
    pub session_id: SessionId,
    pub client_addr: SocketAddr,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub age: Duration,
}

/// Default maximum sessions per IP (DoS protection).
const DEFAULT_MAX_SESSIONS_PER_IP: usize = 100;

/// Default maximum unique IPs to track (OOM protection against IP spoofing attacks).
/// An attacker sending packets from millions of spoofed IPs could cause unbounded
/// HashMap growth without this limit.
const DEFAULT_MAX_TRACKED_IPS: usize = 100_000;

/// Relay session manager.
pub struct SessionManager {
    /// Active sessions indexed by session ID.
    sessions: RwLock<HashMap<SessionId, RelaySession>>,
    /// Per-IP session counts (DoS protection).
    ip_session_counts: RwLock<HashMap<IpAddr, usize>>,
    /// Session timeout duration.
    timeout: Duration,
    /// Maximum sessions allowed. Atomic so the relay can clamp it down
    /// at runtime (FIX-021) without rebuilding the whole `SessionManager`.
    max_sessions: AtomicUsize,
    /// Maximum sessions per IP address (DoS protection).
    max_sessions_per_ip: usize,
    /// Maximum unique IPs to track (OOM protection against IP spoofing).
    max_tracked_ips: usize,
    /// Rate limit: max packets per second per session (0 = unlimited).
    rate_limit_pps: u32,
    /// Rate limit: max bytes per second per session (0 = unlimited).
    rate_limit_bps: u64,
}

/// Result of client packet processing in the relay session manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientPacketProcessResult {
    /// Packet is authorized and should be forwarded.
    Forward {
        /// Whether this packet created a new session mapping.
        is_new: bool,
    },
    /// Packet was rejected because session creation/update was denied.
    SessionRejected,
    /// Packet was rejected because source address does not match session binding.
    RoamingBlocked,
    /// Packet was rejected by per-session rate limiting.
    RateLimited,
}

impl SessionManager {
    /// Create a new session manager.
    pub fn new(timeout: Duration, max_sessions: usize) -> Self {
        Self::with_rate_limits(timeout, max_sessions, 0, 0)
    }

    /// Create a new session manager with rate limits.
    pub fn with_rate_limits(
        timeout: Duration,
        max_sessions: usize,
        rate_limit_pps: u32,
        rate_limit_bps: u64,
    ) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            ip_session_counts: RwLock::new(HashMap::new()),
            timeout,
            max_sessions: AtomicUsize::new(max_sessions),
            max_sessions_per_ip: DEFAULT_MAX_SESSIONS_PER_IP,
            max_tracked_ips: DEFAULT_MAX_TRACKED_IPS,
            rate_limit_pps,
            rate_limit_bps,
        }
    }

    /// Bind a session ID confirmed by a verified upstream `HandshakeResponse`
    /// to the originating client address.
    ///
    /// This is the ONLY path that may create a new session entry in the relay
    /// session table. The data-plane entry point (`process_client_packet`)
    /// MUST NOT create sessions — it rejects unknown IDs so an attacker who
    /// guesses or sniffs a session ID cannot install themselves as the bound
    /// client address by simply sending a single `MessageType::Data` packet.
    ///
    /// `SessionId(0)` is reserved by the protocol for pre-session and
    /// fragmented bootstrap packets. The relay always refuses it here as a
    /// belt-and-braces guard against a malformed upstream response or an
    /// attacker injecting a forged `HandshakeResponse` with `session_id == 0`.
    pub fn bind_established(&self, session_id: SessionId, client_addr: SocketAddr) -> bool {
        if session_id == SessionId(0) {
            tracing::warn!(
                "Refusing to bind reserved SessionId(0) from upstream to {}",
                crate::privacy::addr(client_addr)
            );
            return false;
        }
        self.get_or_create(session_id, client_addr)
    }

    /// Get or create a session for the given session ID and client address.
    ///
    /// Returns true if this is a new session.
    /// Enforces per-IP session limits to prevent session flooding attacks.
    ///
    /// **Use [`Self::bind_established`] from production code paths**. This
    /// method is retained as the internal primitive (still exercised by
    /// unit tests) but offers no `SessionId(0)` protection on its own.
    pub fn get_or_create(&self, session_id: SessionId, client_addr: SocketAddr) -> bool {
        let client_ip = client_addr.ip();

        // First check if session exists (fast path with read lock)
        {
            let sessions = self.sessions.read();
            if let Some(session) = sessions.get(&session_id) {
                // Session exists, but client address may have changed (roaming)
                if session.client_addr == client_addr {
                    return false;
                }
            }
        }

        // Need to create or update (slow path with write lock)
        let mut sessions = self.sessions.write();

        // Check if we need to create a new session
        if let Some(session) = sessions.get_mut(&session_id) {
            // SECURITY: Do NOT allow session roaming in relay mode.
            // The relay cannot cryptographically verify that the "new" client
            // is the same as the original. Allowing roaming would enable an
            // attacker who knows/guesses a session ID to hijack the session
            // by sending packets from their IP.
            //
            // Only the original client IP is allowed for an established session.
            // If the client truly roams, they must establish a new session with
            // the upstream server (which can verify cryptographically).
            if session.client_addr != client_addr {
                // Log potential hijacking attempt — addresses redacted by
                // default via privacy::addr() when `no_log` is enabled.
                tracing::warn!(
                    "Session {} roaming attempt blocked: {} -> {} (possible hijacking)",
                    session_id,
                    crate::privacy::addr(session.client_addr),
                    crate::privacy::addr(client_addr)
                );
                return false;
            }
            session.touch();
            return false;
        }

        // Check global capacity first (before per-IP check to avoid lock
        // contention).
        let cap = self.max_sessions.load(Ordering::Acquire);
        if sessions.len() >= cap {
            // Try to evict expired sessions first
            self.cleanup_expired_locked(&mut sessions);

            if sessions.len() >= cap {
                // Still at capacity - reject
                return false;
            }
        }

        // Atomically check per-IP limit and increment count
        // Holding write lock for both operations prevents race conditions
        {
            let mut ip_counts = self.ip_session_counts.write();

            // Check if this is a new IP and we've hit the tracked IPs limit
            // This prevents OOM from attackers sending packets with millions of spoofed IPs
            if !ip_counts.contains_key(&client_ip) && ip_counts.len() >= self.max_tracked_ips {
                tracing::warn!(
                    "Max tracked IPs limit reached ({}), rejecting new IP {}",
                    self.max_tracked_ips,
                    client_ip
                );
                return false;
            }

            let count = ip_counts.entry(client_ip).or_insert(0);
            if *count >= self.max_sessions_per_ip {
                // IP has too many sessions - reject (fail-closed)
                return false;
            }
            // Increment before releasing lock to prevent races
            *count += 1;
        }

        // Create new session with rate limits
        sessions.insert(
            session_id,
            RelaySession::with_rate_limit(
                session_id,
                client_addr,
                self.rate_limit_pps,
                self.rate_limit_bps,
            ),
        );

        true
    }

    /// Get the client address for a session (test-only — production uses `process_upstream_packet`).
    #[cfg(test)]
    pub fn get_client_addr(&self, session_id: SessionId) -> Option<SocketAddr> {
        self.sessions.read().get(&session_id).map(|s| s.client_addr)
    }

    /// Update session activity and record bytes sent (test-only — production uses `process_client_packet`).
    #[cfg(test)]
    pub fn record_sent(&self, session_id: SessionId, bytes: usize) {
        let sessions = self.sessions.read();
        if let Some(session) = sessions.get(&session_id) {
            session.record_sent(bytes);
        }
    }

    /// Update session activity and record bytes received (test-only — production uses `process_upstream_packet`).
    #[cfg(test)]
    pub fn record_received(&self, session_id: SessionId, bytes: usize) {
        let sessions = self.sessions.read();
        if let Some(session) = sessions.get(&session_id) {
            session.record_received(bytes);
        }
    }

    /// Touch session to update last activity (test-only — production uses combined methods).
    #[cfg(test)]
    pub fn touch(&self, session_id: SessionId) {
        let sessions = self.sessions.read();
        if let Some(session) = sessions.get(&session_id) {
            session.touch();
        }
    }

    /// Process an upstream packet: get client addr, record bytes, and touch - all in one operation.
    /// This reduces 3 separate lock acquisitions to 1.
    #[inline]
    pub fn process_upstream_packet(
        &self,
        session_id: SessionId,
        bytes: usize,
    ) -> Option<SocketAddr> {
        let sessions = self.sessions.read();
        if let Some(session) = sessions.get(&session_id) {
            session.record_received(bytes);
            session.touch();
            Some(session.client_addr)
        } else {
            None
        }
    }

    /// Process a client packet in one flow: session authorization, rate limiting,
    /// and stats/activity updates.
    ///
    /// **Data path only.** Unknown session IDs are rejected — only the
    /// bootstrap path (`forward_handshake_packet` -> `bind_established`)
    /// may create new sessions. This prevents an attacker who guesses or
    /// sniffs a session ID from squatting it by sending a single
    /// `MessageType::Data` packet from their own source address.
    ///
    /// `SessionId(0)` is reserved for fragmented bootstrap and is rejected
    /// here defensively.
    #[inline]
    pub fn process_client_packet(
        &self,
        session_id: SessionId,
        client_addr: SocketAddr,
        bytes: usize,
    ) -> ClientPacketProcessResult {
        if session_id == SessionId(0) {
            return ClientPacketProcessResult::SessionRejected;
        }

        let sessions = self.sessions.read();
        let Some(session) = sessions.get(&session_id) else {
            // No create-on-demand: this is the key security invariant — see
            // method doc comment above.
            return ClientPacketProcessResult::SessionRejected;
        };

        if session.client_addr != client_addr {
            return ClientPacketProcessResult::RoamingBlocked;
        }

        if (self.rate_limit_pps > 0 || self.rate_limit_bps > 0) && !session.check_rate_limit(bytes)
        {
            return ClientPacketProcessResult::RateLimited;
        }

        session.record_sent(bytes);
        session.touch();
        let is_new = false;

        ClientPacketProcessResult::Forward { is_new }
    }

    /// Remove a session and decrement the per-IP session counter.
    ///
    /// Used by the relay's bootstrap rollback path (F-3): if
    /// `bind_established` succeeded but the subsequent
    /// `client_tx.send_to(response, …)` failed, the per-IP counter would
    /// otherwise stay incremented for the full session-timeout window
    /// (default 60s+), so a `send_to`-fails storm against a single
    /// client IP could exhaust the per-IP cap with phantom entries.
    /// Calling `remove` rolls back the session-table entry first, then
    /// the per-IP counter; the two locks are taken in sequence, NOT
    /// atomically as a single critical section. Under high contention
    /// a concurrent `bind_established` may briefly observe a per-IP
    /// count one above the true session count. Self-corrects within
    /// microseconds and never widens the cap, so the consistency drift
    /// is observable only as a momentary alerting blip on
    /// per-IP-saturation dashboards.
    pub fn remove(&self, session_id: SessionId) -> Option<RelaySession> {
        let session = self.sessions.write().remove(&session_id);
        if let Some(ref s) = session {
            let client_ip = s.client_addr.ip();
            let mut ip_counts = self.ip_session_counts.write();
            if let Some(count) = ip_counts.get_mut(&client_ip) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    ip_counts.remove(&client_ip);
                }
            }
        }
        session
    }

    /// Check if a client -> upstream packet is allowed by rate limits (test-only — production uses `process_client_packet`).
    #[cfg(test)]
    pub fn check_rate_limit(&self, session_id: SessionId, bytes: usize) -> bool {
        let sessions = self.sessions.read();
        if let Some(session) = sessions.get(&session_id) {
            session.check_rate_limit(bytes)
        } else {
            // Session doesn't exist, deny by default
            false
        }
    }

    /// Check if an upstream -> client packet is allowed by rate limits.
    ///
    /// Returns true if the packet is allowed, false if rate limited.
    pub fn check_upstream_rate_limit(&self, session_id: SessionId, bytes: usize) -> bool {
        let sessions = self.sessions.read();
        if let Some(session) = sessions.get(&session_id) {
            session.check_upstream_rate_limit(bytes)
        } else {
            false
        }
    }

    /// Check if rate limiting is enabled.
    pub fn is_rate_limited(&self) -> bool {
        self.rate_limit_pps > 0 || self.rate_limit_bps > 0
    }

    /// Cleanup expired sessions.
    pub fn cleanup_expired(&self) -> usize {
        let mut sessions = self.sessions.write();
        self.cleanup_expired_locked(&mut sessions)
    }

    fn cleanup_expired_locked(&self, sessions: &mut HashMap<SessionId, RelaySession>) -> usize {
        let before = sessions.len();

        // Collect IPs of sessions being removed
        let mut removed_ips: Vec<IpAddr> = Vec::new();
        sessions.retain(|_, s| {
            let keep = !s.is_expired(self.timeout);
            if !keep {
                removed_ips.push(s.client_addr.ip());
            }
            keep
        });

        let removed_count = before - sessions.len();

        // Update IP session counts for removed sessions
        if !removed_ips.is_empty() {
            let mut ip_counts = self.ip_session_counts.write();
            for ip in removed_ips {
                if let Some(count) = ip_counts.get_mut(&ip) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        ip_counts.remove(&ip);
                    }
                }
            }
            // Shrink the HashMap if it's significantly oversized
            if ip_counts.capacity() > ip_counts.len() * 4 && ip_counts.len() < 1000 {
                ip_counts.shrink_to_fit();
            }
        }

        // Shrink sessions HashMap if significantly oversized
        if sessions.capacity() > sessions.len() * 4 && sessions.len() < 1000 {
            sessions.shrink_to_fit();
        }

        removed_count
    }

    /// Get current session count.
    pub fn session_count(&self) -> usize {
        self.sessions.read().len()
    }

    /// Get all session statistics (test-only — production uses `aggregate_stats`).
    #[cfg(test)]
    pub fn all_stats(&self) -> Vec<SessionStats> {
        self.sessions.read().values().map(|s| s.stats()).collect()
    }

    /// Get aggregate statistics.
    pub fn aggregate_stats(&self) -> AggregateStats {
        let sessions = self.sessions.read();
        let mut stats = AggregateStats {
            session_count: sessions.len(),
            total_bytes_sent: 0,
            total_bytes_received: 0,
            total_packets_sent: 0,
            total_packets_received: 0,
        };

        for session in sessions.values() {
            stats.total_bytes_sent += session.bytes_sent.load(Ordering::Relaxed);
            stats.total_bytes_received += session.bytes_received.load(Ordering::Relaxed);
            stats.total_packets_sent += session.packets_sent.load(Ordering::Relaxed);
            stats.total_packets_received += session.packets_received.load(Ordering::Relaxed);
        }

        stats
    }
}

/// Aggregate statistics for all sessions.
#[derive(Clone, Debug, Default)]
pub struct AggregateStats {
    pub session_count: usize,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub total_packets_sent: u64,
    pub total_packets_received: u64,
}

impl AggregateStats {
    /// Format as human-readable string.
    pub fn format(&self) -> String {
        format!(
            "Sessions: {}, Sent: {} ({} pkts), Recv: {} ({} pkts)",
            self.session_count,
            format_bytes(self.total_bytes_sent),
            self.total_packets_sent,
            format_bytes(self.total_bytes_received),
            self.total_packets_received
        )
    }
}

/// Format bytes as human-readable string.
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let manager = SessionManager::new(Duration::from_secs(60), 100);
        let session_id = SessionId::generate();
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        // First call creates session
        assert!(manager.get_or_create(session_id, addr));
        assert_eq!(manager.session_count(), 1);

        // Second call returns existing
        assert!(!manager.get_or_create(session_id, addr));
        assert_eq!(manager.session_count(), 1);
    }

    #[test]
    fn test_session_roaming_blocked() {
        // SECURITY: Roaming is intentionally disabled in relay mode to prevent
        // session hijacking attacks. This test verifies that behavior.
        let manager = SessionManager::new(Duration::from_secs(60), 100);
        let session_id = SessionId::generate();
        let addr1: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:12346".parse().unwrap();

        // Create session with first address
        assert!(manager.get_or_create(session_id, addr1));
        assert_eq!(manager.get_client_addr(session_id), Some(addr1));

        // Attempt to "roam" to new address - should be rejected (returns false = not new)
        // and address should remain unchanged
        assert!(!manager.get_or_create(session_id, addr2));
        // Address should still be the original one
        assert_eq!(manager.get_client_addr(session_id), Some(addr1));
    }

    #[test]
    fn test_session_stats() {
        let manager = SessionManager::new(Duration::from_secs(60), 100);
        let session_id = SessionId::generate();
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        manager.get_or_create(session_id, addr);
        manager.record_sent(session_id, 1000);
        manager.record_received(session_id, 2000);

        let stats = manager.aggregate_stats();
        assert_eq!(stats.total_bytes_sent, 1000);
        assert_eq!(stats.total_bytes_received, 2000);
        assert_eq!(stats.total_packets_sent, 1);
        assert_eq!(stats.total_packets_received, 1);
    }

    #[test]
    fn test_rate_limiter_unlimited() {
        let limiter = RateLimiter::unlimited();
        // Unlimited should always allow
        for _ in 0..1000 {
            assert!(limiter.check(1500));
        }
    }

    #[test]
    fn test_rate_limiter_pps() {
        // Allow 10 packets per second (initial bucket = 10, burst allows up to 2x = 20)
        let limiter = RateLimiter::new(10, 0);
        // Should allow first 10 packets (initial bucket starts at max_pps)
        for i in 0..10 {
            assert!(limiter.check(100), "packet {} should be allowed", i);
        }
        // 11th packet should be rate limited (no refill yet)
        assert!(!limiter.check(100), "packet 11 should be rate limited");
    }

    #[test]
    fn test_rate_limiter_bps() {
        // Allow 1000 bytes per second (initial bucket = 1000)
        let limiter = RateLimiter::new(0, 1000);
        // Should allow first 1000 bytes
        assert!(limiter.check(500));
        assert!(limiter.check(500));
        // Next should be rate limited
        assert!(!limiter.check(100));
    }

    #[test]
    fn test_session_with_rate_limit() {
        // Create manager with rate limits: 5 pps, 5000 bps
        let manager = SessionManager::with_rate_limits(Duration::from_secs(60), 100, 5, 5000);
        let session_id = SessionId::generate();
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        manager.get_or_create(session_id, addr);
        assert!(manager.is_rate_limited());

        // First 5 packets should be allowed (initial bucket = max_pps = 5)
        for i in 0..5 {
            assert!(
                manager.check_rate_limit(session_id, 100),
                "packet {} should be allowed",
                i
            );
        }
        // 6th packet should be rate limited
        assert!(!manager.check_rate_limit(session_id, 100));
    }

    #[test]
    fn test_relay_session_creation() {
        let session_id = SessionId::generate();
        let addr: SocketAddr = "192.168.1.1:5000".parse().unwrap();
        let session = RelaySession::new(session_id, addr);

        assert_eq!(session.session_id, session_id);
        assert_eq!(session.client_addr, addr);
        assert_eq!(session.bytes_sent.load(Ordering::Relaxed), 0);
        assert_eq!(session.bytes_received.load(Ordering::Relaxed), 0);
        assert_eq!(session.packets_sent.load(Ordering::Relaxed), 0);
        assert_eq!(session.packets_received.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_relay_session_with_rate_limit() {
        let session_id = SessionId::generate();
        let addr: SocketAddr = "10.0.0.1:8080".parse().unwrap();
        let session = RelaySession::with_rate_limit(session_id, addr, 100, 10000);

        assert_eq!(session.session_id, session_id);
        assert_eq!(session.client_addr, addr);
    }

    #[test]
    fn test_relay_session_record_traffic() {
        let session_id = SessionId::generate();
        let addr: SocketAddr = "172.16.0.1:9090".parse().unwrap();
        let session = RelaySession::new(session_id, addr);

        session.record_sent(1500);
        assert_eq!(session.bytes_sent.load(Ordering::Relaxed), 1500);
        assert_eq!(session.packets_sent.load(Ordering::Relaxed), 1);

        session.record_received(2000);
        assert_eq!(session.bytes_received.load(Ordering::Relaxed), 2000);
        assert_eq!(session.packets_received.load(Ordering::Relaxed), 1);

        // Record more
        session.record_sent(500);
        assert_eq!(session.bytes_sent.load(Ordering::Relaxed), 2000);
        assert_eq!(session.packets_sent.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_relay_session_touch() {
        let session_id = SessionId::generate();
        let addr: SocketAddr = "203.0.113.1:1234".parse().unwrap();
        let session = RelaySession::new(session_id, addr);

        let initial = session.last_activity_ms.load(Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(10));
        session.touch();
        let after = session.last_activity_ms.load(Ordering::Relaxed);

        assert!(after > initial);
    }

    #[test]
    fn test_relay_session_is_expired() {
        let session_id = SessionId::generate();
        let addr: SocketAddr = "10.1.1.1:7777".parse().unwrap();
        let session = RelaySession::new(session_id, addr);

        // Should not be expired immediately
        assert!(!session.is_expired(Duration::from_millis(100)));

        std::thread::sleep(Duration::from_millis(150));

        // Should be expired after 150ms with 100ms timeout
        assert!(session.is_expired(Duration::from_millis(100)));

        // Touch resets expiry
        session.touch();
        assert!(!session.is_expired(Duration::from_millis(100)));
    }

    #[test]
    fn test_relay_session_stats() {
        let session_id = SessionId::generate();
        let addr: SocketAddr = "198.51.100.1:5678".parse().unwrap();
        let session = RelaySession::new(session_id, addr);

        session.record_sent(1500);
        session.record_received(2500);

        let stats = session.stats();
        assert_eq!(stats.session_id, session_id);
        assert_eq!(stats.client_addr, addr);
        assert_eq!(stats.bytes_sent, 1500);
        assert_eq!(stats.bytes_received, 2500);
        assert_eq!(stats.packets_sent, 1);
        assert_eq!(stats.packets_received, 1);
        assert!(stats.age < Duration::from_secs(1));
    }

    #[test]
    fn test_relay_session_check_rate_limit() {
        let session_id = SessionId::generate();
        let addr: SocketAddr = "192.0.2.1:4321".parse().unwrap();
        let session = RelaySession::with_rate_limit(session_id, addr, 10, 10000);

        // First 10 packets should be allowed
        for i in 0..10 {
            assert!(session.check_rate_limit(100), "packet {} should pass", i);
        }

        // 11th should be rate limited
        assert!(!session.check_rate_limit(100));
    }

    #[test]
    fn test_session_manager_get_client_addr() {
        let manager = SessionManager::new(Duration::from_secs(60), 100);
        let session_id = SessionId::generate();
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        assert_eq!(manager.get_client_addr(session_id), None);

        manager.get_or_create(session_id, addr);
        assert_eq!(manager.get_client_addr(session_id), Some(addr));
    }

    #[test]
    fn test_session_manager_touch() {
        let manager = SessionManager::new(Duration::from_secs(60), 100);
        let session_id = SessionId::generate();
        let addr: SocketAddr = "127.0.0.1:8888".parse().unwrap();

        manager.get_or_create(session_id, addr);

        std::thread::sleep(Duration::from_millis(10));
        manager.touch(session_id);

        // Touch should prevent immediate timeout
        assert_eq!(manager.session_count(), 1);
    }

    #[test]
    fn test_session_manager_record_sent() {
        let manager = SessionManager::new(Duration::from_secs(60), 100);
        let session_id = SessionId::generate();
        let addr: SocketAddr = "127.0.0.1:7777".parse().unwrap();

        manager.get_or_create(session_id, addr);
        manager.record_sent(session_id, 1024);

        let stats = manager.aggregate_stats();
        assert_eq!(stats.total_bytes_sent, 1024);
        assert_eq!(stats.total_packets_sent, 1);
    }

    #[test]
    fn test_session_manager_record_received() {
        let manager = SessionManager::new(Duration::from_secs(60), 100);
        let session_id = SessionId::generate();
        let addr: SocketAddr = "127.0.0.1:6666".parse().unwrap();

        manager.get_or_create(session_id, addr);
        manager.record_received(session_id, 2048);

        let stats = manager.aggregate_stats();
        assert_eq!(stats.total_bytes_received, 2048);
        assert_eq!(stats.total_packets_received, 1);
    }

    #[test]
    fn test_session_manager_multiple_sessions() {
        let manager = SessionManager::new(Duration::from_secs(60), 100);

        let id1 = SessionId::generate();
        let id2 = SessionId::generate();
        let id3 = SessionId::generate();

        let addr1: SocketAddr = "127.0.0.1:1111".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:2222".parse().unwrap();
        let addr3: SocketAddr = "127.0.0.1:3333".parse().unwrap();

        manager.get_or_create(id1, addr1);
        manager.get_or_create(id2, addr2);
        manager.get_or_create(id3, addr3);

        assert_eq!(manager.session_count(), 3);
        assert_eq!(manager.get_client_addr(id1), Some(addr1));
        assert_eq!(manager.get_client_addr(id2), Some(addr2));
        assert_eq!(manager.get_client_addr(id3), Some(addr3));
    }

    #[test]
    fn test_session_manager_max_sessions() {
        let manager = SessionManager::new(Duration::from_secs(60), 2);

        let id1 = SessionId::generate();
        let id2 = SessionId::generate();
        let id3 = SessionId::generate();

        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();

        assert!(manager.get_or_create(id1, addr));
        assert!(manager.get_or_create(id2, addr));
        assert!(!manager.get_or_create(id3, addr)); // Should fail - max reached

        assert_eq!(manager.session_count(), 2);
    }

    #[test]
    fn test_session_manager_cleanup_expired() {
        let manager = SessionManager::new(Duration::from_millis(50), 100);
        let session_id = SessionId::generate();
        let addr: SocketAddr = "127.0.0.1:4000".parse().unwrap();

        manager.get_or_create(session_id, addr);
        assert_eq!(manager.session_count(), 1);

        std::thread::sleep(Duration::from_millis(100));

        let removed = manager.cleanup_expired();
        assert!(removed > 0);
        assert_eq!(manager.session_count(), 0);
    }

    #[test]
    fn test_session_manager_is_rate_limited() {
        let manager = SessionManager::new(Duration::from_secs(60), 100);
        assert!(!manager.is_rate_limited());

        let manager_limited =
            SessionManager::with_rate_limits(Duration::from_secs(60), 100, 100, 100000);
        assert!(manager_limited.is_rate_limited());
    }

    #[test]
    fn test_session_manager_check_rate_limit_nonexistent() {
        let manager = SessionManager::with_rate_limits(Duration::from_secs(60), 100, 10, 10000);
        let session_id = SessionId::generate();

        // Should return false for nonexistent session (fail-closed for security)
        assert!(!manager.check_rate_limit(session_id, 100));
    }

    #[test]
    fn test_rate_limiter_new() {
        let limiter = RateLimiter::new(100, 100000);
        assert_eq!(limiter.max_pps, 100);
        assert_eq!(limiter.max_bps, 100000);
        assert_eq!(limiter.packet_tokens.load(Ordering::Relaxed), 100);
        assert_eq!(limiter.byte_tokens.load(Ordering::Relaxed), 100000);
    }

    #[test]
    fn test_rate_limiter_both_limits() {
        let limiter = RateLimiter::new(10, 1000);

        // Should allow packets that fit both limits
        for i in 0..10 {
            assert!(limiter.check(100), "packet {} should be allowed", i);
        }

        // 11th packet should fail (pps limit)
        assert!(!limiter.check(100));
    }

    #[test]
    fn test_rate_limiter_byte_limit_exhaustion() {
        let limiter = RateLimiter::new(100, 1000);

        // Use up byte quota with large packets
        assert!(limiter.check(500));
        assert!(limiter.check(500));

        // Should fail on byte limit even though packet limit not reached
        assert!(!limiter.check(100));
    }

    #[test]
    fn test_rate_limiter_zero_limits_unlimited() {
        let limiter = RateLimiter::new(0, 0);

        for _ in 0..10000 {
            assert!(limiter.check(10000));
        }
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1536), "1.50 KB");
        assert_eq!(format_bytes(1048576), "1.00 MB");
        assert_eq!(format_bytes(1572864), "1.50 MB");
        assert_eq!(format_bytes(1073741824), "1.00 GB");
        assert_eq!(format_bytes(1610612736), "1.50 GB");
    }

    #[test]
    fn test_session_stats_formatting() {
        let manager = SessionManager::new(Duration::from_secs(60), 100);
        let session_id = SessionId::generate();
        let addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();

        manager.get_or_create(session_id, addr);
        manager.record_sent(session_id, 1024);
        manager.record_received(session_id, 2048);

        let stats = manager.aggregate_stats();
        let formatted = stats.format();

        assert!(formatted.contains("Sessions: 1"));
        assert!(formatted.contains("1.00 KB"));
        assert!(formatted.contains("2.00 KB"));
        assert!(formatted.contains("1 pkts"));
    }

    #[test]
    fn test_now_ms_increments() {
        let t1 = now_ms();
        std::thread::sleep(Duration::from_millis(10));
        let t2 = now_ms();

        assert!(t2 > t1);
        assert!(t2 - t1 >= 10);
    }

    #[test]
    fn test_now_us_increments() {
        let t1 = now_us();
        std::thread::sleep(Duration::from_millis(10));
        let t2 = now_us();

        assert!(t2 > t1);
        assert!(t2 - t1 >= 10000); // 10ms = 10000us
    }

    #[test]
    fn test_session_manager_aggregate_stats_multiple() {
        let manager = SessionManager::new(Duration::from_secs(60), 100);

        let id1 = SessionId::generate();
        let id2 = SessionId::generate();
        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();

        manager.get_or_create(id1, addr);
        manager.get_or_create(id2, addr);

        manager.record_sent(id1, 1000);
        manager.record_sent(id2, 2000);
        manager.record_received(id1, 500);
        manager.record_received(id2, 1500);

        let stats = manager.aggregate_stats();
        assert_eq!(stats.session_count, 2);
        assert_eq!(stats.total_bytes_sent, 3000);
        assert_eq!(stats.total_bytes_received, 2000);
        assert_eq!(stats.total_packets_sent, 2);
        assert_eq!(stats.total_packets_received, 2);
    }

    #[test]
    fn test_session_ipv6_address() {
        let manager = SessionManager::new(Duration::from_secs(60), 100);
        let session_id = SessionId::generate();
        let addr: SocketAddr = "[2001:db8::1]:8080".parse().unwrap();

        assert!(manager.get_or_create(session_id, addr));
        assert_eq!(manager.get_client_addr(session_id), Some(addr));
    }

    #[test]
    fn test_max_tracked_ips_limit() {
        // Create manager with small max_tracked_ips for testing
        let mut manager = SessionManager::new(Duration::from_secs(60), 1000);
        manager.max_tracked_ips = 3; // Only allow 3 unique IPs

        // Create sessions from 3 different IPs - should succeed
        let id1 = SessionId::generate();
        let id2 = SessionId::generate();
        let id3 = SessionId::generate();

        let addr1: SocketAddr = "192.168.1.1:1111".parse().unwrap();
        let addr2: SocketAddr = "192.168.1.2:2222".parse().unwrap();
        let addr3: SocketAddr = "192.168.1.3:3333".parse().unwrap();

        assert!(manager.get_or_create(id1, addr1));
        assert!(manager.get_or_create(id2, addr2));
        assert!(manager.get_or_create(id3, addr3));

        // 4th IP should be rejected - max tracked IPs reached
        let id4 = SessionId::generate();
        let addr4: SocketAddr = "192.168.1.4:4444".parse().unwrap();
        assert!(!manager.get_or_create(id4, addr4));

        // But adding another session from existing IP should succeed
        let id5 = SessionId::generate();
        let addr1_new_port: SocketAddr = "192.168.1.1:5555".parse().unwrap();
        assert!(manager.get_or_create(id5, addr1_new_port));
    }

    #[test]
    fn test_max_tracked_ips_cleanup_allows_new() {
        // Create manager with small max_tracked_ips and short timeout
        let mut manager = SessionManager::new(Duration::from_millis(50), 1000);
        manager.max_tracked_ips = 2;

        let id1 = SessionId::generate();
        let id2 = SessionId::generate();

        let addr1: SocketAddr = "10.0.0.1:1111".parse().unwrap();
        let addr2: SocketAddr = "10.0.0.2:2222".parse().unwrap();

        assert!(manager.get_or_create(id1, addr1));
        assert!(manager.get_or_create(id2, addr2));

        // 3rd IP rejected
        let id3 = SessionId::generate();
        let addr3: SocketAddr = "10.0.0.3:3333".parse().unwrap();
        assert!(!manager.get_or_create(id3, addr3));

        // Wait for sessions to expire and cleanup
        std::thread::sleep(Duration::from_millis(100));
        manager.cleanup_expired();

        // Now new IP should be allowed
        assert!(manager.get_or_create(id3, addr3));
    }

    #[test]
    fn test_process_client_packet_roaming_blocked() {
        let manager = SessionManager::new(Duration::from_secs(60), 100);
        let session_id = SessionId::generate();
        let addr1: SocketAddr = "192.168.10.1:5000".parse().unwrap();
        let addr2: SocketAddr = "192.168.10.2:5001".parse().unwrap();

        // The relay only allows the bootstrap path to create new sessions.
        // Simulate that here so the data-plane call has a session to look up.
        assert!(manager.bind_established(session_id, addr1));

        let first = manager.process_client_packet(session_id, addr1, 512);
        assert_eq!(first, ClientPacketProcessResult::Forward { is_new: false });

        let second = manager.process_client_packet(session_id, addr2, 512);
        assert_eq!(second, ClientPacketProcessResult::RoamingBlocked);
    }

    #[test]
    fn test_process_client_packet_rate_limited() {
        let manager = SessionManager::with_rate_limits(Duration::from_secs(60), 100, 2, 0);
        let session_id = SessionId::generate();
        let addr: SocketAddr = "10.10.0.5:6000".parse().unwrap();

        assert!(manager.bind_established(session_id, addr));

        assert_eq!(
            manager.process_client_packet(session_id, addr, 128),
            ClientPacketProcessResult::Forward { is_new: false }
        );
        assert_eq!(
            manager.process_client_packet(session_id, addr, 128),
            ClientPacketProcessResult::Forward { is_new: false }
        );
        assert_eq!(
            manager.process_client_packet(session_id, addr, 128),
            ClientPacketProcessResult::RateLimited
        );
    }

    #[test]
    fn test_bind_established_refuses_session_zero() {
        let manager = SessionManager::new(Duration::from_secs(60), 100);
        let addr: SocketAddr = "192.168.10.1:5000".parse().unwrap();
        assert!(!manager.bind_established(SessionId(0), addr));
    }

    #[test]
    fn test_process_client_packet_refuses_session_zero() {
        let manager = SessionManager::new(Duration::from_secs(60), 100);
        let addr: SocketAddr = "192.168.10.1:5000".parse().unwrap();
        assert_eq!(
            manager.process_client_packet(SessionId(0), addr, 128),
            ClientPacketProcessResult::SessionRejected
        );
    }

    #[test]
    fn test_process_client_packet_refuses_unknown_session() {
        let manager = SessionManager::new(Duration::from_secs(60), 100);
        let session_id = SessionId::generate();
        let addr: SocketAddr = "192.168.10.1:5000".parse().unwrap();
        // No bind_established — the relay must refuse the data packet rather
        // than installing the attacker's address as the session's bound peer.
        assert_eq!(
            manager.process_client_packet(session_id, addr, 128),
            ClientPacketProcessResult::SessionRejected
        );
    }
}
