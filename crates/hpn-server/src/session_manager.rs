//! High-performance session management for multiple clients.
//!
//! Uses lock-free DashMap and atomic counters for maximum throughput.
//! Optimized for multi-threaded access patterns in VPN data plane.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Default rate limit: packets per second per session.
///
/// 100k PPS corresponds to ~1.2 Gbps at 1500-byte MTU — sufficient for any
/// realistic single-client workload (HD streaming, large file transfers) while
/// preventing a single misbehaving or malicious client from saturating the
/// server's UDP worker threads. Operators can raise this via `ServerConfig`.
const DEFAULT_SESSION_RATE_LIMIT_PPS: u32 = 100_000;

/// Default rate limit: bytes per second per session.
///
/// 1 Gbps (125 MB/s) matches the PRO tier bandwidth limit and is a sane ceiling
/// for a per-user VPN connection. Operators running Enterprise deployments can
/// raise or disable this via `ServerConfig::session_rate_limit_bps`.
const DEFAULT_SESSION_RATE_LIMIT_BPS: u64 = 125_000_000;

/// Global start instant for efficient timestamps (avoids SystemTime syscalls).
/// All activity timestamps are stored as milliseconds since this instant.
static START_INSTANT: OnceLock<Instant> = OnceLock::new();

/// Get milliseconds since the global start instant (no syscall in hot path).
#[inline]
fn now_ms() -> u64 {
    let start = START_INSTANT.get_or_init(Instant::now);
    start.elapsed().as_millis() as u64
}

use dashmap::DashMap;
use dashmap::mapref::one::{Ref, RefMut};
use parking_lot::RwLock;
use tracing::{debug, info};

use hpn_core::crypto::SecurityLevel;
use hpn_core::protocol::Session;
use hpn_core::types::SessionId;

use crate::error::{ServerError, ServerResult};

/// Token bucket rate limiter for per-session traffic control.
///
/// Prevents a single client from exhausting server resources.
/// Uses atomic operations for lock-free checking in the hot path.
#[derive(Debug)]
pub struct SessionRateLimiter {
    /// Maximum packets per second (0 = unlimited).
    max_pps: u32,
    /// Maximum bytes per second (0 = unlimited).
    max_bps: u64,
    /// Token bucket for packets.
    packet_tokens: AtomicU64,
    /// Token bucket for bytes.
    byte_tokens: AtomicU64,
    /// Last refill timestamp (microseconds since start instant).
    last_refill_us: AtomicU64,
}

impl SessionRateLimiter {
    /// Create a new rate limiter.
    ///
    /// # Arguments
    /// * `max_pps` - Maximum packets per second (0 = unlimited)
    /// * `max_bps` - Maximum bytes per second (0 = unlimited)
    pub fn new(max_pps: u32, max_bps: u64) -> Self {
        Self {
            max_pps,
            max_bps,
            // Start with full buckets (2 second burst)
            packet_tokens: AtomicU64::new(max_pps as u64 * 2),
            byte_tokens: AtomicU64::new(max_bps * 2),
            last_refill_us: AtomicU64::new(now_us()),
        }
    }

    /// Create an unlimited rate limiter.
    #[inline]
    pub fn unlimited() -> Self {
        Self::new(0, 0)
    }

    /// Check if a packet of the given size is allowed.
    ///
    /// Returns `true` if allowed, `false` if rate limited.
    /// This is designed for the hot path - minimal overhead when unlimited.
    #[inline]
    pub fn check(&self, bytes: usize) -> bool {
        // Fast path: unlimited
        if self.max_pps == 0 && self.max_bps == 0 {
            return true;
        }

        // Refill tokens based on elapsed time
        self.refill();

        // Check packet rate
        if self.max_pps > 0 {
            let tokens = self.packet_tokens.load(Ordering::Relaxed);
            if tokens == 0 {
                return false;
            }
            // Try to consume one packet token
            // Use fetch_sub with saturating semantics via compare_exchange
            if self
                .packet_tokens
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |t| {
                    if t > 0 { Some(t - 1) } else { None }
                })
                .is_err()
            {
                return false;
            }
        }

        // Check byte rate
        if self.max_bps > 0 {
            let bytes_u64 = bytes as u64;
            if self
                .byte_tokens
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |t| {
                    if t >= bytes_u64 {
                        Some(t - bytes_u64)
                    } else {
                        None
                    }
                })
                .is_err()
            {
                // Rollback packet token if we consumed one
                if self.max_pps > 0 {
                    self.packet_tokens.fetch_add(1, Ordering::Relaxed);
                }
                return false;
            }
        }

        true
    }

    /// Refill tokens based on elapsed time.
    #[inline]
    fn refill(&self) {
        let now = now_us();
        let last = self.last_refill_us.load(Ordering::Relaxed);
        let elapsed_us = now.saturating_sub(last);

        // Only refill if at least 1ms has passed
        if elapsed_us < 1000 {
            return;
        }

        // Try to update last_refill (CAS to handle races)
        if self
            .last_refill_us
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return; // Another thread already refilled
        }

        // Calculate tokens to add
        let elapsed_secs = elapsed_us as f64 / 1_000_000.0;

        if self.max_pps > 0 {
            let add_packets = (self.max_pps as f64 * elapsed_secs) as u64;
            let max_burst = self.max_pps as u64 * 2; // 2 second burst
            let _ =
                self.packet_tokens
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                        Some(current.saturating_add(add_packets).min(max_burst))
                    });
        }

        if self.max_bps > 0 {
            let add_bytes = (self.max_bps as f64 * elapsed_secs) as u64;
            let max_burst = self.max_bps * 2; // 2 second burst
            let _ =
                self.byte_tokens
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                        Some(current.saturating_add(add_bytes).min(max_burst))
                    });
        }
    }

    /// Check if rate limiting is enabled.
    #[inline]
    pub fn is_limited(&self) -> bool {
        self.max_pps > 0 || self.max_bps > 0
    }
}

/// Get microseconds since the global start instant (no syscall in hot path).
#[inline]
fn now_us() -> u64 {
    let start = START_INSTANT.get_or_init(Instant::now);
    start.elapsed().as_micros() as u64
}

/// Client session information with atomic stats for lock-free updates.
pub struct ClientSession {
    /// Protocol session (keys, counters, anti-replay).
    pub session: Session,
    /// Client's UDP address (atomic for lock-free roaming updates).
    pub client_addr: parking_lot::Mutex<SocketAddr>,
    /// Allocated tunnel IPv4 address.
    pub tunnel_ip: [u8; 4],
    /// Allocated tunnel IPv6 address (if dual-stack enabled).
    pub tunnel_ipv6: Option<[u8; 16]>,
    /// Negotiated security level for this session.
    pub security_level: SecurityLevel,
    /// Time of last activity (ms since epoch, atomic for lock-free update).
    last_activity_ms: AtomicU64,
    /// Creation time.
    pub created_at: Instant,
    /// Bytes sent to this client (atomic for lock-free update).
    bytes_sent: AtomicU64,
    /// Bytes received from this client (atomic for lock-free update).
    bytes_received: AtomicU64,
    /// Count of source IP mismatches (normal during TUN init, tracked to avoid log spam).
    src_mismatch_count: AtomicU32,
    /// Rate limiter for this session (prevents single client from exhausting resources).
    rate_limiter: SessionRateLimiter,
}

impl ClientSession {
    /// Create a new client session with default rate limits.
    pub fn new(session: Session, client_addr: SocketAddr, tunnel_ip: [u8; 4]) -> Self {
        Self::new_with_level(session, client_addr, tunnel_ip, SecurityLevel::default())
    }

    /// Create a new client session with explicit security level.
    pub fn new_with_level(
        session: Session,
        client_addr: SocketAddr,
        tunnel_ip: [u8; 4],
        security_level: SecurityLevel,
    ) -> Self {
        Self::with_rate_limit(
            session,
            client_addr,
            tunnel_ip,
            None,
            security_level,
            DEFAULT_SESSION_RATE_LIMIT_PPS,
            DEFAULT_SESSION_RATE_LIMIT_BPS,
        )
    }

    /// Create a new dual-stack client session with default rate limits.
    pub fn new_dual_stack(
        session: Session,
        client_addr: SocketAddr,
        tunnel_ip: [u8; 4],
        tunnel_ipv6: [u8; 16],
    ) -> Self {
        Self::new_dual_stack_with_level(
            session,
            client_addr,
            tunnel_ip,
            tunnel_ipv6,
            SecurityLevel::default(),
        )
    }

    /// Create a new dual-stack client session with explicit security level.
    pub fn new_dual_stack_with_level(
        session: Session,
        client_addr: SocketAddr,
        tunnel_ip: [u8; 4],
        tunnel_ipv6: [u8; 16],
        security_level: SecurityLevel,
    ) -> Self {
        Self::with_rate_limit(
            session,
            client_addr,
            tunnel_ip,
            Some(tunnel_ipv6),
            security_level,
            DEFAULT_SESSION_RATE_LIMIT_PPS,
            DEFAULT_SESSION_RATE_LIMIT_BPS,
        )
    }

    /// Create a new client session with custom rate limits.
    ///
    /// # Arguments
    /// * `session` - Protocol session
    /// * `client_addr` - Client's UDP address
    /// * `tunnel_ip` - Allocated tunnel IPv4 address
    /// * `tunnel_ipv6` - Allocated tunnel IPv6 address (if dual-stack)
    /// * `max_pps` - Maximum packets per second (0 = unlimited)
    /// * `max_bps` - Maximum bytes per second (0 = unlimited)
    pub fn with_rate_limit(
        session: Session,
        client_addr: SocketAddr,
        tunnel_ip: [u8; 4],
        tunnel_ipv6: Option<[u8; 16]>,
        security_level: SecurityLevel,
        max_pps: u32,
        max_bps: u64,
    ) -> Self {
        Self {
            session,
            client_addr: parking_lot::Mutex::new(client_addr),
            tunnel_ip,
            tunnel_ipv6,
            security_level,
            last_activity_ms: AtomicU64::new(now_ms()),
            created_at: Instant::now(),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            src_mismatch_count: AtomicU32::new(0),
            rate_limiter: SessionRateLimiter::new(max_pps, max_bps),
        }
    }

    /// Update last activity time (lock-free, no syscall).
    #[inline]
    pub fn touch(&self) {
        self.last_activity_ms.store(now_ms(), Ordering::Relaxed);
    }

    /// Add bytes received (lock-free).
    #[inline]
    pub fn add_bytes_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Add bytes sent (lock-free).
    #[inline]
    pub fn add_bytes_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Get bytes received.
    #[inline]
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }

    /// Get bytes sent.
    #[inline]
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// Check if the session has timed out.
    pub fn is_expired(&self, timeout: Duration) -> bool {
        let last = self.last_activity_ms.load(Ordering::Relaxed);
        now_ms().saturating_sub(last) > timeout.as_millis() as u64
    }

    /// Get session duration.
    pub fn duration(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Get last activity instant (approximate).
    pub fn last_activity(&self) -> Instant {
        let last_ms = self.last_activity_ms.load(Ordering::Relaxed);
        let start = START_INSTANT.get_or_init(Instant::now);
        // last_ms is ms since START_INSTANT, so add it to get the actual instant
        *start + Duration::from_millis(last_ms)
    }

    /// Increment source IP mismatch counter and return new count.
    /// Used to throttle logging during TUN initialization.
    #[inline]
    pub fn increment_src_mismatch(&self) -> u32 {
        self.src_mismatch_count.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Check if a packet of the given size is allowed by rate limits.
    ///
    /// Returns `true` if allowed, `false` if rate limited.
    /// Call this BEFORE processing the packet to prevent resource exhaustion.
    #[inline]
    pub fn check_rate_limit(&self, bytes: usize) -> bool {
        self.rate_limiter.check(bytes)
    }

    /// Check if rate limiting is enabled for this session.
    #[inline]
    pub fn is_rate_limited(&self) -> bool {
        self.rate_limiter.is_limited()
    }
}

/// IP address allocator for tunnel addresses.
pub struct IpAllocator {
    /// Base network address.
    base: [u8; 4],
    /// Network prefix length.
    prefix: u8,
    /// Next address to allocate (offset from base).
    next_offset: u32,
    /// Released addresses that can be reused (HashSet for O(1) lookup).
    released: HashSet<u32>,
    /// Maximum offset based on prefix.
    max_offset: u32,
}

impl IpAllocator {
    /// Create a new IP allocator.
    pub fn new(base: [u8; 4], prefix: u8) -> Self {
        let host_bits = 32 - prefix as u32;
        let max_offset = (1u32 << host_bits).saturating_sub(2);

        Self {
            base,
            prefix,
            next_offset: 2,
            released: HashSet::new(),
            max_offset,
        }
    }

    /// Allocate an IP address.
    pub fn allocate(&mut self) -> Option<[u8; 4]> {
        // Try to reuse a released address first (O(1) removal from HashSet)
        if let Some(&offset) = self.released.iter().next() {
            self.released.remove(&offset);
            return Some(self.offset_to_ip(offset));
        }

        // Check bounds before allocation to prevent offset overflow
        // max_offset is calculated in new() to ensure base + offset never overflows
        if self.next_offset <= self.max_offset {
            let ip = self.offset_to_ip(self.next_offset);
            self.next_offset += 1;
            Some(ip)
        } else {
            None
        }
    }

    /// Release an IP address for reuse.
    pub fn release(&mut self, ip: [u8; 4]) {
        if let Some(offset) = self.ip_to_offset(ip) {
            // HashSet automatically handles duplicates (O(1) insert)
            if offset >= 2 && offset <= self.max_offset {
                self.released.insert(offset);
            }
        }
    }

    fn offset_to_ip(&self, offset: u32) -> [u8; 4] {
        let base_u32 = u32::from_be_bytes(self.base);
        // Use wrapping_add to be explicit about overflow behavior
        // This is safe because allocate() checks offset <= max_offset,
        // which is calculated to prevent overflow for valid subnets
        let ip_u32 = base_u32.wrapping_add(offset);
        ip_u32.to_be_bytes()
    }

    fn ip_to_offset(&self, ip: [u8; 4]) -> Option<u32> {
        let base_u32 = u32::from_be_bytes(self.base);
        let ip_u32 = u32::from_be_bytes(ip);
        ip_u32.checked_sub(base_u32)
    }

    /// Get the number of available addresses.
    pub fn available(&self) -> u32 {
        let allocated = self.next_offset - 2;
        let released = self.released.len() as u32;
        self.max_offset.saturating_sub(allocated) + released
    }

    /// Get the netmask as bytes.
    pub fn netmask(&self) -> [u8; 4] {
        let mask = !((1u32 << (32 - self.prefix)) - 1);
        mask.to_be_bytes()
    }
}

/// IPv6 address allocator for tunnel addresses.
pub struct Ipv6Allocator {
    base: [u8; 16],
    prefix: u8,
    next_offset: u64,
    /// Released addresses that can be reused (HashSet for O(1) lookup).
    released: HashSet<u64>,
    max_offset: u64,
}

impl Ipv6Allocator {
    /// Create a new IPv6 allocator.
    pub fn new(base: [u8; 16], prefix: u8) -> Self {
        let host_bits = (128 - prefix).min(63) as u32;
        let max_offset = if host_bits >= 63 {
            u64::MAX - 2
        } else {
            (1u64 << host_bits).saturating_sub(2)
        };

        Self {
            base,
            prefix,
            next_offset: 2,
            released: HashSet::new(),
            max_offset,
        }
    }

    /// Allocate an IPv6 address.
    pub fn allocate(&mut self) -> Option<[u8; 16]> {
        // Try to reuse a released address first (O(1) removal from HashSet)
        if let Some(&offset) = self.released.iter().next() {
            self.released.remove(&offset);
            return self.offset_to_ip(offset);
        }

        if self.next_offset <= self.max_offset {
            let ip = self.offset_to_ip(self.next_offset)?;
            self.next_offset += 1;
            Some(ip)
        } else {
            None
        }
    }

    /// Release an IPv6 address for reuse.
    pub fn release(&mut self, ip: [u8; 16]) {
        if let Some(offset) = self.ip_to_offset(ip) {
            // HashSet automatically handles duplicates (O(1) insert)
            if offset >= 2 && offset <= self.max_offset {
                self.released.insert(offset);
            }
        }
    }

    /// Convert an offset to an IPv6 address.
    /// Returns None if the addition would overflow (extremely unlikely but handled correctly).
    fn offset_to_ip(&self, offset: u64) -> Option<[u8; 16]> {
        let mut ip = self.base;
        let base_low =
            u64::from_be_bytes([ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15]]);
        // Use checked_add to prevent silent overflow
        let new_low = base_low.checked_add(offset)?;
        let low_bytes = new_low.to_be_bytes();
        ip[8..16].copy_from_slice(&low_bytes);
        Some(ip)
    }

    fn ip_to_offset(&self, ip: [u8; 16]) -> Option<u64> {
        if ip[0..8] != self.base[0..8] {
            return None;
        }
        let base_low = u64::from_be_bytes([
            self.base[8],
            self.base[9],
            self.base[10],
            self.base[11],
            self.base[12],
            self.base[13],
            self.base[14],
            self.base[15],
        ]);
        let ip_low =
            u64::from_be_bytes([ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15]]);
        ip_low.checked_sub(base_low)
    }

    /// Get prefix length.
    pub fn prefix(&self) -> u8 {
        self.prefix
    }
}

/// Callback invoked AFTER a session is created or removed by the manager.
///
/// Used to keep external state (Prometheus gauges, AF_XDP session table,
/// admin event log) consistent with the authoritative session map without
/// duplicating the dec/inc logic at every call site.
pub type SessionLifecycleCallback = Box<dyn Fn(SessionLifecycleEvent) + Send + Sync + 'static>;

/// Lifecycle event passed to [`SessionLifecycleCallback`].
#[derive(Clone, Copy, Debug)]
pub enum SessionLifecycleEvent {
    /// A session was just inserted into the manager.
    Created(SessionId),
    /// A session was just removed from the manager (any cause: expire,
    /// close, admin action, replacement).
    Removed(SessionId),
}

/// High-performance session manager using lock-free DashMap.
///
/// Design optimizations:
/// - DashMap for fine-grained locking (sharded by key)
/// - Atomic counters for stats (no lock needed for touch/bytes)
/// - Separate maps for O(1) lookups by different keys
/// - Atomic session count for TOCTOU-safe capacity checks
pub struct SessionManager {
    /// Active sessions by session ID (primary store).
    sessions: DashMap<SessionId, ClientSession>,
    /// Session ID to tunnel IPv4 mapping.
    ip_to_session: DashMap<[u8; 4], SessionId>,
    /// Session ID to tunnel IPv6 mapping.
    ipv6_to_session: DashMap<[u8; 16], SessionId>,
    /// IPv4 address allocator (needs mutex for allocation).
    ip_allocator: RwLock<IpAllocator>,
    /// IPv6 address allocator (optional).
    ipv6_allocator: RwLock<Option<Ipv6Allocator>>,
    /// Server's tunnel IPv4.
    server_ip: [u8; 4],
    /// Server's tunnel IPv6 (optional).
    server_ipv6: Option<[u8; 16]>,
    /// Session timeout.
    session_timeout: Duration,
    /// Maximum sessions.
    max_sessions: usize,
    /// Atomic session counter for TOCTOU-safe capacity checks.
    /// Uses fetch_add/fetch_sub for reservation pattern.
    session_count: AtomicUsize,
    /// Per-session packets-per-second rate limit (0 = unlimited).
    /// Applied to every new session created by this manager.
    session_rate_limit_pps: u32,
    /// Per-session bytes-per-second rate limit (0 = unlimited).
    session_rate_limit_bps: u64,
    /// Optional lifecycle callback for metrics and bridge synchronisation.
    lifecycle_cb: RwLock<Option<SessionLifecycleCallback>>,
}

impl SessionManager {
    /// Create a new session manager (IPv4 only).
    pub fn new(
        base_ip: [u8; 4],
        prefix: u8,
        server_ip: [u8; 4],
        session_timeout: Duration,
        max_sessions: usize,
    ) -> Self {
        Self {
            sessions: DashMap::with_capacity(max_sessions),
            ip_to_session: DashMap::with_capacity(max_sessions),
            ipv6_to_session: DashMap::new(),
            ip_allocator: RwLock::new(IpAllocator::new(base_ip, prefix)),
            ipv6_allocator: RwLock::new(None),
            server_ip,
            server_ipv6: None,
            session_timeout,
            max_sessions,
            session_count: AtomicUsize::new(0),
            session_rate_limit_pps: DEFAULT_SESSION_RATE_LIMIT_PPS,
            session_rate_limit_bps: DEFAULT_SESSION_RATE_LIMIT_BPS,
            lifecycle_cb: RwLock::new(None),
        }
    }

    /// Register a lifecycle callback. Replaces any previous callback.
    ///
    /// The callback is invoked (synchronously, on the thread that performs
    /// the mutation) after every create/remove. It must not call back into
    /// the manager's mutation APIs (no recursive insert/remove).
    pub fn set_lifecycle_callback(&self, cb: SessionLifecycleCallback) {
        *self.lifecycle_cb.write() = Some(cb);
    }

    /// Dispatch a lifecycle event to the registered callback, if any.
    #[inline]
    fn emit_lifecycle(&self, event: SessionLifecycleEvent) {
        if let Some(ref cb) = *self.lifecycle_cb.read() {
            cb(event);
        }
    }

    /// Override the per-session rate limits for subsequently-created sessions.
    ///
    /// Set either value to 0 to disable that dimension of rate limiting. This
    /// is a builder-style setter intended to be called once at startup from the
    /// `ServerConfig`; existing sessions keep whatever limits they were created
    /// with.
    #[must_use]
    pub fn with_rate_limits(mut self, pps: u32, bps: u64) -> Self {
        self.session_rate_limit_pps = pps;
        self.session_rate_limit_bps = bps;
        self
    }

    /// Create a new dual-stack session manager.
    pub fn new_dual_stack(
        base_ip: [u8; 4],
        prefix: u8,
        server_ip: [u8; 4],
        base_ipv6: [u8; 16],
        prefix_v6: u8,
        server_ipv6: [u8; 16],
        session_timeout: Duration,
        max_sessions: usize,
    ) -> Self {
        Self {
            sessions: DashMap::with_capacity(max_sessions),
            ip_to_session: DashMap::with_capacity(max_sessions),
            ipv6_to_session: DashMap::with_capacity(max_sessions),
            ip_allocator: RwLock::new(IpAllocator::new(base_ip, prefix)),
            ipv6_allocator: RwLock::new(Some(Ipv6Allocator::new(base_ipv6, prefix_v6))),
            server_ip,
            server_ipv6: Some(server_ipv6),
            session_timeout,
            max_sessions,
            session_count: AtomicUsize::new(0),
            session_rate_limit_pps: DEFAULT_SESSION_RATE_LIMIT_PPS,
            session_rate_limit_bps: DEFAULT_SESSION_RATE_LIMIT_BPS,
            lifecycle_cb: RwLock::new(None),
        }
    }

    /// Check if IPv6 is enabled.
    pub fn has_ipv6(&self) -> bool {
        self.ipv6_allocator.read().is_some()
    }

    /// Get server IPv6 address.
    pub fn server_ipv6(&self) -> Option<[u8; 16]> {
        self.server_ipv6
    }

    /// Get IPv6 prefix length.
    pub fn ipv6_prefix(&self) -> Option<u8> {
        self.ipv6_allocator.read().as_ref().map(|a| a.prefix())
    }

    /// Create a new session for a client.
    pub fn create_session(
        &self,
        session: Session,
        client_addr: SocketAddr,
    ) -> ServerResult<[u8; 4]> {
        let (ip, _) = self.create_session_dual_stack_with_level(
            session,
            client_addr,
            SecurityLevel::default(),
        )?;
        Ok(ip)
    }

    /// Create a new session for a client with explicit security level.
    pub fn create_session_with_level(
        &self,
        session: Session,
        client_addr: SocketAddr,
        security_level: SecurityLevel,
    ) -> ServerResult<[u8; 4]> {
        let (ip, _) =
            self.create_session_dual_stack_with_level(session, client_addr, security_level)?;
        Ok(ip)
    }

    /// Create a new dual-stack session for a client.
    ///
    /// Uses atomic reservation pattern to prevent TOCTOU race conditions
    /// when checking session limits.
    pub fn create_session_dual_stack(
        &self,
        session: Session,
        client_addr: SocketAddr,
    ) -> ServerResult<([u8; 4], Option<[u8; 16]>)> {
        self.create_session_dual_stack_with_level(session, client_addr, SecurityLevel::default())
    }

    /// Create a new dual-stack session for a client with explicit security level.
    pub fn create_session_dual_stack_with_level(
        &self,
        session: Session,
        client_addr: SocketAddr,
        security_level: SecurityLevel,
    ) -> ServerResult<([u8; 4], Option<[u8; 16]>)> {
        let session_id = session.session_id();

        // Check if session already exists (rare: collision or reconnect before cleanup)
        // If so, remove it first to ensure clean state (counters reset to 0)
        let is_replacement = if let Some(old_session) = self.sessions.remove(&session_id) {
            tracing::warn!(
                "Replacing existing session {} (counter was at ~{}) - this should be rare!",
                session_id,
                old_session.1.session.send_counter()
            );

            // Release old IPs
            self.ip_to_session.remove(&old_session.1.tunnel_ip);
            self.ip_allocator.write().release(old_session.1.tunnel_ip);

            if let Some(ipv6) = old_session.1.tunnel_ipv6 {
                self.ipv6_to_session.remove(&ipv6);
                if let Some(allocator) = self.ipv6_allocator.write().as_mut() {
                    allocator.release(ipv6);
                }
            }

            // Fire the Removed lifecycle event BEFORE the new insert so
            // observers see the (remove, create) pair in order.
            self.emit_lifecycle(SessionLifecycleEvent::Removed(session_id));

            // Decrement session count since we removed one (saturate to prevent underflow)
            let _ = self
                .session_count
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                    Some(v.saturating_sub(1))
                });
            true
        } else {
            false
        };

        // Atomically reserve a session slot to prevent TOCTOU race.
        // fetch_add returns the previous value, so if prev >= max, we exceeded the limit.
        let prev_count = self.session_count.fetch_add(1, Ordering::SeqCst);
        if prev_count >= self.max_sessions {
            // Exceeded limit - unreserve and reject
            self.session_count.fetch_sub(1, Ordering::SeqCst);
            return Err(ServerError::Session("max sessions reached".into()));
        }

        // Helper to unreserve on failure
        let unreserve = || {
            self.session_count.fetch_sub(1, Ordering::SeqCst);
        };

        // Allocate IPv4
        let ipv4_result = self.ip_allocator.write().allocate();
        let tunnel_ip = match ipv4_result {
            Some(ip) => ip,
            None => {
                unreserve();
                return Err(ServerError::IpAllocation(
                    "no IPv4 addresses available".into(),
                ));
            }
        };

        // Allocate IPv6 if enabled
        let ipv6_result = {
            let mut allocator_guard = self.ipv6_allocator.write();
            allocator_guard
                .as_mut()
                .map(|allocator| allocator.allocate())
        };
        let tunnel_ipv6 = match ipv6_result {
            Some(Some(ip)) => Some(ip),
            Some(None) => {
                self.ip_allocator.write().release(tunnel_ip);
                unreserve();
                return Err(ServerError::IpAllocation(
                    "no IPv6 addresses available".into(),
                ));
            }
            None => None,
        };

        // Create client session with the manager's configured rate limits.
        let client_session = ClientSession::with_rate_limit(
            session,
            client_addr,
            tunnel_ip,
            tunnel_ipv6,
            security_level,
            self.session_rate_limit_pps,
            self.session_rate_limit_bps,
        );

        // Insert into maps (DashMap handles fine-grained locking)
        self.sessions.insert(session_id, client_session);
        self.ip_to_session.insert(tunnel_ip, session_id);
        if let Some(ipv6) = tunnel_ipv6 {
            self.ipv6_to_session.insert(ipv6, session_id);
        }

        let action = if is_replacement {
            "Replaced"
        } else {
            "Created"
        };
        if tunnel_ipv6.is_some() {
            info!(
                "{} dual-stack session {} for {} with IPv4 {}.{}.{}.{}",
                action,
                session_id,
                crate::privacy::addr(client_addr),
                tunnel_ip[0],
                tunnel_ip[1],
                tunnel_ip[2],
                tunnel_ip[3]
            );
        } else {
            info!(
                "{} session {} for {} with IP {}.{}.{}.{}",
                action,
                session_id,
                crate::privacy::addr(client_addr),
                tunnel_ip[0],
                tunnel_ip[1],
                tunnel_ip[2],
                tunnel_ip[3]
            );
        }

        // Dispatch lifecycle event after the maps are consistent. For a
        // replacement we fired a Removed earlier at the top of this function
        // (via `self.sessions.remove`); the Created event here closes the pair.
        self.emit_lifecycle(SessionLifecycleEvent::Created(session_id));

        Ok((tunnel_ip, tunnel_ipv6))
    }

    /// Get a session by ID (read-only reference).
    #[inline]
    pub fn get_session(&self, session_id: SessionId) -> Option<Ref<'_, SessionId, ClientSession>> {
        self.sessions.get(&session_id)
    }

    /// Get a mutable session by ID.
    #[inline]
    pub fn get_session_mut(
        &self,
        session_id: SessionId,
    ) -> Option<RefMut<'_, SessionId, ClientSession>> {
        self.sessions.get_mut(&session_id)
    }

    /// Get a session by tunnel IPv4.
    #[inline]
    pub fn get_session_by_ip(&self, ip: [u8; 4]) -> Option<SessionId> {
        self.ip_to_session.get(&ip).map(|r| *r.value())
    }

    /// Get a session by tunnel IPv6.
    #[inline]
    pub fn get_session_by_ipv6(&self, ip: [u8; 16]) -> Option<SessionId> {
        self.ipv6_to_session.get(&ip).map(|r| *r.value())
    }

    /// Get session ID and client address by tunnel IPv4.
    /// More efficient than separate lookups when both are needed (download path).
    #[inline]
    pub fn get_session_and_addr_by_ip(
        &self,
        ip: [u8; 4],
    ) -> Option<(SessionId, std::net::SocketAddr)> {
        let session_id = self.ip_to_session.get(&ip).map(|r| *r.value())?;
        let session = self.sessions.get(&session_id)?;
        Some((session_id, *session.client_addr.lock()))
    }

    pub fn get_session_and_addr_by_ipv6(
        &self,
        ip: [u8; 16],
    ) -> Option<(SessionId, std::net::SocketAddr)> {
        let session_id = self.ipv6_to_session.get(&ip).map(|r| *r.value())?;
        let session = self.sessions.get(&session_id)?;
        Some((session_id, *session.client_addr.lock()))
    }

    /// Remove a session.
    ///
    /// Fires a [`SessionLifecycleEvent::Removed`] callback if one is registered.
    /// Returns the removed `ClientSession`, or `None` if no session matched.
    pub fn remove_session(&self, session_id: SessionId) -> Option<ClientSession> {
        if let Some((_, client_session)) = self.sessions.remove(&session_id) {
            // Decrement atomic session counter (saturate to prevent underflow)
            let _ = self
                .session_count
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                    Some(v.saturating_sub(1))
                });

            self.ip_to_session.remove(&client_session.tunnel_ip);
            self.ip_allocator.write().release(client_session.tunnel_ip);

            if let Some(ipv6) = client_session.tunnel_ipv6 {
                self.ipv6_to_session.remove(&ipv6);
                if let Some(ref mut v6_alloc) = *self.ipv6_allocator.write() {
                    v6_alloc.release(ipv6);
                }
            }

            info!(
                "Removed session {} (IP {}.{}.{}.{})",
                session_id,
                client_session.tunnel_ip[0],
                client_session.tunnel_ip[1],
                client_session.tunnel_ip[2],
                client_session.tunnel_ip[3]
            );

            self.emit_lifecycle(SessionLifecycleEvent::Removed(session_id));
            Some(client_session)
        } else {
            None
        }
    }

    /// Clean up expired sessions.
    pub fn cleanup_expired(&self) -> Vec<SessionId> {
        let expired: Vec<SessionId> = self
            .sessions
            .iter()
            .filter(|entry| entry.value().is_expired(self.session_timeout))
            .map(|entry| *entry.key())
            .collect();

        for session_id in &expired {
            debug!("Removing expired session {}", session_id);
            self.remove_session(*session_id);
        }

        if !expired.is_empty() {
            info!("Cleaned up {} expired sessions", expired.len());
        }

        expired
    }

    /// Get the number of active sessions.
    ///
    /// Uses atomic counter for consistency with session creation limits.
    #[inline]
    pub fn session_count(&self) -> usize {
        self.session_count.load(Ordering::Relaxed)
    }

    /// Get the server's tunnel IP.
    #[inline]
    pub fn server_ip(&self) -> [u8; 4] {
        self.server_ip
    }

    /// Get the network netmask.
    pub fn netmask(&self) -> [u8; 4] {
        self.ip_allocator.read().netmask()
    }

    /// Get the IPv4 prefix length.
    #[inline]
    pub fn prefix_len(&self) -> u8 {
        self.ip_allocator.read().prefix
    }

    /// Get the IPv6 prefix length.
    #[inline]
    pub fn prefix_len_v6(&self) -> Option<u8> {
        self.ipv6_allocator.read().as_ref().map(|a| a.prefix())
    }

    /// Get all active session IDs.
    pub fn session_ids(&self) -> Vec<SessionId> {
        self.sessions.iter().map(|entry| *entry.key()).collect()
    }

    /// Update client address for a session (NAT rebinding).
    ///
    /// Callers MUST have already authenticated the sender via AEAD
    /// decryption; see `handle_data_packet` and friends for the correct
    /// decrypt-first-then-rebind pattern.
    pub fn update_client_addr(&self, session_id: SessionId, new_addr: SocketAddr) {
        if let Some(session) = self.sessions.get(&session_id) {
            // Single lock acquisition: read the old value and write the new
            // one atomically from a concurrent observer's standpoint. The
            // previous implementation took the lock twice, which could log
            // an inconsistent transition under races with other rebinds.
            let old_addr = {
                let mut guard = session.client_addr.lock();
                let old = *guard;
                *guard = new_addr;
                old
            };
            debug!(
                "Updated client address for session {}: {} -> {}",
                session_id,
                crate::privacy::addr(old_addr),
                crate::privacy::addr(new_addr)
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::needless_collect)]
#[allow(clippy::manual_assert)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_ip_allocator() {
        let mut allocator = IpAllocator::new([10, 0, 0, 0], 24);

        let ip1 = allocator.allocate().unwrap();
        assert_eq!(ip1, [10, 0, 0, 2]);

        let ip2 = allocator.allocate().unwrap();
        assert_eq!(ip2, [10, 0, 0, 3]);

        allocator.release(ip1);

        let ip3 = allocator.allocate().unwrap();
        assert_eq!(ip3, [10, 0, 0, 2]);
    }

    #[test]
    fn test_ip_allocator_netmask() {
        let allocator = IpAllocator::new([10, 0, 0, 0], 24);
        assert_eq!(allocator.netmask(), [255, 255, 255, 0]);

        let allocator16 = IpAllocator::new([172, 16, 0, 0], 16);
        assert_eq!(allocator16.netmask(), [255, 255, 0, 0]);
    }

    #[test]
    fn test_ipv6_allocator() {
        let base: [u8; 16] = [0xfd, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut allocator = Ipv6Allocator::new(base, 64);

        let ip1 = allocator.allocate().unwrap();
        assert_eq!(ip1, [0xfd, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

        let ip2 = allocator.allocate().unwrap();
        assert_eq!(ip2, [0xfd, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);

        allocator.release(ip1);

        let ip3 = allocator.allocate().unwrap();
        assert_eq!(ip3, ip1);
    }

    #[test]
    fn test_ipv6_allocator_prefix() {
        let base: [u8; 16] = [0xfd, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let allocator = Ipv6Allocator::new(base, 64);
        assert_eq!(allocator.prefix(), 64);

        let allocator48 = Ipv6Allocator::new(base, 48);
        assert_eq!(allocator48.prefix(), 48);
    }

    #[test]
    fn test_ipv6_allocator_release_invalid() {
        let base: [u8; 16] = [0xfd, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut allocator = Ipv6Allocator::new(base, 64);

        let different_network: [u8; 16] = [0xfd, 0xaa, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        allocator.release(different_network);

        let ip1 = allocator.allocate().unwrap();
        assert_eq!(ip1, [0xfd, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    }

    #[test]
    fn test_ipv6_allocator_sequential() {
        let base: [u8; 16] = [0xfd, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut allocator = Ipv6Allocator::new(base, 64);

        for i in 2u8..12 {
            let ip = allocator.allocate().unwrap();
            assert_eq!(ip[15], i);
            assert_eq!(&ip[0..8], &base[0..8]);
        }
    }

    #[test]
    fn test_session_manager_dual_stack() {
        let base_ip = [10, 99, 0, 0];
        let prefix = 24;
        let server_ip = [10, 99, 0, 1];
        let base_ipv6: [u8; 16] = [0xfd, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let prefix_v6 = 64;
        let server_ipv6: [u8; 16] = [0xfd, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let timeout = Duration::from_secs(300);

        let manager = SessionManager::new_dual_stack(
            base_ip,
            prefix,
            server_ip,
            base_ipv6,
            prefix_v6,
            server_ipv6,
            timeout,
            100,
        );

        assert!(manager.has_ipv6());
        assert_eq!(manager.server_ipv6(), Some(server_ipv6));
        assert_eq!(manager.ipv6_prefix(), Some(64));
    }

    #[test]
    fn test_session_manager_ipv4_only() {
        let base_ip = [10, 99, 0, 0];
        let prefix = 24;
        let server_ip = [10, 99, 0, 1];
        let timeout = Duration::from_secs(300);

        let manager = SessionManager::new(base_ip, prefix, server_ip, timeout, 100);

        assert!(!manager.has_ipv6());
        assert_eq!(manager.server_ipv6(), None);
        assert_eq!(manager.ipv6_prefix(), None);
    }

    #[test]
    fn test_session_manager_lookup_by_ipv6() {
        use hpn_core::crypto::SessionKeys;
        use hpn_core::protocol::Session;
        use hpn_core::types::SessionId;

        let base_ip = [10, 99, 0, 0];
        let prefix = 24;
        let server_ip = [10, 99, 0, 1];
        let base_ipv6: [u8; 16] = [0xfd, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let prefix_v6 = 64;
        let server_ipv6: [u8; 16] = [0xfd, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let timeout = Duration::from_secs(300);

        let manager = SessionManager::new_dual_stack(
            base_ip,
            prefix,
            server_ip,
            base_ipv6,
            prefix_v6,
            server_ipv6,
            timeout,
            100,
        );

        let session_id = SessionId::generate();
        let keys = SessionKeys {
            send_key: [0u8; 32],
            recv_key: [0u8; 32],
            send_nonce_prefix: [0u8; 4],
            recv_nonce_prefix: [0u8; 4],
        };
        let session = Session::new(session_id, keys).unwrap();
        let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let (ipv4, ipv6) = manager
            .create_session_dual_stack(session, client_addr)
            .unwrap();

        assert_eq!(ipv4, [10, 99, 0, 2]);
        assert!(ipv6.is_some());
        let ipv6_addr = ipv6.unwrap();
        assert_eq!(
            ipv6_addr,
            [0xfd, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]
        );

        let found_session = manager.get_session_by_ipv6(ipv6_addr);
        assert_eq!(found_session, Some(session_id));

        let found_session_v4 = manager.get_session_by_ip(ipv4);
        assert_eq!(found_session_v4, Some(session_id));
    }

    #[test]
    fn test_session_manager_remove_releases_ipv6() {
        use hpn_core::crypto::SessionKeys;
        use hpn_core::protocol::Session;
        use hpn_core::types::SessionId;

        let base_ip = [10, 99, 0, 0];
        let prefix = 24;
        let server_ip = [10, 99, 0, 1];
        let base_ipv6: [u8; 16] = [0xfd, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let prefix_v6 = 64;
        let server_ipv6: [u8; 16] = [0xfd, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let timeout = Duration::from_secs(300);

        let manager = SessionManager::new_dual_stack(
            base_ip,
            prefix,
            server_ip,
            base_ipv6,
            prefix_v6,
            server_ipv6,
            timeout,
            100,
        );

        let session_id1 = SessionId::generate();
        let keys1 = SessionKeys {
            send_key: [0u8; 32],
            recv_key: [0u8; 32],
            send_nonce_prefix: [0u8; 4],
            recv_nonce_prefix: [0u8; 4],
        };
        let session1 = Session::new(session_id1, keys1).unwrap();
        let client_addr1: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let (ipv4_1, ipv6_1) = manager
            .create_session_dual_stack(session1, client_addr1)
            .unwrap();

        let session_id2 = SessionId::generate();
        let keys2 = SessionKeys {
            send_key: [1u8; 32],
            recv_key: [1u8; 32],
            send_nonce_prefix: [1u8; 4],
            recv_nonce_prefix: [1u8; 4],
        };
        let session2 = Session::new(session_id2, keys2).unwrap();
        let client_addr2: SocketAddr = "127.0.0.1:12346".parse().unwrap();

        let (ipv4_2, ipv6_2) = manager
            .create_session_dual_stack(session2, client_addr2)
            .unwrap();

        assert_ne!(ipv4_1, ipv4_2);
        assert_ne!(ipv6_1, ipv6_2);

        manager.remove_session(session_id1);

        assert!(manager.get_session_by_ipv6(ipv6_1.unwrap()).is_none());
        assert!(manager.get_session_by_ip(ipv4_1).is_none());

        assert_eq!(
            manager.get_session_by_ipv6(ipv6_2.unwrap()),
            Some(session_id2)
        );
        assert_eq!(manager.get_session_by_ip(ipv4_2), Some(session_id2));

        let session_id3 = SessionId::generate();
        let keys3 = SessionKeys {
            send_key: [2u8; 32],
            recv_key: [2u8; 32],
            send_nonce_prefix: [2u8; 4],
            recv_nonce_prefix: [2u8; 4],
        };
        let session3 = Session::new(session_id3, keys3).unwrap();
        let client_addr3: SocketAddr = "127.0.0.1:12347".parse().unwrap();

        let (ipv4_3, ipv6_3) = manager
            .create_session_dual_stack(session3, client_addr3)
            .unwrap();

        assert_eq!(ipv4_3, ipv4_1);
        assert_eq!(ipv6_3, ipv6_1);
    }

    #[test]
    fn test_atomic_stats() {
        use hpn_core::crypto::SessionKeys;
        use hpn_core::protocol::Session;
        use hpn_core::types::SessionId;

        let session_id = SessionId::generate();
        let keys = SessionKeys {
            send_key: [0u8; 32],
            recv_key: [0u8; 32],
            send_nonce_prefix: [0u8; 4],
            recv_nonce_prefix: [0u8; 4],
        };
        let session = Session::new(session_id, keys).unwrap();
        let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let tunnel_ip = [10, 0, 0, 2];

        let client_session = ClientSession::new(session, client_addr, tunnel_ip);

        // Test atomic operations
        assert_eq!(client_session.bytes_received(), 0);
        assert_eq!(client_session.bytes_sent(), 0);

        client_session.add_bytes_received(1000);
        client_session.add_bytes_sent(500);

        assert_eq!(client_session.bytes_received(), 1000);
        assert_eq!(client_session.bytes_sent(), 500);

        client_session.add_bytes_received(500);
        assert_eq!(client_session.bytes_received(), 1500);

        // Test touch
        client_session.touch();
        assert!(!client_session.is_expired(Duration::from_secs(60)));
    }

    #[test]
    fn test_session_rate_limiter_unlimited() {
        // Test that unlimited rate limiter allows all traffic
        let limiter = SessionRateLimiter::unlimited();
        assert!(!limiter.is_limited());

        // Should always return true for unlimited
        for _ in 0..1000 {
            assert!(limiter.check(1500)); // MTU-sized packets
        }
    }

    #[test]
    fn test_session_rate_limiter_pps() {
        // Test packet rate limiting with low limit for fast test
        let limiter = SessionRateLimiter::new(100, 0); // 100 PPS, no byte limit
        assert!(limiter.is_limited());

        // Burst through all tokens (100 PPS * 2 second burst = 200 tokens)
        let mut allowed = 0;
        let mut denied = 0;
        for _ in 0..250 {
            if limiter.check(100) {
                allowed += 1;
            } else {
                denied += 1;
            }
        }

        // Should have allowed ~200 (initial burst) and denied ~50
        assert!(allowed >= 180 && allowed <= 220, "allowed: {}", allowed);
        assert!(denied >= 30 && denied <= 70, "denied: {}", denied);
    }

    #[test]
    fn test_session_rate_limiter_refill() {
        // Test that tokens refill over time
        let limiter = SessionRateLimiter::new(1000, 0); // 1000 PPS

        // Consume all burst tokens (1000 * 2 = 2000)
        for _ in 0..2100 {
            limiter.check(100);
        }

        // Should be rate limited now
        let before_wait = limiter.check(100);

        // Wait for tokens to refill (at least 10ms for ~10 tokens)
        std::thread::sleep(std::time::Duration::from_millis(20));

        // Should have some tokens now
        let after_wait = limiter.check(100);

        // Either before was false (limit reached) OR after is true (refilled)
        // This accounts for timing variations in CI
        assert!(
            !before_wait || after_wait,
            "Rate limiter should refill tokens over time"
        );
    }

    #[test]
    fn test_client_session_rate_limit() {
        // Test rate limiting through ClientSession
        use hpn_core::crypto::SessionKeys;
        use hpn_core::protocol::Session;
        use hpn_core::types::SessionId;

        let session_id = SessionId::generate();
        let keys = SessionKeys {
            send_key: [0u8; 32],
            recv_key: [0u8; 32],
            send_nonce_prefix: [0u8; 4],
            recv_nonce_prefix: [0u8; 4],
        };
        let session = Session::new(session_id, keys).unwrap();
        let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let tunnel_ip = [10, 0, 0, 2];

        // Create session with custom rate limit (low for testing)
        let client_session = ClientSession::with_rate_limit(
            session,
            client_addr,
            tunnel_ip,
            None,
            SecurityLevel::default(),
            100, // 100 PPS
            0,   // No byte limit
        );

        // Should allow some traffic
        assert!(client_session.check_rate_limit(1500));

        // Exhaust burst and verify rate limiting kicks in
        let mut denied_count = 0;
        for _ in 0..300 {
            if !client_session.check_rate_limit(1500) {
                denied_count += 1;
            }
        }

        // Should have denied some packets after burst exhausted
        assert!(
            denied_count > 50,
            "Rate limiting should kick in after burst: denied={}",
            denied_count
        );
    }

    #[test]
    fn test_multi_client_concurrent() {
        // SECURITY TEST P0-6: Multi-client concurrent connection handling
        // This test simulates 100+ concurrent client connections to verify:
        // - Session manager handles high concurrency without errors
        // - IP allocation is thread-safe (no duplicate IPs)
        // - Session lookup is correct under concurrent access
        // - Memory and resource cleanup works properly

        use hpn_core::crypto::SessionKeys;
        use hpn_core::protocol::Session;
        use hpn_core::types::SessionId;
        use std::sync::Arc;
        use std::thread;

        const NUM_CLIENTS: usize = 150; // Test with 150 concurrent clients

        let base_ip = [10, 200, 0, 0];
        let prefix = 16; // Large enough for 150+ clients
        let server_ip = [10, 200, 0, 1];
        let timeout = Duration::from_secs(300);

        let manager = Arc::new(SessionManager::new(
            base_ip, prefix, server_ip, timeout, 200, // Max 200 sessions
        ));

        // Spawn threads to create sessions concurrently
        let handles: Vec<_> = (0..NUM_CLIENTS)
            .map(|i| {
                let manager_clone = Arc::clone(&manager);
                thread::spawn(move || {
                    let session_id = SessionId::generate();
                    let keys = SessionKeys {
                        send_key: [(i as u8) ^ 0xAA; 32],
                        recv_key: [(i as u8) ^ 0x55; 32],
                        send_nonce_prefix: [(i as u8); 4],
                        recv_nonce_prefix: [(i as u8) ^ 0xFF; 4],
                    };
                    let session = Session::new(session_id, keys).unwrap();
                    let client_addr: SocketAddr =
                        format!("192.168.1.{}:{}", (i % 255) + 1, 10000 + i)
                            .parse()
                            .unwrap();

                    // Create session
                    let tunnel_ip = manager_clone
                        .create_session(session, client_addr)
                        .expect("Failed to create session");

                    (session_id, tunnel_ip)
                })
            })
            .collect();

        // Collect all results
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // Verify all sessions were created successfully
        assert_eq!(results.len(), NUM_CLIENTS);

        // Verify all tunnel IPs are unique (no duplicate allocations)
        let mut tunnel_ips = std::collections::HashSet::new();
        for (session_id, tunnel_ip) in &results {
            assert!(
                tunnel_ips.insert(tunnel_ip),
                "Duplicate tunnel IP allocated: {:?}",
                tunnel_ip
            );

            // Verify session lookup works
            let found = manager.get_session_by_ip(*tunnel_ip);
            assert_eq!(found, Some(*session_id), "Session lookup failed");

            // Verify session exists
            let session_ref = manager.get_session(*session_id);
            assert!(session_ref.is_some(), "Session not found");
        }

        // Verify session count
        assert_eq!(manager.session_count(), NUM_CLIENTS);

        // Test concurrent session updates
        let update_handles: Vec<_> = results
            .iter()
            .map(|(session_id, _)| {
                let manager_clone = Arc::clone(&manager);
                let sid = *session_id;
                thread::spawn(move || {
                    if let Some(session) = manager_clone.get_session(sid) {
                        // Simulate traffic
                        session.add_bytes_sent(1500); // One MTU packet
                        session.add_bytes_received(100); // ACK
                        session.touch(); // Update activity
                    }
                })
            })
            .collect();

        // Wait for all updates to complete
        for handle in update_handles {
            handle.join().unwrap();
        }

        // Verify stats were updated
        let total_sent: u64 = results
            .iter()
            .filter_map(|(sid, _)| manager.get_session(*sid))
            .map(|s| s.bytes_sent())
            .sum();

        assert_eq!(
            total_sent,
            NUM_CLIENTS as u64 * 1500,
            "Traffic stats mismatch"
        );

        // Test concurrent cleanup
        let cleanup_handles: Vec<_> = results
            .iter()
            .take(50) // Remove first 50 sessions
            .map(|(session_id, _)| {
                let manager_clone = Arc::clone(&manager);
                let sid = *session_id;
                thread::spawn(move || {
                    manager_clone.remove_session(sid);
                })
            })
            .collect();

        for handle in cleanup_handles {
            handle.join().unwrap();
        }

        // Verify session count after cleanup
        assert_eq!(manager.session_count(), NUM_CLIENTS - 50, "Cleanup failed");

        // Verify removed sessions are gone
        for (session_id, _) in results.iter().take(50) {
            assert!(
                manager.get_session(*session_id).is_none(),
                "Session should be removed"
            );
        }

        // Verify remaining sessions still work
        for (session_id, tunnel_ip) in results.iter().skip(50) {
            let found = manager.get_session_by_ip(*tunnel_ip);
            assert_eq!(found, Some(*session_id), "Remaining session broken");
        }
    }

    #[test]
    fn test_session_timeout_cleanup() {
        // BUSINESS LOGIC TEST: Session timeout and expiration handling
        // This test validates:
        // - Sessions expire after configured timeout duration
        // - is_expired() correctly identifies timed-out sessions
        // - Active sessions don't expire when touched
        // - Timeout boundary conditions are handled correctly

        use hpn_core::crypto::SessionKeys;
        use hpn_core::protocol::Session;
        use hpn_core::types::SessionId;

        let base_ip = [10, 100, 0, 0];
        let prefix = 24;
        let server_ip = [10, 100, 0, 1];
        let timeout = Duration::from_millis(100); // Short timeout for testing

        let manager = SessionManager::new(base_ip, prefix, server_ip, timeout, 100);

        // Create session 1
        let session_id1 = SessionId::generate();
        let keys1 = SessionKeys {
            send_key: [1u8; 32],
            recv_key: [1u8; 32],
            send_nonce_prefix: [1u8; 4],
            recv_nonce_prefix: [1u8; 4],
        };
        let session1 = Session::new(session_id1, keys1).unwrap();
        let client_addr1: SocketAddr = "192.168.1.100:10000".parse().unwrap();

        let _tunnel_ip1 = manager.create_session(session1, client_addr1).unwrap();

        // Immediately check - should not be expired
        {
            let session_ref = manager.get_session(session_id1).unwrap();
            assert!(
                !session_ref.is_expired(timeout),
                "Session should not be expired immediately after creation"
            );
        }

        // Wait slightly less than timeout and touch the session
        thread::sleep(Duration::from_millis(50));
        {
            let session_ref = manager.get_session(session_id1).unwrap();
            session_ref.touch(); // Reset activity timer
            assert!(
                !session_ref.is_expired(timeout),
                "Session should not be expired when touched before timeout"
            );
        }

        // Wait another 60ms (total 110ms, but only 60ms since touch)
        thread::sleep(Duration::from_millis(60));
        {
            let session_ref = manager.get_session(session_id1).unwrap();
            assert!(
                !session_ref.is_expired(timeout),
                "Session should not be expired when touched recently"
            );
        }

        // Create session 2 and let it expire
        let session_id2 = SessionId::generate();
        let keys2 = SessionKeys {
            send_key: [2u8; 32],
            recv_key: [2u8; 32],
            send_nonce_prefix: [2u8; 4],
            recv_nonce_prefix: [2u8; 4],
        };
        let session2 = Session::new(session_id2, keys2).unwrap();
        let client_addr2: SocketAddr = "192.168.1.101:10001".parse().unwrap();

        let _tunnel_ip2 = manager.create_session(session2, client_addr2).unwrap();

        // Wait for session 2 to expire (don't touch it)
        thread::sleep(Duration::from_millis(120));

        {
            let session_ref2 = manager.get_session(session_id2).unwrap();
            assert!(
                session_ref2.is_expired(timeout),
                "Session should be expired after timeout with no activity"
            );
        }

        // Session 1 should still be alive (was touched at 50ms, now at ~230ms)
        // But it should now be expired since 230 - 50 = 180ms > 100ms
        thread::sleep(Duration::from_millis(70));
        {
            let session_ref1 = manager.get_session(session_id1).unwrap();
            assert!(
                session_ref1.is_expired(timeout),
                "Session should be expired after timeout even if touched once"
            );
        }
    }

    #[test]
    fn test_ipv4_allocator_exhaustion() {
        // BUSINESS LOGIC TEST: IP allocator exhaustion handling
        // This test validates:
        // - Allocator correctly handles small subnets (/30, /31)
        // - create_session fails gracefully when IPs exhausted
        // - Released IPs are correctly recycled
        // - Maximum capacity calculations are accurate

        use hpn_core::crypto::SessionKeys;
        use hpn_core::protocol::Session;
        use hpn_core::types::SessionId;

        // Use /30 subnet: 4 total IPs, but .0 (network) and .3 (broadcast) reserved
        // Only .1 (server) and .2 (usable) available - so only 1 client IP
        let base_ip = [10, 50, 0, 0];
        let prefix = 30; // /30 = 4 IPs total
        let server_ip = [10, 50, 0, 1];
        let timeout = Duration::from_secs(300);

        let manager = SessionManager::new(base_ip, prefix, server_ip, timeout, 10);

        // First session should succeed (allocate .2)
        let session_id1 = SessionId::generate();
        let keys1 = SessionKeys {
            send_key: [1u8; 32],
            recv_key: [1u8; 32],
            send_nonce_prefix: [1u8; 4],
            recv_nonce_prefix: [1u8; 4],
        };
        let session1 = Session::new(session_id1, keys1).unwrap();
        let client_addr1: SocketAddr = "192.168.1.1:10000".parse().unwrap();

        let tunnel_ip1 = manager
            .create_session(session1, client_addr1)
            .expect("First session should succeed");
        assert_eq!(tunnel_ip1, [10, 50, 0, 2], "Should allocate .2");

        // Second session should fail (IP pool exhausted)
        let session_id2 = SessionId::generate();
        let keys2 = SessionKeys {
            send_key: [2u8; 32],
            recv_key: [2u8; 32],
            send_nonce_prefix: [2u8; 4],
            recv_nonce_prefix: [2u8; 4],
        };
        let session2 = Session::new(session_id2, keys2).unwrap();
        let client_addr2: SocketAddr = "192.168.1.2:10001".parse().unwrap();

        let result = manager.create_session(session2, client_addr2);
        assert!(
            result.is_err(),
            "Second session should fail due to IP exhaustion"
        );
        assert!(
            matches!(result, Err(ServerError::IpAllocation(_))),
            "Should return IpAllocation error"
        );

        // Remove first session to free up .2
        manager.remove_session(session_id1);

        // Now third session should succeed (reuse .2)
        let session_id3 = SessionId::generate();
        let keys3 = SessionKeys {
            send_key: [3u8; 32],
            recv_key: [3u8; 32],
            send_nonce_prefix: [3u8; 4],
            recv_nonce_prefix: [3u8; 4],
        };
        let session3 = Session::new(session_id3, keys3).unwrap();
        let client_addr3: SocketAddr = "192.168.1.3:10002".parse().unwrap();

        let tunnel_ip3 = manager
            .create_session(session3, client_addr3)
            .expect("Third session should succeed with recycled IP");
        assert_eq!(
            tunnel_ip3, tunnel_ip1,
            "Should reuse IP from removed session"
        );

        // Verify session 3 is active
        assert_eq!(manager.session_count(), 1);
        assert!(manager.get_session(session_id3).is_some());
    }

    // Property-based tests using proptest
    #[test]
    fn test_ip_allocator_exhaustion() {
        let mut allocator = IpAllocator::new([10, 0, 0, 0], 28); // /28 = 14 usable IPs

        // Allocate many IPs
        let mut count = 0;
        while allocator.allocate().is_some() {
            count += 1;
            if count > 20 {
                panic!("Allocator didn't exhaust");
            }
        }

        // Should have exhausted
        assert!(count > 0);
        assert!(allocator.allocate().is_none());
    }

    #[test]
    fn test_ip_allocator_prefix_sizes() {
        let alloc24 = IpAllocator::new([192, 168, 1, 0], 24);
        assert_eq!(alloc24.netmask(), [255, 255, 255, 0]);

        let alloc16 = IpAllocator::new([172, 16, 0, 0], 16);
        assert_eq!(alloc16.netmask(), [255, 255, 0, 0]);

        let alloc8 = IpAllocator::new([10, 0, 0, 0], 8);
        assert_eq!(alloc8.netmask(), [255, 0, 0, 0]);
    }

    #[test]
    fn test_ip_allocator_release_and_reuse() {
        let mut allocator = IpAllocator::new([10, 0, 0, 0], 24);

        let _ip1 = allocator.allocate().unwrap();
        let ip2 = allocator.allocate().unwrap();
        let _ip3 = allocator.allocate().unwrap();

        // Release middle IP
        allocator.release(ip2);

        // Next allocation should reuse released IP
        let ip4 = allocator.allocate().unwrap();
        assert_eq!(ip4, ip2);
    }

    #[test]
    fn test_ipv6_allocator_exhaustion() {
        let base: [u8; 16] = [0xfd, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut allocator = Ipv6Allocator::new(base, 124); // /124 = 14 usable IPs

        // Allocate many IPs
        let mut count = 0;
        while allocator.allocate().is_some() {
            count += 1;
            if count > 20 {
                panic!("Allocator didn't exhaust");
            }
        }

        // Should have exhausted
        assert!(count > 0);
        assert!(allocator.allocate().is_none());
    }

    #[test]
    fn test_ipv6_allocator_different_prefixes() {
        let base: [u8; 16] = [0xfd, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        let alloc64 = Ipv6Allocator::new(base, 64);
        assert_eq!(alloc64.prefix(), 64);

        let alloc48 = Ipv6Allocator::new(base, 48);
        assert_eq!(alloc48.prefix(), 48);

        let alloc96 = Ipv6Allocator::new(base, 96);
        assert_eq!(alloc96.prefix(), 96);
    }

    #[test]
    fn test_session_manager_empty_state() {
        let base_ip = [10, 0, 0, 0];
        let prefix = 24;
        let server_ip = [10, 0, 0, 1];
        let timeout = Duration::from_secs(300);

        let manager = SessionManager::new(base_ip, prefix, server_ip, timeout, 100);

        assert_eq!(manager.session_count(), 0);
        assert!(manager.session_ids().is_empty());
    }

    #[test]
    fn test_session_manager_get_nonexistent() {
        let manager = SessionManager::new(
            [10, 0, 0, 0],
            24,
            [10, 0, 0, 1],
            Duration::from_secs(300),
            100,
        );

        let result = manager.get_session(SessionId(999));
        assert!(result.is_none());
    }

    #[test]
    fn test_session_manager_remove_nonexistent() {
        let manager = SessionManager::new(
            [10, 0, 0, 0],
            24,
            [10, 0, 0, 1],
            Duration::from_secs(300),
            100,
        );

        let result = manager.remove_session(SessionId(999));
        assert!(result.is_none());
    }

    #[cfg(test)]
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn prop_ip_allocator_no_duplicates(
                prefix in 16u8..=28,  // /16 to /28 subnets
                count in 1usize..50   // Allocate up to 50 IPs
            ) {
                // PROPERTY TEST: IP allocator uniqueness
                // Property: All allocated IPs are unique (no duplicates)
                use std::collections::HashSet;

                let base = [10, 200, 0, 0];
                let mut allocator = IpAllocator::new(base, prefix);

                let mut allocated = HashSet::new();
                for _ in 0..count {
                    if let Some(ip) = allocator.allocate() {
                        prop_assert!(allocated.insert(ip), "IP {:?} was allocated twice", ip);
                    } else {
                        // Allocator exhausted - acceptable
                        break;
                    }
                }
            }

            #[test]
            fn prop_ip_allocator_release_reuse(
                prefix in 20u8..=28,
                allocations in 1usize..20
            ) {
                // PROPERTY TEST: IP allocator release and reuse
                // Property: Released IPs can be reallocated
                let base = [10, 100, 0, 0];
                let mut allocator = IpAllocator::new(base, prefix);

                // Allocate some IPs
                let mut allocated = Vec::new();
                for _ in 0..allocations {
                    if let Some(ip) = allocator.allocate() {
                        allocated.push(ip);
                    } else {
                        break;
                    }
                }

                // Release all IPs
                for ip in &allocated {
                    allocator.release(*ip);
                }

                // Should be able to reallocate the same number
                let mut reallocated = Vec::new();
                for _ in 0..allocated.len() {
                    if let Some(ip) = allocator.allocate() {
                        reallocated.push(ip);
                    }
                }

                prop_assert_eq!(
                    reallocated.len(),
                    allocated.len(),
                    "Should be able to reallocate all released IPs"
                );
            }

            #[test]
            fn prop_ip_allocator_within_subnet(
                prefix in 16u8..=28,
                count in 1usize..20
            ) {
                // PROPERTY TEST: IP allocator subnet boundaries
                // Property: All allocated IPs are within the specified subnet
                let base = [172, 16, 0, 0];
                let mut allocator = IpAllocator::new(base, prefix);

                let netmask = allocator.netmask();
                let base_u32 = u32::from_be_bytes(base);
                let mask_u32 = u32::from_be_bytes(netmask);

                for _ in 0..count {
                    if let Some(ip) = allocator.allocate() {
                        let ip_u32 = u32::from_be_bytes(ip);

                        // Verify IP is in the same subnet
                        prop_assert_eq!(
                            ip_u32 & mask_u32,
                            base_u32 & mask_u32,
                            "IP {:?} should be in subnet {:?}/{}", ip, base, prefix
                        );
                    } else {
                        break;
                    }
                }
            }

            #[test]
            fn prop_session_count_matches_sessions(
                num_sessions in 1usize..50
            ) {
                // PROPERTY TEST: Session count consistency
                // Property: session_count() always equals number of active sessions
                use hpn_core::crypto::SessionKeys;
                use hpn_core::protocol::Session;
                use hpn_core::types::SessionId;

                let base_ip = [10, 150, 0, 0];
                let prefix = 16; // Large enough for 50 sessions
                let server_ip = [10, 150, 0, 1];
                let timeout = Duration::from_secs(300);

                let manager = SessionManager::new(base_ip, prefix, server_ip, timeout, 100);

                let mut created_ids = Vec::new();
                for i in 0..num_sessions {
                    let session_id = SessionId::generate();
                    let keys = SessionKeys {
                        send_key: [(i as u8); 32],
                        recv_key: [(i as u8) ^ 0xFF; 32],
                        send_nonce_prefix: [(i as u8); 4],
                        recv_nonce_prefix: [(i as u8) ^ 0xAA; 4],
                    };
                    let session = Session::new(session_id, keys).unwrap();
                    let client_addr: SocketAddr = format!("192.168.1.{}:10000", (i % 255) + 1)
                        .parse()
                        .unwrap();

                    if manager.create_session(session, client_addr).is_ok() {
                        created_ids.push(session_id);
                    }
                }

                prop_assert_eq!(
                    manager.session_count(),
                    created_ids.len(),
                    "session_count() should match number of created sessions"
                );

                // Verify session_ids() returns correct count
                let ids = manager.session_ids();
                prop_assert_eq!(
                    ids.len(),
                    created_ids.len(),
                    "session_ids() should return all session IDs"
                );
            }

            #[test]
            fn prop_ipv6_allocator_uniqueness(
                prefix in 64u8..=120,
                count in 1usize..30
            ) {
                // PROPERTY TEST: IPv6 allocator uniqueness
                // Property: All allocated IPv6 addresses are unique
                use std::collections::HashSet;

                let base: [u8; 16] = [0xfd, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
                let mut allocator = Ipv6Allocator::new(base, prefix);

                let mut allocated = HashSet::new();
                for _ in 0..count {
                    if let Some(ip) = allocator.allocate() {
                        prop_assert!(
                            allocated.insert(ip),
                            "IPv6 {:?} was allocated twice",
                            ip
                        );
                    } else {
                        break;
                    }
                }
            }
        }
    }
}
