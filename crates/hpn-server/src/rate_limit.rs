//! Rate limiting for handshake requests.
//!
//! Protects against DoS attacks by limiting the number of handshake
//! requests per IP address per time window.
//!
//! # IPv6 aggregation
//!
//! IPv6 addresses are normalised to their `/64` prefix before being used as a
//! rate-limit key. The reason is that routed IPv6 allocations at the hosting
//! layer are almost always `/64` or larger, so an attacker with a single
//! routed `/64` trivially has 2^64 distinct addresses to burn through the
//! per-IP token bucket. Aggregating to `/64` matches the real "customer"
//! granularity of IPv6 and closes that DoS vector without impacting
//! legitimate users (one residential prefix == one bucket).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

/// Normalise an `IpAddr` to the key used for rate-limit buckets.
///
/// * IPv4 — returned as-is (`/32`).
/// * IPv6 — masked to the `/64` prefix. The remaining 64 bits are zeroed so
///   every address inside the same routed `/64` maps to one bucket.
#[inline]
#[must_use]
fn rate_limit_key(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V4(_) => addr,
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            // Keep the top 64 bits (first four 16-bit segments), zero the rest.
            let masked = Ipv6Addr::new(
                segments[0],
                segments[1],
                segments[2],
                segments[3],
                0,
                0,
                0,
                0,
            );
            IpAddr::V6(masked)
        }
    }
}

/// Default maximum handshakes per IP per minute.
///
/// Conservative limit to prevent DoS amplification attacks.
/// At 5 handshakes/minute, an attacker can at most trigger:
///   - 5 responses * 6503 bytes = ~32 KB/min/IP
///   - With 1000 spoofed IPs = 32 MB/min amplification
///
/// This is a reasonable trade-off between DoS protection and allowing
/// legitimate clients to reconnect (e.g., network switches, roaming).
const DEFAULT_MAX_HANDSHAKES_PER_MINUTE: u32 = 5;

/// Window duration for rate limiting.
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

/// Cleanup interval for expired entries.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(300);

/// Maximum tracked IPs to prevent memory exhaustion from IP spoofing attacks.
/// At 100K IPs with ~24 bytes per entry, this uses ~2.4MB max.
const DEFAULT_MAX_TRACKED_IPS: usize = 100_000;

/// Rate limiter for handshake requests.
///
/// Tracks the number of handshake requests per IP address within a
/// sliding time window. If an IP exceeds the limit, further requests
/// are rejected until the window expires.
pub struct HandshakeRateLimiter {
    /// Map of IP addresses to (request count, window start time).
    requests: Mutex<HashMap<IpAddr, RateLimitEntry>>,
    /// Maximum requests allowed per window.
    max_per_window: u32,
    /// Window duration.
    window: Duration,
    /// Last cleanup time.
    last_cleanup: Mutex<Instant>,
    /// Maximum tracked IPs to prevent memory exhaustion.
    max_tracked_ips: usize,
}

/// Rate limit entry for a single IP.
#[derive(Clone, Copy)]
struct RateLimitEntry {
    /// Number of requests in current window.
    count: u32,
    /// Start of current window.
    window_start: Instant,
}

impl HandshakeRateLimiter {
    /// Create a new rate limiter with default settings.
    ///
    /// Default: 10 handshakes per minute per IP.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limit(DEFAULT_MAX_HANDSHAKES_PER_MINUTE)
    }

    /// Create a new rate limiter with a custom limit.
    ///
    /// # Arguments
    ///
    /// * `max_per_minute` - Maximum handshake requests per IP per minute.
    #[must_use]
    pub fn with_limit(max_per_minute: u32) -> Self {
        Self::with_limits(max_per_minute, DEFAULT_MAX_TRACKED_IPS)
    }

    /// Create a new rate limiter with custom limits.
    ///
    /// # Arguments
    ///
    /// * `max_per_minute` - Maximum handshake requests per IP per minute.
    /// * `max_tracked_ips` - Maximum number of IPs to track (DoS protection).
    #[must_use]
    pub fn with_limits(max_per_minute: u32, max_tracked_ips: usize) -> Self {
        Self {
            requests: Mutex::new(HashMap::new()),
            max_per_window: max_per_minute,
            window: RATE_LIMIT_WINDOW,
            last_cleanup: Mutex::new(Instant::now()),
            max_tracked_ips,
        }
    }

    /// Check if a request from the given IP should be allowed.
    ///
    /// If allowed, increments the request count for this IP.
    /// If not allowed (rate limited), returns `false`.
    ///
    /// # Arguments
    ///
    /// * `addr` - The IP address of the requester.
    ///
    /// # Returns
    ///
    /// `true` if the request is allowed, `false` if rate limited.
    pub fn allow(&self, addr: IpAddr) -> bool {
        let key = rate_limit_key(addr);
        let now = Instant::now();

        // Periodic cleanup of expired entries
        self.maybe_cleanup(now);

        let mut requests = self.requests.lock();

        // DoS protection: reject new IPs if at capacity (fail-closed)
        if !requests.contains_key(&key) && requests.len() >= self.max_tracked_ips {
            tracing::warn!(
                "Rate limiter at capacity ({} keys), rejecting new IP {}",
                self.max_tracked_ips,
                addr
            );
            return false;
        }

        let entry = requests.entry(key).or_insert(RateLimitEntry {
            count: 0,
            window_start: now,
        });

        // Check if window has expired
        if now.duration_since(entry.window_start) > self.window {
            // Reset window
            entry.count = 1;
            entry.window_start = now;
            return true;
        }

        // Check if limit exceeded
        if entry.count >= self.max_per_window {
            return false;
        }

        // Increment count and allow
        entry.count += 1;
        true
    }

    /// Check if an IP is currently rate limited without incrementing.
    ///
    /// # Arguments
    ///
    /// * `addr` - The IP address to check.
    ///
    /// # Returns
    ///
    /// `true` if the IP would be allowed, `false` if rate limited.
    #[must_use]
    pub fn check(&self, addr: IpAddr) -> bool {
        let key = rate_limit_key(addr);
        let now = Instant::now();
        let requests = self.requests.lock();

        match requests.get(&key) {
            None => true,
            Some(entry) => {
                // Window expired?
                if now.duration_since(entry.window_start) > self.window {
                    return true;
                }
                // Under limit?
                entry.count < self.max_per_window
            }
        }
    }

    /// Get the current request count for an IP.
    ///
    /// Returns 0 if the IP has no active window.
    #[must_use]
    pub fn get_count(&self, addr: IpAddr) -> u32 {
        let key = rate_limit_key(addr);
        let now = Instant::now();
        let requests = self.requests.lock();

        match requests.get(&key) {
            None => 0,
            Some(entry) => {
                if now.duration_since(entry.window_start) > self.window {
                    0
                } else {
                    entry.count
                }
            }
        }
    }

    /// Get the number of tracked IPs.
    #[must_use]
    pub fn tracked_ips(&self) -> usize {
        self.requests.lock().len()
    }

    /// Manually clean up expired entries.
    pub fn cleanup(&self) {
        let now = Instant::now();
        let mut requests = self.requests.lock();

        requests.retain(|_, entry| now.duration_since(entry.window_start) <= self.window);
    }

    /// Perform cleanup if enough time has passed since last cleanup.
    fn maybe_cleanup(&self, now: Instant) {
        let mut last_cleanup = self.last_cleanup.lock();

        if now.duration_since(*last_cleanup) > CLEANUP_INTERVAL {
            *last_cleanup = now;
            drop(last_cleanup);
            self.cleanup();
        }
    }

    /// Reset rate limit for a specific IP (for testing or admin override).
    pub fn reset(&self, addr: IpAddr) {
        let key = rate_limit_key(addr);
        self.requests.lock().remove(&key);
    }

    /// Clear all rate limit entries.
    pub fn clear(&self) {
        self.requests.lock().clear();
    }
}

impl Default for HandshakeRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::needless_collect)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_ip(last_octet: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, last_octet))
    }

    #[test]
    fn test_basic_rate_limiting() {
        let limiter = HandshakeRateLimiter::with_limit(3);
        let ip = test_ip(1);

        // First 3 requests should be allowed
        assert!(limiter.allow(ip));
        assert!(limiter.allow(ip));
        assert!(limiter.allow(ip));

        // 4th request should be rate limited
        assert!(!limiter.allow(ip));
        assert!(!limiter.allow(ip));
    }

    #[test]
    fn test_different_ips_independent() {
        let limiter = HandshakeRateLimiter::with_limit(2);
        let ip1 = test_ip(1);
        let ip2 = test_ip(2);

        // Both IPs should have independent limits
        assert!(limiter.allow(ip1));
        assert!(limiter.allow(ip1));
        assert!(!limiter.allow(ip1));

        // IP2 should still be allowed
        assert!(limiter.allow(ip2));
        assert!(limiter.allow(ip2));
        assert!(!limiter.allow(ip2));
    }

    #[test]
    fn test_check_without_increment() {
        let limiter = HandshakeRateLimiter::with_limit(2);
        let ip = test_ip(1);

        // Check should not increment
        assert!(limiter.check(ip));
        assert!(limiter.check(ip));
        assert_eq!(limiter.get_count(ip), 0);

        // Allow should increment
        assert!(limiter.allow(ip));
        assert_eq!(limiter.get_count(ip), 1);
    }

    #[test]
    fn test_reset() {
        let limiter = HandshakeRateLimiter::with_limit(2);
        let ip = test_ip(1);

        assert!(limiter.allow(ip));
        assert!(limiter.allow(ip));
        assert!(!limiter.allow(ip));

        // Reset should allow again
        limiter.reset(ip);
        assert!(limiter.allow(ip));
    }

    #[test]
    fn test_tracked_ips() {
        let limiter = HandshakeRateLimiter::with_limit(10);

        assert_eq!(limiter.tracked_ips(), 0);

        limiter.allow(test_ip(1));
        assert_eq!(limiter.tracked_ips(), 1);

        limiter.allow(test_ip(2));
        assert_eq!(limiter.tracked_ips(), 2);

        limiter.allow(test_ip(1)); // Same IP
        assert_eq!(limiter.tracked_ips(), 2);
    }

    #[test]
    fn test_clear() {
        let limiter = HandshakeRateLimiter::with_limit(10);

        limiter.allow(test_ip(1));
        limiter.allow(test_ip(2));
        assert_eq!(limiter.tracked_ips(), 2);

        limiter.clear();
        assert_eq!(limiter.tracked_ips(), 0);
    }

    #[test]
    fn test_default() {
        let limiter = HandshakeRateLimiter::default();
        let ip = test_ip(1);

        // Default is 5 per minute (DoS protection)
        for _ in 0..5 {
            assert!(limiter.allow(ip));
        }
        assert!(!limiter.allow(ip));
    }

    #[test]
    fn test_capacity_limit() {
        // Create limiter with small capacity for testing
        let limiter = HandshakeRateLimiter::with_limits(10, 3);

        // First 3 IPs should be tracked
        assert!(limiter.allow(test_ip(1)));
        assert!(limiter.allow(test_ip(2)));
        assert!(limiter.allow(test_ip(3)));
        assert_eq!(limiter.tracked_ips(), 3);

        // 4th IP should be rejected (capacity reached)
        assert!(!limiter.allow(test_ip(4)));
        assert_eq!(limiter.tracked_ips(), 3);

        // Existing IPs should still work
        assert!(limiter.allow(test_ip(1)));
        assert!(limiter.allow(test_ip(2)));

        // After clearing, new IPs can be added
        limiter.clear();
        assert!(limiter.allow(test_ip(100)));
    }

    #[test]
    fn test_rate_limit_burst_exceeded() {
        // BUSINESS LOGIC TEST: Rate limiting burst and concurrent access
        // This test validates:
        // - Burst capacity enforcement (exact limit boundary)
        // - Concurrent requests from same IP don't bypass limits
        // - Rate limit window reset behavior
        // - Thread-safe request counting under load

        use std::sync::Arc;
        use std::thread;

        const BURST_LIMIT: u32 = 10;
        const NUM_THREADS: usize = 5;
        const REQUESTS_PER_THREAD: usize = 4; // 5 * 4 = 20 total requests

        let limiter = Arc::new(HandshakeRateLimiter::with_limit(BURST_LIMIT));
        let test_addr = test_ip(42);

        // First burst should allow exactly BURST_LIMIT requests
        for i in 0..BURST_LIMIT {
            assert!(
                limiter.allow(test_addr),
                "Request {} should be allowed (within burst limit)",
                i
            );
        }

        // Next request should be rejected
        assert!(
            !limiter.allow(test_addr),
            "Request after burst limit should be rejected"
        );

        // Concurrent requests from same IP should all be rejected
        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|_| {
                let limiter_clone = Arc::clone(&limiter);
                thread::spawn(move || {
                    let mut allowed_count = 0;
                    for _ in 0..REQUESTS_PER_THREAD {
                        if limiter_clone.allow(test_addr) {
                            allowed_count += 1;
                        }
                    }
                    allowed_count
                })
            })
            .collect();

        let total_allowed: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();

        // All concurrent requests should be rejected (already at limit)
        assert_eq!(
            total_allowed, 0,
            "All concurrent requests should be rejected when at burst limit"
        );

        // Verify final count is still at the limit
        assert_eq!(
            limiter.get_count(test_addr),
            BURST_LIMIT,
            "Count should remain at burst limit"
        );

        // Reset and verify new requests allowed
        limiter.reset(test_addr);
        assert!(
            limiter.allow(test_addr),
            "After reset, requests should be allowed again"
        );
        assert_eq!(
            limiter.get_count(test_addr),
            1,
            "Count should be 1 after reset"
        );
    }

    #[test]
    fn test_max_tracked_ips_enforcement() {
        let limiter = HandshakeRateLimiter::with_limits(10, 3);

        // Fill up to capacity
        assert!(limiter.allow(test_ip(1)));
        assert!(limiter.allow(test_ip(2)));
        assert!(limiter.allow(test_ip(3)));
        assert_eq!(limiter.tracked_ips(), 3);

        // Next IP should be rejected (at capacity)
        assert!(!limiter.allow(test_ip(4)));
        assert_eq!(limiter.tracked_ips(), 3);
    }

    #[test]
    fn test_get_count_nonexistent_ip() {
        let limiter = HandshakeRateLimiter::new();
        let ip = test_ip(99);

        assert_eq!(limiter.get_count(ip), 0);
    }

    #[test]
    fn test_reset_nonexistent_ip() {
        let limiter = HandshakeRateLimiter::new();
        let ip = test_ip(99);

        // Reset on non-existent IP should be a no-op
        limiter.reset(ip);
        assert_eq!(limiter.tracked_ips(), 0);
    }

    #[test]
    fn test_check_nonexistent_ip() {
        let limiter = HandshakeRateLimiter::new();
        let ip = test_ip(99);

        // Non-existent IP should be allowed
        assert!(limiter.check(ip));
    }

    #[test]
    fn test_clear_all_entries() {
        let limiter = HandshakeRateLimiter::with_limit(5);

        // Add multiple IPs
        for i in 1..=10 {
            limiter.allow(test_ip(i));
        }
        assert_eq!(limiter.tracked_ips(), 10);

        // Clear all
        limiter.clear();
        assert_eq!(limiter.tracked_ips(), 0);

        // All IPs should be allowed again
        assert!(limiter.allow(test_ip(1)));
        assert_eq!(limiter.get_count(test_ip(1)), 1);
    }

    #[test]
    fn test_ipv6_addresses() {
        let limiter = HandshakeRateLimiter::with_limit(2);
        let ipv6 = IpAddr::V6("2001:db8::1".parse().unwrap());

        assert!(limiter.allow(ipv6));
        assert!(limiter.allow(ipv6));
        assert!(!limiter.allow(ipv6)); // Rate limited

        assert_eq!(limiter.get_count(ipv6), 2);
    }

    #[test]
    fn test_ipv6_slash64_aggregation() {
        // Any address inside the same /64 must share the bucket, otherwise a
        // routed /64 (common hosting allocation) lets an attacker burn the
        // per-IP limit trivially.
        let limiter = HandshakeRateLimiter::with_limit(3);
        let a: IpAddr = "2001:db8:1234:5678::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1234:5678::ffff".parse().unwrap();
        let c: IpAddr = "2001:db8:1234:5678:aaaa:bbbb:cccc:dddd".parse().unwrap();
        // Different /64 (last of third segment differs).
        let other: IpAddr = "2001:db8:1234:5679::1".parse().unwrap();

        assert!(limiter.allow(a));
        assert!(limiter.allow(b));
        assert!(limiter.allow(c));
        // Same /64, fourth request inside the bucket must be rejected.
        assert!(!limiter.allow(a));
        assert!(!limiter.allow(b));

        // Different /64 is tracked independently.
        assert!(limiter.allow(other));
        assert_eq!(limiter.get_count(other), 1);

        // Only two tracked buckets (the shared /64 and the other /64), despite
        // four distinct /128 addresses having been used.
        assert_eq!(limiter.tracked_ips(), 2);
    }

    #[test]
    fn test_rate_limit_key_normalisation() {
        // Direct check on the helper so refactors do not silently regress.
        let a: IpAddr = "2001:db8:1234:5678::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1234:5678:ffff:ffff:ffff:ffff".parse().unwrap();
        assert_eq!(rate_limit_key(a), rate_limit_key(b));

        let v4: IpAddr = "198.51.100.42".parse().unwrap();
        assert_eq!(rate_limit_key(v4), v4);
    }

    #[test]
    fn test_zero_limit() {
        let limiter = HandshakeRateLimiter::with_limit(0);
        let ip = test_ip(1);

        // With limit of 0, all requests should be rejected
        assert!(!limiter.allow(ip));
        assert!(!limiter.allow(ip));
    }

    #[test]
    fn test_very_high_limit() {
        let limiter = HandshakeRateLimiter::with_limit(1000);
        let ip = test_ip(1);

        // Should allow many requests
        for _ in 0..100 {
            assert!(limiter.allow(ip));
        }
        assert_eq!(limiter.get_count(ip), 100);
    }

    #[test]
    fn test_with_limits_custom_values() {
        let limiter = HandshakeRateLimiter::with_limits(7, 500);
        let ip = test_ip(1);

        // Should allow up to 7 requests
        for _ in 0..7 {
            assert!(limiter.allow(ip));
        }
        assert!(!limiter.allow(ip));
        assert_eq!(limiter.get_count(ip), 7);
    }

    #[test]
    fn test_constants() {
        assert_eq!(DEFAULT_MAX_HANDSHAKES_PER_MINUTE, 5);
        assert_eq!(RATE_LIMIT_WINDOW, Duration::from_secs(60));
        assert_eq!(CLEANUP_INTERVAL, Duration::from_secs(300));
        assert_eq!(DEFAULT_MAX_TRACKED_IPS, 100_000);
    }

    #[test]
    fn test_multiple_resets() {
        let limiter = HandshakeRateLimiter::with_limit(2);
        let ip = test_ip(1);

        assert!(limiter.allow(ip));
        assert!(limiter.allow(ip));
        assert_eq!(limiter.get_count(ip), 2);

        limiter.reset(ip);
        assert_eq!(limiter.get_count(ip), 0);

        assert!(limiter.allow(ip));
        limiter.reset(ip);
        assert_eq!(limiter.get_count(ip), 0);
    }

    #[test]
    fn test_check_does_not_affect_allow() {
        let limiter = HandshakeRateLimiter::with_limit(2);
        let ip = test_ip(1);

        // Multiple checks should not increment
        assert!(limiter.check(ip));
        assert!(limiter.check(ip));
        assert!(limiter.check(ip));

        // Allow should still work normally
        assert!(limiter.allow(ip));
        assert!(limiter.allow(ip));
        assert!(!limiter.allow(ip)); // Now at limit
    }

    #[test]
    fn test_concurrent_different_ips() {
        use std::sync::Arc;
        use std::thread;

        let limiter = Arc::new(HandshakeRateLimiter::with_limit(10));

        let handles: Vec<_> = (1..=10u8)
            .map(|i| {
                let limiter_clone = Arc::clone(&limiter);
                thread::spawn(move || {
                    let ip = test_ip(i);
                    for _ in 0..5 {
                        limiter_clone.allow(ip);
                    }
                    limiter_clone.get_count(ip)
                })
            })
            .collect();

        let counts: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // Each IP should have exactly 5 requests
        for count in counts {
            assert_eq!(count, 5);
        }
    }
}
