//! User-agnostic authentication lockout tracker.
//!
//! Replaces the previous per-username lockout (stored on the SQLite user
//! row) which was exploitable as a denial-of-service primitive: an attacker
//! with 10 distinct IPs could lock any known username out of the service
//! for an hour.
//!
//! ## Policy (HAUTE 8)
//!
//! Three independent throttles are enforced on every authentication attempt:
//!
//! 1. **Per-(username, ip) tuple**
//!    - 10 failed attempts in 1 hour → lock the tuple for 1 hour.
//!    - Successful auth clears the tuple's counter immediately.
//!
//! 2. **Per-ip** (all usernames combined)
//!    - 100 failed attempts/hour across any usernames → ban the IP for 1h.
//!
//! 3. **Per-username** (spread threshold)
//!    - Only lock the *username globally* after ≥ 20 failed attempts from
//!      ≥ 5 distinct IPs inside a rolling 24h window. This makes drive-by
//!      username lockout expensive: an attacker needs both volume *and* a
//!      diverse IP pool to pull it off.
//!
//! All state lives in memory with a hard size cap (default 100 000 entries
//! per map) to prevent an attacker from exhausting the server's RAM by
//! cycling through random usernames/IPs. Oldest entries are evicted when
//! the cap is reached (approximate LRU via a single sweep).
//!
//! The tracker is fully thread-safe (`parking_lot::Mutex`) and held on the
//! blocking-pool task where password verification runs.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;

/// Kind of lockout that fired, for metrics / logging.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockoutKind {
    /// The (username, ip) tuple exhausted its attempt budget.
    Tuple,
    /// The source IP exhausted its cross-username attempt budget.
    Ip,
    /// The username was globally locked due to a distributed attack
    /// (many IPs, many attempts over 24 h).
    UsernameSpread,
}

impl LockoutKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tuple => "tuple",
            Self::Ip => "ip",
            Self::UsernameSpread => "username_spread",
        }
    }
}

/// Thresholds — configurable at construction time for tests.
#[derive(Clone, Copy, Debug)]
pub struct LockoutPolicy {
    /// Per-(username, ip) attempt count before lockout.
    pub tuple_max_attempts: u32,
    /// Lockout duration (secs) for a (username, ip) tuple.
    pub tuple_lockout_secs: u64,
    /// Per-ip attempt count (all usernames) before IP ban.
    pub ip_max_attempts: u32,
    /// Ban duration (secs) for an IP.
    pub ip_ban_secs: u64,
    /// Minimum total failed attempts required to trigger a global
    /// username lock. (Must also meet `username_spread_min_ips`.)
    pub username_min_attempts: u32,
    /// Minimum distinct source IPs required to trigger a global
    /// username lock, inside `username_window_secs`.
    pub username_spread_min_ips: u32,
    /// Rolling window (secs) for the username spread count.
    pub username_window_secs: u64,
    /// Global username lock duration (secs).
    pub username_lock_secs: u64,
    /// Maximum tracked entries per map.
    pub max_entries: usize,
}

impl LockoutPolicy {
    /// Production defaults per the security review.
    pub const fn production() -> Self {
        Self {
            tuple_max_attempts: 10,
            tuple_lockout_secs: 3600, // 1 hour
            ip_max_attempts: 100,
            ip_ban_secs: 3600, // 1 hour
            username_min_attempts: 20,
            username_spread_min_ips: 5,
            username_window_secs: 24 * 3600, // 24 hours
            username_lock_secs: 3600,
            max_entries: 100_000,
        }
    }
}

impl Default for LockoutPolicy {
    fn default() -> Self {
        Self::production()
    }
}

#[derive(Default)]
struct TupleEntry {
    failed_attempts: u32,
    locked_until: u64,
    /// For approximate LRU: updated on every access.
    last_access: u64,
}

#[derive(Default)]
struct IpEntry {
    /// Rolling hour: reset when `window_start + 3600 < now`.
    failed_attempts_hour: u32,
    window_start: u64,
    banned_until: u64,
    last_access: u64,
}

#[derive(Default)]
struct UsernameEntry {
    /// Distinct IPs seen failing against this username in the current window.
    ips: HashSet<IpAddr>,
    total_attempts_window: u32,
    window_start: u64,
    locked_until: u64,
    last_access: u64,
}

/// Inner state guarded by a single mutex. We intentionally use one coarse
/// lock rather than per-entry locks: the hot path is login, which is already
/// CPU-bound by Argon2id (~150 ms/hash) so the mutex is never the bottleneck.
struct LockoutInner {
    tuples: HashMap<(String, IpAddr), TupleEntry>,
    ips: HashMap<IpAddr, IpEntry>,
    usernames: HashMap<String, UsernameEntry>,
}

/// Counters surfaced to the Prometheus metrics module.
#[derive(Default, Debug, Clone, Copy)]
pub struct LockoutMetricsSnapshot {
    pub tuple_lockouts: u64,
    pub ip_bans: u64,
    pub username_locks: u64,
}

/// Main tracker.
pub struct AuthLockoutTracker {
    inner: Mutex<LockoutInner>,
    policy: LockoutPolicy,
    metrics: Mutex<LockoutMetricsSnapshot>,
}

impl AuthLockoutTracker {
    pub fn new(policy: LockoutPolicy) -> Self {
        Self {
            inner: Mutex::new(LockoutInner {
                tuples: HashMap::new(),
                ips: HashMap::new(),
                usernames: HashMap::new(),
            }),
            policy,
            metrics: Mutex::new(LockoutMetricsSnapshot::default()),
        }
    }

    pub fn with_production_defaults() -> Self {
        Self::new(LockoutPolicy::production())
    }

    /// Return `Some(kind)` if the attempt should be refused immediately due
    /// to an active lockout on any of the three dimensions. `None` means the
    /// caller may proceed to verify the password.
    ///
    /// NOTE: callers should still perform an Argon2 "dummy" hash on lockout
    /// rejections to keep auth latency timing-channel-free.
    pub fn check_lockout(&self, username: &str, ip: IpAddr) -> Option<LockoutKind> {
        let now = now_secs();
        let inner = self.inner.lock();

        if let Some(entry) = inner.ips.get(&ip)
            && entry.banned_until > now
        {
            return Some(LockoutKind::Ip);
        }

        if let Some(entry) = inner.tuples.get(&(username.to_string(), ip))
            && entry.locked_until > now
        {
            return Some(LockoutKind::Tuple);
        }

        if let Some(entry) = inner.usernames.get(username)
            && entry.locked_until > now
        {
            return Some(LockoutKind::UsernameSpread);
        }

        None
    }

    /// Register a successful authentication. Clears the (username, ip) tuple
    /// counter. We deliberately leave the per-IP and per-username counters
    /// alone: a single legitimate login should not reset counters that track
    /// the *aggregate* attack behaviour of the IP or username.
    pub fn record_success(&self, username: &str, ip: IpAddr) {
        let mut inner = self.inner.lock();
        inner.tuples.remove(&(username.to_string(), ip));
    }

    /// Register a failed authentication.
    ///
    /// Returns the lockout kind that fired on this call, if any. The caller
    /// should include this in log messages / metrics.
    pub fn record_failure(&self, username: &str, ip: IpAddr) -> Option<LockoutKind> {
        let now = now_secs();
        let policy = self.policy;
        let mut fired: Option<LockoutKind> = None;
        let mut inner = self.inner.lock();

        // ── Per-(username, ip) ─────────────────────────────────────────────
        evict_if_full(&mut inner.tuples, policy.max_entries);
        let tuple_key = (username.to_string(), ip);
        let tuple = inner.tuples.entry(tuple_key).or_default();
        tuple.last_access = now;
        tuple.failed_attempts = tuple.failed_attempts.saturating_add(1);
        if tuple.failed_attempts >= policy.tuple_max_attempts && tuple.locked_until <= now {
            tuple.locked_until = now.saturating_add(policy.tuple_lockout_secs);
            tuple.failed_attempts = 0; // reset the counter after lock
            fired = Some(LockoutKind::Tuple);
            self.metrics.lock().tuple_lockouts += 1;
        }

        // ── Per-ip (rolling 1h) ────────────────────────────────────────────
        evict_if_full(&mut inner.ips, policy.max_entries);
        let ip_entry = inner.ips.entry(ip).or_default();
        if now.saturating_sub(ip_entry.window_start) > 3600 {
            ip_entry.window_start = now;
            ip_entry.failed_attempts_hour = 0;
        }
        ip_entry.last_access = now;
        ip_entry.failed_attempts_hour = ip_entry.failed_attempts_hour.saturating_add(1);
        if ip_entry.failed_attempts_hour >= policy.ip_max_attempts && ip_entry.banned_until <= now {
            ip_entry.banned_until = now.saturating_add(policy.ip_ban_secs);
            ip_entry.failed_attempts_hour = 0;
            if fired.is_none() {
                fired = Some(LockoutKind::Ip);
            }
            self.metrics.lock().ip_bans += 1;
        }

        // ── Per-username (spread, rolling 24h) ─────────────────────────────
        evict_if_full(&mut inner.usernames, policy.max_entries);
        let user_entry = inner.usernames.entry(username.to_string()).or_default();
        if now.saturating_sub(user_entry.window_start) > policy.username_window_secs {
            user_entry.window_start = now;
            user_entry.total_attempts_window = 0;
            user_entry.ips.clear();
        }
        user_entry.last_access = now;
        user_entry.total_attempts_window = user_entry.total_attempts_window.saturating_add(1);
        user_entry.ips.insert(ip);
        if user_entry.total_attempts_window >= policy.username_min_attempts
            && user_entry.ips.len() as u32 >= policy.username_spread_min_ips
            && user_entry.locked_until <= now
        {
            user_entry.locked_until = now.saturating_add(policy.username_lock_secs);
            // Keep counters so we don't re-lock immediately after expiry
            // without fresh evidence.
            user_entry.total_attempts_window = 0;
            user_entry.ips.clear();
            if fired.is_none() {
                fired = Some(LockoutKind::UsernameSpread);
            }
            self.metrics.lock().username_locks += 1;
        }

        fired
    }

    /// Snapshot of cumulative lockout counters for metrics export.
    pub fn metrics_snapshot(&self) -> LockoutMetricsSnapshot {
        *self.metrics.lock()
    }

    /// Sizes of the three tracked maps — useful for debugging.
    #[cfg(test)]
    pub fn debug_sizes(&self) -> (usize, usize, usize) {
        let inner = self.inner.lock();
        (inner.tuples.len(), inner.ips.len(), inner.usernames.len())
    }
}

/// Approximate LRU eviction: if the map is at capacity, remove the entry
/// with the oldest `last_access`. O(N) but only triggered on insertion
/// into a full map — amortised cost is acceptable at our sizes.
fn evict_if_full<K: Eq + std::hash::Hash + Clone, V: HasLastAccess>(
    map: &mut HashMap<K, V>,
    cap: usize,
) {
    if map.len() < cap {
        return;
    }
    // Find the oldest entry.
    let mut oldest_key: Option<K> = None;
    let mut oldest_ts: u64 = u64::MAX;
    for (k, v) in map.iter() {
        if v.last_access() < oldest_ts {
            oldest_ts = v.last_access();
            oldest_key = Some(k.clone());
        }
    }
    if let Some(k) = oldest_key {
        map.remove(&k);
    }
}

trait HasLastAccess {
    fn last_access(&self) -> u64;
}

impl HasLastAccess for TupleEntry {
    fn last_access(&self) -> u64 {
        self.last_access
    }
}
impl HasLastAccess for IpEntry {
    fn last_access(&self) -> u64 {
        self.last_access
    }
}
impl HasLastAccess for UsernameEntry {
    fn last_access(&self) -> u64 {
        self.last_access
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    #[test]
    fn tuple_lockout_fires_after_threshold() {
        let t = AuthLockoutTracker::with_production_defaults();
        let a = ip(1);

        for _ in 0..9 {
            assert_eq!(t.record_failure("alice", a), None);
            assert!(t.check_lockout("alice", a).is_none());
        }
        // 10th failure triggers the lockout.
        assert_eq!(t.record_failure("alice", a), Some(LockoutKind::Tuple));
        assert_eq!(t.check_lockout("alice", a), Some(LockoutKind::Tuple));

        // A different IP against the same user is NOT locked by the
        // tuple — this is the user-agnostic property we wanted.
        assert_eq!(t.check_lockout("alice", ip(2)), None);
    }

    #[test]
    fn success_resets_tuple_counter() {
        let t = AuthLockoutTracker::with_production_defaults();
        let a = ip(1);
        for _ in 0..5 {
            t.record_failure("alice", a);
        }
        t.record_success("alice", a);
        // We need 10 more failures from scratch before lock.
        for _ in 0..9 {
            assert_eq!(t.record_failure("alice", a), None);
        }
        assert_eq!(t.record_failure("alice", a), Some(LockoutKind::Tuple));
    }

    #[test]
    fn ip_ban_triggers_at_cross_user_volume() {
        let t = AuthLockoutTracker::with_production_defaults();
        let a = ip(42);
        // 10 different users, 9 failures each = 90 — below the 100 threshold.
        for u in 0..10 {
            for _ in 0..9 {
                t.record_failure(&format!("user{u}"), a);
            }
        }
        // One more failure pushes us to 91; still below.
        assert!(t.record_failure("user10", a).is_none());
        // Now ramp past 100.
        let mut banned = false;
        for _ in 0..10 {
            if t.record_failure("user11", a) == Some(LockoutKind::Ip) {
                banned = true;
                break;
            }
        }
        assert!(banned, "IP should be banned past 100 failures/hour");
    }

    #[test]
    fn username_spread_requires_multiple_ips() {
        let t = AuthLockoutTracker::with_production_defaults();
        // 100 failures from one IP should never trigger username_spread
        // (it will trigger per-IP ban but not the global username lock).
        for _ in 0..100 {
            t.record_failure("bob", ip(1));
        }
        let snap = t.metrics_snapshot();
        assert_eq!(snap.username_locks, 0);
    }

    #[test]
    fn username_spread_fires_with_diverse_attackers() {
        let policy = LockoutPolicy {
            // Shrink to make the test tractable.
            tuple_max_attempts: 1000,
            ip_max_attempts: 1000,
            username_min_attempts: 20,
            username_spread_min_ips: 5,
            ..LockoutPolicy::production()
        };
        let t = AuthLockoutTracker::new(policy);
        // 5 IPs, 4 failures each = 20 total → should fire the spread lock.
        let mut fired = false;
        for i in 1..=5u8 {
            for _ in 0..4 {
                if t.record_failure("charlie", ip(i)) == Some(LockoutKind::UsernameSpread) {
                    fired = true;
                }
            }
        }
        assert!(fired);
        assert_eq!(
            t.check_lockout("charlie", ip(99)),
            Some(LockoutKind::UsernameSpread)
        );
    }

    #[test]
    fn lru_evicts_when_capped() {
        let policy = LockoutPolicy {
            max_entries: 4,
            ..LockoutPolicy::production()
        };
        let t = AuthLockoutTracker::new(policy);
        for i in 0..10u8 {
            t.record_failure(&format!("u{i}"), ip(i));
        }
        let (tuples, ips, users) = t.debug_sizes();
        assert!(tuples <= 4);
        assert!(ips <= 4);
        assert!(users <= 4);
    }
}
