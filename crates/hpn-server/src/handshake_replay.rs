//! Anti-replay cache for handshake `client_random` values.
//!
//! `HandshakeInit.client_random` is a 32-byte random sampled fresh by every
//! legitimate client. A passive attacker can however record a genuine
//! `HandshakeInit` off the wire and replay it at will: the server has no way
//! to tell a fresh init from a replayed one at the entry-parsing stage, and
//! each accepted init triggers a full PQ decapsulation plus ML-DSA signing
//! (~1-2 ms of CPU at Level 5). Without a replay guard this is a pure CPU
//! amplification vector that the per-IP rate limiter alone can only
//! partially contain.
//!
//! This module adds a bounded LRU-ish cache of recently-seen
//! `client_random` values. An init whose random collides with a recent entry
//! is rejected before any expensive crypto work runs.
//!
//! # Design
//!
//! * Keyed on the full 32-byte `client_random`.
//! * Entries expire after `ttl` (default: 60 s, matching the per-IP rate
//!   window) so a legitimate client reconnecting after a roam with the
//!   exact same random (astronomical odds, but possible) is never
//!   permanently locked out.
//! * Bounded to `max_entries` (default: 256 K ≈ 12 MB) — sized so that even
//!   a `/48` IPv6 attacker spending every available per-`/64` handshake
//!   token cannot saturate the cache within the TTL. At 5 handshakes/min/
//!   `/64` × 60 s TTL = 300 tokens per `/64`; saturating 256 K entries
//!   requires > 800 distinct `/64` prefixes, which is well above what a
//!   single hosting allocation can reach. Raising the cap is the cheap
//!   lever against the documented "fail-open under memory pressure"
//!   weakness: a smaller cap was easy to exhaust.
//! * Fail-closed above 110% of the cap (FIX-030): once both the entry-count
//!   exceeds `max_entries` AND opportunistic TTL cleanup cannot bring it
//!   back under the hard cap (`max_entries + 10%`), brand-new inits are
//!   rejected. The original design fell open under pressure, which let a
//!   sustained handshake flood silently disable the replay cache and
//!   restore the CPU-amplification surface this module exists to close.
//!   The 10% slack absorbs normal TTL-sweep oscillation; crossing the
//!   line indicates real abuse and we drop legitimate retries rather
//!   than go dark. Opportunistic cleanup scans the whole map every time
//!   the cache fills, which is O(n) — acceptable because n is at most
//!   `max_entries`.
//! * Thread-safe via a single `parking_lot::Mutex`. Handshakes are
//!   low-frequency relative to data packets, so lock contention is not a
//!   concern.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

/// Default TTL for replay entries — matches the handshake rate-limit window.
const DEFAULT_TTL: Duration = Duration::from_secs(60);

/// Default cap on retained entries. 256 K × 48 B ≈ 12 MB upper bound.
///
/// Raised from the initial 16 K because that cap was reachable by a single
/// cloud attacker holding a routed `/48` — see the module-level doc for
/// the full saturation math. 256 K pushes the required distinct-`/64`
/// prefix count past what a single hosting allocation can supply while
/// keeping memory well below any reasonable server budget.
const DEFAULT_MAX_ENTRIES: usize = 262_144;

/// Anti-replay cache for `HandshakeInit.client_random`.
pub struct HandshakeReplayCache {
    entries: Mutex<HashMap<[u8; 32], Instant>>,
    ttl: Duration,
    max_entries: usize,
}

impl HandshakeReplayCache {
    /// Build a new cache with default parameters.
    #[must_use]
    pub fn new() -> Self {
        Self::with_params(DEFAULT_TTL, DEFAULT_MAX_ENTRIES)
    }

    /// Build a new cache with custom parameters.
    #[must_use]
    pub fn with_params(ttl: Duration, max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl,
            max_entries,
        }
    }

    /// Check whether the given `client_random` has been seen within the TTL,
    /// and remember it as "seen now" when not.
    ///
    /// Returns `true` when the random is fresh (handshake should proceed),
    /// `false` when it collides with a still-live entry (handshake should be
    /// dropped without further work).
    ///
    /// FIX-030: the previous implementation accepted-but-did-not-record a
    /// new init when the cache was full after TTL sweep ("fail-open on
    /// memory pressure"). Under sustained handshake-flooding the cache
    /// stays saturated and EVERY genuine handshake init slips through
    /// unrecorded — the replay cache effectively goes dark, restoring
    /// the pre-cache attack surface. Now we fail CLOSED above 110% of
    /// the configured `max_entries` (i.e. once we'd be allocating a
    /// fresh slot AND there is no room to evict via TTL sweep). The
    /// 10% slack avoids spurious rejections during normal operation;
    /// crossing the 110% line indicates real abuse and we'd rather
    /// drop legitimate retries than silently disable the cache.
    pub fn check_and_insert(&self, client_random: &[u8; 32]) -> bool {
        let now = Instant::now();
        let mut entries = self.entries.lock();

        // Opportunistic TTL sweep when the cache is full. Capped by
        // `max_entries`, so this is O(max_entries) at worst — hundreds of µs
        // on a handshake, well below the cost of the crypto work we are
        // about to avoid.
        if entries.len() >= self.max_entries {
            let ttl = self.ttl;
            entries.retain(|_, seen| now.duration_since(*seen) < ttl);
        }

        if let Some(seen) = entries.get(client_random)
            && now.duration_since(*seen) < self.ttl
        {
            // Live entry — caller is attempting a replay.
            return false;
        }
        // If `entries` had a stale entry (past TTL), fall through to
        // re-insert with a fresh timestamp below.

        // Cache still full after cleanup? FIX-030: fail CLOSED instead of
        // accepting-but-not-recording. 110% headroom over `max_entries`
        // absorbs normal TTL-sweep oscillation; only sustained pressure
        // crosses the line, in which case we drop the new init.
        let hard_cap = self.max_entries.saturating_add(self.max_entries / 10);
        if entries.len() >= hard_cap && !entries.contains_key(client_random) {
            return false;
        }

        entries.insert(*client_random, now);
        true
    }

    /// Number of entries currently tracked. Exposed mostly for tests / metrics.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    /// Whether the cache is empty. Exposed mostly for tests.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.lock().is_empty()
    }

    /// Force-drop all entries. Used after a config reload to avoid blocking
    /// real clients if the cap has been lowered.
    pub fn clear(&self) {
        self.entries.lock().clear();
    }
}

impl Default for HandshakeReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_random_is_accepted_once() {
        let cache = HandshakeReplayCache::new();
        let random = [0x42u8; 32];
        assert!(cache.check_and_insert(&random));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn replayed_random_is_rejected() {
        let cache = HandshakeReplayCache::new();
        let random = [0x42u8; 32];
        assert!(cache.check_and_insert(&random));
        assert!(
            !cache.check_and_insert(&random),
            "second call with same client_random must be rejected"
        );
    }

    #[test]
    fn expired_entry_is_accepted_again() {
        let cache = HandshakeReplayCache::with_params(Duration::from_millis(10), 32);
        let random = [0x33u8; 32];
        assert!(cache.check_and_insert(&random));
        std::thread::sleep(Duration::from_millis(20));
        assert!(
            cache.check_and_insert(&random),
            "entry past its TTL must be treated as fresh"
        );
    }

    #[test]
    fn distinct_randoms_are_independent() {
        let cache = HandshakeReplayCache::new();
        let a = [0x01u8; 32];
        let b = [0x02u8; 32];
        assert!(cache.check_and_insert(&a));
        assert!(cache.check_and_insert(&b));
        assert!(!cache.check_and_insert(&a));
        assert!(!cache.check_and_insert(&b));
    }

    #[test]
    fn cap_is_enforced_and_fails_closed_under_pressure() {
        // FIX-030: once the cache is full AND no TTL eviction is possible,
        // brand-new randoms are REJECTED (fail-closed). Going dark under
        // sustained handshake flooding would silently disable the replay
        // cache, restoring the CPU-amplification surface.
        // With max_entries=2 the hard cap is 2 + 2/10 = 2, so the third
        // random is over the hard cap and must be dropped.
        let cache = HandshakeReplayCache::with_params(Duration::from_secs(60), 2);
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        assert!(cache.check_and_insert(&a));
        assert!(cache.check_and_insert(&b));
        // Cache at hard cap, no TTL-evictable entries → reject.
        assert!(!cache.check_and_insert(&c));
        // Recorded randoms still rejected on replay — protection holds.
        assert!(!cache.check_and_insert(&a));
        assert!(!cache.check_and_insert(&b));
    }

    #[test]
    fn clear_drops_state() {
        let cache = HandshakeReplayCache::new();
        cache.check_and_insert(&[7u8; 32]);
        assert!(!cache.is_empty());
        cache.clear();
        assert!(cache.is_empty());
    }
}
