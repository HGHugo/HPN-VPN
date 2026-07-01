//! Connection statistics and health monitoring.
//!
//! Provides real-time metrics for VPN connection health and performance.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Maximum number of RTT samples to keep for moving average.
const RTT_SAMPLE_COUNT: usize = 20;

/// Connection statistics.
#[derive(Clone, Debug)]
pub struct ConnectionStats {
    /// Total bytes sent (plaintext).
    pub bytes_sent: u64,
    /// Total bytes received (plaintext).
    pub bytes_received: u64,
    /// Total packets sent.
    pub packets_sent: u64,
    /// Total packets received.
    pub packets_received: u64,
    /// Packets dropped due to errors.
    pub packets_dropped: u64,
    /// Current round-trip time in milliseconds.
    pub rtt_ms: u64,
    /// Average RTT over recent samples.
    pub avg_rtt_ms: u64,
    /// Minimum RTT observed.
    pub min_rtt_ms: u64,
    /// Maximum RTT observed.
    pub max_rtt_ms: u64,
    /// Connection uptime.
    pub uptime: Duration,
    /// Time since last data packet received.
    pub idle_time: Duration,
    /// Number of successful rekeys.
    pub rekey_count: u32,
    /// Current key ID.
    pub key_id: u32,
    /// Session ID.
    pub session_id: u64,
    /// Connection health status.
    pub health: ConnectionHealth,
}

impl Default for ConnectionStats {
    fn default() -> Self {
        Self {
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            packets_dropped: 0,
            rtt_ms: 0,
            avg_rtt_ms: 0,
            min_rtt_ms: u64::MAX,
            max_rtt_ms: 0,
            uptime: Duration::ZERO,
            idle_time: Duration::ZERO,
            rekey_count: 0,
            key_id: 0,
            session_id: 0,
            health: ConnectionHealth::Unknown,
        }
    }
}

/// Connection health status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionHealth {
    /// Connection health is unknown (no data yet).
    Unknown,
    /// Connection is healthy (low latency, recent activity).
    Healthy,
    /// Connection is degraded (high latency or some packet loss).
    Degraded,
    /// Connection may be failing (very high latency or significant packet loss).
    Poor,
    /// Connection appears to be dead (no recent activity).
    Dead,
}

impl ConnectionHealth {
    /// Get a human-readable description.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Healthy => "Healthy",
            Self::Degraded => "Degraded",
            Self::Poor => "Poor",
            Self::Dead => "Dead",
        }
    }

    /// Get an emoji indicator.
    #[must_use]
    pub const fn indicator(&self) -> &'static str {
        match self {
            Self::Unknown => "?",
            Self::Healthy => "●",
            Self::Degraded => "◐",
            Self::Poor => "○",
            Self::Dead => "✕",
        }
    }
}

/// Lock-free atomic counters for hot-path stats (bytes/packets).
/// These are updated on every packet without taking any lock.
pub struct AtomicStats {
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    packets_sent: AtomicU64,
    packets_received: AtomicU64,
    packets_dropped: AtomicU64,
}

impl AtomicStats {
    fn new() -> Self {
        Self {
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
        }
    }

    /// Record bytes sent (lock-free).
    #[inline]
    pub fn on_bytes_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Record bytes received (lock-free).
    #[inline]
    pub fn on_bytes_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
        self.packets_received.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a dropped packet (lock-free).
    #[inline]
    pub fn on_packet_dropped(&self) {
        self.packets_dropped.fetch_add(1, Ordering::Relaxed);
    }

    fn reset(&self) {
        self.bytes_sent.store(0, Ordering::Relaxed);
        self.bytes_received.store(0, Ordering::Relaxed);
        self.packets_sent.store(0, Ordering::Relaxed);
        self.packets_received.store(0, Ordering::Relaxed);
        self.packets_dropped.store(0, Ordering::Relaxed);
    }
}

/// Statistics tracker for monitoring connection health.
pub struct StatsTracker {
    /// Connection start time.
    connected_at: Option<Instant>,
    /// Last activity time (data packet received).
    last_activity: Option<Instant>,
    /// Last keepalive sent time.
    last_keepalive_sent: Option<Instant>,
    /// RTT samples for moving average.
    rtt_samples: VecDeque<u64>,
    /// Current stats.
    stats: ConnectionStats,
    /// Thresholds for health assessment.
    thresholds: HealthThresholds,
    /// Lock-free atomic counters for hot-path stats.
    pub atomic: AtomicStats,
}

/// Thresholds for determining connection health.
#[derive(Clone, Debug)]
pub struct HealthThresholds {
    /// RTT above this (ms) is considered degraded.
    pub degraded_rtt_ms: u64,
    /// RTT above this (ms) is considered poor.
    pub poor_rtt_ms: u64,
    /// Idle time above this is considered degraded.
    pub degraded_idle: Duration,
    /// Idle time above this is considered dead.
    pub dead_idle: Duration,
}

impl Default for HealthThresholds {
    fn default() -> Self {
        Self {
            degraded_rtt_ms: 200,
            poor_rtt_ms: 500,
            degraded_idle: Duration::from_secs(60),
            dead_idle: Duration::from_secs(120),
        }
    }
}

impl StatsTracker {
    /// Create a new stats tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            connected_at: None,
            last_activity: None,
            last_keepalive_sent: None,
            rtt_samples: VecDeque::with_capacity(RTT_SAMPLE_COUNT),
            stats: ConnectionStats::default(),
            thresholds: HealthThresholds::default(),
            atomic: AtomicStats::new(),
        }
    }

    /// Create with custom thresholds.
    #[must_use]
    pub fn with_thresholds(thresholds: HealthThresholds) -> Self {
        Self {
            thresholds,
            ..Self::new()
        }
    }

    /// Mark connection as established.
    pub fn on_connected(&mut self, session_id: u64) {
        let now = Instant::now();
        self.connected_at = Some(now);
        self.last_activity = Some(now);
        self.stats.session_id = session_id;
        self.stats.health = ConnectionHealth::Healthy;
    }

    /// Record bytes sent.
    /// NOTE: For hot-path use, prefer `atomic.on_bytes_sent()` to avoid taking the lock.
    pub fn on_bytes_sent(&mut self, bytes: u64) {
        self.atomic.on_bytes_sent(bytes);
    }

    /// Record bytes received.
    /// NOTE: For hot-path use, prefer `atomic.on_bytes_received()` to avoid taking the lock.
    pub fn on_bytes_received(&mut self, bytes: u64) {
        self.atomic.on_bytes_received(bytes);
        self.last_activity = Some(Instant::now());
    }

    /// Record a dropped packet.
    /// NOTE: For hot-path use, prefer `atomic.on_packet_dropped()` to avoid taking the lock.
    pub fn on_packet_dropped(&mut self) {
        self.atomic.on_packet_dropped();
    }

    /// Record keepalive sent.
    pub fn on_keepalive_sent(&mut self) {
        self.last_keepalive_sent = Some(Instant::now());
    }

    /// Record keepalive response with RTT.
    pub fn on_keepalive_received(&mut self, rtt_ms: u64) {
        self.last_activity = Some(Instant::now());

        // Update RTT stats
        self.stats.rtt_ms = rtt_ms;
        self.stats.min_rtt_ms = self.stats.min_rtt_ms.min(rtt_ms);
        self.stats.max_rtt_ms = self.stats.max_rtt_ms.max(rtt_ms);

        // Add to samples for moving average
        if self.rtt_samples.len() >= RTT_SAMPLE_COUNT {
            self.rtt_samples.pop_front();
        }
        self.rtt_samples.push_back(rtt_ms);

        // Calculate average
        if !self.rtt_samples.is_empty() {
            let sum: u64 = self.rtt_samples.iter().sum();
            self.stats.avg_rtt_ms = sum / self.rtt_samples.len() as u64;
        }

        self.update_health();
    }

    /// Record a successful rekey.
    pub fn on_rekey(&mut self, new_key_id: u32) {
        self.stats.rekey_count = self.stats.rekey_count.saturating_add(1);
        self.stats.key_id = new_key_id;
    }

    /// Update health assessment based on current stats.
    fn update_health(&mut self) {
        let idle_time = self
            .last_activity
            .map(|t| t.elapsed())
            .unwrap_or(Duration::MAX);

        self.stats.idle_time = idle_time;

        // Check for dead connection first
        if idle_time > self.thresholds.dead_idle {
            self.stats.health = ConnectionHealth::Dead;
            return;
        }

        // Check RTT-based health
        let rtt = self.stats.avg_rtt_ms;
        let health_by_rtt = if rtt > self.thresholds.poor_rtt_ms {
            ConnectionHealth::Poor
        } else if rtt > self.thresholds.degraded_rtt_ms {
            ConnectionHealth::Degraded
        } else {
            ConnectionHealth::Healthy
        };

        // Check idle-based health
        let health_by_idle = if idle_time > self.thresholds.degraded_idle {
            ConnectionHealth::Degraded
        } else {
            ConnectionHealth::Healthy
        };

        // Use the worse of the two
        self.stats.health = match (health_by_rtt, health_by_idle) {
            (ConnectionHealth::Poor, _) | (_, ConnectionHealth::Poor) => ConnectionHealth::Poor,
            (ConnectionHealth::Degraded, _) | (_, ConnectionHealth::Degraded) => {
                ConnectionHealth::Degraded
            }
            _ => ConnectionHealth::Healthy,
        };
    }

    /// Get current statistics snapshot.
    ///
    /// Merges lock-free atomic counters with lock-protected stats.
    #[must_use]
    pub fn snapshot(&self) -> ConnectionStats {
        let mut stats = self.stats.clone();

        // Merge atomic counters (hot path stats)
        stats.bytes_sent = self.atomic.bytes_sent.load(Ordering::Relaxed);
        stats.bytes_received = self.atomic.bytes_received.load(Ordering::Relaxed);
        stats.packets_sent = self.atomic.packets_sent.load(Ordering::Relaxed);
        stats.packets_received = self.atomic.packets_received.load(Ordering::Relaxed);
        stats.packets_dropped = self.atomic.packets_dropped.load(Ordering::Relaxed);

        // Update dynamic fields
        if let Some(connected_at) = self.connected_at {
            stats.uptime = connected_at.elapsed();
        }
        if let Some(last_activity) = self.last_activity {
            stats.idle_time = last_activity.elapsed();
        }

        // Update health before returning
        stats.health = self.calculate_current_health();

        stats
    }

    /// Calculate current health without modifying state.
    fn calculate_current_health(&self) -> ConnectionHealth {
        if self.connected_at.is_none() {
            return ConnectionHealth::Unknown;
        }

        let idle_time = self
            .last_activity
            .map(|t| t.elapsed())
            .unwrap_or(Duration::MAX);

        if idle_time > self.thresholds.dead_idle {
            return ConnectionHealth::Dead;
        }

        let rtt = self.stats.avg_rtt_ms;
        let health_by_rtt = if rtt > self.thresholds.poor_rtt_ms {
            ConnectionHealth::Poor
        } else if rtt > self.thresholds.degraded_rtt_ms {
            ConnectionHealth::Degraded
        } else if rtt == 0 && self.rtt_samples.is_empty() {
            ConnectionHealth::Unknown
        } else {
            ConnectionHealth::Healthy
        };

        let health_by_idle = if idle_time > self.thresholds.degraded_idle {
            ConnectionHealth::Degraded
        } else {
            ConnectionHealth::Healthy
        };

        match (health_by_rtt, health_by_idle) {
            (ConnectionHealth::Unknown, _) => ConnectionHealth::Unknown,
            (ConnectionHealth::Poor, _) | (_, ConnectionHealth::Poor) => ConnectionHealth::Poor,
            (ConnectionHealth::Degraded, _) | (_, ConnectionHealth::Degraded) => {
                ConnectionHealth::Degraded
            }
            _ => ConnectionHealth::Healthy,
        }
    }

    /// Get transfer rate in bytes per second (approximate).
    #[must_use]
    pub fn transfer_rate(&self) -> (f64, f64) {
        let uptime_secs = self
            .connected_at
            .map(|t| t.elapsed().as_secs_f64())
            .unwrap_or(1.0)
            .max(1.0);

        let sent_rate = self.atomic.bytes_sent.load(Ordering::Relaxed) as f64 / uptime_secs;
        let recv_rate = self.atomic.bytes_received.load(Ordering::Relaxed) as f64 / uptime_secs;

        (sent_rate, recv_rate)
    }

    /// Reset statistics (e.g., after reconnect).
    pub fn reset(&mut self) {
        self.connected_at = None;
        self.last_activity = None;
        self.last_keepalive_sent = None;
        self.rtt_samples.clear();
        self.stats = ConnectionStats::default();
        self.atomic.reset();
    }
}

impl Default for StatsTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Format bytes as human-readable string.
#[must_use]
pub fn format_bytes(bytes: u64) -> String {
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

/// Format duration as human-readable string.
#[must_use]
pub fn format_duration(duration: Duration) -> String {
    let secs = duration.as_secs();
    if secs >= 3600 {
        let hours = secs / 3600;
        let mins = (secs % 3600) / 60;
        format!("{}h {}m", hours, mins)
    } else if secs >= 60 {
        let mins = secs / 60;
        let secs = secs % 60;
        format!("{}m {}s", mins, secs)
    } else {
        format!("{}s", secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_tracker_new() {
        let tracker = StatsTracker::new();
        let stats = tracker.snapshot();
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.health, ConnectionHealth::Unknown);
    }

    #[test]
    fn test_stats_tracker_connected() {
        let mut tracker = StatsTracker::new();
        tracker.on_connected(12345);
        let stats = tracker.snapshot();
        assert_eq!(stats.session_id, 12345);
        // Health is Unknown until we receive keepalive data
        assert_eq!(stats.health, ConnectionHealth::Unknown);

        // After receiving keepalive, health becomes Healthy
        tracker.on_keepalive_received(50);
        let stats = tracker.snapshot();
        assert_eq!(stats.health, ConnectionHealth::Healthy);
    }

    #[test]
    fn test_stats_tracker_bytes() {
        let mut tracker = StatsTracker::new();
        tracker.on_connected(1);
        tracker.on_bytes_sent(1000);
        tracker.on_bytes_received(2000);
        let stats = tracker.snapshot();
        assert_eq!(stats.bytes_sent, 1000);
        assert_eq!(stats.bytes_received, 2000);
        assert_eq!(stats.packets_sent, 1);
        assert_eq!(stats.packets_received, 1);
    }

    #[test]
    fn test_stats_tracker_rtt() {
        let mut tracker = StatsTracker::new();
        tracker.on_connected(1);
        tracker.on_keepalive_received(50);
        tracker.on_keepalive_received(60);
        tracker.on_keepalive_received(40);
        let stats = tracker.snapshot();
        assert_eq!(stats.rtt_ms, 40);
        assert_eq!(stats.avg_rtt_ms, 50);
        assert_eq!(stats.min_rtt_ms, 40);
        assert_eq!(stats.max_rtt_ms, 60);
    }

    #[test]
    fn test_health_assessment() {
        let thresholds = HealthThresholds {
            degraded_rtt_ms: 100,
            poor_rtt_ms: 300,
            degraded_idle: Duration::from_secs(30),
            dead_idle: Duration::from_secs(60),
        };
        let mut tracker = StatsTracker::with_thresholds(thresholds);
        tracker.on_connected(1);

        // Healthy RTT (single sample, avg = 50)
        tracker.on_keepalive_received(50);
        assert_eq!(tracker.snapshot().health, ConnectionHealth::Healthy);

        // Degraded RTT - use higher values to shift average above 100
        // Samples: [50, 150, 150] -> avg = 116.67 > 100
        tracker.on_keepalive_received(150);
        tracker.on_keepalive_received(150);
        assert_eq!(tracker.snapshot().health, ConnectionHealth::Degraded);

        // Poor RTT - need many high values to shift average above 300
        // Reset tracker to get clean state
        tracker.reset();
        tracker.on_connected(1);
        // Use consistently high RTT to exceed poor threshold
        for _ in 0..5 {
            tracker.on_keepalive_received(400);
        }
        assert_eq!(tracker.snapshot().health, ConnectionHealth::Poor);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1500), "1.46 KB");
        assert_eq!(format_bytes(1_500_000), "1.43 MB");
        assert_eq!(format_bytes(1_500_000_000), "1.40 GB");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_secs(30)), "30s");
        assert_eq!(format_duration(Duration::from_secs(90)), "1m 30s");
        assert_eq!(format_duration(Duration::from_secs(3700)), "1h 1m");
    }

    #[test]
    fn test_rekey_tracking() {
        let mut tracker = StatsTracker::new();
        tracker.on_connected(1);
        tracker.on_rekey(2);
        tracker.on_rekey(3);
        let stats = tracker.snapshot();
        assert_eq!(stats.rekey_count, 2);
        assert_eq!(stats.key_id, 3);
    }

    #[test]
    fn test_connection_health_indicator() {
        assert_eq!(ConnectionHealth::Unknown.indicator(), "?");
        assert_eq!(ConnectionHealth::Healthy.indicator(), "●");
        assert_eq!(ConnectionHealth::Degraded.indicator(), "◐");
        assert_eq!(ConnectionHealth::Poor.indicator(), "○");
        assert_eq!(ConnectionHealth::Dead.indicator(), "✕");
    }

    #[test]
    fn test_stats_tracker_reset() {
        let mut tracker = StatsTracker::new();
        tracker.on_connected(12345);
        tracker.on_bytes_sent(1000);
        tracker.on_keepalive_received(50);

        tracker.reset();

        let stats = tracker.snapshot();
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.health, ConnectionHealth::Unknown);
    }

    #[test]
    fn test_stats_tracker_packet_drops() {
        let mut tracker = StatsTracker::new();
        tracker.on_connected(1);
        tracker.on_packet_dropped();
        tracker.on_packet_dropped();

        let stats = tracker.snapshot();
        assert_eq!(stats.packets_dropped, 2);
    }

    #[test]
    fn test_stats_tracker_transfer_rate() {
        let mut tracker = StatsTracker::new();
        tracker.on_connected(1);
        tracker.on_bytes_sent(10000);
        tracker.on_bytes_received(20000);

        let (sent_rate, recv_rate) = tracker.transfer_rate();
        assert!(sent_rate > 0.0);
        assert!(recv_rate > sent_rate);
    }

    #[test]
    fn test_format_bytes_edge_cases() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
    }

    #[test]
    fn test_format_duration_edge_cases() {
        assert_eq!(format_duration(Duration::from_secs(0)), "0s");
        assert_eq!(format_duration(Duration::from_secs(60)), "1m 0s");
        assert_eq!(format_duration(Duration::from_secs(3600)), "1h 0m");
    }
}
