//! Prometheus metrics and monitoring for HPN server.
//!
//! Provides metrics collection and export in Prometheus format for monitoring:
//! - Connection metrics (active sessions, handshakes, etc.)
//! - Traffic metrics (bytes sent/received, packets)
//! - Performance metrics (latency, processing time)
//! - Error metrics (failed handshakes, decryption errors)
//!
//! Also provides an HTTP server for `/metrics` endpoint.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use parking_lot::RwLock;
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

/// Prometheus metric types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetricType {
    /// Counter: monotonically increasing value.
    Counter,
    /// Gauge: value that can go up and down.
    Gauge,
    /// Histogram: distribution of values.
    Histogram,
}

/// A single metric with name, help, and type.
#[derive(Debug)]
pub struct Metric {
    /// Metric name (prometheus format).
    pub name: &'static str,
    /// Help text.
    pub help: &'static str,
    /// Metric type.
    pub metric_type: MetricType,
    /// Current value (for counters and gauges).
    pub value: AtomicU64,
}

impl Metric {
    /// Create a new counter metric.
    pub const fn counter(name: &'static str, help: &'static str) -> Self {
        Self {
            name,
            help,
            metric_type: MetricType::Counter,
            value: AtomicU64::new(0),
        }
    }

    /// Create a new gauge metric.
    pub const fn gauge(name: &'static str, help: &'static str) -> Self {
        Self {
            name,
            help,
            metric_type: MetricType::Gauge,
            value: AtomicU64::new(0),
        }
    }

    /// Increment counter or gauge.
    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment by a specific amount.
    pub fn inc_by(&self, n: u64) {
        self.value.fetch_add(n, Ordering::Relaxed);
    }

    /// Decrement gauge (saturates at 0 to prevent underflow).
    pub fn dec(&self) {
        let _ = self
            .value
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                if v > 0 { Some(v - 1) } else { None }
            });
    }

    /// Set gauge to a specific value.
    pub fn set(&self, value: u64) {
        self.value.store(value, Ordering::Relaxed);
    }

    /// Get current value.
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }

    /// Format for Prometheus export.
    pub fn format_prometheus(&self) -> String {
        let type_str = match self.metric_type {
            MetricType::Counter => "counter",
            MetricType::Gauge => "gauge",
            MetricType::Histogram => "histogram",
        };

        format!(
            "# HELP {} {}\n# TYPE {} {}\n{} {}\n",
            self.name,
            self.help,
            self.name,
            type_str,
            self.name,
            self.get()
        )
    }
}

/// Server metrics collection.
pub struct ServerMetrics {
    // Connection metrics
    /// Total handshakes initiated.
    pub handshakes_total: Metric,
    /// Successful handshakes.
    pub handshakes_success: Metric,
    /// Failed handshakes.
    pub handshakes_failed: Metric,
    /// Active sessions (gauge).
    pub sessions_active: Metric,
    /// Total sessions created.
    pub sessions_total: Metric,
    /// Sessions timed out.
    pub sessions_timeout: Metric,

    // Traffic metrics
    /// Total bytes received from clients.
    pub bytes_received: Metric,
    /// Total bytes sent to clients.
    pub bytes_sent: Metric,
    /// Total packets received.
    pub packets_received: Metric,
    /// Total packets sent.
    pub packets_sent: Metric,
    /// Packets dropped (invalid, replay, etc.).
    pub packets_dropped: Metric,

    // Error metrics
    /// Decryption failures.
    pub decryption_errors: Metric,
    /// Invalid packets (bad header, etc.).
    pub invalid_packets: Metric,
    /// Anti-replay rejections.
    pub replay_rejections: Metric,
    /// Handshakes rejected by rate limiting.
    pub handshakes_rate_limited: Metric,
    /// Session packets rejected by per-session rate limiting.
    pub session_rate_limited: Metric,
    /// Packets dropped because the source address did not match the
    /// session-bound `client_addr` after AEAD success (FIX-010).
    ///
    /// Distinct from `packets_dropped` so operators can alert on a real
    /// capture+spoof attempt against an established session without the
    /// signal getting drowned in generic drops (rate limits, malformed
    /// packets, source-IP-mismatch with the inner tunnel address, etc.).
    pub address_mismatch_drops: Metric,
    /// Authentications refused due to a (username, ip) tuple lockout.
    ///
    /// Triggered after 10 failed attempts in a 1-hour window from the same
    /// `(username, source-ip)` pair. Cleared on a successful login from the
    /// same pair. Does not lock other IPs against the same username.
    pub auth_lockout_tuple_total: Metric,
    /// Authentications refused due to a per-IP cross-username ban.
    ///
    /// Triggered after 100 failed attempts in a 1-hour window from the same
    /// source IP, regardless of the username tried. Catches drive-by
    /// brute-force from a single host enumerating accounts.
    pub auth_lockout_ip_total: Metric,
    /// Authentications refused due to a global username spread lock.
    ///
    /// Triggered after >=20 failed attempts from >=5 distinct IPs against
    /// the same username inside a 24-hour rolling window. Catches
    /// distributed brute-force without giving a single attacker a cheap
    /// account-DoS primitive.
    pub auth_lockout_username_total: Metric,

    // Performance metrics
    /// Rekey operations.
    pub rekeys_total: Metric,
    /// Control messages processed.
    pub control_messages: Metric,
    /// Keepalives received.
    pub keepalives_received: Metric,

    // Worker health metrics
    /// Total worker panics.
    pub worker_panics_total: Metric,
    /// Current degraded mode flag (1 = degraded, 0 = healthy).
    pub degraded_mode: Metric,
    /// Worker restarts attempted.
    pub worker_restarts_total: Metric,

    // Histogram for latency (stored as distribution buckets)
    latency_buckets: RwLock<LatencyHistogram>,

    // Server start time
    start_time: Instant,
}

impl ServerMetrics {
    /// Create a new metrics instance.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            address_mismatch_drops: Metric::counter(
                "hpn_address_mismatch_drops_total",
                "Packets dropped because the source address did not match the session-bound client_addr (FIX-010)",
            ),
            handshakes_total: Metric::counter("hpn_handshakes_total", "Total handshake attempts"),
            handshakes_success: Metric::counter(
                "hpn_handshakes_success_total",
                "Successful handshakes",
            ),
            handshakes_failed: Metric::counter("hpn_handshakes_failed_total", "Failed handshakes"),
            sessions_active: Metric::gauge("hpn_sessions_active", "Currently active sessions"),
            sessions_total: Metric::counter("hpn_sessions_total", "Total sessions created"),
            sessions_timeout: Metric::counter("hpn_sessions_timeout_total", "Sessions timed out"),
            bytes_received: Metric::counter(
                "hpn_bytes_received_total",
                "Total bytes received from clients",
            ),
            bytes_sent: Metric::counter("hpn_bytes_sent_total", "Total bytes sent to clients"),
            packets_received: Metric::counter(
                "hpn_packets_received_total",
                "Total packets received",
            ),
            packets_sent: Metric::counter("hpn_packets_sent_total", "Total packets sent"),
            packets_dropped: Metric::counter("hpn_packets_dropped_total", "Packets dropped"),
            decryption_errors: Metric::counter(
                "hpn_decryption_errors_total",
                "Decryption failures",
            ),
            invalid_packets: Metric::counter(
                "hpn_invalid_packets_total",
                "Invalid packets (bad header, etc.)",
            ),
            replay_rejections: Metric::counter(
                "hpn_replay_rejections_total",
                "Anti-replay rejections",
            ),
            handshakes_rate_limited: Metric::counter(
                "hpn_handshakes_rate_limited_total",
                "Handshakes rejected by rate limiting",
            ),
            session_rate_limited: Metric::counter(
                "hpn_session_rate_limited_total",
                "Session packets rejected by per-session rate limiting",
            ),
            auth_lockout_tuple_total: Metric::counter(
                "hpn_auth_lockout_tuple_total",
                "Auth attempts refused due to a (username, ip) tuple lockout",
            ),
            auth_lockout_ip_total: Metric::counter(
                "hpn_auth_lockout_ip_total",
                "Auth attempts refused due to a per-IP cross-username ban",
            ),
            auth_lockout_username_total: Metric::counter(
                "hpn_auth_lockout_username_total",
                "Auth attempts refused due to a global username spread lock",
            ),
            rekeys_total: Metric::counter("hpn_rekeys_total", "Total rekey operations"),
            control_messages: Metric::counter(
                "hpn_control_messages_total",
                "Control messages processed",
            ),
            keepalives_received: Metric::counter("hpn_keepalives_total", "Keepalives received"),
            worker_panics_total: Metric::counter(
                "hpn_worker_panics_total",
                "Total worker thread panics",
            ),
            degraded_mode: Metric::gauge(
                "hpn_degraded_mode",
                "Server degraded mode (1=degraded, 0=healthy)",
            ),
            worker_restarts_total: Metric::counter(
                "hpn_worker_restarts_total",
                "Worker restart attempts",
            ),
            latency_buckets: RwLock::new(LatencyHistogram::new()),
            start_time: Instant::now(),
        })
    }

    /// Record a handshake attempt.
    pub fn record_handshake(&self, success: bool) {
        self.handshakes_total.inc();
        if success {
            self.handshakes_success.inc();
        } else {
            self.handshakes_failed.inc();
        }
    }

    /// Record a new session.
    pub fn record_session_created(&self) {
        self.sessions_total.inc();
        self.sessions_active.inc();
    }

    /// Record a session ended.
    pub fn record_session_ended(&self, timeout: bool) {
        self.sessions_active.dec();
        if timeout {
            self.sessions_timeout.inc();
        }
    }

    /// Record bytes sent/received.
    pub fn record_bytes(&self, sent: u64, received: u64) {
        self.bytes_sent.inc_by(sent);
        self.bytes_received.inc_by(received);
    }

    /// Record packets sent/received.
    pub fn record_packets(&self, sent: u64, received: u64) {
        self.packets_sent.inc_by(sent);
        self.packets_received.inc_by(received);
    }

    /// Record a packet drop.
    pub fn record_packet_drop(&self) {
        self.packets_dropped.inc();
    }

    /// Record a decryption error.
    pub fn record_decryption_error(&self) {
        self.decryption_errors.inc();
    }

    /// Record an invalid packet.
    pub fn record_invalid_packet(&self) {
        self.invalid_packets.inc();
    }

    /// Record a replay rejection.
    pub fn record_replay_rejection(&self) {
        self.replay_rejections.inc();
    }

    /// Record a rate-limited handshake.
    pub fn record_rate_limited(&self) {
        self.handshakes_rate_limited.inc();
    }

    /// Record a session rate-limited packet.
    pub fn record_session_rate_limited(&self) {
        self.session_rate_limited.inc();
    }

    /// Record a packet dropped because its source address did not match
    /// the session-bound `client_addr` after AEAD success (FIX-010).
    ///
    /// Also increments `packets_dropped` so the legacy "total drops"
    /// alert keeps working unchanged. Operators alert on this counter
    /// specifically when they want to distinguish a capture+spoof
    /// attempt from generic noise.
    pub fn record_address_mismatch_drop(&self) {
        self.address_mismatch_drops.inc();
        self.packets_dropped.inc();
    }

    /// Record an authentication lockout that fired.
    ///
    /// Called from the handshake auth path when
    /// [`AuthLockoutTracker::check_lockout`] returns `Some(kind)` (the
    /// attempt is refused before Argon2 verification) or when
    /// [`AuthLockoutTracker::record_failure`] reports that this failure
    /// crossed a threshold and triggered a fresh lock.
    ///
    /// [`AuthLockoutTracker::check_lockout`]: crate::auth_lockout::AuthLockoutTracker::check_lockout
    /// [`AuthLockoutTracker::record_failure`]: crate::auth_lockout::AuthLockoutTracker::record_failure
    pub fn record_auth_lockout(&self, kind: crate::auth_lockout::LockoutKind) {
        match kind {
            crate::auth_lockout::LockoutKind::Tuple => self.auth_lockout_tuple_total.inc(),
            crate::auth_lockout::LockoutKind::Ip => self.auth_lockout_ip_total.inc(),
            crate::auth_lockout::LockoutKind::UsernameSpread => {
                self.auth_lockout_username_total.inc();
            }
        }
    }

    /// Record a rekey.
    pub fn record_rekey(&self) {
        self.rekeys_total.inc();
    }

    /// Record a control message.
    pub fn record_control_message(&self) {
        self.control_messages.inc();
    }

    /// Record a keepalive.
    pub fn record_keepalive(&self) {
        self.keepalives_received.inc();
    }

    /// Record a worker panic.
    ///
    /// Returns the new total panic count.
    pub fn record_worker_panic(&self) -> u64 {
        self.worker_panics_total.inc();
        self.worker_panics_total.get()
    }

    /// Set degraded mode flag.
    pub fn set_degraded_mode(&self, degraded: bool) {
        self.degraded_mode.set(u64::from(degraded));
    }

    /// Check if server is in degraded mode.
    pub fn is_degraded(&self) -> bool {
        self.degraded_mode.get() != 0
    }

    /// Record a worker restart attempt.
    pub fn record_worker_restart(&self) {
        self.worker_restarts_total.inc();
    }

    /// Get worker panic count.
    pub fn worker_panic_count(&self) -> u64 {
        self.worker_panics_total.get()
    }

    /// Record latency in milliseconds.
    pub fn record_latency_ms(&self, latency_ms: u64) {
        self.latency_buckets.write().record(latency_ms);
    }

    /// Get uptime in seconds.
    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Export all metrics in Prometheus format.
    pub fn export_prometheus(&self) -> String {
        let mut output = String::new();

        // Server info
        output.push_str(&format!(
            "# HELP hpn_uptime_seconds Server uptime in seconds\n\
             # TYPE hpn_uptime_seconds counter\n\
             hpn_uptime_seconds {}\n\n",
            self.uptime_secs()
        ));

        // Connection metrics
        output.push_str(&self.handshakes_total.format_prometheus());
        output.push_str(&self.handshakes_success.format_prometheus());
        output.push_str(&self.handshakes_failed.format_prometheus());
        output.push_str(&self.sessions_active.format_prometheus());
        output.push_str(&self.sessions_total.format_prometheus());
        output.push_str(&self.sessions_timeout.format_prometheus());

        // Traffic metrics
        output.push_str(&self.bytes_received.format_prometheus());
        output.push_str(&self.bytes_sent.format_prometheus());
        output.push_str(&self.packets_received.format_prometheus());
        output.push_str(&self.packets_sent.format_prometheus());
        output.push_str(&self.packets_dropped.format_prometheus());

        // Error metrics
        output.push_str(&self.decryption_errors.format_prometheus());
        output.push_str(&self.invalid_packets.format_prometheus());
        output.push_str(&self.replay_rejections.format_prometheus());
        output.push_str(&self.handshakes_rate_limited.format_prometheus());
        output.push_str(&self.session_rate_limited.format_prometheus());
        output.push_str(&self.address_mismatch_drops.format_prometheus());
        output.push_str(&self.auth_lockout_tuple_total.format_prometheus());
        output.push_str(&self.auth_lockout_ip_total.format_prometheus());
        output.push_str(&self.auth_lockout_username_total.format_prometheus());

        // Performance metrics
        output.push_str(&self.rekeys_total.format_prometheus());
        output.push_str(&self.control_messages.format_prometheus());
        output.push_str(&self.keepalives_received.format_prometheus());

        // Worker health metrics
        output.push_str(&self.worker_panics_total.format_prometheus());
        output.push_str(&self.degraded_mode.format_prometheus());
        output.push_str(&self.worker_restarts_total.format_prometheus());

        // Latency histogram
        output.push_str(&self.latency_buckets.read().format_prometheus());

        output
    }

    /// Get a summary of metrics for logging.
    pub fn summary(&self) -> MetricsSummary {
        MetricsSummary {
            uptime_secs: self.uptime_secs(),
            sessions_active: self.sessions_active.get(),
            sessions_total: self.sessions_total.get(),
            bytes_sent: self.bytes_sent.get(),
            bytes_received: self.bytes_received.get(),
            packets_sent: self.packets_sent.get(),
            packets_received: self.packets_received.get(),
            packets_dropped: self.packets_dropped.get(),
            decryption_errors: self.decryption_errors.get(),
            handshakes_success: self.handshakes_success.get(),
            handshakes_failed: self.handshakes_failed.get(),
        }
    }
}

impl Default for ServerMetrics {
    fn default() -> Self {
        Arc::try_unwrap(Self::new()).unwrap_or_else(|arc| {
            // This shouldn't happen, but handle it gracefully
            (*arc).clone_inner()
        })
    }
}

impl ServerMetrics {
    fn clone_inner(&self) -> Self {
        Self {
            handshakes_total: Metric::counter("hpn_handshakes_total", "Total handshake attempts"),
            handshakes_success: Metric::counter(
                "hpn_handshakes_success_total",
                "Successful handshakes",
            ),
            handshakes_failed: Metric::counter("hpn_handshakes_failed_total", "Failed handshakes"),
            sessions_active: Metric::gauge("hpn_sessions_active", "Currently active sessions"),
            sessions_total: Metric::counter("hpn_sessions_total", "Total sessions created"),
            sessions_timeout: Metric::counter("hpn_sessions_timeout_total", "Sessions timed out"),
            bytes_received: Metric::counter(
                "hpn_bytes_received_total",
                "Total bytes received from clients",
            ),
            bytes_sent: Metric::counter("hpn_bytes_sent_total", "Total bytes sent to clients"),
            packets_received: Metric::counter(
                "hpn_packets_received_total",
                "Total packets received",
            ),
            packets_sent: Metric::counter("hpn_packets_sent_total", "Total packets sent"),
            packets_dropped: Metric::counter("hpn_packets_dropped_total", "Packets dropped"),
            decryption_errors: Metric::counter(
                "hpn_decryption_errors_total",
                "Decryption failures",
            ),
            invalid_packets: Metric::counter(
                "hpn_invalid_packets_total",
                "Invalid packets (bad header, etc.)",
            ),
            replay_rejections: Metric::counter(
                "hpn_replay_rejections_total",
                "Anti-replay rejections",
            ),
            handshakes_rate_limited: Metric::counter(
                "hpn_handshakes_rate_limited_total",
                "Handshakes rejected by rate limiting",
            ),
            session_rate_limited: Metric::counter(
                "hpn_session_rate_limited_total",
                "Session packets rejected by per-session rate limiting",
            ),
            address_mismatch_drops: Metric::counter(
                "hpn_address_mismatch_drops_total",
                "Packets dropped because the source address did not match the session-bound client_addr (FIX-010)",
            ),
            auth_lockout_tuple_total: Metric::counter(
                "hpn_auth_lockout_tuple_total",
                "Auth attempts refused due to a (username, ip) tuple lockout",
            ),
            auth_lockout_ip_total: Metric::counter(
                "hpn_auth_lockout_ip_total",
                "Auth attempts refused due to a per-IP cross-username ban",
            ),
            auth_lockout_username_total: Metric::counter(
                "hpn_auth_lockout_username_total",
                "Auth attempts refused due to a global username spread lock",
            ),
            rekeys_total: Metric::counter("hpn_rekeys_total", "Total rekey operations"),
            control_messages: Metric::counter(
                "hpn_control_messages_total",
                "Control messages processed",
            ),
            keepalives_received: Metric::counter("hpn_keepalives_total", "Keepalives received"),
            worker_panics_total: Metric::counter(
                "hpn_worker_panics_total",
                "Total worker thread panics",
            ),
            degraded_mode: Metric::gauge(
                "hpn_degraded_mode",
                "Server degraded mode (1=degraded, 0=healthy)",
            ),
            worker_restarts_total: Metric::counter(
                "hpn_worker_restarts_total",
                "Worker restart attempts",
            ),
            latency_buckets: RwLock::new(LatencyHistogram::new()),
            start_time: Instant::now(),
        }
    }
}

/// Metrics summary for logging.
#[derive(Clone, Debug)]
pub struct MetricsSummary {
    pub uptime_secs: u64,
    pub sessions_active: u64,
    pub sessions_total: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub packets_dropped: u64,
    pub decryption_errors: u64,
    pub handshakes_success: u64,
    pub handshakes_failed: u64,
}

impl MetricsSummary {
    /// Format for structured logging.
    pub fn format(&self) -> String {
        format!(
            "uptime={}s sessions={}/{} bytes_tx={} bytes_rx={} pkts_tx={} pkts_rx={} pkts_drop={} decrypt_err={} hs_ok={} hs_fail={}",
            self.uptime_secs,
            self.sessions_active,
            self.sessions_total,
            format_bytes(self.bytes_sent),
            format_bytes(self.bytes_received),
            self.packets_sent,
            self.packets_received,
            self.packets_dropped,
            self.decryption_errors,
            self.handshakes_success,
            self.handshakes_failed
        )
    }
}

/// Latency histogram with buckets.
///
/// Layout:
/// * `buckets[i]` is the upper bound (inclusive) of bucket `i`, in ms.
/// * `counts[i]` is the count of observations falling into `(buckets[i-1], buckets[i]]`.
/// * `overflow` is the count of observations strictly greater than the
///   largest bucket. Kept SEPARATE from `counts.last()` so the
///   `le="<largest>"` Prometheus bucket does not falsely include
///   overflow values, and so the `le="+Inf"` bucket is computed correctly
///   as `cumulative + overflow` instead of double-counting `counts.last()`.
struct LatencyHistogram {
    /// Bucket boundaries in milliseconds.
    buckets: Vec<u64>,
    /// Counts per bucket.
    counts: Vec<AtomicU64>,
    /// Count of observations exceeding the largest bucket boundary.
    overflow: AtomicU64,
    /// Sum of all observed values.
    sum: AtomicU64,
    /// Total observations.
    count: AtomicU64,
}

impl LatencyHistogram {
    /// Create with default buckets.
    fn new() -> Self {
        // Buckets: 1ms, 5ms, 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1000ms, +Inf
        let buckets = vec![1, 5, 10, 25, 50, 100, 250, 500, 1000];
        let counts = buckets.iter().map(|_| AtomicU64::new(0)).collect();

        Self {
            buckets,
            counts,
            overflow: AtomicU64::new(0),
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    /// Record a latency value.
    fn record(&self, value_ms: u64) {
        self.sum.fetch_add(value_ms, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);

        // Find the appropriate bucket
        for (i, &boundary) in self.buckets.iter().enumerate() {
            if value_ms <= boundary {
                self.counts[i].fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        // Value exceeds the largest bucket — track separately so the
        // `le="<largest>"` bucket reports an honest "values ≤ largest"
        // count and the `le="+Inf"` bucket adds these on top.
        self.overflow.fetch_add(1, Ordering::Relaxed);
    }

    /// Format for Prometheus.
    fn format_prometheus(&self) -> String {
        let mut output = String::new();
        output.push_str(
            "# HELP hpn_request_latency_ms Request latency in milliseconds\n\
             # TYPE hpn_request_latency_ms histogram\n",
        );

        let mut cumulative = 0u64;
        for (i, &boundary) in self.buckets.iter().enumerate() {
            cumulative += self.counts[i].load(Ordering::Relaxed);
            output.push_str(&format!(
                "hpn_request_latency_ms_bucket{{le=\"{}\"}} {}\n",
                boundary, cumulative
            ));
        }

        // +Inf bucket = everything in `counts` (the cumulative loop above)
        // PLUS the overflow counter. Previously this added `counts.last()`
        // a second time, producing a double-count.
        cumulative += self.overflow.load(Ordering::Relaxed);
        output.push_str(&format!(
            "hpn_request_latency_ms_bucket{{le=\"+Inf\"}} {}\n",
            cumulative
        ));

        output.push_str(&format!(
            "hpn_request_latency_ms_sum {}\n",
            self.sum.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "hpn_request_latency_ms_count {}\n",
            self.count.load(Ordering::Relaxed)
        ));

        output
    }
}

/// Format bytes as human-readable string.
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2}GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2}MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2}KB", bytes as f64 / KB as f64)
    } else {
        format!("{}B", bytes)
    }
}

/// Periodic metrics reporter.
pub struct MetricsReporter {
    metrics: Arc<ServerMetrics>,
    interval: Duration,
}

impl MetricsReporter {
    /// Create a new metrics reporter.
    pub fn new(metrics: Arc<ServerMetrics>, interval: Duration) -> Self {
        Self { metrics, interval }
    }

    /// Start periodic reporting.
    pub async fn run(&self) {
        let mut interval = tokio::time::interval(self.interval);

        loop {
            interval.tick().await;
            let summary = self.metrics.summary();
            info!(
                target: "hpn_metrics",
                uptime_secs = summary.uptime_secs,
                sessions_active = summary.sessions_active,
                sessions_total = summary.sessions_total,
                bytes_sent = summary.bytes_sent,
                bytes_received = summary.bytes_received,
                packets_sent = summary.packets_sent,
                packets_received = summary.packets_received,
                "Server metrics"
            );
            debug!("Metrics: {}", summary.format());
        }
    }
}

/// HTTP server for metrics endpoint.
///
/// Exposes a `/metrics` endpoint for Prometheus scraping.
pub struct MetricsHttpServer {
    metrics: Arc<ServerMetrics>,
    addr: SocketAddr,
}

impl MetricsHttpServer {
    /// Create a new metrics HTTP server.
    pub fn new(metrics: Arc<ServerMetrics>, addr: SocketAddr) -> Self {
        Self { metrics, addr }
    }

    /// Run the HTTP server.
    ///
    /// This will block until shutdown is signaled.
    pub async fn run(&self) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.addr).await?;
        info!(
            "Metrics HTTP server listening on http://{}/metrics",
            self.addr
        );

        loop {
            let (stream, remote_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    warn!("Failed to accept connection: {}", e);
                    continue;
                }
            };

            let metrics = Arc::clone(&self.metrics);
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let service = service_fn(move |req| {
                    let metrics = Arc::clone(&metrics);
                    async move { handle_request(req, metrics).await }
                });

                if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                    debug!("HTTP connection error from {}: {}", remote_addr, e);
                }
            });
        }
    }

    /// Run the HTTP server with shutdown support.
    pub async fn run_with_shutdown(
        &self,
        mut shutdown: tokio::sync::broadcast::Receiver<()>,
    ) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.addr).await?;
        info!(
            "Metrics HTTP server listening on http://{}/metrics",
            self.addr
        );

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, remote_addr)) => {
                            let metrics = Arc::clone(&self.metrics);
                            tokio::spawn(async move {
                                let io = TokioIo::new(stream);
                                let service = service_fn(move |req| {
                                    let metrics = Arc::clone(&metrics);
                                    async move { handle_request(req, metrics).await }
                                });

                                if let Err(e) = http1::Builder::new()
                                    .serve_connection(io, service)
                                    .await
                                {
                                    debug!("HTTP connection error from {}: {}", remote_addr, e);
                                }
                            });
                        }
                        Err(e) => {
                            warn!("Failed to accept connection: {}", e);
                        }
                    }
                }
                _ = shutdown.recv() => {
                    info!("Metrics HTTP server shutting down");
                    break;
                }
            }
        }

        Ok(())
    }
}

/// Handle an HTTP request.
async fn handle_request(
    req: Request<hyper::body::Incoming>,
    metrics: Arc<ServerMetrics>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let response = match (req.method(), req.uri().path()) {
        (&Method::GET, "/metrics") => {
            let body = metrics.export_prometheus();
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
                .body(Full::new(Bytes::from(body)))
                .unwrap()
        }
        (&Method::GET, "/health") => Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/plain")
            .body(Full::new(Bytes::from("OK")))
            .unwrap(),
        (&Method::GET, "/") => {
            let body = r#"<!DOCTYPE html>
<html>
<head><title>HPN VPN Server Metrics</title></head>
<body>
<h1>HPN VPN Server</h1>
<p><a href="/metrics">Prometheus Metrics</a></p>
<p><a href="/health">Health Check</a></p>
</body>
</html>"#;
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/html")
                .body(Full::new(Bytes::from(body)))
                .unwrap()
        }
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("Not Found")))
            .unwrap(),
    };

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metric_counter() {
        let metric = Metric::counter("test_counter", "A test counter");
        assert_eq!(metric.get(), 0);

        metric.inc();
        assert_eq!(metric.get(), 1);

        metric.inc_by(5);
        assert_eq!(metric.get(), 6);
    }

    #[test]
    fn test_metric_gauge() {
        let metric = Metric::gauge("test_gauge", "A test gauge");
        assert_eq!(metric.get(), 0);

        metric.set(100);
        assert_eq!(metric.get(), 100);

        metric.dec();
        assert_eq!(metric.get(), 99);
    }

    #[test]
    fn test_server_metrics() {
        let metrics = ServerMetrics::new();

        metrics.record_handshake(true);
        metrics.record_handshake(false);
        metrics.record_session_created();
        metrics.record_bytes(1000, 2000);

        let summary = metrics.summary();
        assert_eq!(summary.handshakes_success, 1);
        assert_eq!(summary.handshakes_failed, 1);
        assert_eq!(summary.sessions_active, 1);
        assert_eq!(summary.bytes_sent, 1000);
        assert_eq!(summary.bytes_received, 2000);
    }

    #[test]
    fn test_prometheus_export() {
        let metrics = ServerMetrics::new();
        metrics.record_handshake(true);
        metrics.record_session_created();

        let output = metrics.export_prometheus();
        assert!(output.contains("hpn_handshakes_total"));
        assert!(output.contains("hpn_sessions_active"));
    }

    #[test]
    fn test_latency_histogram() {
        let histogram = LatencyHistogram::new();

        histogram.record(5);
        histogram.record(50);
        histogram.record(500);

        assert_eq!(histogram.count.load(Ordering::Relaxed), 3);
        assert_eq!(histogram.sum.load(Ordering::Relaxed), 555);
    }

    #[test]
    fn test_histogram_buckets_concurrent() {
        // BUSINESS LOGIC TEST: Histogram bucket aggregation under concurrent load
        // This test validates:
        // - Latency histogram correctly categorizes values into buckets
        // - Concurrent metric recording is thread-safe (no lost updates)
        // - Bucket boundaries are accurate (1ms, 5ms, 10ms, etc.)
        // - Sum and count aggregation is accurate under load
        // - Prometheus format output is correct

        use std::sync::Arc;
        use std::thread;

        let metrics = ServerMetrics::new();

        // Record latencies from multiple threads concurrently
        const NUM_THREADS: usize = 10;
        const RECORDS_PER_THREAD: usize = 100;

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|thread_id| {
                let metrics_clone = Arc::clone(&metrics);
                thread::spawn(move || {
                    for i in 0..RECORDS_PER_THREAD {
                        // Distribute latencies across different buckets
                        let latency = match (thread_id + i) % 10 {
                            0 => 1,    // 1ms bucket
                            1 => 3,    // 5ms bucket (3 <= 5)
                            2 => 8,    // 10ms bucket (8 <= 10)
                            3 => 20,   // 25ms bucket
                            4 => 40,   // 50ms bucket
                            5 => 80,   // 100ms bucket
                            6 => 200,  // 250ms bucket
                            7 => 400,  // 500ms bucket
                            8 => 800,  // 1000ms bucket
                            9 => 2000, // +Inf bucket
                            _ => unreachable!(),
                        };
                        metrics_clone.record_latency_ms(latency);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        // Verify total count
        let histogram = metrics.latency_buckets.read();
        let total_count = histogram.count.load(Ordering::Relaxed);
        assert_eq!(
            total_count,
            (NUM_THREADS * RECORDS_PER_THREAD) as u64,
            "Total count should match number of recorded latencies"
        );

        // Verify sum (each thread records same pattern, so calculate expected sum)
        let expected_sum_per_cycle = 1u64 + 3 + 8 + 20 + 40 + 80 + 200 + 400 + 800 + 2000; // 3552
        let total_cycles = (NUM_THREADS * RECORDS_PER_THREAD) / 10;
        let expected_sum = expected_sum_per_cycle * total_cycles as u64;
        let actual_sum = histogram.sum.load(Ordering::Relaxed);
        assert_eq!(
            actual_sum, expected_sum,
            "Sum should match total of all recorded latencies"
        );

        // Verify bucket distribution. After METRICS-2 the histogram tracks
        // overflow values (>1000ms here) in a SEPARATE counter rather than
        // double-counting them into the largest bucket. Each of the 10
        // sample latencies (1, 3, 8, 20, 40, 80, 200, 400, 800, 2000)
        // therefore lands in exactly one slot — 9 in `counts[]`, the
        // 2000 ms value in `overflow`. Each slot then holds ~100 samples.
        let expected_per_bucket = (NUM_THREADS * RECORDS_PER_THREAD) / 10;
        for (i, count_atomic) in histogram.counts.iter().enumerate() {
            let count = count_atomic.load(Ordering::Relaxed);
            let expected_min = expected_per_bucket as u64 * 9 / 10;
            let expected_max = expected_per_bucket as u64 * 11 / 10;
            assert!(
                count >= expected_min && count <= expected_max,
                "Bucket {} should have ~{} samples (expected {}-{}), got {}",
                i,
                expected_per_bucket,
                expected_min,
                expected_max,
                count
            );
        }
        let overflow_count = histogram.overflow.load(Ordering::Relaxed);
        let expected_min = expected_per_bucket as u64 * 9 / 10;
        let expected_max = expected_per_bucket as u64 * 11 / 10;
        assert!(
            overflow_count >= expected_min && overflow_count <= expected_max,
            "Overflow bucket should have ~{} samples (the 2000 ms values), \
             expected {}-{}, got {}",
            expected_per_bucket,
            expected_min,
            expected_max,
            overflow_count
        );

        // Verify Prometheus format output contains expected elements
        let prometheus_output = histogram.format_prometheus();
        assert!(
            prometheus_output.contains("hpn_request_latency_ms_bucket"),
            "Output should contain bucket metric"
        );
        assert!(
            prometheus_output.contains("hpn_request_latency_ms_sum"),
            "Output should contain sum metric"
        );
        assert!(
            prometheus_output.contains("hpn_request_latency_ms_count"),
            "Output should contain count metric"
        );
        assert!(
            prometheus_output.contains("le=\"+Inf\""),
            "Output should contain +Inf bucket"
        );

        // Verify cumulative buckets are monotonically increasing
        let lines: Vec<&str> = prometheus_output.lines().collect();
        let bucket_lines: Vec<&str> = lines
            .iter()
            .filter(|l| l.contains("_bucket"))
            .copied()
            .collect();

        let mut prev_count = 0u64;
        for line in bucket_lines {
            if let Some(count_str) = line.split_whitespace().last() {
                let count: u64 = count_str.parse().unwrap_or(0);
                assert!(
                    count >= prev_count,
                    "Cumulative bucket counts should be monotonically increasing"
                );
                prev_count = count;
            }
        }
    }

    #[test]
    fn test_concurrent_metric_updates() {
        // BUSINESS LOGIC TEST: Concurrent metric updates (counters and gauges)
        // This test validates:
        // - Atomic counter increments don't lose updates
        // - Gauge set/inc/dec operations are thread-safe
        // - Multiple metrics can be updated concurrently
        // - Final values match expected totals

        use std::sync::Arc;
        use std::thread;

        let metrics = ServerMetrics::new();

        const NUM_THREADS: usize = 20;
        const OPS_PER_THREAD: usize = 500;

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|_| {
                let metrics_clone = Arc::clone(&metrics);
                thread::spawn(move || {
                    for _ in 0..OPS_PER_THREAD {
                        // Mix of different metric operations
                        metrics_clone.record_handshake(true);
                        metrics_clone.record_bytes(1500, 100);
                        metrics_clone.record_packets(1, 1);
                        metrics_clone.record_session_created();
                        metrics_clone.record_session_ended(false);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        // Verify final counts
        let summary = metrics.summary();
        let expected_ops = (NUM_THREADS * OPS_PER_THREAD) as u64;

        assert_eq!(
            summary.handshakes_success, expected_ops,
            "Handshake success count mismatch"
        );
        assert_eq!(
            summary.bytes_sent,
            expected_ops * 1500,
            "Bytes sent count mismatch"
        );
        assert_eq!(
            summary.bytes_received,
            expected_ops * 100,
            "Bytes received count mismatch"
        );
        assert_eq!(
            summary.packets_sent, expected_ops,
            "Packets sent count mismatch"
        );
        assert_eq!(
            summary.packets_received, expected_ops,
            "Packets received count mismatch"
        );
        assert_eq!(
            summary.sessions_total, expected_ops,
            "Sessions total count mismatch"
        );

        // Gauge should be 0 (equal inc/dec)
        assert_eq!(
            summary.sessions_active, 0,
            "Active sessions gauge should be 0 (equal creates/ends)"
        );
    }

    #[test]
    fn test_metric_type_display() {
        assert_eq!(MetricType::Counter, MetricType::Counter);
        assert_eq!(MetricType::Gauge, MetricType::Gauge);
        assert_eq!(MetricType::Histogram, MetricType::Histogram);
        assert_ne!(MetricType::Counter, MetricType::Gauge);
    }

    #[test]
    fn test_metric_format_prometheus_counter() {
        let metric = Metric::counter("test_requests_total", "Total requests");
        metric.inc_by(42);

        let output = metric.format_prometheus();
        assert!(output.contains("# HELP test_requests_total Total requests"));
        assert!(output.contains("# TYPE test_requests_total counter"));
        assert!(output.contains("test_requests_total 42"));
    }

    #[test]
    fn test_metric_format_prometheus_gauge() {
        let metric = Metric::gauge("test_connections", "Active connections");
        metric.set(10);

        let output = metric.format_prometheus();
        assert!(output.contains("# HELP test_connections Active connections"));
        assert!(output.contains("# TYPE test_connections gauge"));
        assert!(output.contains("test_connections 10"));
    }

    #[test]
    fn test_metric_counter_overflow_safe() {
        let metric = Metric::counter("overflow_test", "Test overflow");

        // Set close to max
        metric.set(u64::MAX - 10);
        assert_eq!(metric.get(), u64::MAX - 10);

        // Increment should wrap (atomic wrapping behavior)
        metric.inc_by(20);
        // After overflow, value wraps around
        assert!(metric.get() < 20);
    }

    #[test]
    fn test_metric_gauge_dec_from_zero() {
        let metric = Metric::gauge("gauge_underflow", "Test underflow");
        assert_eq!(metric.get(), 0);

        // Decrement from 0 should saturate at 0 (not wrap)
        metric.dec();
        assert_eq!(metric.get(), 0);
    }

    #[test]
    fn test_server_metrics_record_session_lifecycle() {
        let metrics = ServerMetrics::new();

        // Create session
        metrics.record_session_created();
        assert_eq!(metrics.sessions_active.get(), 1);
        assert_eq!(metrics.sessions_total.get(), 1);

        // Create another
        metrics.record_session_created();
        assert_eq!(metrics.sessions_active.get(), 2);
        assert_eq!(metrics.sessions_total.get(), 2);

        // End one (not a timeout)
        metrics.record_session_ended(false);
        assert_eq!(metrics.sessions_active.get(), 1);
        assert_eq!(metrics.sessions_total.get(), 2);
    }

    #[test]
    fn test_server_metrics_record_packets() {
        let metrics = ServerMetrics::new();

        metrics.record_packets(5, 10);

        assert_eq!(metrics.packets_sent.get(), 5);
        assert_eq!(metrics.packets_received.get(), 10);
    }

    #[test]
    fn test_server_metrics_record_packet_drop() {
        let metrics = ServerMetrics::new();

        metrics.record_packet_drop();
        metrics.record_packet_drop();

        assert_eq!(metrics.packets_dropped.get(), 2);
    }

    #[test]
    fn test_server_metrics_record_errors() {
        let metrics = ServerMetrics::new();

        metrics.record_decryption_error();
        metrics.record_invalid_packet();
        metrics.record_replay_rejection();

        assert_eq!(metrics.decryption_errors.get(), 1);
        assert_eq!(metrics.invalid_packets.get(), 1);
        assert_eq!(metrics.replay_rejections.get(), 1);
    }

    #[test]
    fn test_server_metrics_record_rekey() {
        let metrics = ServerMetrics::new();

        metrics.record_rekey();
        metrics.record_rekey();

        assert_eq!(metrics.rekeys_total.get(), 2);
    }

    #[test]
    fn test_server_metrics_record_control_message() {
        let metrics = ServerMetrics::new();

        metrics.record_control_message();

        assert_eq!(metrics.control_messages.get(), 1);
    }

    #[test]
    fn test_server_metrics_record_keepalive() {
        let metrics = ServerMetrics::new();

        metrics.record_keepalive();
        metrics.record_keepalive();
        metrics.record_keepalive();

        assert_eq!(metrics.keepalives_received.get(), 3);
    }

    #[test]
    fn test_server_metrics_record_session_timeout() {
        let metrics = ServerMetrics::new();

        metrics.record_session_created();
        metrics.record_session_ended(true); // timeout=true

        assert_eq!(metrics.sessions_timeout.get(), 1);
    }

    #[test]
    fn test_server_metrics_record_rate_limited() {
        let metrics = ServerMetrics::new();

        metrics.record_rate_limited();

        assert_eq!(metrics.handshakes_rate_limited.get(), 1);
    }

    #[test]
    fn test_latency_histogram_buckets() {
        let histogram = LatencyHistogram::new();

        // Record values in different buckets
        histogram.record(0); // <= 1ms
        histogram.record(1); // <= 1ms
        histogram.record(3); // <= 5ms
        histogram.record(7); // <= 10ms
        histogram.record(20); // <= 25ms
        histogram.record(40); // <= 50ms
        histogram.record(80); // <= 100ms
        histogram.record(200); // <= 250ms
        histogram.record(400); // <= 500ms
        histogram.record(800); // <= 1000ms
        histogram.record(2000); // > 1000ms (inf)

        assert_eq!(histogram.count.load(Ordering::Relaxed), 11);

        // Sum: 0+1+3+7+20+40+80+200+400+800+2000 = 3551
        assert_eq!(histogram.sum.load(Ordering::Relaxed), 3551);
    }

    #[test]
    fn test_latency_histogram_prometheus_format() {
        let histogram = LatencyHistogram::new();

        histogram.record(5);
        histogram.record(50);
        histogram.record(500);

        let output = histogram.format_prometheus();

        assert!(output.contains("# HELP hpn_request_latency_ms"));
        assert!(output.contains("# TYPE hpn_request_latency_ms histogram"));
        assert!(output.contains("hpn_request_latency_ms_sum 555"));
        assert!(output.contains("hpn_request_latency_ms_count 3"));
        assert!(output.contains("le=\"+Inf\""));
    }

    #[test]
    fn test_latency_histogram_empty() {
        let histogram = LatencyHistogram::new();

        assert_eq!(histogram.count.load(Ordering::Relaxed), 0);
        assert_eq!(histogram.sum.load(Ordering::Relaxed), 0);

        let output = histogram.format_prometheus();
        assert!(output.contains("hpn_request_latency_ms_sum 0"));
        assert!(output.contains("hpn_request_latency_ms_count 0"));
    }

    #[test]
    fn test_latency_histogram_max_value() {
        let histogram = LatencyHistogram::new();

        histogram.record(u64::MAX);

        assert_eq!(histogram.count.load(Ordering::Relaxed), 1);
        assert_eq!(histogram.sum.load(Ordering::Relaxed), u64::MAX);
    }

    #[test]
    fn test_server_metrics_summary_structure() {
        let metrics = ServerMetrics::new();

        metrics.record_handshake(true);
        metrics.record_session_created();
        metrics.record_bytes(100, 200);

        let summary = metrics.summary();

        // Verify structure
        assert_eq!(summary.handshakes_success, 1);
        assert_eq!(summary.sessions_active, 1);
        assert_eq!(summary.bytes_sent, 100);
        assert_eq!(summary.bytes_received, 200);
    }

    #[test]
    fn test_server_metrics_export_prometheus_complete() {
        let metrics = ServerMetrics::new();

        // Record various metrics
        metrics.record_handshake(true);
        metrics.record_handshake(false);
        metrics.record_session_created();
        metrics.record_bytes(1000, 2000);
        metrics.record_packets(5, 10);
        metrics.record_decryption_error();

        let output = metrics.export_prometheus();

        // Verify all metrics are present
        assert!(output.contains("hpn_handshakes_total"));
        assert!(output.contains("hpn_handshakes_success_total"));
        assert!(output.contains("hpn_handshakes_failed_total"));
        assert!(output.contains("hpn_sessions_active"));
        assert!(output.contains("hpn_sessions_total"));
        assert!(output.contains("hpn_bytes_sent_total"));
        assert!(output.contains("hpn_bytes_received_total"));
        assert!(output.contains("hpn_packets_sent_total"));
        assert!(output.contains("hpn_packets_received_total"));
        assert!(output.contains("hpn_decryption_errors_total"));
    }

    #[test]
    fn test_metric_concurrent_increments() {
        use std::sync::Arc;
        use std::thread;

        let metric = Arc::new(Metric::counter("concurrent_test", "Test concurrent"));

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let m = Arc::clone(&metric);
                thread::spawn(move || {
                    for _ in 0..100 {
                        m.inc();
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(metric.get(), 1000);
    }
}
