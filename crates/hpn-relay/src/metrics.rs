//! Metrics for HPN relay server.
//!
//! Simplified metrics collection for relay monitoring.
//! Includes HTTP server for Prometheus-compatible metrics export.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

/// Relay metrics collection.
pub struct RelayMetrics {
    /// Total packets forwarded (client → upstream).
    pub packets_forwarded: AtomicU64,
    /// Total packets returned (upstream → client).
    pub packets_returned: AtomicU64,
    /// Total bytes forwarded (client → upstream).
    pub bytes_forwarded: AtomicU64,
    /// Total bytes returned (upstream → client).
    pub bytes_returned: AtomicU64,
    /// Packets dropped (rate limit, invalid, etc.).
    pub packets_dropped: AtomicU64,
    /// Active sessions (approx, updated by session manager).
    pub sessions_active: AtomicU64,
    /// Total sessions created.
    pub sessions_total: AtomicU64,
    /// Upstream health status (1 = healthy, 0 = unhealthy).
    pub upstream_healthy: std::sync::atomic::AtomicBool,
    /// Total upstream health check probes sent.
    pub upstream_probes_total: AtomicU64,
    /// Failed upstream health check probes.
    pub upstream_probes_failed: AtomicU64,
    /// Start time.
    start_time: Instant,
}

impl RelayMetrics {
    /// Create new metrics.
    pub fn new() -> Self {
        Self {
            packets_forwarded: AtomicU64::new(0),
            packets_returned: AtomicU64::new(0),
            bytes_forwarded: AtomicU64::new(0),
            bytes_returned: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            sessions_active: AtomicU64::new(0),
            sessions_total: AtomicU64::new(0),
            upstream_healthy: std::sync::atomic::AtomicBool::new(true),
            upstream_probes_total: AtomicU64::new(0),
            upstream_probes_failed: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }

    /// Record packet forwarded (client → upstream).
    pub fn record_forward(&self, bytes: usize) {
        self.packets_forwarded.fetch_add(1, Ordering::Relaxed);
        self.bytes_forwarded
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Record packet returned (upstream → client).
    pub fn record_return(&self, bytes: usize) {
        self.packets_returned.fetch_add(1, Ordering::Relaxed);
        self.bytes_returned
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Record packet drop.
    pub fn record_drop(&self) {
        self.packets_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Record new session.
    pub fn record_session_created(&self) {
        self.sessions_total.fetch_add(1, Ordering::Relaxed);
        self.sessions_active.fetch_add(1, Ordering::Relaxed);
    }

    /// Record session removed (saturating — never underflows to u64::MAX).
    pub fn record_session_removed(&self) {
        // Use CAS loop instead of fetch_sub to prevent underflow wrapping.
        let mut current = self.sessions_active.load(Ordering::Relaxed);
        loop {
            if current == 0 {
                break;
            }
            match self.sessions_active.compare_exchange_weak(
                current,
                current - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }

    /// Update active sessions count (test-only).
    #[cfg(test)]
    pub fn set_sessions_active(&self, count: usize) {
        self.sessions_active.store(count as u64, Ordering::Relaxed);
    }

    /// Get uptime in seconds.
    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Record upstream health status.
    pub fn set_upstream_healthy(&self, healthy: bool) {
        self.upstream_healthy
            .store(healthy, std::sync::atomic::Ordering::SeqCst);
    }

    /// Record upstream health probe.
    pub fn record_upstream_probe(&self, success: bool) {
        self.upstream_probes_total.fetch_add(1, Ordering::Relaxed);
        if !success {
            self.upstream_probes_failed.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Check if upstream is healthy.
    pub fn is_upstream_healthy(&self) -> bool {
        self.upstream_healthy
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get summary for logging.
    pub fn summary(&self) -> String {
        let upstream_status = if self.is_upstream_healthy() {
            "healthy"
        } else {
            "UNHEALTHY"
        };
        format!(
            "uptime={}s sessions={} fwd={}/{} ret={}/{} drop={} upstream={}",
            self.uptime_secs(),
            self.sessions_active.load(Ordering::Relaxed),
            self.packets_forwarded.load(Ordering::Relaxed),
            self.bytes_forwarded.load(Ordering::Relaxed),
            self.packets_returned.load(Ordering::Relaxed),
            self.bytes_returned.load(Ordering::Relaxed),
            self.packets_dropped.load(Ordering::Relaxed),
            upstream_status,
        )
    }

    /// Export Prometheus metrics.
    pub fn export_prometheus(&self) -> String {
        let upstream_healthy_val = if self.is_upstream_healthy() { 1 } else { 0 };
        format!(
            r#"# HELP hpn_relay_uptime_seconds Relay uptime in seconds
# TYPE hpn_relay_uptime_seconds counter
hpn_relay_uptime_seconds {}

# HELP hpn_relay_sessions_active Currently active relay sessions
# TYPE hpn_relay_sessions_active gauge
hpn_relay_sessions_active {}

# HELP hpn_relay_sessions_total Total relay sessions created
# TYPE hpn_relay_sessions_total counter
hpn_relay_sessions_total {}

# HELP hpn_relay_packets_forwarded_total Packets forwarded to upstream
# TYPE hpn_relay_packets_forwarded_total counter
hpn_relay_packets_forwarded_total {}

# HELP hpn_relay_packets_returned_total Packets returned to clients
# TYPE hpn_relay_packets_returned_total counter
hpn_relay_packets_returned_total {}

# HELP hpn_relay_bytes_forwarded_total Bytes forwarded to upstream
# TYPE hpn_relay_bytes_forwarded_total counter
hpn_relay_bytes_forwarded_total {}

# HELP hpn_relay_bytes_returned_total Bytes returned to clients
# TYPE hpn_relay_bytes_returned_total counter
hpn_relay_bytes_returned_total {}

# HELP hpn_relay_packets_dropped_total Packets dropped (rate limit, invalid)
# TYPE hpn_relay_packets_dropped_total counter
hpn_relay_packets_dropped_total {}

# HELP hpn_relay_upstream_healthy Upstream server health status (1=healthy, 0=unhealthy)
# TYPE hpn_relay_upstream_healthy gauge
hpn_relay_upstream_healthy {}

# HELP hpn_relay_upstream_probes_total Total upstream health probes sent
# TYPE hpn_relay_upstream_probes_total counter
hpn_relay_upstream_probes_total {}

# HELP hpn_relay_upstream_probes_failed_total Failed upstream health probes
# TYPE hpn_relay_upstream_probes_failed_total counter
hpn_relay_upstream_probes_failed_total {}
"#,
            self.uptime_secs(),
            self.sessions_active.load(Ordering::Relaxed),
            self.sessions_total.load(Ordering::Relaxed),
            self.packets_forwarded.load(Ordering::Relaxed),
            self.packets_returned.load(Ordering::Relaxed),
            self.bytes_forwarded.load(Ordering::Relaxed),
            self.bytes_returned.load(Ordering::Relaxed),
            self.packets_dropped.load(Ordering::Relaxed),
            upstream_healthy_val,
            self.upstream_probes_total.load(Ordering::Relaxed),
            self.upstream_probes_failed.load(Ordering::Relaxed),
        )
    }
}

impl Default for RelayMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Constant-time byte-slice comparison for auth-token verification.
/// Prevents timing side-channels that could leak the expected token one
/// character at a time under network load.
#[inline]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// HTTP server for metrics export.
///
/// Serves Prometheus-compatible metrics on `/metrics` endpoint. When
/// `auth_token` is set, endpoints require `Authorization: Bearer <token>`.
pub struct MetricsHttpServer {
    metrics: Arc<RelayMetrics>,
    addr: SocketAddr,
    /// Optional bearer token required for `/metrics` and `/health`. If the
    /// server binds to a non-loopback address this SHOULD be set; the
    /// constructor emits a warning when it isn't.
    auth_token: Option<String>,
}

impl MetricsHttpServer {
    /// Create a new metrics HTTP server with optional bearer-token auth.
    pub fn new(metrics: Arc<RelayMetrics>, addr: SocketAddr, auth_token: Option<String>) -> Self {
        if auth_token.is_none() && !addr.ip().is_loopback() {
            warn!(
                "Metrics server binding to non-loopback address {} without auth_token — this exposes load data to anyone who can reach it",
                addr
            );
        }
        Self {
            metrics,
            addr,
            auth_token,
        }
    }

    /// Run the HTTP server.
    ///
    /// Listens for HTTP requests and serves metrics in Prometheus format.
    /// This function runs indefinitely until an error occurs.
    pub async fn run(&self) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.addr).await?;
        info!(
            "Relay metrics HTTP server listening on http://{}/metrics",
            self.addr
        );

        // FIX-022: bound the number of pre-auth connections concurrently
        // parked on the metrics endpoint. The existing 3-second slow-loris
        // read timeout caps how long each connection can sit idle, but
        // does NOT cap how many fresh TCP connections an attacker can
        // open in parallel — under a sustained connect storm the tokio
        // task queue grows without bound and starves the rest of the
        // relay (background tasks, session GC, etc.).
        //
        // 100 concurrent pre-auth connections is far above the legitimate
        // workload (Prometheus typically polls a single endpoint every
        // 15-60s with one outstanding request) and well below a number
        // that could exhaust the kernel's FD budget or tokio's task
        // scheduler. Mirrors the same primitive used by `hpn-server`'s
        // admin API.
        const MAX_CONCURRENT_PRE_AUTH: usize = 100;
        let preauth_limit = Arc::new(Semaphore::new(MAX_CONCURRENT_PRE_AUTH));

        loop {
            let (mut stream, remote_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    warn!("Failed to accept metrics connection: {}", e);
                    continue;
                }
            };

            // Try to acquire a pre-auth slot WITHOUT blocking. If the
            // permit pool is full, reject immediately with 503 so we
            // never let an attacker's connection occupy a tokio task
            // slot. Legitimate scrapers will retry on the next interval.
            let permit = match Arc::clone(&preauth_limit).try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    debug!(
                        remote = %remote_addr,
                        "Metrics pre-auth semaphore exhausted — rejecting connection"
                    );
                    // Spawn the 503 write into a fire-and-forget task
                    // with a short deadline so a malicious peer that
                    // wedges its TCP receive window cannot hold the
                    // accept loop hostage. The accept loop must keep
                    // processing legitimate scrapers regardless of
                    // what the rejected peer does next.
                    tokio::spawn(async move {
                        use tokio::io::AsyncWriteExt;
                        let _ = tokio::time::timeout(
                            std::time::Duration::from_millis(500),
                            stream.write_all(
                                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            ),
                        )
                        .await;
                    });
                    continue;
                }
            };

            let metrics = Arc::clone(&self.metrics);
            let auth_token = self.auth_token.clone();

            // Spawn task to handle request with a hard deadline.
            // Slowloris protection: if the peer does not send a complete
            // request header within 3 seconds, drop the connection. Without
            // a timeout, a hostile peer opening many connections and
            // sending 1 byte each would pile up tokio tasks indefinitely.
            //
            // The semaphore permit is moved into the task; it is released
            // when the task completes (request handled, error, or
            // timeout), bounding total concurrent pre-auth tasks at
            // `MAX_CONCURRENT_PRE_AUTH`.
            tokio::spawn(async move {
                let _permit = permit;
                use tokio::io::{AsyncReadExt, AsyncWriteExt};

                let mut buf = vec![0u8; 2048];
                let read_result =
                    tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut buf))
                        .await;
                let n = match read_result {
                    Ok(Ok(n)) if n > 0 => n,
                    Ok(Ok(_)) => {
                        warn!(remote = %remote_addr, "Empty request from client");
                        return;
                    }
                    Ok(Err(e)) => {
                        warn!(remote = %remote_addr, error = %e, "Failed to read request");
                        return;
                    }
                    Err(_) => {
                        warn!(remote = %remote_addr, "Request read timeout");
                        return;
                    }
                };

                // Parse simple HTTP request (just check for GET /metrics or /health).
                let request = String::from_utf8_lossy(&buf[..n]);

                // Bearer-token auth if configured. Metrics endpoints typically
                // reveal load patterns, session counts, and upstream health —
                // operators who bind to non-loopback addresses MUST set a
                // token in the config or the relay refuses to start.
                if let Some(ref expected) = auth_token {
                    let provided = request
                        .lines()
                        .find(|l| {
                            let ll = l.to_ascii_lowercase();
                            ll.starts_with("authorization: bearer ")
                                || ll.starts_with("authorization: token ")
                        })
                        .map(|l| l.split_whitespace().last().unwrap_or(""))
                        .unwrap_or("");
                    if !constant_time_eq(provided.as_bytes(), expected.as_bytes()) {
                        let body = "Unauthorized\n";
                        let response = format!(
                            "HTTP/1.1 401 Unauthorized\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nWWW-Authenticate: Bearer\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(response.as_bytes()).await;
                        return;
                    }
                }

                let is_metrics = request.contains("GET /metrics");
                let is_health = request.contains("GET /health");

                let (status, content_type, body) = if is_metrics {
                    // Return Prometheus metrics
                    (
                        "200 OK",
                        "text/plain; version=0.0.4",
                        metrics.export_prometheus(),
                    )
                } else if is_health {
                    // Health check endpoint
                    (
                        "200 OK",
                        "text/plain",
                        format!(
                            "OK\nUptime: {}s\nSessions: {}\n",
                            metrics.uptime_secs(),
                            metrics.sessions_active.load(Ordering::Relaxed)
                        ),
                    )
                } else {
                    // 404 for other paths
                    (
                        "404 Not Found",
                        "text/plain",
                        "Not Found\n\nAvailable endpoints:\n  GET /metrics - Prometheus metrics\n  GET /health  - Health check\n".to_string(),
                    )
                };

                // Send HTTP response
                let response = format!(
                    "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status,
                    content_type,
                    body.len(),
                    body
                );

                if let Err(e) = stream.write_all(response.as_bytes()).await {
                    warn!(remote = %remote_addr, error = %e, "Failed to send response");
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_new() {
        let metrics = RelayMetrics::new();
        assert_eq!(metrics.packets_forwarded.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.packets_returned.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.bytes_forwarded.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.bytes_returned.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.packets_dropped.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.sessions_active.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.sessions_total.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_metrics_default() {
        let metrics = RelayMetrics::default();
        assert_eq!(metrics.packets_forwarded.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_record_forward() {
        let metrics = RelayMetrics::new();
        metrics.record_forward(100);
        metrics.record_forward(200);

        assert_eq!(metrics.packets_forwarded.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.bytes_forwarded.load(Ordering::Relaxed), 300);
    }

    #[test]
    fn test_record_return() {
        let metrics = RelayMetrics::new();
        metrics.record_return(150);
        metrics.record_return(250);

        assert_eq!(metrics.packets_returned.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.bytes_returned.load(Ordering::Relaxed), 400);
    }

    #[test]
    fn test_record_drop() {
        let metrics = RelayMetrics::new();
        metrics.record_drop();
        metrics.record_drop();
        metrics.record_drop();

        assert_eq!(metrics.packets_dropped.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn test_record_session_created() {
        let metrics = RelayMetrics::new();
        metrics.record_session_created();
        metrics.record_session_created();

        assert_eq!(metrics.sessions_total.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.sessions_active.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_record_session_removed() {
        let metrics = RelayMetrics::new();
        metrics.record_session_created();
        metrics.record_session_created();
        metrics.record_session_removed();

        assert_eq!(metrics.sessions_total.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.sessions_active.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_set_sessions_active() {
        let metrics = RelayMetrics::new();
        metrics.set_sessions_active(42);

        assert_eq!(metrics.sessions_active.load(Ordering::Relaxed), 42);
    }

    #[test]
    fn test_uptime_secs() {
        let metrics = RelayMetrics::new();
        std::thread::sleep(std::time::Duration::from_millis(100));

        let uptime = metrics.uptime_secs();
        assert!(uptime == 0); // Less than 1 second
    }

    #[test]
    fn test_summary() {
        let metrics = RelayMetrics::new();
        metrics.record_forward(100);
        metrics.record_return(200);
        metrics.record_drop();
        metrics.record_session_created();

        let summary = metrics.summary();
        assert!(summary.contains("sessions=1"));
        assert!(summary.contains("fwd=1/100"));
        assert!(summary.contains("ret=1/200"));
        assert!(summary.contains("drop=1"));
    }

    #[test]
    fn test_export_prometheus() {
        let metrics = RelayMetrics::new();
        metrics.record_forward(512);
        metrics.record_return(1024);
        metrics.record_session_created();

        let export = metrics.export_prometheus();

        // Check format
        assert!(export.contains("# HELP hpn_relay_uptime_seconds"));
        assert!(export.contains("# TYPE hpn_relay_uptime_seconds counter"));
        assert!(export.contains("# HELP hpn_relay_sessions_active"));
        assert!(export.contains("# TYPE hpn_relay_sessions_active gauge"));
        assert!(export.contains("# HELP hpn_relay_sessions_total"));
        assert!(export.contains("# HELP hpn_relay_packets_forwarded_total"));
        assert!(export.contains("# HELP hpn_relay_packets_returned_total"));
        assert!(export.contains("# HELP hpn_relay_bytes_forwarded_total"));
        assert!(export.contains("# HELP hpn_relay_bytes_returned_total"));
        assert!(export.contains("# HELP hpn_relay_packets_dropped_total"));

        // Check values
        assert!(export.contains("hpn_relay_sessions_active 1"));
        assert!(export.contains("hpn_relay_sessions_total 1"));
        assert!(export.contains("hpn_relay_packets_forwarded_total 1"));
        assert!(export.contains("hpn_relay_packets_returned_total 1"));
        assert!(export.contains("hpn_relay_bytes_forwarded_total 512"));
        assert!(export.contains("hpn_relay_bytes_returned_total 1024"));
    }

    #[test]
    fn test_metrics_http_server_new() {
        let metrics = Arc::new(RelayMetrics::new());
        let addr = "127.0.0.1:9101".parse().unwrap();
        let server = MetricsHttpServer::new(metrics.clone(), addr, None);

        assert_eq!(server.addr, addr);
        assert_eq!(Arc::strong_count(&metrics), 2); // Original + server copy
    }

    #[test]
    fn test_metrics_concurrent_updates() {
        use std::thread;

        let metrics = Arc::new(RelayMetrics::new());
        let mut handles = vec![];

        // Spawn 10 threads, each incrementing counters
        for _ in 0..10 {
            let m = Arc::clone(&metrics);
            let handle = thread::spawn(move || {
                for _ in 0..100 {
                    m.record_forward(10);
                    m.record_return(20);
                }
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // Each thread did 100 operations, 10 threads = 1000 total
        assert_eq!(metrics.packets_forwarded.load(Ordering::Relaxed), 1000);
        assert_eq!(metrics.packets_returned.load(Ordering::Relaxed), 1000);
        assert_eq!(metrics.bytes_forwarded.load(Ordering::Relaxed), 10000);
        assert_eq!(metrics.bytes_returned.load(Ordering::Relaxed), 20000);
    }
}
