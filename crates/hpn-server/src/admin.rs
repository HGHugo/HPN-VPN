//! Admin REST API for server management.
//!
//! Provides HTTP endpoints for:
//! - Session management (list, view, terminate)
//! - Server statistics
//! - Health checks
//!
//! # Endpoints
//!
//! - `GET /api/sessions` - List all active sessions
//! - `GET /api/sessions/{id}` - Get session details
//! - `DELETE /api/sessions/{id}` - Terminate a session
//! - `GET /api/stats` - Get aggregate statistics
//! - `GET /api/health` - Health check
//! - `GET /metrics` - Prometheus metrics (if enabled)
//!
//! # Rate Limiting
//!
//! All endpoints are rate limited per IP address to prevent abuse:
//! - Default: 100 requests per minute per IP
//! - Returns HTTP 429 Too Many Requests when exceeded

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

/// Maximum concurrent admin API connections (DoS protection).
const MAX_CONCURRENT_CONNECTIONS: usize = 100;

/// Default maximum requests per IP per minute for admin API.
const DEFAULT_MAX_REQUESTS_PER_MINUTE: u32 = 100;

/// Rate limit window duration.
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

/// Cleanup interval for expired rate limit entries.
const RATE_LIMIT_CLEANUP_INTERVAL: Duration = Duration::from_secs(300);

/// Maximum tracked IPs to prevent memory exhaustion.
const MAX_TRACKED_IPS: usize = 10_000;

/// Rate limiter for admin API requests.
///
/// Tracks the number of requests per IP address within a sliding time window.
/// If an IP exceeds the limit, further requests receive HTTP 429.
pub struct AdminRateLimiter {
    /// Map of IP addresses to (request count, window start time).
    requests: Mutex<HashMap<IpAddr, RateLimitEntry>>,
    /// Maximum requests allowed per window.
    max_per_window: u32,
    /// Window duration.
    window: Duration,
    /// Last cleanup time.
    last_cleanup: Mutex<Instant>,
}

/// Rate limit entry for a single IP.
#[derive(Clone, Copy)]
struct RateLimitEntry {
    /// Number of requests in current window.
    count: u32,
    /// Start of current window.
    window_start: Instant,
}

impl AdminRateLimiter {
    /// Create a new rate limiter with default settings (100 req/min).
    #[must_use]
    pub fn new() -> Self {
        Self::with_limit(DEFAULT_MAX_REQUESTS_PER_MINUTE)
    }

    /// Create a new rate limiter with a custom limit.
    ///
    /// # Arguments
    ///
    /// * `max_per_minute` - Maximum requests per IP per minute.
    #[must_use]
    pub fn with_limit(max_per_minute: u32) -> Self {
        Self {
            requests: Mutex::new(HashMap::new()),
            max_per_window: max_per_minute,
            window: RATE_LIMIT_WINDOW,
            last_cleanup: Mutex::new(Instant::now()),
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
        let now = Instant::now();

        // Periodic cleanup of expired entries
        self.maybe_cleanup(now);

        let mut requests = self.requests.lock();

        // DoS protection: reject new IPs if at capacity
        if !requests.contains_key(&addr) && requests.len() >= MAX_TRACKED_IPS {
            warn!(
                "Admin API rate limiter at capacity ({} IPs), rejecting new IP {}",
                MAX_TRACKED_IPS, addr
            );
            return false;
        }

        let entry = requests.entry(addr).or_insert(RateLimitEntry {
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

    /// Perform cleanup if enough time has passed since last cleanup.
    fn maybe_cleanup(&self, now: Instant) {
        let mut last_cleanup = self.last_cleanup.lock();

        if now.duration_since(*last_cleanup) > RATE_LIMIT_CLEANUP_INTERVAL {
            *last_cleanup = now;
            drop(last_cleanup);
            self.cleanup();
        }
    }

    /// Manually clean up expired entries.
    pub fn cleanup(&self) {
        let now = Instant::now();
        let mut requests = self.requests.lock();
        requests.retain(|_, entry| now.duration_since(entry.window_start) <= self.window);
    }

    /// Get the number of tracked IPs.
    #[must_use]
    pub fn tracked_ips(&self) -> usize {
        self.requests.lock().len()
    }

    /// Get remaining requests for an IP in the current window.
    /// Returns None if the IP is not being tracked.
    #[must_use]
    pub fn remaining(&self, addr: IpAddr) -> Option<u32> {
        let now = Instant::now();
        let requests = self.requests.lock();

        requests.get(&addr).map(|entry| {
            if now.duration_since(entry.window_start) > self.window {
                self.max_per_window
            } else {
                self.max_per_window.saturating_sub(entry.count)
            }
        })
    }
}

impl Default for AdminRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

use crate::metrics::ServerMetrics;
use crate::session_manager::SessionManager;

/// Session information for API response.
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionInfo {
    /// Session ID (hex encoded).
    pub session_id: String,
    /// Client's UDP address.
    pub client_addr: String,
    /// Allocated tunnel IPv4 address.
    pub tunnel_ip: String,
    /// Allocated tunnel IPv6 address (if dual-stack).
    pub tunnel_ipv6: Option<String>,
    /// Session duration in seconds.
    pub duration_secs: u64,
    /// Time since last activity in seconds.
    pub idle_secs: u64,
    /// Bytes sent to client.
    pub bytes_sent: u64,
    /// Bytes received from client.
    pub bytes_received: u64,
}

/// List of sessions response.
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionListResponse {
    /// Total session count.
    pub count: usize,
    /// List of sessions.
    pub sessions: Vec<SessionInfo>,
}

/// Server statistics response.
#[derive(Debug, Serialize, Deserialize)]
pub struct StatsResponse {
    /// Server uptime in seconds.
    pub uptime_secs: u64,
    /// Active sessions.
    pub sessions_active: u64,
    /// Total sessions created.
    pub sessions_total: u64,
    /// Bytes sent.
    pub bytes_sent: u64,
    /// Bytes received.
    pub bytes_received: u64,
    /// Packets sent.
    pub packets_sent: u64,
    /// Packets received.
    pub packets_received: u64,
    /// Packets dropped.
    pub packets_dropped: u64,
    /// Successful handshakes.
    pub handshakes_success: u64,
    /// Failed handshakes.
    pub handshakes_failed: u64,
}

/// Health check response.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    /// Server status.
    pub status: String,
    /// Server uptime in seconds.
    pub uptime_secs: u64,
    /// Active sessions.
    pub sessions_active: u64,
}

/// Error response.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    /// Error message.
    pub error: String,
}

/// Admin API server context.
pub struct AdminContext {
    /// Session manager.
    pub sessions: Arc<SessionManager>,
    /// Server metrics.
    pub metrics: Arc<ServerMetrics>,
    /// Enable Prometheus metrics endpoint.
    pub enable_metrics: bool,
    /// API authentication token (plain text; legacy path).
    ///
    /// When `api_token_sha256` is set this field is ignored and a startup
    /// warning is emitted. See FIX-032 in the config doc comment.
    pub api_token: Option<String>,
    /// Hex-encoded SHA-256 of the admin token (FIX-032).
    ///
    /// When set, `check_auth` recomputes the SHA-256 of the incoming
    /// bearer token and compares the 32-byte digest against this value in
    /// constant time. The plaintext token never appears on disk.
    pub api_token_sha256: Option<[u8; 32]>,
}

impl AdminContext {
    /// Create a new admin context.
    pub fn new(
        sessions: Arc<SessionManager>,
        metrics: Arc<ServerMetrics>,
        enable_metrics: bool,
    ) -> Self {
        Self {
            sessions,
            metrics,
            enable_metrics,
            api_token: None,
            api_token_sha256: None,
        }
    }

    /// Create a new admin context with authentication token.
    pub fn with_token(
        sessions: Arc<SessionManager>,
        metrics: Arc<ServerMetrics>,
        enable_metrics: bool,
        api_token: Option<String>,
    ) -> Self {
        Self {
            sessions,
            metrics,
            enable_metrics,
            api_token,
            api_token_sha256: None,
        }
    }

    /// Create a new admin context with a SHA-256-hashed token (FIX-032).
    ///
    /// Takes priority over `api_token` when both are present: only the
    /// hash is consulted for `check_auth`.
    pub fn with_token_hash(
        sessions: Arc<SessionManager>,
        metrics: Arc<ServerMetrics>,
        enable_metrics: bool,
        token_sha256_hex: &str,
    ) -> Result<Self, String> {
        let decoded = hex::decode(token_sha256_hex.trim())
            .map_err(|e| format!("admin_api_token_sha256 must be hex: {}", e))?;
        if decoded.len() != 32 {
            return Err(format!(
                "admin_api_token_sha256 must decode to exactly 32 bytes, got {}",
                decoded.len()
            ));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&decoded);
        Ok(Self {
            sessions,
            metrics,
            enable_metrics,
            api_token: None,
            api_token_sha256: Some(hash),
        })
    }

    /// Check if authentication is required and validate the token.
    /// Returns true if authentication passes, false otherwise.
    fn check_auth(&self, req: &Request<hyper::body::Incoming>) -> bool {
        // If neither auth mode is configured, authentication is disabled.
        if self.api_token.is_none() && self.api_token_sha256.is_none() {
            debug!(
                "Admin API: allowing unauthenticated access to {} {} (no token configured)",
                req.method(),
                req.uri().path()
            );
            return true;
        }

        // Pull the Bearer token from the Authorization header.
        let Some(token) = req
            .headers()
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
        else {
            return false;
        };

        // FIX-032: when a SHA-256 hash is configured, ignore the plaintext
        // form even if both are set — only the hash path runs. The startup
        // warning about the redundant field lives in `with_token_hash`'s
        // caller.
        if let Some(expected_hash) = &self.api_token_sha256 {
            let digest = ring::digest::digest(&ring::digest::SHA256, token.as_bytes());
            // The 32-byte SHA-256 output is constant-time compared. The
            // length check is implicit (both sides are always 32 bytes).
            use subtle::ConstantTimeEq;
            return bool::from(digest.as_ref().ct_eq(expected_hash.as_slice()));
        }

        if let Some(expected_token) = &self.api_token {
            return constant_time_eq(token.as_bytes(), expected_token.as_bytes());
        }

        false
    }
}

/// Constant-time string comparison to prevent timing attacks.
///
/// SECURITY: Uses `subtle::ConstantTimeEq` to ensure comparison time
/// does not depend on the content or position of differences.
/// The length check is also constant-time to prevent length oracle attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// Admin HTTP server.
pub struct AdminHttpServer {
    context: Arc<AdminContext>,
    addr: SocketAddr,
    /// Semaphore to limit concurrent connections (DoS protection).
    connection_limit: Arc<Semaphore>,
    /// Rate limiter for requests per IP (DoS/brute-force protection).
    rate_limiter: Arc<AdminRateLimiter>,
}

impl AdminHttpServer {
    /// Create a new admin HTTP server.
    ///
    /// # Security Warning
    ///
    /// If no `api_token` is configured, write operations (DELETE, POST, PUT)
    /// will be unauthenticated. This is a security risk in production.
    /// Always configure `admin_api_token` in production environments.
    pub fn new(context: AdminContext, addr: SocketAddr) -> Self {
        Self::with_rate_limit(context, addr, DEFAULT_MAX_REQUESTS_PER_MINUTE)
    }

    /// Create a new admin HTTP server with custom rate limit.
    ///
    /// # Arguments
    ///
    /// * `context` - Admin context with session manager, metrics, etc.
    /// * `addr` - Address to bind the HTTP server to.
    /// * `max_requests_per_minute` - Maximum requests per IP per minute.
    pub fn with_rate_limit(
        context: AdminContext,
        addr: SocketAddr,
        max_requests_per_minute: u32,
    ) -> Self {
        if context.api_token.is_none() {
            warn!(
                "SECURITY WARNING: Admin API started without authentication token! \
                 Write operations (DELETE, POST) will be unauthenticated. \
                 Configure 'admin_api_token' in server config for production use."
            );
        }
        info!(
            "Admin API rate limiting enabled: {} requests/minute per IP",
            max_requests_per_minute
        );
        Self {
            context: Arc::new(context),
            addr,
            connection_limit: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS)),
            rate_limiter: Arc::new(AdminRateLimiter::with_limit(max_requests_per_minute)),
        }
    }

    /// Run the HTTP server.
    pub async fn run(&self) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.addr).await?;
        info!(
            "Admin API server listening on http://{} (max {} concurrent connections)",
            self.addr, MAX_CONCURRENT_CONNECTIONS
        );

        loop {
            let (stream, remote_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    warn!("Failed to accept connection: {}", e);
                    continue;
                }
            };

            // Acquire permit before spawning connection handler.
            // If all permits are taken, this will block until one is released.
            let permit = match self.connection_limit.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    debug!(
                        "Connection limit reached, rejecting connection from {}",
                        remote_addr
                    );
                    // Drop the stream to reject the connection
                    continue;
                }
            };

            let context = Arc::clone(&self.context);
            let rate_limiter = Arc::clone(&self.rate_limiter);
            tokio::spawn(async move {
                // Permit is automatically released when dropped at end of scope
                let _permit = permit;

                let io = TokioIo::new(stream);
                let client_ip = remote_addr.ip();
                let service = service_fn(move |req| {
                    let ctx = Arc::clone(&context);
                    let limiter = Arc::clone(&rate_limiter);
                    async move { handle_request(req, ctx, limiter, client_ip).await }
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
            "Admin API server listening on http://{} (max {} concurrent connections)",
            self.addr, MAX_CONCURRENT_CONNECTIONS
        );

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, remote_addr)) => {
                            // Acquire permit before spawning connection handler.
                            let permit = match self.connection_limit.clone().try_acquire_owned() {
                                Ok(permit) => permit,
                                Err(_) => {
                                    debug!(
                                        "Connection limit reached, rejecting connection from {}",
                                        remote_addr
                                    );
                                    continue;
                                }
                            };

                            let context = Arc::clone(&self.context);
                            let rate_limiter = Arc::clone(&self.rate_limiter);
                            tokio::spawn(async move {
                                // Permit is automatically released when dropped at end of scope
                                let _permit = permit;

                                let io = TokioIo::new(stream);
                                let client_ip = remote_addr.ip();
                                let service = service_fn(move |req| {
                                    let ctx = Arc::clone(&context);
                                    let limiter = Arc::clone(&rate_limiter);
                                    async move { handle_request(req, ctx, limiter, client_ip).await }
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
                    info!("Admin API server shutting down");
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
    ctx: Arc<AdminContext>,
    rate_limiter: Arc<AdminRateLimiter>,
    client_ip: IpAddr,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    // Rate limiting check - applied to ALL endpoints to prevent abuse
    // This protects against session enumeration, token brute-forcing, and DoS
    if !rate_limiter.allow(client_ip) {
        warn!(
            "Rate limited admin API request: {} {} from {}",
            method, path, client_ip
        );
        return Ok(rate_limit_response());
    }

    // SECURITY: Authentication enforcement for admin API.
    //
    // Public endpoints (no auth required): /, /api, /health, /api/health.
    // `/metrics` is NOT public — it is in the sensitive set below and
    // requires either a configured admin token or a 403 rejection,
    // because aggregate Prometheus output (sessions_active, bytes_total,
    // handshakes_*) is useful reconnaissance for an attacker probing
    // server load / online-state. Operators who need scraping must set
    // `admin_api_token` and authenticate the scraper.
    //
    // All other endpoints require authentication when admin_api_token
    // is configured.
    let is_public_endpoint = matches!(path.as_str(), "/" | "/api" | "/health" | "/api/health");

    if !is_public_endpoint {
        if ctx.api_token.is_some() {
            // Token is configured - require valid authentication
            if !ctx.check_auth(&req) {
                warn!(
                    "Unauthorized admin API access attempt: {} {} from {} (IP: {})",
                    method,
                    path,
                    req.headers()
                        .get("x-forwarded-for")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("direct"),
                    client_ip
                );
                return Ok(json_error(
                    StatusCode::UNAUTHORIZED,
                    "Authentication required. Provide Authorization: Bearer <token>",
                ));
            }
        } else {
            // No token configured - REJECT sensitive endpoints for security
            // This prevents accidental exposure of sensitive data.
            //
            // `/metrics` is treated as sensitive even though it only exposes
            // aggregate counters: those counters are still useful to an
            // attacker probing whether the server is online, gauging load,
            // and detecting whether their own rate-limit/auth attempts
            // register. Operators who need scraping access MUST configure
            // `admin_api_token` and authenticate the scraper.
            let is_write_operation = matches!(
                method,
                Method::DELETE | Method::POST | Method::PUT | Method::PATCH
            );
            let is_sensitive_endpoint =
                path.starts_with("/api/sessions") || path == "/api/stats" || path == "/metrics";

            if is_write_operation || is_sensitive_endpoint {
                warn!(
                    "Admin API request rejected (no token configured): {} {} from {}",
                    method, path, client_ip
                );
                return Ok(json_error(
                    StatusCode::FORBIDDEN,
                    "Admin API token not configured. Set 'admin_api_token' in server config.",
                ));
            }
        }
    }

    let response = match (method, path.as_str()) {
        // List all sessions
        (Method::GET, "/api/sessions") => handle_list_sessions(&ctx),

        // Get session by ID
        (Method::GET, path) if path.starts_with("/api/sessions/") => {
            let session_id = &path[14..]; // Skip "/api/sessions/"
            handle_get_session(&ctx, session_id)
        }

        // Delete session by ID (requires authentication)
        (Method::DELETE, path) if path.starts_with("/api/sessions/") => {
            let session_id = &path[14..]; // Skip "/api/sessions/"
            handle_delete_session(&ctx, session_id)
        }

        // Get aggregate stats
        (Method::GET, "/api/stats") => handle_stats(&ctx),

        // Health check
        (Method::GET, "/api/health") | (Method::GET, "/health") => handle_health(&ctx),

        // Prometheus metrics (if enabled)
        (Method::GET, "/metrics") if ctx.enable_metrics => {
            let body = ctx.metrics.export_prometheus();
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
                .body(Full::new(Bytes::from(body)))
                .expect("static response builder is infallible")
        }

        // Root page
        (Method::GET, "/") | (Method::GET, "/api") => {
            let body = r#"{
  "name": "HPN VPN Server Admin API",
  "version": "0.1.0",
  "endpoints": {
    "sessions": "/api/sessions",
    "stats": "/api/stats",
    "health": "/api/health",
    "metrics": "/metrics"
  }
}"#;
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(body)))
                .expect("static response builder is infallible")
        }

        // Not found
        _ => json_error(StatusCode::NOT_FOUND, "Not Found"),
    };

    Ok(response)
}

/// Handle GET /api/sessions
fn handle_list_sessions(ctx: &AdminContext) -> Response<Full<Bytes>> {
    let session_ids = ctx.sessions.session_ids();
    let mut sessions = Vec::new();

    for session_id in session_ids {
        if let Some(session) = ctx.sessions.get_session(session_id) {
            sessions.push(SessionInfo {
                session_id: format!("{:x}", session_id.0),
                client_addr: session.client_addr.lock().to_string(),
                tunnel_ip: format!(
                    "{}.{}.{}.{}",
                    session.tunnel_ip[0],
                    session.tunnel_ip[1],
                    session.tunnel_ip[2],
                    session.tunnel_ip[3]
                ),
                tunnel_ipv6: session
                    .tunnel_ipv6
                    .map(|ip| std::net::Ipv6Addr::from(ip).to_string()),
                duration_secs: session.duration().as_secs(),
                idle_secs: session.last_activity().elapsed().as_secs(),
                bytes_sent: session.bytes_sent(),
                bytes_received: session.bytes_received(),
            });
        }
    }

    let response = SessionListResponse {
        count: sessions.len(),
        sessions,
    };

    json_response(StatusCode::OK, &response)
}

/// Handle GET /api/sessions/{id}
fn handle_get_session(ctx: &AdminContext, session_id_str: &str) -> Response<Full<Bytes>> {
    // Parse session ID from hex
    let session_id = match u64::from_str_radix(session_id_str, 16) {
        Ok(id) => hpn_core::types::SessionId(id),
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "Invalid session ID format"),
    };

    match ctx.sessions.get_session(session_id) {
        Some(session) => {
            let info = SessionInfo {
                session_id: format!("{:x}", session_id.0),
                client_addr: session.client_addr.lock().to_string(),
                tunnel_ip: format!(
                    "{}.{}.{}.{}",
                    session.tunnel_ip[0],
                    session.tunnel_ip[1],
                    session.tunnel_ip[2],
                    session.tunnel_ip[3]
                ),
                tunnel_ipv6: session
                    .tunnel_ipv6
                    .map(|ip| std::net::Ipv6Addr::from(ip).to_string()),
                duration_secs: session.duration().as_secs(),
                idle_secs: session.last_activity().elapsed().as_secs(),
                bytes_sent: session.bytes_sent(),
                bytes_received: session.bytes_received(),
            };
            json_response(StatusCode::OK, &info)
        }
        None => json_error(StatusCode::NOT_FOUND, "Session not found"),
    }
}

/// Handle DELETE /api/sessions/{id}
fn handle_delete_session(ctx: &AdminContext, session_id_str: &str) -> Response<Full<Bytes>> {
    // Parse session ID from hex
    let session_id = match u64::from_str_radix(session_id_str, 16) {
        Ok(id) => hpn_core::types::SessionId(id),
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "Invalid session ID format"),
    };

    match ctx.sessions.remove_session(session_id) {
        Some(_) => {
            info!("Admin API: terminated session {}", session_id);
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Full::new(Bytes::new()))
                .expect("static response builder is infallible")
        }
        None => json_error(StatusCode::NOT_FOUND, "Session not found"),
    }
}

/// Handle GET /api/stats
fn handle_stats(ctx: &AdminContext) -> Response<Full<Bytes>> {
    let summary = ctx.metrics.summary();
    let response = StatsResponse {
        uptime_secs: summary.uptime_secs,
        sessions_active: summary.sessions_active,
        sessions_total: summary.sessions_total,
        bytes_sent: summary.bytes_sent,
        bytes_received: summary.bytes_received,
        packets_sent: summary.packets_sent,
        packets_received: summary.packets_received,
        packets_dropped: summary.packets_dropped,
        handshakes_success: summary.handshakes_success,
        handshakes_failed: summary.handshakes_failed,
    };
    json_response(StatusCode::OK, &response)
}

/// Handle GET /api/health
fn handle_health(ctx: &AdminContext) -> Response<Full<Bytes>> {
    let summary = ctx.metrics.summary();
    let response = HealthResponse {
        status: "healthy".to_string(),
        uptime_secs: summary.uptime_secs,
        sessions_active: summary.sessions_active,
    };
    json_response(StatusCode::OK, &response)
}

/// Create a JSON response.
fn json_response<T: Serialize>(status: StatusCode, data: &T) -> Response<Full<Bytes>> {
    let body = serde_json::to_string_pretty(data).unwrap_or_else(|_| "{}".to_string());
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| {
            Response::new(Full::new(Bytes::from(
                r#"{"error":"internal server error"}"#,
            )))
        })
}

/// Create a JSON error response.
fn json_error(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    json_response(
        status,
        &ErrorResponse {
            error: message.to_string(),
        },
    )
}

/// Create a rate limit exceeded response (HTTP 429).
fn rate_limit_response() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("Content-Type", "application/json")
        .header("Retry-After", "60") // Suggest retry after 60 seconds
        .body(Full::new(Bytes::from(
            r#"{"error":"Rate limit exceeded. Please try again later."}"#,
        )))
        .unwrap_or_else(|_| {
            Response::new(Full::new(Bytes::from(r#"{"error":"rate limit exceeded"}"#)))
        })
}

#[cfg(test)]
#[allow(clippy::needless_collect)]
mod tests {
    use super::*;

    #[test]
    fn test_session_info_serialize() {
        let info = SessionInfo {
            session_id: "abc123".to_string(),
            client_addr: "192.168.1.100:12345".to_string(),
            tunnel_ip: "10.99.0.5".to_string(),
            tunnel_ipv6: None,
            duration_secs: 3600,
            idle_secs: 30,
            bytes_sent: 1_000_000,
            bytes_received: 500_000,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("abc123"));
        assert!(json.contains("10.99.0.5"));
    }

    #[test]
    fn test_error_response() {
        let error = ErrorResponse {
            error: "Test error".to_string(),
        };
        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("Test error"));
    }

    #[test]
    fn test_stats_response() {
        let stats = StatsResponse {
            uptime_secs: 3600,
            sessions_active: 10,
            sessions_total: 100,
            bytes_sent: 1_000_000,
            bytes_received: 500_000,
            packets_sent: 1000,
            packets_received: 500,
            packets_dropped: 5,
            handshakes_success: 95,
            handshakes_failed: 5,
        };
        let json = serde_json::to_string(&stats).unwrap();
        assert!(json.contains("uptime_secs"));
        assert!(json.contains("sessions_active"));
    }

    #[test]
    fn test_admin_stats_endpoint() {
        // BUSINESS LOGIC TEST: Admin API stats endpoint validation
        // This test validates:
        // - StatsResponse correctly serializes all metric fields
        // - JSON output is well-formed and parsable
        // - All numeric types serialize correctly (u64)
        // - Field names match API specification
        // - Response structure is backward-compatible

        let stats = StatsResponse {
            uptime_secs: 86400, // 1 day
            sessions_active: 42,
            sessions_total: 1000,
            bytes_sent: 10_737_418_240,    // 10 GB
            bytes_received: 5_368_709_120, // 5 GB
            packets_sent: 7_000_000,
            packets_received: 3_500_000,
            packets_dropped: 1234,
            handshakes_success: 995,
            handshakes_failed: 5,
        };

        // Serialize to JSON
        let json = serde_json::to_string(&stats).expect("Serialization should succeed");

        // Verify JSON is valid
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("JSON should be valid");

        // Verify all required fields are present
        assert!(
            parsed["uptime_secs"].is_number(),
            "uptime_secs should be a number"
        );
        assert!(
            parsed["sessions_active"].is_number(),
            "sessions_active should be a number"
        );
        assert!(
            parsed["sessions_total"].is_number(),
            "sessions_total should be a number"
        );
        assert!(
            parsed["bytes_sent"].is_number(),
            "bytes_sent should be a number"
        );
        assert!(
            parsed["bytes_received"].is_number(),
            "bytes_received should be a number"
        );
        assert!(
            parsed["packets_sent"].is_number(),
            "packets_sent should be a number"
        );
        assert!(
            parsed["packets_received"].is_number(),
            "packets_received should be a number"
        );
        assert!(
            parsed["packets_dropped"].is_number(),
            "packets_dropped should be a number"
        );
        assert!(
            parsed["handshakes_success"].is_number(),
            "handshakes_success should be a number"
        );
        assert!(
            parsed["handshakes_failed"].is_number(),
            "handshakes_failed should be a number"
        );

        // Verify values are correct
        assert_eq!(parsed["uptime_secs"].as_u64().unwrap(), 86400);
        assert_eq!(parsed["sessions_active"].as_u64().unwrap(), 42);
        assert_eq!(parsed["sessions_total"].as_u64().unwrap(), 1000);
        assert_eq!(parsed["bytes_sent"].as_u64().unwrap(), 10_737_418_240);
        assert_eq!(parsed["bytes_received"].as_u64().unwrap(), 5_368_709_120);
        assert_eq!(parsed["packets_sent"].as_u64().unwrap(), 7_000_000);
        assert_eq!(parsed["packets_received"].as_u64().unwrap(), 3_500_000);
        assert_eq!(parsed["packets_dropped"].as_u64().unwrap(), 1234);
        assert_eq!(parsed["handshakes_success"].as_u64().unwrap(), 995);
        assert_eq!(parsed["handshakes_failed"].as_u64().unwrap(), 5);

        // Verify pretty-printing works
        let pretty_json = serde_json::to_string_pretty(&stats).expect("Pretty print should work");
        assert!(
            pretty_json.contains('\n'),
            "Pretty JSON should contain newlines"
        );
        assert!(
            pretty_json.len() > json.len(),
            "Pretty JSON should be longer"
        );

        // Verify round-trip deserialization
        let deserialized: StatsResponse =
            serde_json::from_str(&json).expect("Deserialization should succeed");
        assert_eq!(deserialized.uptime_secs, stats.uptime_secs);
        assert_eq!(deserialized.sessions_active, stats.sessions_active);
        assert_eq!(deserialized.bytes_sent, stats.bytes_sent);
    }

    #[test]
    fn test_constant_time_eq() {
        // SECURITY TEST: Constant-time comparison for API tokens
        // This test validates:
        // - constant_time_eq() correctly compares equal strings
        // - constant_time_eq() correctly rejects different strings
        // - Length mismatches are detected
        // - Empty strings are handled correctly

        // Equal strings
        assert!(constant_time_eq(b"secret123", b"secret123"));
        assert!(constant_time_eq(b"", b""));

        // Different strings (same length)
        assert!(!constant_time_eq(b"secret123", b"secret124"));
        assert!(!constant_time_eq(b"aaaaaaa", b"aaaaaab"));

        // Different lengths
        assert!(!constant_time_eq(b"short", b"longer_string"));
        assert!(!constant_time_eq(b"longer_string", b"short"));

        // Single character difference
        assert!(!constant_time_eq(b"password", b"passwOrd"));

        // Complex tokens (realistic API tokens)
        let token1 = b"hpn_sk_1234567890abcdef1234567890abcdef";
        let token2 = b"hpn_sk_1234567890abcdef1234567890abcdef";
        let token3 = b"hpn_sk_1234567890abcdef1234567890abcdeg"; // Last char different

        assert!(constant_time_eq(token1, token2));
        assert!(!constant_time_eq(token1, token3));
    }

    #[test]
    fn test_session_list_response_serialization() {
        // BUSINESS LOGIC TEST: Session list response serialization
        // This test validates:
        // - SessionListResponse correctly serializes multiple sessions
        // - Session count matches array length
        // - IPv6 optional field serialization (Some vs None)
        // - All session fields are present in JSON output

        let sessions = vec![
            SessionInfo {
                session_id: "abc123".to_string(),
                client_addr: "192.168.1.100:12345".to_string(),
                tunnel_ip: "10.99.0.5".to_string(),
                tunnel_ipv6: Some("fd99::5".to_string()),
                duration_secs: 3600,
                idle_secs: 30,
                bytes_sent: 1_000_000,
                bytes_received: 500_000,
            },
            SessionInfo {
                session_id: "def456".to_string(),
                client_addr: "192.168.1.101:12346".to_string(),
                tunnel_ip: "10.99.0.6".to_string(),
                tunnel_ipv6: None, // IPv4-only session
                duration_secs: 1800,
                idle_secs: 15,
                bytes_sent: 2_000_000,
                bytes_received: 1_000_000,
            },
        ];

        let response = SessionListResponse {
            count: sessions.len(),
            sessions,
        };

        let json = serde_json::to_string(&response).expect("Serialization should succeed");

        // Parse JSON to verify structure
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("JSON should be valid");

        // Verify top-level fields
        assert_eq!(parsed["count"].as_u64().unwrap(), 2);
        assert!(parsed["sessions"].is_array());
        assert_eq!(parsed["sessions"].as_array().unwrap().len(), 2);

        // Verify first session
        let session0 = &parsed["sessions"][0];
        assert_eq!(session0["session_id"].as_str().unwrap(), "abc123");
        assert_eq!(session0["tunnel_ip"].as_str().unwrap(), "10.99.0.5");
        assert_eq!(session0["tunnel_ipv6"].as_str().unwrap(), "fd99::5");

        // Verify second session (IPv6 should be null)
        let session1 = &parsed["sessions"][1];
        assert_eq!(session1["session_id"].as_str().unwrap(), "def456");
        assert_eq!(session1["tunnel_ip"].as_str().unwrap(), "10.99.0.6");
        assert!(
            session1["tunnel_ipv6"].is_null(),
            "IPv6 should be null for IPv4-only session"
        );

        // Verify round-trip
        let deserialized: SessionListResponse =
            serde_json::from_str(&json).expect("Deserialization should succeed");
        assert_eq!(deserialized.count, 2);
        assert_eq!(deserialized.sessions.len(), 2);
        assert_eq!(deserialized.sessions[0].session_id, "abc123");
        assert_eq!(deserialized.sessions[1].tunnel_ipv6, None);
    }

    // Rate limiter tests

    fn test_ip(last_octet: u8) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, last_octet))
    }

    #[test]
    fn test_admin_rate_limiter_basic() {
        // SECURITY TEST: Admin API rate limiting
        // This test validates:
        // - Requests are allowed up to the limit
        // - Requests are rejected after the limit is exceeded
        // - Different IPs have independent limits

        let limiter = AdminRateLimiter::with_limit(3);
        let ip = test_ip(1);

        // First 3 requests should be allowed
        assert!(limiter.allow(ip), "Request 1 should be allowed");
        assert!(limiter.allow(ip), "Request 2 should be allowed");
        assert!(limiter.allow(ip), "Request 3 should be allowed");

        // 4th request should be rate limited
        assert!(!limiter.allow(ip), "Request 4 should be rate limited");
        assert!(!limiter.allow(ip), "Request 5 should be rate limited");
    }

    #[test]
    fn test_admin_rate_limiter_different_ips() {
        let limiter = AdminRateLimiter::with_limit(2);
        let ip1 = test_ip(1);
        let ip2 = test_ip(2);

        // Both IPs should have independent limits
        assert!(limiter.allow(ip1));
        assert!(limiter.allow(ip1));
        assert!(!limiter.allow(ip1)); // Rate limited

        // IP2 should still be allowed
        assert!(limiter.allow(ip2));
        assert!(limiter.allow(ip2));
        assert!(!limiter.allow(ip2)); // Rate limited
    }

    #[test]
    fn test_admin_rate_limiter_tracked_ips() {
        let limiter = AdminRateLimiter::with_limit(10);

        assert_eq!(limiter.tracked_ips(), 0);

        limiter.allow(test_ip(1));
        assert_eq!(limiter.tracked_ips(), 1);

        limiter.allow(test_ip(2));
        assert_eq!(limiter.tracked_ips(), 2);

        limiter.allow(test_ip(1)); // Same IP
        assert_eq!(limiter.tracked_ips(), 2);
    }

    #[test]
    fn test_admin_rate_limiter_remaining() {
        let limiter = AdminRateLimiter::with_limit(5);
        let ip = test_ip(1);

        // Before any requests, IP is not tracked
        assert_eq!(limiter.remaining(ip), None);

        // After first request
        assert!(limiter.allow(ip));
        assert_eq!(limiter.remaining(ip), Some(4));

        // After more requests
        assert!(limiter.allow(ip));
        assert!(limiter.allow(ip));
        assert_eq!(limiter.remaining(ip), Some(2));

        // At limit
        assert!(limiter.allow(ip));
        assert!(limiter.allow(ip));
        assert_eq!(limiter.remaining(ip), Some(0));

        // Past limit (still shows 0)
        assert!(!limiter.allow(ip));
        assert_eq!(limiter.remaining(ip), Some(0));
    }

    #[test]
    fn test_admin_rate_limiter_default() {
        let limiter = AdminRateLimiter::default();
        let ip = test_ip(1);

        // Default is 100 per minute
        for _ in 0..100 {
            assert!(limiter.allow(ip));
        }
        assert!(!limiter.allow(ip));
    }

    #[test]
    fn test_admin_rate_limiter_cleanup() {
        let limiter = AdminRateLimiter::with_limit(10);

        // Add multiple IPs
        for i in 1..=10 {
            limiter.allow(test_ip(i));
        }
        assert_eq!(limiter.tracked_ips(), 10);

        // Manual cleanup shouldn't remove entries in current window
        limiter.cleanup();
        assert_eq!(limiter.tracked_ips(), 10);
    }

    #[test]
    fn test_admin_rate_limiter_ipv6() {
        let limiter = AdminRateLimiter::with_limit(2);
        let ipv6 = IpAddr::V6("2001:db8::1".parse().unwrap());

        assert!(limiter.allow(ipv6));
        assert!(limiter.allow(ipv6));
        assert!(!limiter.allow(ipv6)); // Rate limited
    }

    #[test]
    fn test_admin_rate_limiter_concurrent() {
        // SECURITY TEST: Concurrent access to rate limiter
        // This test validates thread-safety under concurrent load

        use std::sync::Arc;
        use std::thread;

        const LIMIT: u32 = 50;
        const NUM_THREADS: usize = 10;
        const REQUESTS_PER_THREAD: usize = 10; // 10 * 10 = 100 total

        let limiter = Arc::new(AdminRateLimiter::with_limit(LIMIT));
        let test_addr = test_ip(42);

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

        // Total allowed should be exactly the limit
        assert_eq!(
            total_allowed, LIMIT as usize,
            "Exactly {} requests should be allowed, got {}",
            LIMIT, total_allowed
        );
    }

    #[test]
    fn test_rate_limit_response() {
        let response = rate_limit_response();

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers().get("Retry-After").unwrap(), "60");
        assert_eq!(
            response.headers().get("Content-Type").unwrap(),
            "application/json"
        );
    }
}
