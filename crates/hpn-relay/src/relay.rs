//! Relay server implementation.
//!
//! Forwards encrypted HPN packets between clients and upstream servers.

use std::collections::HashMap;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::time::Instant;

use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time;
use tracing::{debug, error, info, trace, warn};

use hpn_core::MessageType;
use hpn_core::protocol::{
    HEADER_SIZE, HandshakeFragment, HandshakeResponse, PacketHeader, ReassemblerConfig, Reassembly,
};

use crate::config::RelayConfig;
use crate::error::RelayResult;
use crate::metrics::RelayMetrics;
use crate::session::{ClientPacketProcessResult, SessionManager};

/// HPN relay server.
///
/// Forwards packets between clients and upstream server/relay without
/// decrypting the payload. Only inspects the header to extract session ID.
pub struct RelayServer {
    /// Relay configuration.
    config: RelayConfig,
    /// Session manager.
    sessions: Arc<SessionManager>,
    /// Client-facing socket.
    client_socket: Option<Arc<UdpSocket>>,
    /// Upstream socket.
    upstream_socket: Option<Arc<UdpSocket>>,
    /// Shutdown flag (atomic for lock-free checking in hot path).
    shutdown: Arc<AtomicBool>,
    /// Relay metrics.
    metrics: Arc<RelayMetrics>,
    /// Limits concurrent handshake forwarding tasks.
    handshake_limiter: Arc<Semaphore>,
    /// Per-IP handshake packet rate limiter.
    handshake_rate_limiter: Arc<HandshakeRateLimiter>,
}

/// Maximum number of additional packets to drain from socket without awaiting,
/// reducing scheduler wakeups under load.
const RECV_BURST_BATCH: usize = 32;

/// How long a dedicated handshake socket stays bound waiting for the upstream
/// response before the permit is released and the relay gives up on that
/// client's init.
///
/// Tuned down from 10s to 5s: on a healthy link, server+KEM decap complete
/// in 10-200ms; even a degraded satellite link rarely exceeds 2-3s. The 10s
/// ceiling was adding a 2x margin that wasn't helping legitimate clients but
/// was doubling the window during which a spoofed-source-IP handshake
/// squatted one of the 256 concurrent-handshake permits (cf. the matching
/// per-source and global rate limits). Paired with the global PPS budget
/// introduced earlier, this halves the worst-case DoS footprint.
const HANDSHAKE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_MAX_CONCURRENT_HANDSHAKES: usize = 256;
const DEFAULT_HANDSHAKE_RATE_LIMIT_PPS: u32 = 64;
const MAX_HANDSHAKE_RATE_TRACKED_IPS: usize = 16384;
const HANDSHAKE_RATE_IDLE_TTL: Duration = Duration::from_secs(10);

/// Relay-wide ceiling on new handshakes/s, independent of source IP.
///
/// The per-IP limiter ([`DEFAULT_HANDSHAKE_RATE_LIMIT_PPS`]) is trivially
/// bypassable with IP spoofing: an attacker cycling through N random source
/// addresses can push up to `N × max_pps` handshakes per second, each
/// consuming a concurrent-handshake permit for up to
/// [`HANDSHAKE_RESPONSE_TIMEOUT`]. With the defaults
/// (`DEFAULT_MAX_CONCURRENT_HANDSHAKES = 256`, 10 s timeout), ~26 spoofed
/// IPs/s are enough to squat every concurrent-handshake slot and deny the
/// service to every legitimate client.
///
/// This global ceiling is a hard cap on forwarded handshakes per second,
/// unrelated to the source IP. At 256 PPS it matches the concurrent-handshake
/// semaphore — sustained saturation refills the ring once per second and
/// excess spoofed packets are dropped cheaply (a single atomic compare).
const DEFAULT_GLOBAL_HANDSHAKE_RATE_LIMIT_PPS: u32 = 256;

#[derive(Clone, Copy, Debug)]
struct HandshakeRateEntry {
    window_start: Instant,
    count: u32,
}

#[derive(Debug)]
struct HandshakeRateLimiter {
    max_pps: u32,
    entries: Mutex<HashMap<IpAddr, HandshakeRateEntry>>,
    /// Global 1-second token bucket, shared across all source IPs. Checked
    /// BEFORE the per-IP bucket so spoof floods can't saturate the concurrent
    /// handshake semaphore even when every individual IP appears under the
    /// per-IP limit. Tuple is `(window_start, count_in_window)`.
    global: Mutex<(Instant, u32)>,
    global_max_pps: u32,
}

#[derive(Clone)]
struct HandshakeForwardContext {
    upstream_addr: SocketAddr,
    buffer_size: usize,
    sessions: Arc<SessionManager>,
    client_tx: Arc<UdpSocket>,
    metrics: Arc<RelayMetrics>,
}

impl HandshakeRateLimiter {
    fn new(max_pps: u32, global_max_pps: u32) -> Self {
        Self {
            max_pps,
            entries: Mutex::new(HashMap::new()),
            global: Mutex::new((Instant::now(), 0)),
            global_max_pps,
        }
    }

    fn allow(&self, ip: IpAddr) -> bool {
        let now = Instant::now();

        // Global 1-second bucket first. Rejecting here costs a single mutex
        // lock + integer compare, no map traversal — so spoof floods are
        // cheap to shed before they can disturb the per-IP map or the
        // concurrent-handshake semaphore. `global_max_pps = 0` disables the
        // ceiling for operators who want the legacy behaviour.
        if self.global_max_pps > 0 {
            let mut global = self.global.lock();
            let (window_start, count) = &mut *global;
            if now.duration_since(*window_start) >= Duration::from_secs(1) {
                *window_start = now;
                *count = 0;
            }
            if *count >= self.global_max_pps {
                return false;
            }
            *count = count.saturating_add(1);
        }

        let mut entries = self.entries.lock();

        if entries.len() >= MAX_HANDSHAKE_RATE_TRACKED_IPS {
            entries.retain(|_, entry| {
                now.duration_since(entry.window_start) <= HANDSHAKE_RATE_IDLE_TTL
            });
            if entries.len() >= MAX_HANDSHAKE_RATE_TRACKED_IPS {
                return false;
            }
        }

        let entry = entries.entry(ip).or_insert(HandshakeRateEntry {
            window_start: now,
            count: 0,
        });

        if now.duration_since(entry.window_start) >= Duration::from_secs(1) {
            entry.window_start = now;
            entry.count = 0;
        }

        if entry.count >= self.max_pps {
            return false;
        }

        entry.count = entry.count.saturating_add(1);
        true
    }
}

async fn handle_upstream_packet(
    data: &[u8],
    sessions: &SessionManager,
    client_tx: &UdpSocket,
    metrics: &RelayMetrics,
) {
    if data.len() < HEADER_SIZE {
        return;
    }

    // Parse header to get session ID
    if let Ok(header) = PacketHeader::decode(data) {
        let session_id = header.session_id;

        // Check rate limits on upstream->client path
        if sessions.is_rate_limited() && !sessions.check_upstream_rate_limit(session_id, data.len())
        {
            trace!(
                "Rate limited upstream packet for session {} ({} bytes)",
                session_id,
                data.len()
            );
            metrics.record_drop();
            return;
        }

        // Look up client, record stats, and touch - all in one operation
        if let Some(client_addr) = sessions.process_upstream_packet(session_id, data.len()) {
            if let Err(e) = client_tx.send_to(data, client_addr).await {
                warn!(
                    "Failed to send to client {}: {}",
                    crate::privacy::addr(client_addr),
                    e
                );
            } else {
                metrics.record_return(data.len());
                trace!(
                    "Forwarded {} bytes to client {} (session {})",
                    data.len(),
                    crate::privacy::addr(client_addr),
                    session_id
                );
            }
        } else if header.msg_type == MessageType::HandshakeResponse {
            warn!(
                "Dropping unexpected handshake response for session {} on shared upstream socket",
                session_id
            );
            metrics.record_drop();
        } else {
            debug!("No client for session {}", session_id);
        }
    }
}

async fn forward_handshake_packet(
    data: Vec<u8>,
    client_addr: SocketAddr,
    ctx: HandshakeForwardContext,
    _permit: OwnedSemaphorePermit,
) {
    let bind_addr = if ctx.upstream_addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };

    let handshake_socket = match UdpSocket::bind(bind_addr).await {
        Ok(socket) => socket,
        Err(e) => {
            warn!(
                "Failed to bind dedicated handshake socket for {} via {}: {}",
                crate::privacy::addr(client_addr),
                bind_addr,
                e
            );
            ctx.metrics.record_drop();
            return;
        }
    };

    if let Err(e) = handshake_socket.connect(ctx.upstream_addr).await {
        warn!(
            "Failed to connect dedicated handshake socket for {} to {}: {}",
            crate::privacy::addr(client_addr),
            ctx.upstream_addr,
            e
        );
        ctx.metrics.record_drop();
        return;
    }

    if let Err(e) = handshake_socket.send(&data).await {
        warn!(
            "Failed to forward handshake from {} to upstream {}: {}",
            crate::privacy::addr(client_addr),
            ctx.upstream_addr,
            e
        );
        ctx.metrics.record_drop();
        return;
    }

    ctx.metrics.record_forward(data.len());
    trace!(
        "Forwarded handshake packet from {} to upstream {} via dedicated socket",
        crate::privacy::addr(client_addr),
        ctx.upstream_addr
    );

    // Bootstrap response handling.
    //
    // Post-quantum handshake responses at Security Level 5 serialise to
    // roughly 9 KB and at Level 3 to roughly 6.5 KB — both well above any
    // reasonable UDP MTU. The server fragments them at the protocol layer
    // (see `hpn_core::protocol::fragment::HandshakeFragment`), so the relay
    // must:
    //
    //   1. Drain every datagram on the dedicated socket up to the response
    //      deadline, NOT just the first one.
    //   2. Forward each datagram to the client immediately so they can start
    //      reassembling without round-trip latency.
    //   3. Reassemble locally as well — once the full `HandshakeResponse`
    //      payload is available, the leading 8 bytes give us the real
    //      `session_id` the upstream server allocated. That session id is
    //      what we bind to the client address so that subsequent data-plane
    //      packets resolve to the same client.
    //   4. Use `bind_established` (NOT `get_or_create`) so a forged response
    //      carrying `SessionId(0)` cannot install itself at `sessions[0]`.
    //
    // A non-fragmented `HandshakeResponse` (rare on PQ, possible on legacy
    // configurations) is still accepted via the fast path. `CookieRequest`
    // returns to the client unchanged; the client then retries with a
    // `CookieReply` which the bootstrap branch routes through a fresh
    // dedicated socket.
    let mut response_buf = vec![0u8; ctx.buffer_size];
    let mut reassembly = Reassembly::new(ReassemblerConfig::client_default());
    let reassembly_key = ctx.upstream_addr;
    let deadline = tokio::time::Instant::now() + HANDSHAKE_RESPONSE_TIMEOUT;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            warn!(
                "Timed out waiting for handshake response from upstream {} for {}",
                ctx.upstream_addr,
                crate::privacy::addr(client_addr)
            );
            ctx.metrics.record_drop();
            return;
        }

        let response_len =
            match time::timeout(remaining, handshake_socket.recv(&mut response_buf)).await {
                Ok(Ok(len)) => len,
                Ok(Err(e)) => {
                    warn!(
                        "Failed to receive handshake response from upstream {} for {}: {}",
                        ctx.upstream_addr,
                        crate::privacy::addr(client_addr),
                        e
                    );
                    ctx.metrics.record_drop();
                    return;
                }
                Err(_) => {
                    warn!(
                        "Timed out waiting for handshake response from upstream {} for {}",
                        ctx.upstream_addr,
                        crate::privacy::addr(client_addr)
                    );
                    ctx.metrics.record_drop();
                    return;
                }
            };

        let response = &response_buf[..response_len];
        let header = match PacketHeader::decode(response) {
            Ok(header) => header,
            Err(e) => {
                debug!(
                    "Dropped malformed handshake response from upstream {} for {}: {}",
                    ctx.upstream_addr,
                    crate::privacy::addr(client_addr),
                    e
                );
                ctx.metrics.record_drop();
                continue;
            }
        };

        match header.msg_type {
            MessageType::HandshakeResponse => {
                let session_id = header.session_id;
                if !ctx.sessions.bind_established(session_id, client_addr) {
                    warn!(
                        "Failed to bind upstream session {} for client {} (refused or capacity)",
                        session_id,
                        crate::privacy::addr(client_addr)
                    );
                    ctx.metrics.record_drop();
                    return;
                }
                if let Err(e) = ctx.client_tx.send_to(response, client_addr).await {
                    warn!(
                        "Failed to forward handshake response for session {} to {}: {}",
                        session_id,
                        crate::privacy::addr(client_addr),
                        e
                    );
                    // F-3: roll back the bind so the per-IP counter does
                    // not stay incremented for the full session timeout
                    // when the client became unreachable mid-bootstrap.
                    ctx.sessions.remove(session_id);
                    ctx.metrics.record_drop();
                    return;
                }
                ctx.metrics.record_return(response_len);
                ctx.metrics.record_session_created();
                debug!(
                    "Bound upstream session {} to client {} via dedicated handshake socket",
                    session_id,
                    crate::privacy::addr(client_addr)
                );
                return;
            }
            MessageType::HandshakeFragment => {
                let fragment_bytes = &response[HEADER_SIZE..];
                let fragment = match HandshakeFragment::from_bytes(fragment_bytes) {
                    Ok(f) => f,
                    Err(e) => {
                        debug!(
                            "Dropped malformed HandshakeFragment from upstream {} for {}: {}",
                            ctx.upstream_addr,
                            crate::privacy::addr(client_addr),
                            e
                        );
                        ctx.metrics.record_drop();
                        continue;
                    }
                };

                if fragment.inner_msg_type != MessageType::HandshakeResponse {
                    debug!(
                        "Dropped HandshakeFragment with unexpected inner type {:?} from upstream {} for {}",
                        fragment.inner_msg_type,
                        ctx.upstream_addr,
                        crate::privacy::addr(client_addr)
                    );
                    ctx.metrics.record_drop();
                    continue;
                }

                // F-2: validate the fragment through the local reassembler
                // BEFORE forwarding it to the client. If the relay's own
                // reassembler caps reject this fragment (oversize payload,
                // contradictory frag_total, per-entry byte budget exceeded,
                // duplicate), we drop instead of forwarding — a compromised
                // upstream otherwise gains a bandwidth-amplification
                // primitive: the relay would forward fragments toward the
                // client which it cannot itself reassemble.
                //
                // `reassembly.insert` takes ownership of `fragment`, so we
                // clone the on-wire bytes for the forward-to-client step
                // before handing the parsed struct to the reassembler.
                let fragment_to_forward = response.to_vec();
                let stats_before = reassembly.stats();
                let insert_outcome = reassembly.insert(reassembly_key, fragment);
                let stats_after = reassembly.stats();

                let rejected_by_reassembler = stats_after.fragments_dropped
                    > stats_before.fragments_dropped
                    || stats_after.entries_rejected > stats_before.entries_rejected
                    || stats_after.fragments_duplicate > stats_before.fragments_duplicate;

                if rejected_by_reassembler {
                    debug!(
                        "Fragment from upstream {} for {} rejected by reassembler caps — not forwarding",
                        ctx.upstream_addr,
                        crate::privacy::addr(client_addr)
                    );
                    ctx.metrics.record_drop();
                    continue;
                }

                if let Err(e) = ctx
                    .client_tx
                    .send_to(&fragment_to_forward, client_addr)
                    .await
                {
                    warn!(
                        "Failed to forward HandshakeFragment to {}: {}",
                        crate::privacy::addr(client_addr),
                        e
                    );
                    ctx.metrics.record_drop();
                    return;
                }
                ctx.metrics.record_return(response_len);

                if let Some((_, payload)) = insert_outcome {
                    let session_id = match HandshakeResponse::session_id_from_bytes(&payload) {
                        Ok(id) => id,
                        Err(e) => {
                            warn!(
                                "Reassembled HandshakeResponse too short to carry session_id from upstream {} for {}: {}",
                                ctx.upstream_addr,
                                crate::privacy::addr(client_addr),
                                e
                            );
                            ctx.metrics.record_drop();
                            return;
                        }
                    };
                    if !ctx.sessions.bind_established(session_id, client_addr) {
                        warn!(
                            "Failed to bind reassembled upstream session {} for client {}",
                            session_id,
                            crate::privacy::addr(client_addr)
                        );
                        ctx.metrics.record_drop();
                        return;
                    }
                    // No rollback is needed here: `bind_established` is
                    // the LAST step in this branch — all fragments have
                    // already been forwarded individually above (each
                    // with its own `send_to` failure handler that
                    // returns early without binding). By the time we
                    // reach this point, the client has received every
                    // fragment it needs to reassemble the response on
                    // its own side, so the freshly-bound session id is
                    // the correct end state to commit.
                    ctx.metrics.record_session_created();
                    debug!(
                        "Bound upstream session {} to client {} after handshake reassembly",
                        session_id,
                        crate::privacy::addr(client_addr)
                    );
                    return;
                }
                // Still missing fragments — keep draining the socket.
            }
            MessageType::CookieRequest => {
                // Forward the cookie challenge to the client and terminate
                // this attempt. The client will retry through the bootstrap
                // branch with a `CookieReply` payload.
                if let Err(e) = ctx.client_tx.send_to(response, client_addr).await {
                    warn!(
                        "Failed to forward CookieRequest to {}: {}",
                        crate::privacy::addr(client_addr),
                        e
                    );
                    ctx.metrics.record_drop();
                    return;
                }
                ctx.metrics.record_return(response_len);
                debug!(
                    "Forwarded CookieRequest from upstream {} to client {}",
                    ctx.upstream_addr,
                    crate::privacy::addr(client_addr)
                );
                return;
            }
            other => {
                debug!(
                    "Dropped unexpected bootstrap response msg_type {:?} from upstream {} for {}",
                    other,
                    ctx.upstream_addr,
                    crate::privacy::addr(client_addr)
                );
                ctx.metrics.record_drop();
                continue;
            }
        }
    }
}

impl RelayServer {
    /// Create a new relay server.
    pub fn new(config: RelayConfig) -> RelayResult<Self> {
        Self::with_shutdown(config, Arc::new(AtomicBool::new(false)))
    }

    /// Create a new relay server with external shutdown flag.
    pub fn with_shutdown(config: RelayConfig, shutdown: Arc<AtomicBool>) -> RelayResult<Self> {
        config.validate()?;

        let sessions = Arc::new(SessionManager::with_rate_limits(
            config.session_timeout(),
            config.max_sessions,
            config.rate_limit_pps.unwrap_or(0),
            config.rate_limit_bps.unwrap_or(0),
        ));

        let metrics = Arc::new(RelayMetrics::new());
        let handshake_limiter = Arc::new(Semaphore::new(
            config
                .max_concurrent_handshakes
                .unwrap_or(DEFAULT_MAX_CONCURRENT_HANDSHAKES),
        ));
        let handshake_rate_limiter = Arc::new(HandshakeRateLimiter::new(
            config
                .handshake_rate_limit_pps
                .unwrap_or(DEFAULT_HANDSHAKE_RATE_LIMIT_PPS),
            config
                .handshake_global_rate_limit_pps
                .unwrap_or(DEFAULT_GLOBAL_HANDSHAKE_RATE_LIMIT_PPS),
        ));
        Ok(Self {
            config,
            sessions,
            client_socket: None,
            upstream_socket: None,
            shutdown,
            metrics,
            handshake_limiter,
            handshake_rate_limiter,
        })
    }

    /// Get metrics reference.
    pub fn metrics(&self) -> &Arc<RelayMetrics> {
        &self.metrics
    }

    /// Run the relay server.
    pub async fn run(&mut self) -> RelayResult<()> {
        // Warn if rate limiting is not configured (security best practice for production)
        if !self.config.has_rate_limits() {
            warn!(
                "Rate limiting is not configured. Consider setting rate_limit_pps and/or rate_limit_bps for production use."
            );
        }

        // Initialize privacy/no-log mode
        crate::privacy::init(self.config.no_log);
        if self.config.no_log {
            info!("No-log mode ENABLED — IP addresses will be redacted from logs");
        }

        // Bind client-facing socket
        let client_socket = UdpSocket::bind(self.config.listen_addr).await?;
        info!("Relay listening on {}", self.config.listen_addr);

        // Create upstream socket (ephemeral port)
        // Match address family of upstream server for IPv4/IPv6 compatibility
        let upstream_bind_addr = if self.config.upstream_addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let upstream_socket = UdpSocket::bind(upstream_bind_addr).await?;
        upstream_socket.connect(self.config.upstream_addr).await?;
        let local_addr = upstream_socket.local_addr()?;
        info!(
            "Upstream socket bound to {}, forwarding to {}",
            local_addr, self.config.upstream_addr
        );

        let client_socket = Arc::new(client_socket);
        let upstream_socket = Arc::new(upstream_socket);

        self.client_socket = Some(Arc::clone(&client_socket));
        self.upstream_socket = Some(Arc::clone(&upstream_socket));

        // Spawn cleanup task
        let sessions_cleanup = Arc::clone(&self.sessions);
        let shutdown_cleanup = Arc::clone(&self.shutdown);
        let metrics_cleanup = Arc::clone(&self.metrics);
        let timeout = self.config.session_timeout();
        tokio::spawn(async move {
            let mut interval = time::interval(timeout / 2);
            loop {
                interval.tick().await;
                if shutdown_cleanup.load(Ordering::Relaxed) {
                    break;
                }
                let expired = sessions_cleanup.cleanup_expired();
                if expired > 0 {
                    debug!("Cleaned up {} expired relay sessions", expired);
                    // Update metrics for each removed session
                    for _ in 0..expired {
                        metrics_cleanup.record_session_removed();
                    }
                }
            }
        });

        // Spawn stats reporting task if enabled
        if self.config.enable_stats {
            let sessions_stats = Arc::clone(&self.sessions);
            let shutdown_stats = Arc::clone(&self.shutdown);
            let interval = self.config.stats_interval();
            let relay_id = self.config.relay_id.clone();
            tokio::spawn(async move {
                let mut timer = time::interval(interval);
                loop {
                    timer.tick().await;
                    if shutdown_stats.load(Ordering::Relaxed) {
                        break;
                    }
                    let stats = sessions_stats.aggregate_stats();
                    if let Some(ref id) = relay_id {
                        info!("[{}] {}", id, stats.format());
                    } else {
                        info!("{}", stats.format());
                    }
                }
            });
        }

        // Spawn metrics logging task (always active)
        let metrics_log = Arc::clone(&self.metrics);
        let shutdown_metrics = Arc::clone(&self.shutdown);
        tokio::spawn(async move {
            let mut interval = time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                if shutdown_metrics.load(Ordering::Relaxed) {
                    break;
                }
                info!("Relay metrics: {}", metrics_log.summary());
            }
        });

        // Spawn metrics HTTP server if enabled
        if self.config.enable_metrics {
            let metrics_http = Arc::clone(&self.metrics);
            let metrics_addr = self.config.metrics_addr;
            let metrics_token = self.config.metrics_auth_token.clone();
            tokio::spawn(async move {
                let server = crate::metrics::MetricsHttpServer::new(
                    metrics_http,
                    metrics_addr,
                    metrics_token,
                );
                if let Err(e) = server.run().await {
                    error!("Metrics HTTP server error: {}", e);
                }
            });
        }

        // Spawn upstream health check task
        let metrics_health = Arc::clone(&self.metrics);
        let shutdown_health = Arc::clone(&self.shutdown);
        let upstream_addr = self.config.upstream_addr;
        let relay_id = self.config.relay_id.clone();
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(30));
            // Create a dedicated socket for health probes
            // Bind to IPv4 or IPv6 based on upstream address family
            let bind_addr = if upstream_addr.is_ipv6() {
                "[::]:0"
            } else {
                "0.0.0.0:0"
            };
            let probe_socket = match UdpSocket::bind(bind_addr).await {
                Ok(s) => s,
                Err(e) => {
                    error!(
                        "Failed to create health probe socket ({}): {}",
                        bind_addr, e
                    );
                    return;
                }
            };

            // Set a short timeout for the probe socket
            // We use connect + send pattern for better error detection
            if let Err(e) = probe_socket.connect(upstream_addr).await {
                warn!("Failed to connect probe socket to {}: {}", upstream_addr, e);
                metrics_health.set_upstream_healthy(false);
                metrics_health.record_upstream_probe(false);
            }

            loop {
                interval.tick().await;
                if shutdown_health.load(Ordering::Relaxed) {
                    break;
                }

                // Send a minimal probe packet (single byte)
                // This tests network reachability; a proper HPN server will ignore this
                // as it's too short to be a valid packet
                let probe_result = probe_socket.send(&[0u8; 1]).await;

                match probe_result {
                    Ok(_) => {
                        let was_unhealthy = !metrics_health.is_upstream_healthy();
                        metrics_health.set_upstream_healthy(true);
                        metrics_health.record_upstream_probe(true);

                        if was_unhealthy {
                            if let Some(ref id) = relay_id {
                                info!("[{}] Upstream {} is now reachable", id, upstream_addr);
                            } else {
                                info!("Upstream {} is now reachable", upstream_addr);
                            }
                        } else {
                            debug!("Upstream {} health check passed", upstream_addr);
                        }
                    }
                    Err(e) => {
                        let was_healthy = metrics_health.is_upstream_healthy();
                        metrics_health.set_upstream_healthy(false);
                        metrics_health.record_upstream_probe(false);

                        if was_healthy {
                            if let Some(ref id) = relay_id {
                                warn!("[{}] Upstream {} is unreachable: {}", id, upstream_addr, e);
                            } else {
                                warn!("Upstream {} is unreachable: {}", upstream_addr, e);
                            }
                        } else {
                            debug!("Upstream {} still unreachable: {}", upstream_addr, e);
                        }
                    }
                }
            }
        });

        // Spawn upstream receiver
        let upstream_rx = Arc::clone(&upstream_socket);
        let client_tx = Arc::clone(&client_socket);
        let sessions_upstream = Arc::clone(&self.sessions);
        let shutdown_upstream = Arc::clone(&self.shutdown);
        let metrics_upstream = Arc::clone(&self.metrics);
        let buffer_size = self.config.buffer_size;

        tokio::spawn(async move {
            let mut buf = vec![0u8; buffer_size];
            loop {
                if shutdown_upstream.load(Ordering::Relaxed) {
                    break;
                }

                match upstream_rx.recv(&mut buf).await {
                    Ok(n) => {
                        handle_upstream_packet(
                            &buf[..n],
                            &sessions_upstream,
                            &client_tx,
                            &metrics_upstream,
                        )
                        .await;

                        // Drain an additional burst without awaiting.
                        for _ in 0..RECV_BURST_BATCH {
                            match upstream_rx.try_recv(&mut buf) {
                                Ok(m) => {
                                    handle_upstream_packet(
                                        &buf[..m],
                                        &sessions_upstream,
                                        &client_tx,
                                        &metrics_upstream,
                                    )
                                    .await;
                                }
                                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                                Err(e) => {
                                    if !shutdown_upstream.load(Ordering::Relaxed) {
                                        error!("Upstream try_recv_from error: {}", e);
                                    }
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        if !shutdown_upstream.load(Ordering::Relaxed) {
                            error!("Upstream receive error: {}", e);
                        }
                    }
                }
            }
        });

        // Main loop: receive from clients, forward to upstream
        let mut buf = vec![0u8; self.config.buffer_size];
        let upstream_addr = self.config.upstream_addr;

        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                break;
            }

            tokio::select! {
                result = client_socket.recv_from(&mut buf) => {
                    match result {
                        Ok((n, client_addr)) if n >= HEADER_SIZE => {
                            self.handle_client_packet(&buf[..n], client_addr, &client_socket, &upstream_socket, upstream_addr).await;

                            // Drain an additional burst without awaiting.
                            for _ in 0..RECV_BURST_BATCH {
                                match client_socket.try_recv_from(&mut buf) {
                                    Ok((m, addr)) if m >= HEADER_SIZE => {
                                        self.handle_client_packet(&buf[..m], addr, &client_socket, &upstream_socket, upstream_addr).await;
                                    }
                                    Ok(_) => {
                                        trace!("Packet too short from client");
                                    }
                                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                                    Err(e) => {
                                        if !self.shutdown.load(Ordering::Relaxed) {
                                            error!("Client try_recv_from error: {}", e);
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                        Ok(_) => {
                            trace!("Packet too short from client");
                        }
                        Err(e) => {
                            if !self.shutdown.load(Ordering::Relaxed) {
                                error!("Client receive error: {}", e);
                            }
                        }
                    }
                }
            }
        }

        info!("Relay server shutting down");
        Ok(())
    }

    /// Handle a packet from a client.
    async fn handle_client_packet(
        &self,
        data: &[u8],
        client_addr: SocketAddr,
        client_socket: &Arc<UdpSocket>,
        upstream_socket: &UdpSocket,
        upstream_addr: SocketAddr,
    ) {
        // Parse header to get session ID
        let header = match PacketHeader::decode(data) {
            Ok(h) => h,
            Err(e) => {
                debug!(
                    "Invalid header from {}: {}",
                    crate::privacy::addr(client_addr),
                    e
                );
                return;
            }
        };

        let session_id = header.session_id;

        // Any pre-session / handshake-related packet from the client has to
        // travel through the dedicated forwarding socket so the upstream
        // server's reply lands in this task (not on the shared upstream
        // socket where there is no session id yet). Includes:
        //   - HandshakeInit, EncryptedHandshakeInit: opening messages.
        //   - HandshakeFragment: client-side fragmentation of an oversize
        //     `EncryptedHandshakeInit` payload.
        //   - CookieReply: response to a `CookieRequest` from the server
        //     when cookie anti-DoS is enabled.
        if matches!(
            header.msg_type,
            MessageType::HandshakeInit
                | MessageType::EncryptedHandshakeInit
                | MessageType::HandshakeFragment
                | MessageType::CookieReply
        ) {
            if !self.handshake_rate_limiter.allow(client_addr.ip()) {
                trace!(
                    "Rate limited handshake packet from {} (msg_type={:?})",
                    crate::privacy::addr(client_addr),
                    header.msg_type
                );
                self.metrics.record_drop();
                return;
            }

            let permit = match Arc::clone(&self.handshake_limiter).try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    warn!(
                        "Dropping handshake packet from {}: too many concurrent handshakes",
                        crate::privacy::addr(client_addr)
                    );
                    self.metrics.record_drop();
                    return;
                }
            };

            tokio::spawn(forward_handshake_packet(
                data.to_vec(),
                client_addr,
                HandshakeForwardContext {
                    upstream_addr,
                    buffer_size: self.config.buffer_size,
                    sessions: Arc::clone(&self.sessions),
                    client_tx: Arc::clone(client_socket),
                    metrics: Arc::clone(&self.metrics),
                },
                permit,
            ));
            return;
        }

        match self
            .sessions
            .process_client_packet(session_id, client_addr, data.len())
        {
            ClientPacketProcessResult::Forward { is_new } => {
                if is_new {
                    debug!(
                        "New relay session {} from {} (msg_type={:?})",
                        session_id,
                        crate::privacy::addr(client_addr),
                        header.msg_type
                    );
                    self.metrics.record_session_created();
                }
            }
            ClientPacketProcessResult::RateLimited => {
                trace!(
                    "Rate limited: session {} from {} ({} bytes)",
                    session_id,
                    crate::privacy::addr(client_addr),
                    data.len()
                );
                self.metrics.record_drop();
                return;
            }
            ClientPacketProcessResult::RoamingBlocked => {
                debug!(
                    "Blocked client packet for session {} from unexpected address {}",
                    session_id,
                    crate::privacy::addr(client_addr)
                );
                self.metrics.record_drop();
                return;
            }
            ClientPacketProcessResult::SessionRejected => {
                debug!(
                    "Rejected client packet for session {} from {}",
                    session_id,
                    crate::privacy::addr(client_addr)
                );
                self.metrics.record_drop();
                return;
            }
        }

        // Forward to upstream
        if let Err(e) = upstream_socket.send_to(data, upstream_addr).await {
            warn!("Failed to forward to upstream {}: {}", upstream_addr, e);
        } else {
            self.metrics.record_forward(data.len());
            trace!(
                "Forwarded {} bytes from {} to upstream (session {})",
                data.len(),
                crate::privacy::addr(client_addr),
                session_id
            );
        }
    }

    /// Shutdown the relay server.
    pub fn shutdown(&self) {
        info!("Relay shutdown requested");
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Check if server is shutting down.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    /// Get current session count.
    pub fn session_count(&self) -> usize {
        self.sessions.session_count()
    }

    /// Get aggregate statistics.
    pub fn stats(&self) -> crate::session::AggregateStats {
        self.sessions.aggregate_stats()
    }
}

// ---------------------------------------------------------------------------
// Batch I/O data plane (Linux only, experimental)
// ---------------------------------------------------------------------------

/// Run the high-performance data plane using recvmmsg/sendmmsg on Linux.
///
/// Spawns two OS threads:
/// - **client_receiver**: `recvmmsg` on client socket → process → `sendmmsg` to upstream
/// - **upstream_receiver**: `recvmmsg` on upstream socket → process → `sendmmsg` to clients
///
/// **Experimental** — gated behind the `batch-io` Cargo feature.
/// `RelayServer::run` does NOT call this function today; an operator who
/// wants the throughput gain must wire it from their own `main` after
/// stopping the tokio data-plane tasks. See audit item M-8: integration
/// tests for this path are still missing, and `process_client_packet`
/// has a known race in the tokio path that should be fixed first so the
/// two paths share identical semantics.
#[cfg(all(target_os = "linux", feature = "batch-io"))]
pub fn spawn_batch_data_plane(
    client_std: std::net::UdpSocket,
    upstream_std: std::net::UdpSocket,
    upstream_addr: SocketAddr,
    sessions: Arc<crate::session::SessionManager>,
    metrics: Arc<crate::metrics::RelayMetrics>,
    shutdown: Arc<AtomicBool>,
    buffer_size: usize,
) -> Vec<std::thread::JoinHandle<()>> {
    use crate::batch_io::{MAX_BATCH_SIZE, RecvBatch, SendBatch};

    let mut handles = Vec::new();

    // Thread 1: Client → Upstream (data forwarding)
    {
        let client_sock = client_std.try_clone().expect("clone client socket");
        let upstream_sock = upstream_std.try_clone().expect("clone upstream socket");
        let sessions = Arc::clone(&sessions);
        let metrics = Arc::clone(&metrics);
        let shutdown = Arc::clone(&shutdown);

        let handle = std::thread::Builder::new()
            .name("relay-client-recv".into())
            .spawn(move || {
                let mut recv_batch = RecvBatch::new(MAX_BATCH_SIZE, buffer_size);
                let mut send_batch = SendBatch::new(MAX_BATCH_SIZE, buffer_size);

                while !shutdown.load(Ordering::Relaxed) {
                    let count = match recv_batch.recv(&client_sock) {
                        Ok(0) => {
                            // EAGAIN — short sleep to avoid busy-spin
                            std::thread::sleep(Duration::from_micros(50));
                            continue;
                        }
                        Ok(n) => n,
                        Err(e) => {
                            if !shutdown.load(Ordering::Relaxed) {
                                tracing::error!("Client recvmmsg error: {}", e);
                            }
                            break;
                        }
                    };

                    for i in 0..count {
                        let (data, addr) = recv_batch.get(i);
                        let Some(client_addr) = addr else { continue };
                        if data.len() < HEADER_SIZE {
                            continue;
                        }

                        let header = match PacketHeader::decode(data) {
                            Ok(h) => h,
                            Err(_) => continue,
                        };

                        // Skip handshake / pre-session packets — they are
                        // handled by the tokio async path through
                        // `forward_handshake_packet`. Mirrors the bootstrap
                        // branch in the non-batch data plane so handshake
                        // reassembly and cookie challenges remain on the
                        // dedicated socket regardless of which I/O backend
                        // is active.
                        if matches!(
                            header.msg_type,
                            MessageType::HandshakeInit
                                | MessageType::HandshakeResponse
                                | MessageType::EncryptedHandshakeInit
                                | MessageType::HandshakeFragment
                                | MessageType::CookieRequest
                                | MessageType::CookieReply
                        ) {
                            continue;
                        }

                        let result = sessions.process_client_packet(
                            header.session_id,
                            client_addr,
                            data.len(),
                        );

                        match result {
                            crate::session::ClientPacketProcessResult::Forward { is_new } => {
                                if is_new {
                                    metrics.record_session_created();
                                }
                                send_batch.add(data, upstream_addr);
                                metrics.record_forward(data.len());
                            }
                            _ => {
                                metrics.record_drop();
                            }
                        }

                        if send_batch.is_full() {
                            let _ = send_batch.flush(&upstream_sock);
                        }
                    }

                    // Flush remaining
                    if !send_batch.is_empty() {
                        let _ = send_batch.flush(&upstream_sock);
                    }
                }

                info!("Client receiver batch thread exiting");
            })
            .expect("spawn client-recv thread");
        handles.push(handle);
    }

    // Thread 2: Upstream → Client (return forwarding)
    {
        let client_sock = client_std;
        let upstream_sock = upstream_std;
        let sessions = Arc::clone(&sessions);
        let metrics = Arc::clone(&metrics);
        let shutdown = Arc::clone(&shutdown);

        let handle = std::thread::Builder::new()
            .name("relay-upstream-recv".into())
            .spawn(move || {
                let mut recv_batch = RecvBatch::new(MAX_BATCH_SIZE, buffer_size);
                let mut send_batch = SendBatch::new(MAX_BATCH_SIZE, buffer_size);

                while !shutdown.load(Ordering::Relaxed) {
                    let count = match recv_batch.recv(&upstream_sock) {
                        Ok(0) => {
                            std::thread::sleep(Duration::from_micros(50));
                            continue;
                        }
                        Ok(n) => n,
                        Err(e) => {
                            if !shutdown.load(Ordering::Relaxed) {
                                tracing::error!("Upstream recvmmsg error: {}", e);
                            }
                            break;
                        }
                    };

                    for i in 0..count {
                        let (data, _addr) = recv_batch.get(i);
                        if data.len() < HEADER_SIZE {
                            continue;
                        }

                        let header = match PacketHeader::decode(data) {
                            Ok(h) => h,
                            Err(_) => continue,
                        };

                        // Rate limit check on upstream→client path
                        if sessions.is_rate_limited()
                            && !sessions.check_upstream_rate_limit(header.session_id, data.len())
                        {
                            metrics.record_drop();
                            continue;
                        }

                        if let Some(client_addr) =
                            sessions.process_upstream_packet(header.session_id, data.len())
                        {
                            send_batch.add(data, client_addr);
                            metrics.record_return(data.len());
                        } else {
                            metrics.record_drop();
                        }

                        if send_batch.is_full() {
                            let _ = send_batch.flush(&client_sock);
                        }
                    }

                    if !send_batch.is_empty() {
                        let _ = send_batch.flush(&client_sock);
                    }
                }

                info!("Upstream receiver batch thread exiting");
            })
            .expect("spawn upstream-recv thread");
        handles.push(handle);
    }

    info!(
        "Batch I/O data plane started (2 threads, batch_size={})",
        MAX_BATCH_SIZE
    );
    handles
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_server_creation() {
        let config = RelayConfig::default();
        let relay = RelayServer::new(config);
        assert!(relay.is_ok());
    }

    #[test]
    fn test_relay_config_validation() {
        let config = RelayConfig {
            max_sessions: 0,
            ..Default::default()
        };
        let relay = RelayServer::new(config);
        assert!(relay.is_err());
    }
}
