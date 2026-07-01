//! Main VPN server implementation.
//!
//! Handles incoming client connections, handshakes, and packet routing.
//!
//! # Performance Optimizations
//!
//! This implementation uses several techniques for high throughput:
//! - **Crossbeam channels**: Lock-free MPMC channels for minimal contention
//! - **Buffer pool**: Pre-allocated buffers to avoid per-packet allocations
//! - **Separate I/O threads**: Dedicated TUN read/write threads for parallelism
//! - **Batch processing**: Process multiple packets per iteration when available
//!
//! # DoS Protection
//!
//! The server implements multiple layers of DoS attack mitigation:
//! - **Rate limiting**: Max 5 handshakes per IP per minute (prevents amplification)
//! - **Silent drops**: Rate-limited requests receive no response (anti-probing)
//! - **Session bounds**: Session count capped by the IPv4 pool size
//! - **Memory bounds**: Max tracked IPs (100K) prevents memory exhaustion
//!
//! **Amplification factor**: Handshake response (~6.5KB) vs request (~1.2KB) = 5.4x
//! With rate limiting at 5/min/IP, max amplification is ~32KB/min/IP.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

#[cfg(target_os = "linux")]
use bytes::Bytes;
use crossbeam_channel::{Receiver, Sender, bounded};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time;
use tracing::{debug, error, info, trace, warn};

use hpn_core::crypto::{HybridPublicKey, HybridSecretKey, MlDsaKeypair, SecurityLevel, aead};
use hpn_core::protocol::{
    EncryptedHandshakeInit, HEADER_SIZE, HandshakeFragment, HandshakeInit, PacketHeader,
    ReassemblerConfig, Reassembly, ServerHandshake, Session, SignedRebindAckPayload, TunnelConfig,
    build_handshake_fragments, fragment::FRAGMENTATION_THRESHOLD,
};
use hpn_core::types::{MessageType, SessionId};

#[cfg(all(target_os = "linux", feature = "afxdp"))]
use crate::auto_tune::NetworkBackend;
#[cfg(target_os = "linux")]
use crate::auto_tune::RuntimeConfig;
use crate::config::ServerConfig;
use crate::error::{ServerError, ServerResult};
use crate::nat::NatManager;
use crate::routing;
use crate::session_manager::SessionManager;
use crate::tun::{DestinationAddr, TunDevice, get_destination_addr};
#[cfg(target_os = "linux")]
use crate::tun_multiqueue::MultiQueueTun;
#[cfg(target_os = "linux")]
use crate::udp_workers::{OutboundResponse, UdpWorkerPool, WorkerControl};

/// Maximum packet size.
const MAX_PACKET_SIZE: usize = 65535;

/// Channel capacity for TUN I/O.
///
/// Reduced from 8192 to 2048 for better memory efficiency while maintaining
/// sufficient buffering for burst traffic. With multiqueue enabled, contention
/// is minimal so large buffers provide diminishing returns.
const TUN_CHANNEL_CAPACITY: usize = 2048;

/// Default maximum worker panics before entering degraded mode.
const DEFAULT_MAX_WORKER_PANICS: u32 = 3;

/// Worker health tracker for monitoring and handling TUN worker panics.
///
/// Tracks panic counts across all TUN workers and provides mechanisms to:
/// - Count and report panics
/// - Enter degraded mode after too many failures
/// - Signal shutdown when recovery is not possible
pub struct WorkerHealthTracker {
    /// Total panic count across all workers.
    panic_count: AtomicU32,
    /// Maximum panics before entering degraded mode.
    max_panics: u32,
    /// Flag indicating server is in degraded mode.
    degraded: AtomicBool,
    /// Reference to server metrics for recording panic events.
    pub(crate) metrics: Arc<crate::metrics::ServerMetrics>,
    /// Shutdown flag to signal server shutdown on critical failures.
    shutdown: Arc<AtomicBool>,
}

impl WorkerHealthTracker {
    /// Create a new worker health tracker.
    pub fn new(
        metrics: Arc<crate::metrics::ServerMetrics>,
        shutdown: Arc<AtomicBool>,
        max_panics: Option<u32>,
    ) -> Arc<Self> {
        Arc::new(Self {
            panic_count: AtomicU32::new(0),
            max_panics: max_panics.unwrap_or(DEFAULT_MAX_WORKER_PANICS),
            degraded: AtomicBool::new(false),
            metrics,
            shutdown,
        })
    }

    /// Record a worker panic and handle the consequences.
    ///
    /// Returns `true` if the server should continue (degraded but operational),
    /// `false` if the server should shut down due to critical failure.
    ///
    /// # Arguments
    ///
    /// * `worker_name` - Name of the panicked worker (e.g., "tun-reader-0")
    /// * `panic_info` - Panic message or description
    pub fn record_panic(&self, worker_name: &str, panic_info: &str) -> bool {
        let count = self.panic_count.fetch_add(1, Ordering::SeqCst) + 1;

        // Record in metrics
        self.metrics.record_worker_panic();

        // Log critical error
        error!(
            "CRITICAL: Worker '{}' panicked ({}/{}): {}",
            worker_name, count, self.max_panics, panic_info
        );

        if count >= self.max_panics {
            // Enter degraded mode
            if !self.degraded.swap(true, Ordering::SeqCst) {
                // First time entering degraded mode
                error!(
                    "SERVER ENTERING DEGRADED MODE: {} worker panics exceeded threshold ({})",
                    count, self.max_panics
                );
                error!("Data plane may be impaired. Manual intervention required.");
                self.metrics.set_degraded_mode(true);

                // Signal shutdown to prevent further damage
                self.shutdown.store(true, Ordering::SeqCst);
                return false;
            }
        } else {
            warn!(
                "Worker panic {}/{} - server continues but may have reduced capacity",
                count, self.max_panics
            );
        }

        true
    }

    /// Check if the server is in degraded mode.
    pub fn is_degraded(&self) -> bool {
        self.degraded.load(Ordering::Relaxed)
    }

    /// Get the current panic count.
    pub fn panic_count(&self) -> u32 {
        self.panic_count.load(Ordering::Relaxed)
    }

    /// Extract panic message from a `catch_unwind` result.
    pub fn extract_panic_message(panic_info: &Box<dyn std::any::Any + Send>) -> String {
        if let Some(s) = panic_info.downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = panic_info.downcast_ref::<String>() {
            s.clone()
        } else {
            "unknown panic".to_string()
        }
    }
}

/// A pooled buffer that returns itself to the pool when dropped.
#[cfg(target_os = "linux")]
pub struct PooledBuffer {
    data: Vec<u8>,
    len: usize,
    pool: Sender<Vec<u8>>,
}

#[cfg(target_os = "linux")]
impl PooledBuffer {
    /// Create a new pooled buffer.
    fn new(data: Vec<u8>, pool: Sender<Vec<u8>>) -> Self {
        Self { data, len: 0, pool }
    }

    /// Get the buffer data as a mutable slice.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Set the valid data length.
    #[inline]
    pub fn set_len(&mut self, len: usize) {
        self.len = len;
    }
}

#[cfg(target_os = "linux")]
impl Drop for PooledBuffer {
    fn drop(&mut self) {
        // Return buffer to pool (best effort - if pool is full, buffer is dropped).
        //
        // Performance note: we use `unsafe set_len` to restore the buffer's
        // logical length to its full capacity (MAX_PACKET_SIZE) without
        // re-zeroing. The previous implementation called `buf.resize(N, 0)`
        // which writes N zero bytes every time a buffer is recycled — a
        // significant overhead in the hot path (~65 KB × ~500 kpps).
        //
        // SAFETY: The buffer was originally allocated with `vec![0u8; MAX_PACKET_SIZE]`
        // in `BufferPool::new` or `BufferPool::get`, so `capacity() >= MAX_PACKET_SIZE`.
        // Setting len to capacity is sound for `u8` because `u8` has no drop glue
        // and the underlying memory is valid (fully initialized on first allocation,
        // and subsequent decrypt writes overwrite a prefix; trailing bytes from
        // the previous use remain initialized).
        let mut buf = std::mem::take(&mut self.data);
        let cap = buf.capacity();
        if cap >= MAX_PACKET_SIZE {
            // Justified unsafe: hot-path optimisation (see SAFETY comment above).
            #[allow(unsafe_code)]
            // SAFETY: See the multi-paragraph SAFETY comment earlier in this
            // function for the full argument. In short: the buffer was allocated
            // as `vec![0u8; MAX_PACKET_SIZE]`, `u8` has no drop glue, and all
            // bytes in `0..capacity()` remain initialised for the buffer's life.
            unsafe {
                buf.set_len(MAX_PACKET_SIZE);
            }
        } else {
            // Shouldn't happen — buffers are always allocated at MAX_PACKET_SIZE.
            // Fallback to resize for correctness.
            buf.resize(MAX_PACKET_SIZE, 0);
        }
        let _ = self.pool.try_send(buf);
    }
}

#[cfg(target_os = "linux")]
impl std::ops::Deref for PooledBuffer {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

#[cfg(target_os = "linux")]
impl AsRef<[u8]> for PooledBuffer {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

/// A high-performance buffer pool for packet processing.
#[cfg(target_os = "linux")]
pub struct BufferPool {
    /// Channel to get buffers from the pool.
    get: Receiver<Vec<u8>>,
    /// Channel to return buffers to the pool.
    put: Sender<Vec<u8>>,
}

#[cfg(target_os = "linux")]
impl BufferPool {
    /// Create a new buffer pool with pre-allocated buffers.
    pub fn new(size: usize, buffer_size: usize) -> Self {
        let (put, get) = bounded(size);

        // Pre-allocate buffers
        for _ in 0..size {
            let buf = vec![0u8; buffer_size];
            let _ = put.try_send(buf);
        }

        Self { get, put }
    }

    /// Get a buffer from the pool (allocates if pool is empty).
    #[inline]
    pub fn get(&self) -> PooledBuffer {
        let data = self
            .get
            .try_recv()
            .unwrap_or_else(|_| vec![0u8; MAX_PACKET_SIZE]);
        PooledBuffer::new(data, self.put.clone())
    }
}

/// Worker thread handle with name for logging.
struct WorkerHandle {
    /// Thread name for logging.
    name: String,
    /// Join handle for the thread.
    handle: std::thread::JoinHandle<()>,
}

impl WorkerHandle {
    /// Create a new worker handle.
    #[cfg(target_os = "linux")]
    fn new(name: impl Into<String>, handle: std::thread::JoinHandle<()>) -> Self {
        Self {
            name: name.into(),
            handle,
        }
    }
}

/// VPN server.
pub struct VpnServer {
    /// Server configuration.
    config: ServerConfig,
    /// Server's Level 3 signing keypair (ML-DSA-65, for "standard" security clients).
    keypair_level3: Arc<MlDsaKeypair>,
    /// Server's Level 5 signing keypair (ML-DSA-87, for "high" security clients).
    keypair_level5: Arc<MlDsaKeypair>,
    /// Server's Level 3 KEM keypair for identity hiding (optional).
    /// If set, server can decrypt `EncryptedHandshakeInit` from Level 3 clients.
    kem_keypair_level3: Option<Arc<(HybridSecretKey, HybridPublicKey)>>,
    /// Server's Level 5 KEM keypair for identity hiding (optional).
    /// If set, server can decrypt `EncryptedHandshakeInit` from Level 5 clients.
    kem_keypair_level5: Option<Arc<(HybridSecretKey, HybridPublicKey)>>,
    /// Session manager.
    sessions: Arc<SessionManager>,
    /// TUN device.
    tun: Option<TunDevice>,
    /// NAT manager.
    nat: Option<NatManager>,
    /// UDP socket (used in non-Linux path).
    #[allow(dead_code)]
    socket: Option<Arc<UdpSocket>>,
    /// Shutdown flag (atomic for lock-free checking).
    shutdown: Arc<AtomicBool>,
    /// Handshake rate limiter.
    rate_limiter: Arc<crate::rate_limit::HandshakeRateLimiter>,
    /// Anti-replay cache for handshake `client_random` values.
    ///
    /// An attacker that captures a legitimate `HandshakeInit` off the wire
    /// can replay it indefinitely to burn server CPU on PQ decapsulation +
    /// ML-DSA signing (~1-2 ms at Level 5). The per-IP rate limiter caps
    /// the amplification factor but does not distinguish replay from a
    /// legitimate retry. This cache rejects exact `client_random`
    /// collisions within a 60-second window before any expensive crypto
    /// work runs, collapsing the attack to "per-fresh-random".
    handshake_replay: Arc<crate::handshake_replay::HandshakeReplayCache>,
    /// Reassembly buffer for application-layer handshake fragments.
    ///
    /// Post-quantum handshakes (Level 5 in particular) routinely exceed the
    /// 1500-byte Ethernet MTU once you add a UDP+IP header. Many hosters
    /// drop IP-fragmented UDP as an anti-DoS measure, so clients split
    /// oversized handshake messages into application-layer fragments
    /// (`MessageType::HandshakeFragment`) and the server reassembles them
    /// here before feeding the result back into the handshake state
    /// machine. See [`hpn_core::protocol::fragment`] for the wire format
    /// and the DoS bounds enforced by [`Reassembly`].
    ///
    /// Concurrency: accessed **only** from the single control-plane
    /// dispatch task (`handle_control_message` on Linux / its AF_XDP
    /// twin). The Mutex exists to uphold the `Send + Sync` bound the
    /// server-wide `Arc<Self>` needs, not because concurrent writers
    /// are expected. Every `lock()` call is scoped to a short critical
    /// section and the guard is dropped BEFORE any `.await`, which the
    /// compiler also enforces because `parking_lot::MutexGuard` is
    /// `!Send`.
    fragment_reassembly: Arc<parking_lot::Mutex<Reassembly>>,
    /// Server metrics (used in run() and handlers).
    #[allow(dead_code)]
    // False positive: field is used extensively in run() and packet handlers
    metrics: Arc<crate::metrics::ServerMetrics>,
    /// User store for authentication (optional).
    /// If set and `require_auth` is true, users must provide valid credentials.
    user_store: Option<Arc<parking_lot::Mutex<crate::user_store::UserStore>>>,
    /// User-agnostic authentication lockout tracker.
    ///
    /// Sits IN FRONT of the SQLite-backed per-username counter in
    /// [`UserStore::verify_password`] and enforces three independent
    /// throttles (per-tuple, per-IP, per-username spread) on every login
    /// attempt. The SQL counter is left in place as a defence-in-depth
    /// fallback but it is no longer the primary brute-force barrier and,
    /// crucially, it is no longer the only knob an attacker can hit to
    /// account-DoS a known username — the spread policy here requires
    /// >=5 distinct IPs before locking the username globally.
    ///
    /// All state is in-memory with a 100 000-entry cap per dimension.
    /// Survives restarts via the underlying `MAX_FAILED_ATTEMPTS` SQL
    /// row only; transient process restarts therefore reset the
    /// in-memory counters, which is acceptable: the SQL fallback still
    /// catches anyone who keeps trying the same username after a
    /// crash.
    auth_lockout: Arc<crate::auth_lockout::AuthLockoutTracker>,
    /// UDP worker pool (Linux only) - dropped before joining workers.
    #[cfg(target_os = "linux")]
    udp_workers: Option<UdpWorkerPool>,
    /// Worker thread handles for graceful shutdown.
    /// These are joined on Drop to ensure clean termination.
    worker_handles: Vec<WorkerHandle>,
}

impl VpnServer {
    #[cfg(all(target_os = "linux", feature = "afxdp"))]
    fn is_valid_afxdp_peer_addr(addr: SocketAddr) -> bool {
        !addr.ip().is_unspecified() && addr.port() != 0
    }

    /// Parse the configured minimum security level.
    ///
    /// Falls back to `Level3` (most permissive) if the config value is invalid,
    /// logging a warning. Invalid values are considered a configuration error
    /// but we do not fail closed at handshake time to preserve availability.
    fn min_security_level(&self) -> SecurityLevel {
        match self.config.min_security_level.to_ascii_lowercase().as_str() {
            "level3" | "3" => SecurityLevel::Level3,
            "level5" | "5" => SecurityLevel::Level5,
            other => {
                warn!(
                    "Invalid min_security_level '{}' in config, defaulting to level3",
                    other
                );
                SecurityLevel::Level3
            }
        }
    }

    /// Check whether the client-proposed security level meets the server's
    /// minimum policy. Returns `true` if the handshake may proceed.
    #[inline]
    fn security_level_accepted(&self, proposed: SecurityLevel) -> bool {
        let min = self.min_security_level();
        match (min, proposed) {
            (SecurityLevel::Level3, _) => true,
            (SecurityLevel::Level5, SecurityLevel::Level5) => true,
            (SecurityLevel::Level5, SecurityLevel::Level3) => false,
        }
    }

    /// Create a new VPN server with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Server configuration
    /// * `keypair_level3` - ML-DSA-65 keypair for "standard" security clients
    /// * `keypair_level5` - ML-DSA-87 keypair for "high" security clients
    pub fn new(
        config: ServerConfig,
        keypair_level3: MlDsaKeypair,
        keypair_level5: MlDsaKeypair,
    ) -> ServerResult<Self> {
        Self::new_with_identity_hiding(config, keypair_level3, keypair_level5, None, None)
    }

    /// Create a new VPN server with identity hiding support.
    ///
    /// # Arguments
    ///
    /// * `config` - Server configuration
    /// * `keypair_level3` - ML-DSA-65 keypair for "standard" security clients
    /// * `keypair_level5` - ML-DSA-87 keypair for "high" security clients
    /// * `kem_keypair_level3` - Optional KEM keypair for Level 3 identity hiding
    /// * `kem_keypair_level5` - Optional KEM keypair for Level 5 identity hiding
    pub fn new_with_identity_hiding(
        config: ServerConfig,
        keypair_level3: MlDsaKeypair,
        keypair_level5: MlDsaKeypair,
        kem_keypair_level3: Option<Arc<(HybridSecretKey, HybridPublicKey)>>,
        kem_keypair_level5: Option<Arc<(HybridSecretKey, HybridPublicKey)>>,
    ) -> ServerResult<Self> {
        // Validate the full config at construction time so every call path
        // (not just main.rs) catches invalid values before any resource is
        // allocated. validate() is idempotent and cheap (<1ms).
        config.validate()?;

        let (base_ip, prefix) = config.parse_ipv4_pool()?;
        let server_ip = config.parse_server_tunnel_ip()?;

        // Maximum concurrent sessions is bounded purely by the IPv4 pool
        // size (auto-calculated). HPN is open-source with unlimited
        // sessions — no license tier caps this.
        let effective_max_sessions = config.get_max_sessions();

        // Create session manager (dual-stack if IPv6 configured).
        let sessions = if config.has_ipv6() {
            let (base_ipv6, prefix_v6) = config.parse_ipv6_pool()?.ok_or_else(|| {
                ServerError::Config("IPv6 pool must be set when has_ipv6 is true".into())
            })?;
            let server_ipv6 = config.parse_server_tunnel_ipv6()?.ok_or_else(|| {
                ServerError::Config("Server IPv6 must be set when has_ipv6 is true".into())
            })?;

            info!("IPv6 dual-stack enabled");
            Arc::new(
                SessionManager::new_dual_stack(
                    base_ip,
                    prefix,
                    server_ip,
                    base_ipv6,
                    prefix_v6,
                    server_ipv6,
                    config.session_timeout(),
                    effective_max_sessions,
                )
                .with_rate_limits(config.session_rate_limit_pps, config.session_rate_limit_bps),
            )
        } else {
            Arc::new(
                SessionManager::new(
                    base_ip,
                    prefix,
                    server_ip,
                    config.session_timeout(),
                    effective_max_sessions,
                )
                .with_rate_limits(config.session_rate_limit_pps, config.session_rate_limit_bps),
            )
        };

        // Rate limiter: 5 handshakes per minute per IP (configurable via config in future)
        let rate_limiter = Arc::new(crate::rate_limit::HandshakeRateLimiter::new());

        // Anti-replay cache for handshake client_random values. Default
        // parameters (60 s TTL, 16 K entries) match the handshake rate
        // window and cap memory at ~0.8 MB.
        let handshake_replay = Arc::new(crate::handshake_replay::HandshakeReplayCache::new());

        // Application-layer handshake-fragment reassembly buffer. Bounds
        // come from `ReassemblerConfig::server_default` (1024 entries,
        // 16 MiB total, 64 KiB per entry, 5 s TTL) which caps the memory
        // an attacker spamming first-fragments can cost us.
        let fragment_reassembly = Arc::new(parking_lot::Mutex::new(Reassembly::new(
            ReassemblerConfig::server_default(),
        )));

        // Initialize metrics
        let metrics = crate::metrics::ServerMetrics::new();

        // Wire the sessions manager's lifecycle hook to the metrics gauge so
        // every create/remove path (including cleanup_expired, admin actions,
        // Close messages, replacement, failure rollbacks) stays consistent
        // with the `sessions_active` Prometheus gauge. This fixes a long-
        // standing drift where expired/admin-killed sessions decremented the
        // counter silently or not at all.
        {
            let metrics_for_cb = Arc::clone(&metrics);
            sessions.set_lifecycle_callback(Box::new(move |event| match event {
                crate::session_manager::SessionLifecycleEvent::Created(_) => {
                    // record_session_created bumps both sessions_total
                    // and sessions_active; call sites that only want
                    // to count a *handshake* use handshakes_success.
                    metrics_for_cb.sessions_active.inc();
                }
                crate::session_manager::SessionLifecycleEvent::Removed(_) => {
                    // timeout=false because we don't know the cause
                    // from this layer; the expired-sweep increments
                    // sessions_timeout separately.
                    metrics_for_cb.record_session_ended(false);
                }
            }));
        }

        // Initialize user store if authentication is required
        let user_store = if config.require_auth {
            let db_path = config.users_db_path_or_default();
            match crate::user_store::UserStore::open(&db_path) {
                Ok(store) => {
                    info!(
                        "User authentication enabled, database: {}",
                        db_path.display()
                    );
                    Some(Arc::new(parking_lot::Mutex::new(store)))
                }
                Err(e) => {
                    return Err(ServerError::Config(format!(
                        "Failed to open user database at {}: {}",
                        db_path.display(),
                        e
                    )));
                }
            }
        } else {
            info!("User authentication disabled");
            None
        };

        Ok(Self {
            config,
            keypair_level3: Arc::new(keypair_level3),
            keypair_level5: Arc::new(keypair_level5),
            kem_keypair_level3,
            kem_keypair_level5,
            sessions,
            tun: None,
            nat: None,
            socket: None,
            shutdown: Arc::new(AtomicBool::new(false)),
            rate_limiter,
            handshake_replay,
            fragment_reassembly,
            metrics,
            user_store,
            auth_lockout: Arc::new(
                crate::auth_lockout::AuthLockoutTracker::with_production_defaults(),
            ),
            #[cfg(target_os = "linux")]
            udp_workers: None,
            worker_handles: Vec::new(),
        })
    }

    /// Get the appropriate keypair for the client's requested security level.
    ///
    /// - Level3 (Standard): Returns ML-DSA-65 keypair
    /// - Level5 (High): Returns ML-DSA-87 keypair
    fn keypair_for_level(&self, level: SecurityLevel) -> Arc<MlDsaKeypair> {
        match level {
            SecurityLevel::Level3 => Arc::clone(&self.keypair_level3),
            SecurityLevel::Level5 => Arc::clone(&self.keypair_level5),
        }
    }

    /// Verify decrypted credentials against the user store with the
    /// user-agnostic auth-lockout layer running in front of Argon2id.
    ///
    /// Layered policy:
    ///
    /// 1. **Pre-check** [`AuthLockoutTracker::check_lockout`]. If any of
    ///    the three throttles (tuple, ip, username spread) is active,
    ///    refuse the request immediately. To keep the response time
    ///    indistinguishable from a real Argon2id verify (constant-time
    ///    against remote fingerprinting of "throttled" vs. "wrong
    ///    password"), we still spawn-blocking a single Argon2id hash
    ///    with the production parameters and discard the output.
    ///
    /// 2. **Verify** the password with `UserStore::verify_password`,
    ///    which itself enforces the legacy per-username SQL lockout as a
    ///    defence-in-depth fallback. This is allowed to run on the
    ///    blocking pool.
    ///
    /// 3. **Post-record**. On success, clear the (username, ip) tuple
    ///    counter; we deliberately keep the per-IP and per-username
    ///    counters because a single legitimate login from one user does
    ///    not invalidate evidence of a parallel attack against other
    ///    usernames or from the same IP. On failure, increment all
    ///    three dimensions; if the failure crosses a threshold, the
    ///    matching `auth_lockout_*` Prometheus counter is incremented
    ///    once at the moment the lock fires.
    ///
    /// Returns `Ok(())` on successful authentication, `Err(())` on any
    /// negative outcome (lockout, wrong password, user disabled, user
    /// not found, internal error). The caller logs and records its own
    /// `handshakes_failed` metric — this method only owns the lockout
    /// counters.
    ///
    /// [`AuthLockoutTracker::check_lockout`]: crate::auth_lockout::AuthLockoutTracker::check_lockout
    async fn authenticate_credentials(
        &self,
        store: &Arc<parking_lot::Mutex<crate::user_store::UserStore>>,
        username: &str,
        password: &str,
        addr: SocketAddr,
    ) -> Result<(), ()> {
        // ── Step 1: Lockout pre-check ─────────────────────────────────
        if let Some(kind) = self.auth_lockout.check_lockout(username, addr.ip()) {
            self.metrics.record_auth_lockout(kind);
            // Constant-time padding: do an Argon2id hash on the blocking
            // pool so the response time matches a genuine wrong-password
            // outcome. We hash a copy of the supplied password (worst
            // case) — using a fixed dummy string would itself be
            // observable as a slightly different timing distribution
            // because Argon2id is data-dependent.
            let pwd = password.to_string();
            let _ = tokio::task::spawn_blocking(move || {
                crate::user_store::UserStore::apply_auth_delay_public(&pwd);
            })
            .await;
            warn!(
                "Authentication refused (lockout: {}) from {}",
                kind.as_str(),
                crate::privacy::addr(addr)
            );
            return Err(());
        }

        // ── Step 2: Argon2id verify on the blocking pool ──────────────
        let store_clone = Arc::clone(store);
        let username_owned = username.to_string();
        let password_owned = password.to_string();
        let verify_result = tokio::task::spawn_blocking(move || {
            let store = store_clone.lock();
            store.verify_password(&username_owned, &password_owned)
        })
        .await;

        // ── Step 3: Update lockout counters and report ────────────────
        match verify_result {
            Ok(Ok(true)) => {
                self.auth_lockout.record_success(username, addr.ip());
                debug!(
                    "Authentication succeeded from {}",
                    crate::privacy::addr(addr)
                );
                Ok(())
            }
            Ok(Ok(false)) => {
                if let Some(kind) = self.auth_lockout.record_failure(username, addr.ip()) {
                    // A new lock fired ON this attempt. The pre-check
                    // counter only increments when an *already-active*
                    // lock is hit, so we count the trigger here too
                    // (one increment per lock, not per attempt during
                    // the lock window).
                    self.metrics.record_auth_lockout(kind);
                    warn!(
                        "Authentication failure triggered lockout ({}) from {}",
                        kind.as_str(),
                        crate::privacy::addr(addr)
                    );
                } else {
                    warn!("Authentication failed from {}", crate::privacy::addr(addr));
                }
                Err(())
            }
            Ok(Err(e)) => {
                // Internal store error (DB I/O, hash parse, etc.). Treat
                // as a failure for the client but do NOT count it
                // against the lockout — the user is not at fault and we
                // do not want operators to lock themselves out of every
                // account because of a transient SQLite issue.
                warn!(
                    "Authentication store error from {}: {}",
                    crate::privacy::addr(addr),
                    e
                );
                Err(())
            }
            Err(join_err) => {
                warn!(
                    "Auth task panic from {}: {}",
                    crate::privacy::addr(addr),
                    join_err
                );
                Err(())
            }
        }
    }

    /// Expose the auth-lockout tracker for testing and metrics export.
    ///
    /// `pub(crate)` rather than `pub` so it doesn't leak as part of the
    /// crate's public API surface — the only intended consumers are
    /// in-crate integration tests and the metrics exporter.
    #[allow(dead_code)] // wired for upcoming integration tests
    pub(crate) fn auth_lockout(&self) -> &Arc<crate::auth_lockout::AuthLockoutTracker> {
        &self.auth_lockout
    }

    /// Get the appropriate KEM keypair for the client's requested security level.
    ///
    /// Returns `None` if identity hiding is not configured for this level.
    fn kem_keypair_for_level(
        &self,
        level: SecurityLevel,
    ) -> Option<Arc<(HybridSecretKey, HybridPublicKey)>> {
        match level {
            SecurityLevel::Level3 => self.kem_keypair_level3.clone(),
            SecurityLevel::Level5 => self.kem_keypair_level5.clone(),
        }
    }

    /// Initialize the server (create TUN, setup NAT, etc.).
    pub fn initialize(&mut self) -> ServerResult<()> {
        let server_ip = self.config.parse_server_tunnel_ip()?;
        let netmask = self.sessions.netmask();

        // Only create TUN device now if NOT using multiqueue
        // (multiqueue will create it in run() with special IFF_MULTI_QUEUE flag)
        let use_multiqueue = self.config.should_use_tun_multiqueue();

        if use_multiqueue {
            info!(
                "TUN multiqueue enabled - device {} will be created in run() with IFF_MULTI_QUEUE flag",
                self.config.tun_name
            );
        } else {
            // Create TUN device (dual-stack if IPv6 configured)
            let tun = if self.config.has_ipv6() {
                let server_ipv6 = self.config.parse_server_tunnel_ipv6()?.ok_or_else(|| {
                    ServerError::Config("Server IPv6 must be set when has_ipv6 is true".into())
                })?;
                let ipv6_prefix = self.sessions.ipv6_prefix().unwrap_or(64);

                info!(
                    "Creating dual-stack TUN device {} with IPv4 {}.{}.{}.{} and IPv6",
                    self.config.tun_name, server_ip[0], server_ip[1], server_ip[2], server_ip[3]
                );

                TunDevice::create_dual_stack(
                    &self.config.tun_name,
                    server_ip,
                    netmask,
                    server_ipv6,
                    ipv6_prefix,
                    self.config.mtu,
                )?
            } else {
                info!(
                    "Creating IPv4-only TUN device {} with IP {}.{}.{}.{}",
                    self.config.tun_name, server_ip[0], server_ip[1], server_ip[2], server_ip[3]
                );

                TunDevice::create(&self.config.tun_name, server_ip, netmask, self.config.mtu)?
            };
            self.tun = Some(tun);
        }

        // Enable IP forwarding (IPv4 and IPv6 if configured)
        routing::enable_ip_forwarding()?;
        if self.config.has_ipv6() {
            routing::enable_ipv6_forwarding()?;
        }

        // Setup NAT if enabled
        if self.config.enable_nat {
            let mut nat =
                NatManager::new(&self.config.ipv4_pool, self.config.nat_interface.clone())?;
            nat.enable()?;

            // Add FORWARD rules to allow traffic through the VPN tunnel
            // Without these, the kernel's default FORWARD policy may drop packets
            if let Err(e) = crate::nat::allow_forward(&self.config.ipv4_pool, &self.config.tun_name)
            {
                warn!("Failed to add FORWARD rules for IPv4: {}", e);
            }

            // Setup IPv6 NAT/masquerade if configured
            if self.config.has_ipv6()
                && let Some(ref ipv6_pool) = self.config.ipv6_pool
            {
                nat.enable_ipv6(ipv6_pool)?;
            }

            self.nat = Some(nat);
        }

        info!("Server initialized");
        Ok(())
    }

    /// Run the VPN server with high-performance multi-threaded UDP I/O.
    ///
    /// The networking backend is automatically selected based on detected
    /// hardware capabilities (no configuration needed):
    ///
    /// 1. AF_XDP (kernel >= 4.18 + XDP NIC): Zero-copy, 10+ Gbps
    /// 2. io_uring (kernel >= 5.1): Async I/O, 5-10 Gbps
    /// 3. recvmmsg/sendmmsg: Batched syscalls, 1-5 Gbps
    /// 4. Standard UDP: Fallback, ~1 Gbps
    #[cfg(target_os = "linux")]
    pub async fn run(&mut self) -> ServerResult<()> {
        // Get auto-tuned runtime configuration
        let runtime = RuntimeConfig::auto();
        runtime.log();

        let num_workers = runtime.workers;
        let tun_queue_count = runtime.tun_queues;

        // Log startup info
        info!(
            "Starting server on {} with {} backend",
            self.config.listen_addr,
            runtime.backend.name()
        );
        info!(
            "  Workers: {}, TUN queues: {}, Buffer: {} MB",
            num_workers,
            tun_queue_count,
            runtime.recv_buffer_size / 1024 / 1024
        );

        // Check if we should use AF_XDP (highest performance path)
        #[cfg(feature = "afxdp")]
        if runtime.backend == NetworkBackend::AfXdp {
            info!("Using AF_XDP zero-copy networking for maximum throughput");
            return self.run_afxdp(runtime).await;
        }

        // Fall through to standard UDP path (with io_uring or mmsg optimization)

        // Create buffer pool for zero-copy packet processing
        // Pool size: 2x channel capacity to handle bursts
        let tun_buffer_pool = Arc::new(BufferPool::new(TUN_CHANNEL_CAPACITY * 2, MAX_PACKET_SIZE));

        // Create worker health tracker for panic monitoring
        let worker_health = WorkerHealthTracker::new(
            Arc::clone(&self.metrics),
            Arc::clone(&self.shutdown),
            None, // Use default max panics (3)
        );

        // Crossbeam channel for UDP -> TUN (using pooled buffers for zero-copy)
        let (tun_write_tx, tun_write_rx): (Sender<PooledBuffer>, Receiver<PooledBuffer>) =
            bounded(TUN_CHANNEL_CAPACITY);

        // Create UDP worker pool and store it for cleanup on Drop
        let udp_workers = UdpWorkerPool::new(
            self.config.listen_addr,
            num_workers,
            Arc::clone(&self.sessions),
            tun_write_tx.clone(),
            Arc::clone(&tun_buffer_pool),
            Arc::clone(&self.metrics),
        )?;

        // Note: outbound_tx is no longer used with inline encryption path
        // TUN readers send directly via UDP sockets
        let _outbound_tx = udp_workers.outbound_sender();
        let control_rx = udp_workers.control_rx.clone();
        let response_tx = udp_workers.response_sender();

        // Store UDP worker pool for cleanup on Drop
        // We extract needed references before storing since we can't borrow self during the loop
        self.udp_workers = Some(udp_workers);
        let udp_workers_ref = self
            .udp_workers
            .as_ref()
            .expect("udp_workers must be Some after assignment on previous line");

        // Spawn cleanup task
        let sessions_cleanup = Arc::clone(&self.sessions);
        let shutdown_cleanup = Arc::clone(&self.shutdown);
        tokio::spawn(async move {
            let mut interval = time::interval(std::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                if shutdown_cleanup.load(Ordering::Relaxed) {
                    break;
                }
                sessions_cleanup.cleanup_expired();
            }
        });

        // Spawn metrics HTTP server if enabled
        if self.config.enable_metrics {
            let metrics_server = crate::metrics::MetricsHttpServer::new(
                Arc::clone(&self.metrics),
                self.config.metrics_addr,
            );
            tokio::spawn(async move {
                if let Err(e) = metrics_server.run().await {
                    error!("Metrics HTTP server error: {}", e);
                }
            });
        }

        // Spawn metrics logging task (always active, logs every 60 seconds)
        let metrics_log = Arc::clone(&self.metrics);
        let shutdown_metrics = Arc::clone(&self.shutdown);
        tokio::spawn(async move {
            let mut interval = time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                if shutdown_metrics.load(Ordering::Relaxed) {
                    break;
                }
                let summary = metrics_log.summary();
                info!("Metrics: {}", summary.format());
            }
        });

        // Setup TUN device (multiqueue or single-queue fallback)
        // Check if we should use multiqueue based on config and kernel support
        #[cfg(target_os = "linux")]
        let use_multiqueue = self.config.should_use_tun_multiqueue()
            && crate::tun_multiqueue::is_multiqueue_supported();

        #[cfg(not(target_os = "linux"))]
        let use_multiqueue = false;

        if use_multiqueue {
            // Multiqueue TUN: create device here in run() (not in initialize())
            let tun_name = self.config.tun_name.clone();

            #[cfg(target_os = "linux")]
            {
                #[cfg(target_os = "linux")]
                {
                    // Multi-queue TUN path
                    let queue_count = self.config.get_tun_num_queues();
                    info!(
                        "Enabling TUN multiqueue with {} queues for {}",
                        queue_count, tun_name
                    );

                    // Create multiqueue TUN device
                    let mut mqtun = MultiQueueTun::create(&tun_name, queue_count)?;

                    // Configure IP addresses
                    let server_ip = self.config.parse_server_tunnel_ip()?;
                    let prefix_len = self.sessions.prefix_len();
                    mqtun.configure_ipv4(server_ip, prefix_len)?;

                    if self.config.has_ipv6()
                        && let Some(server_ipv6) = self.config.parse_server_tunnel_ipv6()?
                    {
                        let prefix_len_v6 = self.sessions.prefix_len_v6().unwrap_or(64);
                        mqtun.configure_ipv6(server_ipv6, prefix_len_v6)?;
                    }

                    // Set all queues to non-blocking
                    for queue in mqtun.queues_mut() {
                        queue.set_nonblocking(true)?;
                    }

                    // Take ownership of queues for threading
                    let queues = mqtun.take_queues();
                    let num_queues = queues.len();

                    info!(
                        "Starting {} reader and {} writer threads for multiqueue TUN",
                        num_queues, num_queues
                    );

                    // Clone variables needed for multiqueue worker threads
                    let sessions_for_tun = Arc::clone(&self.sessions);
                    let shutdown_tun_read = Arc::clone(&self.shutdown);
                    let shutdown_tun_write = Arc::clone(&self.shutdown);

                    // Spawn reader threads (one per queue) with INLINE ENCRYPTION
                    // This eliminates the channel hop to UDP senders for 15-25% throughput improvement
                    for (queue_id, queue) in queues.iter().enumerate() {
                        // Clone queue for reader thread
                        // Note: We need to dup() the fd to share between reader/writer
                        use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
                        let fd = queue.as_raw_fd();

                        // Use OwnedFd for RAII - prevents FD leak on error paths
                        #[allow(unsafe_code)]
                        let reader_owned_fd = unsafe {
                            let dup_fd = libc::dup(fd);
                            if dup_fd < 0 {
                                return Err(ServerError::Tun(format!(
                                    "failed to dup queue fd: {}",
                                    std::io::Error::last_os_error()
                                )));
                            }
                            OwnedFd::from_raw_fd(dup_fd)
                        };

                        let reader_queue = crate::tun_multiqueue::TunQueue::from_owned_fd(
                            reader_owned_fd,
                            queue_id,
                        );

                        // Get UDP socket for inline encryption (direct send, no channel)
                        let send_socket = udp_workers_ref.get_send_socket(queue_id);

                        let handle = crate::tun_workers::spawn_tun_reader_inline(
                            queue_id,
                            reader_queue,
                            Arc::clone(&sessions_for_tun),
                            send_socket,
                            Arc::clone(&shutdown_tun_read),
                            tun_name.clone(),
                            Arc::clone(&self.metrics),
                        )
                        .map_err(|e| {
                            // reader_queue dropped here, FD auto-closed via OwnedFd
                            ServerError::Internal(format!(
                                "failed to spawn TUN reader thread {}: {}",
                                queue_id, e
                            ))
                        })?;
                        self.worker_handles.push(WorkerHandle::new(
                            format!("tun-reader-{}", queue_id),
                            handle,
                        ));
                    }

                    // Spawn writer threads (one per queue)
                    for (queue_id, queue) in queues.into_iter().enumerate() {
                        let handle = crate::tun_workers::spawn_tun_writer(
                            queue_id,
                            queue,
                            tun_write_rx.clone(),
                            Arc::clone(&shutdown_tun_write),
                            tun_name.clone(),
                        )
                        .map_err(|e| {
                            ServerError::Internal(format!(
                                "failed to spawn TUN writer thread {}: {}",
                                queue_id, e
                            ))
                        })?;
                        self.worker_handles.push(WorkerHandle::new(
                            format!("tun-writer-{}", queue_id),
                            handle,
                        ));
                    }
                }
            }
        } else if let Some(ref mut tun) = self.tun {
            // Single-queue TUN fallback path
            let tun_name = tun.name().to_string();

            if let Some(tun_device) = tun.take_device() {
                // Single-queue TUN fallback path (original implementation)
                use std::os::fd::AsRawFd;
                let fd = tun_device.as_raw_fd();

                // Set TUN device to non-blocking mode
                #[allow(unsafe_code)]
                {
                    unsafe {
                        let flags = libc::fcntl(fd, libc::F_GETFL);
                        if flags != -1 {
                            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
                            debug!("TUN device set to non-blocking mode");
                        }
                    }
                }

                let tun_device = Arc::new(tun_device);
                let sessions_for_tun = Arc::clone(&self.sessions);
                let shutdown_tun_read = Arc::clone(&self.shutdown);
                let shutdown_tun_write = Arc::clone(&self.shutdown);

                // TUN READ THREAD with INLINE ENCRYPTION - single thread reading packets
                // TUN device is a single file descriptor - multiple readers cause kernel contention
                // Inline encryption: encrypt directly and send via UDP socket (no channel hop)
                let num_tun_readers = 1;
                info!(
                    "Starting {} TUN reader thread(s) with INLINE ENCRYPTION",
                    num_tun_readers
                );

                // Get UDP socket for inline encryption
                let send_socket = udp_workers_ref.get_send_socket(0);

                // Batch size for sendmmsg (smaller than UDP workers for lower latency)
                const TUN_SENDMMSG_BATCH_SIZE: usize = 64;
                const FLUSH_AFTER_EMPTY_READS: u32 = 4;

                for reader_id in 0..num_tun_readers {
                    let tun_device_read = Arc::clone(&tun_device);
                    let sessions_for_reader = Arc::clone(&sessions_for_tun);
                    let shutdown_reader = Arc::clone(&shutdown_tun_read);
                    let send_socket_reader = Arc::clone(&send_socket);
                    let tun_name_reader = tun_name.clone();
                    let health_tracker = Arc::clone(&worker_health);

                    let handle = std::thread::Builder::new()
                        .name(format!("tun-reader-{}", reader_id))
                        .spawn(move || {
                            let worker_name = format!("tun-reader-{}", reader_id);
                            // Wrap thread body in catch_unwind to prevent panics from crashing the server
                            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                use crate::syscall_batch::SendMmsg;

                                info!(
                                    "TUN reader thread {} started (INLINE ENCRYPTION + SENDMMSG batch={}) for {}",
                                    reader_id, TUN_SENDMMSG_BATCH_SIZE, tun_name_reader
                                );

                                // Pre-allocate TUN read buffer
                                let mut read_buf = vec![0u8; MAX_PACKET_SIZE];

                                // Pre-allocate sendmmsg batch for zero-copy encryption
                                let mut send_batch = SendMmsg::new(TUN_SENDMMSG_BATCH_SIZE, MAX_PACKET_SIZE);

                                let mut consecutive_empty = 0u32;
                                let mut packets_processed: u64 = 0;
                                let mut packets_no_session: u64 = 0;
                                let mut send_errors: u64 = 0;
                                let mut batches_sent: u64 = 0;

                                loop {
                                    if shutdown_reader.load(Ordering::Relaxed) {
                                        // Flush remaining packets before shutdown
                                        if !send_batch.is_empty() {
                                            let _ = send_batch.flush(&*send_socket_reader);
                                        }
                                        break;
                                    }

                                    match tun_device_read.recv(&mut read_buf) {
                                        Ok(len) if len > 0 => {
                                            consecutive_empty = 0;

                                            // Get destination IP from packet
                                            let dest_addr = match get_destination_addr(&read_buf[..len]) {
                                                Some(DestinationAddr::V4(dst_ip)) => {
                                                    sessions_for_reader.get_session_and_addr_by_ip(dst_ip)
                                                }
                                                Some(DestinationAddr::V6(dst_ip)) => {
                                                    sessions_for_reader.get_session_and_addr_by_ipv6(dst_ip)
                                                }
                                                None => None,
                                            };

                                            if let Some((session_id, client_addr)) = dest_addr {
                                                // Get session for encryption (read-only, thread-safe)
                                                if let Some(session_guard) = sessions_for_reader.get_session(session_id) {
                                                    // Get buffer from sendmmsg batch for zero-copy encryption
                                                    if let Some(encrypt_buf) = send_batch.get_buffer_mut() {
                                                        // Encrypt directly into sendmmsg buffer
                                                        match session_guard.session.encrypt_packet(
                                                            MessageType::Data,
                                                            &read_buf[..len],
                                                            encrypt_buf,
                                                        ) {
                                                            Ok(encrypted_len) => {
                                                                // Update stats
                                                                session_guard.add_bytes_sent(encrypted_len as u64);
                                                                drop(session_guard);

                                                                // Commit packet to batch
                                                                send_batch.commit(encrypted_len, client_addr);
                                                                packets_processed += 1;

                                                                // Flush if batch is full
                                                                if send_batch.is_full() {
                                                                    match send_batch.flush(&*send_socket_reader) {
                                                                        Ok(_) => batches_sent += 1,
                                                                        Err(e) => {
                                                                            send_errors += 1;
                                                                            if send_errors <= 10 || send_errors.is_multiple_of(1000) {
                                                                                trace!(
                                                                                    "TUN reader {}: sendmmsg error: {}",
                                                                                    reader_id, e
                                                                                );
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                            Err(e) => {
                                                                drop(session_guard);
                                                                trace!(
                                                                    "TUN reader {}: encrypt failed for session {}: {:?}",
                                                                    reader_id, session_id, e
                                                                );
                                                            }
                                                        }
                                                    } else {
                                                        drop(session_guard);
                                                    }
                                                } else {
                                                    packets_no_session += 1;
                                                }
                                            } else {
                                                packets_no_session += 1;
                                            }
                                        }
                                        Ok(_) => {
                                            consecutive_empty += 1;

                                            // Flush partial batch after a few empty reads
                                            if !send_batch.is_empty() && consecutive_empty >= FLUSH_AFTER_EMPTY_READS {
                                                match send_batch.flush(&*send_socket_reader) {
                                                    Ok(_) => batches_sent += 1,
                                                    Err(e) => {
                                                        send_errors += 1;
                                                        if send_errors <= 10 || send_errors.is_multiple_of(1000) {
                                                            trace!("TUN reader {}: sendmmsg flush error: {}", reader_id, e);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                            consecutive_empty += 1;

                                            // Flush partial batch after a few empty reads
                                            if !send_batch.is_empty() && consecutive_empty >= FLUSH_AFTER_EMPTY_READS {
                                                match send_batch.flush(&*send_socket_reader) {
                                                    Ok(_) => batches_sent += 1,
                                                    Err(e) => {
                                                        send_errors += 1;
                                                        if send_errors <= 10 || send_errors.is_multiple_of(1000) {
                                                            trace!("TUN reader {}: sendmmsg flush error: {}", reader_id, e);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            if !shutdown_reader.load(Ordering::Relaxed) {
                                                warn!("TUN read error in reader {}: {}", reader_id, e);
                                            }
                                            // Flush remaining before exit
                                            if !send_batch.is_empty() {
                                                let _ = send_batch.flush(&*send_socket_reader);
                                            }
                                            break;
                                        }
                                    }

                                    // Adaptive sleep based on activity
                                    if consecutive_empty > 0 {
                                        if consecutive_empty > 1000 {
                                            std::thread::sleep(std::time::Duration::from_micros(100));
                                        } else if consecutive_empty > 100 {
                                            std::thread::sleep(std::time::Duration::from_micros(10));
                                        } else {
                                            std::hint::spin_loop();
                                        }
                                    }
                                }
                                info!(
                                    "TUN reader thread {} stopped (processed: {}, batches: {}, no_session: {}, send_errors: {})",
                                    reader_id, packets_processed, batches_sent, packets_no_session, send_errors
                                );
                            }));

                            if let Err(panic_info) = result {
                                let msg = WorkerHealthTracker::extract_panic_message(&panic_info);
                                health_tracker.record_panic(&worker_name, &msg);
                            }
                        })
                        .map_err(|e| {
                            ServerError::Internal(format!(
                                "Failed to spawn TUN reader thread {}: {}",
                                reader_id, e
                            ))
                        })?;
                    self.worker_handles.push(WorkerHandle::new(
                        format!("tun-reader-{}", reader_id),
                        handle,
                    ));
                }

                // TUN WRITE THREAD - receives decrypted packets from UDP workers
                let tun_device_write = Arc::clone(&tun_device);
                let health_tracker_writer = Arc::clone(&worker_health);
                let handle = std::thread::Builder::new()
                    .name("tun-writer".into())
                    .spawn(move || {
                        // Wrap thread body in catch_unwind to prevent panics from crashing the server
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            info!("TUN writer thread started for {}", tun_name);
                            let mut consecutive_empty = 0u32;

                            loop {
                                if shutdown_tun_write.load(Ordering::Relaxed) {
                                    break;
                                }

                                let mut wrote_any = false;
                                for _ in 0..64 {
                                    match tun_write_rx.try_recv() {
                                        Ok(packet) => {
                                            if let Err(e) = tun_device_write.send(&packet) {
                                                warn!("TUN write error: {}", e);
                                            }
                                            wrote_any = true;
                                        }
                                        Err(crossbeam_channel::TryRecvError::Empty) => break,
                                        Err(crossbeam_channel::TryRecvError::Disconnected) => {
                                            return;
                                        }
                                    }
                                }

                                if wrote_any {
                                    consecutive_empty = 0;
                                } else {
                                    consecutive_empty += 1;
                                    if consecutive_empty > 100 {
                                        std::thread::sleep(std::time::Duration::from_micros(50));
                                    } else {
                                        std::hint::spin_loop();
                                    }
                                }
                            }
                            info!("TUN writer thread stopped");
                        }));

                        if let Err(panic_info) = result {
                            let msg = WorkerHealthTracker::extract_panic_message(&panic_info);
                            health_tracker_writer.record_panic("tun-writer", &msg);
                        }
                    })
                    .map_err(|e| {
                        ServerError::Internal(format!("Failed to spawn TUN writer thread: {}", e))
                    })?;
                self.worker_handles
                    .push(WorkerHandle::new("tun-writer", handle));
            }
        }

        // Main loop - only handles control messages that need async/crypto
        info!("Server main loop started - handling control messages");

        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                break;
            }

            // Process control messages from workers
            match control_rx.try_recv() {
                Ok(ctrl) => {
                    self.handle_control_message(ctrl, &response_tx).await;
                }
                Err(crossbeam_channel::TryRecvError::Empty) => {
                    // No control messages, yield to avoid busy loop
                    tokio::time::sleep(std::time::Duration::from_micros(100)).await;
                }
                Err(crossbeam_channel::TryRecvError::Disconnected) => {
                    info!("Control channel disconnected");
                    break;
                }
            }
        }

        // Shutdown is handled by Drop, but signal workers to stop early
        if let Some(ref workers) = self.udp_workers {
            workers.shutdown();
        }
        Ok(())
    }

    /// Run the VPN server with AF_XDP zero-copy networking.
    ///
    /// This is the highest-performance path, using kernel-bypass networking
    /// for 10+ Gbps throughput on supported hardware.
    #[cfg(all(target_os = "linux", feature = "afxdp"))]
    async fn run_afxdp(&mut self, runtime: RuntimeConfig) -> ServerResult<()> {
        use crate::afxdp_workers::{AfXdpPoolConfig, AfXdpWorkerPool};

        info!("Initializing AF_XDP zero-copy networking...");

        // Channel for decrypted packets to TUN
        let (tun_write_tx, tun_write_rx): (Sender<PooledBuffer>, Receiver<PooledBuffer>) =
            bounded(TUN_CHANNEL_CAPACITY);

        // Create AF_XDP configuration
        let afxdp_config = AfXdpPoolConfig {
            interface: runtime.interface.clone(),
            num_workers: runtime.tun_queues as u32,
            ring_size: 4096,
            zero_copy: true,
            busy_poll: false,
        };

        // Create AF_XDP worker pool
        let mut afxdp_pool = AfXdpWorkerPool::new(
            afxdp_config,
            Arc::clone(&self.sessions),
            tun_write_tx.clone(),
        )?;

        // Start workers
        afxdp_pool.start()?;

        info!(
            "AF_XDP networking started: {} workers on {}",
            runtime.tun_queues, runtime.interface
        );

        // Get control channel for handshakes
        let control_rx = afxdp_pool.control_rx().clone();
        let session_bridge = Arc::clone(afxdp_pool.session_bridge());

        // Install a combined lifecycle callback that also propagates
        // removals to the AF_XDP session bridge. Without this, an admin
        // API DELETE (or an expired session cleanup) would leave the
        // bridge table holding keys that still decrypt legitimate-looking
        // packets from a compromised client. Replaces the metrics-only
        // callback installed during `new_with_identity_hiding`.
        {
            let metrics_for_cb = Arc::clone(&self.metrics);
            let bridge_for_cb = Arc::clone(&session_bridge);
            self.sessions
                .set_lifecycle_callback(Box::new(move |event| match event {
                    crate::session_manager::SessionLifecycleEvent::Created(_) => {
                        metrics_for_cb.sessions_active.inc();
                    }
                    crate::session_manager::SessionLifecycleEvent::Removed(sid) => {
                        metrics_for_cb.record_session_ended(false);
                        bridge_for_cb.remove_session(sid);
                    }
                }));
        }

        // Setup TUN device
        let server_ip = self.config.parse_server_tunnel_ip()?;
        let netmask = self.sessions.netmask();

        // Create multiqueue TUN if supported
        let use_multiqueue = runtime.tun_multiqueue;

        if use_multiqueue {
            let mut mqtun = MultiQueueTun::create(&self.config.tun_name, runtime.tun_queues)?;
            mqtun.configure_ipv4(server_ip, self.sessions.prefix_len())?;

            if self.config.has_ipv6() {
                if let Some(server_ipv6) = self.config.parse_server_tunnel_ipv6()? {
                    let prefix_v6 = self.sessions.prefix_len_v6().unwrap_or(64);
                    mqtun.configure_ipv6(server_ipv6, prefix_v6)?;
                }
            }

            for queue in mqtun.queues_mut() {
                queue.set_nonblocking(true)?;
            }

            info!(
                "TUN device {} created with {} queues",
                self.config.tun_name, runtime.tun_queues
            );
        } else {
            // Single-queue TUN
            let tun = if self.config.has_ipv6() {
                let server_ipv6 = self.config.parse_server_tunnel_ipv6()?.ok_or_else(|| {
                    ServerError::Config("Server IPv6 must be set when has_ipv6 is true".into())
                })?;
                let ipv6_prefix = self.sessions.ipv6_prefix().unwrap_or(64);
                TunDevice::create_dual_stack(
                    &self.config.tun_name,
                    server_ip,
                    netmask,
                    server_ipv6,
                    ipv6_prefix,
                    self.config.mtu,
                )?
            } else {
                TunDevice::create(&self.config.tun_name, server_ip, netmask, self.config.mtu)?
            };
            self.tun = Some(tun);
            info!("TUN device {} created (single queue)", self.config.tun_name);
        }

        // Setup NAT if enabled
        if self.config.enable_nat {
            let mut nat =
                NatManager::new(&self.config.ipv4_pool, self.config.nat_interface.clone())?;
            nat.enable()?;
            if let Err(e) = crate::nat::allow_forward(&self.config.ipv4_pool, &self.config.tun_name)
            {
                warn!("Failed to add FORWARD rules: {}", e);
            }
            if self.config.has_ipv6() {
                if let Some(ref ipv6_pool) = self.config.ipv6_pool {
                    nat.enable_ipv6(ipv6_pool)?;
                }
            }
            self.nat = Some(nat);
        }

        // Spawn TUN writer thread - receives decrypted packets from AF_XDP workers
        let tun_name_writer = self.config.tun_name.clone();
        let shutdown_tun_write = Arc::clone(&self.shutdown);
        let tun_device = self
            .tun
            .take()
            .ok_or_else(|| ServerError::Internal("TUN device not initialized".to_string()))?;
        let tun_device = Arc::new(tun_device);

        let tun_device_write = Arc::clone(&tun_device);
        std::thread::Builder::new()
            .name("tun-writer".into())
            .spawn(move || {
                info!("TUN writer thread started for {}", tun_name_writer);
                let mut consecutive_empty = 0u32;

                loop {
                    if shutdown_tun_write.load(Ordering::Relaxed) {
                        break;
                    }

                    let mut wrote_any = false;
                    for _ in 0..64 {
                        match tun_write_rx.try_recv() {
                            Ok(packet) => {
                                if let Err(e) = tun_device_write.send(packet.as_slice()) {
                                    warn!("TUN write error: {}", e);
                                }
                                wrote_any = true;
                            }
                            Err(crossbeam_channel::TryRecvError::Empty) => break,
                            Err(crossbeam_channel::TryRecvError::Disconnected) => return,
                        }
                    }

                    if wrote_any {
                        consecutive_empty = 0;
                    } else {
                        consecutive_empty += 1;
                        if consecutive_empty > 100 {
                            std::thread::sleep(std::time::Duration::from_micros(50));
                        } else {
                            std::hint::spin_loop();
                        }
                    }
                }
                info!("TUN writer thread stopped");
            })
            .map_err(|e| ServerError::Internal(format!("Failed to spawn TUN writer: {}", e)))?;

        // Spawn TUN reader thread - reads packets from TUN and sends to clients via UDP
        // This is the TX path: TUN → encrypt → UDP socket → client
        let tun_name_reader = self.config.tun_name.clone();
        let shutdown_tun_read = Arc::clone(&self.shutdown);
        let sessions_tun_read = Arc::clone(&self.sessions);
        let tun_device_read = Arc::clone(&tun_device);

        // Create UDP socket for outbound data packets
        let tx_socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
        tx_socket.set_nonblocking(true)?;
        info!(
            "TX socket bound to {} (for outbound data packets)",
            tx_socket.local_addr()?
        );

        std::thread::Builder::new()
            .name("tun-reader".into())
            .spawn(move || {
                info!("TUN reader thread started for {}", tun_name_reader);

                let mut read_buf = vec![0u8; MAX_PACKET_SIZE];
                let mut encrypt_buf =
                    vec![0u8; MAX_PACKET_SIZE + HEADER_SIZE + aead::TAG_SIZE + 32];
                let mut consecutive_empty = 0u32;

                loop {
                    if shutdown_tun_read.load(Ordering::Relaxed) {
                        break;
                    }

                    match tun_device_read.recv(&mut read_buf) {
                        Ok(len) if len > 0 => {
                            consecutive_empty = 0;

                            // Get destination IP from packet header and lookup session
                            let session_info = match get_destination_addr(&read_buf[..len]) {
                                Some(DestinationAddr::V4(dst_ip)) => {
                                    sessions_tun_read.get_session_and_addr_by_ip(dst_ip)
                                }
                                Some(DestinationAddr::V6(dst_ip)) => {
                                    sessions_tun_read.get_session_and_addr_by_ipv6(dst_ip)
                                }
                                None => None,
                            };

                            if let Some((session_id, client_addr)) = session_info {
                                // Get session for encryption
                                if let Some(session_guard) =
                                    sessions_tun_read.get_session(session_id)
                                {
                                    match session_guard.session.encrypt_packet(
                                        MessageType::Data,
                                        &read_buf[..len],
                                        &mut encrypt_buf,
                                    ) {
                                        Ok(encrypted_len) => {
                                            session_guard.add_bytes_sent(encrypted_len as u64);
                                            drop(session_guard);

                                            if let Err(e) = tx_socket
                                                .send_to(&encrypt_buf[..encrypted_len], client_addr)
                                            {
                                                if e.kind() != std::io::ErrorKind::WouldBlock {
                                                    trace!("TUN reader: send error: {}", e);
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            drop(session_guard);
                                            trace!("TUN reader: encrypt failed: {:?}", e);
                                        }
                                    }
                                }
                            }
                        }
                        Ok(_) => {
                            consecutive_empty += 1;
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            consecutive_empty += 1;
                        }
                        Err(e) => {
                            if !shutdown_tun_read.load(Ordering::Relaxed) {
                                warn!("TUN read error: {}", e);
                            }
                            break;
                        }
                    }

                    // Adaptive sleep
                    if consecutive_empty > 0 {
                        if consecutive_empty > 1000 {
                            std::thread::sleep(std::time::Duration::from_micros(100));
                        } else if consecutive_empty > 100 {
                            std::thread::sleep(std::time::Duration::from_micros(10));
                        } else {
                            std::hint::spin_loop();
                        }
                    }
                }
                info!("TUN reader thread stopped");
            })
            .map_err(|e| ServerError::Internal(format!("Failed to spawn TUN reader: {}", e)))?;

        // Spawn cleanup task
        let sessions_cleanup = Arc::clone(&self.sessions);
        let shutdown_cleanup = Arc::clone(&self.shutdown);
        tokio::spawn(async move {
            let mut interval = time::interval(std::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                if shutdown_cleanup.load(Ordering::Relaxed) {
                    break;
                }
                sessions_cleanup.cleanup_expired();
            }
        });

        // Start metrics logging
        let metrics = self.metrics.clone();
        let shutdown_metrics = Arc::clone(&self.shutdown);
        tokio::spawn(async move {
            let mut interval = time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                if shutdown_metrics.load(Ordering::Relaxed) {
                    break;
                }
                let summary = metrics.summary();
                info!("Metrics: {}", summary.format());
            }
        });

        info!("AF_XDP server running on {}", self.config.listen_addr);

        // Get response channel for sending replies to clients
        let response_tx = afxdp_pool.response_tx().clone();
        let response_rx = afxdp_pool.response_rx().clone();

        // Spawn a UDP socket for sending responses (handshakes, rekeys, keepalives)
        // AF_XDP handles data packets, but control plane responses go through standard UDP
        // We bind to 0.0.0.0:0 (ephemeral port) to avoid conflict with AF_XDP on the main port.
        // Responses will come from a different source port, but clients handle this correctly
        // as they match by session_id in the packet header, not by source port.
        let response_socket = UdpSocket::bind("0.0.0.0:0").await?;
        let response_socket = Arc::new(response_socket);
        let response_addr = response_socket
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        info!(
            "Response socket bound to {} (for control plane responses)",
            response_addr
        );

        // Spawn response sender task
        let response_socket_clone = Arc::clone(&response_socket);
        let shutdown_response = Arc::clone(&self.shutdown);
        tokio::spawn(async move {
            loop {
                if shutdown_response.load(Ordering::Relaxed) {
                    break;
                }

                match response_rx.try_recv() {
                    Ok(response) => {
                        if let Err(e) = response_socket_clone
                            .send_to(&response.data, response.addr)
                            .await
                        {
                            warn!(
                                "Failed to send response to {}: {}",
                                crate::privacy::addr(response.addr),
                                e
                            );
                        }
                    }
                    Err(crossbeam_channel::TryRecvError::Empty) => {
                        tokio::time::sleep(std::time::Duration::from_micros(50)).await;
                    }
                    Err(crossbeam_channel::TryRecvError::Disconnected) => {
                        debug!("Response channel disconnected");
                        break;
                    }
                }
            }
        });

        // Main event loop - handle control messages
        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                break;
            }

            // Process control messages from AF_XDP workers
            match control_rx.try_recv() {
                Ok(ctrl) => {
                    self.handle_afxdp_control(ctrl, &session_bridge, &response_tx)
                        .await;
                }
                Err(crossbeam_channel::TryRecvError::Empty) => {
                    tokio::time::sleep(std::time::Duration::from_micros(100)).await;
                }
                Err(crossbeam_channel::TryRecvError::Disconnected) => {
                    warn!("AF_XDP control channel disconnected");
                    break;
                }
            }
        }

        // Cleanup
        afxdp_pool.shutdown();
        info!("AF_XDP server stopped");
        Ok(())
    }

    /// Handle control message from AF_XDP workers.
    #[cfg(all(target_os = "linux", feature = "afxdp"))]
    async fn handle_afxdp_control(
        &self,
        ctrl: crate::afxdp_workers::AfXdpControl,
        session_bridge: &Arc<crate::afxdp_workers::SessionBridge>,
        response_tx: &Sender<crate::afxdp_workers::AfXdpResponse>,
    ) {
        use crate::afxdp_workers::AfXdpControl;

        match ctrl {
            AfXdpControl::HandshakeInit { data, addr } => {
                // Handle handshake - creates new session and sends response
                if let Some(session_id) = self
                    .handle_handshake_init_afxdp(&data, addr, response_tx)
                    .await
                {
                    // Sync new session to AF_XDP table
                    if let Err(e) = session_bridge.sync_session(session_id) {
                        warn!("Failed to sync session {} to AF_XDP: {}", session_id.0, e);
                    }
                }
            }
            AfXdpControl::Keepalive {
                session_id,
                data,
                addr,
            } => {
                // Handle keepalive with response
                self.handle_keepalive_afxdp(session_id, &data, addr, response_tx)
                    .await;
            }
            AfXdpControl::Rekey {
                session_id,
                data,
                addr,
            } => {
                // Handle rekey
                if self
                    .handle_rekey_afxdp(session_id, &data, addr, response_tx)
                    .await
                {
                    // Sync updated keys to AF_XDP table
                    if let Err(e) = session_bridge.sync_session(session_id) {
                        warn!(
                            "Failed to sync rekeyed session {} to AF_XDP: {}",
                            session_id.0, e
                        );
                    }
                }
            }
            AfXdpControl::Control {
                session_id,
                data,
                addr,
            } => {
                // Handle control message (may remove session from AF_XDP table)
                if let Some(removed_session_id) = self
                    .handle_control_afxdp(session_id, &data, addr, response_tx)
                    .await
                {
                    session_bridge.remove_session(removed_session_id);
                }
            }
        }
    }

    /// Handle handshake init for AF_XDP path.
    ///
    /// Creates a new session and sends the handshake response via the response channel.
    #[cfg(all(target_os = "linux", feature = "afxdp"))]
    async fn handle_handshake_init_afxdp(
        &self,
        data: &[u8],
        addr: SocketAddr,
        response_tx: &Sender<crate::afxdp_workers::AfXdpResponse>,
    ) -> Option<SessionId> {
        use crate::afxdp_workers::AfXdpResponse;

        self.metrics.handshakes_total.inc();

        // Rate limit check - protect against handshake DoS
        if !self.rate_limiter.allow(addr.ip()) {
            debug!("Rate limited handshake from {}", crate::privacy::addr(addr));
            self.metrics.record_rate_limited();
            self.metrics.handshakes_failed.inc();
            return None;
        }

        // Parse handshake init (skip header for AF_XDP path - data is already payload)
        let payload = if data.len() > HEADER_SIZE {
            &data[HEADER_SIZE..]
        } else {
            data
        };

        let init = match HandshakeInit::from_bytes(payload) {
            Ok(i) => i,
            Err(e) => {
                debug!(
                    "Invalid handshake init from {}: {}",
                    crate::privacy::addr(addr),
                    e
                );
                self.metrics.record_invalid_packet();
                self.metrics.handshakes_failed.inc();
                return None;
            }
        };

        // Enforce minimum security level policy (prevents downgrade).
        if !self.security_level_accepted(init.security_level) {
            warn!(
                "Rejecting handshake with security level {:?} below configured minimum from {}",
                init.security_level,
                crate::privacy::addr(addr)
            );
            self.metrics.handshakes_failed.inc();
            return None;
        }

        // Handshake-level anti-replay (AF_XDP path). Cheap hash-set
        // lookup before credential decryption and ML-DSA signing. A
        // `client_random` collision within the cache TTL is either a
        // passive-capture replay or an unlucky retry — silently dropping
        // is correct (the legitimate retry will regenerate a fresh
        // random on the next attempt).
        if !self.handshake_replay.check_and_insert(&init.client_random) {
            debug!(
                "Dropping replayed HandshakeInit (duplicate client_random) from {}",
                crate::privacy::addr(addr)
            );
            self.metrics.handshakes_failed.inc();
            return None;
        }

        // Validate credentials if authentication is required
        if let Some(ref user_store) = self.user_store {
            // Get the KEM keypair for decrypting credentials
            let kem_keypair = match self.kem_keypair_for_level(init.security_level) {
                Some(kp) => kp,
                None => {
                    warn!(
                        "Authentication requires identity hiding but no KEM keypair for {:?} from {}",
                        init.security_level,
                        crate::privacy::addr(addr)
                    );
                    self.metrics.handshakes_failed.inc();
                    return None;
                }
            };

            // Check if credentials are provided
            let Some(ref encrypted_creds) = init.credentials else {
                warn!(
                    "Authentication required but no credentials provided from {}",
                    crate::privacy::addr(addr)
                );
                self.metrics.handshakes_failed.inc();
                return None;
            };

            // Decrypt and verify credentials
            let creds = match encrypted_creds.decrypt(&kem_keypair.0) {
                Ok(creds) => creds,
                Err(e) => {
                    warn!(
                        "Failed to decrypt credentials from {}: {}",
                        crate::privacy::addr(addr),
                        e
                    );
                    self.metrics.handshakes_failed.inc();
                    return None;
                }
            };

            // Verify against user store with auth-lockout layer (see
            // `authenticate_credentials` for the layered policy and the
            // constant-time properties of the rejection path).
            if self
                .authenticate_credentials(user_store, &creds.username, &creds.password, addr)
                .await
                .is_err()
            {
                self.metrics.handshakes_failed.inc();
                return None;
            }
        }

        // Create server handshake state with keypair matching client's security level
        let keypair = self.keypair_for_level(init.security_level);
        let mut handshake = ServerHandshake::new(keypair.clone());
        let session_id = SessionId::generate();

        // Build tunnel configuration
        let dns_servers = self.config.parse_dns_servers().unwrap_or_default();
        let dns_servers_v6 = self.config.parse_dns_servers_v6().unwrap_or_default();
        let config = TunnelConfig {
            client_ipv4: [0, 0, 0, 0], // Will be filled after allocation
            netmask_ipv4: self.sessions.netmask(),
            gateway_ipv4: self.sessions.server_ip(),
            dns_ipv4: dns_servers,
            client_ipv6: None,
            prefix_len_ipv6: self.sessions.ipv6_prefix(),
            gateway_ipv6: self.sessions.server_ipv6(),
            dns_ipv6: dns_servers_v6,
            mtu: self.config.mtu,
        };

        // Process init and generate response
        let (mut response, server_keys) = match handshake.process_init(&init, session_id, config) {
            Ok(r) => r,
            Err(e) => {
                error!(
                    "Handshake processing failed for {}: {}",
                    crate::privacy::addr(addr),
                    e
                );
                self.metrics.handshakes_failed.inc();
                return None;
            }
        };
        let response_send_key = server_keys.send_key;

        // Create session and allocate tunnel IP
        let session = match Session::new(session_id, server_keys) {
            Ok(s) => s,
            Err(e) => {
                error!(
                    "Session key init failed for {}: {}",
                    crate::privacy::addr(addr),
                    e
                );
                self.metrics.handshakes_failed.inc();
                return None;
            }
        };
        let (tunnel_ip, tunnel_ipv6) = match self.sessions.create_session_dual_stack_with_level(
            session,
            addr,
            init.security_level,
        ) {
            Ok(ips) => ips,
            Err(e) => {
                error!(
                    "Session creation failed for {}: {}",
                    crate::privacy::addr(addr),
                    e
                );
                self.metrics.handshakes_failed.inc();
                return None;
            }
        };

        // Update response with allocated IPs
        response.config.client_ipv4 = tunnel_ip;
        response.config.client_ipv6 = tunnel_ipv6;

        if let Err(e) = hpn_core::protocol::handshake::refresh_handshake_response_auth(
            &mut response,
            &init.client_random,
            init.security_level,
            keypair.as_ref(),
            &response_send_key,
        ) {
            error!(
                "Failed to refresh handshake response authentication for {}: {}",
                crate::privacy::addr(addr),
                e
            );
            self.sessions.remove_session(session_id);
            self.metrics.handshakes_failed.inc();
            return None;
        }

        // Encode and send response — may produce multiple datagrams if
        // the response payload exceeds `FRAGMENTATION_THRESHOLD`.
        //
        // TODO(afxdp): the AF_XDP RX worker in `afxdp_workers.rs` does
        // not yet classify `MessageType::HandshakeFragment`, so a
        // Level 5 handshake that required application-layer
        // fragmentation on the client side will not reach this
        // handler when the server is running on the AF_XDP fast path.
        // The recvmmsg/io_uring workers in `udp_workers.rs` DO
        // handle it, which is the production path. Extend
        // `afxdp_workers::classify_packet` when AF_XDP becomes a
        // supported customer deployment.
        let response_packets =
            match self.encode_handshake_response_as_packets(&response, session_id) {
                Ok(packets) => packets,
                Err(e) => {
                    error!(
                        "Failed to encode handshake response for {}: {}",
                        crate::privacy::addr(addr),
                        e
                    );
                    return None;
                }
            };

        let total_fragments = response_packets.len();
        let mut queued = 0usize;
        for packet in response_packets {
            match response_tx.try_send(AfXdpResponse {
                addr,
                data: Bytes::from(packet),
            }) {
                Ok(()) => queued += 1,
                Err(e) => {
                    error!(
                        "Failed to queue handshake response packet {}/{} to {}: {:?}",
                        queued + 1,
                        total_fragments,
                        crate::privacy::addr(addr),
                        e
                    );
                    break;
                }
            }
        }

        if queued == total_fragments {
            self.metrics.handshakes_success.inc();
            self.metrics.sessions_total.inc();
            // sessions_active is maintained by the manager's lifecycle
            // callback installed at startup (see `new_with_identity_hiding`).
            info!(
                "Handshake complete for {}, session {}, IP {} ({} packet{})",
                crate::privacy::addr(addr),
                session_id,
                if crate::privacy::is_enabled() {
                    "[redacted]".to_string()
                } else {
                    format!(
                        "{}.{}.{}.{}",
                        tunnel_ip[0], tunnel_ip[1], tunnel_ip[2], tunnel_ip[3]
                    )
                },
                total_fragments,
                if total_fragments == 1 { "" } else { "s" }
            );
            Some(session_id)
        } else {
            // Clean up the session we just created: partial transmission
            // of a fragmented response will leave the client unable to
            // complete reassembly, so it is not useful to keep the
            // server-side session around.
            self.sessions.remove_session(session_id);
            self.metrics.handshakes_failed.inc();
            None
        }
    }

    /// Handle keepalive for AF_XDP path.
    #[cfg(all(target_os = "linux", feature = "afxdp"))]
    async fn handle_keepalive_afxdp(
        &self,
        session_id: SessionId,
        data: &[u8],
        addr: SocketAddr,
        response_tx: &Sender<crate::afxdp_workers::AfXdpResponse>,
    ) {
        use crate::afxdp_workers::AfXdpResponse;
        use hpn_core::protocol::KeepaliveMessage;

        // No `mut` needed: FIX-010 removed the rebind branch that used to
        // reassign `session_guard` after dropping it for `update_client_addr`.
        // The remaining call sites (`touch`, `decrypt_packet`, `encrypt_packet`,
        // `client_addr.lock()`) only need a shared borrow.
        let session_guard = match self.sessions.get_session_mut(session_id) {
            Some(s) => s,
            None => return,
        };

        // Defer roaming update until after AEAD authentication succeeds.
        // AF_XDP workers may emit placeholder 0.0.0.0:0 when source metadata is unavailable.
        let addr_changed =
            Self::is_valid_afxdp_peer_addr(addr) && *session_guard.client_addr.lock() != addr;

        // Decrypt keepalive FIRST (authenticates via AEAD tag).
        let mut decrypt_buf = vec![0u8; data.len()];
        let (_, len) = match session_guard.session.decrypt_packet(data, &mut decrypt_buf) {
            Ok(r) => r,
            Err(_) => {
                self.metrics.decryption_errors.inc();
                return;
            }
        };

        let keepalive = match KeepaliveMessage::from_bytes(&decrypt_buf[..len]) {
            Ok(k) => k,
            Err(_) => return,
        };

        // FIX-010: refuse to rebind on a Keepalive packet even after AEAD
        // success. Roaming MUST travel through an explicit
        // `ControlType::Rebind` from the client; anything else risks a
        // capture+spoof hijack of the return path. Drop instead of update.
        //
        // Check BEFORE `touch()` so an attacker who captures a fresh
        // authenticated keepalive cannot keep the session alive by
        // replaying it from a spoofed source IP. Without this ordering,
        // FIX-010 would close the hijack but not the keep-alive-zombie
        // vector (bounded by the anti-replay window, but real).
        if addr_changed {
            debug!(
                "Address mismatch on AF_XDP keepalive for session {} — dropping (FIX-010)",
                session_id
            );
            self.metrics.record_address_mismatch_drop();
            return;
        }

        session_guard.touch();

        // Build reply
        let server_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let reply = hpn_core::protocol::KeepaliveReplyMessage {
            sequence: keepalive.sequence,
            server_timestamp,
        };

        let payload = reply.to_bytes();
        let mut output = vec![0u8; HEADER_SIZE + payload.len() + aead::TAG_SIZE + 32];
        let len = match session_guard.session.encrypt_packet(
            MessageType::KeepaliveReply,
            &payload,
            &mut output,
        ) {
            Ok(l) => l,
            Err(_) => return,
        };

        let client_addr = *session_guard.client_addr.lock();
        drop(session_guard);

        let _ = response_tx.try_send(AfXdpResponse {
            addr: client_addr,
            data: Bytes::copy_from_slice(&output[..len]),
        });
    }

    /// Handle rekey for AF_XDP path.
    ///
    /// Processes a rekey request, generates new session keys, and sends the response.
    /// Returns true if rekey was successful (caller should sync to AF_XDP table).
    #[cfg(all(target_os = "linux", feature = "afxdp"))]
    async fn handle_rekey_afxdp(
        &self,
        session_id: SessionId,
        data: &[u8],
        addr: SocketAddr,
        response_tx: &Sender<crate::afxdp_workers::AfXdpResponse>,
    ) -> bool {
        use crate::afxdp_workers::AfXdpResponse;
        use hpn_core::protocol::RekeyMessage;

        let mut session_guard = match self.sessions.get_session_mut(session_id) {
            Some(s) => s,
            None => {
                debug!("Rekey for unknown session {}", session_id.0);
                return false;
            }
        };

        // Defer roaming update until after AEAD authentication succeeds.
        // AF_XDP workers may emit placeholder 0.0.0.0:0 when source metadata is unavailable.
        let addr_changed =
            Self::is_valid_afxdp_peer_addr(addr) && *session_guard.client_addr.lock() != addr;

        // Decrypt rekey message FIRST (authenticates via AEAD tag).
        let mut decrypt_buf = vec![0u8; data.len()];
        let (_, len) = match session_guard.session.decrypt_packet(data, &mut decrypt_buf) {
            Ok(r) => r,
            Err(e) => {
                debug!(
                    "Failed to decrypt rekey from session {}: {:?}",
                    session_id.0, e
                );
                return false;
            }
        };

        let rekey_msg = match RekeyMessage::from_bytes(&decrypt_buf[..len]) {
            Ok(r) => r,
            Err(e) => {
                debug!(
                    "Failed to parse rekey from session {}: {:?}",
                    session_id.0, e
                );
                return false;
            }
        };

        // FIX-010: refuse to rebind on a Rekey packet even after AEAD
        // success. The client must send `ControlType::Rebind` first if it
        // really roamed; otherwise this is a capture+spoof attempt. Drop
        // and bail out.
        if addr_changed {
            debug!(
                "Address mismatch on AF_XDP rekey for session {} — dropping (FIX-010)",
                session_id.0
            );
            self.metrics.record_address_mismatch_drop();
            return false;
        }

        if rekey_msg.client_ephemeral_pk.security_level != session_guard.security_level {
            warn!(
                "Rejected rekey with mismatched security level for session {}: established={:?}, requested={:?}",
                session_id.0,
                session_guard.security_level,
                rekey_msg.client_ephemeral_pk.security_level
            );
            return false;
        }

        info!("Rekey request from session {}", session_id.0);

        // Process rekey with keypair matching client's security level
        let keypair = self.keypair_for_level(rekey_msg.client_ephemeral_pk.security_level);
        let rekey_handler = ServerHandshake::new(keypair);
        let current_key_id = session_guard.session.key_id();

        let (response, new_keys) =
            match rekey_handler.process_rekey(&rekey_msg, current_key_id, session_id) {
                Ok(r) => r,
                Err(e) => {
                    error!(
                        "Rekey processing failed for session {}: {}",
                        session_id.0, e
                    );
                    return false;
                }
            };

        // Encrypt response
        let payload = response.to_bytes();
        let mut output = vec![0u8; HEADER_SIZE + payload.len() + aead::TAG_SIZE + 32];
        let len = match session_guard.session.encrypt_packet(
            MessageType::RekeyResponse,
            &payload,
            &mut output,
        ) {
            Ok(l) => l,
            Err(e) => {
                error!(
                    "Failed to encrypt rekey response for session {}: {:?}",
                    session_id.0, e
                );
                return false;
            }
        };

        // Update session with new keys BEFORE sending response
        if let Err(e) = session_guard.session.update_keys(new_keys) {
            error!("Rekey failed — invalid key material: {}", e);
            return false;
        }
        session_guard.touch();
        let client_addr = *session_guard.client_addr.lock();
        drop(session_guard);

        // Send response
        match response_tx.try_send(AfXdpResponse {
            addr: client_addr,
            data: Bytes::copy_from_slice(&output[..len]),
        }) {
            Ok(()) => {
                info!(
                    "Rekey complete for session {}, new key_id={}",
                    session_id.0, response.new_key_id
                );
                true
            }
            Err(e) => {
                warn!(
                    "Failed to queue rekey response to {}: {:?}",
                    crate::privacy::addr(client_addr),
                    e
                );
                false
            }
        }
    }

    /// Handle control message for AF_XDP path.
    ///
    /// Processes control messages (close, rebind, etc.).
    /// Returns Some(session_id) if the session was removed and should be cleaned up from AF_XDP table.
    #[cfg(all(target_os = "linux", feature = "afxdp"))]
    async fn handle_control_afxdp(
        &self,
        session_id: SessionId,
        data: &[u8],
        addr: SocketAddr,
        response_tx: &Sender<crate::afxdp_workers::AfXdpResponse>,
    ) -> Option<SessionId> {
        use crate::afxdp_workers::AfXdpResponse;
        use hpn_core::protocol::ControlMessage;
        use hpn_core::types::ControlType;

        let session_guard = match self.sessions.get_session_mut(session_id) {
            Some(s) => s,
            None => {
                debug!("Control message for unknown session {}", session_id.0);
                return None;
            }
        };

        // Decrypt control message
        let mut decrypt_buf = vec![0u8; data.len()];
        let (_, len) = match session_guard.session.decrypt_packet(data, &mut decrypt_buf) {
            Ok(r) => r,
            Err(e) => {
                debug!(
                    "Failed to decrypt control from session {}: {:?}",
                    session_id.0, e
                );
                return None;
            }
        };

        let control = match ControlMessage::from_bytes(&decrypt_buf[..len]) {
            Ok(c) => c,
            Err(e) => {
                debug!(
                    "Failed to parse control from session {}: {:?}",
                    session_id.0, e
                );
                return None;
            }
        };

        drop(session_guard);

        match control.control_type {
            ControlType::Close => {
                info!("Client {} requested disconnect", session_id.0);
                // sessions_active is decremented by the lifecycle callback.
                self.sessions.remove_session(session_id);
                Some(session_id)
            }
            ControlType::Rebind => {
                // Update client address and send ack
                if Self::is_valid_afxdp_peer_addr(addr) {
                    self.sessions.update_client_addr(session_id, addr);
                }
                self.send_rebind_ack_afxdp(session_id, response_tx).await;
                if Self::is_valid_afxdp_peer_addr(addr) {
                    info!(
                        "Session {} rebound to {}",
                        session_id.0,
                        crate::privacy::addr(addr)
                    );
                } else {
                    debug!(
                        "Session {} sent rebind on AF_XDP path without peer address metadata",
                        session_id.0
                    );
                }
                None
            }
            _ => {
                debug!(
                    "Unhandled control type {:?} for session {}",
                    control.control_type, session_id.0
                );
                None
            }
        }
    }

    /// Send rebind acknowledgment for AF_XDP path.
    #[cfg(all(target_os = "linux", feature = "afxdp"))]
    async fn send_rebind_ack_afxdp(
        &self,
        session_id: SessionId,
        response_tx: &Sender<crate::afxdp_workers::AfXdpResponse>,
    ) {
        use crate::afxdp_workers::AfXdpResponse;
        use hpn_core::protocol::ControlMessage;

        let session_guard = match self.sessions.get_session(session_id) {
            Some(s) => s,
            None => return,
        };

        let client_addr = *session_guard.client_addr.lock();
        let security_level = session_guard.security_level;
        // Drop the session guard BEFORE building the (potentially CPU-
        // expensive) ML-DSA signature so we don't hold the dashmap shard
        // lock across the signing call.
        drop(session_guard);

        // Audit H11: bind the ack to the post-roaming endpoint with an
        // ML-DSA signature so a session-key-only attacker cannot forge
        // a redirect ack. `keypair_for_level` matches the level the
        // session was established with, so the client's stored
        // `server_static_pk` will verify it on the receiving side.
        let keypair = self.keypair_for_level(security_level);
        // Audit H11-F4: signing failure is a genuine security regression
        // (the H11 mitigation is silently downgraded). ML-DSA is
        // deterministic on supported targets, so this branch is
        // unreachable in practice — but logging at `error!` ensures any
        // future signing-error condition surfaces in alert pipelines
        // instead of being lost in `warn!` noise.
        let ack = match SignedRebindAckPayload::sign(&keypair, session_id, client_addr) {
            Ok(signed) => ControlMessage::rebind_ack_signed(signed),
            Err(e) => {
                error!(
                    "Failed to sign rebind ack for session {}: {} — falling back to unsigned (audit H11 mitigation downgraded)",
                    session_id, e
                );
                ControlMessage {
                    control_type: hpn_core::types::ControlType::RebindAck,
                    error_code: None,
                    message: None,
                    signed_payload: None,
                }
            }
        };

        // Re-acquire the session for encryption only.
        let session_guard = match self.sessions.get_session(session_id) {
            Some(s) => s,
            None => return,
        };

        let payload = ack.to_bytes();
        let mut output = vec![0u8; HEADER_SIZE + payload.len() + aead::TAG_SIZE + 32];
        let len =
            match session_guard
                .session
                .encrypt_packet(MessageType::Control, &payload, &mut output)
            {
                Ok(l) => l,
                Err(_) => return,
            };

        // Audit H11 follow-up (FIX-004): close the read-vs-sign TOCTOU.
        // The signature commits to the address we read at the top of this
        // function. If another concurrent rebind has since shifted
        // `client_addr` to a different endpoint, sending the ack THERE
        // would deliver a signature certifying an obsolete address — the
        // client (with `require_signed_rebind_ack = true`) verifies the
        // embedded address against its CURRENT public endpoint and would
        // reject the ack anyway. Drop here so the metric stays consistent
        // with what reaches the wire.
        let current_addr = *session_guard.client_addr.lock();
        drop(session_guard);
        if current_addr != client_addr {
            warn!(
                "Dropping signed rebind ack for session {}: client_addr drifted from {} to {} between sign and send",
                session_id,
                crate::privacy::addr(client_addr),
                crate::privacy::addr(current_addr)
            );
            return;
        }

        let _ = response_tx.try_send(AfXdpResponse {
            addr: client_addr,
            data: Bytes::copy_from_slice(&output[..len]),
        });
    }

    /// Handle a control message from UDP workers.
    #[cfg(target_os = "linux")]
    async fn handle_control_message(
        &self,
        ctrl: WorkerControl,
        response_tx: &Sender<OutboundResponse>,
    ) {
        match ctrl {
            WorkerControl::HandshakeInit { data, addr } => {
                self.handle_handshake_init_internal(&data, addr, response_tx)
                    .await;
            }
            WorkerControl::HandshakeFragment { data, addr } => {
                self.handle_handshake_fragment_internal(&data, addr, response_tx)
                    .await;
            }
            WorkerControl::Keepalive {
                session_id,
                data,
                addr,
            } => {
                self.handle_keepalive_internal(session_id, &data, addr, response_tx)
                    .await;
            }
            WorkerControl::Control {
                session_id,
                data,
                addr,
            } => {
                self.handle_control_internal(session_id, &data, addr, response_tx)
                    .await;
            }
            WorkerControl::Rekey {
                session_id,
                data,
                addr,
            } => {
                self.handle_rekey_internal(session_id, &data, addr, response_tx)
                    .await;
            }
        }
    }

    /// Run the VPN server (non-Linux fallback).
    #[cfg(not(target_os = "linux"))]
    pub async fn run(&mut self) -> ServerResult<()> {
        // Bind UDP socket
        let socket = UdpSocket::bind(self.config.listen_addr).await?;
        info!("Server listening on {}", self.config.listen_addr);

        let socket = Arc::new(socket);
        self.socket = Some(Arc::clone(&socket));

        let (tun_tx, mut tun_rx) = mpsc::unbounded_channel::<(Vec<u8>, SessionId)>();

        #[allow(unused_variables)]
        let (tun_write_tx, tun_write_rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) =
            bounded(TUN_CHANNEL_CAPACITY);

        // Spawn cleanup task
        let sessions_cleanup = Arc::clone(&self.sessions);
        let shutdown_cleanup = Arc::clone(&self.shutdown);
        tokio::spawn(async move {
            let mut interval = time::interval(std::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                if shutdown_cleanup.load(Ordering::Relaxed) {
                    break;
                }
                sessions_cleanup.cleanup_expired();
            }
        });

        let tun_write_tx = Arc::new(tun_write_tx);
        let mut recv_buf = vec![0u8; MAX_PACKET_SIZE];
        let mut decrypt_buf = vec![0u8; MAX_PACKET_SIZE];

        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                break;
            }

            tokio::select! {
                result = socket.recv_from(&mut recv_buf) => {
                    match result {
                        Ok((n, addr)) if n > 0 => {
                            self.handle_packet(&recv_buf[..n], addr, &mut decrypt_buf, &tun_tx, &tun_write_tx).await;
                        }
                        Ok(_) => {}
                        Err(e) => {
                            error!("Socket receive error: {}", e);
                        }
                    }
                }

                Some((packet, session_id)) = tun_rx.recv() => {
                    self.send_to_client(session_id, &packet, &socket).await;
                }
            }
        }

        Ok(())
    }

    /// Handle an incoming packet (used in non-Linux path).
    #[allow(dead_code)]
    async fn handle_packet(
        &self,
        data: &[u8],
        addr: SocketAddr,
        decrypt_buf: &mut [u8],
        _tun_rx_tx: &mpsc::UnboundedSender<(Vec<u8>, SessionId)>,
        tun_write_tx: &Arc<Sender<Vec<u8>>>,
    ) {
        if data.len() < HEADER_SIZE {
            trace!("Packet too short from {}", crate::privacy::addr(addr));
            return;
        }

        let header = match PacketHeader::decode(data) {
            Ok(h) => h,
            Err(e) => {
                debug!("Invalid header from {}: {}", crate::privacy::addr(addr), e);
                return;
            }
        };

        debug!(
            "Packet received: type={:?}, session={}, from={}, len={}",
            header.msg_type,
            header.session_id,
            addr,
            data.len()
        );

        match header.msg_type {
            MessageType::HandshakeInit | MessageType::EncryptedHandshakeInit => {
                self.handle_handshake_init(data, addr, header.msg_type)
                    .await;
            }
            MessageType::HandshakeFragment => {
                self.handle_handshake_fragment(data, addr).await;
            }
            MessageType::Data => {
                self.handle_data_packet(data, addr, header, decrypt_buf, tun_write_tx)
                    .await;
            }
            MessageType::Keepalive => {
                self.handle_keepalive(data, addr, header).await;
            }
            MessageType::Control => {
                self.handle_control(data, addr, header).await;
            }
            MessageType::Rekey => {
                self.handle_rekey(data, addr, header).await;
            }
            _ => {
                debug!(
                    "Unhandled message type {:?} from {}",
                    header.msg_type,
                    crate::privacy::addr(addr)
                );
            }
        }
    }

    /// Handle a `HandshakeFragment` packet (non-Linux fallback path).
    ///
    /// Same semantics as the Linux hot-path handler: parse the outer
    /// header + fragment body, charge the per-IP rate limiter only on
    /// `frag_index == 0`, feed the fragment to the reassembler, and
    /// re-enter `handle_handshake_init_prechecked` on completion so
    /// rate limiting is not double-charged.
    #[allow(dead_code)]
    async fn handle_handshake_fragment(&self, data: &[u8], addr: SocketAddr) {
        if data.len() < HEADER_SIZE {
            return;
        }
        let header = match PacketHeader::decode(data) {
            Ok(h) => h,
            Err(e) => {
                debug!(
                    "Invalid fragment header from {}: {}",
                    crate::privacy::addr(addr),
                    e
                );
                return;
            }
        };
        if header.msg_type != MessageType::HandshakeFragment {
            debug!(
                "Dropping non-fragment packet {:?} dispatched to fragment handler from {}",
                header.msg_type,
                crate::privacy::addr(addr)
            );
            return;
        }

        let fragment = match HandshakeFragment::from_bytes(&data[HEADER_SIZE..]) {
            Ok(f) => f,
            Err(e) => {
                debug!(
                    "Invalid handshake fragment from {}: {}",
                    crate::privacy::addr(addr),
                    e
                );
                return;
            }
        };

        // Rate limit on fragments that would create a NEW reassembly
        // entry, regardless of the fragment index. Using the `contains`
        // probe instead of `frag_index == 0` prevents an attacker who
        // deliberately sends only non-zero-index fragments from
        // bypassing the per-IP bucket (since out-of-order delivery is
        // allowed, a non-zero index CAN legitimately arrive first).
        // A legitimate multi-fragment handshake still spends exactly
        // one token because the token is charged only on the first
        // fragment of the attempt, whichever index that happens to be.
        let is_new_attempt = !self
            .fragment_reassembly
            .lock()
            .contains(addr, fragment.frag_id);
        if is_new_attempt && !self.rate_limiter.allow(addr.ip()) {
            debug!(
                "Rate limited handshake fragment from {}",
                crate::privacy::addr(addr)
            );
            return;
        }

        let completed = {
            let mut reasm = self.fragment_reassembly.lock();
            reasm.insert(addr, fragment)
        };
        let (inner_msg_type, reassembled) = match completed {
            Some(x) => x,
            None => return,
        };

        // Synthesise the full inner packet.
        let synth_header = PacketHeader::new(
            inner_msg_type,
            SessionId(0),
            hpn_core::types::KeyId::initial(),
            hpn_core::types::Counter::initial(),
        );
        let mut synth = vec![0u8; HEADER_SIZE + reassembled.len()];
        if let Err(e) = synth_header.encode(&mut synth[..HEADER_SIZE]) {
            error!(
                "Failed to encode synthesised handshake header for {}: {}",
                crate::privacy::addr(addr),
                e
            );
            return;
        }
        synth[HEADER_SIZE..].copy_from_slice(&reassembled);

        debug!(
            "Reassembled {:?} handshake ({} bytes) from {}",
            inner_msg_type,
            reassembled.len(),
            crate::privacy::addr(addr)
        );

        self.handle_handshake_init_prechecked(&synth, addr, inner_msg_type)
            .await;
    }

    /// Handle a handshake init message (used in non-Linux path).
    ///
    /// Supports both regular `HandshakeInit` and `EncryptedHandshakeInit` (identity hiding).
    ///
    /// Rate-limited entry point — callers that have already charged the
    /// limiter (e.g. the fragment reassembler) must invoke
    /// [`Self::handle_handshake_init_prechecked`] directly.
    #[allow(dead_code)]
    async fn handle_handshake_init(&self, data: &[u8], addr: SocketAddr, msg_type: MessageType) {
        // Rate limiting check - protect against handshake DoS
        if !self.rate_limiter.allow(addr.ip()) {
            warn!("Rate limited handshake from {}", crate::privacy::addr(addr));
            return;
        }

        self.handle_handshake_init_prechecked(data, addr, msg_type)
            .await;
    }

    /// Same as [`Self::handle_handshake_init`] but assumes the per-IP
    /// rate limiter has already been charged. Used by the fragment
    /// reassembly completion path.
    #[allow(dead_code)]
    async fn handle_handshake_init_prechecked(
        &self,
        data: &[u8],
        addr: SocketAddr,
        msg_type: MessageType,
    ) {
        if data.len() < HEADER_SIZE {
            return;
        }
        let payload = &data[HEADER_SIZE..];

        // Determine if this is encrypted or regular handshake init
        let (init, is_encrypted) = match msg_type {
            MessageType::EncryptedHandshakeInit => {
                // Parse the encrypted handshake init
                let encrypted_init = match EncryptedHandshakeInit::from_bytes(payload) {
                    Ok(e) => e,
                    Err(e) => {
                        debug!(
                            "Invalid encrypted handshake init from {}: {}",
                            crate::privacy::addr(addr),
                            e
                        );
                        return;
                    }
                };

                // Enforce min_security_level on the OUTER level BEFORE the
                // expensive ML-KEM decapsulation. This prevents CPU DoS from
                // attackers who would otherwise force us to decap a Level 5
                // ciphertext only to reject the inner level. The inner level
                // is re-checked below because a weaker inner init could still
                // be embedded inside a strong-outer envelope.
                if !self.security_level_accepted(encrypted_init.security_level) {
                    warn!(
                        "Rejecting encrypted handshake (outer) with security level {:?} below configured minimum from {}",
                        encrypted_init.security_level,
                        crate::privacy::addr(addr)
                    );
                    self.metrics.handshakes_failed.inc();
                    return;
                }

                // Get KEM keypair for this security level
                let kem_keypair = match self.kem_keypair_for_level(encrypted_init.security_level) {
                    Some(kp) => kp,
                    None => {
                        warn!(
                            "Identity hiding not supported for {:?} from {} (no KEM keypair configured)",
                            encrypted_init.security_level, addr
                        );
                        return;
                    }
                };

                // Decrypt the inner HandshakeInit
                let inner_init = match encrypted_init.decrypt(&kem_keypair.0) {
                    Ok(init) => init,
                    Err(e) => {
                        debug!(
                            "Failed to decrypt handshake init from {}: {}",
                            crate::privacy::addr(addr),
                            e
                        );
                        return;
                    }
                };

                debug!(
                    "Decrypted identity-hiding handshake from {} (level={:?})",
                    crate::privacy::addr(addr),
                    inner_init.security_level
                );
                (inner_init, true)
            }
            MessageType::HandshakeInit => {
                // Regular (non-encrypted) handshake init
                let init = match HandshakeInit::from_bytes(payload) {
                    Ok(i) => i,
                    Err(e) => {
                        debug!(
                            "Invalid handshake init from {}: {}",
                            crate::privacy::addr(addr),
                            e
                        );
                        return;
                    }
                };
                (init, false)
            }
            _ => {
                debug!(
                    "Unexpected message type {:?} in handshake handler",
                    msg_type
                );
                return;
            }
        };

        // Enforce minimum security level policy (prevents downgrade).
        if !self.security_level_accepted(init.security_level) {
            warn!(
                "Rejecting handshake with security level {:?} below configured minimum from {}",
                init.security_level,
                crate::privacy::addr(addr)
            );
            self.metrics.handshakes_failed.inc();
            return;
        }

        // Handshake-level anti-replay (see rationale at the other call site).
        if !self.handshake_replay.check_and_insert(&init.client_random) {
            debug!(
                "Dropping replayed HandshakeInit (duplicate client_random) from {}",
                crate::privacy::addr(addr)
            );
            self.metrics.handshakes_failed.inc();
            return;
        }

        // Validate credentials if authentication is required
        if let Some(ref user_store) = self.user_store {
            // Get the KEM keypair for decrypting credentials
            let kem_keypair = match self.kem_keypair_for_level(init.security_level) {
                Some(kp) => kp,
                None => {
                    warn!(
                        "Authentication requires identity hiding but no KEM keypair for {:?} from {}",
                        init.security_level,
                        crate::privacy::addr(addr)
                    );
                    return;
                }
            };

            // Check if credentials are provided
            let Some(ref encrypted_creds) = init.credentials else {
                warn!(
                    "Authentication required but no credentials provided from {}",
                    crate::privacy::addr(addr)
                );
                return;
            };

            // Decrypt and verify credentials
            let creds = match encrypted_creds.decrypt(&kem_keypair.0) {
                Ok(creds) => creds,
                Err(e) => {
                    warn!(
                        "Failed to decrypt credentials from {}: {}",
                        crate::privacy::addr(addr),
                        e
                    );
                    self.metrics.handshakes_failed.inc();
                    return;
                }
            };

            // Verify against user store with auth-lockout layer (see
            // `authenticate_credentials`). This site historically did not
            // increment `handshakes_failed` on auth errors — preserve
            // that behaviour for compatibility with the existing
            // metrics dashboard, but still let the lockout counters
            // record the event.
            if self
                .authenticate_credentials(user_store, &creds.username, &creds.password, addr)
                .await
                .is_err()
            {
                return;
            }
        }

        // Create server handshake handler with keypair matching client's security level
        let keypair = self.keypair_for_level(init.security_level);
        let mut handshake = ServerHandshake::new(keypair.clone());

        // Generate session ID
        let session_id = SessionId::generate();

        // Create tunnel config for client
        let dns_servers = self.config.parse_dns_servers().unwrap_or_default();
        let dns_servers_v6 = self.config.parse_dns_servers_v6().unwrap_or_default();
        let config = TunnelConfig {
            client_ipv4: [0, 0, 0, 0], // Will be filled after IP allocation
            netmask_ipv4: self.sessions.netmask(),
            gateway_ipv4: self.sessions.server_ip(),
            dns_ipv4: dns_servers,
            client_ipv6: None, // Will be filled after IP allocation if dual-stack
            prefix_len_ipv6: self.sessions.ipv6_prefix(),
            gateway_ipv6: self.sessions.server_ipv6(),
            dns_ipv6: dns_servers_v6,
            mtu: self.config.mtu,
        };

        // Process init and get response
        let (mut response, server_keys) = match handshake.process_init(&init, session_id, config) {
            Ok(r) => r,
            Err(e) => {
                error!(
                    "Handshake processing failed for {}: {}",
                    crate::privacy::addr(addr),
                    e
                );
                return;
            }
        };
        let response_send_key = server_keys.send_key;

        // Create session and allocate IP (dual-stack if configured)
        // Note: Never log key material, even partially
        let session = match Session::new(session_id, server_keys) {
            Ok(s) => s,
            Err(e) => {
                error!(
                    "Session key init failed for {}: {}",
                    crate::privacy::addr(addr),
                    e
                );
                return;
            }
        };
        let (tunnel_ip, tunnel_ipv6) = match self.sessions.create_session_dual_stack_with_level(
            session,
            addr,
            init.security_level,
        ) {
            Ok(ips) => ips,
            Err(e) => {
                error!(
                    "Session creation failed for {}: {}",
                    crate::privacy::addr(addr),
                    e
                );
                return;
            }
        };

        // Update response with allocated IPs
        response.config.client_ipv4 = tunnel_ip;
        response.config.client_ipv6 = tunnel_ipv6;

        if let Err(e) = hpn_core::protocol::handshake::refresh_handshake_response_auth(
            &mut response,
            &init.client_random,
            init.security_level,
            keypair.as_ref(),
            &response_send_key,
        ) {
            error!(
                "Failed to refresh handshake response authentication for {}: {}",
                crate::privacy::addr(addr),
                e
            );
            self.sessions.remove_session(session_id);
            self.metrics.handshakes_failed.inc();
            return;
        }

        // Send response — may be fragmented into multiple datagrams
        // when the payload exceeds `FRAGMENTATION_THRESHOLD`.
        if let Some(ref socket) = self.socket {
            let response_packets =
                match self.encode_handshake_response_as_packets(&response, session_id) {
                    Ok(packets) => packets,
                    Err(e) => {
                        error!(
                            "Failed to encode handshake response for {}: {}",
                            crate::privacy::addr(addr),
                            e
                        );
                        return;
                    }
                };
            let total_fragments = response_packets.len();
            debug!(
                "Sending handshake response to {} ({} packet{})",
                addr,
                total_fragments,
                if total_fragments == 1 { "" } else { "s" }
            );

            let mut sent_ok = true;
            let mut total_bytes = 0usize;
            for (i, packet) in response_packets.iter().enumerate() {
                match socket.send_to(packet, addr).await {
                    Ok(sent) => total_bytes += sent,
                    Err(e) => {
                        error!(
                            "Failed to send handshake response packet {}/{} to {}: {}",
                            i + 1,
                            total_fragments,
                            crate::privacy::addr(addr),
                            e
                        );
                        sent_ok = false;
                        break;
                    }
                }
            }
            if sent_ok {
                info!(
                    "Handshake{} complete for {}, session {} (sent {} bytes across {} packet{})",
                    if is_encrypted {
                        " (identity-hiding)"
                    } else {
                        ""
                    },
                    crate::privacy::addr(addr),
                    session_id,
                    total_bytes,
                    total_fragments,
                    if total_fragments == 1 { "" } else { "s" }
                );
            }
        } else {
            error!("No socket available to send handshake response");
        }
    }

    /// Encode a `HandshakeResponse` into one or more UDP datagrams.
    ///
    /// The Level 5 post-quantum `HandshakeResponse` can exceed ~9 KB,
    /// which is well above the 1500-byte Ethernet MTU. Rather than rely
    /// on IP-level fragmentation (which many commercial hosters drop),
    /// we split responses whose payload exceeds
    /// [`FRAGMENTATION_THRESHOLD`] into application-layer
    /// `HandshakeFragment` packets. The client reassembles them before
    /// feeding the bytes back into its handshake state machine. See
    /// [`hpn_core::protocol::fragment`] for the wire format.
    ///
    /// Returns a `Vec` of fully-formed packet byte vectors. The typical
    /// un-fragmented case returns a single element; a Level 5 response
    /// returns ~8 fragments.
    ///
    /// # Errors
    ///
    /// Returns `ServerError::Protocol` if header encoding fails, or if
    /// the response payload is too large to be fragmented (currently
    /// 32 × 1165 = ~37 KB, well above any legitimate handshake).
    fn encode_handshake_response_as_packets(
        &self,
        response: &hpn_core::protocol::HandshakeResponse,
        session_id: SessionId,
    ) -> Result<Vec<Vec<u8>>, ServerError> {
        // CRITICAL: Verify session IDs match (header vs payload)
        if response.session_id == session_id {
            debug!(
                "Session IDs match: header={} payload={}",
                session_id, response.session_id
            );
        } else {
            error!(
                "SESSION ID MISMATCH BUG: header={} payload={} - THIS IS THE BUG!",
                session_id, response.session_id
            );
        }

        let payload = response.to_bytes();

        // Small path: single datagram with the standard
        // `HandshakeResponse` outer header.
        if payload.len() <= FRAGMENTATION_THRESHOLD {
            let header = PacketHeader::new(
                MessageType::HandshakeResponse,
                session_id,
                hpn_core::types::KeyId::initial(),
                hpn_core::types::Counter::initial(),
            );
            let mut buf = vec![0u8; HEADER_SIZE + payload.len()];
            header.encode(&mut buf[..HEADER_SIZE])?;
            buf[HEADER_SIZE..].copy_from_slice(&payload);
            return Ok(vec![buf]);
        }

        // Fragmented path: build N `HandshakeFragment` packets. Each
        // carries a fresh outer `PacketHeader` with
        // `msg_type = HandshakeFragment`, `session_id = 0` (pre-session
        // convention — the client has not seen this session yet), and
        // the serialised fragment body.
        //
        // `frag_id` is random per response so a client that retries a
        // handshake (new attempt, new frag_id) does not collide with
        // any pending reassembly on its side.
        let frag_id: u32 = rand::random();
        let fragment_bodies =
            build_handshake_fragments(MessageType::HandshakeResponse, frag_id, &payload).map_err(
                |e| {
                    ServerError::Protocol(hpn_core::error::ProtocolError::InvalidData(format!(
                        "failed to fragment handshake response: {}",
                        e
                    )))
                },
            )?;

        debug!(
            "Fragmenting HandshakeResponse for session {}: {} bytes → {} fragments (frag_id={})",
            session_id,
            payload.len(),
            fragment_bodies.len(),
            frag_id
        );

        let mut packets = Vec::with_capacity(fragment_bodies.len());
        for body in fragment_bodies {
            let header = PacketHeader::new(
                MessageType::HandshakeFragment,
                SessionId(0),
                hpn_core::types::KeyId::initial(),
                hpn_core::types::Counter::initial(),
            );
            let mut buf = vec![0u8; HEADER_SIZE + body.len()];
            header.encode(&mut buf[..HEADER_SIZE])?;
            buf[HEADER_SIZE..].copy_from_slice(&body);
            packets.push(buf);
        }
        Ok(packets)
    }

    /// Handle a `HandshakeFragment` packet (Linux hot path).
    ///
    /// Parses the outer `PacketHeader` + fragment body, charges the
    /// per-IP rate limiter only on `frag_index == 0` (so a legitimate
    /// multi-fragment handshake spends exactly one token), inserts the
    /// fragment into the server-wide reassembly buffer, and on
    /// completion synthesises the original `HandshakeInit` /
    /// `EncryptedHandshakeInit` packet and re-enters the normal
    /// handshake flow via
    /// [`Self::handle_handshake_init_internal_prechecked`] — note the
    /// prechecked variant, to avoid double-charging the limiter.
    #[cfg(target_os = "linux")]
    async fn handle_handshake_fragment_internal(
        &self,
        data: &[u8],
        addr: SocketAddr,
        response_tx: &Sender<OutboundResponse>,
    ) {
        // Parse outer header. If the datagram is truncated or the header
        // is malformed we drop it silently — same policy as every other
        // control-plane entry point.
        if data.len() < HEADER_SIZE {
            self.metrics.record_invalid_packet();
            return;
        }
        let header = match PacketHeader::decode(data) {
            Ok(h) => h,
            Err(e) => {
                debug!(
                    "Invalid fragment header from {}: {}",
                    crate::privacy::addr(addr),
                    e
                );
                self.metrics.record_invalid_packet();
                return;
            }
        };
        if header.msg_type != MessageType::HandshakeFragment {
            debug!(
                "Dropping non-fragment packet {:?} dispatched to fragment handler from {}",
                header.msg_type,
                crate::privacy::addr(addr)
            );
            self.metrics.record_invalid_packet();
            return;
        }

        // Parse the fragment body.
        let fragment = match HandshakeFragment::from_bytes(&data[HEADER_SIZE..]) {
            Ok(f) => f,
            Err(e) => {
                debug!(
                    "Invalid handshake fragment from {}: {}",
                    crate::privacy::addr(addr),
                    e
                );
                self.metrics.record_invalid_packet();
                return;
            }
        };

        // Rate limit ONLY on the first fragment of a given handshake
        // attempt. The `frag_index == 0` check is the simplest reliable
        // signal: the limiter is charged on the fragment that creates a
        // NEW reassembly entry for this (addr, frag_id). We probe the
        // reassembler with `contains` instead of `frag_index == 0` so
        // an attacker who sends only non-zero-index fragments cannot
        // bypass the per-IP bucket (reassembly accepts any arrival
        // order, so index != 0 can legitimately be the first
        // fragment of an attempt). A legitimate multi-fragment
        // handshake still spends exactly one token because every
        // subsequent fragment hits the existing entry.
        let is_new_attempt = !self
            .fragment_reassembly
            .lock()
            .contains(addr, fragment.frag_id);
        if is_new_attempt && !self.rate_limiter.allow(addr.ip()) {
            debug!(
                "Rate limited handshake fragment from {}",
                crate::privacy::addr(addr)
            );
            self.metrics.record_rate_limited();
            // No handshakes_failed bump: we haven't actually attempted
            // to parse a handshake yet. The limiter rejection alone is
            // the signal.
            return;
        }

        // Insert into the reassembly buffer. On completion we get the
        // inner message type and the reassembled payload.
        let completed = {
            let mut reasm = self.fragment_reassembly.lock();
            reasm.insert(addr, fragment)
        };

        let (inner_msg_type, reassembled) = match completed {
            Some(x) => x,
            None => return, // more fragments pending (or dropped by reassembler)
        };

        // Synthesise a full `HandshakeInit` / `EncryptedHandshakeInit`
        // packet: fresh outer `PacketHeader` with the inner message
        // type, and the reassembled payload appended. Re-enter the
        // handler via the prechecked entry point — rate limiting was
        // already charged on the first fragment.
        let synth_header = PacketHeader::new(
            inner_msg_type,
            SessionId(0),
            hpn_core::types::KeyId::initial(),
            hpn_core::types::Counter::initial(),
        );
        let mut synth = vec![0u8; HEADER_SIZE + reassembled.len()];
        if let Err(e) = synth_header.encode(&mut synth[..HEADER_SIZE]) {
            // Should not happen — `encode` only fails on short buffers.
            error!(
                "Failed to encode synthesised handshake header for {}: {}",
                crate::privacy::addr(addr),
                e
            );
            self.metrics.handshakes_failed.inc();
            return;
        }
        synth[HEADER_SIZE..].copy_from_slice(&reassembled);

        debug!(
            "Reassembled {:?} handshake ({} bytes) from {}",
            inner_msg_type,
            reassembled.len(),
            crate::privacy::addr(addr)
        );

        self.handle_handshake_init_internal_prechecked(&synth, addr, response_tx)
            .await;
    }

    /// Handle handshake init with explicit socket (for high-performance path).
    ///
    /// Supports both regular `HandshakeInit` and `EncryptedHandshakeInit` (identity hiding).
    ///
    /// This is the rate-limited entry point. Callers that have already
    /// enforced rate limiting (e.g. the handshake-fragment reassembler)
    /// must use [`Self::handle_handshake_init_internal_prechecked`]
    /// instead, so a legitimate multi-fragment handshake is not
    /// double-charged against the per-IP bucket.
    #[cfg(target_os = "linux")]
    async fn handle_handshake_init_internal(
        &self,
        data: &[u8],
        addr: SocketAddr,
        response_tx: &Sender<OutboundResponse>,
    ) {
        // Rate limiting check - protect against handshake DoS. The
        // `handshakes_total` counter is incremented inside
        // `handle_handshake_init_internal_prechecked` so rate-limited
        // attempts are NOT counted as "parsed" — only `handshakes_failed`
        // below is bumped for them, matching the previous semantics.
        if !self.rate_limiter.allow(addr.ip()) {
            warn!("Rate limited handshake from {}", crate::privacy::addr(addr));
            self.metrics.record_rate_limited();
            self.metrics.handshakes_failed.inc();
            return;
        }

        self.handle_handshake_init_internal_prechecked(data, addr, response_tx)
            .await;
    }

    /// Same as [`Self::handle_handshake_init_internal`] but assumes the
    /// per-IP rate limiter has already been charged for this handshake
    /// attempt.
    ///
    /// Used on the fragment-reassembly completion path: the rate
    /// limiter was charged once when the first fragment arrived, so
    /// when the synthesised `HandshakeInit` / `EncryptedHandshakeInit`
    /// re-enters the handler we must not charge it again.
    ///
    /// `self.metrics.handshakes_total` is incremented here (not in the
    /// rate-limited wrapper) so the counter always reflects "a
    /// handshake attempt actually reached parsing", regardless of which
    /// entry point was used.
    #[cfg(target_os = "linux")]
    async fn handle_handshake_init_internal_prechecked(
        &self,
        data: &[u8],
        addr: SocketAddr,
        response_tx: &Sender<OutboundResponse>,
    ) {
        self.metrics.handshakes_total.inc();

        if data.len() < HEADER_SIZE {
            self.metrics.record_invalid_packet();
            self.metrics.handshakes_failed.inc();
            return;
        }

        // Parse header to determine message type
        let header = match PacketHeader::decode(data) {
            Ok(h) => h,
            Err(e) => {
                debug!("Invalid header from {}: {}", crate::privacy::addr(addr), e);
                self.metrics.record_invalid_packet();
                self.metrics.handshakes_failed.inc();
                return;
            }
        };

        let payload = &data[HEADER_SIZE..];

        // Determine if this is encrypted or regular handshake init
        let (init, is_encrypted) = match header.msg_type {
            MessageType::EncryptedHandshakeInit => {
                // Parse the encrypted handshake init
                let encrypted_init = match EncryptedHandshakeInit::from_bytes(payload) {
                    Ok(e) => e,
                    Err(e) => {
                        debug!(
                            "Invalid encrypted handshake init from {}: {}",
                            crate::privacy::addr(addr),
                            e
                        );
                        self.metrics.record_invalid_packet();
                        self.metrics.handshakes_failed.inc();
                        return;
                    }
                };

                // Enforce min_security_level on the OUTER level BEFORE the
                // expensive ML-KEM decapsulation (DoS mitigation).
                if !self.security_level_accepted(encrypted_init.security_level) {
                    warn!(
                        "Rejecting encrypted handshake (outer) with security level {:?} below configured minimum from {}",
                        encrypted_init.security_level,
                        crate::privacy::addr(addr)
                    );
                    self.metrics.handshakes_failed.inc();
                    return;
                }

                // Get KEM keypair for this security level
                let kem_keypair = match self.kem_keypair_for_level(encrypted_init.security_level) {
                    Some(kp) => kp,
                    None => {
                        warn!(
                            "Identity hiding not supported for {:?} from {} (no KEM keypair configured)",
                            encrypted_init.security_level, addr
                        );
                        self.metrics.handshakes_failed.inc();
                        return;
                    }
                };

                // Decrypt the inner HandshakeInit
                let inner_init = match encrypted_init.decrypt(&kem_keypair.0) {
                    Ok(init) => init,
                    Err(e) => {
                        debug!(
                            "Failed to decrypt handshake init from {}: {}",
                            crate::privacy::addr(addr),
                            e
                        );
                        self.metrics.record_invalid_packet();
                        self.metrics.handshakes_failed.inc();
                        return;
                    }
                };

                debug!(
                    "Decrypted identity-hiding handshake from {} (level={:?})",
                    crate::privacy::addr(addr),
                    inner_init.security_level
                );
                (inner_init, true)
            }
            MessageType::HandshakeInit => {
                // Regular (non-encrypted) handshake init
                let init = match HandshakeInit::from_bytes(payload) {
                    Ok(i) => i,
                    Err(e) => {
                        debug!(
                            "Invalid handshake init from {}: {}",
                            crate::privacy::addr(addr),
                            e
                        );
                        self.metrics.record_invalid_packet();
                        self.metrics.handshakes_failed.inc();
                        return;
                    }
                };
                (init, false)
            }
            _ => {
                debug!(
                    "Unexpected message type {:?} in handshake handler",
                    header.msg_type
                );
                self.metrics.record_invalid_packet();
                self.metrics.handshakes_failed.inc();
                return;
            }
        };

        // Enforce minimum security level policy (prevents downgrade).
        if !self.security_level_accepted(init.security_level) {
            warn!(
                "Rejecting handshake with security level {:?} below configured minimum from {}",
                init.security_level,
                crate::privacy::addr(addr)
            );
            self.metrics.handshakes_failed.inc();
            return;
        }

        // Handshake-level anti-replay (production Linux UDP-workers path).
        // Cheap hash-set lookup before credential decryption and ML-DSA
        // signing. See the identical block in the AFXDP handler for the
        // full rationale.
        if !self.handshake_replay.check_and_insert(&init.client_random) {
            debug!(
                "Dropping replayed HandshakeInit (duplicate client_random) from {}",
                crate::privacy::addr(addr)
            );
            self.metrics.handshakes_failed.inc();
            return;
        }

        // Validate credentials if authentication is required
        if let Some(ref user_store) = self.user_store {
            // Get the KEM keypair for decrypting credentials
            let kem_keypair = match self.kem_keypair_for_level(init.security_level) {
                Some(kp) => kp,
                None => {
                    warn!(
                        "Authentication requires identity hiding but no KEM keypair for {:?} from {}",
                        init.security_level,
                        crate::privacy::addr(addr)
                    );
                    self.metrics.handshakes_failed.inc();
                    return;
                }
            };

            // Check if credentials are provided
            let Some(ref encrypted_creds) = init.credentials else {
                warn!(
                    "Authentication required but no credentials provided from {}",
                    crate::privacy::addr(addr)
                );
                self.metrics.handshakes_failed.inc();
                return;
            };

            // Decrypt and verify credentials
            let creds = match encrypted_creds.decrypt(&kem_keypair.0) {
                Ok(creds) => creds,
                Err(e) => {
                    warn!(
                        "Failed to decrypt credentials from {}: {}",
                        crate::privacy::addr(addr),
                        e
                    );
                    self.metrics.handshakes_failed.inc();
                    return;
                }
            };

            // Verify against user store with auth-lockout layer (see
            // `authenticate_credentials` for the policy details).
            if self
                .authenticate_credentials(user_store, &creds.username, &creds.password, addr)
                .await
                .is_err()
            {
                self.metrics.handshakes_failed.inc();
                return;
            }
        }

        // Create handshake handler with keypair matching client's security level
        let keypair = self.keypair_for_level(init.security_level);
        let mut handshake = ServerHandshake::new(keypair.clone());
        let session_id = SessionId::generate();

        let dns_servers = self.config.parse_dns_servers().unwrap_or_default();
        let dns_servers_v6 = self.config.parse_dns_servers_v6().unwrap_or_default();
        let config = TunnelConfig {
            client_ipv4: [0, 0, 0, 0],
            netmask_ipv4: self.sessions.netmask(),
            gateway_ipv4: self.sessions.server_ip(),
            dns_ipv4: dns_servers,
            client_ipv6: None,
            prefix_len_ipv6: self.sessions.ipv6_prefix(),
            gateway_ipv6: self.sessions.server_ipv6(),
            dns_ipv6: dns_servers_v6,
            mtu: self.config.mtu,
        };

        let (mut response, server_keys) = match handshake.process_init(&init, session_id, config) {
            Ok(r) => r,
            Err(e) => {
                error!(
                    "Handshake processing failed for {}: {}",
                    crate::privacy::addr(addr),
                    e
                );
                self.metrics.handshakes_failed.inc();
                return;
            }
        };
        let response_send_key = server_keys.send_key;

        // Note: Never log key material, even partially
        let session = match Session::new(session_id, server_keys) {
            Ok(s) => s,
            Err(e) => {
                error!(
                    "Session key init failed for {}: {}",
                    crate::privacy::addr(addr),
                    e
                );
                self.metrics.handshakes_failed.inc();
                return;
            }
        };
        let (tunnel_ip, tunnel_ipv6) = match self.sessions.create_session_dual_stack_with_level(
            session,
            addr,
            init.security_level,
        ) {
            Ok(ips) => ips,
            Err(e) => {
                error!(
                    "Session creation failed for {}: {}",
                    crate::privacy::addr(addr),
                    e
                );
                self.metrics.handshakes_failed.inc();
                return;
            }
        };

        // Success metrics; sessions_active is maintained via the manager
        // lifecycle callback.
        self.metrics.handshakes_success.inc();
        self.metrics.sessions_total.inc();

        response.config.client_ipv4 = tunnel_ip;
        response.config.client_ipv6 = tunnel_ipv6;

        if let Err(e) = hpn_core::protocol::handshake::refresh_handshake_response_auth(
            &mut response,
            &init.client_random,
            init.security_level,
            keypair.as_ref(),
            &response_send_key,
        ) {
            error!(
                "Failed to refresh handshake response authentication for {}: {}",
                crate::privacy::addr(addr),
                e
            );
            self.sessions.remove_session(session_id);
            self.metrics.handshakes_failed.inc();
            return;
        }

        let response_packets =
            match self.encode_handshake_response_as_packets(&response, session_id) {
                Ok(packets) => packets,
                Err(e) => {
                    error!(
                        "Failed to encode handshake response for {}: {}",
                        crate::privacy::addr(addr),
                        e
                    );
                    return;
                }
            };
        let total_fragments = response_packets.len();

        // Bytes::from(vec) reuses the allocation without copying.
        // Queue every packet — the sender worker drains `response_rx`
        // and sends them with sendmmsg in order.
        let mut queued = 0usize;
        for packet in response_packets {
            match response_tx.try_send(OutboundResponse {
                addr,
                data: Bytes::from(packet),
            }) {
                Ok(()) => queued += 1,
                Err(e) => {
                    error!(
                        "Failed to queue handshake response packet {}/{} to {}: {}",
                        queued + 1,
                        total_fragments,
                        crate::privacy::addr(addr),
                        e
                    );
                    break;
                }
            }
        }

        if queued == total_fragments {
            info!(
                "Handshake{} complete for {}, session {} ({} packet{})",
                if is_encrypted {
                    " (identity-hiding)"
                } else {
                    ""
                },
                crate::privacy::addr(addr),
                session_id,
                total_fragments,
                if total_fragments == 1 { "" } else { "s" }
            );
        } else {
            // Partial transmission of a fragmented response is fatal
            // for the client's reassembly, so tear down the session
            // we just created to keep the server's session accounting
            // consistent with the client's observable state.
            self.sessions.remove_session(session_id);
            self.metrics.handshakes_failed.inc();
        }
    }

    /// Handle keepalive with explicit socket (for high-performance path).
    #[cfg(target_os = "linux")]
    async fn handle_keepalive_internal(
        &self,
        session_id: SessionId,
        data: &[u8],
        addr: SocketAddr,
        response_tx: &Sender<OutboundResponse>,
    ) {
        // No `mut` needed: FIX-010 removed the rebind branch that used to
        // reassign `session_guard` after dropping it for `update_client_addr`.
        let session_guard = match self.sessions.get_session_mut(session_id) {
            Some(s) => s,
            None => return,
        };

        // Defer roaming update until after AEAD authentication succeeds.
        let addr_changed = *session_guard.client_addr.lock() != addr;

        let mut decrypt_buf = vec![0u8; data.len()];
        let (_, len) = match session_guard.session.decrypt_packet(data, &mut decrypt_buf) {
            Ok(r) => r,
            Err(_) => return,
        };

        let keepalive = match hpn_core::protocol::KeepaliveMessage::from_bytes(&decrypt_buf[..len])
        {
            Ok(k) => k,
            Err(_) => return,
        };

        // FIX-010: same invariant as AF_XDP / data paths — refuse the
        // post-AEAD silent rebind. Drop the keepalive and let the client
        // re-issue a `ControlType::Rebind` if they really roamed.
        //
        // Check BEFORE `touch()` so a spoofed-IP replay of a fresh
        // keepalive cannot keep the legitimate session alive past its
        // inactivity timeout. See the matching comment in
        // `handle_keepalive_afxdp`.
        if addr_changed {
            debug!(
                "Address mismatch on Linux keepalive for session {} — dropping (FIX-010)",
                session_id
            );
            self.metrics.record_address_mismatch_drop();
            return;
        }

        session_guard.touch();

        let server_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let reply = hpn_core::protocol::KeepaliveReplyMessage {
            sequence: keepalive.sequence,
            server_timestamp,
        };

        let payload = reply.to_bytes();
        let mut output = vec![0u8; HEADER_SIZE + payload.len() + aead::TAG_SIZE + 32];
        let len = match session_guard.session.encrypt_packet(
            MessageType::KeepaliveReply,
            &payload,
            &mut output,
        ) {
            Ok(l) => l,
            Err(_) => return,
        };

        let client_addr = *session_guard.client_addr.lock();
        drop(session_guard);

        let _ = response_tx.try_send(OutboundResponse {
            addr: client_addr,
            data: Bytes::copy_from_slice(&output[..len]),
        });
    }

    /// Handle control message with explicit socket (for high-performance path).
    #[cfg(target_os = "linux")]
    async fn handle_control_internal(
        &self,
        session_id: SessionId,
        data: &[u8],
        addr: SocketAddr,
        response_tx: &Sender<OutboundResponse>,
    ) {
        use hpn_core::protocol::ControlMessage;
        use hpn_core::types::ControlType;

        let session_guard = match self.sessions.get_session_mut(session_id) {
            Some(s) => s,
            None => return,
        };

        let mut decrypt_buf = vec![0u8; data.len()];
        let (_, len) = match session_guard.session.decrypt_packet(data, &mut decrypt_buf) {
            Ok(r) => r,
            Err(_) => return,
        };

        let control = match ControlMessage::from_bytes(&decrypt_buf[..len]) {
            Ok(c) => c,
            Err(_) => return,
        };

        session_guard.touch();

        match control.control_type {
            ControlType::Close => {
                info!("Client {} requested disconnect", session_id);
                drop(session_guard);
                self.sessions.remove_session(session_id);
            }
            ControlType::Rebind => {
                drop(session_guard);
                self.sessions.update_client_addr(session_id, addr);
                self.send_rebind_ack_internal(session_id, response_tx).await;
            }
            _ => {}
        }
    }

    /// Handle rekey with explicit socket (for high-performance path).
    #[cfg(target_os = "linux")]
    async fn handle_rekey_internal(
        &self,
        session_id: SessionId,
        data: &[u8],
        addr: SocketAddr,
        response_tx: &Sender<OutboundResponse>,
    ) {
        use hpn_core::protocol::RekeyMessage;

        let mut session_guard = match self.sessions.get_session_mut(session_id) {
            Some(s) => s,
            None => return,
        };

        // Defer roaming update until after AEAD authentication succeeds.
        let addr_changed = *session_guard.client_addr.lock() != addr;

        let mut decrypt_buf = vec![0u8; data.len()];
        let (_, len) = match session_guard.session.decrypt_packet(data, &mut decrypt_buf) {
            Ok(r) => r,
            Err(_) => return,
        };

        let rekey_msg = match RekeyMessage::from_bytes(&decrypt_buf[..len]) {
            Ok(r) => r,
            Err(_) => return,
        };

        // FIX-010: refuse to rebind on a Rekey packet. Same rationale as
        // the keepalive path above — only `ControlType::Rebind` may rebind.
        if addr_changed {
            debug!(
                "Address mismatch on Linux rekey for session {} — dropping (FIX-010)",
                session_id
            );
            self.metrics.record_address_mismatch_drop();
            return;
        }

        if rekey_msg.client_ephemeral_pk.security_level != session_guard.security_level {
            warn!(
                "Rejected rekey with mismatched security level for session {}: established={:?}, requested={:?}",
                session_id,
                session_guard.security_level,
                rekey_msg.client_ephemeral_pk.security_level
            );
            return;
        }

        info!("Rekey request from session {}", session_id);

        // Use keypair matching client's security level
        let keypair = self.keypair_for_level(rekey_msg.client_ephemeral_pk.security_level);
        let rekey_handler = ServerHandshake::new(keypair);
        let current_key_id = session_guard.session.key_id();

        let (response, new_keys) =
            match rekey_handler.process_rekey(&rekey_msg, current_key_id, session_id) {
                Ok(r) => r,
                Err(e) => {
                    error!("Rekey processing failed for session {}: {}", session_id, e);
                    return;
                }
            };

        let payload = response.to_bytes();
        let mut output = vec![0u8; HEADER_SIZE + payload.len() + aead::TAG_SIZE + 32];
        let len = match session_guard.session.encrypt_packet(
            MessageType::RekeyResponse,
            &payload,
            &mut output,
        ) {
            Ok(l) => l,
            Err(_) => return,
        };

        if let Err(e) = session_guard.session.update_keys(new_keys) {
            error!("Rekey failed — invalid key material: {}", e);
            return;
        }
        session_guard.touch();
        let client_addr = *session_guard.client_addr.lock();
        drop(session_guard);

        match response_tx.try_send(OutboundResponse {
            addr: client_addr,
            data: Bytes::copy_from_slice(&output[..len]),
        }) {
            Ok(()) => {
                info!(
                    "Rekey complete for session {}, new key_id={}",
                    session_id, response.new_key_id
                );
            }
            Err(e) => {
                warn!(
                    "Failed to queue rekey response to {}: {}",
                    crate::privacy::addr(client_addr),
                    e
                );
            }
        }
    }

    /// Send rebind ack with explicit socket (for high-performance path).
    #[cfg(target_os = "linux")]
    async fn send_rebind_ack_internal(
        &self,
        session_id: SessionId,
        response_tx: &Sender<OutboundResponse>,
    ) {
        use hpn_core::protocol::ControlMessage;

        // Use read lock - encrypt_packet is thread-safe with atomic counters
        let session_guard = match self.sessions.get_session(session_id) {
            Some(s) => s,
            None => return,
        };

        let client_addr = *session_guard.client_addr.lock();
        let security_level = session_guard.security_level;
        // Drop before signing — see send_rebind_ack_afxdp for rationale.
        drop(session_guard);

        // Audit H11: ML-DSA-signed `RebindAck` (defence in depth against
        // session-key-only attackers who try to redirect the client to
        // an attacker-controlled endpoint).
        let keypair = self.keypair_for_level(security_level);
        // Audit H11-F4: signing failure is a genuine security regression
        // (the H11 mitigation is silently downgraded). ML-DSA is
        // deterministic on supported targets, so this branch is
        // unreachable in practice — but logging at `error!` ensures any
        // future signing-error condition surfaces in alert pipelines
        // instead of being lost in `warn!` noise.
        let ack = match SignedRebindAckPayload::sign(&keypair, session_id, client_addr) {
            Ok(signed) => ControlMessage::rebind_ack_signed(signed),
            Err(e) => {
                error!(
                    "Failed to sign rebind ack for session {}: {} — falling back to unsigned (audit H11 mitigation downgraded)",
                    session_id, e
                );
                ControlMessage {
                    control_type: hpn_core::types::ControlType::RebindAck,
                    error_code: None,
                    message: None,
                    signed_payload: None,
                }
            }
        };

        let session_guard = match self.sessions.get_session(session_id) {
            Some(s) => s,
            None => return,
        };

        let payload = ack.to_bytes();
        let mut output = vec![0u8; HEADER_SIZE + payload.len() + aead::TAG_SIZE + 32];
        let len =
            match session_guard
                .session
                .encrypt_packet(MessageType::Control, &payload, &mut output)
            {
                Ok(l) => l,
                Err(_) => return,
            };

        // Audit H11 follow-up (FIX-004): close the read-vs-sign TOCTOU —
        // see `send_rebind_ack_afxdp` for the rationale.
        let current_addr = *session_guard.client_addr.lock();
        drop(session_guard);
        if current_addr != client_addr {
            warn!(
                "Dropping signed rebind ack for session {}: client_addr drifted from {} to {} between sign and send",
                session_id,
                crate::privacy::addr(client_addr),
                crate::privacy::addr(current_addr)
            );
            return;
        }

        let _ = response_tx.try_send(OutboundResponse {
            addr: client_addr,
            data: Bytes::copy_from_slice(&output[..len]),
        });
    }

    /// Handle a data packet (used in non-Linux path).
    #[allow(dead_code)]
    async fn handle_data_packet(
        &self,
        data: &[u8],
        addr: SocketAddr,
        header: PacketHeader,
        decrypt_buf: &mut [u8],
        tun_write_tx: &Arc<Sender<Vec<u8>>>,
    ) {
        // Find session
        let session_id = header.session_id;

        let session_guard = match self.sessions.get_session_mut(session_id) {
            Some(s) => s,
            None => {
                debug!(
                    "Unknown session {} from {}",
                    session_id,
                    crate::privacy::addr(addr)
                );
                return;
            }
        };

        // Note: roaming update is performed AFTER successful decryption to prevent
        // pre-authentication session hijacking via spoofed source addresses.
        let addr_changed = *session_guard.client_addr.lock() != addr;

        // Decrypt packet FIRST (authenticates the sender via AEAD tag).
        let (_, len) = match session_guard.session.decrypt_packet(data, decrypt_buf) {
            Ok(r) => r,
            Err(e) => {
                debug!("Decryption failed for session {}: {}", session_id, e);
                return;
            }
        };

        // FIX-010: refuse the post-AEAD silent rebind on the non-Linux
        // data path too. Roaming has to go through ControlType::Rebind.
        //
        // Check BEFORE updating activity timestamp / byte counters so a
        // spoofed-IP replay can't extend the session's idle timeout or
        // inflate its byte-counter metrics.
        if addr_changed {
            debug!(
                "Address mismatch on non-Linux data path for session {} — dropping (FIX-010)",
                session_id
            );
            self.metrics.record_address_mismatch_drop();
            return;
        }

        session_guard.touch();
        session_guard.add_bytes_received(data.len() as u64);
        drop(session_guard);

        // Send to TUN device via lock-free crossbeam channel
        if let Err(e) = tun_write_tx.try_send(decrypt_buf[..len].to_vec()) {
            warn!("TUN write channel send failed: {}", e);
        }
    }

    /// Handle a keepalive packet (used in non-Linux path).
    #[allow(dead_code)]
    async fn handle_keepalive(&self, data: &[u8], addr: SocketAddr, header: PacketHeader) {
        let session_id = header.session_id;

        // Get session
        let session_guard = match self.sessions.get_session_mut(session_id) {
            Some(s) => s,
            None => {
                debug!(
                    "Keepalive from unknown session {} ({})",
                    session_id,
                    crate::privacy::addr(addr)
                );
                return;
            }
        };

        // Note: roaming update is deferred until AFTER successful decryption to prevent
        // pre-authentication session hijacking via spoofed source addresses.
        let old_addr = *session_guard.client_addr.lock();
        let addr_changed = old_addr != addr;

        // Decrypt keepalive payload FIRST (authenticates via AEAD tag).
        let mut decrypt_buf = vec![0u8; data.len()];
        let (_, len) = match session_guard.session.decrypt_packet(data, &mut decrypt_buf) {
            Ok(r) => r,
            Err(e) => {
                debug!(
                    "Failed to decrypt keepalive from session {}: {}",
                    session_id, e
                );
                return;
            }
        };

        // FIX-010: refuse the post-AEAD silent rebind on the non-Linux
        // keepalive path. Same rationale as the other data/keepalive sites
        // — only ControlType::Rebind may rebind.
        if addr_changed {
            debug!(
                "Address mismatch on non-Linux keepalive for session {} ({} vs {}) — dropping (FIX-010)",
                session_id,
                crate::privacy::addr(old_addr),
                crate::privacy::addr(addr)
            );
            self.metrics.record_address_mismatch_drop();
            return;
        }

        // Parse keepalive message
        let keepalive = match hpn_core::protocol::KeepaliveMessage::from_bytes(&decrypt_buf[..len])
        {
            Ok(k) => k,
            Err(e) => {
                debug!(
                    "Invalid keepalive message from session {}: {}",
                    session_id, e
                );
                return;
            }
        };

        session_guard.touch();
        trace!(
            "Keepalive from session {} seq={}",
            session_id, keepalive.sequence
        );

        // Create keepalive reply with server timestamp
        let server_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let reply = hpn_core::protocol::KeepaliveReplyMessage {
            sequence: keepalive.sequence,
            server_timestamp,
        };

        // Encrypt and send reply
        let payload = reply.to_bytes();
        let mut output = vec![0u8; HEADER_SIZE + payload.len() + aead::TAG_SIZE + 32];
        let len = match session_guard.session.encrypt_packet(
            MessageType::KeepaliveReply,
            &payload,
            &mut output,
        ) {
            Ok(l) => l,
            Err(e) => {
                debug!(
                    "Failed to encrypt keepalive reply for session {}: {}",
                    session_id, e
                );
                return;
            }
        };

        let client_addr = *session_guard.client_addr.lock();
        drop(session_guard);

        // Send reply
        if let Some(ref socket) = self.socket {
            if let Err(e) = socket.send_to(&output[..len], client_addr).await {
                warn!(
                    "Failed to send keepalive reply to {}: {}",
                    crate::privacy::addr(client_addr),
                    e
                );
            } else {
                trace!(
                    "Sent keepalive reply to session {} seq={}",
                    session_id, keepalive.sequence
                );
            }
        }
    }

    /// Handle a control packet (used in non-Linux path).
    #[allow(dead_code)]
    async fn handle_control(&self, data: &[u8], addr: SocketAddr, header: PacketHeader) {
        use hpn_core::protocol::ControlMessage;
        use hpn_core::types::ControlType;

        let session_id = header.session_id;

        // Get session and decrypt control payload
        let session_guard = match self.sessions.get_session_mut(session_id) {
            Some(s) => s,
            None => {
                debug!(
                    "Control from unknown session {} ({})",
                    session_id,
                    crate::privacy::addr(addr)
                );
                return;
            }
        };

        // Decrypt control message
        let mut decrypt_buf = vec![0u8; data.len()];
        let (_, len) = match session_guard.session.decrypt_packet(data, &mut decrypt_buf) {
            Ok(r) => r,
            Err(e) => {
                debug!(
                    "Failed to decrypt control from session {}: {}",
                    session_id, e
                );
                return;
            }
        };

        // Parse control message
        let control = match ControlMessage::from_bytes(&decrypt_buf[..len]) {
            Ok(c) => c,
            Err(e) => {
                debug!("Invalid control message from session {}: {}", session_id, e);
                return;
            }
        };

        session_guard.touch();

        debug!(
            "Control message from session {}: type={:?}, message={:?}",
            session_id, control.control_type, control.message
        );

        match control.control_type {
            ControlType::Close => {
                info!("Client {} requested disconnect", session_id);
                drop(session_guard);
                self.sessions.remove_session(session_id);
            }
            ControlType::Rebind => {
                // Client is notifying us of their new public endpoint
                if let Some(ref new_endpoint_str) = control.message {
                    if let Ok(new_endpoint) = new_endpoint_str.parse::<SocketAddr>() {
                        let old_addr = *session_guard.client_addr.lock();
                        drop(session_guard);

                        info!(
                            "Rebind request from session {}: {} -> {}",
                            session_id,
                            crate::privacy::addr(old_addr),
                            new_endpoint
                        );

                        // Update client address
                        self.sessions.update_client_addr(session_id, addr);

                        // Send acknowledgment
                        self.send_rebind_ack(session_id).await;
                    } else {
                        warn!(
                            "Invalid endpoint in rebind request from session {}: {}",
                            session_id, new_endpoint_str
                        );
                    }
                } else {
                    // No specific endpoint, just update to sender's address
                    let old_addr = *session_guard.client_addr.lock();
                    if old_addr != addr {
                        drop(session_guard);
                        info!(
                            "Rebind request from session {} (implicit): {} -> {}",
                            session_id,
                            crate::privacy::addr(old_addr),
                            addr
                        );
                        self.sessions.update_client_addr(session_id, addr);
                        self.send_rebind_ack(session_id).await;
                    }
                }
            }
            ControlType::Error => {
                warn!(
                    "Error from client session {}: code={:?}, msg={:?}",
                    session_id, control.error_code, control.message
                );
            }
            ControlType::Config => {
                debug!(
                    "Config request from session {}: {:?}",
                    session_id, control.message
                );
                // Future: handle config updates
            }
            ControlType::RebindAck => {
                // Client acknowledging our rebind request (unusual for server)
                debug!("Rebind ack from session {}", session_id);
            }
        }
    }

    /// Send a rebind acknowledgment to a client (used in non-Linux path).
    #[allow(dead_code)]
    async fn send_rebind_ack(&self, session_id: SessionId) {
        use hpn_core::protocol::ControlMessage;

        // Use read lock - encrypt_packet is thread-safe with atomic counters
        let session_guard = match self.sessions.get_session(session_id) {
            Some(s) => s,
            None => return,
        };

        let client_addr = *session_guard.client_addr.lock();
        let security_level = session_guard.security_level;
        // Drop before signing — see send_rebind_ack_afxdp for rationale.
        drop(session_guard);

        // Audit H11: ML-DSA-signed `RebindAck`.
        let keypair = self.keypair_for_level(security_level);
        // Audit H11-F4: signing failure is a genuine security regression
        // (the H11 mitigation is silently downgraded). ML-DSA is
        // deterministic on supported targets, so this branch is
        // unreachable in practice — but logging at `error!` ensures any
        // future signing-error condition surfaces in alert pipelines
        // instead of being lost in `warn!` noise.
        let ack = match SignedRebindAckPayload::sign(&keypair, session_id, client_addr) {
            Ok(signed) => ControlMessage::rebind_ack_signed(signed),
            Err(e) => {
                error!(
                    "Failed to sign rebind ack for session {}: {} — falling back to unsigned (audit H11 mitigation downgraded)",
                    session_id, e
                );
                ControlMessage {
                    control_type: hpn_core::types::ControlType::RebindAck,
                    error_code: None,
                    message: None,
                    signed_payload: None,
                }
            }
        };

        let session_guard = match self.sessions.get_session(session_id) {
            Some(s) => s,
            None => return,
        };

        let payload = ack.to_bytes();
        let mut output = vec![0u8; HEADER_SIZE + payload.len() + aead::TAG_SIZE + 32];
        let len =
            match session_guard
                .session
                .encrypt_packet(MessageType::Control, &payload, &mut output)
            {
                Ok(l) => l,
                Err(e) => {
                    debug!(
                        "Failed to encrypt rebind ack for session {}: {}",
                        session_id, e
                    );
                    return;
                }
            };

        // Audit H11 follow-up (FIX-004): close the read-vs-sign TOCTOU.
        // See `send_rebind_ack_afxdp` for the rationale — sending a
        // signature certifying address A to a different address B would
        // be rejected client-side anyway and just consumes a UDP packet.
        let current_addr = *session_guard.client_addr.lock();
        drop(session_guard);
        if current_addr != client_addr {
            warn!(
                "Dropping signed rebind ack for session {}: client_addr drifted from {} to {} between sign and send",
                session_id,
                crate::privacy::addr(client_addr),
                crate::privacy::addr(current_addr)
            );
            return;
        }

        if let Some(ref socket) = self.socket {
            if let Err(e) = socket.send_to(&output[..len], client_addr).await {
                warn!(
                    "Failed to send rebind ack to {}: {}",
                    crate::privacy::addr(client_addr),
                    e
                );
            } else {
                debug!("Sent rebind ack to session {}", session_id);
            }
        }
    }

    /// Handle a rekey request (used in non-Linux path).
    #[allow(dead_code)]
    async fn handle_rekey(&self, data: &[u8], addr: SocketAddr, header: PacketHeader) {
        use hpn_core::protocol::{RekeyMessage, ServerHandshake};

        let session_id = header.session_id;

        // Get session
        let mut session_guard = match self.sessions.get_session_mut(session_id) {
            Some(s) => s,
            None => {
                debug!(
                    "Rekey from unknown session {} ({})",
                    session_id,
                    crate::privacy::addr(addr)
                );
                return;
            }
        };

        // Decrypt rekey request
        let mut decrypt_buf = vec![0u8; data.len()];
        let (_, len) = match session_guard.session.decrypt_packet(data, &mut decrypt_buf) {
            Ok(r) => r,
            Err(e) => {
                debug!(
                    "Failed to decrypt rekey request from session {}: {}",
                    session_id, e
                );
                return;
            }
        };

        // Parse rekey message
        let rekey_msg = match RekeyMessage::from_bytes(&decrypt_buf[..len]) {
            Ok(r) => r,
            Err(e) => {
                debug!("Invalid rekey message from session {}: {}", session_id, e);
                return;
            }
        };

        if rekey_msg.client_ephemeral_pk.security_level != session_guard.security_level {
            warn!(
                "Rejected rekey with mismatched security level for session {}: established={:?}, requested={:?}",
                session_id,
                session_guard.security_level,
                rekey_msg.client_ephemeral_pk.security_level
            );
            return;
        }

        info!("Rekey request from session {}", session_id);

        // Use keypair matching client's security level
        let keypair = self.keypair_for_level(rekey_msg.client_ephemeral_pk.security_level);
        let rekey_handler = ServerHandshake::new(keypair);
        let current_key_id = session_guard.session.key_id();

        // Process rekey and get response + new keys (with session_id for key derivation context)
        let (response, new_keys) =
            match rekey_handler.process_rekey(&rekey_msg, current_key_id, session_id) {
                Ok(r) => r,
                Err(e) => {
                    error!("Rekey processing failed for session {}: {}", session_id, e);
                    return;
                }
            };

        // Encrypt response with OLD keys
        let payload = response.to_bytes();
        let mut output = vec![0u8; HEADER_SIZE + payload.len() + aead::TAG_SIZE + 32];
        let len = match session_guard.session.encrypt_packet(
            MessageType::RekeyResponse,
            &payload,
            &mut output,
        ) {
            Ok(l) => l,
            Err(e) => {
                debug!(
                    "Failed to encrypt rekey response for session {}: {}",
                    session_id, e
                );
                return;
            }
        };

        // Update to new keys AFTER encrypting response
        if let Err(e) = session_guard.session.update_keys(new_keys) {
            error!("Rekey failed — invalid key material: {}", e);
            return;
        }
        session_guard.touch();

        let client_addr = *session_guard.client_addr.lock();
        drop(session_guard);

        // Send response
        if let Some(ref socket) = self.socket {
            if let Err(e) = socket.send_to(&output[..len], client_addr).await {
                warn!(
                    "Failed to send rekey response to {}: {}",
                    crate::privacy::addr(client_addr),
                    e
                );
            } else {
                info!(
                    "Rekey complete for session {}, new key_id={}",
                    session_id, response.new_key_id
                );
            }
        }
    }

    /// Send encrypted data to a client (used in non-Linux path).
    #[allow(dead_code)]
    async fn send_to_client(&self, session_id: SessionId, data: &[u8], socket: &UdpSocket) {
        let session_guard = match self.sessions.get_session_mut(session_id) {
            Some(s) => s,
            None => return,
        };

        let client_addr = *session_guard.client_addr.lock();

        // Encrypt packet
        let mut output = vec![0u8; HEADER_SIZE + data.len() + aead::TAG_SIZE + 32];
        let len = match session_guard
            .session
            .encrypt_packet(MessageType::Data, data, &mut output)
        {
            Ok(l) => l,
            Err(e) => {
                debug!("Encryption failed for session {}: {}", session_id, e);
                return;
            }
        };

        session_guard.add_bytes_sent(len as u64);
        drop(session_guard);

        // Send to client
        if let Err(e) = socket.send_to(&output[..len], client_addr).await {
            warn!(
                "Failed to send to {}: {}",
                crate::privacy::addr(client_addr),
                e
            );
        }
    }

    /// Route a packet from TUN to the appropriate client.
    pub fn route_tun_packet(&self, packet: &[u8]) -> Option<SessionId> {
        // Get destination IP from packet (IPv4 or IPv6)
        match get_destination_addr(packet)? {
            DestinationAddr::V4(dst_ip) => {
                // Find session by IPv4 tunnel IP
                self.sessions.get_session_by_ip(dst_ip)
            }
            DestinationAddr::V6(dst_ip) => {
                // Find session by IPv6 tunnel IP
                self.sessions.get_session_by_ipv6(dst_ip)
            }
        }
    }

    /// Shutdown the server.
    pub fn shutdown(&self) {
        info!("Shutting down server");
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Check if server is shutting down.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    /// Get the number of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.session_count()
    }

    /// Get the server's Level 3 (Standard) public key (ML-DSA-65).
    pub fn public_key_level3(&self) -> &hpn_core::crypto::MlDsaPublicKey {
        &self.keypair_level3.public_key
    }

    /// Get the server's Level 5 (High) public key (ML-DSA-87).
    pub fn public_key_level5(&self) -> &hpn_core::crypto::MlDsaPublicKey {
        &self.keypair_level5.public_key
    }

    /// Get the server's public key for a specific security level.
    pub fn public_key(&self, level: SecurityLevel) -> &hpn_core::crypto::MlDsaPublicKey {
        match level {
            SecurityLevel::Level3 => &self.keypair_level3.public_key,
            SecurityLevel::Level5 => &self.keypair_level5.public_key,
        }
    }

    /// Get the server's KEM public key for a specific security level.
    ///
    /// Returns `None` if identity hiding is not configured for this level.
    pub fn kem_public_key(&self, level: SecurityLevel) -> Option<&HybridPublicKey> {
        match level {
            SecurityLevel::Level3 => self.kem_keypair_level3.as_ref().map(|kp| &kp.1),
            SecurityLevel::Level5 => self.kem_keypair_level5.as_ref().map(|kp| &kp.1),
        }
    }
}

impl Drop for VpnServer {
    fn drop(&mut self) {
        info!("VpnServer shutdown initiated");

        // 1. Signal shutdown to all workers
        self.shutdown.store(true, Ordering::SeqCst);
        info!("Shutdown signal sent to all workers");

        // 2. Shutdown UDP worker pool first (this signals UDP workers to stop)
        #[cfg(target_os = "linux")]
        if let Some(ref udp_workers) = self.udp_workers {
            info!("Shutting down UDP worker pool");
            udp_workers.shutdown();
        }

        // 3. Give workers a moment to notice shutdown signal
        std::thread::sleep(std::time::Duration::from_millis(50));

        // 4. Join all worker threads with timeout
        let join_timeout = std::time::Duration::from_secs(5);
        let start = std::time::Instant::now();

        info!(
            "Joining {} worker threads (timeout: {:?})",
            self.worker_handles.len(),
            join_timeout
        );

        // Drain worker handles to take ownership
        let handles: Vec<WorkerHandle> = std::mem::take(&mut self.worker_handles);
        let mut joined_count = 0;
        let mut timeout_count = 0;

        for worker in handles {
            let remaining = join_timeout.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                warn!(
                    "Timeout waiting for workers to join. {} workers may not have terminated cleanly.",
                    self.worker_handles.len() - joined_count
                );
                timeout_count = self.worker_handles.len() - joined_count;
                break;
            }

            // Try to join with a short park to allow the thread to finish
            // std::thread::JoinHandle doesn't have timeout, so we use is_finished()
            let thread_start = std::time::Instant::now();
            let thread_timeout = std::time::Duration::from_secs(1);

            loop {
                if worker.handle.is_finished() {
                    match std::thread::Builder::new()
                        .spawn(move || worker.handle.join())
                        .ok()
                        .and_then(|h| h.join().ok())
                    {
                        Some(Ok(())) => {
                            debug!("Worker '{}' joined successfully", worker.name);
                            joined_count += 1;
                        }
                        Some(Err(_)) => {
                            warn!("Worker '{}' panicked during shutdown", worker.name);
                            joined_count += 1;
                        }
                        None => {
                            warn!("Failed to join worker '{}'", worker.name);
                        }
                    }
                    break;
                }

                if thread_start.elapsed() >= thread_timeout {
                    warn!(
                        "Worker '{}' did not finish within timeout, continuing...",
                        worker.name
                    );
                    timeout_count += 1;
                    // Thread handle is dropped here, thread continues running but is detached
                    break;
                }

                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }

        if joined_count > 0 || timeout_count > 0 {
            info!(
                "Worker threads: {} joined, {} timed out",
                joined_count, timeout_count
            );
        }

        // 5. Drop UDP worker pool (joins its internal threads)
        #[cfg(target_os = "linux")]
        {
            info!("Dropping UDP worker pool");
            self.udp_workers = None;
        }

        // 6. Close TUN device
        if let Some(ref mut tun) = self.tun {
            info!("Closing TUN device '{}'", tun.name());
            tun.close();
        }

        // 7. Cleanup FORWARD rules
        info!("Cleaning up iptables FORWARD rules");
        if let Err(e) = crate::nat::disallow_forward(&self.config.ipv4_pool, &self.config.tun_name)
        {
            warn!("Failed to cleanup FORWARD rules: {}", e);
        }

        // 8. Cleanup NAT
        if let Some(ref mut nat) = self.nat {
            info!("Disabling NAT");
            if let Err(e) = nat.disable() {
                warn!("Failed to disable NAT: {}", e);
            }
        }

        // 9. Clear sessions
        info!("Clearing {} active sessions", self.sessions.session_count());

        info!("VpnServer shutdown complete");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_worker_health_tracker_basic() {
        let metrics = crate::metrics::ServerMetrics::new();
        let shutdown = Arc::new(AtomicBool::new(false));
        let tracker = WorkerHealthTracker::new(Arc::clone(&metrics), Arc::clone(&shutdown), None);

        // Initially healthy
        assert!(!tracker.is_degraded());
        assert_eq!(tracker.panic_count(), 0);
        assert!(!shutdown.load(Ordering::Relaxed));
    }

    #[test]
    fn test_worker_health_tracker_panic_count() {
        let metrics = crate::metrics::ServerMetrics::new();
        let shutdown = Arc::new(AtomicBool::new(false));
        let tracker = WorkerHealthTracker::new(Arc::clone(&metrics), Arc::clone(&shutdown), None);

        // First panic - should continue
        let should_continue = tracker.record_panic("test-worker-0", "test panic 1");
        assert!(should_continue);
        assert_eq!(tracker.panic_count(), 1);
        assert!(!tracker.is_degraded());

        // Second panic - should continue
        let should_continue = tracker.record_panic("test-worker-1", "test panic 2");
        assert!(should_continue);
        assert_eq!(tracker.panic_count(), 2);
        assert!(!tracker.is_degraded());

        // Third panic - should enter degraded mode (default max is 3)
        let should_continue = tracker.record_panic("test-worker-2", "test panic 3");
        assert!(!should_continue);
        assert_eq!(tracker.panic_count(), 3);
        assert!(tracker.is_degraded());
        assert!(shutdown.load(Ordering::Relaxed));
    }

    #[test]
    fn test_worker_health_tracker_custom_max_panics() {
        let metrics = crate::metrics::ServerMetrics::new();
        let shutdown = Arc::new(AtomicBool::new(false));
        let tracker =
            WorkerHealthTracker::new(Arc::clone(&metrics), Arc::clone(&shutdown), Some(1));

        // First panic - should enter degraded mode immediately (max is 1)
        let should_continue = tracker.record_panic("test-worker", "fatal panic");
        assert!(!should_continue);
        assert_eq!(tracker.panic_count(), 1);
        assert!(tracker.is_degraded());
        assert!(shutdown.load(Ordering::Relaxed));
    }

    #[test]
    fn test_worker_health_tracker_metrics_updated() {
        let metrics = crate::metrics::ServerMetrics::new();
        let shutdown = Arc::new(AtomicBool::new(false));
        let tracker = WorkerHealthTracker::new(Arc::clone(&metrics), Arc::clone(&shutdown), None);

        assert_eq!(metrics.worker_panic_count(), 0);
        assert!(!metrics.is_degraded());

        tracker.record_panic("worker-1", "panic 1");
        assert_eq!(metrics.worker_panic_count(), 1);

        tracker.record_panic("worker-2", "panic 2");
        assert_eq!(metrics.worker_panic_count(), 2);

        tracker.record_panic("worker-3", "panic 3");
        assert_eq!(metrics.worker_panic_count(), 3);
        assert!(metrics.is_degraded());
    }

    #[test]
    fn test_extract_panic_message_str() {
        let panic_info: Box<dyn std::any::Any + Send> = Box::new("test panic message");
        let msg = WorkerHealthTracker::extract_panic_message(&panic_info);
        assert_eq!(msg, "test panic message");
    }

    #[test]
    fn test_extract_panic_message_string() {
        let panic_info: Box<dyn std::any::Any + Send> =
            Box::new(String::from("owned panic message"));
        let msg = WorkerHealthTracker::extract_panic_message(&panic_info);
        assert_eq!(msg, "owned panic message");
    }

    #[test]
    fn test_extract_panic_message_unknown() {
        let panic_info: Box<dyn std::any::Any + Send> = Box::new(42i32);
        let msg = WorkerHealthTracker::extract_panic_message(&panic_info);
        assert_eq!(msg, "unknown panic");
    }

    #[test]
    fn test_worker_health_tracker_concurrent_panics() {
        use std::thread;

        let metrics = crate::metrics::ServerMetrics::new();
        let shutdown = Arc::new(AtomicBool::new(false));
        let tracker =
            WorkerHealthTracker::new(Arc::clone(&metrics), Arc::clone(&shutdown), Some(100));

        let num_threads = 10;
        let panics_per_thread = 5;

        let handles: Vec<_> = (0..num_threads)
            .map(|tid| {
                let tracker = Arc::clone(&tracker);
                thread::spawn(move || {
                    for i in 0..panics_per_thread {
                        tracker.record_panic(
                            &format!("thread-{}-worker-{}", tid, i),
                            "concurrent panic",
                        );
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        // All panics should be counted
        assert_eq!(
            tracker.panic_count(),
            (num_threads * panics_per_thread) as u32
        );
        assert_eq!(
            metrics.worker_panic_count(),
            (num_threads * panics_per_thread) as u64
        );
    }
}
