//! AF_XDP Zero-Copy Data Path Workers.
//!
//! This module provides high-performance packet processing using AF_XDP
//! for zero-copy kernel-bypass networking. It integrates with the existing
//! server architecture and provides a drop-in replacement for the regular
//! UDP worker pool when AF_XDP is available and enabled.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │                        HPN Server                                │
//! │                                                                  │
//! │  ┌──────────────────────────────────────────────────────────┐   │
//! │  │                    AfXdpWorkerPool                        │   │
//! │  │                                                           │   │
//! │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐       │   │
//! │  │  │ AfXdpWorker │  │ AfXdpWorker │  │ AfXdpWorker │ ...   │   │
//! │  │  │   Queue 0   │  │   Queue 1   │  │   Queue 2   │       │   │
//! │  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘       │   │
//! │  │         │                │                │              │   │
//! │  │         ▼                ▼                ▼              │   │
//! │  │  ┌──────────────────────────────────────────────────┐    │   │
//! │  │  │              Shared UMEM (Zero-Copy)             │    │   │
//! │  │  └──────────────────────────────────────────────────┘    │   │
//! │  └──────────────────────────────────────────────────────────┘   │
//! │                              │                                  │
//! ├──────────────────────────────┼──────────────────────────────────┤
//! │         Kernel Space         │                                  │
//! │  ┌───────────────────────────▼──────────────────────────────┐   │
//! │  │                     XDP Program                          │   │
//! │  │              (Redirect to AF_XDP sockets)                │   │
//! │  └──────────────────────────────────────────────────────────┘   │
//! │                              │                                  │
//! │  ┌───────────────────────────▼──────────────────────────────┐   │
//! │  │                        NIC                               │   │
//! │  └──────────────────────────────────────────────────────────┘   │
//! └──────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! The AF_XDP worker pool is created and started by the server when
//! `enable_afxdp = true` is set in the configuration and the system
//! supports AF_XDP.

use std::net::SocketAddr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::JoinHandle;

use crate::server::WorkerHealthTracker;

use bytes::Bytes;
use crossbeam_channel::{Receiver, Sender, TrySendError, bounded};
use crossbeam_utils::CachePadded;
use parking_lot::RwLock;
use tracing::{debug, error, info, trace, warn};

use hpn_afxdp::{
    SessionCrypto, SessionTable, SharedSessionTable, SharedUmem, WorkerConfig, XdpManager, XdpMode,
    XskConfig, XskSocket,
};
use hpn_core::protocol::header::{HEADER_SIZE, PacketHeader};
use hpn_core::types::{MessageType, SessionId};

use crate::error::{ServerError, ServerResult};
use crate::server::PooledBuffer;
use crate::session_manager::SessionManager;

/// Configuration for AF_XDP worker pool.
#[derive(Debug, Clone)]
pub struct AfXdpPoolConfig {
    /// Network interface to bind to.
    pub interface: String,
    /// Number of workers (one per NIC queue).
    pub num_workers: u32,
    /// Ring size for each socket.
    pub ring_size: u32,
    /// Enable zero-copy mode.
    pub zero_copy: bool,
    /// Enable busy polling (higher CPU, lower latency).
    pub busy_poll: bool,
}

impl AfXdpPoolConfig {
    /// Create configuration from server config.
    #[allow(dead_code)]
    pub fn from_server_config(config: &crate::config::ServerConfig) -> Option<Self> {
        let (interface, num_workers, ring_size, zero_copy) = config.get_afxdp_config()?;
        Some(Self {
            interface,
            num_workers,
            ring_size,
            zero_copy,
            busy_poll: false,
        })
    }
}

/// Control message from AF_XDP workers to the main server.
pub enum AfXdpControl {
    /// Handshake init received - needs async handling.
    HandshakeInit { data: Vec<u8>, addr: SocketAddr },
    /// Keepalive received.
    Keepalive {
        session_id: SessionId,
        data: Vec<u8>,
        addr: SocketAddr,
    },
    /// Control message received.
    Control {
        session_id: SessionId,
        data: Vec<u8>,
        addr: SocketAddr,
    },
    /// Rekey request received.
    Rekey {
        session_id: SessionId,
        data: Vec<u8>,
        addr: SocketAddr,
    },
}

/// Response to send back to a client via UDP.
///
/// Used for handshake responses, rekey responses, keepalive replies, etc.
/// These are sent via standard UDP socket since AF_XDP workers don't have
/// client address information for new connections.
#[derive(Debug)]
pub struct AfXdpResponse {
    /// Destination address.
    pub addr: SocketAddr,
    /// Response data to send.
    pub data: Bytes,
}

/// Statistics for AF_XDP worker pool.
///
/// Each counter is wrapped in [`CachePadded`] so it lives on its own
/// 64-byte cache line. Without padding, several `fetch_add(1)` calls
/// from different worker threads (e.g. `rx_packets` on worker 0 and
/// `tx_packets` on worker 1, both touching the same line) trigger
/// MESI invalidations that ricochet through the cache hierarchy and
/// measurably hurt throughput at high packet rates. The padding adds
/// ~600 bytes of static memory but eliminates the false-sharing
/// hotspot. `CachePadded<T>` implements `Deref<Target=T>` so every
/// existing call site (`stats.rx_packets.fetch_add(...)`) keeps
/// working unchanged.
#[derive(Debug, Default)]
pub struct AfXdpPoolStats {
    /// Total packets received across all workers.
    pub rx_packets: CachePadded<AtomicU64>,
    /// Total packets transmitted across all workers.
    pub tx_packets: CachePadded<AtomicU64>,
    /// Total bytes received (decrypted).
    pub rx_bytes: CachePadded<AtomicU64>,
    /// Total bytes transmitted (encrypted).
    pub tx_bytes: CachePadded<AtomicU64>,
    /// Packets dropped due to unknown session.
    pub unknown_session: CachePadded<AtomicU64>,
    /// Packets dropped due to decryption failure.
    pub decrypt_errors: CachePadded<AtomicU64>,
    /// Packets dropped due to replay detection.
    pub replay_drops: CachePadded<AtomicU64>,
    /// Packets dropped due to per-session rate limiting.
    pub rate_limited_drops: CachePadded<AtomicU64>,
    /// Packets dropped due to invalid AF_XDP descriptor bounds.
    pub invalid_desc_drops: CachePadded<AtomicU64>,
    /// Control messages forwarded to main thread.
    pub control_messages: CachePadded<AtomicU64>,
}

/// AF_XDP session bridge.
///
/// Bridges between the server's SessionManager and the AF_XDP SessionTable
/// for fast crypto lookups during packet processing.
pub struct SessionBridge {
    /// The AF_XDP session table.
    afxdp_sessions: SharedSessionTable,
    /// Reference to the server's session manager.
    server_sessions: Arc<SessionManager>,
}

impl SessionBridge {
    /// Create a new session bridge.
    pub fn new(server_sessions: Arc<SessionManager>) -> Self {
        Self {
            afxdp_sessions: Arc::new(SessionTable::new()),
            server_sessions,
        }
    }

    /// Get the AF_XDP session table.
    pub fn afxdp_table(&self) -> SharedSessionTable {
        Arc::clone(&self.afxdp_sessions)
    }

    /// Sync a session from server to AF_XDP table.
    ///
    /// Called when a new session is created or keys are updated.
    /// Extracts crypto keys from the Session and creates an AF_XDP SessionCrypto.
    pub fn sync_session(&self, session_id: SessionId) -> ServerResult<()> {
        // Get session from server's session manager
        let session_guard = self
            .server_sessions
            .get_session(session_id)
            .ok_or_else(|| ServerError::Internal(format!("Session {} not found", session_id.0)))?;

        let session = &session_guard.session;

        // Extract keys from SessionKeys (Session stores the raw keys in the keys field)
        let keys = session.keys();

        // Create AF_XDP session crypto with real keys
        // Note: For the server, send_key encrypts outgoing packets (to client),
        // recv_key decrypts incoming packets (from client).
        let crypto = SessionCrypto::new(
            session_id,
            keys.send_key,          // TX key for server -> client
            keys.recv_key,          // RX key for client -> server
            keys.send_nonce_prefix, // Nonce prefix for sending
            session.key_id(),
        )
        .map_err(|e| ServerError::Internal(format!("Failed to create session crypto: {}", e)))?;

        self.afxdp_sessions.add(Arc::new(crypto));
        debug!(
            "Synced session {} to AF_XDP table (key_id={})",
            session_id.0,
            session.key_id().0
        );
        Ok(())
    }

    /// Remove a session from the AF_XDP table.
    pub fn remove_session(&self, session_id: SessionId) {
        self.afxdp_sessions.remove(session_id);
    }
}

/// AF_XDP worker pool.
///
/// Manages multiple AF_XDP workers for high-performance packet processing.
pub struct AfXdpWorkerPool {
    /// Worker thread handles.
    workers: Vec<JoinHandle<()>>,
    /// XDP manager for program attachment.
    xdp_manager: Arc<RwLock<XdpManager>>,
    /// Shared UMEM for all sockets.
    umem: SharedUmem,
    /// Session bridge for crypto lookups.
    session_bridge: Arc<SessionBridge>,
    /// Channel for control messages to main server.
    control_tx: Sender<AfXdpControl>,
    /// Receiver for control messages (given to server).
    control_rx: Receiver<AfXdpControl>,
    /// Channel for responses to send back to clients.
    response_tx: Sender<AfXdpResponse>,
    /// Receiver for responses (workers send via standard UDP).
    response_rx: Receiver<AfXdpResponse>,
    /// Channel for decrypted packets to TUN.
    tun_write_tx: Sender<PooledBuffer>,
    /// Shutdown flag.
    shutdown: Arc<AtomicBool>,
    /// Configuration.
    config: AfXdpPoolConfig,
    /// Pool-wide statistics.
    stats: Arc<AfXdpPoolStats>,
    /// Buffer pool for decrypted packets.
    buffer_pool: Arc<crate::server::BufferPool>,
}

impl AfXdpWorkerPool {
    /// Maximum packet size for buffer allocation.
    const MAX_PACKET_SIZE: usize = 65535;

    /// Create a new AF_XDP worker pool.
    pub fn new(
        config: AfXdpPoolConfig,
        server_sessions: Arc<SessionManager>,
        tun_write_tx: Sender<PooledBuffer>,
    ) -> ServerResult<Self> {
        info!(
            "Creating AF_XDP worker pool: interface={}, workers={}, ring_size={}, zero_copy={}",
            config.interface, config.num_workers, config.ring_size, config.zero_copy
        );

        // Check AF_XDP support
        if !hpn_afxdp::is_supported() {
            return Err(ServerError::Internal(
                "AF_XDP not supported on this system".to_string(),
            ));
        }

        // Create XDP manager and attach program
        let mut xdp_manager = XdpManager::new(&config.interface)
            .map_err(|e| ServerError::Internal(format!("Failed to create XDP manager: {}", e)))?;

        // Try native mode first, fall back to SKB mode
        let xdp_mode = if config.zero_copy {
            XdpMode::Native
        } else {
            XdpMode::Skb
        };

        if let Err(e) = xdp_manager.attach(xdp_mode) {
            warn!(
                "Failed to attach XDP program in {:?} mode: {}, trying SKB mode",
                xdp_mode, e
            );
            xdp_manager.attach(XdpMode::Skb).map_err(|e| {
                ServerError::Internal(format!("Failed to attach XDP program: {}", e))
            })?;
        }

        info!(
            "XDP program attached to {} in {:?} mode",
            config.interface,
            xdp_manager.mode()
        );

        // Create shared UMEM
        let umem_config = hpn_afxdp::UmemConfig::default();
        let umem = Arc::new(
            hpn_afxdp::Umem::new(umem_config)
                .map_err(|e| ServerError::Internal(format!("Failed to create UMEM: {}", e)))?,
        );

        // Create channels
        let (control_tx, control_rx) = bounded(8192);
        let (response_tx, response_rx) = bounded(4096);
        let shutdown = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(AfXdpPoolStats::default());

        // Create buffer pool for decrypted packets (1024 buffers per worker)
        let buffer_pool_size = (config.num_workers as usize) * 1024;
        let buffer_pool = Arc::new(crate::server::BufferPool::new(
            buffer_pool_size,
            Self::MAX_PACKET_SIZE,
        ));

        // Create session bridge
        let session_bridge = Arc::new(SessionBridge::new(server_sessions));

        Ok(Self {
            workers: Vec::with_capacity(config.num_workers as usize),
            xdp_manager: Arc::new(RwLock::new(xdp_manager)),
            umem,
            session_bridge,
            control_tx,
            control_rx,
            response_tx,
            response_rx,
            tun_write_tx,
            shutdown,
            config,
            stats,
            buffer_pool,
        })
    }

    /// Start the worker threads.
    pub fn start(&mut self) -> ServerResult<()> {
        info!("Starting {} AF_XDP worker threads", self.config.num_workers);

        for queue_id in 0..self.config.num_workers {
            let handle = self.spawn_worker(queue_id)?;
            self.workers.push(handle);
        }

        info!("AF_XDP worker pool started");
        Ok(())
    }

    /// Spawn a single worker thread.
    fn spawn_worker(&self, queue_id: u32) -> ServerResult<JoinHandle<()>> {
        // Create XSK socket for this queue
        let xsk_config = XskConfig::new(&self.config.interface)
            .queue_id(queue_id)
            .ring_size(self.config.ring_size)
            .zero_copy(self.config.zero_copy);

        let socket = XskSocket::with_umem(&xsk_config, Arc::clone(&self.umem)).map_err(|e| {
            ServerError::Internal(format!(
                "Failed to create XSK socket for queue {}: {}",
                queue_id, e
            ))
        })?;

        info!(
            "Created XSK socket for queue {}: zero_copy={}",
            queue_id,
            socket.is_zero_copy()
        );

        // Clone handles for the thread
        let sessions = self.session_bridge.afxdp_table();
        let tun_write_tx = self.tun_write_tx.clone();
        let control_tx = self.control_tx.clone();
        let shutdown = Arc::clone(&self.shutdown);
        let stats = Arc::clone(&self.stats);
        let buffer_pool = Arc::clone(&self.buffer_pool);

        let worker_config = WorkerConfig {
            rx_batch_size: 64,
            tx_batch_size: 64,
            busy_poll: self.config.busy_poll,
            poll_timeout_ms: 1,
        };

        let worker_name = format!("afxdp-worker-{}", queue_id);
        let handle = std::thread::Builder::new()
            .name(worker_name.clone())
            .spawn(move || {
                // Wrap with panic recovery to prevent crashes from taking down the server
                let result = catch_unwind(AssertUnwindSafe(|| {
                    run_afxdp_worker(
                        queue_id,
                        socket,
                        sessions,
                        tun_write_tx,
                        control_tx,
                        shutdown,
                        worker_config,
                        stats,
                        buffer_pool,
                    );
                }));

                if let Err(panic_info) = result {
                    let panic_msg = WorkerHealthTracker::extract_panic_message(&panic_info);
                    error!("PANIC in AF_XDP worker '{}': {}", worker_name, panic_msg);
                }
            })
            .map_err(|e| {
                ServerError::Internal(format!(
                    "Failed to spawn AF_XDP worker thread {}: {}",
                    queue_id, e
                ))
            })?;

        Ok(handle)
    }

    /// Get the control message receiver.
    pub fn control_rx(&self) -> &Receiver<AfXdpControl> {
        &self.control_rx
    }

    /// Get the response receiver for sending responses to clients.
    pub fn response_rx(&self) -> &Receiver<AfXdpResponse> {
        &self.response_rx
    }

    /// Get the response sender for queueing responses.
    pub fn response_tx(&self) -> &Sender<AfXdpResponse> {
        &self.response_tx
    }

    /// Get the session bridge for syncing sessions.
    pub fn session_bridge(&self) -> &Arc<SessionBridge> {
        &self.session_bridge
    }

    /// Get pool statistics for monitoring.
    #[allow(dead_code)]
    pub fn stats(&self) -> &Arc<AfXdpPoolStats> {
        &self.stats
    }

    /// Shutdown the worker pool.
    pub fn shutdown(&self) {
        info!("Shutting down AF_XDP worker pool");
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Check if the pool is shutdown.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }
}

impl Drop for AfXdpWorkerPool {
    fn drop(&mut self) {
        info!("AF_XDP worker pool cleanup");

        // Signal shutdown
        self.shutdown.store(true, Ordering::SeqCst);

        // Give workers time to notice
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Join worker threads
        let workers = std::mem::take(&mut self.workers);
        for (i, handle) in workers.into_iter().enumerate() {
            let timeout = std::time::Duration::from_secs(2);
            let start = std::time::Instant::now();

            loop {
                if handle.is_finished() {
                    match handle.join() {
                        Ok(()) => debug!("AF_XDP worker {} joined", i),
                        Err(_) => warn!("AF_XDP worker {} panicked", i),
                    }
                    break;
                }

                if start.elapsed() >= timeout {
                    warn!("AF_XDP worker {} join timeout", i);
                    break;
                }

                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }

        // Detach XDP program
        if let Ok(mut manager) = self.xdp_manager.try_write() {
            if let Err(e) = manager.detach() {
                warn!("Failed to detach XDP program: {}", e);
            } else {
                info!("XDP program detached");
            }
        }

        info!("AF_XDP worker pool cleanup complete");
    }
}

/// Run a single AF_XDP worker thread.
///
/// This is the high-performance data path that processes packets with zero-copy.
/// - Data packets: Decrypt and forward to TUN
/// - Control packets (handshake, rekey, keepalive): Forward to main server thread
fn run_afxdp_worker(
    worker_id: u32,
    mut socket: XskSocket,
    sessions: SharedSessionTable,
    tun_write_tx: Sender<PooledBuffer>,
    control_tx: Sender<AfXdpControl>,
    shutdown: Arc<AtomicBool>,
    config: WorkerConfig,
    stats: Arc<AfXdpPoolStats>,
    buffer_pool: Arc<crate::server::BufferPool>,
) {
    use hpn_core::crypto::aead::TAG_SIZE;

    // Pin to the same CPU as the NIC RSS queue this worker drains. With
    // an N-queue NIC and N AF_XDP workers, this gives each worker a
    // private CPU + private RX queue + private UMEM partition — the
    // canonical "per-core pipeline" topology that AF_XDP expects.
    // Migrating an AF_XDP worker between CPUs while the NIC keeps
    // delivering completions to the original CPU's poll list is
    // catastrophic for cache locality and adds inter-core IPI churn.
    //
    // Failure modes (systemd CPUAffinity narrower than ours, etc.) are
    // logged at `debug!` and ignored — the worker still runs, just
    // unpinned.
    {
        let cpus = hpn_core::perf::affinity::num_cpus();
        if cpus > 0 {
            let target = (worker_id as usize) % cpus;
            match hpn_core::perf::affinity::set_thread_affinity(target) {
                Ok(()) => debug!(
                    "AF_XDP worker {} pinned to CPU {} (of {} online)",
                    worker_id, target, cpus
                ),
                Err(e) => debug!(
                    "AF_XDP worker {}: set_thread_affinity({}) failed: {} \
                     (continuing without pinning)",
                    worker_id, target, e
                ),
            }
        }
    }

    info!(
        "AF_XDP worker {} started (queue={}, busy_poll={})",
        worker_id,
        socket.queue_id(),
        config.busy_poll
    );

    let mut consecutive_empty = 0u32;

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Poll for packets if not busy polling
        if !config.busy_poll {
            match socket.poll(config.poll_timeout_ms) {
                Ok((can_rx, _)) => {
                    if !can_rx {
                        consecutive_empty += 1;
                        if consecutive_empty > 1000 {
                            std::thread::sleep(std::time::Duration::from_micros(100));
                        } else if consecutive_empty > 100 {
                            std::thread::sleep(std::time::Duration::from_micros(10));
                        }
                        continue;
                    }
                }
                Err(e) => {
                    warn!("AF_XDP worker {} poll error: {}", worker_id, e);
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    continue;
                }
            }
        }

        // Process received packets in batches
        match socket.recv(config.rx_batch_size, |addr, len| {
            let encrypted_packet = match socket.umem().packet_checked(addr, len) {
                Ok(packet) => packet,
                Err(e) => {
                    stats.invalid_desc_drops.fetch_add(1, Ordering::Relaxed);
                    trace!(
                        "Worker {}: invalid descriptor addr={:#x} len={}: {}",
                        worker_id, addr, len, e
                    );
                    return;
                }
            };

            stats.rx_packets.fetch_add(1, Ordering::Relaxed);

            // Minimum packet size: header + tag
            if encrypted_packet.len() < HEADER_SIZE + TAG_SIZE {
                trace!(
                    "Worker {}: packet too small ({})",
                    worker_id,
                    encrypted_packet.len()
                );
                return;
            }

            // Parse header
            let header = match PacketHeader::decode(encrypted_packet) {
                Ok(h) => h,
                Err(_) => {
                    trace!("Worker {}: invalid header", worker_id);
                    return;
                }
            };

            let session_id = header.session_id;

            // Route based on message type
            match header.msg_type {
                MessageType::Data => {
                    // Fast path: decrypt and forward to TUN.
                    if let Some(session) = sessions.get(session_id.0) {
                        // SECURITY: replay-window and per-session rate-limit
                        // checks are MUTATING operations. If we ran them before
                        // AEAD decryption, an off-path attacker who observed a
                        // SessionId could forge packets with arbitrary counters,
                        // poisoning the legitimate client's replay window or
                        // draining its rate-limit tokens. We therefore decrypt
                        // FIRST (the AEAD tag authenticates the sender) and
                        // only mutate session state after cryptographic proof.
                        //
                        // Note: this trades a few microseconds of CPU on
                        // spoofed packets for correctness under attack. The
                        // per-IP handshake rate limiter in `server.rs` already
                        // caps unauthenticated packet volume per source.

                        // Get a buffer from the pool
                        let mut buffer = match buffer_pool.get() {
                            Some(b) => b,
                            None => {
                                trace!("Worker {}: buffer pool exhausted", worker_id);
                                return;
                            }
                        };

                        // Decrypt the packet.
                        let header_size = header.encoded_size();
                        let ciphertext = &encrypted_packet[header_size..];

                        match session.decrypt(
                            header.counter.0,
                            &encrypted_packet[..header_size],
                            ciphertext,
                            buffer.as_mut_slice(),
                        ) {
                            Ok(plaintext_len) => {
                                // AEAD tag verified — now safe to mutate
                                // replay window and rate-limit tokens.
                                if !session.check_replay(header.counter.0) {
                                    stats.replay_drops.fetch_add(1, Ordering::Relaxed);
                                    trace!(
                                        "Worker {}: replay detected for session {}",
                                        worker_id, session_id.0
                                    );
                                    return;
                                }
                                if !session.check_rate_limit(plaintext_len) {
                                    stats.rate_limited_drops.fetch_add(1, Ordering::Relaxed);
                                    trace!(
                                        "Worker {}: session {} rate limited ({} bytes)",
                                        worker_id, session_id.0, plaintext_len
                                    );
                                    return;
                                }
                                buffer.set_len(plaintext_len);
                                stats
                                    .rx_bytes
                                    .fetch_add(plaintext_len as u64, Ordering::Relaxed);

                                // Send to TUN writer
                                match tun_write_tx.try_send(buffer) {
                                    Ok(()) => {}
                                    Err(TrySendError::Full(_)) => {
                                        trace!("Worker {}: TUN channel full", worker_id);
                                    }
                                    Err(TrySendError::Disconnected(_)) => {
                                        warn!("Worker {}: TUN channel disconnected", worker_id);
                                    }
                                }
                            }
                            Err(_) => {
                                stats.decrypt_errors.fetch_add(1, Ordering::Relaxed);
                                trace!(
                                    "Worker {}: decrypt failed for session {}",
                                    worker_id, session_id.0
                                );
                            }
                        }
                    } else {
                        stats.unknown_session.fetch_add(1, Ordering::Relaxed);
                        trace!("Worker {}: unknown session {}", worker_id, session_id.0);
                    }
                }

                MessageType::HandshakeInit | MessageType::EncryptedHandshakeInit => {
                    // Forward to main server for async handling
                    // Both regular and encrypted handshakes are handled by the main server
                    stats.control_messages.fetch_add(1, Ordering::Relaxed);
                    // Note: We don't have the source address in AF_XDP raw packets
                    // This would require parsing the IP/UDP headers
                    // For now, handshakes should go through the standard UDP path
                    trace!("Worker {}: handshake init (needs UDP path)", worker_id);
                }

                MessageType::Keepalive => {
                    // Forward keepalive to main server
                    if let Err(e) = control_tx.try_send(AfXdpControl::Keepalive {
                        session_id,
                        data: encrypted_packet.to_vec(),
                        addr: SocketAddr::from(([0, 0, 0, 0], 0)), // Placeholder - real addr from IP header
                    }) {
                        trace!("Worker {}: failed to forward keepalive: {:?}", worker_id, e);
                    } else {
                        stats.control_messages.fetch_add(1, Ordering::Relaxed);
                    }
                }

                MessageType::Rekey => {
                    // Forward rekey to main server
                    if let Err(e) = control_tx.try_send(AfXdpControl::Rekey {
                        session_id,
                        data: encrypted_packet.to_vec(),
                        addr: SocketAddr::from(([0, 0, 0, 0], 0)),
                    }) {
                        trace!("Worker {}: failed to forward rekey: {:?}", worker_id, e);
                    } else {
                        stats.control_messages.fetch_add(1, Ordering::Relaxed);
                    }
                }

                MessageType::Control => {
                    // Forward control message to main server
                    if let Err(e) = control_tx.try_send(AfXdpControl::Control {
                        session_id,
                        data: encrypted_packet.to_vec(),
                        addr: SocketAddr::from(([0, 0, 0, 0], 0)),
                    }) {
                        trace!("Worker {}: failed to forward control: {:?}", worker_id, e);
                    } else {
                        stats.control_messages.fetch_add(1, Ordering::Relaxed);
                    }
                }

                _ => {
                    // Ignore other message types (responses, etc.)
                    trace!(
                        "Worker {}: ignoring message type {:?}",
                        worker_id, header.msg_type
                    );
                }
            }
        }) {
            Ok(processed) => {
                if processed > 0 {
                    consecutive_empty = 0;
                } else {
                    consecutive_empty += 1;
                }
            }
            Err(e) => {
                warn!("AF_XDP worker {} recv_batch error: {}", worker_id, e);
            }
        }

        // Adaptive sleep when idle
        if consecutive_empty > 0 && !config.busy_poll {
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
        "AF_XDP worker {} stopped (rx={}, tx={}, unknown={}, decrypt_err={}, replay={}, rate_limited={}, invalid_desc={})",
        worker_id,
        stats.rx_packets.load(Ordering::Relaxed),
        stats.tx_packets.load(Ordering::Relaxed),
        stats.unknown_session.load(Ordering::Relaxed),
        stats.decrypt_errors.load(Ordering::Relaxed),
        stats.replay_drops.load(Ordering::Relaxed),
        stats.rate_limited_drops.load(Ordering::Relaxed),
        stats.invalid_desc_drops.load(Ordering::Relaxed),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_afxdp_pool_config() {
        let config = AfXdpPoolConfig {
            interface: "eth0".to_string(),
            num_workers: 4,
            ring_size: 4096,
            zero_copy: true,
            busy_poll: false,
        };

        assert_eq!(config.interface, "eth0");
        assert_eq!(config.num_workers, 4);
        assert_eq!(config.ring_size, 4096);
        assert!(config.zero_copy);
        assert!(!config.busy_poll);
    }
}
