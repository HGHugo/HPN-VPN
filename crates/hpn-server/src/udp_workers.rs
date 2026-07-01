//! High-performance multi-threaded UDP I/O workers.
//!
//! This module implements a scalable UDP packet processing architecture:
//! - Multiple UDP sockets bound to the same port using SO_REUSEPORT
//! - Dedicated worker threads for each socket
//! - Lock-free channels for inter-thread communication
//! - Batch processing for high throughput
//! - **recvmmsg/sendmmsg**: Syscall batching for 15-25% throughput improvement

use std::net::SocketAddr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use bytes::Bytes;
use crossbeam_channel::{Receiver, Sender, bounded};
use crossbeam_utils::CachePadded;
use tracing::{debug, error, info, trace, warn};

use crate::metrics::ServerMetrics;

use crate::server::WorkerHealthTracker;

use hpn_core::crypto::aead;
use hpn_core::protocol::{HEADER_SIZE, PacketHeader};
use hpn_core::types::{MessageType, SessionId};

use crate::server::{BufferPool, PooledBuffer};
use crate::session_manager::SessionManager;
use crate::syscall_batch::{
    GsoSegmentIter, MAX_BATCH_SIZE, MAX_SEND_BATCH_SIZE, RecvMmsg, SendMmsg,
};

/// Maximum packet size for UDP.
const MAX_PACKET_SIZE: usize = 65535;

/// Channel capacity for worker communication.
///
/// Channel capacity for worker communication.
///
/// Set to 8192 for sufficient buffering in high-throughput scenarios while
/// keeping memory footprint manageable. The multiqueue architecture
/// prevents bottlenecks at this capacity.
const CHANNEL_CAPACITY: usize = 8192;

/// Packet to be sent to a client (needs encryption).
/// Uses `Bytes` for zero-copy sharing when possible.
/// Includes cached client_addr to avoid redundant session lookup in sender.
pub struct OutboundPacket {
    pub session_id: SessionId,
    pub data: Bytes,
    /// Cached client address (avoids double lookup in download path).
    pub client_addr: SocketAddr,
}

/// Raw response to send (already encoded, no encryption needed).
/// Uses `Bytes` for zero-copy sharing.
pub struct OutboundResponse {
    pub addr: SocketAddr,
    pub data: Bytes,
}

/// Packet received from a client (decrypted).
pub struct InboundPacket {
    pub session_id: SessionId,
    pub data: Bytes,
    pub addr: SocketAddr,
}

/// Control message for workers.
/// Uses `Bytes` for zero-copy packet data sharing.
pub enum WorkerControl {
    /// Handshake init received - needs async handling
    HandshakeInit { data: Bytes, addr: SocketAddr },
    /// Handshake fragment received - needs reassembly before async handling.
    ///
    /// `data` is the full UDP datagram (outer `PacketHeader` + fragment body).
    /// The dispatcher parses the header, feeds the fragment into the
    /// server's reassembly buffer, and on completion synthesises a
    /// `HandshakeInit` / `EncryptedHandshakeInit` packet that re-enters
    /// the normal handshake flow. See
    /// [`hpn_core::protocol::fragment`] for the wire format.
    HandshakeFragment { data: Bytes, addr: SocketAddr },
    /// Keepalive received
    Keepalive {
        session_id: SessionId,
        data: Bytes,
        addr: SocketAddr,
    },
    /// Control message received
    Control {
        session_id: SessionId,
        data: Bytes,
        addr: SocketAddr,
    },
    /// Rekey request received
    Rekey {
        session_id: SessionId,
        data: Bytes,
        addr: SocketAddr,
    },
}

/// Network backend type for worker selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerBackend {
    /// io_uring async I/O (best for single-queue NICs).
    IoUring,
    /// recvmmsg/sendmmsg batched syscalls (fallback).
    BatchedSyscalls,
}

/// High-performance UDP worker pool.
pub struct UdpWorkerPool {
    /// Worker thread handles (kept alive, joined on drop).
    #[allow(dead_code)]
    workers: Vec<JoinHandle<()>>,
    /// Sender thread handles (kept alive, joined on drop).
    #[allow(dead_code)]
    senders: Vec<JoinHandle<()>>,
    /// Channel for sending packets to clients (needs encryption).
    /// NOTE: With inline encryption, this is only used for fallback/legacy path.
    outbound_tx: Sender<OutboundPacket>,
    /// Channel for sending raw responses (already encoded).
    response_tx: Sender<OutboundResponse>,
    /// Channel for receiving decrypted data packets (to TUN).
    pub inbound_rx: Receiver<Vec<u8>>,
    /// Channel for control messages that need async handling.
    pub control_rx: Receiver<WorkerControl>,
    /// Shutdown flag (atomic for lock-free checking).
    shutdown: Arc<AtomicBool>,
    /// Shared UDP sockets for inline encryption (TUN readers can send directly).
    #[cfg(target_os = "linux")]
    send_sockets: Vec<Arc<std::net::UdpSocket>>,
    /// Worker health tracker for panic recovery.
    #[allow(dead_code)]
    health_tracker: Option<Arc<WorkerHealthTracker>>,
}

impl UdpWorkerPool {
    /// Create a new UDP worker pool with auto-detected backend.
    ///
    /// # Arguments
    /// * `listen_addr` - Address to bind to
    /// * `num_workers` - Number of worker threads (typically num_cpus)
    /// * `sessions` - Shared session manager
    /// * `tun_write_tx` - Channel to send decrypted packets to TUN (pooled buffers)
    /// * `tun_buffer_pool` - Buffer pool for zero-copy packet processing
    /// * `metrics` - Server metrics for traffic statistics
    #[cfg(target_os = "linux")]
    pub fn new(
        listen_addr: SocketAddr,
        num_workers: usize,
        sessions: Arc<SessionManager>,
        tun_write_tx: Sender<PooledBuffer>,
        tun_buffer_pool: Arc<BufferPool>,
        metrics: Arc<ServerMetrics>,
    ) -> std::io::Result<Self> {
        // Production backend: recvmmsg/sendmmsg
        // Simple, proven, maximum compatibility.
        Self::new_with_backend(
            listen_addr,
            num_workers,
            sessions,
            tun_write_tx,
            tun_buffer_pool,
            WorkerBackend::BatchedSyscalls,
            metrics,
        )
    }

    /// Create a new UDP worker pool with specified backend.
    #[cfg(target_os = "linux")]
    pub fn new_with_backend(
        listen_addr: SocketAddr,
        num_workers: usize,
        sessions: Arc<SessionManager>,
        tun_write_tx: Sender<PooledBuffer>,
        tun_buffer_pool: Arc<BufferPool>,
        backend: WorkerBackend,
        metrics: Arc<ServerMetrics>,
    ) -> std::io::Result<Self> {
        use std::os::unix::io::AsRawFd;

        let shutdown = Arc::new(AtomicBool::new(false));

        // Channels for communication
        let (outbound_tx, outbound_rx) = bounded::<OutboundPacket>(CHANNEL_CAPACITY);
        let (response_tx, response_rx) = bounded::<OutboundResponse>(CHANNEL_CAPACITY);
        let (_inbound_tx, inbound_rx) = bounded::<Vec<u8>>(CHANNEL_CAPACITY);
        let (control_tx, control_rx) = bounded::<WorkerControl>(CHANNEL_CAPACITY);

        // Create shared socket for sending (we'll use one sender thread per socket)
        let mut sockets = Vec::with_capacity(num_workers);

        // Get high-throughput socket options (UDP_GRO enabled for both backends)
        let socket_opts = crate::socket_opts::SocketOptions::high_throughput();

        // Create SO_REUSEPORT sockets with optimizations
        for i in 0..num_workers {
            let socket = socket2::Socket::new(
                match listen_addr {
                    SocketAddr::V4(_) => socket2::Domain::IPV4,
                    SocketAddr::V6(_) => socket2::Domain::IPV6,
                },
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )?;

            // Enable SO_REUSEPORT for load balancing across threads
            socket.set_reuse_port(true)?;
            socket.set_reuse_address(true)?;

            // Set socket buffer sizes for high throughput
            socket.set_recv_buffer_size(socket_opts.recv_buffer_size)?;
            socket.set_send_buffer_size(socket_opts.send_buffer_size)?;

            // Bind to address
            socket.bind(&listen_addr.into())?;

            // Set non-blocking
            socket.set_nonblocking(true)?;

            let std_socket: std::net::UdpSocket = socket.into();

            // Apply additional optimizations (SO_BUSY_POLL, UDP_GRO, etc.)
            if let Err(e) = crate::socket_opts::optimize_udp_socket(&std_socket, &socket_opts) {
                warn!(
                    "Failed to apply socket optimizations for worker {}: {}",
                    i, e
                );
            }

            info!(
                "UDP worker {} bound to {} (fd={}, optimized)",
                i,
                listen_addr,
                std_socket.as_raw_fd()
            );
            sockets.push(Arc::new(std_socket));
        }

        let mut workers = Vec::with_capacity(num_workers);
        let mut senders = Vec::new();

        match backend {
            #[cfg(feature = "io_uring")]
            WorkerBackend::IoUring => {
                // io_uring: experimental, use HPN_BACKEND=io_uring to enable
                info!(
                    "Using EXPERIMENTAL io_uring backend for {} worker(s)",
                    num_workers
                );
                for (i, socket) in sockets.iter().enumerate() {
                    let socket = Arc::clone(socket);
                    let sessions = Arc::clone(&sessions);
                    let shutdown = Arc::clone(&shutdown);
                    let tun_write_tx = tun_write_tx.clone();
                    let control_tx = control_tx.clone();
                    let buffer_pool = Arc::clone(&tun_buffer_pool);
                    let outbound_rx = outbound_rx.clone();
                    let response_rx = response_rx.clone();
                    let metrics = Arc::clone(&metrics);
                    let worker_name = format!("udp-io_uring-{}", i);

                    let shutdown_for_recovery = Arc::clone(&shutdown);
                    let handle = std::thread::Builder::new()
                        .name(worker_name.clone())
                        .spawn(move || {
                            run_worker_with_panic_recovery(
                                worker_name,
                                None,
                                shutdown_for_recovery,
                                || {
                                    let socket = Arc::clone(&socket);
                                    let sessions = Arc::clone(&sessions);
                                    let shutdown = Arc::clone(&shutdown);
                                    let tun_write_tx = tun_write_tx.clone();
                                    let control_tx = control_tx.clone();
                                    let buffer_pool = Arc::clone(&buffer_pool);
                                    let outbound_rx = outbound_rx.clone();
                                    let response_rx = response_rx.clone();
                                    let metrics = Arc::clone(&metrics);
                                    AssertUnwindSafe(move || {
                                        run_io_uring_worker(
                                            i,
                                            socket,
                                            sessions,
                                            shutdown,
                                            tun_write_tx,
                                            control_tx,
                                            buffer_pool,
                                            outbound_rx,
                                            response_rx,
                                            metrics,
                                        );
                                    })
                                },
                            );
                        })
                        .map_err(|e| {
                            std::io::Error::other(format!(
                                "Failed to spawn io_uring worker {}: {}",
                                i, e
                            ))
                        })?;
                    workers.push(handle);
                }
            }
            #[allow(unreachable_patterns)]
            WorkerBackend::IoUring | WorkerBackend::BatchedSyscalls => {
                // recvmmsg/sendmmsg: production backend
                info!(
                    "Using recvmmsg/sendmmsg backend for {} worker(s) (production)",
                    num_workers
                );
                for (i, socket) in sockets.iter().enumerate() {
                    let socket = Arc::clone(socket);
                    let sessions = Arc::clone(&sessions);
                    let shutdown = Arc::clone(&shutdown);
                    let tun_write_tx = tun_write_tx.clone();
                    let control_tx = control_tx.clone();
                    let buffer_pool = Arc::clone(&tun_buffer_pool);
                    let worker_metrics = Arc::clone(&metrics);
                    let worker_name = format!("udp-recv-{}", i);

                    let shutdown_for_recovery = Arc::clone(&shutdown);
                    let handle = std::thread::Builder::new()
                        .name(worker_name.clone())
                        .spawn(move || {
                            run_worker_with_panic_recovery(
                                worker_name,
                                None,
                                shutdown_for_recovery,
                                || {
                                    let socket = Arc::clone(&socket);
                                    let sessions = Arc::clone(&sessions);
                                    let shutdown = Arc::clone(&shutdown);
                                    let tun_write_tx = tun_write_tx.clone();
                                    let control_tx = control_tx.clone();
                                    let buffer_pool = Arc::clone(&buffer_pool);
                                    let worker_metrics = Arc::clone(&worker_metrics);
                                    AssertUnwindSafe(move || {
                                        run_receiver_worker(
                                            i,
                                            socket,
                                            sessions,
                                            shutdown,
                                            tun_write_tx,
                                            control_tx,
                                            buffer_pool,
                                            worker_metrics,
                                        );
                                    })
                                },
                            );
                        })
                        .map_err(|e| {
                            std::io::Error::other(format!(
                                "Failed to spawn UDP receiver worker {}: {}",
                                i, e
                            ))
                        })?;
                    workers.push(handle);
                }

                // Spawn sender workers
                for (i, socket) in sockets.iter().enumerate() {
                    let socket = Arc::clone(socket);
                    let sessions = Arc::clone(&sessions);
                    let shutdown = Arc::clone(&shutdown);
                    let outbound_rx = outbound_rx.clone();
                    let response_rx = response_rx.clone();
                    let worker_metrics = Arc::clone(&metrics);
                    let worker_name = format!("udp-send-{}", i);

                    let shutdown_for_recovery = Arc::clone(&shutdown);
                    let handle = std::thread::Builder::new()
                        .name(worker_name.clone())
                        .spawn(move || {
                            run_worker_with_panic_recovery(
                                worker_name,
                                None,
                                shutdown_for_recovery,
                                || {
                                    let socket = Arc::clone(&socket);
                                    let sessions = Arc::clone(&sessions);
                                    let shutdown = Arc::clone(&shutdown);
                                    let outbound_rx = outbound_rx.clone();
                                    let response_rx = response_rx.clone();
                                    let worker_metrics = Arc::clone(&worker_metrics);
                                    AssertUnwindSafe(move || {
                                        run_sender_worker(
                                            i,
                                            socket,
                                            sessions,
                                            shutdown,
                                            outbound_rx,
                                            response_rx,
                                            worker_metrics,
                                        );
                                    })
                                },
                            );
                        })
                        .map_err(|e| {
                            std::io::Error::other(format!(
                                "Failed to spawn UDP sender worker {}: {}",
                                i, e
                            ))
                        })?;
                    senders.push(handle);
                }
            }
        }

        info!(
            "Started {} UDP worker(s) on {} with {:?} backend",
            num_workers, listen_addr, backend
        );

        // Clone sockets for TUN readers (inline encryption path)
        let send_sockets: Vec<Arc<std::net::UdpSocket>> = sockets.clone();

        Ok(Self {
            workers,
            senders,
            outbound_tx,
            response_tx,
            inbound_rx,
            control_rx,
            shutdown,
            send_sockets,
            health_tracker: None,
        })
    }

    /// Set the worker health tracker for panic recovery.
    ///
    /// When set, worker panics will be caught and reported to the health tracker
    /// instead of crashing the server. The server can then decide whether to
    /// continue in degraded mode or shutdown.
    pub fn set_health_tracker(&mut self, tracker: Arc<WorkerHealthTracker>) {
        self.health_tracker = Some(tracker);
    }

    /// Get the outbound channel sender for sending packets to clients.
    pub fn outbound_sender(&self) -> Sender<OutboundPacket> {
        self.outbound_tx.clone()
    }

    /// Get the response channel sender for sending raw responses (handshake, keepalive, etc.).
    pub fn response_sender(&self) -> Sender<OutboundResponse> {
        self.response_tx.clone()
    }

    /// Shutdown the worker pool.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Check if shutdown.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    /// Get a UDP socket for inline encryption (TUN readers can send directly).
    /// Returns socket at index % num_sockets for load distribution.
    #[cfg(target_os = "linux")]
    pub fn get_send_socket(&self, index: usize) -> Arc<std::net::UdpSocket> {
        let idx = index % self.send_sockets.len();
        Arc::clone(&self.send_sockets[idx])
    }

    /// Get the number of available send sockets.
    #[cfg(target_os = "linux")]
    pub fn num_send_sockets(&self) -> usize {
        self.send_sockets.len()
    }
}

impl Drop for UdpWorkerPool {
    fn drop(&mut self) {
        info!("UdpWorkerPool shutdown initiated");

        // Signal shutdown to all workers
        self.shutdown.store(true, Ordering::SeqCst);

        // Give workers a moment to notice shutdown signal
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Join receiver workers
        let workers = std::mem::take(&mut self.workers);
        for (i, handle) in workers.into_iter().enumerate() {
            let thread_start = std::time::Instant::now();
            let thread_timeout = std::time::Duration::from_secs(2);

            loop {
                if handle.is_finished() {
                    match handle.join() {
                        Ok(()) => {
                            debug!("UDP receiver worker {} joined successfully", i);
                        }
                        Err(_) => {
                            warn!("UDP receiver worker {} panicked during shutdown", i);
                        }
                    }
                    break;
                }

                if thread_start.elapsed() >= thread_timeout {
                    warn!("UDP receiver worker {} did not finish within timeout", i);
                    break;
                }

                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }

        // Join sender workers
        let senders = std::mem::take(&mut self.senders);
        for (i, handle) in senders.into_iter().enumerate() {
            let thread_start = std::time::Instant::now();
            let thread_timeout = std::time::Duration::from_secs(2);

            loop {
                if handle.is_finished() {
                    match handle.join() {
                        Ok(()) => {
                            debug!("UDP sender worker {} joined successfully", i);
                        }
                        Err(_) => {
                            warn!("UDP sender worker {} panicked during shutdown", i);
                        }
                    }
                    break;
                }

                if thread_start.elapsed() >= thread_timeout {
                    warn!("UDP sender worker {} did not finish within timeout", i);
                    break;
                }

                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }

        info!("UdpWorkerPool shutdown complete");
    }
}

/// Maximum restarts per worker before giving up.
const MAX_WORKER_RESTARTS: u32 = 3;
/// Cooldown between worker restarts (doubles each time).
const RESTART_BASE_DELAY_MS: u64 = 500;

/// Run a worker function with panic recovery and automatic restart.
///
/// Wraps the worker function with `catch_unwind`. On panic:
/// - Logs the panic with full details
/// - Records panic in health tracker (if provided)
/// - Automatically restarts the worker (up to `MAX_WORKER_RESTARTS` times)
/// - Exponential backoff between restarts (500ms, 1s, 2s)
/// - Worker data must be in `Arc`s (cloned per-restart) — the factory `f`
///   is called each time to produce a fresh closure.
fn run_worker_with_panic_recovery<F, G>(
    worker_name: String,
    health_tracker: Option<Arc<WorkerHealthTracker>>,
    shutdown: Arc<AtomicBool>,
    f: F,
) where
    F: Fn() -> G,
    G: FnOnce() + std::panic::UnwindSafe,
{
    let mut restart_count = 0u32;

    loop {
        let worker_fn = f();
        let result = catch_unwind(worker_fn);

        match result {
            Ok(()) => break, // Worker exited normally (shutdown)
            Err(panic_info) => {
                let panic_msg = WorkerHealthTracker::extract_panic_message(&panic_info);
                error!("PANIC in worker '{}': {}", worker_name, panic_msg);

                if let Some(ref tracker) = health_tracker {
                    tracker.record_panic(&worker_name, &panic_msg);
                }

                restart_count += 1;

                if shutdown.load(Ordering::Relaxed) {
                    info!(
                        "Worker '{}' not restarting (shutdown in progress)",
                        worker_name
                    );
                    break;
                }

                if restart_count > MAX_WORKER_RESTARTS {
                    error!(
                        "Worker '{}' exceeded max restarts ({}), giving up",
                        worker_name, MAX_WORKER_RESTARTS
                    );
                    break;
                }

                let delay_ms = RESTART_BASE_DELAY_MS * (1 << (restart_count - 1));
                warn!(
                    "Restarting worker '{}' in {}ms (attempt {}/{})",
                    worker_name, delay_ms, restart_count, MAX_WORKER_RESTARTS
                );

                if let Some(ref tracker) = health_tracker {
                    tracker.metrics.record_worker_restart();
                }

                std::thread::sleep(std::time::Duration::from_millis(delay_ms));
            }
        }
    }
}

/// Statistics for worker performance monitoring.
///
/// Each counter is `CachePadded` so cross-worker `fetch_add` calls
/// don't ricochet between cores via MESI invalidations on shared
/// cache lines (false sharing). `CachePadded<T>` implements
/// `Deref<Target=T>` so callers can keep using
/// `stats.packets_received.fetch_add(1, ...)` unchanged.
///
/// `Default` is derived: `CachePadded<T>: Default` whenever `T: Default`,
/// and `AtomicU64::default()` returns `AtomicU64::new(0)`. The derive
/// gives identical behaviour to a hand-written `impl` with much less
/// boilerplate; mirrors the same pattern on `AfXdpPoolStats` in
/// `afxdp_workers.rs`.
#[derive(Default)]
pub struct WorkerStats {
    /// Total packets received.
    pub packets_received: CachePadded<AtomicU64>,
    /// Total batches processed (recvmmsg calls).
    pub batches_received: CachePadded<AtomicU64>,
    /// Total packets sent.
    pub packets_sent: CachePadded<AtomicU64>,
    /// Total batches sent (sendmmsg calls).
    pub batches_sent: CachePadded<AtomicU64>,
}

/// Sync interval for local worker stats to global ServerMetrics.
/// Using 5 seconds provides good granularity without CPU overhead.
const METRICS_SYNC_INTERVAL: Duration = Duration::from_secs(5);

/// Local per-worker statistics with periodic sync to ServerMetrics.
///
/// This avoids atomic contention on the hot path by using local counters
/// and syncing to the global metrics every few seconds.
struct LocalWorkerStats {
    /// Packets received (decrypted successfully).
    rx_packets: u64,
    /// Packets sent (encrypted).
    tx_packets: u64,
    /// Bytes received (decrypted payload size).
    rx_bytes: u64,
    /// Bytes sent (encrypted packet size).
    tx_bytes: u64,
    /// Last sync time.
    last_sync: Instant,
    /// Reference to global metrics for periodic sync.
    metrics: Arc<ServerMetrics>,
}

impl LocalWorkerStats {
    /// Create new local stats with reference to global metrics.
    fn new(metrics: Arc<ServerMetrics>) -> Self {
        Self {
            rx_packets: 0,
            tx_packets: 0,
            rx_bytes: 0,
            tx_bytes: 0,
            last_sync: Instant::now(),
            metrics,
        }
    }

    /// Record a received packet (fast path - just local increment).
    #[inline]
    fn record_rx(&mut self, bytes: usize) {
        self.rx_packets += 1;
        self.rx_bytes += bytes as u64;
    }

    // Note: TX metrics are recorded via direct field access in run_sender_worker
    // to allow efficient batch updates (tx_packets += sent, tx_bytes += batch_bytes).

    /// Sync to global metrics if interval elapsed.
    /// Called periodically in the worker loop (e.g., after each batch).
    #[inline]
    fn maybe_sync(&mut self) {
        if self.last_sync.elapsed() >= METRICS_SYNC_INTERVAL {
            self.force_sync();
        }
    }

    /// Force sync to global metrics (called on worker shutdown).
    fn force_sync(&mut self) {
        if self.rx_packets > 0 || self.tx_packets > 0 {
            self.metrics
                .record_packets(self.tx_packets, self.rx_packets);
            self.metrics.record_bytes(self.tx_bytes, self.rx_bytes);
            self.rx_packets = 0;
            self.tx_packets = 0;
            self.rx_bytes = 0;
            self.tx_bytes = 0;
        }
        self.last_sync = Instant::now();
    }
}

/// Pin the calling worker thread to a CPU core, modulo the number of
/// online CPUs.
///
/// Without pinning, the kernel scheduler is free to migrate every UDP
/// receiver/sender thread between cores at every wakeup, which kills
/// L1/L2 cache locality on the hot path (recvmmsg buffer pool, session
/// dashmap shards, RecvBatch / SendBatch internal arrays). Pinning each
/// worker `i` to `i % num_cpus` keeps every worker's working set on
/// the same core for its lifetime; combined with `SO_REUSEPORT` (one
/// kernel queue per core), this gives the data plane a clean
/// "per-core pipeline" topology and measurably reduces tail latency
/// under load.
///
/// Failures are logged at `debug!` and ignored — the worker continues
/// without affinity. Common reasons for failure on Linux: the calling
/// process was started by `systemd` with a CPUAffinity= mask narrower
/// than what we tried to set (the call returns EINVAL); on those
/// hosts, the systemd unit's affinity wins and we honour it
/// implicitly.
#[cfg(target_os = "linux")]
#[inline]
fn pin_worker_to_cpu(role: &str, worker_id: usize) {
    let cpus = hpn_core::perf::affinity::num_cpus();
    if cpus == 0 {
        return;
    }
    let target = worker_id % cpus;
    match hpn_core::perf::affinity::set_thread_affinity(target) {
        Ok(()) => debug!(
            "UDP {} worker {} pinned to CPU {} (of {} online)",
            role, worker_id, target, cpus
        ),
        Err(e) => debug!(
            "UDP {} worker {}: CPU affinity set_thread_affinity({}) failed: {} \
             (continuing without pinning — likely a systemd CPUAffinity= mask)",
            role, worker_id, target, e
        ),
    }
}

/// Run a receiver worker thread using recvmmsg for syscall batching.
#[cfg(target_os = "linux")]
fn run_receiver_worker(
    worker_id: usize,
    socket: Arc<std::net::UdpSocket>,
    sessions: Arc<SessionManager>,
    shutdown: Arc<AtomicBool>,
    tun_write_tx: Sender<PooledBuffer>,
    control_tx: Sender<WorkerControl>,
    buffer_pool: Arc<BufferPool>,
    metrics: Arc<ServerMetrics>,
) {
    pin_worker_to_cpu("receiver", worker_id);

    info!(
        "UDP receiver worker {} started (recvmmsg batch={}, zero-copy)",
        worker_id, MAX_BATCH_SIZE
    );

    // Pre-allocate recvmmsg batch receiver
    let mut recv_batch = RecvMmsg::new(MAX_BATCH_SIZE, MAX_PACKET_SIZE);
    let mut consecutive_empty = 0u32;
    let mut total_packets: u64 = 0;
    let mut total_batches: u64 = 0;

    // Local stats with periodic sync (every 5s) to avoid atomic contention
    let mut local_stats = LocalWorkerStats::new(metrics);

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Receive multiple packets in single syscall
        match recv_batch.recv(&socket) {
            Ok(count) if count > 0 => {
                consecutive_empty = 0;
                total_batches += 1;

                // Process all received packets, handling GRO-coalesced buffers
                // using the proper gso_size from UDP_GRO control message
                for i in 0..count {
                    let (data, addr_opt, gso_size) = recv_batch.get(i);

                    // If gso_size > 0, this is a GRO-coalesced buffer that needs splitting
                    if gso_size > 0 && (gso_size as usize) < data.len() {
                        // GRO detected: split into segments of gso_size bytes
                        for (segment, seg_addr) in GsoSegmentIter::new(data, addr_opt, gso_size) {
                            total_packets += 1;
                            if let Some(addr) = seg_addr {
                                process_packet(
                                    worker_id,
                                    segment,
                                    addr,
                                    &sessions,
                                    &tun_write_tx,
                                    &control_tx,
                                    &buffer_pool,
                                    &mut local_stats,
                                );
                            }
                        }
                    } else {
                        // Single packet (not GRO-coalesced, or gso_size covers entire buffer)
                        total_packets += 1;
                        if let Some(addr) = addr_opt {
                            process_packet(
                                worker_id,
                                data,
                                addr,
                                &sessions,
                                &tun_write_tx,
                                &control_tx,
                                &buffer_pool,
                                &mut local_stats,
                            );
                        }
                    }
                }

                // Periodic sync to global metrics (every 5s)
                local_stats.maybe_sync();
            }
            Ok(_) => {
                consecutive_empty += 1;
            }
            Err(e) => {
                if !shutdown.load(Ordering::Relaxed) {
                    warn!("UDP recvmmsg error in worker {}: {}", worker_id, e);
                }
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

    // Final sync on shutdown
    local_stats.force_sync();

    info!(
        "UDP receiver worker {} stopped (packets: {}, batches: {}, avg: {:.1}/batch)",
        worker_id,
        total_packets,
        total_batches,
        if total_batches > 0 {
            total_packets as f64 / total_batches as f64
        } else {
            0.0
        }
    );
}

/// Process a single packet.
/// Uses zero-copy buffer pooling for data packets to avoid allocation overhead.
#[cfg(target_os = "linux")]
fn process_packet(
    _worker_id: usize,
    data: &[u8],
    addr: SocketAddr,
    sessions: &SessionManager,
    tun_write_tx: &Sender<PooledBuffer>,
    control_tx: &Sender<WorkerControl>,
    buffer_pool: &BufferPool,
    local_stats: &mut LocalWorkerStats,
) {
    if data.len() < HEADER_SIZE {
        return;
    }

    let header = match PacketHeader::decode(data) {
        Ok(h) => h,
        Err(_) => return,
    };

    match header.msg_type {
        MessageType::Data => {
            // Fast path: decrypt and forward to TUN using pooled buffer (zero-copy)
            let session_id = header.session_id;

            let session_guard = match sessions.get_session(session_id) {
                Some(s) => s,
                None => {
                    trace!("Unknown session {} from {}", session_id, addr);
                    return;
                }
            };

            // Snapshot roaming state. Both the rebind AND the rate-limit
            // token consumption are deferred until AFTER successful AEAD
            // decryption below, to prevent a spoofed-source-IP packet bearing
            // a known SessionId from hijacking the return path or draining
            // the legitimate client's rate-limit tokens.
            let current_addr = *session_guard.client_addr.lock();
            let addr_changed = current_addr != addr;

            // Get a pooled buffer for decryption (zero-copy: no allocation)
            let mut pooled_buf = buffer_pool.get();

            // Decrypt packet directly into pooled buffer (authenticates sender via AEAD tag).
            let (_, len) = match session_guard
                .session
                .decrypt_packet(data, pooled_buf.as_mut_slice())
            {
                Ok(r) => r,
                Err(e) => {
                    local_stats.metrics.decryption_errors.inc();
                    tracing::trace!(
                        "Decryption failed for session {} from {}: {:?}",
                        session_id,
                        addr,
                        e
                    );
                    return;
                }
            };

            // FIX-010: refuse to rebind on a Data packet, even after AEAD
            // success. An attacker who captures a single fresh data packet
            // and replays it from a spoofed source IP would otherwise hijack
            // the return path silently. Legitimate roaming has to travel
            // through `ControlType::Rebind`, which is the only path
            // authorised to call `update_client_addr`.
            //
            // Drops here surface on `hpn_address_mismatch_drops_total`
            // (F-1 follow-up); the same call also bumps the legacy
            // `hpn_packets_dropped_total` so existing alerts keep working.
            if addr_changed {
                debug!(
                    "Address mismatch on data path for session {} ({} vs {}) — dropping (FIX-010)",
                    session_id, current_addr, addr
                );
                local_stats.metrics.record_address_mismatch_drop();
                return;
            }

            // Per-session rate limiting (consumes tokens). Now safe to call
            // because the AEAD tag proves the sender holds session keys.
            if !session_guard.check_rate_limit(len) {
                local_stats.metrics.record_session_rate_limited();
                trace!("Session {} rate limited (packet size: {})", session_id, len);
                return;
            }

            // Validate source IP in decrypted packet matches client's tunnel IP.
            // This prevents a malicious client from spoofing source IPs.
            if len > 0 {
                let buf = &pooled_buf.as_mut_slice()[..len];
                let ip_version = buf[0] >> 4;
                let valid_src = match ip_version {
                    4 if len >= 20 => buf[12..16] == session_guard.tunnel_ip,
                    6 if len >= 40 => match &session_guard.tunnel_ipv6 {
                        Some(ipv6) => buf[8..24] == *ipv6,
                        None => false, // IPv6 packet but no IPv6 assigned
                    },
                    _ => false,
                };
                if !valid_src {
                    // Track mismatch count per session to avoid log spam during TUN init.
                    // First few mismatches are normal as the client's routing converges.
                    let mismatch_count = session_guard.increment_src_mismatch();
                    if mismatch_count <= 3 {
                        // Log detailed info for first few occurrences only
                        let packet_src = if ip_version == 4 && len >= 20 {
                            format!("{}.{}.{}.{}", buf[12], buf[13], buf[14], buf[15])
                        } else if ip_version == 6 && len >= 40 {
                            format!("IPv6:{:02x}{:02x}:...", buf[8], buf[9])
                        } else {
                            format!("unknown(v{}, len={})", ip_version, len)
                        };
                        let expected = format!(
                            "{}.{}.{}.{}",
                            session_guard.tunnel_ip[0],
                            session_guard.tunnel_ip[1],
                            session_guard.tunnel_ip[2],
                            session_guard.tunnel_ip[3]
                        );
                        tracing::debug!(
                            "Source IP mismatch #{} for session {} from {}: got {} expected {} (normal during TUN init)",
                            mismatch_count,
                            session_id,
                            addr,
                            packet_src,
                            expected
                        );
                    }
                    return;
                }
            }

            // Record RX metrics (local counter, synced every 5s)
            local_stats.record_rx(len);

            session_guard.touch();
            session_guard.add_bytes_received(data.len() as u64);
            drop(session_guard);

            // Set the valid data length and send to TUN
            pooled_buf.set_len(len);
            if let Err(e) = tun_write_tx.try_send(pooled_buf) {
                trace!("TUN write channel full: {}", e);
                // pooled_buf auto-returns to pool on drop (from channel error)
            }
        }
        MessageType::HandshakeInit | MessageType::EncryptedHandshakeInit => {
            // Send to control channel for async handling
            // Both regular and encrypted handshakes use the same control message;
            // the server distinguishes them by the message type in the header
            // Bytes::copy_from_slice is efficient: single allocation + memcpy
            let _ = control_tx.try_send(WorkerControl::HandshakeInit {
                data: Bytes::copy_from_slice(data),
                addr,
            });
        }
        MessageType::HandshakeFragment => {
            // Fragmented handshake (PQ handshakes can exceed MTU; see
            // `hpn_core::protocol::fragment`). The async handler owns
            // the reassembly buffer and synthesises a `HandshakeInit`
            // packet once all fragments have arrived.
            let _ = control_tx.try_send(WorkerControl::HandshakeFragment {
                data: Bytes::copy_from_slice(data),
                addr,
            });
        }
        MessageType::Keepalive => {
            let _ = control_tx.try_send(WorkerControl::Keepalive {
                session_id: header.session_id,
                data: Bytes::copy_from_slice(data),
                addr,
            });
        }
        MessageType::Control => {
            let _ = control_tx.try_send(WorkerControl::Control {
                session_id: header.session_id,
                data: Bytes::copy_from_slice(data),
                addr,
            });
        }
        MessageType::Rekey => {
            let _ = control_tx.try_send(WorkerControl::Rekey {
                session_id: header.session_id,
                data: Bytes::copy_from_slice(data),
                addr,
            });
        }
        _ => {
            debug!("Unhandled message type {:?} from {}", header.msg_type, addr);
        }
    }
}

/// Run a sender worker thread using sendmmsg for syscall batching.
#[cfg(target_os = "linux")]
fn run_sender_worker(
    worker_id: usize,
    socket: Arc<std::net::UdpSocket>,
    sessions: Arc<SessionManager>,
    shutdown: Arc<AtomicBool>,
    outbound_rx: Receiver<OutboundPacket>,
    response_rx: Receiver<OutboundResponse>,
    metrics: Arc<ServerMetrics>,
) {
    pin_worker_to_cpu("sender", worker_id);

    info!(
        "UDP sender worker {} started (sendmmsg batch={}, zero-copy encryption)",
        worker_id, MAX_SEND_BATCH_SIZE
    );

    // Pre-allocate sendmmsg batch sender with buffers for zero-copy encryption.
    // TX batch is capped at MAX_SEND_BATCH_SIZE (64) rather than
    // MAX_BATCH_SIZE (256) to keep p99 send latency tight — see constant
    // docs for rationale.
    let mut send_batch = SendMmsg::new(MAX_SEND_BATCH_SIZE, MAX_PACKET_SIZE);
    let mut consecutive_empty = 0u32;
    let mut total_packets: u64 = 0;
    let mut total_batches: u64 = 0;

    // Local stats with periodic sync (every 5s) to avoid atomic contention
    let mut local_stats = LocalWorkerStats::new(metrics);

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Batch process outbound packets with zero-copy encryption
        let mut queued_any = false;
        let mut empty_spins = 0u32;
        const MAX_EMPTY_SPINS: u32 = 8; // Brief spin-wait to maximize batch size
        // Track bytes per batch for metrics (accumulated during batch building)
        let mut batch_tx_bytes: u64 = 0;

        // Collect packets for batch sending - encrypt directly into sendmmsg buffers
        // Use spin-wait to allow more packets to arrive, improving batch efficiency.
        while send_batch.len() < MAX_SEND_BATCH_SIZE {
            // Get buffer for zero-copy encryption
            let encrypt_buf = match send_batch.get_buffer_mut() {
                Some(buf) => buf,
                None => break, // Batch full
            };

            match outbound_rx.try_recv() {
                Ok(packet) => {
                    queued_any = true;
                    empty_spins = 0; // Reset spin counter on success
                    // Zero-copy: encrypt directly into sendmmsg buffer
                    if let Some((len, addr)) =
                        encrypt_packet_zero_copy(&sessions, &packet, encrypt_buf)
                    {
                        send_batch.commit(len, addr);
                        batch_tx_bytes += len as u64;
                    }
                }
                Err(crossbeam_channel::TryRecvError::Empty) => {
                    // If we have packets and hit empty, spin briefly for more
                    if queued_any && empty_spins < MAX_EMPTY_SPINS {
                        empty_spins += 1;
                        std::hint::spin_loop();
                        continue;
                    }
                    break;
                }
                Err(crossbeam_channel::TryRecvError::Disconnected) => {
                    local_stats.force_sync();
                    info!("UDP sender {}: outbound channel disconnected", worker_id);
                    return;
                }
            }
        }

        // Also collect raw responses
        for _ in 0..MAX_SEND_BATCH_SIZE {
            if send_batch.is_full() {
                break;
            }

            match response_rx.try_recv() {
                Ok(response) => {
                    queued_any = true;
                    batch_tx_bytes += response.data.len() as u64;
                    send_batch.add(&response.data, response.addr);
                }
                Err(crossbeam_channel::TryRecvError::Empty) => break,
                Err(crossbeam_channel::TryRecvError::Disconnected) => {
                    local_stats.force_sync();
                    info!("UDP sender {}: response channel disconnected", worker_id);
                    return;
                }
            }
        }

        // Flush batch if we have any packets
        if !send_batch.is_empty() {
            let batch_count = send_batch.len();
            match send_batch.flush(&*socket) {
                Ok(sent) => {
                    if sent > 0 {
                        total_packets += sent as u64;
                        total_batches += 1;

                        // Record TX metrics for successfully sent packets
                        // Note: We record the full batch_tx_bytes assuming all packets sent.
                        // For partial sends, this slightly overestimates but is acceptable for metrics.
                        for _ in 0..sent {
                            local_stats.tx_packets += 1;
                        }
                        local_stats.tx_bytes += batch_tx_bytes;
                    }
                    if sent < batch_count {
                        trace!(
                            "UDP sender {}: partial sendmmsg {}/{}",
                            worker_id, sent, batch_count
                        );
                    }
                }
                Err(e) => {
                    trace!("UDP sendmmsg error in worker {}: {}", worker_id, e);
                }
            }

            // Periodic sync to global metrics (every 5s)
            local_stats.maybe_sync();
        }

        if queued_any {
            consecutive_empty = 0;
        } else {
            consecutive_empty += 1;
            if consecutive_empty > 1000 {
                std::thread::sleep(std::time::Duration::from_micros(100));
            } else if consecutive_empty > 100 {
                std::thread::sleep(std::time::Duration::from_micros(10));
            } else {
                std::hint::spin_loop();
            }
        }
    }

    // Final sync on shutdown
    local_stats.force_sync();

    info!(
        "UDP sender worker {} stopped (packets: {}, batches: {}, avg: {:.1}/batch)",
        worker_id,
        total_packets,
        total_batches,
        if total_batches > 0 {
            total_packets as f64 / total_batches as f64
        } else {
            0.0
        }
    );
}

/// Zero-copy encryption: encrypt directly into the provided buffer.
/// Returns (encrypted_length, client_address) on success.
#[cfg(target_os = "linux")]
/// Encrypt packet using cached client_addr from OutboundPacket.
/// This eliminates the second session lookup that was causing download path slowdown.
#[inline]
fn encrypt_packet_zero_copy(
    sessions: &SessionManager,
    packet: &OutboundPacket,
    encrypt_buf: &mut [u8],
) -> Option<(usize, SocketAddr)> {
    // Use cached client_addr from packet (set during TUN read)
    // This avoids a redundant DashMap lookup
    let session_guard = sessions.get_session(packet.session_id)?;

    let len = session_guard
        .session
        .encrypt_packet(MessageType::Data, &packet.data, encrypt_buf)
        .ok()?;

    // Use cached address instead of reading from session
    Some((len, packet.client_addr))
}

/// Encrypt a packet for batch sending and return data + address.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
fn encrypt_packet_for_batch<'a>(
    sessions: &SessionManager,
    packet: OutboundPacket,
    encrypt_buf: &'a mut [u8],
) -> Option<(&'a [u8], SocketAddr)> {
    let session_guard = sessions.get_session(packet.session_id)?;

    let len = session_guard
        .session
        .encrypt_packet(MessageType::Data, &packet.data, encrypt_buf)
        .ok()?;

    drop(session_guard);
    // Use cached address from packet
    Some((&encrypt_buf[..len], packet.client_addr))
}

// Legacy send_packet() removed — replaced by encrypt_packet_zero_copy() for
// batch sendmmsg path and encrypt_packet_for_batch() for io_uring.

// ============================================================================
// io_uring-based worker (optional, requires Linux >= 5.6 and io_uring feature)
// ============================================================================

/// Run an io_uring-based combined receive/send worker.
/// This provides ~50% higher throughput than recvmmsg/sendmmsg on supported kernels.
#[cfg(all(target_os = "linux", feature = "io_uring"))]
pub fn run_io_uring_worker(
    worker_id: usize,
    socket: Arc<std::net::UdpSocket>,
    sessions: Arc<SessionManager>,
    shutdown: Arc<AtomicBool>,
    tun_write_tx: Sender<PooledBuffer>,
    control_tx: Sender<WorkerControl>,
    buffer_pool: Arc<BufferPool>,
    outbound_rx: Receiver<OutboundPacket>,
    response_rx: Receiver<OutboundResponse>,
    metrics: Arc<ServerMetrics>,
) {
    use crate::io_uring_udp::{DEFAULT_RING_SIZE, IoUringUdp};

    info!(
        "UDP io_uring worker {} starting (ring_size={})",
        worker_id, DEFAULT_RING_SIZE
    );

    // Create io_uring handler
    let mut io_uring = match IoUringUdp::with_defaults(&*socket) {
        Ok(ring) => ring,
        Err(e) => {
            warn!(
                "Failed to create io_uring for worker {}: {}. Falling back to recvmmsg.",
                worker_id, e
            );
            // Fall back to regular worker
            let socket_clone = Arc::clone(&socket);
            let sessions_clone = Arc::clone(&sessions);
            let shutdown_clone = Arc::clone(&shutdown);
            let buffer_pool_clone = Arc::clone(&buffer_pool);
            let metrics_clone = Arc::clone(&metrics);

            // Start separate recv and send workers
            std::thread::spawn(move || {
                run_receiver_worker(
                    worker_id,
                    socket_clone,
                    sessions_clone,
                    shutdown_clone,
                    tun_write_tx,
                    control_tx,
                    buffer_pool_clone,
                    metrics_clone,
                );
            });
            run_sender_worker(
                worker_id,
                socket,
                sessions,
                shutdown,
                outbound_rx,
                response_rx,
                metrics,
            );
            return;
        }
    };

    info!(
        "UDP io_uring worker {} started successfully (SQPOLL enabled if root)",
        worker_id
    );

    // Pre-allocate encrypt buffer
    let mut encrypt_buf = vec![0u8; MAX_PACKET_SIZE + HEADER_SIZE + aead::TAG_SIZE + 32];
    let mut consecutive_empty = 0u32;
    let mut total_received: u64 = 0;
    let mut total_sent: u64 = 0;

    // Submit initial recv operations
    if let Err(e) = io_uring.submit_recvs() {
        warn!(
            "io_uring worker {}: failed to submit initial recvs: {}",
            worker_id, e
        );
    }

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Process outbound packets (from TUN)
        let mut sent_any = false;
        for _ in 0..64 {
            // Process up to 64 outbound packets per iteration
            match outbound_rx.try_recv() {
                Ok(packet) => {
                    if let Some((data, addr)) =
                        encrypt_packet_for_batch(&sessions, packet, &mut encrypt_buf)
                    {
                        if let Err(e) = io_uring.queue_send(data, addr) {
                            trace!("io_uring queue_send error: {}", e);
                        } else {
                            sent_any = true;
                        }
                    }
                }
                Err(crossbeam_channel::TryRecvError::Empty) => break,
                Err(crossbeam_channel::TryRecvError::Disconnected) => {
                    info!(
                        "io_uring worker {}: outbound channel disconnected",
                        worker_id
                    );
                    io_uring.shutdown();
                    break;
                }
            }
        }

        // Process raw response packets (handshake responses, etc.)
        for _ in 0..16 {
            match response_rx.try_recv() {
                Ok(response) => {
                    if let Err(e) = io_uring.queue_send(&response.data, response.addr) {
                        trace!("io_uring queue_send response error: {}", e);
                    } else {
                        sent_any = true;
                    }
                }
                Err(crossbeam_channel::TryRecvError::Empty) => break,
                Err(crossbeam_channel::TryRecvError::Disconnected) => break,
            }
        }

        // Flush pending sends
        if sent_any && let Err(e) = io_uring.flush() {
            trace!("io_uring flush error: {}", e);
        }

        // Process completions (both recv and send)
        match io_uring.poll_completions() {
            Ok(packets) => {
                for packet in packets {
                    // Handle GRO-coalesced packets by splitting them
                    if packet.gso_size > 0 && (packet.gso_size as usize) < packet.data.len() {
                        // GRO detected: split into segments
                        for (segment, seg_addr) in
                            GsoSegmentIter::new(&packet.data, Some(packet.addr), packet.gso_size)
                        {
                            total_received += 1;
                            if let Some(addr) = seg_addr {
                                process_io_uring_segment(
                                    segment,
                                    addr,
                                    &sessions,
                                    &tun_write_tx,
                                    &control_tx,
                                    &buffer_pool,
                                    &metrics,
                                );
                            }
                        }
                    } else {
                        // Single packet (not GRO-coalesced)
                        total_received += 1;
                        process_io_uring_segment(
                            &packet.data,
                            packet.addr,
                            &sessions,
                            &tun_write_tx,
                            &control_tx,
                            &buffer_pool,
                            &metrics,
                        );
                    }
                }
            }
            Err(e) => {
                trace!("io_uring poll_completions error: {}", e);
            }
        }

        // Update stats
        let stats = io_uring.stats();
        total_sent = stats.packets_sent;

        // Re-submit recv operations for completed buffers
        if let Err(e) = io_uring.submit_recvs() {
            trace!("io_uring submit_recvs error: {}", e);
        }

        // Adaptive sleeping
        if !sent_any && total_received == 0 {
            consecutive_empty += 1;
            if consecutive_empty > 1000 {
                std::thread::sleep(std::time::Duration::from_micros(100));
            } else if consecutive_empty > 100 {
                std::thread::sleep(std::time::Duration::from_micros(10));
            } else {
                std::hint::spin_loop();
            }
        } else {
            consecutive_empty = 0;
        }
    }

    info!(
        "UDP io_uring worker {} stopped (received: {}, sent: {})",
        worker_id, total_received, total_sent
    );
}

/// Process a data packet received via io_uring.
#[cfg(all(target_os = "linux", feature = "io_uring"))]
fn process_data_packet_io_uring(
    data: &[u8],
    addr: SocketAddr,
    header: PacketHeader,
    sessions: &SessionManager,
    tun_write_tx: &Sender<PooledBuffer>,
    buffer_pool: &BufferPool,
    metrics: &ServerMetrics,
) {
    let session_id = header.session_id;

    // Debug: log packet info
    trace!(
        "io_uring data packet: session={:x}, len={}, counter={:?}, key_id={}",
        session_id.0,
        data.len(),
        header.counter,
        header.key_id.0
    );

    let session_guard = match sessions.get_session(session_id) {
        Some(s) => s,
        None => {
            trace!("Unknown session {} from {}", session_id, addr);
            return;
        }
    };

    // Snapshot roaming state. Both the rebind and the rate-limit token
    // consumption are deferred until AFTER successful AEAD decryption below,
    // to prevent a spoofed-source-IP packet bearing a known SessionId from
    // hijacking the return path or draining the legitimate client's
    // rate-limit tokens.
    let current_addr = *session_guard.client_addr.lock();
    let addr_changed = current_addr != addr;

    // Get a pooled buffer for decryption (zero-copy: no allocation)
    let mut pooled_buf = buffer_pool.get();

    // Decrypt packet directly into pooled buffer (authenticates sender via AEAD tag).
    let (_, len) = match session_guard
        .session
        .decrypt_packet(data, pooled_buf.as_mut_slice())
    {
        Ok(r) => r,
        Err(e) => {
            metrics.decryption_errors.inc();
            tracing::trace!(
                "Decryption failed for session {} from {}: {:?}",
                session_id,
                addr,
                e
            );
            return;
        }
    };

    // FIX-010: same invariant as the standard data path above — refuse to
    // rebind on Data, even after AEAD success. Legitimate roaming has to go
    // through ControlType::Rebind.
    if addr_changed {
        debug!(
            "Address mismatch on io_uring data path for session {} ({} vs {}) — dropping (FIX-010)",
            session_id, current_addr, addr
        );
        metrics.record_address_mismatch_drop();
        return;
    }

    // Per-session rate limiting (consumes tokens). Now safe to call because
    // the AEAD tag proves the sender holds session keys.
    if !session_guard.check_rate_limit(len) {
        metrics.record_session_rate_limited();
        trace!("Session {} rate limited (packet size: {})", session_id, len);
        return;
    }

    // Validate source IP in decrypted packet matches client's tunnel IP.
    // This prevents a malicious client from spoofing source IPs.
    if len > 0 {
        let buf = &pooled_buf.as_mut_slice()[..len];
        let ip_version = buf[0] >> 4;
        let valid_src = match ip_version {
            4 if len >= 20 => buf[12..16] == session_guard.tunnel_ip,
            6 if len >= 40 => match &session_guard.tunnel_ipv6 {
                Some(ipv6) => buf[8..24] == *ipv6,
                None => false,
            },
            _ => false,
        };
        if !valid_src {
            tracing::warn!(
                "Source IP mismatch for session {} from {}: packet dropped",
                session_id,
                addr
            );
            return;
        }
    }

    session_guard.touch();
    session_guard.add_bytes_received(data.len() as u64);
    drop(session_guard);

    // Send decrypted packet to TUN
    pooled_buf.set_len(len);
    let _ = tun_write_tx.try_send(pooled_buf);
}

/// Process a single segment from io_uring (handles GRO splitting).
#[cfg(all(target_os = "linux", feature = "io_uring"))]
fn process_io_uring_segment(
    data: &[u8],
    addr: SocketAddr,
    sessions: &SessionManager,
    tun_write_tx: &Sender<PooledBuffer>,
    control_tx: &Sender<WorkerControl>,
    buffer_pool: &BufferPool,
    metrics: &ServerMetrics,
) {
    if data.len() < HEADER_SIZE {
        return;
    }

    let header = match PacketHeader::decode(data) {
        Ok(h) => h,
        Err(_) => return,
    };

    match header.msg_type {
        MessageType::Data => {
            process_data_packet_io_uring(
                data,
                addr,
                header,
                sessions,
                tun_write_tx,
                buffer_pool,
                metrics,
            );
        }
        MessageType::HandshakeInit | MessageType::EncryptedHandshakeInit => {
            // Both regular and encrypted handshakes use the same control message
            let data = Bytes::copy_from_slice(data);
            let _ = control_tx.try_send(WorkerControl::HandshakeInit { data, addr });
        }
        MessageType::HandshakeFragment => {
            // Fragmented handshake; reassembled by the async handler.
            let data = Bytes::copy_from_slice(data);
            let _ = control_tx.try_send(WorkerControl::HandshakeFragment { data, addr });
        }
        MessageType::Keepalive => {
            let data = Bytes::copy_from_slice(data);
            let _ = control_tx.try_send(WorkerControl::Keepalive {
                session_id: header.session_id,
                data,
                addr,
            });
        }
        MessageType::Control => {
            let data = Bytes::copy_from_slice(data);
            let _ = control_tx.try_send(WorkerControl::Control {
                session_id: header.session_id,
                data,
                addr,
            });
        }
        MessageType::Rekey => {
            let data = Bytes::copy_from_slice(data);
            let _ = control_tx.try_send(WorkerControl::Rekey {
                session_id: header.session_id,
                data,
                addr,
            });
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_capacity() {
        assert!(CHANNEL_CAPACITY > 0);
    }
}
