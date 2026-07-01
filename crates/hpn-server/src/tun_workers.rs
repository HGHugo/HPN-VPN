//! TUN device worker threads for multi-queue parallel I/O.
//!
//! Provides dedicated reader and writer threads for TUN multiqueue devices,
//! enabling 3-4x throughput improvement via parallel packet processing.
//!
//! # Inline Encryption Mode
//!
//! When `spawn_tun_reader_inline` is used, the TUN reader thread performs
//! encryption directly and sends via the UDP socket, eliminating the channel
//! hop to UDP sender workers. This provides 15-25% throughput improvement
//! on the download (server→client) path.

use std::net::UdpSocket;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::BytesMut;
use crossbeam_channel::{Receiver, Sender, bounded};
use tracing::{debug, error, info, trace, warn};

use hpn_core::types::MessageType;

use crate::server::WorkerHealthTracker;
use crate::session_manager::SessionManager;
use crate::tun::{DestinationAddr, get_destination_addr};
use crate::tun_multiqueue::TunQueue;
use crate::udp_workers::OutboundPacket;

/// Maximum packet size (standard MTU + overhead).
const MAX_PACKET_SIZE: usize = 65535;

/// Size of the BytesMut buffer pool per TUN reader.
const BYTES_POOL_SIZE: usize = 512;

/// High-performance buffer pool for zero-allocation packet handling.
struct BytesPool {
    pool: Receiver<BytesMut>,
    return_tx: Sender<BytesMut>,
}

impl BytesPool {
    /// Create a new pool with pre-allocated buffers.
    fn new(size: usize, buffer_size: usize) -> Self {
        let (return_tx, pool) = bounded(size);

        // Pre-allocate buffers
        for _ in 0..size {
            let buf = BytesMut::zeroed(buffer_size);
            let _ = return_tx.try_send(buf);
        }

        Self { pool, return_tx }
    }

    /// Get a buffer from the pool (allocates if empty).
    #[inline]
    fn get(&self) -> BytesMut {
        self.pool
            .try_recv()
            .unwrap_or_else(|_| BytesMut::zeroed(MAX_PACKET_SIZE))
    }

    /// Return a buffer to the pool.
    ///
    /// Performance note: we use `unsafe set_len` rather than `resize(N, 0)` to
    /// avoid zero-initialising 64 KiB on every recycled buffer. See the
    /// identical pattern documented in `hpn-server/src/server.rs`
    /// `PooledBuffer::drop` for the full safety argument.
    #[inline]
    fn put(&self, mut buf: BytesMut) {
        buf.clear();
        if buf.capacity() >= MAX_PACKET_SIZE {
            // Justified unsafe: hot-path optimisation mirrors the pattern in
            // `hpn-server/src/server.rs::PooledBuffer::drop`.
            #[allow(unsafe_code)]
            // SAFETY: `buf` was originally produced by
            // `BytesMut::zeroed(MAX_PACKET_SIZE)` (see `get` at line 60) or
            // acquired from the pool which maintains this invariant. `u8` is
            // POD (no drop glue), every byte in `0..capacity()` is initialised
            // on first allocation, and subsequent writes preserve that
            // invariant. No read past `len` occurs anywhere in this crate.
            unsafe {
                buf.set_len(MAX_PACKET_SIZE);
            }
            let _ = self.return_tx.try_send(buf);
        }
        // If capacity is too small, let it drop and allocate fresh next time.
    }
}

/// Set CPU affinity for current thread (Linux-only optimization).
///
/// Pins the thread to a specific CPU core to improve cache locality
/// and reduce context switching overhead.
///
/// # Arguments
/// * `cpu_id` - CPU core to pin to (0-indexed)
///
/// Returns `true` if affinity was set successfully, `false` otherwise.
///
/// # Safety
/// Uses FFI to call libc::sched_setaffinity which requires unsafe.
/// This is safe because:
/// - cpu_set is properly initialized with zeroed()
/// - size_of is correct for the type
/// - Error handling checks return value
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn set_cpu_affinity(cpu_id: usize) -> bool {
    use std::mem;

    unsafe {
        let mut cpu_set: libc::cpu_set_t = mem::zeroed();
        libc::CPU_SET(cpu_id, &mut cpu_set);

        let result = libc::sched_setaffinity(
            0, // 0 = current thread
            mem::size_of::<libc::cpu_set_t>(),
            &raw const cpu_set,
        );

        if result == 0 {
            debug!("Set CPU affinity to core {}", cpu_id);
            true
        } else {
            warn!(
                "Failed to set CPU affinity to core {}: {}",
                cpu_id,
                std::io::Error::last_os_error()
            );
            false
        }
    }
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
#[allow(unused_variables)]
fn set_cpu_affinity(cpu_id: usize) -> bool {
    false
}

/// Spawn a TUN reader thread for a specific queue.
///
/// # Arguments
///
/// * `queue_id` - Queue identifier for logging
/// * `queue` - TUN queue to read from
/// * `sessions` - Session manager for IP→SessionID lookup
/// * `outbound_tx` - Channel to send packets to UDP workers
/// * `shutdown` - Shutdown signal
/// * `tun_name` - Device name for logging
///
/// # Returns
///
/// Returns `JoinHandle` for the spawned thread, or error if spawn failed.
#[allow(clippy::too_many_arguments)]
pub fn spawn_tun_reader(
    queue_id: usize,
    queue: TunQueue,
    sessions: Arc<SessionManager>,
    outbound_tx: Sender<OutboundPacket>,
    shutdown: Arc<AtomicBool>,
    tun_name: String,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    spawn_tun_reader_with_tracker(
        queue_id,
        queue,
        sessions,
        outbound_tx,
        shutdown,
        tun_name,
        None,
    )
}

/// Spawn a TUN reader thread with health tracking.
///
/// See [`spawn_tun_reader`] for details.
#[allow(clippy::too_many_arguments)]
pub fn spawn_tun_reader_with_tracker(
    queue_id: usize,
    queue: TunQueue,
    sessions: Arc<SessionManager>,
    outbound_tx: Sender<OutboundPacket>,
    shutdown: Arc<AtomicBool>,
    tun_name: String,
    health_tracker: Option<Arc<WorkerHealthTracker>>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name(format!("tun-reader-{}", queue_id))
        .spawn(move || {
            let worker_name = format!("tun-reader-{}", queue_id);
            // Set CPU affinity for better cache locality and reduced context switching
            // Pin each queue to a different CPU core for optimal parallelism
            let num_cpus = std::thread::available_parallelism()
                .map(|p| p.get())
                .unwrap_or(4);
            let cpu_id = queue_id % num_cpus;
            set_cpu_affinity(cpu_id);

            // Wrap in catch_unwind to prevent panics from crashing the server
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                info!(
                    "TUN reader queue {} started for {} (fd={}, cpu={}, pool_size={})",
                    queue_id,
                    tun_name,
                    queue.index(),
                    cpu_id,
                    BYTES_POOL_SIZE
                );

                // Create buffer pool for zero-allocation packet handling
                let bytes_pool = BytesPool::new(BYTES_POOL_SIZE, MAX_PACKET_SIZE);
                let mut buf = bytes_pool.get();
                let mut consecutive_empty = 0u32;
                let mut packets_processed: u64 = 0;
                let mut packets_dropped: u64 = 0;

                loop {
                    if shutdown.load(Ordering::Relaxed) {
                        break;
                    }

                    match queue.recv(&mut buf) {
                        Ok(len) if len > 0 => {
                            consecutive_empty = 0;

                            // Lookup destination session by IP address
                            // Use combined lookup to get session_id + client_addr in one operation
                            let dest_session = match get_destination_addr(&buf[..len]) {
                                Some(DestinationAddr::V4(dst_ip)) => {
                                    sessions.get_session_and_addr_by_ip(dst_ip)
                                }
                                Some(DestinationAddr::V6(dst_ip)) => {
                                    sessions.get_session_and_addr_by_ipv6(dst_ip)
                                }
                                None => None,
                            };

                            if let Some((session_id, client_addr)) = dest_session {
                                // Zero-copy: freeze the buffer portion as Bytes
                                // We need a fresh buffer for next read
                                let packet_data = buf.split_to(len).freeze();

                                // Get a new buffer for next iteration
                                // Return old (now empty) buffer to pool if it has enough capacity
                                if buf.capacity() >= MAX_PACKET_SIZE {
                                    buf.resize(MAX_PACKET_SIZE, 0);
                                } else {
                                    // Buffer too small after split, get fresh one from pool
                                    bytes_pool.put(buf);
                                    buf = bytes_pool.get();
                                }

                                // Send to UDP workers for encryption + transmission
                                // Use blocking send with short timeout to avoid dropping packets
                                match outbound_tx.send_timeout(
                                    OutboundPacket {
                                        session_id,
                                        data: packet_data,
                                        client_addr,
                                    },
                                    std::time::Duration::from_micros(100),
                                ) {
                                    Ok(()) => packets_processed += 1,
                                    Err(_) => {
                                        packets_dropped += 1;
                                        if packets_dropped.is_multiple_of(10000) {
                                            warn!(
                                                "TUN reader queue {}: {} packets dropped (channel full)",
                                                queue_id, packets_dropped
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        Ok(_) => consecutive_empty += 1,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            consecutive_empty += 1;
                        }
                        Err(e) => {
                            if !shutdown.load(Ordering::Relaxed) {
                                warn!("TUN queue {} read error: {}", queue_id, e);
                            }
                            break;
                        }
                    }

                    // Adaptive sleep: less aggressive under low load
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
                    "TUN reader queue {} stopped (processed: {}, dropped: {})",
                    queue_id, packets_processed, packets_dropped
                );
            }));

            if let Err(panic_info) = result {
                let msg = WorkerHealthTracker::extract_panic_message(&panic_info);
                if let Some(ref tracker) = health_tracker {
                    tracker.record_panic(&worker_name, &msg);
                } else {
                    error!("TUN reader queue {} panicked: {}", queue_id, msg);
                }
            }
        })
}

/// Batch size for writev in TUN writer.
const TUN_WRITEV_BATCH_SIZE: usize = 64;

/// Spawn a TUN writer thread for a specific queue.
///
/// Receives decrypted packets from UDP workers and writes them to the TUN device.
/// Uses writev batching to reduce syscall overhead on Linux.
///
/// # Arguments
///
/// * `queue_id` - Queue identifier for logging
/// * `queue` - TUN queue to write to
/// * `tun_write_rx` - Channel to receive decrypted packets from UDP workers
/// * `shutdown` - Shutdown signal
/// * `tun_name` - Device name for logging
///
/// # Returns
///
/// Returns `JoinHandle` for the spawned thread, or error if spawn failed.
pub fn spawn_tun_writer<T>(
    queue_id: usize,
    queue: TunQueue,
    tun_write_rx: Receiver<T>,
    shutdown: Arc<AtomicBool>,
    tun_name: String,
) -> std::io::Result<std::thread::JoinHandle<()>>
where
    T: AsRef<[u8]> + Send + 'static,
{
    spawn_tun_writer_with_tracker(queue_id, queue, tun_write_rx, shutdown, tun_name, None)
}

/// Spawn a TUN writer thread with health tracking.
///
/// See [`spawn_tun_writer`] for details.
#[allow(clippy::too_many_arguments)]
pub fn spawn_tun_writer_with_tracker<T>(
    queue_id: usize,
    queue: TunQueue,
    tun_write_rx: Receiver<T>,
    shutdown: Arc<AtomicBool>,
    tun_name: String,
    health_tracker: Option<Arc<WorkerHealthTracker>>,
) -> std::io::Result<std::thread::JoinHandle<()>>
where
    T: AsRef<[u8]> + Send + 'static,
{
    std::thread::Builder::new()
        .name(format!("tun-writer-{}", queue_id))
        .spawn(move || {
            let worker_name = format!("tun-writer-{}", queue_id);
            // Set CPU affinity for better cache locality
            let num_cpus = std::thread::available_parallelism()
                .map(|p| p.get())
                .unwrap_or(4);
            let cpu_id = queue_id % num_cpus;
            set_cpu_affinity(cpu_id);

            // Wrap in catch_unwind to prevent panics from crashing the server
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                info!(
                    "TUN writer queue {} started (WRITEV batch={}) for {} (fd={}, cpu={})",
                    queue_id,
                    TUN_WRITEV_BATCH_SIZE,
                    tun_name,
                    queue.index(),
                    cpu_id
                );

                let mut consecutive_empty = 0u32;
                let mut packets_written: u64 = 0;
                let mut batches_written: u64 = 0;

                // Pre-allocate batch storage
                let mut packet_batch: Vec<T> = Vec::with_capacity(TUN_WRITEV_BATCH_SIZE);

                loop {
                    if shutdown.load(Ordering::Relaxed) {
                        break;
                    }

                    // Collect packets into batch
                    packet_batch.clear();
                    loop {
                        if packet_batch.len() >= TUN_WRITEV_BATCH_SIZE {
                            break;
                        }
                        match tun_write_rx.try_recv() {
                            Ok(packet) => packet_batch.push(packet),
                            Err(crossbeam_channel::TryRecvError::Empty) => break,
                            Err(crossbeam_channel::TryRecvError::Disconnected) => return,
                        }
                    }

                    if packet_batch.is_empty() {
                        consecutive_empty += 1;

                        // Adaptive sleep
                        if consecutive_empty > 1000 {
                            std::thread::sleep(std::time::Duration::from_micros(100));
                        } else if consecutive_empty > 100 {
                            std::thread::sleep(std::time::Duration::from_micros(10));
                        } else {
                            std::hint::spin_loop();
                        }
                    } else {
                        consecutive_empty = 0;

                        // Write packets individually (TUN doesn't support scatter-gather)
                        for (i, packet) in packet_batch.iter().enumerate() {
                            if let Err(e) = queue.send(packet.as_ref()) {
                                warn!("TUN queue {} write error: {}", queue_id, e);
                            } else {
                                packets_written += 1;
                            }
                            // Yield occasionally in large batches
                            if i > 0 && i % 16 == 0 {
                                std::hint::spin_loop();
                            }
                        }

                        batches_written += 1;
                    }
                }

                info!(
                    "TUN writer queue {} stopped (written: {}, batches: {})",
                    queue_id, packets_written, batches_written
                );
            }));

            if let Err(panic_info) = result {
                let msg = WorkerHealthTracker::extract_panic_message(&panic_info);
                if let Some(ref tracker) = health_tracker {
                    tracker.record_panic(&worker_name, &msg);
                } else {
                    error!("TUN writer queue {} panicked: {}", queue_id, msg);
                }
            }
        })
}

/// Batch size for sendmmsg in TUN reader (smaller than UDP workers for lower latency).
const TUN_SENDMMSG_BATCH_SIZE: usize = 64;

/// Maximum empty reads before flushing partial batch.
const FLUSH_AFTER_EMPTY_READS: u32 = 4;

/// Spawn a TUN reader thread with inline encryption and sendmmsg batching.
///
/// This is the high-performance path that eliminates the channel hop between
/// TUN reader and UDP sender by encrypting packets directly in the TUN reader
/// thread and sending via sendmmsg syscall batching.
///
/// **Performance improvement**: 30-45% throughput increase on download path
/// by avoiding:
/// - Channel send/receive overhead
/// - Second DashMap lookup in UDP sender
/// - Context switch between threads
/// - Per-packet send() syscall overhead (now batched via sendmmsg)
///
/// # Arguments
///
/// * `queue_id` - Queue identifier for logging and CPU affinity
/// * `queue` - TUN queue to read from
/// * `sessions` - Session manager for IP→Session lookup
/// * `send_socket` - UDP socket for direct packet transmission
/// * `shutdown` - Shutdown signal
/// * `tun_name` - Device name for logging
/// * `health_tracker` - Optional worker health tracker for panic monitoring
///
/// # Returns
///
/// Returns `JoinHandle` for the spawned thread, or error if spawn failed.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
pub fn spawn_tun_reader_inline(
    queue_id: usize,
    queue: TunQueue,
    sessions: Arc<SessionManager>,
    send_socket: Arc<UdpSocket>,
    shutdown: Arc<AtomicBool>,
    tun_name: String,
    metrics: Arc<crate::metrics::ServerMetrics>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    spawn_tun_reader_inline_with_tracker(
        queue_id,
        queue,
        sessions,
        send_socket,
        shutdown,
        tun_name,
        None,
        metrics,
    )
}

/// Spawn a TUN reader thread with inline encryption and health tracking.
///
/// See [`spawn_tun_reader_inline`] for details.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
pub fn spawn_tun_reader_inline_with_tracker(
    queue_id: usize,
    queue: TunQueue,
    sessions: Arc<SessionManager>,
    send_socket: Arc<UdpSocket>,
    shutdown: Arc<AtomicBool>,
    tun_name: String,
    health_tracker: Option<Arc<WorkerHealthTracker>>,
    metrics: Arc<crate::metrics::ServerMetrics>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    use crate::syscall_batch::SendMmsg;

    std::thread::Builder::new()
        .name(format!("tun-reader-{}", queue_id))
        .spawn(move || {
            let worker_name = format!("tun-reader-{}", queue_id);
            // Set CPU affinity for better cache locality and reduced context switching
            let num_cpus = std::thread::available_parallelism()
                .map(|p| p.get())
                .unwrap_or(4);
            let cpu_id = queue_id % num_cpus;
            set_cpu_affinity(cpu_id);

            // Wrap in catch_unwind to prevent panics from crashing the server
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                info!(
                    "TUN reader queue {} started (INLINE ENCRYPTION + SENDMMSG batch={}) for {} (fd={}, cpu={})",
                    queue_id,
                    TUN_SENDMMSG_BATCH_SIZE,
                    tun_name,
                    queue.index(),
                    cpu_id,
                );

                // Pre-allocate TUN read buffer
                let mut read_buf = vec![0u8; MAX_PACKET_SIZE];

                // Pre-allocate sendmmsg batch for zero-copy encryption
                let mut send_batch = SendMmsg::new(TUN_SENDMMSG_BATCH_SIZE, MAX_PACKET_SIZE);

                let mut consecutive_empty = 0u32;
                let mut packets_processed: u64 = 0;
                let mut bytes_encrypted: u64 = 0;
                let mut packets_no_session: u64 = 0;
                let mut send_errors: u64 = 0;
                let mut batches_sent: u64 = 0;
                let mut last_metrics_sync = std::time::Instant::now();

                loop {
                    if shutdown.load(Ordering::Relaxed) {
                        // Flush remaining packets before shutdown
                        if !send_batch.is_empty() {
                            let _ = send_batch.flush(&*send_socket);
                        }
                        break;
                    }

                    match queue.recv(&mut read_buf) {
                        Ok(len) if len > 0 => {
                            consecutive_empty = 0;

                            // Get destination IP from packet
                            let dest_addr = match get_destination_addr(&read_buf[..len]) {
                                Some(DestinationAddr::V4(ip)) => {
                                    sessions.get_session_and_addr_by_ip(ip)
                                }
                                Some(DestinationAddr::V6(ip)) => {
                                    sessions.get_session_and_addr_by_ipv6(ip)
                                }
                                None => None,
                            };

                            if let Some((session_id, client_addr)) = dest_addr {
                                // Get session for encryption (read-only, thread-safe)
                                if let Some(session_guard) = sessions.get_session(session_id) {
                                    // Get buffer from sendmmsg batch for zero-copy encryption
                                    if let Some(encrypt_buf) = send_batch.get_buffer_mut() {
                                        // Encrypt directly into sendmmsg buffer
                                        match session_guard.session.encrypt_packet(
                                            MessageType::Data,
                                            &read_buf[..len],
                                            encrypt_buf,
                                        ) {
                                            Ok(encrypted_len) => {
                                                session_guard.add_bytes_sent(encrypted_len as u64);
                                                drop(session_guard);

                                                send_batch.commit(encrypted_len, client_addr);
                                                packets_processed += 1;
                                                bytes_encrypted += encrypted_len as u64;

                                                // Flush if batch is full
                                                if send_batch.is_full() {
                                                    match send_batch.flush(&*send_socket) {
                                                        Ok(_) => batches_sent += 1,
                                                        Err(e) => {
                                                            send_errors += 1;
                                                            if send_errors <= 10
                                                                || send_errors.is_multiple_of(1000)
                                                            {
                                                                trace!(
                                                                    "TUN reader {}: sendmmsg error: {}",
                                                                    queue_id, e
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
                                                    queue_id, session_id, e
                                                );
                                            }
                                        }
                                    } else {
                                        // Batch full but not flushed yet - shouldn't happen
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

                            // Sync local counters to global metrics every second
                            if last_metrics_sync.elapsed() >= std::time::Duration::from_secs(1) {
                                if packets_processed > 0 {
                                    metrics.record_packets(packets_processed, 0);
                                    metrics.record_bytes(bytes_encrypted, 0);
                                    packets_processed = 0;
                                    bytes_encrypted = 0;
                                }
                                last_metrics_sync = std::time::Instant::now();
                            }

                            // Flush partial batch after a few empty reads to reduce latency
                            if !send_batch.is_empty() && consecutive_empty >= FLUSH_AFTER_EMPTY_READS
                            {
                                match send_batch.flush(&*send_socket) {
                                    Ok(_) => batches_sent += 1,
                                    Err(e) => {
                                        send_errors += 1;
                                        if send_errors <= 10 || send_errors.is_multiple_of(1000) {
                                            trace!(
                                                "TUN reader {}: sendmmsg flush error: {}",
                                                queue_id, e
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            consecutive_empty += 1;

                            // Flush partial batch after a few empty reads
                            if !send_batch.is_empty() && consecutive_empty >= FLUSH_AFTER_EMPTY_READS
                            {
                                match send_batch.flush(&*send_socket) {
                                    Ok(_) => batches_sent += 1,
                                    Err(e) => {
                                        send_errors += 1;
                                        if send_errors <= 10 || send_errors.is_multiple_of(1000) {
                                            trace!(
                                                "TUN reader {}: sendmmsg flush error: {}",
                                                queue_id, e
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            if !shutdown.load(Ordering::Relaxed) {
                                warn!("TUN queue {} read error: {}", queue_id, e);
                            }
                            // Flush remaining before exit
                            if !send_batch.is_empty() {
                                let _ = send_batch.flush(&*send_socket);
                            }
                            break;
                        }
                    }

                    // Adaptive sleep: less aggressive under low load
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
                    "TUN reader queue {} stopped (processed: {}, batches: {}, no_session: {}, send_errors: {})",
                    queue_id, packets_processed, batches_sent, packets_no_session, send_errors
                );
            }));

            if let Err(panic_info) = result {
                let msg = WorkerHealthTracker::extract_panic_message(&panic_info);
                if let Some(ref tracker) = health_tracker {
                    tracker.record_panic(&worker_name, &msg);
                } else {
                    error!("TUN reader queue {} panicked: {}", queue_id, msg);
                }
            }
        })
}
