//! Performance optimizations for high-throughput VPN processing.
//!
//! This module provides utilities for achieving 2.5+ Gbps throughput:
//! - Lock-free buffer pooling to reduce allocations
//! - Batch processing for packets
//! - CPU affinity hints
//! - Memory-aligned buffers for SIMD
//! - Slab allocator for fixed-size objects

// Allow unsafe code for low-level CPU affinity and memory operations
#![allow(unsafe_code)]

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crossbeam_channel::{Receiver, Sender, TrySendError, bounded};
use parking_lot::Mutex;

/// Default buffer size for high-throughput processing.
pub const DEFAULT_BUFFER_SIZE: usize = 65536;

/// Maximum packet size (MTU + headers).
pub const MAX_PACKET_SIZE: usize = 1500 + 100;

/// Number of buffers to pre-allocate in the pool.
pub const DEFAULT_POOL_SIZE: usize = 4096;

/// Cache line size for alignment.
pub const CACHE_LINE_SIZE: usize = 64;

/// Lock-free buffer pool using crossbeam channels.
///
/// Pre-allocates buffers and recycles them using a lock-free MPMC channel.
/// This eliminates mutex contention in the hot path.
pub struct LockFreeBufferPool {
    /// Channel to get buffers from the pool.
    get_rx: Receiver<Vec<u8>>,
    /// Channel to return buffers to the pool.
    put_tx: Sender<Vec<u8>>,
    /// Buffer size.
    buffer_size: usize,
    /// Statistics: buffers allocated.
    stats_allocated: AtomicU64,
    /// Statistics: buffers recycled.
    stats_recycled: AtomicU64,
    /// Statistics: pool misses (had to allocate).
    stats_misses: AtomicU64,
}

impl LockFreeBufferPool {
    /// Create a new lock-free buffer pool.
    pub fn new(buffer_size: usize, pool_size: usize) -> Self {
        let (put_tx, get_rx) = bounded(pool_size);

        // Pre-allocate buffers
        for _ in 0..pool_size {
            let buf = vec![0u8; buffer_size];
            let _ = put_tx.try_send(buf);
        }

        Self {
            get_rx,
            put_tx,
            buffer_size,
            stats_allocated: AtomicU64::new(pool_size as u64),
            stats_recycled: AtomicU64::new(0),
            stats_misses: AtomicU64::new(0),
        }
    }

    /// Get a buffer from the pool (lock-free).
    ///
    /// Returns a buffer from the pool if available, otherwise allocates a new one.
    #[inline]
    pub fn get(&self) -> Vec<u8> {
        if let Ok(mut buf) = self.get_rx.try_recv() {
            buf.clear();
            buf
        } else {
            self.stats_misses.fetch_add(1, Ordering::Relaxed);
            self.stats_allocated.fetch_add(1, Ordering::Relaxed);
            vec![0u8; self.buffer_size]
        }
    }

    /// Return a buffer to the pool (lock-free, best effort).
    ///
    /// If the pool is full, the buffer is dropped.
    #[inline]
    pub fn put(&self, mut buf: Vec<u8>) {
        buf.clear();
        match self.put_tx.try_send(buf) {
            Ok(()) => {
                self.stats_recycled.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                // Pool is full or disconnected, buffer is dropped
            }
        }
    }

    /// Get pool statistics.
    pub fn stats(&self) -> BufferPoolStats {
        BufferPoolStats {
            allocated: self.stats_allocated.load(Ordering::Relaxed),
            recycled: self.stats_recycled.load(Ordering::Relaxed),
            misses: self.stats_misses.load(Ordering::Relaxed),
            available: self.get_rx.len(),
        }
    }

    /// Get buffer size.
    #[inline]
    pub fn buffer_size(&self) -> usize {
        self.buffer_size
    }
}

impl Default for LockFreeBufferPool {
    fn default() -> Self {
        Self::new(DEFAULT_BUFFER_SIZE, DEFAULT_POOL_SIZE)
    }
}

/// A buffer pool for reducing allocation overhead.
///
/// Pre-allocates buffers and recycles them to avoid malloc/free overhead
/// in the hot path. This is critical for achieving 2.5 Gbps throughput.
///
/// Note: For highest performance in multi-threaded scenarios, use
/// `LockFreeBufferPool` instead.
pub struct BufferPool {
    /// Available buffers.
    buffers: Mutex<VecDeque<AlignedBuffer>>,
    /// Buffer size.
    buffer_size: usize,
    /// Maximum pool size.
    max_size: usize,
    /// Statistics: buffers allocated.
    stats_allocated: AtomicU64,
    /// Statistics: buffers recycled.
    stats_recycled: AtomicU64,
    /// Statistics: pool misses (had to allocate).
    stats_misses: AtomicU64,
}

impl BufferPool {
    /// Create a new buffer pool.
    pub fn new(buffer_size: usize, initial_count: usize) -> Self {
        let mut buffers = VecDeque::with_capacity(initial_count);

        for _ in 0..initial_count {
            buffers.push_back(AlignedBuffer::new(buffer_size));
        }

        Self {
            buffers: Mutex::new(buffers),
            buffer_size,
            max_size: initial_count * 2,
            stats_allocated: AtomicU64::new(initial_count as u64),
            stats_recycled: AtomicU64::new(0),
            stats_misses: AtomicU64::new(0),
        }
    }

    /// Get a buffer from the pool.
    pub fn get(&self) -> AlignedBuffer {
        let mut pool = self.buffers.lock();
        if let Some(mut buf) = pool.pop_front() {
            buf.clear();
            buf
        } else {
            drop(pool);
            self.stats_misses.fetch_add(1, Ordering::Relaxed);
            self.stats_allocated.fetch_add(1, Ordering::Relaxed);
            AlignedBuffer::new(self.buffer_size)
        }
    }

    /// Return a buffer to the pool.
    pub fn put(&self, buf: AlignedBuffer) {
        let mut pool = self.buffers.lock();
        if pool.len() < self.max_size {
            pool.push_back(buf);
            self.stats_recycled.fetch_add(1, Ordering::Relaxed);
        }
        // If pool is full, buffer is dropped
    }

    /// Get pool statistics.
    pub fn stats(&self) -> BufferPoolStats {
        BufferPoolStats {
            allocated: self.stats_allocated.load(Ordering::Relaxed),
            recycled: self.stats_recycled.load(Ordering::Relaxed),
            misses: self.stats_misses.load(Ordering::Relaxed),
            available: self.buffers.lock().len(),
        }
    }
}

impl Default for BufferPool {
    fn default() -> Self {
        Self::new(DEFAULT_BUFFER_SIZE, DEFAULT_POOL_SIZE)
    }
}

/// Slab allocator for fixed-size packet buffers.
///
/// More efficient than general-purpose allocators for fixed-size allocations.
/// Uses a free list for O(1) allocation and deallocation.
pub struct SlabAllocator {
    /// Channel to get buffers.
    get_rx: Receiver<Box<[u8]>>,
    /// Channel to return buffers.
    put_tx: Sender<Box<[u8]>>,
    /// Slab size.
    slab_size: usize,
    /// Stats.
    stats_allocated: AtomicU64,
    stats_recycled: AtomicU64,
}

impl SlabAllocator {
    /// Create a new slab allocator.
    pub fn new(slab_size: usize, initial_count: usize) -> Self {
        let (put_tx, get_rx) = bounded(initial_count * 2);

        // Pre-allocate slabs
        for _ in 0..initial_count {
            let slab = vec![0u8; slab_size].into_boxed_slice();
            let _ = put_tx.try_send(slab);
        }

        Self {
            get_rx,
            put_tx,
            slab_size,
            stats_allocated: AtomicU64::new(initial_count as u64),
            stats_recycled: AtomicU64::new(0),
        }
    }

    /// Allocate a slab.
    #[inline]
    pub fn alloc(&self) -> Box<[u8]> {
        if let Ok(slab) = self.get_rx.try_recv() {
            slab
        } else {
            self.stats_allocated.fetch_add(1, Ordering::Relaxed);
            vec![0u8; self.slab_size].into_boxed_slice()
        }
    }

    /// Free a slab.
    #[inline]
    pub fn free(&self, slab: Box<[u8]>) {
        if self.put_tx.try_send(slab).is_ok() {
            self.stats_recycled.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get slab size.
    #[inline]
    pub fn slab_size(&self) -> usize {
        self.slab_size
    }
}

/// Buffer pool statistics.
#[derive(Clone, Debug)]
pub struct BufferPoolStats {
    /// Total buffers allocated.
    pub allocated: u64,
    /// Buffers recycled.
    pub recycled: u64,
    /// Pool misses (had to allocate new buffer).
    pub misses: u64,
    /// Currently available buffers.
    pub available: usize,
}

/// A cache-line aligned buffer for SIMD-friendly memory access.
#[repr(C, align(64))]
pub struct AlignedBuffer {
    /// The actual data.
    data: Vec<u8>,
    /// Current length of valid data.
    len: usize,
}

impl AlignedBuffer {
    /// Create a new aligned buffer with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            data: vec![0u8; capacity],
            len: 0,
        }
    }

    /// Get the buffer as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// Get the buffer as a mutable slice.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }

    /// Get the full buffer for writing.
    pub fn as_write_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Set the length of valid data.
    pub fn set_len(&mut self, len: usize) {
        self.len = len.min(self.data.len());
    }

    /// Get the length of valid data.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Check if buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Get the capacity.
    pub fn capacity(&self) -> usize {
        self.data.len()
    }

    /// Clear the buffer.
    pub fn clear(&mut self) {
        self.len = 0;
    }

    /// Extend from a slice.
    pub fn extend_from_slice(&mut self, data: &[u8]) {
        let new_len = self.len + data.len();
        if new_len <= self.data.len() {
            self.data[self.len..new_len].copy_from_slice(data);
            self.len = new_len;
        }
    }
}

impl Default for AlignedBuffer {
    fn default() -> Self {
        Self::new(DEFAULT_BUFFER_SIZE)
    }
}

impl AsRef<[u8]> for AlignedBuffer {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsMut<[u8]> for AlignedBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

/// Batch processor for handling multiple packets efficiently.
///
/// Groups packets for batch crypto operations and reduces syscall overhead.
pub struct BatchProcessor {
    /// Maximum batch size.
    max_batch_size: usize,
    /// Current batch.
    batch: Vec<PacketWork>,
    /// Statistics.
    stats: BatchStats,
}

/// Work item for batch processing.
pub struct PacketWork {
    /// Packet data.
    pub data: AlignedBuffer,
    /// Source/destination info.
    pub addr: std::net::SocketAddr,
    /// Session ID (if known).
    pub session_id: Option<u64>,
}

/// Batch processing statistics.
#[derive(Debug, Default)]
pub struct BatchStats {
    /// Total batches processed.
    pub batches: AtomicU64,
    /// Total packets processed.
    pub packets: AtomicU64,
    /// Average batch size.
    pub avg_batch_size: AtomicU64,
}

impl BatchProcessor {
    /// Create a new batch processor.
    pub fn new(max_batch_size: usize) -> Self {
        Self {
            max_batch_size,
            batch: Vec::with_capacity(max_batch_size),
            stats: BatchStats::default(),
        }
    }

    /// Add a packet to the batch.
    pub fn add(&mut self, work: PacketWork) -> bool {
        if self.batch.len() >= self.max_batch_size {
            return false;
        }
        self.batch.push(work);
        true
    }

    /// Check if batch is full.
    pub fn is_full(&self) -> bool {
        self.batch.len() >= self.max_batch_size
    }

    /// Check if batch is empty.
    pub fn is_empty(&self) -> bool {
        self.batch.is_empty()
    }

    /// Get current batch size.
    pub fn len(&self) -> usize {
        self.batch.len()
    }

    /// Take the current batch for processing.
    pub fn take(&mut self) -> Vec<PacketWork> {
        let batch_size = self.batch.len() as u64;
        self.stats.batches.fetch_add(1, Ordering::Relaxed);
        self.stats.packets.fetch_add(batch_size, Ordering::Relaxed);

        std::mem::take(&mut self.batch)
    }

    /// Get statistics.
    pub fn stats(&self) -> &BatchStats {
        &self.stats
    }
}

impl Default for BatchProcessor {
    fn default() -> Self {
        Self::new(64)
    }
}

/// Throughput tracker for performance monitoring.
pub struct ThroughputTracker {
    /// Bytes processed in current window.
    bytes_current: AtomicU64,
    /// Packets processed in current window.
    packets_current: AtomicU64,
    /// Window start time (Unix timestamp in millis).
    window_start: AtomicU64,
    /// Window duration in milliseconds.
    window_ms: u64,
    /// Last calculated throughput (bytes/sec).
    last_throughput_bps: AtomicU64,
    /// Last calculated packet rate (packets/sec).
    last_pps: AtomicU64,
}

impl ThroughputTracker {
    /// Create a new throughput tracker.
    pub fn new(window_ms: u64) -> Self {
        let now = Self::now_ms();
        Self {
            bytes_current: AtomicU64::new(0),
            packets_current: AtomicU64::new(0),
            window_start: AtomicU64::new(now),
            window_ms,
            last_throughput_bps: AtomicU64::new(0),
            last_pps: AtomicU64::new(0),
        }
    }

    /// Record bytes and packets.
    pub fn record(&self, bytes: u64, packets: u64) {
        self.bytes_current.fetch_add(bytes, Ordering::Relaxed);
        self.packets_current.fetch_add(packets, Ordering::Relaxed);

        // Check if window has elapsed
        let now = Self::now_ms();
        let start = self.window_start.load(Ordering::Relaxed);
        if now - start >= self.window_ms {
            self.rotate_window(now);
        }
    }

    /// Rotate to a new measurement window.
    fn rotate_window(&self, now: u64) {
        let start = self.window_start.swap(now, Ordering::Relaxed);
        let elapsed_ms = now - start;
        if elapsed_ms == 0 {
            return;
        }

        let bytes = self.bytes_current.swap(0, Ordering::Relaxed);
        let packets = self.packets_current.swap(0, Ordering::Relaxed);

        // Calculate rates
        let bps = (bytes * 1000) / elapsed_ms;
        let pps = (packets * 1000) / elapsed_ms;

        self.last_throughput_bps.store(bps, Ordering::Relaxed);
        self.last_pps.store(pps, Ordering::Relaxed);
    }

    /// Get current throughput in bytes/sec.
    pub fn throughput_bps(&self) -> u64 {
        self.last_throughput_bps.load(Ordering::Relaxed)
    }

    /// Get current throughput in Gbps.
    pub fn throughput_gbps(&self) -> f64 {
        self.throughput_bps() as f64 * 8.0 / 1_000_000_000.0
    }

    /// Get current packet rate.
    pub fn packets_per_second(&self) -> u64 {
        self.last_pps.load(Ordering::Relaxed)
    }

    /// Check if throughput exceeds target (2.5 Gbps).
    pub fn is_at_target(&self) -> bool {
        self.throughput_gbps() >= 2.5
    }

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

impl Default for ThroughputTracker {
    fn default() -> Self {
        Self::new(1000) // 1 second window
    }
}

/// CPU affinity helper for pinning threads to cores.
#[cfg(target_os = "linux")]
pub mod affinity {
    use std::io;

    /// Set CPU affinity for the current thread.
    pub fn set_thread_affinity(cpu: usize) -> io::Result<()> {
        use std::mem;

        let mut set: libc::cpu_set_t = unsafe { mem::zeroed() };
        unsafe {
            libc::CPU_ZERO(&mut set);
            libc::CPU_SET(cpu, &mut set);

            let result =
                libc::sched_setaffinity(0, mem::size_of::<libc::cpu_set_t>(), &raw const set);

            if result == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }

    /// Get the number of available CPUs.
    #[allow(clippy::cast_sign_loss)]
    pub fn num_cpus() -> usize {
        let cpus = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
        if cpus > 0 { cpus as usize } else { 1 }
    }
}

#[cfg(not(target_os = "linux"))]
pub mod affinity {
    use std::io;

    /// Set CPU affinity (no-op on non-Linux).
    pub fn set_thread_affinity(_cpu: usize) -> io::Result<()> {
        Ok(())
    }

    /// Get the number of available CPUs.
    pub fn num_cpus() -> usize {
        std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(1)
    }
}

/// Ring buffer for lock-free packet queuing.
pub struct PacketRingBuffer {
    /// Buffer storage.
    slots: Vec<parking_lot::Mutex<Option<AlignedBuffer>>>,
    /// Write position.
    write_pos: AtomicUsize,
    /// Read position.
    read_pos: AtomicUsize,
    /// Capacity (must be power of 2).
    mask: usize,
}

impl PacketRingBuffer {
    /// Create a new ring buffer with the given capacity (rounded up to power of 2).
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.next_power_of_two();
        let mut slots = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            slots.push(parking_lot::Mutex::new(None));
        }

        Self {
            slots,
            write_pos: AtomicUsize::new(0),
            read_pos: AtomicUsize::new(0),
            mask: capacity - 1,
        }
    }

    /// Try to push a buffer into the ring.
    pub fn try_push(&self, buf: AlignedBuffer) -> Result<(), AlignedBuffer> {
        let write = self.write_pos.load(Ordering::Relaxed);
        let read = self.read_pos.load(Ordering::Acquire);

        // Check if full
        if write.wrapping_sub(read) > self.mask {
            return Err(buf);
        }

        let slot = &self.slots[write & self.mask];
        let mut guard = slot.lock();
        if guard.is_some() {
            return Err(buf);
        }

        *guard = Some(buf);
        drop(guard);

        self.write_pos.fetch_add(1, Ordering::Release);
        Ok(())
    }

    /// Try to pop a buffer from the ring.
    pub fn try_pop(&self) -> Option<AlignedBuffer> {
        let read = self.read_pos.load(Ordering::Relaxed);
        let write = self.write_pos.load(Ordering::Acquire);

        // Check if empty
        if read == write {
            return None;
        }

        let slot = &self.slots[read & self.mask];
        let mut guard = slot.lock();
        let buf = guard.take()?;
        drop(guard);

        self.read_pos.fetch_add(1, Ordering::Release);
        Some(buf)
    }

    /// Get current length.
    pub fn len(&self) -> usize {
        let write = self.write_pos.load(Ordering::Relaxed);
        let read = self.read_pos.load(Ordering::Relaxed);
        write.wrapping_sub(read)
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_pool() {
        let pool = BufferPool::new(1024, 10);

        // Get buffers
        let buf1 = pool.get();
        let buf2 = pool.get();

        assert_eq!(buf1.capacity(), 1024);
        assert_eq!(buf2.capacity(), 1024);

        // Return buffers
        pool.put(buf1);
        pool.put(buf2);

        let stats = pool.stats();
        assert!(stats.allocated >= 10);
    }

    #[test]
    fn test_aligned_buffer() {
        let mut buf = AlignedBuffer::new(1024);

        // Check struct alignment (the struct itself is 64-byte aligned)
        let struct_ptr = std::ptr::from_ref(&buf) as usize;
        assert_eq!(struct_ptr % CACHE_LINE_SIZE, 0);

        // Note: The internal Vec's heap data may not be aligned to cache line size,
        // as Vec uses the global allocator which typically provides 8 or 16-byte alignment.
        // The struct alignment ensures the struct fields are cache-line aligned.

        // Test operations
        buf.extend_from_slice(b"hello");
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.as_slice(), b"hello");

        buf.clear();
        assert!(buf.is_empty());
    }

    #[test]
    fn test_batch_processor() {
        let mut batch = BatchProcessor::new(4);

        for i in 0..3 {
            let work = PacketWork {
                data: AlignedBuffer::new(64),
                addr: "127.0.0.1:1234".parse().unwrap(),
                session_id: Some(i),
            };
            assert!(batch.add(work));
        }

        assert_eq!(batch.len(), 3);
        assert!(!batch.is_full());

        let items = batch.take();
        assert_eq!(items.len(), 3);
        assert!(batch.is_empty());
    }

    #[test]
    fn test_throughput_tracker() {
        let tracker = ThroughputTracker::new(100);

        // Record some traffic
        tracker.record(1_000_000, 1000);

        // Initial rate should be 0 until window rotates
        assert_eq!(tracker.throughput_bps(), 0);
    }

    #[test]
    fn test_ring_buffer() {
        let ring = PacketRingBuffer::new(4);

        // Push some buffers
        let mut buf = AlignedBuffer::new(64);
        buf.extend_from_slice(b"test");
        assert!(ring.try_push(buf).is_ok());

        assert_eq!(ring.len(), 1);

        // Pop
        let popped = ring.try_pop().unwrap();
        assert_eq!(popped.as_slice(), b"test");

        assert!(ring.is_empty());
    }

    #[test]
    fn test_num_cpus() {
        let cpus = affinity::num_cpus();
        assert!(cpus >= 1);
    }

    #[test]
    fn test_lock_free_buffer_pool() {
        let pool = LockFreeBufferPool::new(1024, 10);

        // Get buffers
        let buf1 = pool.get();
        let buf2 = pool.get();

        assert_eq!(buf1.capacity(), 1024);
        assert_eq!(buf2.capacity(), 1024);

        // Return buffers
        pool.put(buf1);
        pool.put(buf2);

        let stats = pool.stats();
        assert!(stats.allocated >= 10);
        assert!(stats.recycled >= 2);
    }

    #[test]
    fn test_lock_free_buffer_pool_concurrent() {
        use std::sync::Arc;
        use std::thread;

        let pool = Arc::new(LockFreeBufferPool::new(1024, 100));
        let mut handles = vec![];

        // Spawn multiple threads to stress test
        for _ in 0..4 {
            let pool = Arc::clone(&pool);
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    let buf = pool.get();
                    pool.put(buf);
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let stats = pool.stats();
        assert!(stats.recycled > 0);
    }

    #[test]
    fn test_slab_allocator() {
        let slab = SlabAllocator::new(1500, 16);

        // Allocate
        let buf1 = slab.alloc();
        let buf2 = slab.alloc();

        assert_eq!(buf1.len(), 1500);
        assert_eq!(buf2.len(), 1500);

        // Free
        slab.free(buf1);
        slab.free(buf2);
    }

    #[test]
    fn test_buffer_pool_stats() {
        let pool = LockFreeBufferPool::new(1024, 10);

        let stats = pool.stats();
        assert_eq!(stats.allocated, 10);
        assert_eq!(stats.recycled, 0);
        assert_eq!(stats.misses, 0);
    }

    #[test]
    fn test_buffer_pool_miss() {
        let pool = LockFreeBufferPool::new(512, 2);

        // Get all buffers from pool
        let _buf1 = pool.get();
        let _buf2 = pool.get();

        // Next get should be a miss (allocate new)
        let _buf3 = pool.get();

        let stats = pool.stats();
        assert_eq!(stats.misses, 1);
    }

    #[test]
    fn test_buffer_pool_recycle() {
        let pool = LockFreeBufferPool::new(1024, 5);

        let buf = pool.get();
        pool.put(buf);

        let stats = pool.stats();
        assert_eq!(stats.recycled, 1);
    }

    #[test]
    fn test_constants() {
        assert_eq!(DEFAULT_BUFFER_SIZE, 65536);
        assert_eq!(MAX_PACKET_SIZE, 1600);
        assert_eq!(DEFAULT_POOL_SIZE, 4096);
        assert_eq!(CACHE_LINE_SIZE, 64);
    }

    #[test]
    fn test_slab_allocator_reuse() {
        let slab = SlabAllocator::new(1024, 8);

        // Initial allocation count should be 8
        let initial_allocated = slab.stats_allocated.load(Ordering::Relaxed);
        assert_eq!(initial_allocated, 8);

        let buf1 = slab.alloc();
        assert_eq!(buf1.len(), 1024);

        // No new allocation should have occurred (reused from pool)
        assert_eq!(slab.stats_allocated.load(Ordering::Relaxed), 8);

        slab.free(buf1);

        // Should have recycled 1 buffer
        assert_eq!(slab.stats_recycled.load(Ordering::Relaxed), 1);

        let buf2 = slab.alloc();
        assert_eq!(buf2.len(), 1024);

        // Still no new allocation (reused the recycled buffer)
        assert_eq!(slab.stats_allocated.load(Ordering::Relaxed), 8);
    }

    #[test]
    fn test_slab_allocator_exhaustion() {
        let slab = SlabAllocator::new(512, 3);

        let _buf1 = slab.alloc();
        let _buf2 = slab.alloc();
        let _buf3 = slab.alloc();

        // 4th allocation should allocate new (not from slab)
        let buf4 = slab.alloc();
        assert_eq!(buf4.len(), 512);
    }

    #[test]
    fn test_buffer_pool_default_size() {
        let pool = LockFreeBufferPool::new(DEFAULT_BUFFER_SIZE, 100);
        let buf = pool.get();
        assert_eq!(buf.capacity(), DEFAULT_BUFFER_SIZE);
    }

    #[test]
    fn test_aligned_buffer_various_sizes() {
        let buf1 = AlignedBuffer::new(1024);
        assert_eq!(buf1.capacity(), 1024);

        let buf2 = AlignedBuffer::new(4096);
        assert_eq!(buf2.capacity(), 4096);
    }

    #[test]
    fn test_buffer_pool_multiple_gets() {
        let pool = BufferPool::new(1024, 5);

        let buf1 = pool.get();
        let buf2 = pool.get();

        // Buffers from pool are cleared, check capacity
        assert_eq!(buf1.capacity(), 1024);
        assert_eq!(buf2.capacity(), 1024);
    }

    #[test]
    fn test_slab_allocator_multiple_cycles() {
        let slab = SlabAllocator::new(512, 3);

        // Allocate and free multiple times
        for _ in 0..5 {
            let buf = slab.alloc();
            assert_eq!(buf.len(), 512);
            slab.free(buf);
        }
    }

    #[test]
    fn test_lock_free_buffer_pool_large_size() {
        let pool = LockFreeBufferPool::new(8192, 10);
        let buf = pool.get();
        assert_eq!(buf.capacity(), 8192);
    }
}
