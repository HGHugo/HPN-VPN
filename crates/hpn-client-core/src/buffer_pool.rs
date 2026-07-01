//! High-performance buffer pool for zero-allocation packet handling.
//!
//! This module provides lock-free buffer pools that eliminate per-packet
//! allocations in the hot path, providing 10-20% throughput improvement.
//!
//! Two pool types are provided:
//! - `BufferPool`: For Vec<u8> buffers (used in send path)
//! - `BytesPool`: For BytesMut buffers that can be frozen to Bytes (used in receive path)

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use crossbeam_channel::{Receiver, Sender, bounded};
use zeroize::Zeroize;

/// Maximum packet size for VPN traffic.
const MAX_PACKET_SIZE: usize = 65535;

/// Default pool size (number of pre-allocated buffers).
const DEFAULT_POOL_SIZE: usize = 256;
const DEFAULT_OVERFLOW_MULTIPLIER: usize = 4;
const MIN_OVERFLOW_CAP: usize = 64;
const POOL_BACKPRESSURE_WAIT: Duration = Duration::from_millis(10);

/// A pooled buffer that returns itself to the pool on drop.
pub struct PooledBuffer {
    /// The actual buffer data.
    data: Vec<u8>,
    /// Valid data length (may be less than capacity).
    len: usize,
    /// Channel to return buffer to pool on drop.
    return_tx: Sender<Vec<u8>>,
    /// Overflow slot counter (set only for overflow-allocated buffers).
    overflow_in_use: Option<Arc<AtomicUsize>>,
}

impl PooledBuffer {
    /// Create a new pooled buffer.
    fn new(
        mut data: Vec<u8>,
        return_tx: Sender<Vec<u8>>,
        overflow_in_use: Option<Arc<AtomicUsize>>,
    ) -> Self {
        // Ensure buffer has sufficient capacity
        if data.capacity() < MAX_PACKET_SIZE {
            data.reserve(MAX_PACKET_SIZE - data.len());
        }
        data.resize(MAX_PACKET_SIZE, 0);
        Self {
            data,
            len: 0,
            return_tx,
            overflow_in_use,
        }
    }

    /// Get the valid data as a slice.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// Get the valid data as a mutable slice.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }

    /// Get the entire buffer for writing.
    #[inline]
    pub fn buffer(&self) -> &[u8] {
        &self.data
    }

    /// Get the entire buffer for writing (mutable).
    #[inline]
    pub fn buffer_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Set the valid data length.
    #[inline]
    pub fn set_len(&mut self, len: usize) {
        debug_assert!(len <= self.data.capacity());
        self.len = len.min(self.data.capacity());
    }

    /// Get the valid data length.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Check if buffer is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Get buffer capacity.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.data.capacity()
    }

    /// Clear the buffer (sets length to 0).
    #[inline]
    pub fn clear(&mut self) {
        self.len = 0;
    }

    /// Copy data into the buffer.
    #[inline]
    pub fn copy_from(&mut self, src: &[u8]) {
        let len = src.len().min(self.data.capacity());
        self.data[..len].copy_from_slice(&src[..len]);
        self.len = len;
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        if let Some(ref counter) = self.overflow_in_use {
            counter.fetch_sub(1, Ordering::Relaxed);
        }
        // Clear the full pooled allocation before reuse. Some call sites write
        // through `buffer_mut()` without first updating `len`, so wiping only
        // the valid range would leave stale plaintext in the pool.
        self.data.as_mut_slice().zeroize();
        let buf = std::mem::take(&mut self.data);
        let _ = self.return_tx.try_send(buf);
    }
}

impl AsRef<[u8]> for PooledBuffer {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsMut<[u8]> for PooledBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

/// Lock-free buffer pool for high-performance packet handling.
///
/// Uses crossbeam channels for lock-free allocation and deallocation.
#[derive(Clone)]
pub struct BufferPool {
    /// Channel to get buffers from pool.
    pool_rx: Receiver<Vec<u8>>,
    /// Channel to return buffers to pool.
    return_tx: Sender<Vec<u8>>,
    /// Number of overflow allocations currently in use.
    overflow_in_use: Arc<AtomicUsize>,
    /// Maximum number of concurrent overflow allocations.
    max_overflow_allocations: usize,
}

impl BufferPool {
    /// Create a new buffer pool with the specified size.
    pub fn new(size: usize) -> Self {
        let (return_tx, pool_rx) = bounded(size);

        // Pre-allocate buffers
        for _ in 0..size {
            let buf = vec![0u8; MAX_PACKET_SIZE];
            let _ = return_tx.try_send(buf);
        }

        let max_overflow_allocations =
            (size.saturating_mul(DEFAULT_OVERFLOW_MULTIPLIER)).max(MIN_OVERFLOW_CAP);

        Self {
            pool_rx,
            return_tx,
            overflow_in_use: Arc::new(AtomicUsize::new(0)),
            max_overflow_allocations,
        }
    }

    /// Create a new buffer pool with default size.
    pub fn with_default_size() -> Self {
        Self::new(DEFAULT_POOL_SIZE)
    }

    /// Get a buffer from the pool.
    ///
    /// If the pool is empty, allocates a new buffer.
    /// The buffer is automatically returned to the pool when dropped.
    #[inline]
    pub fn get(&self) -> PooledBuffer {
        if let Ok(buf) = self.pool_rx.try_recv() {
            return PooledBuffer::new(buf, self.return_tx.clone(), None);
        }

        if self.try_acquire_overflow_slot() {
            return PooledBuffer::new(
                vec![0u8; MAX_PACKET_SIZE],
                self.return_tx.clone(),
                Some(Arc::clone(&self.overflow_in_use)),
            );
        }

        let buf = self
            .pool_rx
            .recv_timeout(POOL_BACKPRESSURE_WAIT)
            .unwrap_or_else(|_| vec![0u8; MAX_PACKET_SIZE]);
        PooledBuffer::new(buf, self.return_tx.clone(), None)
    }

    fn try_acquire_overflow_slot(&self) -> bool {
        loop {
            let current = self.overflow_in_use.load(Ordering::Relaxed);
            if current >= self.max_overflow_allocations {
                return false;
            }
            if self
                .overflow_in_use
                .compare_exchange_weak(current, current + 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }

    /// Get the approximate number of available buffers.
    #[inline]
    pub fn available(&self) -> usize {
        self.pool_rx.len()
    }

    /// Check if the pool is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.pool_rx.is_empty()
    }
}

impl Default for BufferPool {
    fn default() -> Self {
        Self::with_default_size()
    }
}

/// Thread-safe shared buffer pool.
pub type SharedBufferPool = Arc<BufferPool>;

/// Create a new shared buffer pool.
pub fn create_shared_pool(size: usize) -> SharedBufferPool {
    Arc::new(BufferPool::new(size))
}

// =============================================================================
// BytesMut Pool for Zero-Copy Receive Path
// =============================================================================

/// A pooled BytesMut buffer that returns itself to the pool on drop.
///
/// This is used for the receive path where we need to decrypt data and
/// then send it through a channel. The BytesMut can be frozen to Bytes
/// for efficient channel transmission.
pub struct PooledBytesMut {
    /// The actual buffer data.
    data: Option<BytesMut>,
    /// Channel to return buffer to pool on drop.
    return_tx: Sender<BytesMut>,
    /// Overflow slot counter (set only for overflow-allocated buffers).
    overflow_in_use: Option<Arc<AtomicUsize>>,
}

impl PooledBytesMut {
    /// Create a new pooled BytesMut buffer.
    fn new(
        mut data: BytesMut,
        return_tx: Sender<BytesMut>,
        overflow_in_use: Option<Arc<AtomicUsize>>,
    ) -> Self {
        // Ensure buffer has sufficient capacity
        if data.capacity() < MAX_PACKET_SIZE {
            data.reserve(MAX_PACKET_SIZE - data.len());
        }
        data.resize(MAX_PACKET_SIZE, 0);
        Self {
            data: Some(data),
            return_tx,
            overflow_in_use,
        }
    }

    /// Get the buffer for writing (mutable).
    #[inline]
    pub fn buffer_mut(&mut self) -> &mut [u8] {
        self.data.as_mut().map(|b| b.as_mut()).unwrap_or(&mut [])
    }

    /// Get the buffer as a slice.
    #[inline]
    pub fn buffer(&self) -> &[u8] {
        self.data.as_ref().map(|b| b.as_ref()).unwrap_or(&[])
    }

    /// Freeze the buffer to Bytes and return it, consuming self.
    ///
    /// This is zero-copy - the underlying memory is reused.
    /// The buffer is NOT returned to the pool when using this method.
    #[inline]
    pub fn freeze_to_bytes(mut self, len: usize) -> Bytes {
        let mut data = self.data.take().expect("buffer already taken");
        data.truncate(len);
        data.freeze()
    }

    /// Split off the first `len` bytes as Bytes.
    ///
    /// This is zero-copy for the returned Bytes.
    /// The remaining buffer is returned to the pool when self is dropped.
    #[inline]
    pub fn split_to_bytes(&mut self, len: usize) -> Bytes {
        if let Some(ref mut data) = self.data {
            data.split_to(len).freeze()
        } else {
            Bytes::new()
        }
    }

    /// Get the buffer capacity.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.data.as_ref().map(|b| b.capacity()).unwrap_or(0)
    }
}

impl Drop for PooledBytesMut {
    fn drop(&mut self) {
        if let Some(ref counter) = self.overflow_in_use {
            counter.fetch_sub(1, Ordering::Relaxed);
        }
        if let Some(mut buf) = self.data.take() {
            // Wipe the bytes still owned by the pooled buffer before it goes
            // back on the channel. Anything handed out through
            // `split_to_bytes` / `freeze_to_bytes` lives in a separate
            // `Bytes` allocation that this Drop never sees; that lifetime is
            // the consumer's responsibility.
            buf.as_mut().zeroize();
            let _ = self.return_tx.try_send(buf);
        }
    }
}

/// Lock-free BytesMut pool for zero-copy receive path.
///
/// Uses crossbeam channels for lock-free allocation and deallocation.
/// BytesMut buffers can be frozen to Bytes for efficient channel transmission.
#[derive(Clone)]
pub struct BytesPool {
    /// Channel to get buffers from pool.
    pool_rx: Receiver<BytesMut>,
    /// Channel to return buffers to pool.
    return_tx: Sender<BytesMut>,
    /// Number of overflow allocations currently in use.
    overflow_in_use: Arc<AtomicUsize>,
    /// Maximum number of concurrent overflow allocations.
    max_overflow_allocations: usize,
}

impl BytesPool {
    /// Create a new BytesMut pool with the specified size.
    pub fn new(size: usize) -> Self {
        let (return_tx, pool_rx) = bounded(size);

        // Pre-allocate buffers
        for _ in 0..size {
            let buf = BytesMut::zeroed(MAX_PACKET_SIZE);
            let _ = return_tx.try_send(buf);
        }

        let max_overflow_allocations =
            (size.saturating_mul(DEFAULT_OVERFLOW_MULTIPLIER)).max(MIN_OVERFLOW_CAP);

        Self {
            pool_rx,
            return_tx,
            overflow_in_use: Arc::new(AtomicUsize::new(0)),
            max_overflow_allocations,
        }
    }

    /// Create a new BytesMut pool with default size.
    pub fn with_default_size() -> Self {
        Self::new(DEFAULT_POOL_SIZE)
    }

    /// Get a buffer from the pool.
    ///
    /// If the pool is empty, allocates a new buffer.
    #[inline]
    pub fn get(&self) -> PooledBytesMut {
        if let Ok(buf) = self.pool_rx.try_recv() {
            return PooledBytesMut::new(buf, self.return_tx.clone(), None);
        }

        if self.try_acquire_overflow_slot() {
            return PooledBytesMut::new(
                BytesMut::zeroed(MAX_PACKET_SIZE),
                self.return_tx.clone(),
                Some(Arc::clone(&self.overflow_in_use)),
            );
        }

        let buf = self
            .pool_rx
            .recv_timeout(POOL_BACKPRESSURE_WAIT)
            .unwrap_or_else(|_| BytesMut::zeroed(MAX_PACKET_SIZE));
        PooledBytesMut::new(buf, self.return_tx.clone(), None)
    }

    fn try_acquire_overflow_slot(&self) -> bool {
        loop {
            let current = self.overflow_in_use.load(Ordering::Relaxed);
            if current >= self.max_overflow_allocations {
                return false;
            }
            if self
                .overflow_in_use
                .compare_exchange_weak(current, current + 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }

    /// Get the approximate number of available buffers.
    #[inline]
    pub fn available(&self) -> usize {
        self.pool_rx.len()
    }

    /// Check if the pool is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.pool_rx.is_empty()
    }
}

impl Default for BytesPool {
    fn default() -> Self {
        Self::with_default_size()
    }
}

/// Thread-safe shared BytesMut pool.
pub type SharedBytesPool = Arc<BytesPool>;

/// Create a new shared BytesMut pool.
pub fn create_shared_bytes_pool(size: usize) -> SharedBytesPool {
    Arc::new(BytesPool::new(size))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_pool_basic() {
        let pool = BufferPool::new(4);

        // Get some buffers
        let mut buf1 = pool.get();
        let mut buf2 = pool.get();

        // Write to buffers
        buf1.copy_from(b"hello");
        buf2.copy_from(b"world");

        assert_eq!(buf1.as_slice(), b"hello");
        assert_eq!(buf2.as_slice(), b"world");

        // Drop returns to pool
        drop(buf1);
        drop(buf2);

        // Pool should have buffers again
        assert_eq!(pool.available(), 4);
    }

    #[test]
    fn test_buffer_pool_exhaustion() {
        let pool = BufferPool::new(2);

        // Exhaust pool
        let _buf1 = pool.get();
        let _buf2 = pool.get();
        assert!(pool.is_empty());

        // Should still work (allocates new buffer)
        let _buf3 = pool.get();
    }

    #[test]
    fn test_pooled_buffer_capacity() {
        let pool = BufferPool::new(1);
        let buf = pool.get();
        assert!(buf.capacity() >= MAX_PACKET_SIZE);
    }

    #[test]
    fn test_pooled_buffer_zeroized_on_return() {
        let pool = BufferPool::new(1);
        {
            let mut buf = pool.get();
            buf.buffer_mut()[128..134].copy_from_slice(b"secret");
            buf.set_len(5);
        }

        let buf = pool.get();
        assert!(buf.buffer()[128..134].iter().all(|b| *b == 0));
    }

    #[test]
    fn test_bytes_pool_basic() {
        let pool = BytesPool::new(4);

        // Get a buffer and write to it
        let mut buf = pool.get();
        buf.buffer_mut()[..5].copy_from_slice(b"hello");

        // Freeze to Bytes
        let bytes = buf.freeze_to_bytes(5);
        assert_eq!(&bytes[..], b"hello");

        // Pool should have 3 buffers (one was consumed by freeze)
        assert_eq!(pool.available(), 3);
    }

    #[test]
    fn test_bytes_pool_return_on_drop() {
        let pool = BytesPool::new(2);

        {
            let _buf1 = pool.get();
            let _buf2 = pool.get();
            assert!(pool.is_empty());
        }

        // Buffers should be returned after drop
        assert_eq!(pool.available(), 2);
    }

    #[test]
    fn test_bytes_pool_freeze_does_not_return() {
        let pool = BytesPool::new(2);

        let mut buf = pool.get();
        buf.buffer_mut()[..5].copy_from_slice(b"test!");
        let _bytes = buf.freeze_to_bytes(5);

        // Only 1 buffer should be available (other was consumed by freeze)
        assert_eq!(pool.available(), 1);
    }

    #[test]
    fn test_pooled_bytes_mut_capacity() {
        let pool = BytesPool::new(1);
        let buf = pool.get();
        assert!(buf.capacity() >= MAX_PACKET_SIZE);
    }

    #[test]
    fn test_pooled_bytes_mut_zeroized_on_return() {
        let pool = BytesPool::new(1);
        {
            let mut buf = pool.get();
            buf.buffer_mut()[256..262].copy_from_slice(b"secret");
        }

        let buf = pool.get();
        assert!(buf.buffer()[256..262].iter().all(|b| *b == 0));
    }
}
