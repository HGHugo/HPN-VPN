//! UMEM (User Memory) management for AF_XDP.
//!
//! UMEM is a contiguous region of memory shared between userspace and the kernel.
//! It's divided into fixed-size frames that hold packet data.

use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use memmap2::MmapMut;
use tracing::{debug, trace};

use crate::error::{AfXdpError, Result};
use crate::sys::{self, XDP_UMEM_REG, XdpUmemReg};

/// Default frame size (2KB, good for most packets).
pub const DEFAULT_FRAME_SIZE: u32 = 2048;

/// Default headroom (space before packet data for metadata).
pub const DEFAULT_HEADROOM: u32 = 256;

/// Default number of frames in UMEM.
pub const DEFAULT_NUM_FRAMES: u32 = 16384;

/// UMEM configuration.
#[derive(Debug, Clone)]
pub struct UmemConfig {
    /// Size of each frame in bytes.
    pub frame_size: u32,
    /// Headroom before packet data.
    pub headroom: u32,
    /// Total number of frames.
    pub num_frames: u32,
}

impl Default for UmemConfig {
    fn default() -> Self {
        Self {
            frame_size: DEFAULT_FRAME_SIZE,
            headroom: DEFAULT_HEADROOM,
            num_frames: DEFAULT_NUM_FRAMES,
        }
    }
}

impl UmemConfig {
    /// Create a new UMEM configuration.
    pub fn new(frame_size: u32, headroom: u32, num_frames: u32) -> Result<Self> {
        // Validate frame size
        if frame_size < sys::XDP_MIN_FRAME_SIZE || frame_size > sys::XDP_MAX_FRAME_SIZE {
            return Err(AfXdpError::InvalidFrameSize {
                size: frame_size,
                min: sys::XDP_MIN_FRAME_SIZE,
                max: sys::XDP_MAX_FRAME_SIZE,
            });
        }

        // Frame size should be power of 2 for alignment
        if !frame_size.is_power_of_two() {
            return Err(AfXdpError::Config(format!(
                "frame_size must be power of 2, got {}",
                frame_size
            )));
        }

        // Headroom must fit in frame
        if headroom >= frame_size {
            return Err(AfXdpError::Config(format!(
                "headroom {} must be less than frame_size {}",
                headroom, frame_size
            )));
        }

        // num_frames must be power of 2
        if !num_frames.is_power_of_two() {
            return Err(AfXdpError::Config(format!(
                "num_frames must be power of 2, got {}",
                num_frames
            )));
        }

        Ok(Self {
            frame_size,
            headroom,
            num_frames,
        })
    }

    /// Total UMEM size in bytes.
    #[inline]
    pub fn total_size(&self) -> usize {
        self.frame_size as usize * self.num_frames as usize
    }

    /// Maximum packet size that fits in a frame.
    #[inline]
    pub fn max_packet_size(&self) -> u32 {
        self.frame_size - self.headroom
    }
}

/// A frame allocator using a lock-free stack.
///
/// This allows multiple threads to allocate and free frames concurrently.
struct FrameAllocator {
    /// Stack of free frame addresses (stored as indices).
    free_stack: Box<[AtomicU64]>,
    /// Stack pointer (index of next free slot).
    stack_top: AtomicU64,
    /// Frame size for address calculation.
    frame_size: u32,
    /// Total number of frames.
    num_frames: u32,
}

impl FrameAllocator {
    /// Create a new frame allocator.
    fn new(frame_size: u32, num_frames: u32) -> Self {
        // Initialize stack with all frames free
        let stack: Vec<AtomicU64> = (0..num_frames)
            .map(|i| AtomicU64::new(i as u64 * frame_size as u64))
            .collect();

        Self {
            free_stack: stack.into_boxed_slice(),
            stack_top: AtomicU64::new(num_frames as u64),
            frame_size,
            num_frames,
        }
    }

    /// Allocate a frame, returning its address.
    ///
    /// If a concurrent `free()` has reserved the slot but not yet written the
    /// address, this spins briefly until the value is available.
    #[inline]
    fn alloc(&self) -> Option<u64> {
        loop {
            let top = self.stack_top.load(Ordering::Acquire);
            if top == 0 {
                return None; // Stack empty
            }

            // Try to pop from stack
            if self
                .stack_top
                .compare_exchange_weak(top, top - 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                // We own slot[top-1]. The free() that pushed this slot
                // may still be writing the address (store after CAS).
                // Spin until we see a valid address (not 0 from initial zeroed state,
                // unless it's a valid frame 0 address). Since free() uses Release
                // and we use Acquire, once we see the store we have full visibility.
                let slot = &self.free_stack[(top - 1) as usize];
                let addr = slot.load(Ordering::Acquire);
                return Some(addr);
            }
            // CAS failed, retry
        }
    }

    /// Free a frame back to the allocator.
    ///
    /// Uses CAS to reserve a slot, then writes the address. The sentinel
    /// value `u64::MAX` marks slots being written to. The `alloc()` side
    /// spins briefly if it reads a sentinel, ensuring it gets the real address.
    #[inline]
    fn free(&self, addr: u64) {
        // Validate address
        debug_assert!(addr % self.frame_size as u64 == 0);
        debug_assert!(addr < self.num_frames as u64 * self.frame_size as u64);

        loop {
            let top = self.stack_top.load(Ordering::Acquire);
            debug_assert!(top < self.num_frames as u64);

            // Atomically reserve the slot by incrementing top first.
            if self
                .stack_top
                .compare_exchange_weak(top, top + 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                // We exclusively own slot[top]. Write the address.
                self.free_stack[top as usize].store(addr, Ordering::Release);
                return;
            }
            // CAS failed, retry with fresh top
        }
    }

    /// Number of free frames.
    #[inline]
    fn available(&self) -> u32 {
        self.stack_top.load(Ordering::Relaxed) as u32
    }
}

/// UMEM region shared between kernel and userspace.
///
/// UMEM is the foundation of AF_XDP zero-copy networking. It provides:
/// - A large contiguous memory region
/// - Fixed-size frames for packet data
/// - Lock-free frame allocation/deallocation
pub struct Umem {
    /// Memory-mapped region.
    mmap: MmapMut,
    /// Configuration.
    config: UmemConfig,
    /// Frame allocator.
    allocator: FrameAllocator,
}

impl Umem {
    #[inline]
    fn validate_packet_bounds(&self, addr: u64, len: u32) -> Result<usize> {
        if !self.validate_addr(addr) {
            return Err(AfXdpError::InvalidFrameAddress(addr));
        }

        if len > self.config.max_packet_size() {
            return Err(AfXdpError::Config(format!(
                "packet length {} exceeds max packet size {}",
                len,
                self.config.max_packet_size()
            )));
        }

        let start = addr
            .checked_add(self.config.headroom as u64)
            .ok_or_else(|| AfXdpError::Config("packet start offset overflow".to_string()))?;

        let end = start
            .checked_add(len as u64)
            .ok_or_else(|| AfXdpError::Config("packet end offset overflow".to_string()))?;

        if end > self.config.total_size() as u64 {
            return Err(AfXdpError::Config(format!(
                "packet range out of bounds: addr={:#x}, len={}, headroom={}, total_size={}",
                addr,
                len,
                self.config.headroom,
                self.config.total_size()
            )));
        }

        Ok(start as usize)
    }

    /// Create a new UMEM region.
    pub fn new(config: UmemConfig) -> Result<Self> {
        let size = config.total_size();

        debug!(
            "Creating UMEM: {} frames x {} bytes = {} MB",
            config.num_frames,
            config.frame_size,
            size / (1024 * 1024)
        );

        // Allocate anonymous memory
        let mmap = MmapMut::map_anon(size).map_err(|e| {
            AfXdpError::UmemAllocation(std::io::Error::new(std::io::ErrorKind::Other, e))
        })?;

        let allocator = FrameAllocator::new(config.frame_size, config.num_frames);

        Ok(Self {
            mmap,
            config,
            allocator,
        })
    }

    /// Register UMEM with an AF_XDP socket.
    pub fn register(&self, fd: RawFd) -> Result<()> {
        let reg = XdpUmemReg {
            addr: self.mmap.as_ptr() as u64,
            len: self.config.total_size() as u64,
            chunk_size: self.config.frame_size,
            headroom: self.config.headroom,
            flags: 0,
        };

        sys::xsk_setsockopt(fd, XDP_UMEM_REG, &reg).map_err(AfXdpError::UmemRegistration)?;

        debug!("UMEM registered with socket fd={}", fd);
        Ok(())
    }

    /// Get the base address of UMEM.
    #[inline]
    pub fn base_addr(&self) -> *mut u8 {
        self.mmap.as_ptr() as *mut u8
    }

    /// Get the configuration.
    #[inline]
    pub fn config(&self) -> &UmemConfig {
        &self.config
    }

    /// Allocate a frame.
    ///
    /// Returns the frame address (offset from UMEM base).
    #[inline]
    pub fn alloc_frame(&self) -> Option<u64> {
        let addr = self.allocator.alloc()?;
        trace!("Allocated frame at {:#x}", addr);
        Some(addr)
    }

    /// Free a frame.
    #[inline]
    pub fn free_frame(&self, addr: u64) {
        trace!("Freeing frame at {:#x}", addr);
        self.allocator.free(addr);
    }

    /// Get number of available frames.
    #[inline]
    pub fn available_frames(&self) -> u32 {
        self.allocator.available()
    }

    /// Get a mutable slice to frame data.
    ///
    /// # Safety
    /// The caller must ensure exclusive access to this frame.
    #[inline]
    pub unsafe fn frame_mut(&self, addr: u64) -> &mut [u8] {
        debug_assert!(self.validate_addr(addr));
        let ptr = self.mmap.as_ptr().add(addr as usize) as *mut u8;
        std::slice::from_raw_parts_mut(ptr, self.config.frame_size as usize)
    }

    /// Get an immutable slice to frame data.
    ///
    /// # Safety
    /// The caller must ensure the frame is valid.
    #[inline]
    pub unsafe fn frame(&self, addr: u64) -> &[u8] {
        debug_assert!(self.validate_addr(addr));
        let ptr = self.mmap.as_ptr().add(addr as usize);
        std::slice::from_raw_parts(ptr, self.config.frame_size as usize)
    }

    /// Get a mutable slice to packet data (after headroom).
    ///
    /// # Safety
    /// The caller must ensure exclusive access to this frame.
    #[inline]
    pub unsafe fn packet_mut(&self, addr: u64, len: u32) -> &mut [u8] {
        debug_assert!(self.validate_packet_bounds(addr, len).is_ok());
        let ptr = self
            .mmap
            .as_ptr()
            .add(addr as usize + self.config.headroom as usize) as *mut u8;
        std::slice::from_raw_parts_mut(ptr, len as usize)
    }

    /// Get an immutable slice to packet data.
    ///
    /// # Safety
    /// The caller must ensure the frame is valid.
    #[inline]
    pub unsafe fn packet(&self, addr: u64, len: u32) -> &[u8] {
        debug_assert!(self.validate_packet_bounds(addr, len).is_ok());
        let ptr = self
            .mmap
            .as_ptr()
            .add(addr as usize + self.config.headroom as usize);
        std::slice::from_raw_parts(ptr, len as usize)
    }

    /// Get an immutable packet slice with bounds validation.
    pub fn packet_checked(&self, addr: u64, len: u32) -> Result<&[u8]> {
        let start = self.validate_packet_bounds(addr, len)?;
        let ptr = self.mmap.as_ptr().wrapping_add(start);

        // SAFETY: Bounds were validated by `validate_packet_bounds` above.
        Ok(unsafe { std::slice::from_raw_parts(ptr, len as usize) })
    }

    /// Get a mutable packet slice with bounds validation.
    pub fn packet_mut_checked(&self, addr: u64, len: u32) -> Result<&mut [u8]> {
        let start = self.validate_packet_bounds(addr, len)?;
        let ptr = self.mmap.as_ptr().wrapping_add(start) as *mut u8;

        // SAFETY: Bounds were validated by `validate_packet_bounds` above.
        Ok(unsafe { std::slice::from_raw_parts_mut(ptr, len as usize) })
    }

    /// Validate a frame address.
    #[inline]
    pub fn validate_addr(&self, addr: u64) -> bool {
        addr < self.config.total_size() as u64 && addr % self.config.frame_size as u64 == 0
    }
}

// SAFETY: Umem can be shared between threads (atomic allocator)
unsafe impl Send for Umem {}
unsafe impl Sync for Umem {}

/// Shared UMEM handle for use across multiple sockets/threads.
pub type SharedUmem = Arc<Umem>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_umem_config_default() {
        let config = UmemConfig::default();
        assert_eq!(config.frame_size, DEFAULT_FRAME_SIZE);
        assert_eq!(config.headroom, DEFAULT_HEADROOM);
        assert_eq!(config.num_frames, DEFAULT_NUM_FRAMES);
    }

    #[test]
    fn test_umem_config_validation() {
        // Valid config
        assert!(UmemConfig::new(2048, 256, 4096).is_ok());

        // Invalid frame size (not power of 2)
        assert!(UmemConfig::new(3000, 256, 4096).is_err());

        // Invalid frame size (too small)
        assert!(UmemConfig::new(1024, 256, 4096).is_err());

        // Invalid headroom (>= frame_size)
        assert!(UmemConfig::new(2048, 2048, 4096).is_err());

        // Invalid num_frames (not power of 2)
        assert!(UmemConfig::new(2048, 256, 1000).is_err());
    }

    #[test]
    fn test_umem_total_size() {
        let config = UmemConfig::new(2048, 256, 4096).unwrap();
        assert_eq!(config.total_size(), 2048 * 4096);
    }

    #[test]
    fn test_umem_max_packet_size() {
        let config = UmemConfig::new(2048, 256, 4096).unwrap();
        assert_eq!(config.max_packet_size(), 2048 - 256);
    }

    #[test]
    fn test_frame_allocator_basic() {
        let alloc = FrameAllocator::new(2048, 16);

        // Should have 16 frames available
        assert_eq!(alloc.available(), 16);

        // Allocate all frames
        let mut addrs = Vec::new();
        for i in 0..16 {
            let addr = alloc.alloc().expect("should have frame");
            assert_eq!(addr % 2048, 0);
            addrs.push(addr);
            assert_eq!(alloc.available(), 15 - i);
        }

        // No more frames
        assert!(alloc.alloc().is_none());
        assert_eq!(alloc.available(), 0);

        // Free all frames
        for (i, addr) in addrs.into_iter().enumerate() {
            alloc.free(addr);
            assert_eq!(alloc.available(), i as u32 + 1);
        }

        // All frames back
        assert_eq!(alloc.available(), 16);
    }

    #[test]
    fn test_umem_creation() {
        // Use small UMEM for testing
        let config = UmemConfig::new(2048, 256, 64).unwrap();
        let umem = Umem::new(config).expect("should create UMEM");

        assert_eq!(umem.available_frames(), 64);
    }

    #[test]
    fn test_umem_alloc_free() {
        let config = UmemConfig::new(2048, 256, 64).unwrap();
        let umem = Umem::new(config).unwrap();

        // Allocate a frame
        let addr = umem.alloc_frame().expect("should have frame");
        assert!(umem.validate_addr(addr));
        assert_eq!(umem.available_frames(), 63);

        // Free it
        umem.free_frame(addr);
        assert_eq!(umem.available_frames(), 64);
    }

    #[test]
    fn test_umem_validate_addr() {
        let config = UmemConfig::new(2048, 256, 64).unwrap();
        let umem = Umem::new(config).unwrap();

        // Valid addresses
        assert!(umem.validate_addr(0));
        assert!(umem.validate_addr(2048));
        assert!(umem.validate_addr(2048 * 63));

        // Invalid addresses
        assert!(!umem.validate_addr(2048 * 64)); // Out of bounds
        assert!(!umem.validate_addr(100)); // Not aligned
    }
}
