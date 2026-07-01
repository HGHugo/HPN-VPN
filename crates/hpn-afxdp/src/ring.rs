//! Ring buffer implementations for AF_XDP.
//!
//! AF_XDP uses four ring buffers for communication between userspace and kernel:
//! - **Fill Ring**: Userspace provides empty frames for RX
//! - **Completion Ring**: Kernel returns completed TX frames
//! - **RX Ring**: Kernel delivers received packets
//! - **TX Ring**: Userspace submits packets for transmission

use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU32, Ordering};

use tracing::trace;

use crate::error::{AfXdpError, Result};
use crate::sys::{
    self, XDP_PGOFF_RX_RING, XDP_PGOFF_TX_RING, XDP_RING_NEED_WAKEUP, XDP_RX_RING, XDP_TX_RING,
    XDP_UMEM_COMPLETION_RING, XDP_UMEM_FILL_RING, XDP_UMEM_PGOFF_COMPLETION_RING,
    XDP_UMEM_PGOFF_FILL_RING, XdpDesc, XdpRingOffset,
};

/// Ring buffer configuration.
#[derive(Debug, Clone, Copy)]
pub struct RingConfig {
    /// Number of entries (must be power of 2).
    pub size: u32,
}

impl RingConfig {
    /// Create a new ring configuration.
    pub fn new(size: u32) -> Result<Self> {
        if !size.is_power_of_two() {
            return Err(AfXdpError::InvalidRingSize(size));
        }
        Ok(Self { size })
    }
}

impl Default for RingConfig {
    fn default() -> Self {
        Self { size: 4096 }
    }
}

/// Memory-mapped ring buffer pointers.
///
/// All rings share this common structure:
/// - producer: index where next entry will be written
/// - consumer: index where next entry will be read
/// - ring: array of entries
/// - flags: ring flags (e.g., NEED_WAKEUP)
struct RingMmap {
    /// Base address of mapped region.
    base: *mut u8,
    /// Total size of mapped region.
    size: usize,
    /// Producer pointer offset.
    producer_off: u64,
    /// Consumer pointer offset.
    consumer_off: u64,
    /// Ring entries offset.
    desc_off: u64,
    /// Flags offset.
    flags_off: u64,
    /// Ring mask (size - 1).
    mask: u32,
}

impl RingMmap {
    /// Get producer pointer.
    #[inline]
    fn producer(&self) -> &AtomicU32 {
        // SAFETY: Memory was properly mapped and offset was validated
        unsafe { &*(self.base.add(self.producer_off as usize) as *const AtomicU32) }
    }

    /// Get consumer pointer.
    #[inline]
    fn consumer(&self) -> &AtomicU32 {
        // SAFETY: Memory was properly mapped and offset was validated
        unsafe { &*(self.base.add(self.consumer_off as usize) as *const AtomicU32) }
    }

    /// Get flags pointer.
    #[inline]
    fn flags(&self) -> &AtomicU32 {
        // SAFETY: Memory was properly mapped and offset was validated
        unsafe { &*(self.base.add(self.flags_off as usize) as *const AtomicU32) }
    }

    /// Check if kernel needs wakeup.
    #[inline]
    fn needs_wakeup(&self) -> bool {
        self.flags().load(Ordering::Relaxed) & XDP_RING_NEED_WAKEUP != 0
    }
}

impl Drop for RingMmap {
    fn drop(&mut self) {
        if !self.base.is_null() {
            // SAFETY: We own this mapping and it was created with mmap
            unsafe {
                let _ = sys::munmap_ring(self.base, self.size);
            }
        }
    }
}

// ============================================================================
// Fill Ring
// ============================================================================

/// Fill ring: userspace provides empty frames for kernel to fill with RX data.
pub struct FillRing {
    mmap: RingMmap,
    /// Cached producer value for batching.
    cached_prod: u32,
}

impl FillRing {
    /// Create and map a fill ring.
    pub fn new(fd: RawFd, config: &RingConfig, offsets: &XdpRingOffset) -> Result<Self> {
        // Set ring size
        sys::xsk_setsockopt(fd, XDP_UMEM_FILL_RING, &config.size).map_err(|e| {
            AfXdpError::RingCreation {
                ring_type: "fill".to_string(),
                source: e,
            }
        })?;

        // Calculate map size
        let map_size =
            (offsets.desc as usize) + (config.size as usize * std::mem::size_of::<u64>());

        // Map the ring
        let base = sys::mmap_ring(fd, map_size, XDP_UMEM_PGOFF_FILL_RING).map_err(|e| {
            AfXdpError::RingMapping {
                ring_type: "fill".to_string(),
                source: e,
            }
        })?;

        Ok(Self {
            mmap: RingMmap {
                base,
                size: map_size,
                producer_off: offsets.producer,
                consumer_off: offsets.consumer,
                desc_off: offsets.desc,
                flags_off: offsets.flags,
                mask: config.size - 1,
            },
            cached_prod: 0,
        })
    }

    /// Get number of free slots in the ring.
    #[inline]
    pub fn free_slots(&self) -> u32 {
        let cons = self.mmap.consumer().load(Ordering::Acquire);
        let prod = self.cached_prod;
        (self.mmap.mask + 1) - (prod - cons)
    }

    /// Reserve slots for producing.
    ///
    /// Returns the starting index if successful.
    #[inline]
    pub fn reserve(&mut self, count: u32) -> Option<u32> {
        if self.free_slots() < count {
            return None;
        }
        let idx = self.cached_prod;
        self.cached_prod = self.cached_prod.wrapping_add(count);
        Some(idx)
    }

    /// Write a frame address to the ring at the given index.
    #[inline]
    pub fn write(&self, idx: u32, addr: u64) {
        let ring_idx = idx & self.mmap.mask;
        // SAFETY: Index was validated and memory was properly mapped
        unsafe {
            let entry_ptr =
                self.mmap.base.add(
                    self.mmap.desc_off as usize + ring_idx as usize * std::mem::size_of::<u64>(),
                ) as *mut u64;
            entry_ptr.write_volatile(addr);
        }
    }

    /// Submit entries to the kernel.
    #[inline]
    pub fn submit(&self, count: u32) {
        // Memory barrier to ensure writes are visible
        std::sync::atomic::fence(Ordering::Release);
        self.mmap.producer().fetch_add(count, Ordering::Release);
        trace!("Fill ring: submitted {} frames", count);
    }

    /// Check if kernel needs wakeup.
    #[inline]
    pub fn needs_wakeup(&self) -> bool {
        self.mmap.needs_wakeup()
    }
}

// SAFETY: Ring can be sent between threads
unsafe impl Send for FillRing {}

// ============================================================================
// Completion Ring
// ============================================================================

/// Completion ring: kernel returns addresses of transmitted frames.
pub struct CompletionRing {
    mmap: RingMmap,
    /// Cached consumer value for batching.
    cached_cons: u32,
}

impl CompletionRing {
    /// Create and map a completion ring.
    pub fn new(fd: RawFd, config: &RingConfig, offsets: &XdpRingOffset) -> Result<Self> {
        // Set ring size
        sys::xsk_setsockopt(fd, XDP_UMEM_COMPLETION_RING, &config.size).map_err(|e| {
            AfXdpError::RingCreation {
                ring_type: "completion".to_string(),
                source: e,
            }
        })?;

        // Calculate map size
        let map_size =
            (offsets.desc as usize) + (config.size as usize * std::mem::size_of::<u64>());

        // Map the ring
        let base = sys::mmap_ring(fd, map_size, XDP_UMEM_PGOFF_COMPLETION_RING).map_err(|e| {
            AfXdpError::RingMapping {
                ring_type: "completion".to_string(),
                source: e,
            }
        })?;

        Ok(Self {
            mmap: RingMmap {
                base,
                size: map_size,
                producer_off: offsets.producer,
                consumer_off: offsets.consumer,
                desc_off: offsets.desc,
                flags_off: offsets.flags,
                mask: config.size - 1,
            },
            cached_cons: 0,
        })
    }

    /// Get number of entries available for consuming.
    #[inline]
    pub fn available(&self) -> u32 {
        let prod = self.mmap.producer().load(Ordering::Acquire);
        prod.wrapping_sub(self.cached_cons)
    }

    /// Peek at the next available entry without consuming.
    #[inline]
    pub fn peek(&self, idx: u32) -> u64 {
        let ring_idx = (self.cached_cons.wrapping_add(idx)) & self.mmap.mask;
        // SAFETY: Index was validated and memory was properly mapped
        unsafe {
            let entry_ptr =
                self.mmap.base.add(
                    self.mmap.desc_off as usize + ring_idx as usize * std::mem::size_of::<u64>(),
                ) as *const u64;
            entry_ptr.read_volatile()
        }
    }

    /// Release consumed entries.
    #[inline]
    pub fn release(&mut self, count: u32) {
        self.cached_cons = self.cached_cons.wrapping_add(count);
        self.mmap
            .consumer()
            .store(self.cached_cons, Ordering::Release);
        trace!("Completion ring: released {} frames", count);
    }
}

// SAFETY: Ring can be sent between threads
unsafe impl Send for CompletionRing {}

// ============================================================================
// RX Ring
// ============================================================================

/// RX ring: kernel delivers received packets.
pub struct RxRing {
    mmap: RingMmap,
    /// Cached consumer value for batching.
    cached_cons: u32,
}

impl RxRing {
    /// Create and map an RX ring.
    pub fn new(fd: RawFd, config: &RingConfig, offsets: &XdpRingOffset) -> Result<Self> {
        // Set ring size
        sys::xsk_setsockopt(fd, XDP_RX_RING, &config.size).map_err(|e| {
            AfXdpError::RingCreation {
                ring_type: "rx".to_string(),
                source: e,
            }
        })?;

        // Calculate map size (XdpDesc is 16 bytes)
        let map_size =
            (offsets.desc as usize) + (config.size as usize * std::mem::size_of::<XdpDesc>());

        // Map the ring
        let base = sys::mmap_ring(fd, map_size, XDP_PGOFF_RX_RING).map_err(|e| {
            AfXdpError::RingMapping {
                ring_type: "rx".to_string(),
                source: e,
            }
        })?;

        Ok(Self {
            mmap: RingMmap {
                base,
                size: map_size,
                producer_off: offsets.producer,
                consumer_off: offsets.consumer,
                desc_off: offsets.desc,
                flags_off: offsets.flags,
                mask: config.size - 1,
            },
            cached_cons: 0,
        })
    }

    /// Get number of packets available for receiving.
    #[inline]
    pub fn available(&self) -> u32 {
        let prod = self.mmap.producer().load(Ordering::Acquire);
        prod.wrapping_sub(self.cached_cons)
    }

    /// Get descriptor at index (relative to cached_cons).
    #[inline]
    pub fn get_desc(&self, idx: u32) -> XdpDesc {
        let ring_idx = (self.cached_cons.wrapping_add(idx)) & self.mmap.mask;
        // SAFETY: Index was validated and memory was properly mapped
        unsafe {
            let desc_ptr = self.mmap.base.add(
                self.mmap.desc_off as usize + ring_idx as usize * std::mem::size_of::<XdpDesc>(),
            ) as *const XdpDesc;
            desc_ptr.read_volatile()
        }
    }

    /// Release consumed entries.
    #[inline]
    pub fn release(&mut self, count: u32) {
        self.cached_cons = self.cached_cons.wrapping_add(count);
        self.mmap
            .consumer()
            .store(self.cached_cons, Ordering::Release);
        trace!("RX ring: released {} packets", count);
    }

    /// Check if kernel needs wakeup.
    #[inline]
    pub fn needs_wakeup(&self) -> bool {
        self.mmap.needs_wakeup()
    }
}

// SAFETY: Ring can be sent between threads
unsafe impl Send for RxRing {}

// ============================================================================
// TX Ring
// ============================================================================

/// TX ring: userspace submits packets for transmission.
pub struct TxRing {
    mmap: RingMmap,
    /// Cached producer value for batching.
    cached_prod: u32,
}

impl TxRing {
    /// Create and map a TX ring.
    pub fn new(fd: RawFd, config: &RingConfig, offsets: &XdpRingOffset) -> Result<Self> {
        // Set ring size
        sys::xsk_setsockopt(fd, XDP_TX_RING, &config.size).map_err(|e| {
            AfXdpError::RingCreation {
                ring_type: "tx".to_string(),
                source: e,
            }
        })?;

        // Calculate map size
        let map_size =
            (offsets.desc as usize) + (config.size as usize * std::mem::size_of::<XdpDesc>());

        // Map the ring
        let base = sys::mmap_ring(fd, map_size, XDP_PGOFF_TX_RING).map_err(|e| {
            AfXdpError::RingMapping {
                ring_type: "tx".to_string(),
                source: e,
            }
        })?;

        Ok(Self {
            mmap: RingMmap {
                base,
                size: map_size,
                producer_off: offsets.producer,
                consumer_off: offsets.consumer,
                desc_off: offsets.desc,
                flags_off: offsets.flags,
                mask: config.size - 1,
            },
            cached_prod: 0,
        })
    }

    /// Get number of free slots in the ring.
    #[inline]
    pub fn free_slots(&self) -> u32 {
        let cons = self.mmap.consumer().load(Ordering::Acquire);
        let prod = self.cached_prod;
        (self.mmap.mask + 1) - (prod - cons)
    }

    /// Reserve slots for producing.
    #[inline]
    pub fn reserve(&mut self, count: u32) -> Option<u32> {
        if self.free_slots() < count {
            return None;
        }
        let idx = self.cached_prod;
        self.cached_prod = self.cached_prod.wrapping_add(count);
        Some(idx)
    }

    /// Write a descriptor to the ring.
    #[inline]
    pub fn write(&self, idx: u32, desc: &XdpDesc) {
        let ring_idx = idx & self.mmap.mask;
        // SAFETY: Index was validated and memory was properly mapped
        unsafe {
            let desc_ptr = self.mmap.base.add(
                self.mmap.desc_off as usize + ring_idx as usize * std::mem::size_of::<XdpDesc>(),
            ) as *mut XdpDesc;
            desc_ptr.write_volatile(*desc);
        }
    }

    /// Submit entries to the kernel.
    #[inline]
    pub fn submit(&self, count: u32) {
        // Memory barrier to ensure writes are visible
        std::sync::atomic::fence(Ordering::Release);
        self.mmap.producer().fetch_add(count, Ordering::Release);
        trace!("TX ring: submitted {} packets", count);
    }

    /// Check if kernel needs wakeup.
    #[inline]
    pub fn needs_wakeup(&self) -> bool {
        self.mmap.needs_wakeup()
    }
}

// SAFETY: Ring can be sent between threads
unsafe impl Send for TxRing {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ring_config_validation() {
        // Valid sizes (power of 2)
        assert!(RingConfig::new(1024).is_ok());
        assert!(RingConfig::new(4096).is_ok());
        assert!(RingConfig::new(16384).is_ok());

        // Invalid sizes (not power of 2)
        assert!(RingConfig::new(1000).is_err());
        assert!(RingConfig::new(3000).is_err());
    }

    #[test]
    fn test_ring_config_default() {
        let config = RingConfig::default();
        assert_eq!(config.size, 4096);
        assert!(config.size.is_power_of_two());
    }
}
