//! Low-level system bindings for AF_XDP.
//!
//! This module provides raw syscall interfaces and kernel structure definitions
//! for AF_XDP socket operations.

use std::ffi::CString;
use std::io;
use std::os::unix::io::RawFd;

// ============================================================================
// Constants from linux/if_xdp.h
// ============================================================================

/// AF_XDP socket family.
pub const AF_XDP: i32 = 44;

/// XDP ring offset magic for mmap.
pub const XDP_PGOFF_RX_RING: u64 = 0;
pub const XDP_PGOFF_TX_RING: u64 = 0x8000_0000;
pub const XDP_UMEM_PGOFF_FILL_RING: u64 = 0x1_0000_0000;
pub const XDP_UMEM_PGOFF_COMPLETION_RING: u64 = 0x1_8000_0000;

/// Socket options for AF_XDP.
pub const SOL_XDP: i32 = 283;

pub const XDP_MMAP_OFFSETS: i32 = 1;
pub const XDP_RX_RING: i32 = 2;
pub const XDP_TX_RING: i32 = 3;
pub const XDP_UMEM_REG: i32 = 4;
pub const XDP_UMEM_FILL_RING: i32 = 5;
pub const XDP_UMEM_COMPLETION_RING: i32 = 6;
pub const XDP_STATISTICS: i32 = 7;

/// XDP bind flags.
pub const XDP_COPY: u16 = 1 << 1;
pub const XDP_ZEROCOPY: u16 = 1 << 2;
pub const XDP_USE_NEED_WAKEUP: u16 = 1 << 3;

/// XDP ring flags.
pub const XDP_RING_NEED_WAKEUP: u32 = 1 << 0;

/// Minimum and maximum frame sizes.
pub const XDP_MIN_FRAME_SIZE: u32 = 2048;
pub const XDP_MAX_FRAME_SIZE: u32 = 4096;

// ============================================================================
// Kernel structures
// ============================================================================

/// XDP socket address for bind().
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SockaddrXdp {
    pub sxdp_family: u16,
    pub sxdp_flags: u16,
    pub sxdp_ifindex: u32,
    pub sxdp_queue_id: u32,
    pub sxdp_shared_umem_fd: u32,
}

/// UMEM registration structure.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct XdpUmemReg {
    pub addr: u64,
    pub len: u64,
    pub chunk_size: u32,
    pub headroom: u32,
    pub flags: u32,
}

/// Ring offset information from getsockopt.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct XdpRingOffset {
    pub producer: u64,
    pub consumer: u64,
    pub desc: u64,
    pub flags: u64,
}

/// Mmap offsets for all rings.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct XdpMmapOffsets {
    pub rx: XdpRingOffset,
    pub tx: XdpRingOffset,
    pub fr: XdpRingOffset, // Fill ring
    pub cr: XdpRingOffset, // Completion ring
}

/// RX/TX ring descriptor.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct XdpDesc {
    pub addr: u64,
    pub len: u32,
    pub options: u32,
}

/// XDP statistics from getsockopt.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct XdpStatistics {
    pub rx_dropped: u64,
    pub rx_invalid_descs: u64,
    pub tx_invalid_descs: u64,
    pub rx_ring_full: u64,
    pub rx_fill_ring_empty_descs: u64,
    pub tx_ring_empty_descs: u64,
}

// ============================================================================
// Syscall wrappers
// ============================================================================

/// Create an AF_XDP socket.
pub fn xsk_socket() -> io::Result<RawFd> {
    // SAFETY: socket() is a standard syscall with no memory safety concerns
    let fd = unsafe { libc::socket(AF_XDP, libc::SOCK_RAW, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

/// Bind an AF_XDP socket to an interface queue.
pub fn xsk_bind(fd: RawFd, addr: &SockaddrXdp) -> io::Result<()> {
    // SAFETY: bind() is a standard syscall, addr points to valid memory
    let ret = unsafe {
        libc::bind(
            fd,
            (addr as *const SockaddrXdp).cast::<libc::sockaddr>(),
            std::mem::size_of::<SockaddrXdp>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Set socket option.
pub fn xsk_setsockopt<T>(fd: RawFd, optname: i32, optval: &T) -> io::Result<()> {
    // SAFETY: setsockopt is a standard syscall with valid parameters
    let ret = unsafe {
        libc::setsockopt(
            fd,
            SOL_XDP,
            optname,
            (optval as *const T).cast::<libc::c_void>(),
            std::mem::size_of::<T>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Get socket option.
pub fn xsk_getsockopt<T: Default>(fd: RawFd, optname: i32) -> io::Result<T> {
    let mut optval = T::default();
    let mut optlen = std::mem::size_of::<T>() as libc::socklen_t;

    // SAFETY: getsockopt is a standard syscall with valid parameters
    let ret = unsafe {
        libc::getsockopt(
            fd,
            SOL_XDP,
            optname,
            (&mut optval as *mut T).cast::<libc::c_void>(),
            &mut optlen,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(optval)
}

/// Get mmap offsets for rings.
pub fn xsk_get_mmap_offsets(fd: RawFd) -> io::Result<XdpMmapOffsets> {
    xsk_getsockopt(fd, XDP_MMAP_OFFSETS)
}

/// Get XDP statistics.
pub fn xsk_get_statistics(fd: RawFd) -> io::Result<XdpStatistics> {
    xsk_getsockopt(fd, XDP_STATISTICS)
}

/// Get interface index by name.
pub fn if_nametoindex(name: &str) -> io::Result<u32> {
    let c_name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface name contains null"))?;

    // SAFETY: if_nametoindex is a standard libc function with valid C string
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(index)
}

/// Memory map a region.
pub fn mmap_ring(fd: RawFd, size: usize, offset: u64) -> io::Result<*mut u8> {
    // SAFETY: mmap is a standard syscall with valid parameters
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_POPULATE,
            fd,
            offset as libc::off_t,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    Ok(ptr.cast::<u8>())
}

/// Unmap a memory region.
///
/// # Safety
/// ptr must be a valid mapped region of the given size.
pub unsafe fn munmap_ring(ptr: *mut u8, size: usize) -> io::Result<()> {
    let ret = libc::munmap(ptr.cast::<libc::c_void>(), size);
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Poll a socket for readiness.
pub fn poll_socket(fd: RawFd, events: i16, timeout_ms: i32) -> io::Result<i16> {
    let mut pfd = libc::pollfd {
        fd,
        events,
        revents: 0,
    };

    // SAFETY: poll is a standard syscall with valid parameters
    let ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(pfd.revents)
}

/// Send a wakeup to the kernel (needed when XDP_USE_NEED_WAKEUP is set).
pub fn xsk_sendto(fd: RawFd) -> io::Result<()> {
    // SAFETY: sendto with MSG_DONTWAIT on XDP socket triggers TX processing
    let ret = unsafe {
        libc::sendto(
            fd,
            std::ptr::null(),
            0,
            libc::MSG_DONTWAIT,
            std::ptr::null(),
            0,
        )
    };
    // EAGAIN is expected and OK for non-blocking send
    if ret < 0 {
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::WouldBlock {
            return Err(err);
        }
    }
    Ok(())
}

/// Check if AF_XDP is supported on this kernel.
pub fn is_afxdp_supported() -> bool {
    match xsk_socket() {
        Ok(fd) => {
            // SAFETY: closing a valid fd we just created
            unsafe { libc::close(fd) };
            true
        }
        Err(e) => {
            // EPERM means we don't have permission but AF_XDP is supported
            e.raw_os_error() == Some(libc::EPERM)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sockaddr_xdp_size() {
        assert_eq!(std::mem::size_of::<SockaddrXdp>(), 16);
    }

    #[test]
    fn test_xdp_desc_size() {
        assert_eq!(std::mem::size_of::<XdpDesc>(), 16);
    }

    #[test]
    fn test_xdp_umem_reg_size() {
        assert_eq!(std::mem::size_of::<XdpUmemReg>(), 28);
    }

    #[test]
    fn test_constants() {
        assert_eq!(AF_XDP, 44);
        assert_eq!(SOL_XDP, 283);
    }

    #[test]
    fn test_xdp_ring_offset_size() {
        assert_eq!(std::mem::size_of::<XdpRingOffset>(), 32);
    }

    #[test]
    fn test_xdp_statistics_size() {
        assert_eq!(std::mem::size_of::<XdpStatistics>(), 48);
    }
}
