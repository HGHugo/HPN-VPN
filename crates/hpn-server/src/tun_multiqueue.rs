//! Multi-queue TUN device support for high-throughput parallel I/O.
//!
//! This module provides support for Linux's `IFF_MULTI_QUEUE` TUN feature,
//! which allows multiple file descriptors for the same TUN device.
//! This enables parallel reads/writes from multiple threads without
//! kernel-level contention.
//!
//! # Performance Benefits
//!
//! - **Parallel I/O**: Multiple threads can read/write without locking
//! - **Kernel load balancing**: Packets distributed across queues
//! - **Reduced contention**: Each thread has its own file descriptor
//!
//! # Usage
//!
//! ```rust,ignore
//! let tun = MultiQueueTun::create("hpn0", num_queues)?;
//! let queues = tun.take_queues();
//!
//! for (id, queue) in queues.into_iter().enumerate() {
//!     thread::spawn(move || {
//!         // Each thread handles one queue
//!     });
//! }
//! ```

#![allow(unsafe_code)]

use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};

use tracing::{debug, info, warn};

use crate::error::{ServerError, ServerResult};
use crate::validation::{validate_interface_name, validate_ipv4_cidr, validate_ipv6_cidr};

/// TUN device flags.
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
const IFF_MULTI_QUEUE: libc::c_short = 0x0100;

/// Maximum number of queues supported.
pub const MAX_QUEUES: usize = 16;

/// A single TUN queue (file descriptor).
pub struct TunQueue {
    /// File descriptor.
    fd: OwnedFd,
    /// Queue index.
    index: usize,
}

impl TunQueue {
    /// Create from raw fd (private, internal use).
    fn from_raw(fd: RawFd, index: usize) -> Self {
        Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            index,
        }
    }

    /// Create from raw fd (public, for multiqueue worker spawning).
    ///
    /// # Safety
    /// Caller must ensure the fd is valid and will not be closed elsewhere.
    pub fn from_raw_fd(fd: RawFd, index: usize) -> Self {
        Self::from_raw(fd, index)
    }

    /// Create from OwnedFd (RAII-safe, prevents leaks).
    ///
    /// This is the preferred method as it ensures the FD is properly closed
    /// even on error paths.
    pub fn from_owned_fd(fd: OwnedFd, index: usize) -> Self {
        Self { fd, index }
    }

    /// Get queue index.
    pub fn index(&self) -> usize {
        self.index
    }

    /// Read a packet from this queue.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let n = unsafe { libc::read(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    /// Write a packet to this queue.
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        let n = unsafe { libc::write(self.fd.as_raw_fd(), buf.as_ptr().cast(), buf.len()) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    /// Write multiple packets to this queue using writev (batch syscall).
    ///
    /// Each iovec element represents one complete IP packet.
    /// Returns the total number of bytes written.
    ///
    /// Note: Unlike regular files, TUN devices process packets individually,
    /// so writev writes each iovec as a separate packet to the kernel.
    /// This is more efficient than multiple write() calls.
    #[cfg(target_os = "linux")]
    pub fn send_batch(&self, iovecs: &[libc::iovec]) -> io::Result<usize> {
        if iovecs.is_empty() {
            return Ok(0);
        }

        let n = unsafe {
            libc::writev(
                self.fd.as_raw_fd(),
                iovecs.as_ptr(),
                iovecs.len() as libc::c_int,
            )
        };

        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    /// Set non-blocking mode.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        let fd = self.fd.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }

        let new_flags = if nonblocking {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };

        let result = unsafe { libc::fcntl(fd, libc::F_SETFL, new_flags) };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

impl AsRawFd for TunQueue {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl IntoRawFd for TunQueue {
    fn into_raw_fd(self) -> RawFd {
        self.fd.into_raw_fd()
    }
}

/// Multi-queue TUN device.
///
/// Provides multiple file descriptors for parallel I/O on a single TUN device.
pub struct MultiQueueTun {
    /// Device name.
    name: String,
    /// TUN queues (file descriptors).
    queues: Vec<TunQueue>,
    /// MTU.
    mtu: u16,
}

impl MultiQueueTun {
    /// Create a new multi-queue TUN device.
    ///
    /// # Arguments
    /// * `name` - Device name (e.g., "hpn0")
    /// * `num_queues` - Number of queues to create
    ///
    /// # Note
    /// Requires CAP_NET_ADMIN capability or root privileges.
    #[cfg(target_os = "linux")]
    pub fn create(name: &str, num_queues: usize) -> ServerResult<Self> {
        // Validate interface name before using in commands
        validate_interface_name(name)?;

        let num_queues = num_queues.min(MAX_QUEUES);
        if num_queues == 0 {
            return Err(ServerError::Tun("num_queues must be > 0".into()));
        }

        let mut queues = Vec::with_capacity(num_queues);

        // Open /dev/net/tun for each queue
        for i in 0..num_queues {
            let fd = Self::open_queue(name, i == 0)?;
            queues.push(TunQueue::from_raw(fd, i));
        }

        info!(
            "Created multi-queue TUN device {} with {} queues",
            name, num_queues
        );

        Ok(Self {
            name: name.to_string(),
            queues,
            mtu: 1500,
        })
    }

    /// Open a single TUN queue.
    #[cfg(target_os = "linux")]
    fn open_queue(name: &str, first: bool) -> ServerResult<RawFd> {
        use std::ffi::CString;

        // Open /dev/net/tun
        let tun_path = CString::new("/dev/net/tun").unwrap();
        let fd = unsafe { libc::open(tun_path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(ServerError::Tun(format!(
                "failed to open /dev/net/tun: {}",
                io::Error::last_os_error()
            )));
        }

        // Prepare ifreq struct
        #[repr(C)]
        struct IfReq {
            ifr_name: [libc::c_char; libc::IFNAMSIZ],
            ifr_flags: libc::c_short,
            _pad: [u8; 22],
        }

        let mut ifr: IfReq = unsafe { std::mem::zeroed() };

        // Copy name
        let name_bytes = name.as_bytes();
        let copy_len = name_bytes.len().min(libc::IFNAMSIZ - 1);
        for (i, &b) in name_bytes.iter().take(copy_len).enumerate() {
            ifr.ifr_name[i] = b as libc::c_char;
        }

        // Set flags
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;

        // TUNSETIFF ioctl
        const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
        let result = unsafe { libc::ioctl(fd, TUNSETIFF, &ifr) };
        if result < 0 {
            unsafe { libc::close(fd) };
            return Err(ServerError::Tun(format!(
                "TUNSETIFF failed: {}",
                io::Error::last_os_error()
            )));
        }

        // If this is the first queue, bring up the interface
        if first {
            Self::bring_up_interface(name)?;
        }

        debug!(
            "Opened TUN queue for device {} (fd={}, first={})",
            name, fd, first
        );

        Ok(fd)
    }

    /// Bring up the network interface.
    #[cfg(target_os = "linux")]
    fn bring_up_interface(name: &str) -> ServerResult<()> {
        use std::process::Command;

        // Validate interface name (caller should have validated, but defense in depth)
        validate_interface_name(name)?;

        let output = Command::new("ip")
            .args(["link", "set", name, "up"])
            .output()
            .map_err(|e| ServerError::Tun(format!("failed to run ip command: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("Failed to bring up interface {}: {}", name, stderr);
        }

        Ok(())
    }

    /// Configure IPv4 address on the interface.
    #[cfg(target_os = "linux")]
    pub fn configure_ipv4(&self, ip: [u8; 4], prefix_len: u8) -> ServerResult<()> {
        use std::process::Command;

        // Validate interface name before using in command
        validate_interface_name(&self.name)?;

        let ip_str = format!("{}.{}.{}.{}/{}", ip[0], ip[1], ip[2], ip[3], prefix_len);

        // Validate the constructed CIDR
        validate_ipv4_cidr(&ip_str)?;

        let output = Command::new("ip")
            .args(["addr", "add", &ip_str, "dev", &self.name])
            .output()
            .map_err(|e| ServerError::Tun(format!("failed to run ip command: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Ignore "already exists" errors
            if !stderr.contains("RTNETLINK answers: File exists") {
                return Err(ServerError::Tun(format!(
                    "failed to configure IPv4: {}",
                    stderr
                )));
            }
        }

        info!("Configured IPv4 {} on {}", ip_str, self.name);
        Ok(())
    }

    /// Configure IPv6 address on the interface.
    #[cfg(target_os = "linux")]
    pub fn configure_ipv6(&self, ip: [u8; 16], prefix_len: u8) -> ServerResult<()> {
        use std::net::Ipv6Addr;
        use std::process::Command;

        // Validate interface name before using in command
        validate_interface_name(&self.name)?;

        let ipv6_addr = Ipv6Addr::from(ip);
        let ip_str = format!("{}/{}", ipv6_addr, prefix_len);

        // Validate the constructed CIDR
        validate_ipv6_cidr(&ip_str)?;

        let output = Command::new("ip")
            .args(["-6", "addr", "add", &ip_str, "dev", &self.name])
            .output()
            .map_err(|e| ServerError::Tun(format!("failed to run ip command: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("RTNETLINK answers: File exists") {
                return Err(ServerError::Tun(format!(
                    "failed to configure IPv6: {}",
                    stderr
                )));
            }
        }

        info!("Configured IPv6 {} on {}", ip_str, self.name);
        Ok(())
    }

    /// Set MTU on the interface.
    #[cfg(target_os = "linux")]
    pub fn set_mtu(&mut self, mtu: u16) -> ServerResult<()> {
        use std::process::Command;

        // Validate interface name before using in command
        validate_interface_name(&self.name)?;

        let output = Command::new("ip")
            .args(["link", "set", &self.name, "mtu", &mtu.to_string()])
            .output()
            .map_err(|e| ServerError::Tun(format!("failed to run ip command: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ServerError::Tun(format!("failed to set MTU: {}", stderr)));
        }

        self.mtu = mtu;
        info!("Set MTU {} on {}", mtu, self.name);
        Ok(())
    }

    /// Get device name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get number of queues.
    pub fn num_queues(&self) -> usize {
        self.queues.len()
    }

    /// Get MTU.
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Get mutable references to all queues.
    ///
    /// Useful for setting non-blocking mode before spawning threads.
    pub fn queues_mut(&mut self) -> &mut [TunQueue] {
        &mut self.queues
    }

    /// Get immutable references to all queues.
    ///
    /// Useful for duplicating file descriptors for reader/writer split.
    pub fn queues(&self) -> &[TunQueue] {
        &self.queues
    }

    /// Take ownership of the queues.
    ///
    /// After this call, the `MultiQueueTun` can no longer be used for I/O.
    pub fn take_queues(&mut self) -> Vec<TunQueue> {
        std::mem::take(&mut self.queues)
    }

    /// Get a reference to a specific queue.
    pub fn queue(&self, index: usize) -> Option<&TunQueue> {
        self.queues.get(index)
    }

    /// Set all queues to non-blocking mode.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        for queue in &self.queues {
            queue.set_nonblocking(nonblocking)?;
        }
        Ok(())
    }
}

/// Check if multi-queue TUN is supported by the kernel.
///
/// This function attempts to detect kernel support for `IFF_MULTI_QUEUE`.
/// Returns `true` if supported, `false` otherwise.
#[cfg(target_os = "linux")]
pub fn is_multiqueue_supported() -> bool {
    // Try to open /dev/net/tun with multiqueue flag
    use std::ffi::CString;

    let tun_path = match CString::new("/dev/net/tun") {
        Ok(p) => p,
        Err(_) => return false,
    };

    let fd = unsafe { libc::open(tun_path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        debug!("Cannot open /dev/net/tun - multiqueue not supported");
        return false;
    }

    // Prepare ifreq with multiqueue flag
    #[repr(C)]
    struct IfReq {
        ifr_name: [libc::c_char; libc::IFNAMSIZ],
        ifr_flags: libc::c_short,
        _pad: [u8; 22],
    }

    let mut ifr: IfReq = unsafe { std::mem::zeroed() };
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;

    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
    let result = unsafe { libc::ioctl(fd, TUNSETIFF, &ifr) };
    unsafe { libc::close(fd) };

    if result < 0 {
        debug!("Kernel does not support IFF_MULTI_QUEUE");
        false
    } else {
        debug!("Kernel supports IFF_MULTI_QUEUE - multi-queue TUN available");
        true
    }
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub fn is_multiqueue_supported() -> bool {
    false
}

impl Drop for MultiQueueTun {
    fn drop(&mut self) {
        // FDs are automatically closed when queues are dropped
        debug!("Closing multi-queue TUN device {}", self.name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_max_queues() {
        assert!(MAX_QUEUES > 0);
        assert!(MAX_QUEUES <= 64);
    }

    #[test]
    fn test_is_multiqueue_supported() {
        // Just ensure it doesn't panic
        let _ = is_multiqueue_supported();
    }
}
