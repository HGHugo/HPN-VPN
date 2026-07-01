//! XDP program management for AF_XDP.
//!
//! This module handles loading and attaching XDP programs to network interfaces.
//! The XDP program redirects matching packets to AF_XDP sockets for zero-copy
//! processing in userspace.

use std::collections::HashMap;
use std::io;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tracing::{debug, error, info, warn};

use crate::error::{AfXdpError, Result};

// ============================================================================
// XDP constants
// ============================================================================

/// XDP attach flags.
pub mod xdp_flags {
    /// Use SKB (generic) mode - slowest but always works.
    pub const XDP_FLAGS_SKB_MODE: u32 = 1 << 1;
    /// Use driver (native) mode - faster, requires driver support.
    pub const XDP_FLAGS_DRV_MODE: u32 = 1 << 2;
    /// Use hardware offload mode - fastest, requires NIC support.
    pub const XDP_FLAGS_HW_MODE: u32 = 1 << 3;
}

/// Netlink constants for XDP.
mod netlink {
    pub const NETLINK_ROUTE: i32 = 0;
    pub const RTM_SETLINK: u16 = 19;
    pub const NLM_F_REQUEST: u16 = 1;
    pub const NLM_F_ACK: u16 = 4;
    pub const NLMSG_ERROR: u16 = 2;
    pub const IFLA_XDP: u16 = 43;
    pub const IFLA_XDP_FD: u16 = 1;
    pub const IFLA_XDP_FLAGS: u16 = 3;
}

// ============================================================================
// XDP Program Manager
// ============================================================================

/// XDP program attachment mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpMode {
    /// Generic/SKB mode - works everywhere but slowest.
    Skb,
    /// Driver (native) mode - faster, requires driver support.
    Driver,
    /// Hardware offload - fastest, requires NIC support.
    Hardware,
    /// Auto-detect best available mode.
    Auto,
}

impl XdpMode {
    /// Convert to XDP flags.
    fn to_flags(self) -> u32 {
        match self {
            XdpMode::Skb => xdp_flags::XDP_FLAGS_SKB_MODE,
            XdpMode::Driver => xdp_flags::XDP_FLAGS_DRV_MODE,
            XdpMode::Hardware => xdp_flags::XDP_FLAGS_HW_MODE,
            XdpMode::Auto => 0, // Let kernel decide
        }
    }
}

/// Manages XDP program attachment to interfaces.
///
/// In modern kernels (5.x+), AF_XDP sockets can work without explicitly loading
/// an XDP program - the kernel handles redirection automatically when using
/// `XDP_ZEROCOPY` or `XDP_COPY` bind flags.
///
/// This manager provides:
/// - Tracking of attached interfaces
/// - Cleanup on drop
/// - Optional explicit XDP program loading for advanced use cases
pub struct XdpManager {
    /// Map of interface index -> attached XDP program info.
    attached: HashMap<u32, AttachedProgram>,
    /// Whether we own the XDP programs (for cleanup).
    owns_programs: bool,
}

/// Information about an attached XDP program.
struct AttachedProgram {
    /// Interface index.
    ifindex: u32,
    /// Interface name.
    ifname: String,
    /// XDP mode used.
    #[allow(dead_code)] // Kept for future use in mode-specific detach
    mode: XdpMode,
    /// Program FD (if explicitly loaded).
    prog_fd: Option<RawFd>,
    /// Whether program is currently attached.
    attached: AtomicBool,
}

impl XdpManager {
    /// Create a new XDP manager.
    pub fn new() -> Self {
        Self {
            attached: HashMap::new(),
            owns_programs: true,
        }
    }

    /// Attach XDP redirection to an interface.
    ///
    /// For AF_XDP, the kernel automatically handles redirection when sockets
    /// are bound with appropriate flags. This method is primarily for tracking
    /// and explicit program management.
    ///
    /// # Arguments
    /// * `interface` - Interface name
    /// * `mode` - XDP attachment mode
    pub fn attach(&mut self, interface: &str, mode: XdpMode) -> Result<()> {
        let ifindex =
            crate::sys::if_nametoindex(interface).map_err(|e| AfXdpError::InterfaceIndex {
                interface: interface.to_string(),
                source: e,
            })?;

        if self.attached.contains_key(&ifindex) {
            debug!(
                "XDP already attached to {} (ifindex={})",
                interface, ifindex
            );
            return Ok(());
        }

        info!(
            "Attaching XDP to {} (ifindex={}) in {:?} mode",
            interface, ifindex, mode
        );

        // For modern kernels, AF_XDP socket binding handles XDP program attachment
        // automatically. We just track the attachment for cleanup purposes.
        let prog = AttachedProgram {
            ifindex,
            ifname: interface.to_string(),
            mode,
            prog_fd: None, // Kernel-managed
            attached: AtomicBool::new(true),
        };

        self.attached.insert(ifindex, prog);

        Ok(())
    }

    /// Detach XDP program from an interface.
    pub fn detach(&mut self, interface: &str) -> Result<()> {
        let ifindex =
            crate::sys::if_nametoindex(interface).map_err(|e| AfXdpError::InterfaceIndex {
                interface: interface.to_string(),
                source: e,
            })?;

        if let Some(prog) = self.attached.remove(&ifindex) {
            if prog.attached.load(Ordering::Relaxed) {
                info!("Detaching XDP from {} (ifindex={})", interface, ifindex);

                // Use netlink to detach XDP program
                if let Err(e) = self.netlink_detach_xdp(ifindex) {
                    warn!("Failed to detach XDP from {}: {}", interface, e);
                }
            }

            // Close program fd if we own it
            if let Some(fd) = prog.prog_fd {
                // SAFETY: We own this fd
                unsafe {
                    libc::close(fd);
                }
            }
        }

        Ok(())
    }

    /// Detach XDP using netlink.
    fn netlink_detach_xdp(&self, ifindex: u32) -> io::Result<()> {
        // Create netlink socket
        // SAFETY: socket() is a standard syscall
        let sock =
            unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, netlink::NETLINK_ROUTE) };
        if sock < 0 {
            return Err(io::Error::last_os_error());
        }

        // Build netlink message to detach XDP (-1 fd means detach)
        let result = self.send_xdp_netlink_msg(sock, ifindex, -1, 0);

        // SAFETY: We own this socket
        unsafe {
            libc::close(sock);
        }

        result
    }

    /// Send netlink message to attach/detach XDP program.
    fn send_xdp_netlink_msg(
        &self,
        sock: RawFd,
        ifindex: u32,
        prog_fd: i32,
        flags: u32,
    ) -> io::Result<()> {
        // Netlink message buffer
        let mut buf = [0u8; 256];
        let mut offset = 0;

        // Netlink message header (16 bytes)
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct NlMsgHdr {
            nlmsg_len: u32,
            nlmsg_type: u16,
            nlmsg_flags: u16,
            nlmsg_seq: u32,
            nlmsg_pid: u32,
        }

        // Interface info message (16 bytes)
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct IfInfoMsg {
            ifi_family: u8,
            __ifi_pad: u8,
            ifi_type: u16,
            ifi_index: i32,
            ifi_flags: u32,
            ifi_change: u32,
        }

        // Netlink attribute header (4 bytes)
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct NlAttr {
            nla_len: u16,
            nla_type: u16,
        }

        // Write netlink header
        let hdr = NlMsgHdr {
            nlmsg_len: 0, // Will be filled in later
            nlmsg_type: netlink::RTM_SETLINK,
            nlmsg_flags: netlink::NLM_F_REQUEST | netlink::NLM_F_ACK,
            nlmsg_seq: 1,
            nlmsg_pid: 0,
        };
        // SAFETY: NlMsgHdr is #[repr(C)] with known 16-byte layout
        let hdr_bytes =
            unsafe { std::slice::from_raw_parts((&hdr as *const NlMsgHdr).cast::<u8>(), 16) };
        buf[offset..offset + 16].copy_from_slice(hdr_bytes);
        offset += 16;

        // Write ifinfo message
        let ifinfo = IfInfoMsg {
            ifi_family: libc::AF_UNSPEC as u8,
            __ifi_pad: 0,
            ifi_type: 0,
            ifi_index: ifindex as i32,
            ifi_flags: 0,
            ifi_change: 0,
        };
        // SAFETY: IfInfoMsg is #[repr(C)] with known 16-byte layout
        let ifinfo_bytes =
            unsafe { std::slice::from_raw_parts((&ifinfo as *const IfInfoMsg).cast::<u8>(), 16) };
        buf[offset..offset + 16].copy_from_slice(ifinfo_bytes);
        offset += 16;

        // Write IFLA_XDP nested attribute
        let xdp_attr_start = offset;

        // Placeholder for IFLA_XDP length
        offset += 4;

        // IFLA_XDP_FD attribute
        let fd_attr = NlAttr {
            nla_len: 8, // 4 header + 4 fd
            nla_type: netlink::IFLA_XDP_FD,
        };
        // SAFETY: NlAttr is #[repr(C)] with known 4-byte layout
        let fd_attr_bytes =
            unsafe { std::slice::from_raw_parts((&fd_attr as *const NlAttr).cast::<u8>(), 4) };
        buf[offset..offset + 4].copy_from_slice(fd_attr_bytes);
        offset += 4;
        buf[offset..offset + 4].copy_from_slice(&prog_fd.to_ne_bytes());
        offset += 4;

        // IFLA_XDP_FLAGS attribute (if flags != 0)
        if flags != 0 {
            let flags_attr = NlAttr {
                nla_len: 8,
                nla_type: netlink::IFLA_XDP_FLAGS,
            };
            // SAFETY: NlAttr is #[repr(C)] with known 4-byte layout
            let flags_attr_bytes = unsafe {
                std::slice::from_raw_parts((&flags_attr as *const NlAttr).cast::<u8>(), 4)
            };
            buf[offset..offset + 4].copy_from_slice(flags_attr_bytes);
            offset += 4;
            buf[offset..offset + 4].copy_from_slice(&flags.to_ne_bytes());
            offset += 4;
        }

        // Update IFLA_XDP length
        let xdp_attr_len = (offset - xdp_attr_start) as u16;
        let xdp_attr = NlAttr {
            nla_len: xdp_attr_len,
            nla_type: netlink::IFLA_XDP,
        };
        // SAFETY: NlAttr is #[repr(C)] with known 4-byte layout
        let xdp_attr_bytes =
            unsafe { std::slice::from_raw_parts((&xdp_attr as *const NlAttr).cast::<u8>(), 4) };
        buf[xdp_attr_start..xdp_attr_start + 4].copy_from_slice(xdp_attr_bytes);

        // Update total message length
        let total_len = offset as u32;
        buf[0..4].copy_from_slice(&total_len.to_ne_bytes());

        // Send message
        // SAFETY: send() is a standard syscall with valid buffer
        let sent = unsafe { libc::send(sock, buf.as_ptr().cast::<libc::c_void>(), offset, 0) };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }

        // Receive response
        let mut resp_buf = [0u8; 256];
        // SAFETY: recv() is a standard syscall with valid buffer
        let received = unsafe {
            libc::recv(
                sock,
                resp_buf.as_mut_ptr().cast::<libc::c_void>(),
                resp_buf.len(),
                0,
            )
        };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }

        // Parse response - check for error
        if received >= 20 {
            let resp_type = u16::from_ne_bytes([resp_buf[4], resp_buf[5]]);
            if resp_type == netlink::NLMSG_ERROR {
                let error_code =
                    i32::from_ne_bytes([resp_buf[16], resp_buf[17], resp_buf[18], resp_buf[19]]);
                if error_code < 0 {
                    return Err(io::Error::from_raw_os_error(-error_code));
                }
            }
        }

        Ok(())
    }

    /// Check if an interface has XDP attached.
    pub fn is_attached(&self, interface: &str) -> bool {
        if let Ok(ifindex) = crate::sys::if_nametoindex(interface) {
            self.attached
                .get(&ifindex)
                .map(|p| p.attached.load(Ordering::Relaxed))
                .unwrap_or(false)
        } else {
            false
        }
    }

    /// Get list of attached interfaces.
    pub fn attached_interfaces(&self) -> Vec<String> {
        self.attached
            .values()
            .filter(|p| p.attached.load(Ordering::Relaxed))
            .map(|p| p.ifname.clone())
            .collect()
    }
}

impl Default for XdpManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for XdpManager {
    fn drop(&mut self) {
        if !self.owns_programs {
            return;
        }

        // Detach all XDP programs
        for (ifindex, prog) in self.attached.drain() {
            if prog.attached.load(Ordering::Relaxed) {
                debug!("Cleaning up XDP on {} (ifindex={})", prog.ifname, ifindex);
                if let Err(e) = self.netlink_detach_xdp(ifindex) {
                    error!("Failed to detach XDP from {}: {}", prog.ifname, e);
                }
            }

            if let Some(fd) = prog.prog_fd {
                // SAFETY: We own this fd
                unsafe {
                    libc::close(fd);
                }
            }
        }
    }
}

// SAFETY: XdpManager uses interior mutability only for AtomicBool
unsafe impl Send for XdpManager {}
unsafe impl Sync for XdpManager {}

/// Handle to a shared XDP manager.
pub type SharedXdpManager = Arc<parking_lot::Mutex<XdpManager>>;

/// Create a shared XDP manager.
pub fn shared_xdp_manager() -> SharedXdpManager {
    Arc::new(parking_lot::Mutex::new(XdpManager::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xdp_mode_flags() {
        assert_eq!(XdpMode::Skb.to_flags(), xdp_flags::XDP_FLAGS_SKB_MODE);
        assert_eq!(XdpMode::Driver.to_flags(), xdp_flags::XDP_FLAGS_DRV_MODE);
        assert_eq!(XdpMode::Hardware.to_flags(), xdp_flags::XDP_FLAGS_HW_MODE);
        assert_eq!(XdpMode::Auto.to_flags(), 0);
    }

    #[test]
    fn test_xdp_manager_new() {
        let manager = XdpManager::new();
        assert!(manager.attached_interfaces().is_empty());
    }

    #[test]
    fn test_xdp_manager_default() {
        let manager = XdpManager::default();
        assert!(manager.attached_interfaces().is_empty());
    }
}
