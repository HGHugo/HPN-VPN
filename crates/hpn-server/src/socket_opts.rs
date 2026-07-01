//! Socket optimization utilities for high-throughput networking.
//!
//! This module provides socket configuration options for maximizing
//! UDP throughput on Linux servers.
//!
//! # Optimizations
//!
//! - **SO_BUSY_POLL**: Reduce latency by polling in kernel
//! - **SO_RCVBUF/SO_SNDBUF**: Large socket buffers
//! - **SO_REUSEPORT**: Multi-queue socket load balancing
//! - **UDP_GRO**: Generic Receive Offload for UDP
//! - **UDP_SEGMENT**: UDP Segmentation Offload (GSO)
//! - **SO_ZEROCOPY**: Zero-copy sendmsg
//!
//! # Usage
//!
//! ```rust,ignore
//! use hpn_server::socket_opts::optimize_udp_socket;
//!
//! let socket = std::net::UdpSocket::bind("0.0.0.0:51820")?;
//! optimize_udp_socket(&socket, &SocketOptions::high_throughput())?;
//! ```

#![allow(unsafe_code)]
#![allow(clippy::ptr_as_ptr, clippy::ref_as_ptr)]

use std::io;
use std::net::UdpSocket;
use std::os::unix::io::AsRawFd;

use tracing::{debug, info, warn};

// Linux socket options not in libc
const SO_BUSY_POLL: libc::c_int = 46;
const SO_BUSY_POLL_BUDGET: libc::c_int = 70;
const SO_PREFER_BUSY_POLL: libc::c_int = 69;
const SO_ZEROCOPY: libc::c_int = 60;

// UDP-specific options
const UDP_SEGMENT: libc::c_int = 103;
const UDP_GRO: libc::c_int = 104;

/// Socket optimization options.
#[derive(Debug, Clone)]
pub struct SocketOptions {
    /// Receive buffer size (bytes). Default: 16MB.
    pub recv_buffer_size: usize,
    /// Send buffer size (bytes). Default: 16MB.
    pub send_buffer_size: usize,
    /// Enable SO_REUSEPORT for multi-queue.
    pub reuse_port: bool,
    /// Enable SO_REUSEADDR.
    pub reuse_addr: bool,
    /// SO_BUSY_POLL timeout (microseconds). 0 = disabled.
    pub busy_poll_us: u32,
    /// SO_BUSY_POLL_BUDGET (number of packets). 0 = default.
    pub busy_poll_budget: u32,
    /// Enable UDP GRO (Generic Receive Offload).
    pub udp_gro: bool,
    /// UDP GSO segment size. 0 = disabled.
    pub udp_gso_segment_size: u16,
    /// Enable SO_ZEROCOPY for sendmsg.
    pub zerocopy: bool,
    /// Set socket to non-blocking mode.
    pub non_blocking: bool,
    /// Enable IP_RECVORIGDSTADDR for transparent proxy.
    pub recv_orig_dst_addr: bool,
}

impl Default for SocketOptions {
    fn default() -> Self {
        Self {
            recv_buffer_size: 16 * 1024 * 1024, // 16MB
            send_buffer_size: 16 * 1024 * 1024, // 16MB
            reuse_port: true,
            reuse_addr: true,
            busy_poll_us: 0,
            busy_poll_budget: 0,
            udp_gro: false,
            udp_gso_segment_size: 0,
            zerocopy: false,
            non_blocking: true,
            recv_orig_dst_addr: false,
        }
    }
}

impl SocketOptions {
    /// Production-optimized socket options.
    ///
    /// Enabled optimizations:
    /// - Large socket buffers (16MB) for burst handling
    /// - SO_REUSEPORT for multi-worker load balancing
    /// - UDP_GRO: kernel coalesces RX packets, ~20-30% throughput gain
    ///
    /// Disabled (unstable/counterproductive):
    /// - UDP_GSO: breaks VPN handshake (large packets)
    /// - SO_ZEROCOPY: unstable with encryption workloads
    /// - SO_BUSY_POLL: wastes CPU on VPS/cloud
    pub fn high_throughput() -> Self {
        Self {
            recv_buffer_size: 16 * 1024 * 1024, // 16MB - sufficient for 10Gbps
            send_buffer_size: 16 * 1024 * 1024, // 16MB
            reuse_port: true,
            reuse_addr: true,
            busy_poll_us: 0,         // Disabled - wastes CPU on VPS
            busy_poll_budget: 0,     // Disabled
            udp_gro: true,           // Enabled - 20-30% RX throughput gain
            udp_gso_segment_size: 0, // Disabled - breaks handshake
            zerocopy: false,         // Disabled - unstable with crypto
            non_blocking: true,
            recv_orig_dst_addr: false,
        }
    }

    /// Alias for high_throughput - the production default.
    pub fn low_latency() -> Self {
        Self::high_throughput()
    }

    /// Alias for high_throughput - the production default.
    pub fn max_pps() -> Self {
        Self::high_throughput()
    }
}

/// Apply optimizations to a UDP socket.
pub fn optimize_udp_socket(socket: &UdpSocket, opts: &SocketOptions) -> io::Result<()> {
    let fd = socket.as_raw_fd();

    // Set buffer sizes
    set_socket_option(
        fd,
        libc::SOL_SOCKET,
        libc::SO_RCVBUF,
        opts.recv_buffer_size as i32,
    )?;
    set_socket_option(
        fd,
        libc::SOL_SOCKET,
        libc::SO_SNDBUF,
        opts.send_buffer_size as i32,
    )?;

    // Verify buffer sizes (kernel may limit)
    let actual_recv = get_socket_option(fd, libc::SOL_SOCKET, libc::SO_RCVBUF)?;
    let actual_send = get_socket_option(fd, libc::SOL_SOCKET, libc::SO_SNDBUF)?;
    debug!(
        "Socket buffers: recv={}KB (requested {}KB), send={}KB (requested {}KB)",
        actual_recv / 1024,
        opts.recv_buffer_size / 1024,
        actual_send / 1024,
        opts.send_buffer_size / 1024
    );

    // SO_REUSEPORT
    if opts.reuse_port {
        set_socket_option(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT, 1)?;
    }

    // SO_REUSEADDR
    if opts.reuse_addr {
        set_socket_option(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
    }

    // SO_BUSY_POLL
    if opts.busy_poll_us > 0 {
        if let Err(e) =
            set_socket_option(fd, libc::SOL_SOCKET, SO_BUSY_POLL, opts.busy_poll_us as i32)
        {
            warn!("Failed to set SO_BUSY_POLL: {} (may require root)", e);
        } else {
            debug!("SO_BUSY_POLL set to {}µs", opts.busy_poll_us);

            // Also set prefer busy poll and budget
            let _ = set_socket_option(fd, libc::SOL_SOCKET, SO_PREFER_BUSY_POLL, 1);

            if opts.busy_poll_budget > 0 {
                let _ = set_socket_option(
                    fd,
                    libc::SOL_SOCKET,
                    SO_BUSY_POLL_BUDGET,
                    opts.busy_poll_budget as i32,
                );
            }
        }
    }

    // UDP GRO
    if opts.udp_gro {
        if let Err(e) = set_socket_option(fd, libc::SOL_UDP, UDP_GRO, 1) {
            debug!("UDP_GRO not supported: {}", e);
        } else {
            debug!("UDP_GRO enabled");
        }
    }

    // UDP GSO (segmentation offload)
    if opts.udp_gso_segment_size > 0 {
        if let Err(e) = set_socket_option(
            fd,
            libc::SOL_UDP,
            UDP_SEGMENT,
            opts.udp_gso_segment_size as i32,
        ) {
            debug!("UDP_SEGMENT not supported: {}", e);
        } else {
            debug!("UDP_SEGMENT set to {}", opts.udp_gso_segment_size);
        }
    }

    // SO_ZEROCOPY
    if opts.zerocopy {
        if let Err(e) = set_socket_option(fd, libc::SOL_SOCKET, SO_ZEROCOPY, 1) {
            debug!("SO_ZEROCOPY not supported: {}", e);
        } else {
            debug!("SO_ZEROCOPY enabled");
        }
    }

    // Non-blocking mode
    if opts.non_blocking {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags >= 0 {
            unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        }
    }

    // IP_RECVORIGDSTADDR (for transparent proxy)
    if opts.recv_orig_dst_addr {
        let _ = set_socket_option(fd, libc::SOL_IP, libc::IP_RECVORIGDSTADDR, 1);
    }

    info!(
        "Socket optimized: buf_recv={}MB, buf_send={}MB, busy_poll={}µs",
        actual_recv / 1024 / 1024,
        actual_send / 1024 / 1024,
        opts.busy_poll_us
    );

    Ok(())
}

/// Set a socket option.
fn set_socket_option(fd: i32, level: i32, optname: i32, value: i32) -> io::Result<()> {
    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            optname,
            (&raw const value).cast::<libc::c_void>(),
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };

    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Get a socket option.
fn get_socket_option(fd: i32, level: i32, optname: i32) -> io::Result<i32> {
    let mut value: i32 = 0;
    let mut len: libc::socklen_t = std::mem::size_of::<i32>() as libc::socklen_t;

    let result = unsafe {
        libc::getsockopt(
            fd,
            level,
            optname,
            (&raw mut value).cast::<libc::c_void>(),
            &raw mut len,
        )
    };

    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(value)
    }
}

/// Tune system-wide network settings for high throughput.
///
/// These settings require root privileges and affect all network interfaces.
/// Returns a list of settings that were successfully applied.
pub fn tune_system_network() -> Vec<String> {
    let mut applied = Vec::new();

    let settings = [
        // Increase max socket buffer sizes (256MB for 10Gbps+)
        ("net.core.rmem_max", "268435456"),    // 256MB
        ("net.core.wmem_max", "268435456"),    // 256MB
        ("net.core.rmem_default", "33554432"), // 32MB
        ("net.core.wmem_default", "33554432"), // 32MB
        // Increase network device backlog (handle packet bursts)
        ("net.core.netdev_max_backlog", "262144"), // 256K packets
        ("net.core.netdev_budget", "3000"),        // Process more packets per NAPI poll
        ("net.core.netdev_budget_usecs", "20000"), // 20ms budget
        // UDP specific (high throughput)
        ("net.ipv4.udp_mem", "16777216 33554432 67108864"), // Min/Pressure/Max pages
        ("net.ipv4.udp_rmem_min", "16384"),                 // 16KB min
        ("net.ipv4.udp_wmem_min", "16384"),                 // 16KB min
        // Enable busy polling (reduce latency)
        ("net.core.busy_poll", "50"),
        ("net.core.busy_read", "50"),
        // Enable GRO/GSO
        ("net.core.gro_normal_batch", "8"), // GRO batch size
        // Increase connection tracking table (high session count)
        ("net.netfilter.nf_conntrack_max", "2000000"), // 2M concurrent connections
    ];

    for (key, value) in settings {
        if apply_sysctl(key, value).is_ok() {
            applied.push(format!("{}={}", key, value));
        }
    }

    if !applied.is_empty() {
        info!("Applied {} system network settings", applied.len());
    }

    applied
}

/// Apply a sysctl setting.
fn apply_sysctl(key: &str, value: &str) -> io::Result<()> {
    use std::fs;

    let path = format!("/proc/sys/{}", key.replace('.', "/"));
    fs::write(&path, value)?;
    debug!("Applied sysctl: {}={}", key, value);
    Ok(())
}

/// Get current sysctl value.
pub fn get_sysctl(key: &str) -> io::Result<String> {
    use std::fs;

    let path = format!("/proc/sys/{}", key.replace('.', "/"));
    let value = fs::read_to_string(&path)?;
    Ok(value.trim().to_string())
}

/// Report current network tuning status.
pub fn report_network_tuning() -> NetworkTuningReport {
    let rmem_max = get_sysctl("net.core.rmem_max")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let wmem_max = get_sysctl("net.core.wmem_max")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let busy_poll = get_sysctl("net.core.busy_poll")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let netdev_max_backlog = get_sysctl("net.core.netdev_max_backlog")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    NetworkTuningReport {
        rmem_max,
        wmem_max,
        busy_poll,
        netdev_max_backlog,
        is_optimized: rmem_max >= 16 * 1024 * 1024 && wmem_max >= 16 * 1024 * 1024,
    }
}

/// Network tuning report.
#[derive(Debug, Clone)]
pub struct NetworkTuningReport {
    /// Maximum receive buffer size.
    pub rmem_max: u64,
    /// Maximum send buffer size.
    pub wmem_max: u64,
    /// Busy poll timeout.
    pub busy_poll: u32,
    /// Network device max backlog.
    pub netdev_max_backlog: u32,
    /// Whether the system is optimized for high throughput.
    pub is_optimized: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_options() {
        let opts = SocketOptions::default();
        assert!(opts.recv_buffer_size > 0);
        assert!(opts.send_buffer_size > 0);
    }

    #[test]
    fn test_high_throughput_options() {
        let opts = SocketOptions::high_throughput();
        assert!(opts.recv_buffer_size >= 16 * 1024 * 1024);
        assert!(opts.udp_gro); // GRO enabled for throughput
    }

    #[test]
    fn test_low_latency_options() {
        let opts = SocketOptions::low_latency();
        assert!(opts.recv_buffer_size > 0);
    }

    #[test]
    fn test_report_network_tuning() {
        // Just ensure it doesn't panic
        let report = report_network_tuning();
        println!("Network tuning: {:?}", report);
    }
}
