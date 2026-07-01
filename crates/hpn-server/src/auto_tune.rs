//! Automatic performance tuning.
//!
//! This module auto-detects hardware capabilities and selects optimal
//! networking backends and parameters. Users don't need to configure any
//! performance settings - everything is automatic.
//!
//! # Backend Selection Priority
//!
//! 1. **AF_XDP** (kernel >= 4.18 + XDP-capable NIC): Zero-copy kernel bypass, 10+ Gbps
//! 2. **io_uring** (kernel >= 5.1): Async batched I/O, 5-10 Gbps
//! 3. **recvmmsg/sendmmsg**: Batched syscalls, 1-5 Gbps
//! 4. **Standard UDP**: Fallback, ~1 Gbps
//!
//! # Auto-detected Parameters
//!
//! - TUN queues: min(CPU cores, NIC RX queues)
//! - UDP workers: matches TUN queues
//! - Buffer sizes: scaled by available RAM
//! - Batch sizes: optimal for detected backend

use std::sync::OnceLock;

use tracing::info;

/// Detected system capabilities (cached).
static SYSTEM_CAPS: OnceLock<SystemCapabilities> = OnceLock::new();

/// Network backend types in order of preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkBackend {
    /// AF_XDP zero-copy kernel bypass (best performance).
    AfXdp,
    /// io_uring async I/O (great performance).
    IoUring,
    /// recvmmsg/sendmmsg batched syscalls (good performance).
    BatchedSyscalls,
    /// Standard recvfrom/sendto (baseline).
    Standard,
}

impl NetworkBackend {
    /// Get human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::AfXdp => "AF_XDP (zero-copy)",
            Self::IoUring => "io_uring",
            Self::BatchedSyscalls => "recvmmsg/sendmmsg",
            Self::Standard => "standard UDP",
        }
    }

    /// Estimated throughput capability.
    pub fn estimated_throughput(&self) -> &'static str {
        match self {
            Self::AfXdp => "10+ Gbps",
            Self::IoUring => "5-10 Gbps",
            Self::BatchedSyscalls => "1-5 Gbps",
            Self::Standard => "~1 Gbps",
        }
    }
}

/// System capabilities detected at startup.
#[derive(Debug, Clone)]
pub struct SystemCapabilities {
    /// Number of CPU cores.
    pub cpu_cores: usize,
    /// Total RAM in bytes.
    pub total_memory: u64,
    /// Default network interface.
    pub default_interface: Option<String>,
    /// Number of NIC RX queues.
    pub nic_rx_queues: usize,
    /// NIC link speed in Mbps (0 if unknown).
    pub nic_speed_mbps: u32,
    /// Kernel version (major, minor).
    pub kernel_version: (u32, u32),
    /// AF_XDP available.
    pub has_afxdp: bool,
    /// io_uring available.
    pub has_io_uring: bool,
    /// recvmmsg/sendmmsg available.
    pub has_mmsg: bool,
    /// TUN multiqueue available.
    pub has_tun_multiqueue: bool,
    /// Selected network backend.
    pub backend: NetworkBackend,
}

impl SystemCapabilities {
    /// Detect system capabilities.
    pub fn detect() -> Self {
        let cpu_cores = detect_cpu_cores();
        let total_memory = detect_total_memory();
        let default_interface = detect_default_interface();
        let nic_rx_queues = default_interface
            .as_ref()
            .map(|iface| detect_nic_rx_queues(iface))
            .unwrap_or(1);
        let nic_speed_mbps = default_interface
            .as_ref()
            .map(|iface| detect_nic_speed(iface))
            .unwrap_or(0);
        let kernel_version = detect_kernel_version();
        let has_afxdp = check_afxdp_support(kernel_version, default_interface.as_deref());
        let has_io_uring = check_io_uring_support(kernel_version);
        let has_mmsg = cfg!(target_os = "linux"); // Always available on Linux
        let has_tun_multiqueue = check_tun_multiqueue_support(kernel_version);

        // Select best backend
        let backend = if has_afxdp {
            NetworkBackend::AfXdp
        } else if has_io_uring {
            NetworkBackend::IoUring
        } else if has_mmsg {
            NetworkBackend::BatchedSyscalls
        } else {
            NetworkBackend::Standard
        };

        let caps = Self {
            cpu_cores,
            total_memory,
            default_interface,
            nic_rx_queues,
            nic_speed_mbps,
            kernel_version,
            has_afxdp,
            has_io_uring,
            has_mmsg,
            has_tun_multiqueue,
            backend,
        };

        info!("=== System Capabilities ===");
        info!(
            "  CPU: {} cores | Memory: {} GB",
            caps.cpu_cores,
            caps.total_memory / 1024 / 1024 / 1024
        );
        info!(
            "  NIC: {} ({} RX queue(s), {} Mbps)",
            caps.default_interface.as_deref().unwrap_or("unknown"),
            caps.nic_rx_queues,
            caps.nic_speed_mbps
        );
        info!(
            "  Kernel: {}.{}",
            caps.kernel_version.0, caps.kernel_version.1
        );
        info!(
            "  Features: AF_XDP={} io_uring={} mmsg={} tun_mq={}",
            if caps.has_afxdp { "yes" } else { "no" },
            if caps.has_io_uring { "yes" } else { "no" },
            if caps.has_mmsg { "yes" } else { "no" },
            if caps.has_tun_multiqueue { "yes" } else { "no" }
        );
        info!(
            "  Backend: {} ({})",
            caps.backend.name(),
            caps.backend.estimated_throughput()
        );

        // Explain the worker decision for single-queue NICs
        if caps.nic_rx_queues == 1 && caps.cpu_cores > 1 {
            info!("  Note: 1 RX queue = 1 worker (more workers would cause contention)");
        }

        caps
    }

    /// Get cached or detect capabilities.
    pub fn get() -> &'static Self {
        SYSTEM_CAPS.get_or_init(Self::detect)
    }

    /// Get optimal number of TUN queues.
    ///
    /// TUN multiqueue only helps when we have multiple NIC RX queues to match.
    /// With 1 NIC queue, multiqueue TUN just adds overhead.
    pub fn optimal_tun_queues(&self) -> usize {
        if !self.has_tun_multiqueue {
            return 1;
        }

        // Key insight: TUN queues should match NIC RX queues, not CPU cores.
        // Having more TUN queues than NIC queues creates imbalanced load.
        // Having more TUN queues than CPUs wastes resources.
        //
        // Formula: min(NIC queues, CPU cores), capped at 16
        let optimal = self.nic_rx_queues.min(self.cpu_cores);

        // Only use multiqueue if we have multiple NIC queues
        // Single NIC queue + multiqueue TUN = overhead with no benefit
        if self.nic_rx_queues <= 1 {
            return 1;
        }

        optimal.clamp(1, 16)
    }

    /// Get optimal number of worker threads.
    ///
    /// Worker count should match the parallelism we can actually achieve:
    /// - 1 NIC queue = 1 worker (multiple workers fight over same socket)
    /// - N NIC queues = N workers (each worker owns a queue)
    ///
    /// More workers than NIC queues causes lock contention and hurts performance.
    pub fn optimal_workers(&self) -> usize {
        // Workers should match TUN queues which match NIC queues
        // This ensures each worker has dedicated resources (no contention)
        self.optimal_tun_queues()
    }

    /// Get optimal buffer size in bytes.
    pub fn optimal_buffer_size(&self) -> usize {
        let gb = (self.total_memory / 1024 / 1024 / 1024) as usize;
        // 8MB per 2GB RAM, min 8MB, max 64MB
        let size_mb = ((gb / 2).max(1) * 8).min(64);
        size_mb * 1024 * 1024
    }

    /// Get optimal batch size for syscalls.
    pub fn optimal_batch_size(&self) -> usize {
        match self.backend {
            NetworkBackend::AfXdp => 64,           // Larger batches for zero-copy
            NetworkBackend::IoUring => 64,         // io_uring handles large batches well
            NetworkBackend::BatchedSyscalls => 32, // Standard mmsg batch
            NetworkBackend::Standard => 1,         // No batching
        }
    }
}

/// Auto-tuned runtime configuration.
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    /// Selected network backend.
    pub backend: NetworkBackend,
    /// Network interface for AF_XDP.
    pub interface: String,
    /// Number of TUN queues.
    pub tun_queues: usize,
    /// Number of worker threads.
    pub workers: usize,
    /// UDP receive buffer size.
    pub recv_buffer_size: usize,
    /// UDP send buffer size.
    pub send_buffer_size: usize,
    /// Batch size for recv/send.
    pub batch_size: usize,
    /// Enable TUN multiqueue.
    pub tun_multiqueue: bool,
}

impl RuntimeConfig {
    /// Create auto-tuned configuration.
    pub fn auto() -> Self {
        let caps = SystemCapabilities::get();
        let config = Self {
            backend: caps.backend,
            interface: caps.default_interface.clone().unwrap_or_default(),
            tun_queues: caps.optimal_tun_queues(),
            workers: caps.optimal_workers(),
            recv_buffer_size: caps.optimal_buffer_size(),
            send_buffer_size: caps.optimal_buffer_size(),
            batch_size: caps.optimal_batch_size(),
            tun_multiqueue: caps.has_tun_multiqueue && caps.optimal_tun_queues() > 1,
        };

        // Log performance recommendation if NIC has single queue but multiple CPUs
        if caps.nic_rx_queues == 1 && caps.cpu_cores > 1 {
            info!(
                "⚠️  Performance hint: NIC has only 1 RX queue but {} CPU cores available",
                caps.cpu_cores
            );
            info!(
                "   Try: ethtool -L {} combined {} (if driver supports multi-queue)",
                caps.default_interface.as_deref().unwrap_or("eth0"),
                caps.cpu_cores.min(8)
            );
        }

        config
    }

    /// Log the runtime configuration.
    pub fn log(&self) {
        info!("Runtime configuration (auto-tuned):");
        info!("  Network backend: {}", self.backend.name());
        if self.backend == NetworkBackend::AfXdp {
            info!("  AF_XDP interface: {}", self.interface);
        }
        info!("  TUN queues: {}", self.tun_queues);
        info!("  Worker threads: {}", self.workers);
        info!(
            "  Buffer sizes: {} MB (recv/send)",
            self.recv_buffer_size / 1024 / 1024
        );
        info!("  Batch size: {}", self.batch_size);
        info!("  TUN multiqueue: {}", self.tun_multiqueue);
    }
}

// ============================================================================
// Detection Functions
// ============================================================================

fn detect_cpu_cores() -> usize {
    std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1)
}

fn detect_total_memory() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
            for line in meminfo.lines() {
                if line.starts_with("MemTotal:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2
                        && let Ok(kb) = parts[1].parse::<u64>()
                    {
                        return kb * 1024; // Convert to bytes
                    }
                }
            }
        }
    }
    // Default: assume 4GB
    4 * 1024 * 1024 * 1024
}

fn detect_default_interface() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(routes) = std::fs::read_to_string("/proc/net/route") {
            for line in routes.lines().skip(1) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                // Destination 00000000 = default route
                if fields.len() >= 2 && fields[1] == "00000000" {
                    return Some(fields[0].to_string());
                }
            }
        }
    }
    None
}

fn detect_nic_rx_queues(interface: &str) -> usize {
    #[cfg(target_os = "linux")]
    {
        let queue_path = format!("/sys/class/net/{}/queues", interface);
        if let Ok(entries) = std::fs::read_dir(&queue_path) {
            let count = entries
                .filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().starts_with("rx-"))
                .count();
            if count > 0 {
                return count;
            }
        }
    }
    let _ = interface;
    1
}

fn detect_nic_speed(interface: &str) -> u32 {
    #[cfg(target_os = "linux")]
    {
        let speed_path = format!("/sys/class/net/{}/speed", interface);
        if let Ok(speed_str) = std::fs::read_to_string(&speed_path)
            && let Ok(speed) = speed_str.trim().parse::<i32>()
            && speed > 0
        {
            return speed as u32;
        }
    }
    let _ = interface;
    1000 // Default: assume 1Gbps
}

fn detect_kernel_version() -> (u32, u32) {
    #[cfg(target_os = "linux")]
    {
        if let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
            let parts: Vec<&str> = release.trim().split('.').collect();
            if parts.len() >= 2
                && let (Ok(major), Ok(minor)) = (parts[0].parse(), parts[1].parse())
            {
                return (major, minor);
            }
        }
    }
    (0, 0)
}

fn check_afxdp_support(kernel_version: (u32, u32), interface: Option<&str>) -> bool {
    #[cfg(all(target_os = "linux", feature = "afxdp"))]
    {
        // Requires kernel >= 4.18
        if kernel_version.0 < 4 || (kernel_version.0 == 4 && kernel_version.1 < 18) {
            return false;
        }

        // Check if we have an interface
        let iface = match interface {
            Some(i) => i,
            None => return false,
        };

        // Check NIC driver support
        let driver_path = format!("/sys/class/net/{}/device/driver", iface);
        if let Ok(driver_link) = std::fs::read_link(&driver_path) {
            if let Some(driver_name) = driver_link.file_name() {
                let driver = driver_name.to_string_lossy();
                // Known XDP-capable drivers
                let xdp_drivers = [
                    "i40e",
                    "ixgbe",
                    "ixgbevf",
                    "mlx4_en",
                    "mlx5_core",
                    "nfp",
                    "virtio_net",
                    "veth",
                    "tun",
                    "e1000e",
                    "igb",
                    "igc",
                    "bnxt_en",
                    "thunder",
                    "qede",
                    "sfc",
                    "atlantic",
                    "ice",
                ];
                if xdp_drivers.iter().any(|d| driver.contains(d)) {
                    return hpn_afxdp::is_supported();
                }
            }
        }

        // Kernel 5.x+ has good generic XDP support (copy mode)
        if kernel_version.0 >= 5 {
            return hpn_afxdp::is_supported();
        }

        false
    }

    #[cfg(not(all(target_os = "linux", feature = "afxdp")))]
    {
        let _ = (kernel_version, interface);
        false
    }
}

fn check_io_uring_support(kernel_version: (u32, u32)) -> bool {
    #[cfg(all(target_os = "linux", feature = "io_uring"))]
    {
        // Requires kernel >= 5.1
        if kernel_version.0 > 5 || (kernel_version.0 == 5 && kernel_version.1 >= 1) {
            // Check if io_uring is disabled
            if let Ok(disabled) = std::fs::read_to_string("/proc/sys/kernel/io_uring_disabled")
                && disabled.trim() == "2"
            {
                return false;
            }
            return crate::io_uring_udp::is_io_uring_supported();
        }
        false
    }

    #[cfg(not(all(target_os = "linux", feature = "io_uring")))]
    {
        let _ = kernel_version;
        false
    }
}

fn check_tun_multiqueue_support(kernel_version: (u32, u32)) -> bool {
    #[cfg(target_os = "linux")]
    {
        // TUN multiqueue requires kernel >= 3.8
        if kernel_version.0 > 3 || (kernel_version.0 == 3 && kernel_version.1 >= 8) {
            // Also check if /dev/net/tun exists
            return std::path::Path::new("/dev/net/tun").exists();
        }
        false
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = kernel_version;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_cpu_cores() {
        let cores = detect_cpu_cores();
        assert!(cores >= 1);
    }

    #[test]
    fn test_detect_total_memory() {
        let mem = detect_total_memory();
        assert!(mem >= 1024 * 1024); // At least 1MB
    }

    #[test]
    fn test_network_backend_names() {
        assert_eq!(NetworkBackend::AfXdp.name(), "AF_XDP (zero-copy)");
        assert_eq!(NetworkBackend::IoUring.name(), "io_uring");
        assert_eq!(NetworkBackend::BatchedSyscalls.name(), "recvmmsg/sendmmsg");
        assert_eq!(NetworkBackend::Standard.name(), "standard UDP");
    }

    #[test]
    fn test_runtime_config_auto() {
        let config = RuntimeConfig::auto();
        assert!(config.tun_queues >= 1);
        assert!(config.workers >= 1);
        assert!(config.recv_buffer_size >= 1024 * 1024); // At least 1MB
        assert!(config.batch_size >= 1);
    }

    #[test]
    fn test_system_capabilities() {
        let caps = SystemCapabilities::detect();
        assert!(caps.cpu_cores >= 1);
        assert!(caps.total_memory >= 1024 * 1024);
        assert!(caps.optimal_tun_queues() >= 1);
        assert!(caps.optimal_workers() >= 1);
        assert!(caps.optimal_buffer_size() >= 1024 * 1024);
    }
}
