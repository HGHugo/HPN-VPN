//! AF_XDP Zero-Copy Networking for HPN VPN
//!
//! This crate provides high-performance, zero-copy networking using Linux AF_XDP
//! sockets. It enables the HPN VPN server to achieve multi-gigabit throughput
//! by bypassing most of the kernel network stack.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                         User Space                              │
//! │  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐ │
//! │  │  XskSocket  │    │  DataPath   │    │   SessionTable      │ │
//! │  │  (AF_XDP)   │◄──►│  (Crypto)   │◄──►│   (Lookup)          │ │
//! │  └──────┬──────┘    └─────────────┘    └─────────────────────┘ │
//! │         │                                                       │
//! │  ┌──────▼──────┐                                               │
//! │  │    UMEM     │ ◄─── Zero-copy shared memory                  │
//! │  │  (Frames)   │                                               │
//! │  └──────┬──────┘                                               │
//! │         │                                                       │
//! ├─────────┼───────────────────────────────────────────────────────┤
//! │         │              Kernel Space                             │
//! │  ┌──────▼──────┐                                               │
//! │  │ XDP Program │ ◄─── Redirect to AF_XDP socket                │
//! │  └──────┬──────┘                                               │
//! │         │                                                       │
//! │  ┌──────▼──────┐                                               │
//! │  │    NIC      │                                               │
//! │  │  Driver     │                                               │
//! │  └─────────────┘                                               │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Features
//!
//! - **Zero-copy RX/TX**: Packets are DMA'd directly to/from userspace memory
//! - **Kernel bypass**: Minimal kernel involvement for maximum throughput
//! - **Multi-queue support**: One socket per NIC queue for parallelism
//! - **Fallback support**: Automatic fallback to copy mode if driver doesn't support zero-copy
//!
//! # Requirements
//!
//! - Linux kernel >= 4.18 (5.x+ recommended for best performance)
//! - CAP_NET_ADMIN or root privileges
//! - NIC with XDP support (for zero-copy mode)
//!
//! # Example
//!
//! ```rust,ignore
//! use hpn_afxdp::{XskSocket, XskConfig, SessionTable, DataPath};
//! use std::sync::Arc;
//!
//! // Create session table
//! let sessions = Arc::new(SessionTable::new());
//!
//! // Configure XSK socket
//! let config = XskConfig::new("eth0")
//!     .queue_id(0)
//!     .ring_size(4096)
//!     .zero_copy(true);
//!
//! // Create socket
//! let socket = XskSocket::new(&config)?;
//!
//! // Create data path processor
//! let mut datapath = DataPath::new(sessions);
//!
//! // Process packets
//! loop {
//!     datapath.process_rx(&mut socket, |session_id, decrypted_data| {
//!         // Handle decrypted packet
//!     })?;
//! }
//! ```
//!
//! # Modules
//!
//! - [`error`]: Error types for AF_XDP operations
//! - [`sys`]: Low-level syscall bindings
//! - [`umem`]: User memory (UMEM) management
//! - [`ring`]: Ring buffer implementations
//! - [`socket`]: XSK socket wrapper
//! - [`xdp_program`]: XDP program management
//! - [`datapath`]: High-performance data path with crypto
//! - [`metrics`]: Prometheus metrics

#![cfg(target_os = "linux")]
// Pedantic lint policy: intentional suppressions.
// Structural:
#![allow(clippy::too_many_lines)]
#![allow(clippy::cognitive_complexity)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::cast_possible_truncation)]
// Style:
#![allow(clippy::similar_names)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::struct_field_names)]
#![allow(clippy::single_match_else)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

pub mod datapath;
pub mod error;
pub mod metrics;
pub mod ring;
pub mod socket;
pub mod sys;
pub mod umem;
pub mod xdp_program;

// Re-exports for convenience
pub use datapath::{
    BatchStats, DataPath, DataPathWorker, SessionCrypto, SessionTable, SharedSessionCrypto,
    SharedSessionTable, WorkerConfig,
};
pub use error::{AfXdpError, Result};
pub use metrics::{AfXdpMetrics, FastMetrics};
pub use ring::{CompletionRing, FillRing, RingConfig, RxRing, TxRing};
pub use socket::{SocketStats, XskConfig, XskSocket};
pub use umem::{SharedUmem, Umem, UmemConfig};
pub use xdp_program::{SharedXdpManager, XdpManager, XdpMode, shared_xdp_manager};

/// Check if AF_XDP is supported on this system.
///
/// Returns `true` if:
/// - Running on Linux
/// - Kernel supports AF_XDP (>= 4.18)
/// - Process has permission to create AF_XDP sockets
pub fn is_supported() -> bool {
    sys::is_afxdp_supported()
}

/// Get the recommended number of XSK sockets for an interface.
///
/// Returns the number of RX queues on the interface, which is typically
/// the optimal number of XSK sockets for maximum parallelism.
pub fn recommended_socket_count(interface: &str) -> std::io::Result<u32> {
    // Read from /sys/class/net/<iface>/queues/
    let path = format!("/sys/class/net/{}/queues", interface);
    let entries = std::fs::read_dir(&path)?;

    let mut rx_queues = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name.to_string_lossy().starts_with("rx-") {
            rx_queues += 1;
        }
    }

    // Minimum of 1
    Ok(rx_queues.max(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_supported() {
        // Just verify it doesn't panic
        let _ = is_supported();
    }

    #[test]
    fn test_recommended_socket_count_invalid_interface() {
        // Should return error for non-existent interface
        let result = recommended_socket_count("nonexistent_interface_12345");
        assert!(result.is_err());
    }
}
