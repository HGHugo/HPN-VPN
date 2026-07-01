//! HPN Server
//!
//! Linux server implementation for the HPN VPN.
//!
//! # Architecture
//!
//! - [`config`]: Server configuration (minimal, automatic tuning)
//! - [`auto_tune`]: Automatic performance tuning (no user config needed)
//! - [`server`]: Main server loop with automatic backend selection
//! - [`session_manager`]: Client session management and IP allocation
//! - [`tun`]: Linux TUN device handling
//! - [`routing`]: IP forwarding setup
//! - [`nat`]: NAT/masquerade configuration
//! - [`metrics`]: Prometheus metrics and monitoring
//!
//! # Performance
//!
//! Performance is fully automatic. The server detects hardware capabilities
//! and selects the optimal networking backend:
//!
//! 1. **AF_XDP** (kernel >= 4.18 + XDP NIC): Zero-copy, 10+ Gbps
//! 2. **io_uring** (kernel >= 5.1): Async I/O, 5-10 Gbps  
//! 3. **recvmmsg/sendmmsg**: Batched syscalls, 1-5 Gbps
//! 4. **Standard UDP**: Fallback, ~1 Gbps

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
// Numeric:
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::cast_precision_loss)]
// Async:
#![allow(clippy::await_holding_lock)]
#![allow(clippy::future_not_send)]
#![allow(clippy::unused_async)]
// API:
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::fn_params_excessive_bools)]
#![allow(clippy::too_many_arguments)]
// Crate-specific:
#![allow(clippy::items_after_statements)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::derivable_impls)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::match_same_arms)]
// Pervasive in server code (246 occurrences):
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::map_unwrap_or)]
#![allow(clippy::format_push_string)]
#![allow(clippy::unused_self)]
#![allow(clippy::unnested_or_patterns)]
#![allow(clippy::manual_range_contains)]
#![allow(clippy::missing_fields_in_debug)]

pub mod admin;
#[cfg(all(target_os = "linux", feature = "afxdp"))]
pub mod afxdp_workers;
pub mod auth_lockout;
pub mod auto_tune;
pub mod config;
pub mod error;
pub mod handshake_replay;
#[cfg(all(target_os = "linux", feature = "io_uring"))]
pub mod io_uring_udp;
pub mod log_file;
pub mod metrics;
pub mod nat;
pub mod privacy;
#[cfg(unix)]
pub mod privileges;
pub mod rate_limit;
pub mod routing;
pub mod server;
pub mod session_manager;
#[cfg(target_os = "linux")]
pub mod socket_opts;
#[cfg(target_os = "linux")]
pub mod syscall_batch;
pub mod tun;
#[cfg(target_os = "linux")]
pub mod tun_multiqueue;
#[cfg(target_os = "linux")]
pub mod tun_workers;
#[cfg(target_os = "linux")]
pub mod udp_workers;
pub mod user_store;
pub mod validation;

pub use admin::{AdminContext, AdminHttpServer};
pub use auth_lockout::{AuthLockoutTracker, LockoutKind, LockoutMetricsSnapshot, LockoutPolicy};
pub use auto_tune::{NetworkBackend, RuntimeConfig, SystemCapabilities};
pub use config::ServerConfig;
pub use error::ServerError;
pub use handshake_replay::HandshakeReplayCache;
pub use metrics::{MetricsHttpServer, MetricsReporter, MetricsSummary, ServerMetrics};
#[cfg(unix)]
pub use privileges::PrivilegeDropper;
pub use rate_limit::HandshakeRateLimiter;
pub use server::VpnServer;
pub use session_manager::SessionManager;
pub use user_store::{UserInfo, UserStore};
pub use validation::{
    validate_interface_name, validate_ipv4_address, validate_ipv4_cidr, validate_ipv6_address,
    validate_ipv6_cidr, validate_network_cidr,
};

// Re-export io_uring detection functions when available
#[cfg(all(target_os = "linux", feature = "io_uring"))]
pub use io_uring_udp::{io_uring_requirements, is_io_uring_supported, is_sqpoll_supported};
