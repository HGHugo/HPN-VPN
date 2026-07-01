//! HPN Client for Windows
//!
//! Windows-specific client implementation using Wintun.

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
// Async:
#![allow(clippy::await_holding_lock)]
#![allow(clippy::future_not_send)]
#![allow(clippy::unused_async)]
// Crate-specific:
#![allow(clippy::missing_fields_in_debug)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::unnecessary_wraps)]

#[cfg(windows)]
pub mod adapter;
pub mod error;
#[cfg(windows)]
pub mod recovery;
#[cfg(windows)]
pub mod routing;
#[cfg(windows)]
pub mod windows_api;

pub use error::WindowsClientError;
#[cfg(windows)]
pub use recovery::{RecoveryError, RecoveryState};
#[cfg(windows)]
pub use routing::{DnsLeakProtection, Ipv6LeakProtection, RouteManager};
#[cfg(windows)]
pub use windows_api::{
    DnsSettings, InterfaceInfo, RouteEntry, WindowsApiError, add_route, clear_interface_dns,
    delete_route, flush_dns_cache, get_adapter_guid, get_default_gateway, get_interface_dns,
    get_interface_index, get_interface_luid, get_interfaces, get_physical_interfaces, get_routes,
    set_interface_dns,
};
