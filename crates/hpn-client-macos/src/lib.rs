//! HPN Client for macOS
//!
//! macOS-specific client implementation using the utun interface.

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
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::derivable_impls)]
// Pervasive:
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::unused_self)]
#![allow(clippy::use_self)]
#![allow(clippy::if_not_else)]
#![allow(clippy::io_other_error)]

#[cfg(target_os = "macos")]
pub mod adapter;
/// Legacy CLI DNS-management module (FIX-026).
///
/// Calls `scutil --set State:/Network/...` which requires the process
/// to run as root. The Tauri/NetworkExtension shipping build does not
/// use it (the extension hands DNS to macOS through `NEDNSSettings`),
/// so it sits in the workspace as dead code unless an operator
/// explicitly opts in via the `cli-dns` Cargo feature. Gating it off
/// by default ensures a future refactor cannot accidentally call into
/// the root-only path from a user-context host process.
#[cfg(feature = "cli-dns")]
pub mod dns;
pub mod error;
pub mod power;
/// Crash-recovery state for the legacy CLI client.
///
/// Disabled by default — the Tauri/NetworkExtension build does NOT use it
/// because Apple's `NETunnelProviderManager` tears the tunnel down cleanly
/// on app death, so there is no host-level state (PF rules, custom routes)
/// for the app to restore. Enable the `cli-recovery` Cargo feature when
/// building a standalone CLI binary that manipulates routes / PF directly.
#[cfg(feature = "cli-recovery")]
pub mod recovery;
pub mod routing;

pub use error::MacosClientError;
#[cfg(feature = "cli-recovery")]
pub use recovery::{RecoveryError, RecoveryState};

/// Check if the current process is running with root privileges.
///
/// Returns `true` if running as root (UID 0), `false` otherwise.
/// On non-Unix platforms, always returns `false`.
#[cfg(unix)]
#[allow(unsafe_code)]
pub fn is_root() -> bool {
    // SAFETY: getuid() is always safe to call and has no side effects
    unsafe { libc::getuid() == 0 }
}

#[cfg(not(unix))]
pub fn is_root() -> bool {
    false
}

/// Verify that the process has root privileges.
///
/// Returns an error if not running as root. This should be called
/// early in the client initialization to provide a clear error message.
pub fn require_root() -> Result<(), MacosClientError> {
    if !is_root() {
        return Err(MacosClientError::Adapter(
            "Root privileges required. Please run with sudo.".to_string(),
        ));
    }
    Ok(())
}
