//! Crash recovery system for the **legacy CLI** macOS VPN client.
//!
//! # Status
//!
//! Gated behind the `cli-recovery` Cargo feature, which is **off by
//! default**. The shipping macOS app (Tauri + Packet Tunnel Extension)
//! does **not** compile this module — see `crates/hpn-client-macos/Cargo.toml`
//! and `crates/hpn-ui-macos/src-tauri/src/main.rs` for the rationale:
//! Apple's `NETunnelProviderManager` already tears the tunnel down
//! cleanly when the host app dies, and the Tauri build never touches
//! PF rules or custom host routes. There is therefore no host-level
//! state to restore from a recovery file.
//!
//! The module is preserved on the workspace because it is still useful
//! for a future standalone CLI binary that manipulates routes / PF
//! directly (the same surface as the original Linux/macOS daemon
//! design). When such a binary appears it must enable the
//! `cli-recovery` feature **and** wire `RecoveryState::check_and_perform_recovery`
//! into its boot sequence — without that wiring the file is never
//! written and the module is dead code.
//!
//! # Behaviour (when the feature is enabled)
//!
//! Provides persistent state tracking to ensure network settings
//! can be restored after:
//! - Application crash
//! - Cmd+Q / forced termination
//! - System reboot while VPN is connected
//! - Process kill (kill -9)
//!
//! The recovery file is stored at `~/Library/Application Support/HPN/recovery.json`
//! and contains all information needed to restore the original network configuration.
//!
//! # Security
//!
//! The recovery file is created with restricted permissions (0600, owner-only access)
//! to prevent other users from reading sensitive VPN configuration data.
//! File locking is used to prevent concurrent access race conditions.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::Command;

use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use crate::error::MacosClientError;
use crate::routing::{add_route, delete_route, delete_route_v6, get_default_gateway};

/// Current version of the recovery file format.
const RECOVERY_VERSION: u32 = 1;

/// Recovery state that is persisted to disk.
///
/// # Safety
/// This struct uses `flock()` for file locking which is safe to call on valid file descriptors.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
#[allow(clippy::unsafe_derive_deserialize)]
pub struct RecoveryState {
    /// Version of the recovery file format.
    pub version: u32,

    /// Unix timestamp when the recovery file was created.
    pub timestamp: u64,

    /// Whether VPN was active when the state was saved.
    pub vpn_active: bool,

    /// Original default gateway IPv4 address.
    pub original_gateway: Option<String>,

    /// Original default gateway interface name.
    pub original_interface: Option<String>,

    /// Original default gateway IPv6 address.
    pub original_gateway_v6: Option<String>,

    /// Original default gateway IPv6 interface name.
    pub original_interface_v6: Option<String>,

    /// Routes that were added by VPN (need to be deleted).
    pub added_routes: Vec<SerializedRoute>,

    /// Original DNS servers per interface (for restoration).
    pub original_dns: HashMap<String, SerializedDns>,

    /// VPN interface name.
    pub vpn_interface: Option<String>,

    /// VPN server endpoint IP.
    pub server_endpoint: Option<String>,

    /// Whether kill switch was enabled.
    pub kill_switch_enabled: bool,

    /// Whether allow LAN was enabled.
    pub allow_lan: bool,

    /// Whether PF firewall rules were added.
    pub pf_enabled: bool,

    /// PF anchor name used (for cleanup).
    pub pf_anchor: Option<String>,
}

/// Serializable route entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedRoute {
    /// Destination address (CIDR notation).
    pub destination: String,
    /// Gateway address.
    pub gateway: String,
    /// Interface name.
    pub interface: Option<String>,
    /// Whether this is an IPv6 route.
    pub is_v6: bool,
}

/// Serializable DNS settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedDns {
    /// DNS servers.
    pub servers: Vec<String>,
    /// Search domains.
    pub search_domains: Vec<String>,
}

impl RecoveryState {
    /// Create a new empty recovery state.
    pub fn new() -> Self {
        Self {
            version: RECOVERY_VERSION,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            vpn_active: false,
            original_gateway: None,
            original_interface: None,
            original_gateway_v6: None,
            original_interface_v6: None,
            added_routes: Vec::new(),
            original_dns: HashMap::new(),
            vpn_interface: None,
            server_endpoint: None,
            kill_switch_enabled: false,
            allow_lan: false,
            pf_enabled: false,
            pf_anchor: None,
        }
    }

    /// Get the path to the recovery file.
    ///
    /// Returns `~/Library/Application Support/HPN/recovery.json`.
    pub fn path() -> Option<PathBuf> {
        let home = std::env::var("HOME").ok()?;
        let mut path = PathBuf::from(home);
        path.push("Library");
        path.push("Application Support");
        path.push("HPN");
        path.push("recovery.json");
        Some(path)
    }

    /// Load recovery state from disk.
    ///
    /// Returns `None` if the file doesn't exist or is invalid.
    pub fn load() -> Option<Self> {
        Self::load_with_lock().map(|(state, _)| state)
    }

    /// Load recovery state from disk with exclusive lock.
    ///
    /// Returns the state and the locked file handle if successful.
    #[allow(unsafe_code)]
    fn load_with_lock() -> Option<(Self, File)> {
        let path = Self::path()?;

        if !path.exists() {
            debug!("No recovery file found at {:?}", path);
            return None;
        }

        let file = match File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                warn!("Failed to open recovery file: {}", e);
                return None;
            }
        };

        // Acquire exclusive lock using flock
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = file.as_raw_fd();
            // SAFETY: flock is safe to call on a valid file descriptor
            let result = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
            if result != 0 {
                warn!("Failed to acquire lock on recovery file");
                return None;
            }
        }

        let reader = BufReader::new(&file);

        match serde_json::from_reader(reader) {
            Ok(state) => {
                let state: RecoveryState = state;
                if state.version > RECOVERY_VERSION {
                    warn!(
                        "Recovery file version {} is newer than supported version {}",
                        state.version, RECOVERY_VERSION
                    );
                }
                info!("Loaded recovery state from {:?}", path);
                Some((state, file))
            }
            Err(e) => {
                error!(
                    "Recovery file corrupted at {:?}: {}. File will be removed.",
                    path, e
                );
                // Unlock before deleting
                #[cfg(unix)]
                {
                    use std::os::unix::io::AsRawFd;
                    let fd = file.as_raw_fd();
                    unsafe { libc::flock(fd, libc::LOCK_UN) };
                }
                drop(file);
                if let Err(del_err) = fs::remove_file(&path) {
                    warn!("Failed to delete corrupted recovery file: {}", del_err);
                }
                None
            }
        }
    }

    /// Save recovery state to disk with secure permissions.
    ///
    /// Uses atomic write (temp file + rename) to prevent corruption.
    #[allow(unsafe_code)]
    pub fn save(&self) -> Result<(), std::io::Error> {
        let Some(path) = Self::path() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Could not determine recovery file path",
            ));
        };

        // Create directory if it doesn't exist
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Use atomic write: write to temp file, then rename
        let temp_path = path.with_extension("json.tmp");

        // Create temp file with restrictive permissions (0600)
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temp_path)?;

        // Acquire exclusive lock during write
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = file.as_raw_fd();
            unsafe { libc::flock(fd, libc::LOCK_EX) };
        }

        // Serialize to JSON
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        // Write with buffering
        let mut writer = BufWriter::new(&file);
        writer.write_all(json.as_bytes())?;
        writer.flush()?;

        // Sync to disk before renaming
        file.sync_all()?;

        // Unlock before close
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = file.as_raw_fd();
            unsafe { libc::flock(fd, libc::LOCK_UN) };
        }
        drop(writer);
        drop(file);

        // Atomic rename
        fs::rename(&temp_path, &path)?;

        debug!("Saved recovery state to {:?}", path);
        Ok(())
    }

    /// Delete the recovery file.
    pub fn delete() -> Result<(), std::io::Error> {
        if let Some(path) = Self::path()
            && path.exists()
        {
            fs::remove_file(&path)?;
            info!("Deleted recovery file at {:?}", path);
        }
        Ok(())
    }

    /// Check if recovery is needed.
    pub fn needs_recovery() -> bool {
        if let Some(state) = Self::load() {
            state.vpn_active
        } else {
            false
        }
    }

    /// Check if recovery is needed and perform it atomically.
    ///
    /// Returns `Ok(true)` if recovery was performed, `Ok(false)` if not needed.
    pub fn check_and_perform_recovery() -> Result<bool, RecoveryError> {
        let Some((state, lock)) = Self::load_with_lock() else {
            debug!("No recovery needed - no recovery file found");
            return Ok(false);
        };

        if !state.vpn_active {
            info!("No recovery needed - VPN was not active");
            drop(lock);
            Self::delete().ok();
            return Ok(false);
        }

        info!("Performing network recovery after unclean shutdown...");
        Self::perform_recovery_with_state(&state)?;

        Ok(true)
    }

    /// Internal method to perform recovery with a pre-loaded state.
    fn perform_recovery_with_state(state: &RecoveryState) -> Result<(), RecoveryError> {
        let mut errors = Vec::new();

        // Step 1: Remove PF firewall rules if they were enabled
        if state.pf_enabled
            && let Some(anchor) = &state.pf_anchor
        {
            info!("Removing PF firewall rules (anchor: {})", anchor);
            if let Err(e) = remove_pf_rules(anchor) {
                warn!("Failed to remove PF rules: {}", e);
                errors.push(format!("PF cleanup failed: {}", e));
            }
        }

        // Step 2: Delete routes that were added by the VPN
        for route in &state.added_routes {
            debug!("Deleting VPN route: {}", route.destination);
            let result = if route.is_v6 {
                delete_route_v6(&route.destination)
            } else {
                delete_route(&route.destination)
            };
            if let Err(e) = result {
                // Route might already be gone - not critical
                debug!("Could not delete route (may already be gone): {}", e);
            }
        }

        // Step 3: Delete server endpoint route if it exists
        if let Some(server) = &state.server_endpoint {
            let _ = delete_route(&format!("{}/32", server));
        }

        // Step 4: Restore original default route (IPv4)
        if let (Some(gw), Some(iface)) = (&state.original_gateway, &state.original_interface) {
            info!("Restoring original gateway: {} via {}", gw, iface);
            if let Ok(gw_addr) = gw.parse::<Ipv4Addr>() {
                // Delete any existing default
                let _ = delete_route("default");
                // Add back original
                if let Err(e) = add_route("default", gw_addr, Some(iface)) {
                    warn!("Failed to restore default gateway: {}", e);
                    errors.push(format!("Default gateway restore failed: {}", e));
                }
            }
        }

        // Step 5: Restore original default route (IPv6)
        if let (Some(gw), Some(iface)) = (&state.original_gateway_v6, &state.original_interface_v6)
        {
            info!("Restoring original IPv6 gateway: {} via {}", gw, iface);
            if let Ok(gw_addr) = gw.parse::<Ipv6Addr>() {
                let _ = delete_route_v6("default");
                if let Err(e) = add_route_v6("default", gw_addr, Some(iface)) {
                    warn!("Failed to restore IPv6 default gateway: {}", e);
                    errors.push(format!("IPv6 default gateway restore failed: {}", e));
                }
            }
        }

        // Step 6: Restore DNS configuration
        if !state.original_dns.is_empty() {
            info!("Restoring DNS configuration");
            // Remove VPN DNS entry
            let _ = remove_vpn_dns();
            // Flush DNS cache
            let _ = flush_dns_cache();
        }

        // Delete the recovery file
        if let Err(e) = Self::delete() {
            warn!("Failed to delete recovery file: {}", e);
        }

        if errors.is_empty() {
            info!("Network recovery completed successfully");
            Ok(())
        } else {
            warn!("Network recovery completed with {} errors", errors.len());
            Err(RecoveryError::PartialRecovery(errors))
        }
    }

    /// Capture the current network state before VPN connection.
    ///
    /// This should be called BEFORE any VPN-related network changes are made.
    pub fn capture_pre_vpn_state(
        vpn_interface: &str,
        server_endpoint: Ipv4Addr,
        kill_switch: bool,
        allow_lan: bool,
    ) -> Result<Self, RecoveryError> {
        let mut state = Self::new();
        state.vpn_active = true;
        state.vpn_interface = Some(vpn_interface.to_string());
        state.server_endpoint = Some(server_endpoint.to_string());
        state.kill_switch_enabled = kill_switch;
        state.allow_lan = allow_lan;

        // Capture default gateway
        if let Ok((gw, iface)) = get_default_gateway() {
            state.original_gateway = Some(gw.to_string());
            state.original_interface = Some(iface);
            debug!("Captured original gateway: {:?}", state.original_gateway);
        }

        // Capture IPv6 default gateway
        if let Some((gw, iface)) = crate::routing::get_default_gateway_v6() {
            state.original_gateway_v6 = Some(gw.to_string());
            state.original_interface_v6 = Some(iface);
            debug!(
                "Captured original IPv6 gateway: {:?}",
                state.original_gateway_v6
            );
        }

        Ok(state)
    }

    /// Record a route that was added.
    pub fn record_added_route(
        &mut self,
        destination: &str,
        gateway: &str,
        interface: Option<&str>,
        is_v6: bool,
    ) {
        self.added_routes.push(SerializedRoute {
            destination: destination.to_string(),
            gateway: gateway.to_string(),
            interface: interface.map(|s| s.to_string()),
            is_v6,
        });
    }

    /// Record that PF firewall rules were enabled.
    pub fn record_pf_enabled(&mut self, anchor: &str) {
        self.pf_enabled = true;
        self.pf_anchor = Some(anchor.to_string());
    }

    /// Mark VPN as disconnected and clear the recovery state.
    pub fn mark_clean_disconnect(&mut self) {
        self.vpn_active = false;
        // Delete the recovery file
        Self::delete().ok();
    }
}

impl Default for RecoveryState {
    fn default() -> Self {
        Self::new()
    }
}

/// Error type for recovery operations.
#[derive(Debug)]
pub enum RecoveryError {
    /// I/O error.
    Io(std::io::Error),
    /// macOS client error.
    MacosClient(MacosClientError),
    /// Recovery completed but with some errors.
    PartialRecovery(Vec<String>),
}

impl std::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecoveryError::Io(e) => write!(f, "I/O error: {}", e),
            RecoveryError::MacosClient(e) => write!(f, "macOS client error: {}", e),
            RecoveryError::PartialRecovery(errors) => {
                write!(f, "Partial recovery ({} errors): ", errors.len())?;
                for (i, err) in errors.iter().enumerate() {
                    if i > 0 {
                        write!(f, "; ")?;
                    }
                    write!(f, "{}", err)?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for RecoveryError {}

impl From<std::io::Error> for RecoveryError {
    fn from(e: std::io::Error) -> Self {
        RecoveryError::Io(e)
    }
}

impl From<MacosClientError> for RecoveryError {
    fn from(e: MacosClientError) -> Self {
        RecoveryError::MacosClient(e)
    }
}

// ============================================================================
// Helper functions for recovery
// ============================================================================

/// Add an IPv6 route (wrapper for recovery use).
fn add_route_v6(
    destination: &str,
    gateway: Ipv6Addr,
    interface: Option<&str>,
) -> Result<(), MacosClientError> {
    let gateway_str = gateway.to_string();
    let mut args = vec!["-n", "add", "-inet6", destination, &gateway_str];

    let iface_flag;
    if let Some(iface) = interface {
        args.push("-interface");
        iface_flag = iface.to_string();
        args.push(&iface_flag);
    }

    let output = Command::new("route")
        .args(&args)
        .output()
        .map_err(|e| MacosClientError::Routing(format!("failed to run route add (v6): {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("already in table") {
            return Err(MacosClientError::Routing(format!(
                "route add (v6) failed: {}",
                stderr
            )));
        }
    }

    Ok(())
}

/// Remove PF firewall rules.
fn remove_pf_rules(anchor: &str) -> Result<(), MacosClientError> {
    // Validate anchor name
    if !anchor
        .chars()
        .all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return Err(MacosClientError::SystemConfig(format!(
            "Invalid PF anchor name: {}",
            anchor
        )));
    }

    // Flush the anchor rules
    let output = Command::new("pfctl")
        .args(["-a", anchor, "-F", "all"])
        .output()
        .map_err(|e| MacosClientError::SystemConfig(format!("failed to run pfctl: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Ignore "No ALTQ support" and "pfctl: not found" type errors
        if !stderr.contains("No ALTQ") && !stderr.contains("does not exist") {
            debug!("pfctl flush warning: {}", stderr);
        }
    }

    // Remove the anchor file
    let anchor_file = format!("/etc/pf.anchors/{}", anchor);
    if std::path::Path::new(&anchor_file).exists() {
        let _ = fs::remove_file(&anchor_file);
    }

    info!("Removed PF anchor: {}", anchor);
    Ok(())
}

/// Remove VPN DNS configuration.
fn remove_vpn_dns() -> Result<(), MacosClientError> {
    use std::io::Write;

    let mut child = Command::new("scutil")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| MacosClientError::Dns(format!("failed to run scutil: {}", e)))?;

    if let Some(stdin) = child.stdin.as_mut() {
        let _ = stdin.write_all(b"remove State:/Network/Service/HPN-VPN/DNS\nquit\n");
    }

    let _ = child.wait();
    debug!("Removed VPN DNS configuration");
    Ok(())
}

/// Flush DNS cache.
fn flush_dns_cache() -> Result<(), MacosClientError> {
    // dscacheutil -flushcache
    let _ = Command::new("dscacheutil").args(["-flushcache"]).output();

    // killall -HUP mDNSResponder
    let _ = Command::new("killall")
        .args(["-HUP", "mDNSResponder"])
        .output();

    debug!("Flushed DNS cache");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recovery_state_new() {
        let state = RecoveryState::new();
        assert_eq!(state.version, RECOVERY_VERSION);
        assert!(!state.vpn_active);
        assert!(state.original_gateway.is_none());
        assert!(state.added_routes.is_empty());
    }

    #[test]
    fn test_recovery_path() {
        if std::env::var("HOME").is_ok() {
            let path = RecoveryState::path();
            assert!(path.is_some());
            let path = path.unwrap();
            assert!(path.to_string_lossy().contains("HPN"));
            assert!(path.to_string_lossy().contains("recovery.json"));
        }
    }

    #[test]
    fn test_serialized_route() {
        let route = SerializedRoute {
            destination: "0.0.0.0/1".to_string(),
            gateway: "10.0.0.1".to_string(),
            interface: Some("utun3".to_string()),
            is_v6: false,
        };
        assert_eq!(route.destination, "0.0.0.0/1");
        assert!(!route.is_v6);
    }

    #[test]
    fn test_record_added_route() {
        let mut state = RecoveryState::new();
        state.record_added_route("0.0.0.0/1", "10.0.0.1", Some("utun3"), false);
        assert_eq!(state.added_routes.len(), 1);
        assert_eq!(state.added_routes[0].destination, "0.0.0.0/1");
    }

    #[test]
    fn test_record_pf_enabled() {
        let mut state = RecoveryState::new();
        state.record_pf_enabled("com.hpn-vpn");
        assert!(state.pf_enabled);
        assert_eq!(state.pf_anchor, Some("com.hpn-vpn".to_string()));
    }
}
