//! Crash recovery system for Windows VPN client.
//!
//! This module provides persistent state tracking to ensure network settings
//! can be restored after:
//! - Application crash
//! - Alt+F4 / forced termination
//! - System reboot while VPN is connected
//! - Process kill
//!
//! The recovery file is stored at `%APPDATA%\HPN\recovery.json` and contains
//! all information needed to restore the original network configuration.
//!
//! # Security
//!
//! The recovery file is created with restricted permissions (owner-only access)
//! to prevent other users from reading sensitive VPN configuration data.
//! File locking is used to prevent concurrent access race conditions.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use crate::windows_api::{
    DnsSettings, RouteEntry, WindowsApiError, add_route, clear_interface_dns, delete_route,
    get_default_gateway, get_interface_dns, get_physical_interfaces, set_interface_dns,
};

/// Apply a restrictive DACL to a file so only NT AUTHORITY\SYSTEM and
/// the file's current owner can read or write it.
///
/// `recovery.json` carries the original gateway, route table and DNS
/// settings the VPN replaced; an attacker with read access to that file
/// learns the user's pre-VPN network footprint and can social-engineer
/// from it. FIX-018 closes that read window by stripping the inherited
/// `Users` ACE that `%APPDATA%\HPN\` carries by default.
///
/// SDDL breakdown: `D:P(A;;FA;;;SY)(A;;FA;;;OW)`
///   - `D:P` — protected DACL (do NOT inherit from the parent directory)
///   - `(A;;FA;;;SY)` — Allow ACE, Full Access, SYSTEM principal
///   - `(A;;FA;;;OW)` — Allow ACE, Full Access, "Owner Rights" SID
///     (`S-1-3-4`). At ACL-check time Windows resolves this against
///     the file's current Owner field; whatever principal owns the
///     file gets Full Access, everyone else gets denied.
///
/// **Caveat on file ownership**: this verifier does NOT force the
/// owner to the current process user. In the normal path the VPN host
/// creates the file fresh (Windows defaults the owner to the creating
/// token user, so OW resolves to the current user and they retain
/// access). If `recovery.json` is INHERITED from an earlier elevated
/// install (e.g. an Administrators-owned file from an MSI run as
/// admin), the OW ACE resolves to that older owner — the current
/// non-admin user is then locked out of their own recovery file and
/// the VPN logs a `restrict_recovery_file_acl failed: …` warning on
/// the next save (because the user no longer has `WRITE_DAC`).
/// Operators hitting this should delete the stale `recovery.json`
/// once and let the VPN recreate it fresh under their session.
/// Pulling the current user's SID via `GetTokenInformation` and
/// stamping `OWNER_SECURITY_INFORMATION` is tracked as a P2 hardening
/// (lots of unsafe Win32 plumbing for a corner case).
///
/// Failures are logged but non-fatal: a recovery file with looser ACLs
/// is still a strict improvement over no recovery file at all, and the
/// crash-recovery feature MUST not be disabled by a permission edge
/// case (locked-down corporate Windows builds where SetNamedSecurityInfo
/// is denied to the user, for example).
#[cfg(windows)]
#[allow(unsafe_code)]
fn restrict_recovery_file_acl(path: &std::path::Path) -> Result<(), std::io::Error> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SE_FILE_OBJECT, SetNamedSecurityInfoW,
    };
    use windows::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, PROTECTED_DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR,
    };
    use windows::core::{HSTRING, PCWSTR};

    // Wide string for the file path. Avoid `\\?\`-prefixed paths because
    // SetNamedSecurityInfoW accepts both but other tooling does not, and
    // `recovery.json` lives well under MAX_PATH anyway.
    let path_w: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let sddl = HSTRING::from("D:P(A;;FA;;;SY)(A;;FA;;;OW)");

    // Build a SECURITY_DESCRIPTOR from the SDDL string. `LocalFree`
    // must be called on the returned pointer to avoid leaking ~512
    // bytes per save.
    let mut psd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            1, // SDDL_REVISION_1
            &mut psd,
            None,
        )
        .map_err(|e| {
            std::io::Error::other(format!(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW failed: {}",
                e
            ))
        })?;
    }

    // Extract the DACL pointer out of the descriptor. We never set the
    // owner / group / SACL fields, so DACL is the only piece of
    // SetNamedSecurityInfoW input we populate.
    let mut dacl_present = windows::Win32::Foundation::BOOL(0);
    let mut dacl_defaulted = windows::Win32::Foundation::BOOL(0);
    let mut dacl_ptr: *mut windows::Win32::Security::ACL = std::ptr::null_mut();
    let extract_result = unsafe {
        GetSecurityDescriptorDacl(psd, &mut dacl_present, &mut dacl_ptr, &mut dacl_defaulted)
    };
    if let Err(e) = extract_result {
        unsafe {
            let _ = LocalFree(HLOCAL(psd.0));
        }
        return Err(std::io::Error::other(format!(
            "GetSecurityDescriptorDacl failed: {}",
            e
        )));
    }
    // Defensive: `GetSecurityDescriptorDacl` succeeds even when the
    // descriptor carries no DACL (in which case `dacl_present == FALSE`
    // and `dacl_ptr` is NULL). On Windows, passing a NULL DACL to
    // `SetNamedSecurityInfoW` would install a security descriptor that
    // grants Everyone full access — the opposite of what we want.
    // Refuse explicitly here so a future SDDL refactor that drops the
    // `D:` clause cannot silently widen the file's permissions.
    if dacl_present.0 == 0 || dacl_ptr.is_null() {
        unsafe {
            let _ = LocalFree(HLOCAL(psd.0));
        }
        return Err(std::io::Error::other(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW produced no DACL — refusing to apply NULL DACL (would grant Everyone full access)",
        ));
    }

    let win32_result = unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None, // owner: leave alone
            None, // group: leave alone
            Some(dacl_ptr as *const _),
            None, // sacl: leave alone
        )
    };

    // Free the security descriptor regardless of the SetNamedSecurityInfoW
    // result; the descriptor allocation is independent.
    unsafe {
        let _ = LocalFree(HLOCAL(psd.0));
    }

    if win32_result.is_err() {
        return Err(std::io::Error::other(format!(
            "SetNamedSecurityInfoW(DACL) failed: {:?}",
            win32_result
        )));
    }

    Ok(())
}

/// Current version of the recovery file format.
const RECOVERY_VERSION: u32 = 1;

/// Recovery state that is persisted to disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryState {
    /// Version of the recovery file format.
    pub version: u32,

    /// Unix timestamp when the recovery file was created.
    pub timestamp: u64,

    /// Whether VPN was active when the state was saved.
    pub vpn_active: bool,

    /// Original default gateway IPv4 address.
    pub original_gateway: Option<String>,

    /// Original default gateway interface index.
    pub original_interface_idx: Option<u32>,

    /// Original default gateway IPv6 address.
    pub original_gateway_v6: Option<String>,

    /// Routes that were deleted (need to be restored).
    pub deleted_routes: Vec<SerializedRoute>,

    /// Routes that were added (need to be deleted).
    pub added_routes: Vec<SerializedRoute>,

    /// Original DNS settings per interface (interface name -> DNS servers).
    pub original_dns: HashMap<String, SerializedDns>,

    /// VPN interface name.
    pub vpn_interface: Option<String>,

    /// Whether kill switch was enabled.
    pub kill_switch_enabled: bool,

    /// Whether allow LAN was enabled.
    pub allow_lan: bool,

    /// Whether LLMNR was disabled (needs restore on recovery).
    #[serde(default)]
    pub llmnr_disabled: bool,

    /// Whether NetBIOS was disabled (needs restore on recovery).
    #[serde(default)]
    pub netbios_disabled: bool,

    /// Whether the HPN IPv6-block firewall rule was installed.
    ///
    /// When `true`, the recovery path at next start-up will call
    /// `RouteManager::remove_stale_ipv6_block_rule()` so the user is not
    /// stuck without IPv6 connectivity on the physical interface after a
    /// crash (the rule blocks ALL IPv6 egress, profile=any).
    ///
    /// `#[serde(default)]` so recovery files written by older versions of
    /// the client (without this field) deserialise cleanly — they are
    /// simply treated as "no IPv6 block was installed".
    #[serde(default)]
    pub ipv6_blocked: bool,

    /// GUID of the NRPT (Name Resolution Policy Table) rule installed by
    /// `DnsLeakProtection::enable`. The crash-recovery path removes it
    /// via `Remove-DnsClientNrptRule -Name <guid>`; without removal an
    /// orphaned rule would force every DNS query through (now-closed)
    /// VPN resolvers, breaking all name resolution on the host until
    /// the user manually fixes it. Also see
    /// `DnsLeakProtection::cleanup_orphaned_nrpt_rules` for the
    /// comment-based cleanup that catches rules installed by older
    /// clients which did not persist their GUID.
    #[serde(default)]
    pub nrpt_rule_guid: Option<String>,

    /// `true` when `DnsLeakProtection::enable` wrote the
    /// `DisableSmartNameResolution=1` + `DisableParallelAandAAAA=1`
    /// registry policy values under
    /// `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`.
    /// The crash-recovery path then deletes the override so Windows
    /// returns to its default name-resolution behaviour.
    #[serde(default)]
    pub smart_multi_homed_disabled: bool,
}

/// Serializable route entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedRoute {
    /// Destination address (IPv4 or IPv6 string).
    pub destination: String,
    /// Prefix length.
    pub prefix_length: u8,
    /// Gateway address.
    pub gateway: String,
    /// Interface index.
    pub interface_index: u32,
    /// Route metric.
    pub metric: u32,
    /// Whether this is an IPv6 route.
    pub is_v6: bool,
}

impl SerializedRoute {
    /// Create from a RouteEntry.
    pub fn from_route_entry(entry: &RouteEntry) -> Self {
        Self {
            destination: entry.destination.to_string(),
            prefix_length: entry.prefix_length,
            gateway: entry.gateway.to_string(),
            interface_index: entry.interface_index,
            metric: entry.metric,
            is_v6: entry.is_v6(),
        }
    }

    /// Convert to a RouteEntry.
    pub fn to_route_entry(&self) -> Option<RouteEntry> {
        if self.is_v6 {
            let dest: Ipv6Addr = self.destination.parse().ok()?;
            let gw: Ipv6Addr = self.gateway.parse().ok()?;
            Some(
                RouteEntry::new_v6(dest, self.prefix_length, gw, self.interface_index)
                    .with_metric(self.metric),
            )
        } else {
            let dest: Ipv4Addr = self.destination.parse().ok()?;
            let gw: Ipv4Addr = self.gateway.parse().ok()?;
            Some(
                RouteEntry::new_v4(dest, self.prefix_length, gw, self.interface_index)
                    .with_metric(self.metric),
            )
        }
    }
}

/// Serializable DNS settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedDns {
    /// IPv4 DNS servers.
    pub ipv4_servers: Vec<String>,
    /// IPv6 DNS servers.
    pub ipv6_servers: Vec<String>,
    /// Whether DHCP was used.
    pub is_dhcp: bool,
}

impl SerializedDns {
    /// Create from DnsSettings.
    pub fn from_dns_settings(settings: &DnsSettings) -> Self {
        Self {
            ipv4_servers: settings
                .ipv4_servers
                .iter()
                .map(|s| s.to_string())
                .collect(),
            ipv6_servers: settings
                .ipv6_servers
                .iter()
                .map(|s| s.to_string())
                .collect(),
            is_dhcp: settings.is_dhcp,
        }
    }

    /// Convert to DnsSettings.
    pub fn to_dns_settings(&self) -> DnsSettings {
        DnsSettings {
            ipv4_servers: self
                .ipv4_servers
                .iter()
                .filter_map(|s| s.parse().ok())
                .collect(),
            ipv6_servers: self
                .ipv6_servers
                .iter()
                .filter_map(|s| s.parse().ok())
                .collect(),
            is_dhcp: self.is_dhcp,
        }
    }
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
            original_interface_idx: None,
            original_gateway_v6: None,
            deleted_routes: Vec::new(),
            added_routes: Vec::new(),
            original_dns: HashMap::new(),
            vpn_interface: None,
            kill_switch_enabled: false,
            allow_lan: false,
            llmnr_disabled: false,
            netbios_disabled: false,
            ipv6_blocked: false,
            nrpt_rule_guid: None,
            smart_multi_homed_disabled: false,
        }
    }

    /// Get the path to the recovery file.
    ///
    /// Returns `%APPDATA%\HPN\recovery.json`.
    pub fn path() -> Option<PathBuf> {
        let app_data = std::env::var("APPDATA").ok()?;
        let mut path = PathBuf::from(app_data);
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
    /// The lock is held until the file handle is dropped.
    /// This prevents TOCTOU race conditions between checking and acting.
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

        // Acquire exclusive lock to prevent concurrent access
        if let Err(e) = file.lock_exclusive() {
            warn!("Failed to acquire lock on recovery file: {}", e);
            return None;
        }

        let reader = BufReader::new(&file);

        match serde_json::from_reader(reader) {
            Ok(state) => {
                let state: RecoveryState = state;
                // Validate version
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
                // SECURITY: Log corruption as a potential security issue
                error!(
                    "Recovery file corrupted or tampered with at {:?}: {}. \
                     This may indicate a security issue. File will be removed.",
                    path, e
                );
                // Unlock before deleting
                let _ = file.unlock();
                drop(file);
                // Delete the corrupted file
                if let Err(del_err) = fs::remove_file(&path) {
                    warn!("Failed to delete corrupted recovery file: {}", del_err);
                }
                None
            }
        }
    }

    /// Save recovery state to disk with secure permissions.
    ///
    /// The file is created with restricted permissions and uses atomic
    /// write (temp file + rename) to prevent corruption from crashes.
    /// File locking prevents concurrent write attempts.
    pub fn save(&self) -> Result<(), std::io::Error> {
        let path = match Self::path() {
            Some(p) => p,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Could not determine recovery file path",
                ));
            }
        };

        // Create directory if it doesn't exist
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Use atomic write: write to temp file, then rename
        let temp_path = path.with_extension("json.tmp");

        // Create temp file - on Windows, we'll set permissions after creation
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp_path)?;

        // Acquire exclusive lock during write
        file.lock_exclusive()?;

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
        file.unlock()?;
        drop(writer);
        drop(file);

        // Atomic rename (on same filesystem)
        fs::rename(&temp_path, &path)?;

        // FIX-018: tighten the ACL after the rename so even the inherited
        // `Users` ACE from `%APPDATA%\` is stripped. The recovery file
        // contains the user's pre-VPN gateway / DNS / route table, which
        // is information an attacker can use to fingerprint or social-
        // engineer; restricting reads to SYSTEM + the owner closes the
        // accidental disclosure path. Logged but not fatal — see the
        // `restrict_recovery_file_acl` doc for the rationale.
        if let Err(e) = restrict_recovery_file_acl(&path) {
            warn!(
                "Failed to restrict recovery file ACL — falling back to inherited permissions: {}",
                e
            );
        }

        debug!("Saved recovery state to {:?}", path);
        Ok(())
    }

    /// Delete the recovery file.
    pub fn delete() -> Result<(), std::io::Error> {
        if let Some(path) = Self::path() {
            if path.exists() {
                fs::remove_file(&path)?;
                info!("Deleted recovery file at {:?}", path);
            }
        }
        Ok(())
    }

    /// Check if recovery is needed.
    ///
    /// Returns `true` if a recovery file exists and indicates VPN was active.
    ///
    /// NOTE: Prefer using `check_and_perform_recovery()` instead to avoid
    /// TOCTOU race conditions between checking and performing recovery.
    pub fn needs_recovery() -> bool {
        if let Some(state) = Self::load() {
            state.vpn_active
        } else {
            false
        }
    }

    /// Check if recovery is needed and perform it atomically.
    ///
    /// This is the preferred method for startup recovery as it:
    /// 1. Loads the recovery state with exclusive lock
    /// 2. Checks if recovery is needed
    /// 3. Performs recovery while holding the lock
    /// 4. Deletes the recovery file
    ///
    /// Returns `Ok(true)` if recovery was performed, `Ok(false)` if not needed.
    pub fn check_and_perform_recovery() -> Result<bool, RecoveryError> {
        // Unconditional best-effort cleanup of any stale HPN IPv6-block
        // firewall rule, BEFORE touching the recovery file.
        //
        // We run this even when `recovery.json` is missing because that
        // case covers the nastiest real-world scenario: the user enabled
        // `kill_switch=true`, the client installed the IPv6 block rule,
        // and the process was killed (Task Manager, BSOD, forced reboot)
        // BEFORE it managed to save a recovery file. In that state the
        // netsh rule is still live but no recovery metadata describes it,
        // and the user wakes up without IPv6 egress on the physical NIC
        // until they delete the rule by hand.
        //
        // The operation is a no-op if the rule does not exist, so there
        // is no cost to running it on every cold start.
        if let Err(e) = crate::routing::RouteManager::remove_stale_ipv6_block_rule() {
            debug!(
                "Startup IPv6-block-rule cleanup (no-op if not present): {}",
                e
            );
        }

        // Load with lock to prevent concurrent access
        let (state, _lock) = match Self::load_with_lock() {
            Some(s) => s,
            None => {
                debug!("No recovery needed - no recovery file found");
                return Ok(false);
            }
        };

        if !state.vpn_active {
            info!("No recovery needed - VPN was not active");
            // Lock is dropped here, then we delete
            drop(_lock);
            Self::delete().ok();
            return Ok(false);
        }

        // Perform recovery with the loaded state (lock still held)
        info!("Performing network recovery after unclean shutdown...");
        Self::perform_recovery_with_state(&state)?;

        // Lock is released when _lock is dropped
        Ok(true)
    }

    /// Perform network recovery.
    ///
    /// This restores the original network settings:
    /// 1. Delete routes that were added by the VPN
    /// 2. Restore routes that were deleted by the VPN
    /// 3. Restore DNS settings for all interfaces
    ///
    /// NOTE: Prefer using `check_and_perform_recovery()` for startup recovery
    /// to avoid TOCTOU race conditions.
    pub fn perform_recovery() -> Result<(), RecoveryError> {
        let (state, _lock) = match Self::load_with_lock() {
            Some(s) => s,
            None => {
                info!("No recovery needed - no recovery file found");
                return Ok(());
            }
        };

        if !state.vpn_active {
            info!("No recovery needed - VPN was not active");
            drop(_lock);
            Self::delete().ok();
            return Ok(());
        }

        info!("Performing network recovery after unclean shutdown...");
        Self::perform_recovery_with_state(&state)
    }

    /// Internal method to perform recovery with a pre-loaded state.
    fn perform_recovery_with_state(state: &RecoveryState) -> Result<(), RecoveryError> {
        let mut errors = Vec::new();

        // Step 1: Delete routes that were added by the VPN
        for route in &state.added_routes {
            if let Some(entry) = route.to_route_entry() {
                debug!(
                    "Deleting VPN route: {}/{} via {}",
                    route.destination, route.prefix_length, route.gateway
                );
                if let Err(e) = delete_route(&entry) {
                    // Route might already be gone - not a critical error
                    debug!("Could not delete route (may already be gone): {}", e);
                }
            }
        }

        // Step 2: Restore routes that were deleted by the VPN
        for route in &state.deleted_routes {
            if let Some(entry) = route.to_route_entry() {
                info!(
                    "Restoring original route: {}/{} via {}",
                    route.destination, route.prefix_length, route.gateway
                );
                if let Err(e) = add_route(&entry) {
                    // This is more serious - log it
                    warn!("Failed to restore route: {}", e);
                    errors.push(format!("Route restore failed: {}", e));
                }
            }
        }

        // If we don't have specific route info, try to detect and restore default gateway
        if state.deleted_routes.is_empty() && state.original_gateway.is_some() {
            if let Some(gw) = &state.original_gateway {
                if let Ok(gw_addr) = gw.parse::<Ipv4Addr>() {
                    info!("Restoring default gateway: {}", gw);
                    let entry = RouteEntry::new_v4(
                        Ipv4Addr::UNSPECIFIED,
                        0,
                        gw_addr,
                        state.original_interface_idx.unwrap_or(0),
                    );
                    if let Err(e) = add_route(&entry) {
                        warn!("Failed to restore default gateway: {}", e);
                        errors.push(format!("Default gateway restore failed: {}", e));
                    }
                }
            }
        }

        // Step 3: Restore DNS settings
        for (interface_name, dns) in &state.original_dns {
            info!("Restoring DNS for interface: {}", interface_name);

            if dns.is_dhcp || (dns.ipv4_servers.is_empty() && dns.ipv6_servers.is_empty()) {
                // Clear DNS to use DHCP
                if let Err(e) = clear_interface_dns(interface_name) {
                    warn!("Failed to clear DNS for {}: {}", interface_name, e);
                    errors.push(format!("DNS clear failed for {}: {}", interface_name, e));
                }
            } else {
                // Restore static DNS
                let settings = dns.to_dns_settings();
                if let Err(e) = set_interface_dns(interface_name, &settings) {
                    warn!("Failed to restore DNS for {}: {}", interface_name, e);
                    errors.push(format!("DNS restore failed for {}: {}", interface_name, e));
                }
            }
        }

        // Step 4: Flush DNS cache
        if let Err(e) = crate::windows_api::flush_dns_cache() {
            warn!("Failed to flush DNS cache: {}", e);
        }

        // Step 5: Restore LLMNR if it was disabled
        if state.llmnr_disabled {
            info!("Restoring LLMNR after crash recovery");
            crate::routing::DnsLeakProtection::enable_llmnr();
        }

        // Step 6: Restore NetBIOS if it was disabled
        if state.netbios_disabled {
            info!("Restoring NetBIOS after crash recovery");
            crate::routing::DnsLeakProtection::enable_netbios(&[]);
        }

        // Step 6.bis: Remove the NRPT rule that forced every DNS query
        // through the (now-defunct) VPN resolvers. Without removal, a
        // crashed-then-rebooted system has BROKEN name resolution
        // system-wide — every app trying to resolve any host gets a
        // SERVFAIL because the rule still says "send to 10.x.x.x" but
        // that resolver isn't reachable any more.
        //
        // We attempt removal even when `state.nrpt_rule_guid` is None
        // because (a) older clients pre-dating this field may have
        // installed a rule without persisting the GUID, and (b) the
        // comment-based fallback `cleanup_orphaned_nrpt_rules` catches
        // any rule we may have installed in a previous version.
        if let Some(guid) = state.nrpt_rule_guid.as_deref() {
            info!("Removing NRPT rule after crash recovery: {}", guid);
            crate::routing::DnsLeakProtection::remove_nrpt_rule(guid);
        }
        crate::routing::DnsLeakProtection::cleanup_orphaned_nrpt_rules();

        // Step 6.ter: Restore the SmartMultiHomed DNS policy if we
        // overrode it. Same rationale as the NRPT case: an orphaned
        // policy could subtly bias DNS resolution on the user's machine
        // even after the VPN process is long gone.
        if state.smart_multi_homed_disabled {
            info!("Restoring SmartMultiHomed DNS policy after crash recovery");
            crate::routing::DnsLeakProtection::restore_smart_multi_homed();
        }

        // Step 7: Remove the HPN IPv6-block firewall rule if it was
        // installed. A clean disconnect already removes the rule via
        // `RouteManager::cleanup()`, so this path is the crash-recovery
        // fallback: without it, a user whose process was killed (Task
        // Manager End Task, BSOD, forced reboot) wakes up to a system
        // that still refuses all IPv6 egress because the rule outlives
        // the VPN process.
        //
        // Always attempt the removal, even if `state.ipv6_blocked` is
        // false, because older clients (before this field was added)
        // may have installed the rule without recording the flag. The
        // operation is a no-op when no rule matches the name.
        if let Err(e) = crate::routing::RouteManager::remove_stale_ipv6_block_rule() {
            // Not fatal: if netsh is unavailable the user can remove the
            // rule manually with `netsh advfirewall firewall delete rule
            // name=HPN_VPN_IPv6_Block`.
            warn!(
                "Failed to remove stale HPN IPv6 block rule during recovery: {}",
                e
            );
        } else if state.ipv6_blocked {
            info!("Removed stale HPN IPv6 block rule after crash recovery");
        }

        // Delete the recovery file after successful recovery
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
        kill_switch: bool,
        allow_lan: bool,
    ) -> Result<Self, RecoveryError> {
        let mut state = Self::new();
        state.vpn_active = true;
        state.vpn_interface = Some(vpn_interface.to_string());
        state.kill_switch_enabled = kill_switch;
        state.allow_lan = allow_lan;

        // Capture default gateway
        if let Ok(Some(gw)) = get_default_gateway() {
            state.original_gateway = Some(gw.gateway.to_string());
            state.original_interface_idx = Some(gw.interface_index);
            debug!("Captured original gateway: {:?}", state.original_gateway);
        }

        // Capture DNS settings for all physical interfaces
        if let Ok(interfaces) = get_physical_interfaces() {
            for iface in interfaces {
                if let Ok(dns) = get_interface_dns(&iface.alias) {
                    state
                        .original_dns
                        .insert(iface.alias.clone(), SerializedDns::from_dns_settings(&dns));
                    debug!("Captured DNS for {}: {:?}", iface.alias, dns);
                }
            }
        }

        Ok(state)
    }

    /// Record a route that was added.
    pub fn record_added_route(&mut self, entry: &RouteEntry) {
        self.added_routes
            .push(SerializedRoute::from_route_entry(entry));
    }

    /// Record a route that was deleted.
    pub fn record_deleted_route(&mut self, entry: &RouteEntry) {
        self.deleted_routes
            .push(SerializedRoute::from_route_entry(entry));
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
    /// Windows API error.
    WindowsApi(WindowsApiError),
    /// Recovery completed but with some errors.
    PartialRecovery(Vec<String>),
}

impl std::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecoveryError::Io(e) => write!(f, "I/O error: {}", e),
            RecoveryError::WindowsApi(e) => write!(f, "Windows API error: {}", e),
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

impl From<WindowsApiError> for RecoveryError {
    fn from(e: WindowsApiError) -> Self {
        RecoveryError::WindowsApi(e)
    }
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
        assert!(state.deleted_routes.is_empty());
    }

    #[test]
    fn test_serialized_route_roundtrip() {
        let entry = RouteEntry::new_v4(
            Ipv4Addr::new(10, 0, 0, 0),
            8,
            Ipv4Addr::new(192, 168, 1, 1),
            5,
        )
        .with_metric(100);

        let serialized = SerializedRoute::from_route_entry(&entry);
        let restored = serialized.to_route_entry().expect("should restore");

        assert_eq!(restored.destination, entry.destination);
        assert_eq!(restored.prefix_length, entry.prefix_length);
        assert_eq!(restored.gateway, entry.gateway);
        assert_eq!(restored.interface_index, entry.interface_index);
        assert_eq!(restored.metric, entry.metric);
    }

    #[test]
    fn test_serialized_dns_roundtrip() {
        let settings = DnsSettings::with_dual_stack(
            vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)],
            vec![Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)],
        );

        let serialized = SerializedDns::from_dns_settings(&settings);
        let restored = serialized.to_dns_settings();

        assert_eq!(restored.ipv4_servers, settings.ipv4_servers);
        assert_eq!(restored.ipv6_servers, settings.ipv6_servers);
    }

    #[test]
    fn test_recovery_path() {
        // This test will only pass on Windows with APPDATA set
        if std::env::var("APPDATA").is_ok() {
            let path = RecoveryState::path();
            assert!(path.is_some());
            let path = path.unwrap();
            assert!(path.to_string_lossy().contains("HPN"));
            assert!(path.to_string_lossy().contains("recovery.json"));
        }
    }
}
