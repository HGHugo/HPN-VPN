//! Tauri command handlers.
//!
//! These commands are invoked from the React frontend via Tauri's IPC.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use tauri::{AppHandle, State};
use tokio::sync::Mutex as TokioMutex;
use tracing::debug;

/// Global flag to prevent concurrent connections.
/// This flag is set to `true` when connect() starts and remains `true` until
/// the connection reaches a terminal state (Connected, Disconnected, Error).
/// It is NOT reset when connect() returns - only when the status changes.
static CONNECT_IN_PROGRESS: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Timestamp of last connection attempt for rate limiting.
/// Stored as milliseconds since UNIX epoch.
static LAST_CONNECT_ATTEMPT: AtomicU64 = AtomicU64::new(0);

/// Minimum interval between connection attempts in milliseconds (2 seconds).
const MIN_CONNECT_INTERVAL_MS: u64 = 2000;

/// Check if enough time has passed since the last connection attempt.
/// Returns an error if the rate limit is exceeded.
fn check_connect_rate_limit() -> Result<(), String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    // Atomic load+check+store to prevent races on concurrent connect attempts.
    loop {
        let last = LAST_CONNECT_ATTEMPT.load(Ordering::Relaxed);

        if now.saturating_sub(last) < MIN_CONNECT_INTERVAL_MS {
            return Err("Please wait before attempting to connect again".to_string());
        }

        if LAST_CONNECT_ATTEMPT
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            break;
        }

        std::hint::spin_loop();
    }

    Ok(())
}

/// Reset the CONNECT_IN_PROGRESS flag.
/// Called when connection reaches a terminal state.
pub fn reset_connect_in_progress() {
    CONNECT_IN_PROGRESS.store(false, Ordering::SeqCst);
}

use hpn_client_core::config::{ClientConfig, Credentials};

use crate::config::{Profile, Settings};

/// Full provider-config teardown: clear `NETunnelProviderProtocol
/// .providerConfiguration`, remove legacy on-disk copies, and purge any
/// stale `io.hpn.vpn.profile.*` Keychain entries left by older builds.
///
/// Used on:
///   - App startup (clean slate).
///   - Connect-failure (we never reached a usable tunnel).
///   - Disconnect (user-initiated teardown).
///
/// MUST NOT be called right after a successful connect: erasing
/// `providerConfiguration` while the tunnel is running would prevent the
/// OS from restarting the Packet Tunnel Extension after a crash, sleep/
/// wake event, or `sysextd` recycle (we removed the legacy file fallback,
/// so the extension would fail closed with no credentials to use).
/// Use [`clear_provider_config_post_success`] for the connect-success path
/// instead.
///
/// Uses `real_user_home()` to bypass App Sandbox container remapping:
/// under sandbox, `dirs::home_dir()` returns the container path, not the real
/// home where the Group Container actually lives. Without this bypass, the
/// sandboxed app would try to delete a non-existent file while the real
/// `provider-config.json` with credentials would persist.
///
/// This build never writes to the macOS Keychain anymore, but the purge
/// step is retained so a fresh install on top of an older one wipes any
/// legacy `io.hpn.vpn.profile.*` items that older builds may have left.
pub fn clear_provider_config_full() {
    // In unit-test builds, `clear_provider_configuration` short-circuits
    // to `Ok(())` (no FFI call into NetworkExtension preferences) — see
    // its body. The caller does NOT need an extra `#[cfg(not(test))]`
    // guard; the function already handles that, and removing the guard
    // here keeps the function alive (otherwise the test build would see
    // it as dead code).
    if let Err(e) = crate::native_vpn::clear_provider_configuration() {
        tracing::warn!(
            "Failed to clear NetworkExtension providerConfiguration: {}",
            e
        );
    }

    let home = crate::commands::connection::real_user_home();
    let primary = home.join("Library/Group Containers/group.io.hpn.vpn/provider-config.json");
    let _ = std::fs::remove_file(&primary);
    // Also try the non-sandbox fallback location in case a CLI build was
    // used previously.
    if let Some(data) = dirs::data_dir() {
        let path = data.join("hpn-vpn/provider-config.json");
        let _ = std::fs::remove_file(&path);
    }
    // Defensive: this build never calls `keychain::set_password`, so the
    // purge is purely a migration aid for users upgrading from older
    // installs that did stash profile passwords in the Keychain.
    crate::keychain::purge_all_profile_credentials();
}

/// Post-success cleanup: deliberately a no-op.
///
/// On Tahoe Developer-ID System Extensions, the running tunnel reads its
/// credentials from `NETunnelProviderProtocol.providerConfiguration` not
/// only at first start but on every OS-initiated restart (sleep/wake,
/// sysextd recycle, etc.). The legacy on-disk fallback was removed from
/// the extension, so wiping `providerConfiguration` here would
/// permanently brick the tunnel until the user clicks Connect again.
///
/// We also no longer write the password to the user Keychain at connect
/// time, so there is nothing to scrub. The function exists only to make
/// the intent explicit at the success-branch call site.
pub fn clear_provider_config_post_success() {
    // No-op by design. See doc comment.
}

/// Clean up temporary tunnel files (stats, legacy rekey signal) using
/// the real (unsandboxed) home path for the same reason as
/// `clear_provider_config_full`.
///
/// The `rekey-signal` file is no longer written by this build — rekey
/// requests are delivered synchronously through the
/// `NETunnelProviderSession.sendProviderMessage` path (see
/// `native_vpn::force_rekey`). We still remove the file on startup to
/// clear the stale leftover from previous installs that relied on the
/// polled-file mechanism, so the extension cannot be confused by a
/// long-forgotten signal sitting in the container.
pub fn clear_tunnel_temp_files() {
    let home = crate::commands::connection::real_user_home();
    let container = home.join("Library/Group Containers/group.io.hpn.vpn");
    let _ = std::fs::remove_file(container.join("tunnel-stats.json"));
    // Legacy: pre-M12 installs wrote here. Harmless cleanup.
    let _ = std::fs::remove_file(container.join("rekey-signal"));
    if let Some(data) = dirs::data_dir() {
        let dir = data.join("hpn-vpn");
        let _ = std::fs::remove_file(dir.join("tunnel-stats.json"));
        // Same legacy cleanup, non-sandbox fallback path.
        let _ = std::fs::remove_file(dir.join("rekey-signal"));
    }
}

/// Check the system VPN status via scutil (no deadlock risk).
fn check_system_vpn_status() -> String {
    let output = std::process::Command::new("scutil")
        .args(["--nc", "list"])
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                if line.contains("HPN VPN") {
                    if line.contains("Connected") && !line.contains("Disconnected") {
                        return "Connected".to_string();
                    } else if line.contains("Connecting") {
                        return "Connecting".to_string();
                    } else if line.contains("Disconnecting") {
                        return "Disconnecting".to_string();
                    } else if line.contains("Disconnected") {
                        return "Disconnected".to_string();
                    }
                }
            }
            "Invalid".to_string()
        }
        Err(_) => "Invalid".to_string(),
    }
}

/// Mutex to prevent concurrent connect calls.
pub type ConnectMutex = TokioMutex<()>;
use crate::error::{AppError, CommandError};
use crate::state::{AppState, ConnectionStats, ConnectionStatus, LogEntry, LogLevel};
use crate::validation::{
    validate_port, validate_profile_id, validate_profile_name, validate_public_key,
    validate_server_address,
};

mod connection;
mod logs;
mod profiles;
mod settings;

// ============================================================================
// Log Commands (wrappers)
// ============================================================================

#[tauri::command]
pub fn get_logs(state: State<'_, AppStateRef>) -> Vec<LogEntry> {
    logs::get_logs(state)
}

#[tauri::command]
pub fn clear_logs(state: State<'_, AppStateRef>) {
    logs::clear_logs(state)
}

#[tauri::command]
pub fn export_logs(state: State<'_, AppStateRef>) -> Result<String, CommandError> {
    logs::export_logs(state)
}

/// Stored menu item for tray status text updates.
pub static TRAY_STATUS_ITEM: std::sync::OnceLock<tauri::menu::MenuItem<tauri::Wry>> =
    std::sync::OnceLock::new();

/// Update the system tray icon and tooltip based on connection status.
fn update_tray_status(app: &AppHandle, status: ConnectionStatus) {
    let tooltip = match status {
        ConnectionStatus::Connected => "HPN VPN - Connected",
        ConnectionStatus::Connecting => "HPN VPN - Connecting...",
        ConnectionStatus::Disconnecting => "HPN VPN - Disconnecting...",
        ConnectionStatus::Reconnecting => "HPN VPN - Reconnecting...",
        ConnectionStatus::Disconnected => "HPN VPN - Disconnected",
        ConnectionStatus::Error => "HPN VPN - Error",
    };

    let menu_text = match status {
        ConnectionStatus::Connected => "Status: Connected",
        ConnectionStatus::Connecting => "Status: Connecting...",
        ConnectionStatus::Disconnecting => "Status: Disconnecting...",
        ConnectionStatus::Reconnecting => "Status: Reconnecting...",
        ConnectionStatus::Disconnected => "Status: Disconnected",
        ConnectionStatus::Error => "Status: Error",
    };

    if let Some(tray) = app.tray_by_id("main") {
        let _ = tray.set_tooltip(Some(tooltip));
    }

    if let Some(item) = TRAY_STATUS_ITEM.get() {
        let _ = item.set_text(menu_text);
    }
}

type AppStateRef = Arc<RwLock<AppState>>;

// ============================================================================
// Connection Commands
// ============================================================================

/// Connect to a VPN profile (without authentication).
///
/// For profiles that require authentication, use `connect_with_auth` instead.
#[tauri::command]
pub async fn connect(
    app: AppHandle,
    state: State<'_, AppStateRef>,
    connect_mutex: State<'_, ConnectMutex>,
    profile_id: String,
) -> Result<(), CommandError> {
    // Check rate limit to prevent rapid reconnection attempts
    check_connect_rate_limit().map_err(|e| CommandError::from(AppError::Connection(e)))?;

    debug!("connect() called with profile_id: {}", profile_id);

    // Validate profile_id before any operations
    validate_profile_id(&profile_id).map_err(|e| CommandError::from(AppError::Config(e)))?;

    // Call internal connect function without credentials
    connect_internal(app, state, connect_mutex, profile_id, None)
        .await
        .map_err(|e| CommandError::from(AppError::Connection(e)))
}

/// Connect to a VPN profile with user authentication.
///
/// This is similar to `connect` but accepts username and password for servers
/// that require user authentication. The password is encrypted using the server's
/// KEM public key before transmission.
#[tauri::command]
pub async fn connect_with_auth(
    app: AppHandle,
    state: State<'_, AppStateRef>,
    connect_mutex: State<'_, ConnectMutex>,
    profile_id: String,
    username: String,
    password: String,
) -> Result<(), CommandError> {
    // Check rate limit to prevent rapid reconnection attempts
    check_connect_rate_limit().map_err(|e| CommandError::from(AppError::Connection(e)))?;

    debug!("connect_with_auth() called with profile_id: {}", profile_id);

    // Validate profile_id before any operations
    validate_profile_id(&profile_id).map_err(|e| CommandError::from(AppError::Config(e)))?;

    // Create credentials from provided username/password
    let credentials = Credentials::new(username, password);

    // Validate credentials format
    credentials
        .validate()
        .map_err(|e: hpn_client_core::error::ClientError| {
            CommandError::from(AppError::Config(e.to_string()))
        })?;

    // Call internal connect function with credentials
    connect_internal(app, state, connect_mutex, profile_id, Some(credentials))
        .await
        .map_err(|e| CommandError::from(AppError::Connection(e)))
}

/// Internal connect implementation shared by `connect` and `connect_with_auth`.
///
/// On macOS, this uses the Apple-native `NETunnelProviderManager` path:
/// 1. Build the provider config from the selected profile.
/// 2. Write it to the shared app group container.
/// 3. Install/start the VPN via the native manager.
///
/// The actual handshake, encryption, and packet pumping happen inside the
/// Packet Tunnel Extension (`hpn-tunnel-ext`), not in this process.
async fn connect_internal(
    app: AppHandle,
    state: State<'_, AppStateRef>,
    connect_mutex: State<'_, ConnectMutex>,
    profile_id: String,
    credentials: Option<Credentials>,
) -> Result<(), String> {
    // Use atomic compare-and-swap to ensure only one connect runs at a time.
    if CONNECT_IN_PROGRESS
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err("Connection already in progress".to_string());
    }

    let _connect_guard = match connect_mutex.inner().try_lock() {
        Ok(guard) => guard,
        Err(_) => {
            reset_connect_in_progress();
            return Err("Connection already in progress".to_string());
        }
    };

    // Get profile and settings, set status to Connecting.
    let (profile, settings) = {
        let mut state = state.write();
        let old_status = state.status;
        debug!("connect_internal() current status: {:?}", old_status);

        // Only allow connecting from Disconnected or Error states
        if state.status == ConnectionStatus::Connected {
            reset_connect_in_progress();
            return Err("Already connected".to_string());
        }

        let profile = match state.get_profile(&profile_id).cloned() {
            Some(p) => p,
            None => {
                reset_connect_in_progress();
                return Err(format!("Profile not found: {}", profile_id));
            }
        };

        // Check if profile requires auth but no credentials provided
        if profile.requires_auth && credentials.is_none() {
            reset_connect_in_progress();
            return Err(
                "This profile requires authentication. Please provide credentials.".to_string(),
            );
        }

        // Validate profile fields before using them
        if let Err(e) = validate_server_address(&profile.server) {
            reset_connect_in_progress();
            return Err(e);
        }
        if let Err(e) = validate_port(profile.port) {
            reset_connect_in_progress();
            return Err(e);
        }

        // Force status to Connecting regardless of previous state
        debug!(
            "connect_internal() setting status from {:?} to Connecting",
            state.status
        );
        state.status = ConnectionStatus::Connecting;
        state.active_profile_id = Some(profile_id.clone());
        state.add_log(
            LogLevel::Info,
            format!("Connecting to {}...", profile.server),
        );
        state.add_log(LogLevel::Info, "Generating ephemeral ML-KEM keypair...");

        if credentials.is_some() {
            state.add_log(LogLevel::Info, "Using user authentication");
        }

        (profile, state.settings.clone())
    };
    update_tray_status(&app, ConnectionStatus::Connecting);

    // Parse server address for the provider config.
    let server_addr: SocketAddr = format!("{}:{}", profile.server, profile.port)
        .parse()
        .map_err(|e| {
            let mut state = state.write();
            state.status = ConnectionStatus::Error;
            state.add_log(LogLevel::Error, format!("Invalid server address: {}", e));
            reset_connect_in_progress();
            format!("Invalid server address: {}", e)
        })?;

    // Build the client config that the Packet Tunnel Extension will use.
    let security_level = profile.security_level.to_core_level();
    let client_config = ClientConfig {
        server_addr,
        server_public_key: profile.server_public_key.clone(),
        server_kem_public_key: profile.server_kem_public_key.clone(),
        keepalive_interval_secs: settings.keepalive_interval,
        connection_timeout_secs: settings.connection_timeout,
        auto_reconnect: settings.auto_reconnect,
        security_level,
        requires_auth: profile.requires_auth,
        ..Default::default()
    };

    // Build the provider config JSON for the extension.
    let split_cfg = profile.split_tunnel.as_ref();
    let is_split = split_cfg
        .map(|s| s.enabled && s.mode == "bypass")
        .unwrap_or(false);
    let allow_lan = split_cfg.map(|s| s.bypass_local).unwrap_or(true);
    let split_routes: Vec<String> = if is_split {
        split_cfg
            .and_then(|s| s.routes.as_ref())
            .map(|r| {
                r.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    // Provider-config IPC: the JSON below is delivered to the Packet
    // Tunnel System Extension via `NETunnelProviderProtocol.provider
    // Configuration` — see `VPNManager.swift::pendingProviderConfig`
    // doc comment for the full architectural rationale.
    //
    // SECURITY MODEL (revised May 2026 after field investigation):
    //   - On macOS Tahoe Developer ID, a Packet Tunnel System Extension
    //     runs as `root` and CANNOT access the user's keychain (or any
    //     keychain) via SecItemCopyMatching, returning errSecNotAvailable
    //     (-25291) regardless of `kSecUseDataProtectionKeychain` and
    //     `keychain-access-groups` entitlement.
    //   - Apple's documented IPC channel for system-extension VPNs is
    //     `providerConfiguration`, which the system persists in
    //     `/Library/Preferences/com.apple.networkextension.plist`
    //     (root-only readable). This is the SAME storage backend Apple
    //     uses for IKEv2/L2TP shared-secrets, so writing the password
    //     here matches the trust boundary of the OS's own VPN stack.
    //   - The audit-CRED-1 prohibition was about not leaving the
    //     password in a world-readable file inside the App Group
    //     container; that path is gone (we no longer use the file-based
    //     handoff for the authoritative IPC). The plist that NEVPN
    //     persists is restricted to `_networkd:wheel 600` and the
    //     password is never visible to non-admin processes.
    //   - The audit-H15 envelope code in `hpn_core::provider_envelope`
    //     is no longer used on this platform. The extension running as
    //     root cannot share a Keychain master key with the host, so
    //     verifying the envelope is impossible; the providerConfiguration
    //     XPC channel is the trust boundary instead.
    //
    // This build does NOT touch the user Keychain on connect. We hand the
    // credentials inline through providerConfiguration; macOS persists
    // them in its own root-only plist and re-supplies them on every
    // OS-initiated tunnel restart (sleep/wake, sysextd recycle). No
    // "remember password" Keychain entry is created — the persistence is
    // entirely owned by macOS NetworkExtension.
    let provider_config = if let Some(ref creds) = credentials {
        // INLINE the credentials directly. `creds.password` is a
        // `Zeroizing<String>`; `&**creds.password` is `&str` borrowed
        // from the live, soon-to-be-zeroized backing buffer. Serde
        // copies it into the JSON string output, which is itself
        // wrapped in `Zeroizing<String>` at the call site below — so
        // the password lifetime is bounded to this connect attempt.
        // After NETunnelProviderManager.saveToPreferences() runs, the
        // OS holds the password in its own plist; the host's
        // in-process buffer is dropped + zeroed.
        serde_json::json!({
            "client_config": client_config,
            "server_endpoint": server_addr.to_string(),
            "full_tunnel": !is_split,
            "allow_lan": allow_lan,
            "split_routes": split_routes,
            "credentials": {
                "username": &*creds.username,
                "password": &**creds.password,
            },
        })
    } else {
        serde_json::json!({
            "client_config": client_config,
            "server_endpoint": server_addr.to_string(),
            "full_tunnel": !is_split,
            "allow_lan": allow_lan,
            "split_routes": split_routes,
            "credentials": serde_json::Value::Null,
        })
    };

    // Wrap in Zeroizing to clear the raw provider JSON from memory after use.
    // It contains the password when the profile uses password authentication;
    // macOS then persists it in providerConfiguration's root-only plist.
    let config_json =
        zeroize::Zeroizing::new(serde_json::to_string(&provider_config).map_err(|e| {
            reset_connect_in_progress();
            format!("Failed to serialize provider config: {}", e)
        })?);

    // Write config to app group container (shared with extension).
    {
        let mut state = state.write();
        state.add_log(LogLevel::Info, "Preparing tunnel configuration...");
    }

    crate::native_vpn::save_provider_config(&config_json).map_err(|e| {
        // No host Keychain rollback needed — this build never writes the
        // password to the user Keychain.
        let mut state = state.write();
        state.status = ConnectionStatus::Error;
        state.add_log(
            LogLevel::Error,
            format!("Failed to save tunnel config: {}", e),
        );
        reset_connect_in_progress();
        e
    })?;

    // Install VPN profile and start the tunnel via NETunnelProviderManager.
    // Launch in a background thread so the Tauri command returns immediately.
    // The frontend polls get_status to detect when the tunnel is connected.
    {
        let mut state = state.write();
        state.add_log(LogLevel::Info, "Starting Apple-native VPN tunnel...");
    }

    let security_level_copy = security_level;
    let state_clone = state.inner().clone();
    let app_clone = app.clone();

    // Snapshot the routing-policy bits we need to hand to the Swift
    // NETunnelProviderManager helper. `is_split` is the profile-level
    // split-tunnel toggle — when it's true we explicitly forbid the
    // system from collapsing our `includedRoutes` into full-tunnel by
    // setting `includeAllNetworks=false` on the Apple side.
    let full_tunnel = !is_split;
    let allow_lan_flag = allow_lan;

    std::thread::spawn(move || {
        match crate::native_vpn::install_and_start_vpn(full_tunnel, allow_lan_flag) {
            Ok(()) => {
                // Wait for the extension to complete the handshake.
                // Poll system VPN status to detect success or failure.
                let mut connected = false;
                for i in 0..30 {
                    std::thread::sleep(std::time::Duration::from_millis(500));

                    let status = check_system_vpn_status();
                    match status.as_str() {
                        "Connected" => {
                            connected = true;
                            break;
                        }
                        "Disconnected" | "Invalid" if i > 2 => {
                            // Extension tried and failed (e.g. bad credentials)
                            break;
                        }
                        _ => continue, // Still connecting...
                    }
                }

                if connected {
                    // Post-success is a deliberate no-op: the running
                    // tunnel needs `providerConfiguration` to survive any
                    // OS-initiated restart (sleep/wake, sysextd recycle).
                    clear_provider_config_post_success();

                    let session_id = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos() as u64;

                    let mut state = state_clone.write();
                    state.set_connected(session_id);

                    let kem_name = match security_level_copy {
                        hpn_core::crypto::SecurityLevel::Level3 => "ML-KEM-768",
                        hpn_core::crypto::SecurityLevel::Level5 => "ML-KEM-1024",
                    };
                    state.add_log(
                        LogLevel::Info,
                        format!(
                            "Connected via Apple Network Extension. Cipher: AES-256-GCM. KEM: X25519 + {kem_name}"
                        ),
                    );
                    drop(state);
                    update_tray_status(&app_clone, ConnectionStatus::Connected);
                } else {
                    // Tunnel never reached Connected — wipe everything so
                    // the next attempt starts from a clean slate.
                    clear_provider_config_full();

                    let mut state = state_clone.write();
                    state.status = ConnectionStatus::Error;
                    state.add_log(
                        LogLevel::Error,
                        "Authentication failed or tunnel rejected by server".to_string(),
                    );
                    drop(state);
                    update_tray_status(&app_clone, ConnectionStatus::Error);
                }
            }
            Err(e) => {
                clear_provider_config_full();
                let mut state = state_clone.write();
                state.status = ConnectionStatus::Error;
                state.add_log(LogLevel::Error, format!("VPN start failed: {}", e));
            }
        }
        reset_connect_in_progress();
    });

    Ok(())
}

/// Disconnect from VPN.
#[tauri::command]
pub async fn disconnect(app: AppHandle, state: State<'_, AppStateRef>) -> Result<(), CommandError> {
    connection::disconnect(app, state).await
}

/// Get current connection status.
#[tauri::command]
pub fn get_status(app: AppHandle, state: State<'_, AppStateRef>) -> ConnectionStatus {
    let status = connection::get_status(state);
    // Keep tray in sync with status on every poll.
    update_tray_status(&app, status);
    status
}

/// Get connection statistics.
#[tauri::command]
pub fn get_stats(state: State<'_, AppStateRef>) -> ConnectionStats {
    connection::get_stats(state)
}

// ============================================================================
// Profile Commands
// ============================================================================

#[tauri::command]
pub fn get_profiles(state: State<'_, AppStateRef>) -> Vec<Profile> {
    profiles::get_profiles(state)
}

#[tauri::command]
pub fn save_profile(
    state: State<'_, AppStateRef>,
    profile: profiles::ProfileInput,
) -> Result<Profile, CommandError> {
    profiles::save_profile(state, profile)
}

#[tauri::command]
pub fn delete_profile(
    state: State<'_, AppStateRef>,
    profile_id: String,
) -> Result<(), CommandError> {
    profiles::delete_profile(state, profile_id)
}

// ============================================================================
// Settings Commands
// ============================================================================

#[tauri::command]
pub fn get_settings(state: State<'_, AppStateRef>) -> Settings {
    settings::get_settings(state)
}

#[tauri::command]
pub fn save_settings(
    state: State<'_, AppStateRef>,
    settings: Settings,
) -> Result<(), CommandError> {
    settings::save_settings(state, settings)
}

/// Force key rotation.
#[tauri::command]
pub async fn force_rekey(state: State<'_, AppStateRef>) -> Result<(), CommandError> {
    connection::force_rekey(state).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests in this module poke at process-global atomics
    /// (`CONNECT_IN_PROGRESS`, `LAST_CONNECT_ATTEMPT`). Cargo runs
    /// `#[test]` functions on a thread pool, so without
    /// serialisation two of these tests race on the same atomic and
    /// flake. Holding this mutex across each test body forces them
    /// to execute sequentially regardless of the runner's
    /// scheduling decisions.
    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    /// Reset the global rate-limit state to a known timestamp so the
    /// test order doesn't matter. We call `LAST_CONNECT_ATTEMPT.store`
    /// directly rather than relying on the public API because the
    /// helper takes wall-clock time and we want a deterministic
    /// fixture.
    fn reset_rate_limit_to(ms_since_epoch: u64) {
        LAST_CONNECT_ATTEMPT.store(ms_since_epoch, Ordering::Relaxed);
    }

    #[test]
    fn test_rate_limit_first_attempt_passes() {
        let _guard = TEST_LOCK.lock();
        // A long-ago last-attempt timestamp must NOT block the next call.
        reset_rate_limit_to(0);
        let result = check_connect_rate_limit();
        assert!(result.is_ok(), "first attempt after reset must pass");
    }

    #[test]
    fn test_rate_limit_blocks_immediate_retry() {
        let _guard = TEST_LOCK.lock();
        // Two calls within MIN_CONNECT_INTERVAL_MS must reject the
        // second. Run two checks back-to-back; the second sees the
        // freshly-stamped timestamp from the first.
        reset_rate_limit_to(0);
        check_connect_rate_limit().expect("first attempt must pass after rate-limit reset");
        let result = check_connect_rate_limit();
        assert!(
            result.is_err(),
            "second attempt within {} ms must be rate-limited",
            MIN_CONNECT_INTERVAL_MS
        );
        let err = result.unwrap_err();
        assert!(
            err.to_lowercase().contains("wait"),
            "rate-limit error must instruct user to wait, got: {}",
            err
        );
    }

    #[test]
    fn test_rate_limit_unblocks_after_interval() {
        let _guard = TEST_LOCK.lock();
        // Set the last attempt to "MIN_CONNECT_INTERVAL_MS + 100ms ago"
        // and verify the next call is accepted. We compute "now - delta"
        // in ms-since-epoch units to match the helper's clock source.
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        reset_rate_limit_to(now_ms.saturating_sub(MIN_CONNECT_INTERVAL_MS + 100));
        let result = check_connect_rate_limit();
        assert!(
            result.is_ok(),
            "attempt {} ms after last must pass: {:?}",
            MIN_CONNECT_INTERVAL_MS + 100,
            result
        );
    }

    #[test]
    fn test_connect_in_progress_compare_exchange() {
        let _guard = TEST_LOCK.lock();
        // CONNECT_IN_PROGRESS must serialise concurrent connect calls.
        // Manually reset, set, verify second CAS fails, reset, second
        // CAS now succeeds.
        CONNECT_IN_PROGRESS.store(false, Ordering::SeqCst);
        let first =
            CONNECT_IN_PROGRESS.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst);
        assert!(first.is_ok(), "first CAS must succeed");

        let second =
            CONNECT_IN_PROGRESS.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst);
        assert!(
            second.is_err(),
            "second CAS while flag is true must fail (serialises connects)"
        );

        reset_connect_in_progress();
        let third =
            CONNECT_IN_PROGRESS.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst);
        assert!(third.is_ok(), "CAS after reset must succeed");

        // Clean up so we don't poison subsequent tests.
        reset_connect_in_progress();
    }

    #[test]
    fn test_clear_provider_config_full_idempotent() {
        // Calling `clear_provider_config_full` when nothing is on disk
        // must succeed silently. This is the recovery path that runs
        // on connect-failure / disconnect; making it idempotent
        // prevents start-up loops. There is no return value to
        // assert on — surviving three consecutive calls without
        // panicking is the contract.
        clear_provider_config_full();
        clear_provider_config_full();
        clear_provider_config_full();
    }

    #[test]
    fn test_clear_provider_config_post_success_is_noop() {
        // The post-success path MUST NOT touch `providerConfiguration`
        // or the on-disk state — see doc comment on the function.
        // It is therefore expected to be a no-op. The test just pins
        // that it is callable any number of times without panicking
        // and without side effects observable from Rust.
        clear_provider_config_post_success();
        clear_provider_config_post_success();
    }

    #[test]
    fn test_clear_tunnel_temp_files_idempotent() {
        // Same contract as `clear_provider_config_full` above: idempotent
        // best-effort cleanup, no return value to inspect.
        clear_tunnel_temp_files();
        clear_tunnel_temp_files();
    }
}
