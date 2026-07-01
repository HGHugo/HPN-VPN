use tauri::{AppHandle, State};
use tracing::{info, warn};

use crate::error::{AppError, CommandError};
use crate::state::{ConnectionStats, ConnectionStatus, LogLevel};

use super::AppStateRef;

pub async fn disconnect(app: AppHandle, state: State<'_, AppStateRef>) -> Result<(), CommandError> {
    {
        let state_guard = state.read();
        if state_guard.status != ConnectionStatus::Connected
            && state_guard.status != ConnectionStatus::Reconnecting
        {
            return Err(CommandError::from(AppError::NotConnected));
        }
    }

    {
        let mut state_guard = state.write();
        state_guard.status = ConnectionStatus::Disconnecting;
        state_guard.add_log(LogLevel::Info, "Disconnecting...");
    }
    super::update_tray_status(&app, ConnectionStatus::Disconnecting);

    // Stop in background thread to avoid blocking the Tauri command.
    let state_clone = state.inner().clone();
    let app_clone = app.clone();
    std::thread::spawn(move || {
        match crate::native_vpn::stop_vpn() {
            Ok(()) => info!("VPN tunnel stopped"),
            Err(e) => warn!("VPN stop error: {}", e),
        }
        super::clear_provider_config_full();
        {
            let mut state_guard = state_clone.write();
            state_guard.set_disconnected(Some("User requested"));
        }
        super::update_tray_status(&app_clone, ConnectionStatus::Disconnected);
    });

    Ok(())
}

pub fn get_status(state: State<'_, AppStateRef>) -> ConnectionStatus {
    // Return the internal state directly. The background thread in
    // connect_internal updates this when the tunnel connects/disconnects.
    // Polling the native VPN manager here causes deadlocks.
    state.read().status
}

pub fn get_stats(state: State<'_, AppStateRef>) -> ConnectionStats {
    // Read tunnel stats from shared file written by the extension.
    if let Some(tunnel_stats) = read_tunnel_stats() {
        let mut state = state.write();
        state.update_uptime();
        state.stats.tx = tunnel_stats.tx;
        state.stats.rx = tunnel_stats.rx;
        // Calculate transfer rate (bytes per second).
        let total = tunnel_stats.tx + tunnel_stats.rx;
        let uptime = state.stats.uptime;
        if uptime > 0 {
            state.stats.rate = total / uptime;
        }
        // RTT in milliseconds.
        state.stats.rtt = tunnel_stats.rtt_us / 1000;
        // Session key from extension (updates on rekey).
        if let Some(ref key) = tunnel_stats.session_key
            && !key.is_empty()
        {
            state.stats.session_id = key.clone();
        }
        state.stats.clone()
    } else {
        let mut state = state.write();
        state.update_uptime();
        state.stats.clone()
    }
}

#[derive(serde::Deserialize)]
struct TunnelStats {
    tx: u64,
    rx: u64,
    #[serde(default)]
    rtt_us: u64,
    #[serde(default)]
    session_key: Option<String>,
}

/// Get the real user home directory, bypassing App Sandbox container remapping.
/// Under sandbox, dirs::home_dir() returns ~/Library/Containers/<bundle-id>/Data
/// but the Group Container is at the real ~/Library/Group Containers/.
pub(crate) fn real_user_home() -> std::path::PathBuf {
    // NSHomeDirectoryForUser(nil) is sandboxed, but we can read /etc/passwd
    // or parse the container path to get the real home.
    if let Some(home) = dirs::home_dir() {
        let home_str = home.to_string_lossy();
        // If sandboxed, path looks like /Users/<name>/Library/Containers/<id>/Data
        if let Some(pos) = home_str.find("/Library/Containers/") {
            return std::path::PathBuf::from(&home_str[..pos]);
        }
        return home;
    }
    std::path::PathBuf::from("/Users/admin")
}

fn read_tunnel_stats() -> Option<TunnelStats> {
    // Read the most recent stats from the in-process cache. The
    // cache is kept fresh by the background poller spawned in
    // `main.rs::setup`, which calls
    // `native_vpn::get_tunnel_stats_json` (the synchronous FFI
    // path that round-trips through `sendProviderMessage` to the
    // Packet Tunnel Extension) every ~1 s and writes the JSON
    // bytes into the cache.
    //
    // CRITICAL: this function MUST NOT call the FFI directly. The
    // Tauri command `get_stats` is invoked on a Tauri worker
    // thread at ~1 Hz from the React UI, and the FFI takes
    // 100-300 ms per call (loadAllFromPreferences + XPC
    // round-trip) — blocking that long every second produces a
    // visibly-stuttering UI. Going through the cache returns
    // instantly.
    if let Some(bytes) = crate::native_vpn::read_stats_cache()
        && let Ok(stats) = serde_json::from_slice::<TunnelStats>(&bytes)
    {
        return Some(stats);
    }

    // File-based fallback. Retained for two reasons:
    //   1. Forensic / diagnostic — operators can still inspect a
    //      stale stats file in the App Group container if it ever
    //      gets written (it doesn't on Tahoe; might in future macOS
    //      releases or non-systemextension builds).
    //   2. Future-proofing for a hypothetical CLI build (no
    //      NETunnelProviderManager session available) where the only
    //      readable surface is the file system.
    // On healthy Tahoe builds this branch never produces data; the
    // primary cache+XPC path always succeeds once the poller has
    // run at least once after connect.
    let home = real_user_home();
    let group_path = home.join("Library/Group Containers/group.io.hpn.vpn/tunnel-stats.json");
    if let Ok(data) = std::fs::read(&group_path)
        && let Ok(stats) = serde_json::from_slice::<TunnelStats>(&data)
    {
        return Some(stats);
    }

    let app_support_path = home.join("Library/Application Support/hpn-vpn/tunnel-stats.json");
    if let Ok(data) = std::fs::read(&app_support_path)
        && let Ok(stats) = serde_json::from_slice::<TunnelStats>(&data)
    {
        return Some(stats);
    }
    None
}

pub async fn force_rekey(state: State<'_, AppStateRef>) -> Result<(), CommandError> {
    let status = state.read().status;
    if status != ConnectionStatus::Connected {
        return Err(CommandError::from(AppError::NotConnected));
    }

    // Deliver the rekey request synchronously through
    // `NETunnelProviderSession.sendProviderMessage`. The old
    // implementation wrote a `rekey-signal` file in the app-group
    // container and the extension polled it every 2 s — that meant a
    // 0-2 s visible lag between the user's click and the actual key
    // rotation starting. The provider-message path reaches the
    // extension in microseconds and the existing `handleAppMessage`
    // handler flips `REKEY_REQUESTED` atomically.
    if let Err(e) = crate::native_vpn::force_rekey() {
        let mut state = state.write();
        state.add_log(
            LogLevel::Warn,
            format!("Key rotation request failed: {}", e),
        );
        return Err(CommandError::from(AppError::Client(format!(
            "Force rekey failed: {}",
            e
        ))));
    }

    {
        let mut state = state.write();
        state.add_log(LogLevel::Info, "Key rotation requested");
    }

    Ok(())
}
