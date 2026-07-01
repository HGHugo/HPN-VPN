//! Native VPN manager bridge.
//!
//! Calls into the Swift static library (`libHPNVPNManager.a`) linked at build
//! time. The Swift code wraps `NETunnelProviderManager` for Apple-native tunnel
//! lifecycle management.

use std::os::raw::c_char;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use tracing::{debug, error, info};

/// In-process cache for tunnel stats JSON. See
/// [`get_tunnel_stats_json`] for the rationale and TTL.
struct StatsCache {
    last_refresh: Instant,
    last_value: Option<Vec<u8>>,
}

/// Shared single-cell cache. `OnceLock` for lazy init,
/// `Mutex` because the cache mutates on every refresh and
/// the contention window is microseconds (clone a small Vec).
static STATS_CACHE: OnceLock<Mutex<StatsCache>> = OnceLock::new();

unsafe extern "C" {
    fn hpn_vpn_manager_save_config(config_json: *const c_char, config_len: usize) -> i32;
    #[cfg(not(test))]
    fn hpn_vpn_manager_clear_provider_config() -> i32;
    fn hpn_vpn_manager_install_and_start(full_tunnel: i32, allow_lan: i32) -> i32;
    fn hpn_vpn_manager_stop() -> i32;
    fn hpn_vpn_manager_force_rekey() -> i32;
    fn hpn_vpn_manager_get_stats(out_buf: *mut u8, out_buf_len: usize) -> i32;
    /// Returns the current `SystemExtensionStatus` raw value (0..=4).
    /// Used by the UI to disambiguate "approval still pending in
    /// System Settings" from "activation outright failed".
    ///
    /// Currently only invoked via the optional `system_extension_status()`
    /// public helper — the React UI may surface this in a future
    /// "stuck on approval" diagnostic; the FFI is shipped already so
    /// the Swift bridge does not need a second recompile when that
    /// lands.
    #[allow(dead_code)]
    fn hpn_vpn_manager_systemextension_status() -> i32;
}

/// Fetch the latest tunnel stats JSON from the running Packet Tunnel
/// Extension via `NETunnelProviderSession.sendProviderMessage`.
///
/// REPLACES the legacy file-based read of
/// `~/Library/Group Containers/group.io.hpn.vpn/tunnel-stats.json`.
/// On Tahoe Developer ID, the extension runs as root and its file
/// writes land under `/var/root/Library/...` — invisible to the
/// host running as the user. The provider-message channel bypasses
/// the path-resolution mismatch entirely; see the matching
/// host→extension fix in `save_provider_config` doc comment for the
/// architectural symmetry.
///
/// CACHING: the React UI polls `get_stats` aggressively (~1 Hz, and
/// faster during animation transitions). Every miss would fire a
/// `bgQueue.async { sendProviderMessage }` round-trip on the Swift
/// side; `bgQueue` is a serial queue shared with the connect /
/// install / loadAll paths, so a flood of stats requests starves
/// the user-facing buttons (visible as a UI freeze on the
/// HPN VPN.app's status pane). We cache the most recent successful
/// response for 500 ms, which is well below the user's perceptual
/// threshold for stats refresh and effectively bounds the
/// extension-bound XPC traffic to 2 calls/sec regardless of how
/// fast React polls.
///
/// Returns `None` when the tunnel is not running, the extension has
/// not produced stats yet, or the XPC call timed out (250 ms). The
/// caller treats `None` as "render the cached / zero stats" rather
/// than as a fatal error — losing one polling tick of stats is
/// invisible to the user, while propagating a hard error would
/// surface a meaningless toast every second.
pub fn get_tunnel_stats_json() -> Option<Vec<u8>> {
    /// Cache TTL. 500 ms is invisible to a human polling 1 Hz and
    /// caps the XPC round-trips at 2/sec even if the React UI loops
    /// faster (e.g. during a status transition animation).
    const CACHE_TTL: Duration = Duration::from_millis(500);

    let cache = STATS_CACHE.get_or_init(|| {
        Mutex::new(StatsCache {
            // `Instant::now() - 1s` so the very first call after
            // process start does NOT short-circuit and skip the FFI
            // (which would return None on the first render).
            last_refresh: Instant::now()
                .checked_sub(Duration::from_secs(1))
                .unwrap_or_else(Instant::now),
            last_value: None,
        })
    });

    // Fast path: cache hit. The lock guards a tiny critical section
    // (clone the Vec) so contention is negligible even at 100 Hz.
    {
        let entry = cache.lock().expect("CACHE mutex poisoned");
        if entry.last_refresh.elapsed() < CACHE_TTL {
            return entry.last_value.clone();
        }
    }

    // Slow path: cache miss. Issue the XPC call, repopulate the
    // cache. We hold the cache lock ONLY across the cache write,
    // not across the FFI call, so a concurrent caller can still
    // see the previous value while we refresh.
    //
    // 4 KiB matches the host-side cap in
    // `VPNManager.swift::hpn_vpn_manager_get_stats` and is several
    // orders of magnitude above any legitimate stats payload (the
    // current schema is ~200 bytes).
    let mut buf = vec![0u8; 4096];
    // SAFETY: buf has capacity 4096 and Swift writes at most that
    // many bytes (the FFI documents the contract).
    let n = unsafe { hpn_vpn_manager_get_stats(buf.as_mut_ptr(), buf.len()) };

    let new_value = if n > 0 {
        buf.truncate(n as usize);
        Some(buf)
    } else {
        // Negative codes are documented in the Swift FFI; -4
        // (timeout) is the most common when the tunnel is in a
        // transient state. Don't log here — the React UI polls
        // every second and a per-call log line would drown the
        // rest of the diagnostic stream.
        None
    };

    let mut entry = cache.lock().expect("CACHE mutex poisoned");
    entry.last_refresh = Instant::now();
    // Only OVERWRITE the cache on a successful refresh. A transient
    // FFI failure (e.g. -4 timeout during a disconnect/reconnect
    // race) should not blank the UI to zero for 500 ms; let the
    // last good value linger until either we get a fresh one or
    // the user disconnects (which clears the cache via
    // `clear_stats_cache` below).
    if new_value.is_some() {
        entry.last_value.clone_from(&new_value);
    }
    entry.last_value.clone()
}

/// Wipe the stats cache. Called on disconnect so the next get_stats
/// call after a fresh connect doesn't return values from the
/// previous session. Idempotent.
#[allow(dead_code)]
pub fn clear_stats_cache() {
    // The cache may not yet be initialised on the very first
    // disconnect (no get_stats call ever happened) — in that case
    // there is nothing to clear.
    if let Some(cache) = STATS_CACHE.get() {
        let mut entry = cache.lock().expect("STATS_CACHE mutex poisoned");
        entry.last_value = None;
    }
}

/// Read the most recent cached stats JSON without ever touching the
/// FFI.
///
/// This is the path the React UI's `get_stats` command takes: it
/// runs once per ~1 s on a Tauri command thread and MUST return
/// instantly so the UI doesn't visibly hiccup. The cache is kept
/// fresh by the background poller spawned in `main.rs::setup`,
/// which calls [`get_tunnel_stats_json`] (the FFI path) every
/// second and updates this same cache.
///
/// Returns `None` until the poller has populated the cache for the
/// first time (typically <2 s after app start) and after a
/// disconnect that calls [`clear_stats_cache`].
pub fn read_stats_cache() -> Option<Vec<u8>> {
    let cache = STATS_CACHE.get()?;
    let entry = cache.lock().ok()?;
    entry.last_value.clone()
}

/// Read the current System Extension activation status (raw integer).
///
/// 0 = unknown, 1 = activated, 2 = will activate on reboot,
/// 3 = user approval required (System Settings prompt visible),
/// 4 = failed.
#[allow(dead_code)]
pub fn system_extension_status() -> i32 {
    // SAFETY: no arguments; Swift-side returns a plain Int32.
    unsafe { hpn_vpn_manager_systemextension_status() }
}

/// Hand the provider configuration JSON to the Swift bridge for
/// delivery via `NETunnelProviderProtocol.providerConfiguration`.
///
/// REVISED ARCHITECTURE (May 2026 field investigation):
///
/// We send RAW JSON (not the audit-H15 HMAC envelope) on this path.
/// The historical envelope was designed for the legacy file-based
/// handoff, where the Packet Tunnel Provider read the JSON from the
/// App Group container and needed an HMAC to detect tampering by any
/// process in the same App Group.
///
/// On Tahoe Developer ID, the legacy file-based path is unusable:
///   1. The Packet Tunnel runs as a `.systemextension` in `root`
///      context and cannot access the host's user-context Keychain
///      (returns `errSecNotAvailable -25291` regardless of
///      `kSecUseDataProtectionKeychain` or `keychain-access-groups`).
///      Without Keychain access there is no way to share the HMAC
///      master key between host and extension.
///   2. `FileManager.containerURL(forSecurityApplicationGroupIdentifier:)`
///      resolves to different paths in the host (uid 501) vs the
///      extension (uid 0), so the file the host writes is not the
///      file the extension reads.
///
/// `providerConfiguration` (an NSDictionary delivered through Apple's
/// XPC channel and persisted in `/Library/Preferences/
/// com.apple.networkextension.plist`, root-only readable) IS the
/// supported IPC channel for `.systemextension` packet tunnels. It
/// is the same backend Apple uses for IKEv2/L2TP shared-secrets, so
/// trusting it for our credentials matches the trust boundary of
/// the OS's own VPN stack. The XPC delivery is system-managed; a
/// rogue process cannot inject crafted bytes here without already
/// being able to spoof the host app entirely. The HMAC envelope
/// would only add value if BOTH sides could share a key, which they
/// can't on Tahoe — so we drop the wrap on this hot path.
///
/// The audit-H15 envelope code (`hpn_core::provider_envelope::wrap`
/// and the matching unwrap FFI) is RETAINED in the workspace because
/// other platforms (Windows wintun setup) and other future IPC
/// surfaces may still want it; only the macOS host↔extension hop is
/// changed here.
pub fn save_provider_config(config_json: &str) -> Result<(), String> {
    // SAFETY: ptr+len describe a valid borrow of `config_json`'s
    // backing buffer, valid for the duration of this FFI call.
    let result = unsafe {
        hpn_vpn_manager_save_config(config_json.as_ptr() as *const c_char, config_json.len())
    };

    if result == 0 {
        debug!(
            "Provider config staged for providerConfiguration IPC ({} bytes raw JSON)",
            config_json.len()
        );
        Ok(())
    } else {
        let msg = format!(
            "Failed to stage provider config (code {}, len {})",
            result,
            config_json.len()
        );
        error!("{}", msg);
        Err(msg)
    }
}

/// Clear staged and persisted providerConfiguration credentials.
pub fn clear_provider_configuration() -> Result<(), String> {
    #[cfg(test)]
    {
        debug!("Skipping NetworkExtension providerConfiguration clear in unit tests");
        Ok(())
    }

    #[cfg(not(test))]
    {
        let result = unsafe { hpn_vpn_manager_clear_provider_config() };
        if result == 0 {
            debug!("Provider configuration cleared from NetworkExtension preferences");
            Ok(())
        } else {
            let msg = format!("Failed to clear provider configuration (code {})", result);
            tracing::warn!("{}", msg);
            Err(msg)
        }
    }
}

/// Install/start the VPN tunnel via `NETunnelProviderManager`.
///
/// Parameters mirror the profile's routing configuration so the
/// network-extension-level kill switch and the in-extension routing
/// agree. See `VPNManager.swift::hpnVpnManagerInstallAndStart` for the
/// full Apple-docs derivation; the short version:
///
/// * `full_tunnel = true` →
///   `includeAllNetworks=true`, `enforceRoutes=false`,
///   `excludeLocalNetworks=allow_lan`. Apple routes everything through
///   the VPN except its hard-coded "designated system services" and
///   (when allow_lan) RFC1918.
/// * `full_tunnel = false` →
///   `includeAllNetworks=false`, `enforceRoutes=true`,
///   `excludeLocalNetworks=allow_lan`. Apple strictly enforces the
///   in-extension `includedRoutes` / `excludedRoutes`
///   (NEPacketTunnelNetworkSettings), superseding the system routing
///   table and app-level interface scoping. This is what gives bypass
///   / split-tunnel mode an actual kill switch.
///
/// `allow_lan` is the user-facing "local network bypass" toggle:
/// `true` means LAN traffic stays on the LAN (faster + reachable),
/// `false` means LAN traffic also gets pulled into the tunnel.
pub fn install_and_start_vpn(full_tunnel: bool, allow_lan: bool) -> Result<(), String> {
    info!(
        "Starting VPN tunnel via NETunnelProviderManager (full_tunnel={}, allow_lan={})",
        full_tunnel, allow_lan
    );
    let result =
        unsafe { hpn_vpn_manager_install_and_start(i32::from(full_tunnel), i32::from(allow_lan)) };

    if result == 0 {
        info!("VPN tunnel start requested successfully");
        Ok(())
    } else {
        let msg = match result {
            -10 => "Failed to load VPN preferences".to_string(),
            -11 => "Failed to save VPN preferences (user may have denied permission)".to_string(),
            -12 => "Failed to reload VPN preferences after save".to_string(),
            -13 => "Failed to start VPN tunnel".to_string(),
            -14 => "macOS 14.0 or later is required (kill switch uses NetworkExtension \
                    `includeAllNetworks` available since macOS 14). Please update your system."
                .to_string(),
            -15 => "System Extension activation failed. Open System Settings → \
                    Privacy & Security and check for any blocked HPN VPN extension. \
                    If none is shown, try reinstalling the app."
                .to_string(),
            -16 => "Approval required for the HPN VPN System Extension. \
                    Open System Settings → Privacy & Security and click Allow next \
                    to the HPN VPN entry, then click Connect again."
                .to_string(),
            -17 => "The HPN VPN System Extension was approved but a reboot is required \
                    to finish activation. Please restart your Mac and try again."
                .to_string(),
            -18 => "Internal error: provider configuration was not stashed before \
                    install_and_start. The connect flow skipped save_provider_config or \
                    the call failed silently. Please retry; if the error persists, the \
                    profile may be corrupted."
                .to_string(),
            _ => format!("VPN manager error (code {})", result),
        };
        error!("{}", msg);
        Err(msg)
    }
}

/// Stop the VPN tunnel.
pub fn stop_vpn() -> Result<(), String> {
    info!("Stopping VPN tunnel");
    let result = unsafe { hpn_vpn_manager_stop() };

    if result == 0 {
        Ok(())
    } else {
        Err(format!("Failed to stop VPN (code {})", result))
    }
}

/// Request an immediate rekey of the active VPN session.
///
/// Uses `NETunnelProviderSession.sendProviderMessage` under the hood,
/// which hits the running Packet Tunnel Extension in microseconds —
/// compared with the previous file-polled scheme where the extension
/// only noticed the request on its 2-second poll. Callers that write a
/// `rekey-signal` file should migrate to this function.
///
/// Returns `Ok(())` when the message was delivered (not when the rekey
/// itself completes; that happens asynchronously on the next keepalive
/// tick inside the extension). A non-running tunnel returns `Err`.
pub fn force_rekey() -> Result<(), String> {
    info!("Requesting immediate rekey via provider message");
    let result = unsafe { hpn_vpn_manager_force_rekey() };

    if result == 0 {
        Ok(())
    } else {
        let msg = match result {
            -20 => "No active VPN session (tunnel not running)".to_string(),
            -21 => "sendProviderMessage failed (extension may be stuck)".to_string(),
            _ => format!("Force rekey failed (code {})", result),
        };
        error!("{}", msg);
        Err(msg)
    }
}
