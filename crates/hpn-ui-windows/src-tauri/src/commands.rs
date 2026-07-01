//! Tauri command handlers.
//!
//! These commands are invoked from the React frontend via Tauri's IPC.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use tauri::State;
use tokio::sync::Mutex as TokioMutex;

#[cfg(windows)]
use tracing::{debug, error, info, warn};

#[cfg(windows)]
use std::net::SocketAddr;
#[cfg(windows)]
use tauri::{AppHandle, Manager};
#[cfg(windows)]
use tauri_plugin_notification::NotificationExt;
#[cfg(windows)]
use tokio::sync::mpsc;

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

/// RAII guard that tears down the bootstrap `HPN_VPN_IPv6_Block` firewall
/// rule on drop, unless explicitly disarmed.
///
/// The bootstrap rule is installed before the handshake to close the
/// IPv6-leak window during the setup phase. Once the normal ownership
/// chain has been established (RouteManager takes it over in
/// `setup_full_tunnel` / `setup_bypass_tunnel`, OR we deliberately
/// remove it on failure), the guard must be disarmed. If code unwinds
/// via panic between install and disarm, the guard fires and leaves
/// the user's IPv6 connectivity intact.
///
/// `RecoveryState::perform_recovery_with_state` also cleans up on next
/// start-up, but that is at-least-15-seconds later. This guard fires
/// in-process, which is what the user feels.
#[cfg(windows)]
struct BootstrapIpv6BlockGuard {
    armed: bool,
}

#[cfg(windows)]
impl BootstrapIpv6BlockGuard {
    /// Construct a disarmed guard. `arm` must be called after a
    /// successful `RouteManager::install_bootstrap_ipv6_block`.
    fn disarmed() -> Self {
        Self { armed: false }
    }

    fn arm(&mut self) {
        self.armed = true;
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(windows)]
impl Drop for BootstrapIpv6BlockGuard {
    fn drop(&mut self) {
        if self.armed {
            if let Err(e) =
                hpn_client_windows::routing::RouteManager::remove_stale_ipv6_block_rule()
            {
                tracing::warn!(
                    "BootstrapIpv6BlockGuard: failed to remove bootstrap IPv6 block \
                     during panic cleanup: {}",
                    e
                );
            } else {
                tracing::debug!(
                    "BootstrapIpv6BlockGuard: bootstrap IPv6 block removed during panic cleanup"
                );
            }
        }
    }
}

/// RAII guard that mirrors `BootstrapIpv6BlockGuard` for the IPv4 setup-
/// window kill switch.
///
/// The bootstrap IPv4 block (see
/// [`RouteManager::install_bootstrap_ipv4_block`]) drops every outbound
/// IPv4 packet that is not destined to the VPN server (or loopback). If
/// we panic between install and successful tunnel setup, the user is
/// left with no IPv4 connectivity at all. This guard makes the worst
/// case "no IPv4 for a few hundred milliseconds during cleanup" instead
/// of "no IPv4 until reboot".
///
/// Disarmed once the regular `setup_full_tunnel` /
/// `setup_bypass_tunnel` path has taken ownership of the kill switch
/// (those functions remove the bootstrap rules at their start).
#[cfg(windows)]
struct BootstrapIpv4BlockGuard {
    armed: bool,
}

#[cfg(windows)]
impl BootstrapIpv4BlockGuard {
    fn disarmed() -> Self {
        Self { armed: false }
    }

    fn arm(&mut self) {
        self.armed = true;
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(windows)]
impl Drop for BootstrapIpv4BlockGuard {
    fn drop(&mut self) {
        if self.armed {
            if let Err(e) =
                hpn_client_windows::routing::RouteManager::remove_stale_ipv4_bootstrap_rules()
            {
                tracing::warn!(
                    "BootstrapIpv4BlockGuard: failed to remove bootstrap IPv4 rules \
                     during panic cleanup: {}",
                    e
                );
            } else {
                tracing::debug!(
                    "BootstrapIpv4BlockGuard: bootstrap IPv4 rules removed during panic cleanup"
                );
            }
        }
    }
}

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

#[cfg(windows)]
use hpn_client_core::TunnelDevice;
#[cfg(windows)]
use hpn_client_core::client::{ClientEvent, VpnClient};
#[cfg(windows)]
use hpn_client_core::config::{ClientConfig, Credentials};
#[cfg(windows)]
use hpn_client_core::connection::UdpConnection;
#[cfg(windows)]
use hpn_client_core::kill_switch::{DisconnectReason, KillSwitchManager, KillSwitchMode};
#[cfg(windows)]
use hpn_core::types::MessageType;

#[cfg(windows)]
use hpn_client_windows::adapter::WintunAdapter;
#[cfg(windows)]
use hpn_client_windows::routing::{DnsLeakProtection, Ipv6LeakProtection, RouteManager};

use crate::error::{AppError, CommandError};

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

/// Maximum packet size for buffer pool.
/// VPN MTU is 1420, but we allow for jumbo frames and protocol overhead.
/// 2048 bytes is sufficient for any realistic VPN packet.
#[cfg(windows)]
const MAX_PACKET_SIZE: usize = 2048;

/// A buffer borrowed from the pool that auto-returns on drop.
#[cfg(windows)]
pub struct PooledBuffer {
    data: Vec<u8>,
    len: usize,
    pool: Arc<BufferPool>,
}

#[cfg(windows)]
impl PooledBuffer {
    /// Set the length of valid data in the buffer.
    #[inline]
    pub fn set_len(&mut self, len: usize) {
        self.len = len;
    }

    /// Get a mutable slice to write into.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

#[cfg(windows)]
impl std::ops::Deref for PooledBuffer {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

#[cfg(windows)]
impl Drop for PooledBuffer {
    fn drop(&mut self) {
        // Return buffer to pool (take ownership with mem::take)
        let buf = std::mem::take(&mut self.data);
        if !buf.is_empty() {
            self.pool.return_buffer(buf);
        }
    }
}

/// High-performance buffer pool for zero-copy packet processing.
#[cfg(windows)]
pub struct BufferPool {
    buffers: parking_lot::Mutex<Vec<Vec<u8>>>,
    buffer_size: usize,
    max_pool_size: usize,
}

#[cfg(windows)]
impl BufferPool {
    /// Create a new buffer pool with pre-allocated buffers.
    /// `max_pool_size` caps the pool to prevent unbounded memory growth.
    pub fn new(initial_size: usize, buffer_size: usize) -> Self {
        let max_pool_size = initial_size.max(4096);
        let mut buffers = Vec::with_capacity(initial_size);
        for _ in 0..initial_size {
            buffers.push(vec![0u8; buffer_size]);
        }
        Self {
            buffers: parking_lot::Mutex::new(buffers),
            buffer_size,
            max_pool_size,
        }
    }

    /// Get a buffer from the pool (allocates if empty).
    #[inline]
    pub fn get(self: &Arc<Self>) -> PooledBuffer {
        let data = self
            .buffers
            .lock()
            .pop()
            .unwrap_or_else(|| vec![0u8; self.buffer_size]);
        PooledBuffer {
            data,
            len: 0,
            pool: Arc::clone(self),
        }
    }

    /// Return a buffer to the pool. Drops the buffer if the pool is at max capacity.
    #[inline]
    fn return_buffer(&self, buf: Vec<u8>) {
        let mut pool = self.buffers.lock();
        if pool.len() < self.max_pool_size {
            pool.push(buf);
        }
        // else: drop the buffer to prevent unbounded growth.
    }
}

/// Update the system tray icon and tooltip based on connection status.
#[cfg(windows)]
fn update_tray_status(app: &AppHandle, status: ConnectionStatus) {
    // Get the tray icon and update tooltip
    if let Some(tray) = app.tray_by_id("main") {
        let tooltip = match status {
            ConnectionStatus::Connected => "HPN VPN - Connected",
            ConnectionStatus::Connecting => "HPN VPN - Connecting...",
            ConnectionStatus::Disconnecting => "HPN VPN - Disconnecting...",
            ConnectionStatus::Reconnecting => "HPN VPN - Reconnecting...",
            ConnectionStatus::Disconnected => "HPN VPN - Disconnected",
            ConnectionStatus::Error => "HPN VPN - Error",
        };
        let _ = tray.set_tooltip(Some(tooltip));
    }

    // Update menu item text
    if let Some(menu) = app.menu().as_ref().and_then(|m| m.get("status")) {
        if let Some(item) = menu.as_menuitem() {
            let text = match status {
                ConnectionStatus::Connected => "Status: Connected",
                ConnectionStatus::Connecting => "Status: Connecting...",
                ConnectionStatus::Disconnecting => "Status: Disconnecting...",
                ConnectionStatus::Reconnecting => "Status: Reconnecting...",
                ConnectionStatus::Disconnected => "Status: Disconnected",
                ConnectionStatus::Error => "Status: Error",
            };
            let _ = item.set_text(text);
        }
    }
}

use crate::config::{Profile, Settings};
use crate::state::{AppState, ConnectionStats, ConnectionStatus, LogEntry, LogLevel};
use crate::validation::{
    validate_port, validate_profile_id, validate_profile_name, validate_public_key,
    validate_server_address,
};

type AppStateRef = Arc<RwLock<AppState>>;

/// Mutex to prevent concurrent connect calls.
/// This ensures only one connect operation can run at a time.
pub type ConnectMutex = TokioMutex<()>;

#[cfg(windows)]
/// Adapter name for the VPN tunnel.
const ADAPTER_NAME: &str = "HPN Tunnel";
#[cfg(windows)]
/// Default MTU for the VPN tunnel.
const DEFAULT_MTU: u16 = 1420;

/// SHA-256 of the bundled Wintun DLL, embedded at build time by `build.rs`.
///
/// Empty string when the file at `resources/wintun.dll` was missing or empty
/// at build time (typical on developer machines that haven't fetched the
/// DLL yet). The runtime loader treats `""` as "skip verification, log a
/// loud warning" so local dev builds still work; release CI builds always
/// have a real hash because the pipeline fetches the official Wintun ZIP
/// before invoking `cargo tauri build` (see `.gitlab-ci.yml`).
#[cfg_attr(not(windows), allow(dead_code))]
const EMBEDDED_WINTUN_SHA256: &str = env!("HPN_WINTUN_SHA256");

// Defence-in-depth: refuse to ship a release build with an empty embedded
// hash. The runtime path treats `""` as "skip verification" so a misconfigured
// CI (cache miss, broken Wintun download, etc.) could otherwise produce a
// signed release artefact that silently disables the check. This compile-time
// assertion turns that scenario into a hard build error on release builds
// (`debug_assertions` is enabled for `cargo build` and `cargo run` but
// disabled by `cargo build --release`, which is what `cargo tauri build`
// uses for the bundled installer).
#[cfg(all(windows, not(debug_assertions)))]
const _: () = {
    if EMBEDDED_WINTUN_SHA256.is_empty() {
        panic!(
            "EMBEDDED_WINTUN_SHA256 is empty in a release build. \
             The CI pipeline must download resources/wintun.dll BEFORE \
             building. Refusing to ship without runtime integrity verification."
        );
    }
};

/// Verify the integrity of a Wintun DLL on disk against the SHA-256 hash
/// embedded into the binary at build time.
///
/// # Threat model
///
/// HPN runs as `requireAdministrator` on Windows. An attacker that can
/// write to the install directory (Program Files, after a UAC bypass or
/// privilege escalation; user-level for portable installs) can drop a
/// malicious `wintun.dll` and have it loaded with admin rights when the
/// user clicks Connect. That is a complete tunnel-bypass / RCE chain.
///
/// The hash is baked in at build time and the executable is signed with
/// Azure Trusted Signing, so the value cannot be modified without
/// invalidating the signature. The check therefore terminates the chain
/// at "DLL on disk does not match what the signed binary expects".
///
/// Returns `Ok(())` on match, `Err(reason)` on mismatch or read failure.
/// In dev/local builds where `EMBEDDED_WINTUN_SHA256` is empty (i.e. the
/// resource was a placeholder) we return `Ok(())` after logging a loud
/// warning — this keeps `cargo run` working on engineer laptops without
/// downgrading the security of CI-built release artefacts.
#[cfg(windows)]
fn verify_wintun_dll(path: &std::path::Path) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    if EMBEDDED_WINTUN_SHA256.is_empty() {
        tracing::warn!(
            "Wintun integrity verification disabled at build time (empty embedded hash). \
             Release builds must NEVER ship with this state."
        );
        return Ok(());
    }

    let mut file = std::fs::File::open(path)
        .map_err(|e| format!("cannot open {} for hashing: {}", path.display(), e))?;
    let mut buf = [0u8; 64 * 1024];
    let mut hasher = Sha256::new();
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("read {} failed: {}", path.display(), e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for b in digest.iter() {
        hex.push_str(&format!("{:02x}", b));
    }
    if !hex.eq_ignore_ascii_case(EMBEDDED_WINTUN_SHA256) {
        return Err(format!(
            "wintun.dll integrity check failed: expected sha256 {}, got {}. \
             Refusing to load — possible tampering.",
            EMBEDDED_WINTUN_SHA256, hex
        ));
    }
    Ok(())
}

#[cfg(windows)]
/// Locate `wintun.dll`, canonicalise its path, and verify the SHA-256 of
/// the file on disk against the value embedded at build time.
///
/// Search order:
/// 1. Tauri resource directory (installed app — under Program Files,
///    protected by Authenticode chain).
/// 2. Directory containing the executable (portable launches).
///
/// Note: the previous version of this function also searched the current
/// working directory. That fallback was removed (audit BUN-2) because a
/// `.lnk` shortcut launching HPN from an attacker-controlled folder
/// would have made it trivial to deliver a malicious wintun.dll there.
/// With the integrity check now in place the third location is no longer
/// useful even with a hash check — it only widens the attack surface.
///
/// We `canonicalize()` each candidate before reading it for the SHA-256
/// check AND return that same canonical path to the caller. This shrinks
/// the TOCTOU window between hash check and `LoadLibraryW`: both
/// operations resolve the same physical file because `LoadLibraryW`
/// receives the canonical NT path, not a path containing reparse points
/// or junctions that an attacker could repoint between the two reads.
/// A determined attacker who can write to the install directory can
/// still race the file content itself; closing that gap requires
/// holding an exclusive `CreateFileW` handle across the hash + load,
/// which is tracked separately (relay audit M-8 equivalent).
fn find_wintun_dll(app: &AppHandle) -> Option<std::path::PathBuf> {
    let dll_name = "wintun.dll";

    let mut candidates = Vec::new();

    if let Ok(resource_dir) = app.path().resource_dir() {
        candidates.push(resource_dir.join(dll_name));
    }
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            candidates.push(exe_dir.join(dll_name));
        }
    }

    for raw_path in candidates {
        debug!("Checking wintun.dll candidate: {}", raw_path.display());
        if !raw_path.exists() {
            continue;
        }
        // Resolve symlinks/junctions/reparse points BEFORE hashing so the
        // path we hash is the same path Windows will resolve when calling
        // LoadLibraryW. Without canonicalisation an attacker who controls
        // a reparse point in the resource directory could make the hash
        // check read one file and `LoadLibraryW` load another.
        let canonical = match std::fs::canonicalize(&raw_path) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(
                    "Refusing to load {}: canonicalize failed ({})",
                    raw_path.display(),
                    e
                );
                return None;
            }
        };
        match verify_wintun_dll(&canonical) {
            Ok(()) => return Some(canonical),
            Err(reason) => {
                // We deliberately do NOT fall through to the next
                // candidate on mismatch: an attacker who has tampered
                // with one location is just as likely to have tampered
                // with the next. Returning `None` makes the caller
                // surface a clean "wintun.dll not available" error to
                // the user, who can then escalate or reinstall.
                tracing::error!("Refusing to load {}: {}", canonical.display(), reason);
                return None;
            }
        }
    }

    None
}

// ============================================================================
// Connection Commands
// ============================================================================

/// Connect to a VPN profile (stub for non-Windows).
#[cfg(not(windows))]
#[tauri::command]
pub async fn connect(
    state: State<'_, AppStateRef>,
    _connect_mutex: State<'_, ConnectMutex>,
    profile_id: String,
) -> Result<(), CommandError> {
    // Check rate limit to prevent rapid reconnection attempts
    check_connect_rate_limit().map_err(|e| CommandError::from(AppError::Connection(e)))?;

    // Validate profile_id even on non-Windows to maintain consistent behavior
    validate_profile_id(&profile_id).map_err(|e| CommandError::from(AppError::Config(e)))?;

    let mut state = state.write();
    state.add_log(
        LogLevel::Error,
        "Windows VPN client not available on this platform",
    );
    Err(CommandError::from(AppError::InvalidState(
        "This VPN client only runs on Windows".to_string(),
    )))
}

/// Connect to a VPN profile with authentication (stub for non-Windows).
#[cfg(not(windows))]
#[tauri::command]
pub async fn connect_with_auth(
    state: State<'_, AppStateRef>,
    _connect_mutex: State<'_, ConnectMutex>,
    profile_id: String,
    _username: String,
    _password: String,
) -> Result<(), CommandError> {
    // Check rate limit to prevent rapid reconnection attempts
    check_connect_rate_limit().map_err(|e| CommandError::from(AppError::Connection(e)))?;

    // Validate profile_id even on non-Windows to maintain consistent behavior
    validate_profile_id(&profile_id).map_err(|e| CommandError::from(AppError::Config(e)))?;

    let mut state = state.write();
    state.add_log(
        LogLevel::Error,
        "Windows VPN client not available on this platform",
    );
    Err(CommandError::from(AppError::InvalidState(
        "This VPN client only runs on Windows".to_string(),
    )))
}

/// Connect to a VPN profile (without authentication).
///
/// For profiles that require authentication, use `connect_with_auth` instead.
#[cfg(windows)]
#[tauri::command]
pub async fn connect(
    app: AppHandle,
    state: State<'_, AppStateRef>,
    connect_mutex: State<'_, ConnectMutex>,
    profile_id: String,
) -> Result<(), CommandError> {
    // Check rate limit to prevent rapid reconnection attempts
    check_connect_rate_limit().map_err(|e| CommandError::from(AppError::Connection(e)))?;

    // Validate profile_id before any operations
    validate_profile_id(&profile_id).map_err(|e| CommandError::from(AppError::Config(e)))?;

    debug!("connect() called with profile_id: {}", profile_id);

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
#[cfg(windows)]
#[tauri::command]
pub async fn connect_with_auth(
    app: AppHandle,
    state: State<'_, AppStateRef>,
    connect_mutex: State<'_, ConnectMutex>,
    profile_id: String,
    username: String,
    password: String,
) -> Result<(), CommandError> {
    // Wrap the password in `Zeroizing` immediately so the heap memory is
    // wiped at the latest when this function returns, even on the early
    // failure paths below. Tauri's IPC layer hands us a plain `String`
    // (the command macro reads it via serde-deserialize from the JS
    // payload); without this wrap, the bytes linger in the allocator
    // until they happen to be overwritten by a future allocation.
    let password = zeroize::Zeroizing::new(password);

    // Check rate limit to prevent rapid reconnection attempts
    check_connect_rate_limit().map_err(|e| CommandError::from(AppError::Connection(e)))?;

    // Validate profile_id before any operations
    validate_profile_id(&profile_id).map_err(|e| CommandError::from(AppError::Config(e)))?;

    debug!("connect_with_auth() called with profile_id: {}", profile_id);

    // Create credentials from provided username/password.
    // `with_zeroizing_password` consumes the wrapper so we never make
    // an extra plaintext copy via `.to_string()`.
    let credentials = Credentials::with_zeroizing_password(username, password);

    // Validate credentials format
    credentials
        .validate()
        .map_err(|e| CommandError::from(AppError::Config(e.to_string())))?;

    // Call internal connect function with credentials
    connect_internal(app, state, connect_mutex, profile_id, Some(credentials))
        .await
        .map_err(|e| CommandError::from(AppError::Connection(e)))
}

/// Internal connect implementation shared by `connect` and `connect_with_auth`.
///
/// This function contains all the VPN connection logic and is called by both
/// the regular connect (without credentials) and connect_with_auth (with credentials).
#[cfg(windows)]
async fn connect_internal(
    app: AppHandle,
    state: State<'_, AppStateRef>,
    connect_mutex: State<'_, ConnectMutex>,
    profile_id: String,
    credentials: Option<Credentials>,
) -> Result<(), String> {
    // Use atomic compare-and-swap to ensure only one connect runs at a time.
    // This flag stays TRUE until the connection reaches a terminal state
    // (Connected, Disconnected, Error) - NOT when this function returns.
    if CONNECT_IN_PROGRESS
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        debug!("connect_internal() BLOCKED: another connect already in progress");
        return Err("Connection already in progress".to_string());
    }
    debug!("connect_internal() acquired CONNECT_IN_PROGRESS lock");

    // Also try the Tauri mutex as secondary protection
    let _connect_guard = match connect_mutex.inner().try_lock() {
        Ok(guard) => guard,
        Err(_) => {
            debug!("connect_internal() mutex already held, returning error");
            // Reset flag since we're returning an error
            reset_connect_in_progress();
            return Err("Connection already in progress".to_string());
        }
    };

    // Now we have exclusive access to the connect operation (mutex acquired).
    // Get profile and settings, then set status to Connecting.
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

        // Force status to Connecting regardless of previous state
        // The mutex ensures only one connect() runs at a time
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
    // Update tray to show connecting
    update_tray_status(&app, ConnectionStatus::Connecting);

    // Validate profile data before using it
    if let Err(e) = validate_server_address(&profile.server) {
        let mut state = state.write();
        state.status = ConnectionStatus::Error;
        state.add_log(LogLevel::Error, format!("Invalid server: {}", e));
        reset_connect_in_progress();
        return Err(e);
    }

    if let Err(e) = validate_port(profile.port) {
        let mut state = state.write();
        state.status = ConnectionStatus::Error;
        state.add_log(LogLevel::Error, format!("Invalid port: {}", e));
        reset_connect_in_progress();
        return Err(e);
    }

    // Parse server address
    let server_addr: SocketAddr = format!("{}:{}", profile.server, profile.port)
        .parse()
        .map_err(|e| {
            let mut state = state.write();
            state.status = ConnectionStatus::Error;
            state.add_log(LogLevel::Error, format!("Invalid server address: {}", e));
            reset_connect_in_progress();
            format!("Invalid server address: {}", e)
        })?;

    // Build client config with security level from profile
    let security_level = profile.security_level.to_core_level();
    let config = ClientConfig {
        server_addr,
        server_public_key: profile.server_public_key.clone(),
        server_kem_public_key: profile.server_kem_public_key.clone(),
        keepalive_interval_secs: settings.keepalive_interval,
        connection_timeout_secs: settings.connection_timeout,
        auto_reconnect: settings.auto_reconnect,
        security_level,
        ..Default::default()
    };

    // Create VPN client
    let (client, mut event_rx) = match VpnClient::new(config) {
        Ok(c) => c,
        Err(e) => {
            let mut state = state.write();
            state.status = ConnectionStatus::Error;
            state.add_log(LogLevel::Error, format!("Failed to create client: {}", e));
            reset_connect_in_progress();
            return Err(e.to_string());
        }
    };

    // Bootstrap IPv6 egress block BEFORE the first UDP packet leaves the
    // client.
    //
    // Between the moment the user clicks "Connect" and the moment the
    // Wintun adapter is up with all routes installed, Windows keeps
    // serving IPv6 natively through the physical interface. During that
    // ~1-3 s window, DNS queries, already-established IPv6 connections
    // and new AAAA-only flows all leak clear. The full-tunnel /
    // bypass-tunnel setup later calls `enable_ipv6_leak_protection()`
    // which installs the same firewall rule — but by then the leak has
    // already happened.
    //
    // So we install the same `HPN_VPN_IPv6_Block` rule preemptively
    // when ALL of the following hold:
    //   1. the user has enabled the kill switch in settings, AND
    //   2. the server endpoint itself is IPv4.
    //
    // Condition (2) is critical: if the server address is an IPv6
    // literal (or an AAAA-only host), the very handshake UDP packets
    // would be blocked by our own rule and the connection fails
    // silently — the exact DoS we were trying to avoid. When the server
    // is IPv6-reachable we rely on the later
    // `setup_full_tunnel_v6` / `setup_bypass_tunnel` path to install
    // appropriate protection once routes are in place.
    //
    // If the handshake later reveals a dual-stack tunnel
    // (`tunnel_info.has_ipv6()`), we remove the bootstrap rule right
    // away so legitimate IPv6 VPN traffic can flow. Otherwise the rule
    // stays in place; the subsequent `enable_ipv6_leak_protection()` in
    // setup_full_tunnel / setup_bypass_tunnel is idempotent and takes
    // ownership of the rule's lifecycle.
    // Scope-guard that removes the bootstrap IPv6 block rule on drop,
    // unless disarmed. We arm it on successful install and disarm once
    // ownership transfers to the RouteManager (post-setup_full_tunnel /
    // post-setup_bypass_tunnel) or once we explicitly remove the rule
    // on a handshake failure path. If ANY code between install and
    // disarm panics, this RAII guard still runs — ensuring the user
    // does not end up with IPv6 globally blocked due to a crash.
    //
    // Note: `RecoveryState::perform_recovery_with_state` on next start
    // also handles this case, but that is an at-least-15-seconds later
    // cleanup. The guard fires in-process, at most ~1 unwind later.
    let mut bootstrap_ipv6_guard = BootstrapIpv6BlockGuard::disarmed();
    let mut bootstrap_ipv4_guard = BootstrapIpv4BlockGuard::disarmed();

    if settings.kill_switch && server_addr.is_ipv4() {
        if let Err(e) = RouteManager::install_bootstrap_ipv6_block() {
            // `e` already includes the translated hint (admin/IPv6)
            // from `format_netsh_error` in hpn-client-windows, so we
            // don't need to re-interpret the raw netsh output here.
            // Surface it verbatim in the UI log and the structured
            // log so the user has a one-line explanation of why the
            // protection didn't install.
            warn!(
                "Failed to install bootstrap IPv6 block (setup-window leak \
                 protection may be partial): {}",
                e
            );
            let mut state = state.write();
            state.add_log(
                LogLevel::Warn,
                format!(
                    "IPv6 setup-window protection unavailable: {}. The VPN \
                     will still connect; install the protection manually by \
                     running as Administrator once to let the client create \
                     the firewall rule.",
                    e
                ),
            );
        } else {
            debug!("Bootstrap IPv6 egress block installed for setup window");
            bootstrap_ipv6_guard.arm();
        }
    }

    // Bootstrap IPv4 kill-switch — DISABLED in this release.
    //
    // The intended design is symmetric to the IPv6 path above: drop
    // every outbound IPv4 packet except those targeting the VPN server
    // (and loopback) for the 1-3 s between "user clicked Connect" and
    // "regular routing is up". Closes the setup-window IP leak.
    //
    // Field testing showed Windows Firewall does NOT honour Allow >
    // Block at the same priority on every Windows build: with
    // ordinary Allow rules ahead of a `Block 0.0.0.0/1,128.0.0.0/1`,
    // Windows applies the Block rule first and traps the handshake
    // packets along with everything else. Symptom (reported in the
    // wild after the P1 release): "the network drops, comes back, the
    // VPN server never sees a single handshake packet". The fix is
    // to mark the Allow rules with `-OverrideBlockRules $true`, which
    // promotes them into the "Authenticated bypass" precedence class
    // that beats Block — `RouteManager::install_bootstrap_ipv4_block`
    // already does this — but until we can validate the corrected
    // rules on every supported Windows build (10 22H2, 11 23H2 +
    // Server 2022) and verify there is no UAC / domain GPO
    // interaction that re-introduces the deadlock, we keep the
    // bootstrap IPv4 install disabled at the call site. The IPv6
    // bootstrap (which does not have this issue because Windows
    // Firewall has no native "Block all IPv6" precedence quirk)
    // remains active above.
    //
    // The function and its RAII guard stay in the codebase so the
    // re-enable can land as a one-line revert once validation is
    // complete; see audit item P1-3 in `AGENTS.md`.
    if false && settings.kill_switch && server_addr.is_ipv4() {
        let server_ip = server_addr.ip().to_string();
        if let Err(e) = RouteManager::install_bootstrap_ipv4_block(&server_ip) {
            warn!(
                "Failed to install bootstrap IPv4 block (setup-window leak \
                 protection may be partial): {}",
                e
            );
            let mut state = state.write();
            state.add_log(
                LogLevel::Warn,
                format!(
                    "IPv4 setup-window protection unavailable: {}. The VPN \
                     will still connect; install the protection manually by \
                     running as Administrator once to let the client create \
                     the firewall rules.",
                    e
                ),
            );
        } else {
            debug!(
                "Bootstrap IPv4 egress block installed for setup window (allow VPN server only)"
            );
            bootstrap_ipv4_guard.arm();
        }
    }

    // Defence in depth: if a previous build of this client (with the
    // bootstrap IPv4 install enabled) crashed before the regular
    // routing took ownership, the Allow + Block rules would persist
    // across a reboot and brick IPv4 on the host. Always remove any
    // stale rules at connect time so an upgrade from a broken build
    // self-heals on the next click.
    if let Err(e) = RouteManager::remove_stale_ipv4_bootstrap_rules() {
        debug!("Stale IPv4 bootstrap rule cleanup: {}", e);
    }

    // Create UDP connection
    let connection = match UdpConnection::connect(server_addr).await {
        Ok(c) => c,
        Err(e) => {
            let mut state = state.write();
            state.status = ConnectionStatus::Error;
            state.add_log(LogLevel::Error, format!("Connection failed: {}", e));
            reset_connect_in_progress();
            return Err(e.to_string());
        }
    };

    // Perform handshake (with optional credentials)
    let tunnel_info = match client
        .connect_with_credentials(&connection, credentials)
        .await
    {
        Ok(info) => {
            let mut state = state.write();
            state.add_log(LogLevel::Info, "Handshake successful");
            state.add_log(
                LogLevel::Info,
                format!(
                    "Tunnel IP: {}.{}.{}.{}",
                    info.client_ip[0], info.client_ip[1], info.client_ip[2], info.client_ip[3]
                ),
            );
            let kem_name = match security_level {
                hpn_core::crypto::SecurityLevel::Level3 => "ML-KEM-768",
                hpn_core::crypto::SecurityLevel::Level5 => "ML-KEM-1024",
            };
            state.add_log(
                LogLevel::Info,
                format!("Cipher: AES-256-GCM. KEM: X25519 + {kem_name}"),
            );
            info
        }
        Err(e) => {
            // The bootstrap IPv6 block we may have installed is about to
            // become a footgun: if the handshake failed, the user ends up
            // with IPv6 globally blocked while the VPN is not up. Undo
            // it on every failure path before returning. The condition
            // mirrors the install condition (kill_switch + IPv4 server)
            // so we never try to remove a rule we never installed; the
            // call is idempotent anyway, but the log noise would be
            // misleading.
            if settings.kill_switch && server_addr.is_ipv4() {
                if let Err(re) = RouteManager::remove_stale_ipv6_block_rule() {
                    debug!(
                        "Failed to tear down bootstrap IPv6 block after handshake failure: {}",
                        re
                    );
                }
                // We explicitly removed the rule — disarm the guard so
                // it does not try again on Drop.
                bootstrap_ipv6_guard.disarm();

                // Same teardown for the bootstrap IPv4 rules: leaving
                // them in place after a failed connect would block
                // every outbound IPv4 destination except the unreachable
                // VPN server, and the user would lose IPv4 entirely.
                if let Err(re) = RouteManager::remove_stale_ipv4_bootstrap_rules() {
                    debug!(
                        "Failed to tear down bootstrap IPv4 rules after handshake failure: {}",
                        re
                    );
                }
                bootstrap_ipv4_guard.disarm();
            }

            let mut state = state.write();
            state.status = ConnectionStatus::Error;

            // Provide more helpful error message for auth failures
            let error_msg = e.to_string();
            let error_msg_lower = error_msg.to_lowercase();
            let display_msg =
                if error_msg_lower.contains("auth") || error_msg_lower.contains("credential") {
                    format!("Authentication failed: {}", error_msg)
                } else {
                    format!("Handshake failed: {}", error_msg)
                };

            state.add_log(LogLevel::Error, &display_msg);
            reset_connect_in_progress();
            return Err(display_msg);
        }
    };

    // If the handshake revealed a dual-stack tunnel, we must tear down
    // the bootstrap IPv6 block right now — otherwise legitimate IPv6 VPN
    // traffic would hit our own firewall rule the moment the routes are
    // installed. In the IPv4-only case, leave the rule in place: either
    // `setup_full_tunnel` or `setup_bypass_tunnel` will re-install the
    // identical rule (idempotent) and take ownership of its lifecycle.
    //
    // The `server_addr.is_ipv4()` guard mirrors the install condition:
    // if the server is IPv6 we never installed the bootstrap rule, so
    // there is nothing to remove here either.
    if settings.kill_switch && server_addr.is_ipv4() && tunnel_info.has_ipv6() {
        if let Err(e) = RouteManager::remove_stale_ipv6_block_rule() {
            warn!(
                "Failed to remove bootstrap IPv6 block after dual-stack handshake: {}",
                e
            );
        } else {
            debug!(
                "Bootstrap IPv6 block removed (tunnel is dual-stack, IPv6 will flow through VPN)"
            );
        }
        // Explicit removal — disarm the guard so it doesn't retry on Drop.
        bootstrap_ipv6_guard.disarm();
    }
    // IMPORTANT: for IPv4-only tunnels we MUST keep the guard armed
    // through the upcoming Wintun / RouteManager setup. Several fallible
    // steps (adapter creation, IP configuration, wait-for-ready) can
    // still return Err between here and the `setup_full_tunnel` /
    // `setup_bypass_tunnel` call that actually takes ownership of the
    // rule. Disarming prematurely would strand the firewall rule on the
    // user's system across any one of those failures. The guard is
    // disarmed once routing is successfully configured (see the
    // post-setup block further down).

    // Create Wintun adapter
    {
        let mut state = state.write();
        state.add_log(LogLevel::Info, "Creating network adapter...");
    }

    // Try to find wintun.dll in multiple locations
    let wintun_dll_path = find_wintun_dll(&app);

    if let Some(ref path) = wintun_dll_path {
        info!("Found wintun.dll at: {}", path.display());
        let mut state = state.write();
        state.add_log(
            LogLevel::Info,
            format!("Loading wintun.dll from: {}", path.display()),
        );
    } else {
        info!("wintun.dll not found in any known location, will try system PATH");
        let mut state = state.write();
        state.add_log(
            LogLevel::Warn,
            "wintun.dll not found, trying system PATH...",
        );
    }

    // CRITICAL: Capture original default gateway BEFORE creating VPN adapter
    // Once the VPN adapter is configured with a gateway, Windows may create
    // a default route via the VPN gateway, which would corrupt our detection.
    let (original_gateway, original_interface_idx) = {
        use hpn_client_windows::windows_api;
        match windows_api::get_default_gateway() {
            Ok(Some(route)) => {
                info!(
                    "Captured original gateway: {} (IF={})",
                    route.gateway, route.interface_index
                );
                (Some(route.gateway.to_string()), Some(route.interface_index))
            }
            Ok(None) => {
                warn!("No default gateway found before VPN adapter creation");
                (None, None)
            }
            Err(e) => {
                warn!("Failed to get default gateway: {}", e);
                (None, None)
            }
        }
    };

    info!("Loading Wintun driver...");
    let adapter = match WintunAdapter::create_with_dll(
        ADAPTER_NAME,
        DEFAULT_MTU,
        wintun_dll_path.as_deref(),
    ) {
        Ok(a) => {
            info!("Created Wintun adapter: {}", ADAPTER_NAME);
            {
                let mut state = state.write();
                state.add_log(LogLevel::Info, "Network adapter created");
            }
            a
        }
        Err(e) => {
            error!("Failed to create Wintun adapter: {}", e);
            let mut state = state.write();
            state.status = ConnectionStatus::Error;
            state.add_log(
                LogLevel::Error,
                format!("Failed to create adapter: {}. Make sure wintun.dll is present and you have administrator privileges.", e),
            );
            reset_connect_in_progress();
            return Err(e.to_string());
        }
    };

    // Configure adapter IP using values from server
    let client_ip = tunnel_info.client_ip;
    let netmask = tunnel_info.netmask;
    let gateway = tunnel_info.gateway;

    if let Err(e) = adapter.configure_ip(client_ip, netmask, gateway) {
        let mut state = state.write();
        state.status = ConnectionStatus::Error;
        state.add_log(
            LogLevel::Error,
            format!("Failed to configure adapter: {}", e),
        );
        reset_connect_in_progress();
        return Err(e.to_string());
    }

    {
        let mut state = state.write();
        state.add_log(LogLevel::Info, "Adapter configured");
    }

    // Wait for interface to become operational
    // CRITICAL: Windows needs time to initialize the interface after configuration
    // Without this, worker threads may start before the interface is ready,
    // causing packets to be dropped and connection to timeout
    {
        let mut state = state.write();
        state.add_log(LogLevel::Info, "Waiting for interface to become ready...");
    }

    if let Err(e) = adapter.wait_for_ready(std::time::Duration::from_secs(5)) {
        error!("Adapter failed to become ready: {}", e);
        let mut state = state.write();
        state.status = ConnectionStatus::Error;
        state.add_log(
            LogLevel::Error,
            format!("Interface not ready: {}", e).as_str(),
        );
        reset_connect_in_progress();
        return Err(e.to_string());
    }

    {
        let mut state = state.write();
        state.add_log(LogLevel::Info, "Interface ready");
    }

    // Configure IPv6 if server provided dual-stack support
    if tunnel_info.has_ipv6() {
        if let (Some(ipv6), Some(prefix)) = (tunnel_info.client_ipv6, tunnel_info.prefix_len_ipv6) {
            match adapter.configure_ipv6(ipv6, prefix, tunnel_info.gateway_ipv6) {
                Ok(_) => {
                    info!(
                        "Configured IPv6 on adapter: {}",
                        tunnel_info.client_ipv6_cidr().unwrap_or_default()
                    );
                    let mut state = state.write();
                    state.add_log(
                        LogLevel::Info,
                        &format!(
                            "IPv6: {}",
                            tunnel_info.client_ipv6_cidr().unwrap_or_default()
                        ),
                    );
                }
                Err(e) => {
                    warn!(
                        "Failed to configure IPv6: {} - continuing with IPv4 only",
                        e
                    );
                    let mut state = state.write();
                    state.add_log(LogLevel::Warn, &format!("IPv6 config failed: {}", e));
                }
            }
        }
    }

    // Set MTU on the interface (critical for large transfers)
    // Wintun doesn't respect MTU from driver, must be set explicitly via API or netsh
    // Without correct MTU: small packets work (DNS, ping) but large packets fail (downloads, speedtest)
    {
        use hpn_client_windows::windows_api;

        // Get interface index
        match windows_api::get_interface_index(ADAPTER_NAME) {
            Ok(if_index) => {
                // Try Windows API first, fall back to netsh if it fails (error 87 on some adapters)
                if let Err(e) =
                    windows_api::set_interface_mtu(if_index, tunnel_info.mtu as u32, false)
                {
                    warn!("Windows API MTU failed: {} - trying netsh fallback", e);
                    // Fallback to netsh which has better compatibility with virtual adapters
                    if let Err(e2) =
                        windows_api::set_interface_mtu_netsh(ADAPTER_NAME, tunnel_info.mtu as u32)
                    {
                        warn!(
                            "Failed to set MTU via netsh: {} - large transfers may fail",
                            e2
                        );
                        let mut state = state.write();
                        state.add_log(
                            LogLevel::Warn,
                            &format!("MTU config failed: {} / {}", e, e2),
                        );
                    } else {
                        info!("Set interface MTU to {} bytes via netsh", tunnel_info.mtu);
                        let mut state = state.write();
                        state.add_log(
                            LogLevel::Info,
                            &format!("MTU set to {} bytes", tunnel_info.mtu),
                        );
                    }
                } else {
                    info!("Set interface MTU to {} bytes", tunnel_info.mtu);
                    let mut state = state.write();
                    state.add_log(
                        LogLevel::Info,
                        &format!("MTU set to {} bytes", tunnel_info.mtu),
                    );
                }
            }
            Err(e) => {
                warn!("Failed to get interface index for MTU setup: {}", e);
                // Try netsh directly with interface name
                if let Err(e2) =
                    windows_api::set_interface_mtu_netsh(ADAPTER_NAME, tunnel_info.mtu as u32)
                {
                    warn!(
                        "Failed to set MTU: {} / {} - large transfers may fail",
                        e, e2
                    );
                } else {
                    info!("Set interface MTU to {} bytes via netsh", tunnel_info.mtu);
                }
            }
        }
    }

    // Setup routing
    let vpn_gateway = format!(
        "{}.{}.{}.{}",
        gateway[0], gateway[1], gateway[2], gateway[3]
    );
    let server_endpoint = format!("{}", server_addr.ip());

    // Determine split tunnel settings from profile
    let (use_bypass_tunnel, bypass_routes, bypass_local, bypass_discovery) =
        if let Some(ref split_config) = profile.split_tunnel {
            if split_config.enabled && split_config.mode == "bypass" {
                let routes: Vec<String> = split_config
                    .routes
                    .as_deref()
                    .unwrap_or("")
                    .split(',')
                    .map(|s: &str| s.trim().to_string())
                    .filter(|s: &String| !s.is_empty())
                    .collect();
                (
                    true,
                    routes,
                    split_config.bypass_local,
                    split_config.bypass_discovery,
                )
            } else {
                (false, Vec::new(), true, true)
            }
        } else {
            (false, Vec::new(), true, true)
        };

    // For bypass tunnel, allow_lan is controlled by bypass_local setting
    // For full tunnel, we always allow LAN
    let allow_lan = if use_bypass_tunnel {
        bypass_local
    } else {
        true
    };

    let mut route_manager = RouteManager::with_kill_switch(
        &vpn_gateway,
        ADAPTER_NAME,
        &server_endpoint,
        settings.kill_switch,
        allow_lan,
    );

    // Set pre-captured original gateway to prevent routing loop
    // This MUST be done before setup_full_tunnel() is called
    if let (Some(gw), Some(idx)) = (original_gateway, original_interface_idx) {
        route_manager.set_original_gateway(gw, idx);
    } else {
        warn!(
            "No pre-captured gateway available - routing may fail if VPN adapter already has a default route"
        );
    }

    // Enable IPv6 routing if server provided IPv6 gateway
    if tunnel_info.has_ipv6() {
        if let Some(gw_v6_str) = tunnel_info.gateway_ipv6_str() {
            info!("Enabling IPv6 routing via {}", gw_v6_str);
            route_manager.enable_ipv6(&gw_v6_str);
        }
    }

    // Track if we have security warnings to show user
    let mut security_warnings: Vec<String> = Vec::new();
    let mut routing_success = false;

    // Setup routing based on split tunnel configuration
    if use_bypass_tunnel {
        // Bypass mode: all traffic through VPN except specified routes
        let routes_ref: Vec<&str> = bypass_routes.iter().map(|s: &String| s.as_str()).collect();
        {
            let mut state = state.write();
            state.add_log(
                LogLevel::Info,
                format!(
                    "Configuring bypass tunnel ({} routes, local={}, discovery={})",
                    routes_ref.len(),
                    bypass_local,
                    bypass_discovery
                ),
            );
        }
        if let Err(e) =
            route_manager.setup_bypass_tunnel(&routes_ref, bypass_local, bypass_discovery)
        {
            warn!("Failed to setup bypass routing: {}", e);
            let warning = format!("Routing failed: {} - Traffic may leak!", e);
            {
                let mut state = state.write();
                state.add_log(LogLevel::Error, &warning);
            }
            security_warnings.push(warning);
        } else {
            routing_success = true;
            // RouteManager now owns the IPv6 block rule (its own
            // `enable_ipv6_leak_protection` will install/manage it; its
            // Drop path will clean it up on disconnect or failure).
            // The bootstrap IPv4 rules were torn down at the start of
            // `setup_bypass_tunnel`. Safe to disarm both guards.
            bootstrap_ipv6_guard.disarm();
            bootstrap_ipv4_guard.disarm();
            let mut state = state.write();
            state.add_log(LogLevel::Info, "Bypass routes configured");
        }
    } else {
        // Full tunnel mode: all traffic through VPN
        if let Err(e) = route_manager.setup_full_tunnel() {
            warn!("Failed to setup routing: {}", e);
            let warning = format!("Routing failed: {} - Traffic may leak!", e);
            {
                let mut state = state.write();
                state.add_log(LogLevel::Error, &warning);
            }
            security_warnings.push(warning);
        } else {
            routing_success = true;
            // See above: RouteManager owns the IPv6 rule from here on,
            // and the bootstrap IPv4 rules were torn down at the start
            // of `setup_full_tunnel`.
            bootstrap_ipv6_guard.disarm();
            bootstrap_ipv4_guard.disarm();
            let mut state = state.write();
            state.add_log(LogLevel::Info, "Routes configured");
        }
    }

    // Setup DNS leak protection if DNS servers provided.
    // Note: We do this even if routing failed, because the VPN adapter
    // DNS should still work — and we pass BOTH the v4 and v6 server lists
    // so that dual-stack tunnels get IPv6 DNS configured on Wintun (in
    // earlier builds, dual-stack tunnels had IPv6 DNS only on the
    // physical interface via RA-RDNSS = ISP resolver leak; that's the
    // exact symptom the Free SAS field tester reported).
    let mut dns_protection = DnsLeakProtection::new(ADAPTER_NAME);
    if !tunnel_info.dns_servers.is_empty() || !tunnel_info.dns_servers_v6.is_empty() {
        info!("Configuring DNS leak protection for VPN tunnel...");
        match dns_protection.enable(&tunnel_info.dns_servers, &tunnel_info.dns_servers_v6) {
            Ok(_) => {
                let mut state = state.write();
                state.add_log(LogLevel::Info, "DNS leak protection enabled");
            }
            Err(e) => {
                // DNS protection failed - log warning but continue
                // The VPN is still functional, just with potential DNS leaks
                warn!("Failed to enable DNS protection: {}", e);
                let warning = format!("DNS protection failed: {} - DNS may leak!", e);
                {
                    let mut state = state.write();
                    state.add_log(LogLevel::Warn, &warning);
                }
                security_warnings.push(warning);
            }
        }
    }

    // Setup IPv6 leak protection OR enable dual-stack VPN
    // If server provides IPv6, we route it through the VPN tunnel instead of blocking it
    let mut ipv6_protection = Ipv6LeakProtection::new();
    if tunnel_info.has_ipv6() {
        // Server provides IPv6 - don't disable it, the VPN tunnel handles IPv6 traffic
        info!("IPv6 dual-stack enabled - skipping IPv6 leak protection");
        let mut state = state.write();
        state.add_log(LogLevel::Info, "IPv6 dual-stack active");
    } else {
        // No IPv6 from server - disable IPv6 on non-VPN interfaces to prevent leaks
        match ipv6_protection.disable_ipv6() {
            Ok(_) => {
                let mut state = state.write();
                state.add_log(LogLevel::Info, "IPv6 leak protection enabled");
            }
            Err(e) => {
                warn!("Failed to enable IPv6 protection: {}", e);
                let warning = format!("IPv6 protection failed: {} - IPv6 may leak!", e);
                {
                    let mut state = state.write();
                    state.add_log(LogLevel::Warn, &warning);
                }
                security_warnings.push(warning);
            }
        }
    }

    // If routing failed completely, we should disconnect and cleanup
    if !routing_success {
        error!("Critical: routing setup failed, cleaning up");
        // Cleanup will happen via Drop when route_manager goes out of scope
        let mut state = state.write();
        state.status = ConnectionStatus::Error;
        state.add_log(LogLevel::Error, "Connection aborted: routing setup failed");
        reset_connect_in_progress();
        return Err("Failed to setup VPN routing".to_string());
    }

    // Log combined security warning if any issues (but we're still connected)
    if !security_warnings.is_empty() {
        let mut state = state.write();
        state.add_log(
            LogLevel::Warn,
            "Connected with security warnings - check logs",
        );
    }

    // Get session_id from client stats
    let session_id = client.stats().session_id;

    // Create and arm the kill switch manager based on settings
    let kill_switch_mode = if settings.kill_switch {
        if allow_lan {
            KillSwitchMode::EnabledAllowLan
        } else {
            KillSwitchMode::Enabled
        }
    } else {
        KillSwitchMode::Disabled
    };
    let kill_switch_manager = Arc::new(KillSwitchManager::new(kill_switch_mode));
    kill_switch_manager.on_vpn_connected();
    info!(
        "Kill switch manager created and armed (mode={:?})",
        kill_switch_mode
    );

    // Kill switch is route-based only.
    // Windows Firewall rules are NOT used because:
    // 1. They cause issues on non-English Windows locales (IPv6 address format)
    // 2. They can persist after crashes, blocking all internet
    // 3. Route-based kill switch is sufficient and self-cleaning
    //
    // The route-based kill switch works by:
    // - Adding specific routes for the VPN server via the original gateway
    // - Setting a default route (0.0.0.0/0) via the VPN tunnel
    // - Without the tunnel, traffic has nowhere to go = kill switch effect

    // Set connected state (set_connected already logs "Tunnel established")
    {
        let mut state = state.write();
        state.set_connected(session_id);
    }
    // Update tray icon to show connected
    update_tray_status(&app, ConnectionStatus::Connected);

    // Create shutdown, rekey, and cleanup completion channels
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
    let (rekey_tx, mut rekey_rx) = mpsc::channel::<()>(1);
    let (cleanup_tx, cleanup_rx) = tokio::sync::oneshot::channel::<()>();
    {
        let mut state = state.write();
        state.shutdown_tx = Some(shutdown_tx);
        state.rekey_tx = Some(rekey_tx);
        state.cleanup_complete_rx = Some(cleanup_rx);
    }

    // Channel capacity sized for 2.5 Gbps throughput target:
    // - 2.5 Gbps / 8 = 312.5 MB/s
    // - At MTU 1420: ~220k packets/sec peak
    // - 8192 packets = ~37ms buffer at full speed
    const CHANNEL_CAPACITY: usize = 8192;

    // Buffer pool pre-allocation:
    // - 1024 buffers × 2KB = 2MB per pool (4MB total)
    // - Pools grow on demand if exhausted (rare at steady state)
    // - Much smaller than before (was 32k × 64KB = 4GB!)
    const POOL_SIZE: usize = 1024;

    // Create buffer pools for zero-copy packet processing
    let upload_buffer_pool = Arc::new(BufferPool::new(POOL_SIZE, MAX_PACKET_SIZE));
    let download_buffer_pool = Arc::new(BufferPool::new(POOL_SIZE, MAX_PACKET_SIZE));

    // Create channels for packet forwarding with large capacity
    // Both paths use PooledBuffer for zero-copy (critical for multi-gigabit throughput)
    let (tun_to_udp_tx, mut tun_to_udp_rx) = mpsc::channel::<PooledBuffer>(CHANNEL_CAPACITY);
    let (udp_to_tun_tx, udp_to_tun_rx) = mpsc::channel::<PooledBuffer>(CHANNEL_CAPACITY);

    // Wrap adapter in Arc for sharing between threads
    let adapter: Arc<WintunAdapter> = Arc::new(adapter);

    // Shutdown flag for worker threads
    let shutdown_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Task 1: Read from TUN adapter and send to channel (dedicated thread)
    // CRITICAL: No per-packet logging here - it destroys throughput!
    let adapter_reader: Arc<WintunAdapter> = Arc::clone(&adapter);
    let shutdown_tun_read = Arc::clone(&shutdown_flag);
    let upload_pool = Arc::clone(&upload_buffer_pool);
    let tun_reader_handle = std::thread::Builder::new()
        .name("tun-reader".into())
        .spawn(move || {
            tracing::info!("TUN reader thread started");
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut packets_read = 0u64;
                let mut errors = 0u64;
                loop {
                    if shutdown_tun_read.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                    // Get buffer from pool (zero-copy)
                    let mut pooled_buf = upload_pool.get();
                    match adapter_reader.recv(pooled_buf.as_mut_slice()) {
                        Ok(len) if len > 0 => {
                            packets_read += 1;
                            pooled_buf.set_len(len);
                            if tun_to_udp_tx.blocking_send(pooled_buf).is_err() {
                                break;
                            }
                        }
                        Ok(_) => {
                            // Zero-length read, continue
                        }
                        Err(_e) => {
                            errors += 1;
                            if errors % 1000 == 1 {
                                tracing::warn!("TUN read errors: {} total", errors);
                            }
                            // Don't break on error - Wintun may recover
                        }
                    }
                }
                tracing::info!(
                    "TUN reader stopped: {} packets, {} errors",
                    packets_read,
                    errors
                );
            }));

            if let Err(panic_info) = result {
                let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = panic_info.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "unknown panic".to_string()
                };
                tracing::error!("TUN reader thread panicked: {}", msg);
            }
        })
        .map_err(|e| format!("Failed to spawn TUN reader thread: {}", e))?;

    // Task 2: Write decrypted packets to TUN adapter (dedicated blocking thread)
    // CRITICAL: No per-packet logging here - it destroys throughput!
    let adapter_writer: Arc<WintunAdapter> = Arc::clone(&adapter);
    let shutdown_tun_write = Arc::clone(&shutdown_flag);
    let tun_writer_handle = std::thread::Builder::new()
        .name("tun-writer".into())
        .spawn(move || {
            tracing::info!("TUN writer thread started");
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut rx = udp_to_tun_rx;
                let mut packets_written = 0u64;
                let mut errors = 0u64;
                loop {
                    if shutdown_tun_write.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                    match rx.blocking_recv() {
                        Some(packet) => {
                            packets_written += 1;
                            if let Err(_e) = adapter_writer.send(&packet) {
                                errors += 1;
                                // Only log every 1000 errors to avoid spam
                                if errors % 1000 == 1 {
                                    tracing::warn!("TUN write errors: {} total", errors);
                                }
                            }
                        }
                        None => break,
                    }
                }
                tracing::info!(
                    "TUN writer stopped: {} packets, {} errors",
                    packets_written,
                    errors
                );
            }));

            if let Err(panic_info) = result {
                let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = panic_info.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "unknown panic".to_string()
                };
                tracing::error!("TUN writer thread panicked: {}", msg);
            }
        })
        .map_err(|e| format!("Failed to spawn TUN writer thread: {}", e))?;

    // Task 3: Forward TUN packets to UDP (encrypt and send)
    // CRITICAL: No per-packet logging - throughput sensitive!
    let client_for_tun = Arc::new(client);
    let connection_for_tun = Arc::new(connection);
    let client_tx = Arc::clone(&client_for_tun);
    let conn_tx = Arc::clone(&connection_for_tun);
    let tun_forwarder_handle = tokio::spawn(async move {
        let mut packets_forwarded = 0u64;
        let mut errors = 0u64;
        while let Some(packet) = tun_to_udp_rx.recv().await {
            packets_forwarded += 1;
            if let Err(_e) = client_tx.send_data(&conn_tx, &packet).await {
                errors += 1;
            }
        }
        tracing::info!(
            "TUN->UDP forwarder stopped: {} packets, {} errors",
            packets_forwarded,
            errors
        );
    });

    // Task 4: Receive UDP packets and forward to TUN (decrypt and send to channel)
    // This is the critical download path - optimized for throughput with zero-copy
    let client_rx = Arc::clone(&client_for_tun);
    let conn_rx = Arc::clone(&connection_for_tun);
    let state_for_rx = state.inner().clone();
    let buffer_pool_rx = Arc::clone(&download_buffer_pool);
    let udp_receiver_handle = tokio::spawn(async move {
        let mut recv_buf = vec![0u8; 65535];

        loop {
            // Fast path: receive and process without unnecessary logging
            match conn_rx.recv(&mut recv_buf).await {
                Ok((len, addr)) if len > 0 => {
                    // Only accept packets from server IP
                    if addr.ip() != conn_rx.server_addr().ip() {
                        continue;
                    }

                    // Get a buffer from the pool for zero-copy decryption
                    let mut pooled_buf = buffer_pool_rx.get();

                    match client_rx
                        .process_packet(&recv_buf[..len], pooled_buf.as_mut_slice())
                        .await
                    {
                        Ok(Some((MessageType::Data, decrypted_len))) => {
                            // Set the valid data length in the pooled buffer
                            pooled_buf.set_len(decrypted_len);

                            // Use try_send to avoid blocking on full channel
                            // On success, the buffer is sent (ownership transferred)
                            // On failure, the buffer is returned to pool automatically on drop
                            if let Err(err) = udp_to_tun_tx.try_send(pooled_buf) {
                                // Channel full - get the buffer back and retry with blocking send
                                let buf = err.into_inner();
                                if udp_to_tun_tx.send(buf).await.is_err() {
                                    break;
                                }
                            }
                        }
                        Ok(Some(_)) => {
                            // Non-data packet (keepalive, control, etc.), buffer auto-returns to pool on drop
                        }
                        Ok(None) => {
                            // No packet produced, buffer auto-returns to pool on drop
                        }
                        Err(e) => {
                            // Log decryption/replay errors at debug level to help diagnose issues
                            tracing::debug!("Packet processing error: {}", e);
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    error!("UDP receive error: {}", e);
                    let mut state = state_for_rx.write();
                    state.add_log(LogLevel::Error, format!("Connection error: {}", e));
                    break;
                }
            }
        }
    });

    // Main event handler task
    let state_clone = state.inner().clone();
    let app_clone = app.clone();
    let client_main = Arc::clone(&client_for_tun);
    let conn_main = Arc::clone(&connection_for_tun);
    let client_for_stats = Arc::clone(&client_for_tun);
    let state_for_stats = state.inner().clone();
    let shutdown_flag_main = Arc::clone(&shutdown_flag);
    let ks_manager = Arc::clone(&kill_switch_manager);
    tokio::spawn(async move {
        // Keep route_manager, dns_protection, and ipv6_protection alive.
        // `_ipv6_protection` must be `mut` so we can flip its
        // force_restore_on_drop flag on the kill-switch-engaged
        // disconnect path (see below).
        let mut _route_manager = route_manager;
        let _dns_protection = dns_protection;
        let mut _ipv6_protection = ipv6_protection;

        // Stats update interval
        let mut stats_interval = tokio::time::interval(std::time::Duration::from_secs(1));
        // Keepalive interval (check every 5 seconds, send if needed)
        let mut keepalive_interval = tokio::time::interval(std::time::Duration::from_secs(5));

        // Track previous bytes for rate calculation
        let mut prev_bytes_sent: u64 = 0;
        let mut prev_bytes_received: u64 = 0;

        // Track disconnect reason for kill switch logic
        // Note: this value is updated progressively as events occur, so some
        // assignments may be overwritten before being read - this is intentional.
        #[allow(unused_assignments)]
        let mut disconnect_reason = DisconnectReason::Unknown;

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("Shutdown signal received (user requested)");
                    disconnect_reason = DisconnectReason::UserRequested;
                    // Signal worker threads to stop
                    shutdown_flag_main.store(true, std::sync::atomic::Ordering::SeqCst);
                    // Send disconnect message to server
                    if let Err(e) = client_main.disconnect(&conn_main).await {
                        debug!("Error sending disconnect: {}", e);
                    }
                    // Abort async tasks
                    tun_forwarder_handle.abort();
                    udp_receiver_handle.abort();
                    break;
                }
                _ = rekey_rx.recv() => {
                    info!("Rekey request received");
                    if let Err(e) = client_main.initiate_rekey(&conn_main).await {
                        error!("Rekey failed: {}", e);
                        let mut state = state_clone.write();
                        state.add_log(LogLevel::Error, format!("Key rotation failed: {}", e));
                    }
                }
                Some(event) = event_rx.recv() => {
                    // Check for events that indicate connection loss
                    match &event {
                        ClientEvent::Disconnected(reason) => {
                            disconnect_reason = if reason.as_ref().map(|r| r.contains("user")).unwrap_or(false) {
                                DisconnectReason::UserRequested
                            } else {
                                DisconnectReason::ServerClosed
                            };
                            // Signal shutdown
                            shutdown_flag_main.store(true, std::sync::atomic::Ordering::SeqCst);
                            tun_forwarder_handle.abort();
                            udp_receiver_handle.abort();
                            handle_client_event(&app_clone, &state_clone, event);
                            break;
                        }
                        ClientEvent::KeepaliveTimeout { missed_count } => {
                            // Connection dead - this is a network error
                            // Track this for when loop eventually breaks
                            if *missed_count >= 3 {
                                warn!("Connection presumed dead after {} missed keepalives", missed_count);
                                #[allow(unused_assignments)]
                                {
                                    disconnect_reason = DisconnectReason::NetworkError;
                                }
                            }
                        }
                        ClientEvent::ReconnectionFailed { .. } => {
                            disconnect_reason = DisconnectReason::NetworkError;
                            // Signal shutdown
                            shutdown_flag_main.store(true, std::sync::atomic::Ordering::SeqCst);
                            tun_forwarder_handle.abort();
                            udp_receiver_handle.abort();
                            handle_client_event(&app_clone, &state_clone, event);
                            break;
                        }
                        _ => {}
                    }
                    handle_client_event(&app_clone, &state_clone, event);
                }
                _ = stats_interval.tick() => {
                    // Update UI stats from VpnClient stats
                    let client_stats = client_for_stats.stats();
                    let mut state = state_for_stats.write();
                    state.stats.tx = client_stats.bytes_sent;
                    state.stats.rx = client_stats.bytes_received;
                    state.stats.rtt = client_stats.rtt_ms;
                    state.stats.key_id = client_stats.key_id;
                    // Calculate instantaneous rate (bytes/sec since last measurement)
                    let current_total = client_stats.bytes_sent.saturating_add(client_stats.bytes_received);
                    let prev_total = prev_bytes_sent.saturating_add(prev_bytes_received);
                    state.stats.rate = current_total.saturating_sub(prev_total);
                    // Update previous values for next iteration
                    prev_bytes_sent = client_stats.bytes_sent;
                    prev_bytes_received = client_stats.bytes_received;
                }
                _ = keepalive_interval.tick() => {
                    tracing::debug!("Keepalive interval tick - checking if should send");
                    // Send keepalive if needed
                    if client_main.should_send_keepalive() {
                        tracing::info!("Sending keepalive now");
                        if let Err(e) = client_main.send_keepalive(&conn_main).await {
                            debug!("Keepalive send error: {}", e);
                        } else {
                            tracing::info!("Keepalive sent successfully");
                        }
                    } else {
                        tracing::debug!("Skipping keepalive (not time yet)");
                    }
                    // Check for keepalive timeout
                    if let Some(missed) = client_main.check_keepalive_timeout() {
                        if missed > 3 {
                            warn!("Connection may be unstable: {} missed keepalives", missed);
                        }
                    }
                }
            }
        }

        // Notify kill switch manager of disconnection
        let should_block = ks_manager.on_vpn_disconnected(disconnect_reason);
        info!(
            "Kill switch: disconnect_reason={:?}, should_block={}",
            disconnect_reason, should_block
        );

        // Configure route manager cleanup behavior based on kill switch state
        if should_block {
            // Kill switch engaged - don't restore routes on drop
            _route_manager.set_force_restore_on_drop(false);
            // Also pin down IPv6: if we let `Ipv6LeakProtection::Drop`
            // re-enable IPv6 on physical interfaces while IPv4 is
            // route-blocked, the user silently leaks their real IP over
            // every AAAA destination. Keep IPv6 disabled until the user
            // reconnects or explicitly disables the kill switch.
            _ipv6_protection.set_force_restore_on_drop(false);
            // Keep Windows Firewall kill switch ENABLED - this is the point! Block all traffic.
            // The firewall will block everything until user reconnects.
            info!("Windows Firewall kill switch remains active (blocking all non-local traffic)");
            // Log that internet is blocked
            {
                let mut state = state_clone.write();
                state.add_log(
                    LogLevel::Warn,
                    "Kill switch engaged: Internet blocked until reconnect",
                );
            }
            // CRITICAL: Notify user that kill switch is engaged and internet is blocked
            send_notification(
                &app_clone,
                "Kill Switch Activated",
                "Internet blocked for your protection. Reconnect to restore access.",
            );
        }
        // Note: Route-based kill switch is used instead of Windows Firewall rules.
        // Routes are automatically restored when the adapter is dropped (force_restore_on_drop).
        // else: force_restore_on_drop remains true (default) - will restore routes

        // Cleanup: drop adapter to signal threads
        drop(adapter);

        // Wait for worker threads with timeout
        let join_timeout = std::time::Duration::from_secs(2);

        // Join TUN reader thread
        let reader_join = std::thread::spawn(move || tun_reader_handle.join());
        let start = std::time::Instant::now();
        while !reader_join.is_finished() && start.elapsed() < join_timeout {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        if reader_join.is_finished() {
            let _ = reader_join.join();
        }

        // Join TUN writer thread
        let writer_join = std::thread::spawn(move || tun_writer_handle.join());
        let start = std::time::Instant::now();
        while !writer_join.is_finished() && start.elapsed() < join_timeout {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        if writer_join.is_finished() {
            let _ = writer_join.join();
        }

        info!("All VPN tasks stopped");

        // Drop route_manager, dns_protection, and ipv6_protection explicitly to ensure cleanup
        // The Drop implementations will handle route restoration based on kill switch state
        drop(_route_manager);
        drop(_dns_protection);
        drop(_ipv6_protection);

        if should_block {
            info!("Routes cleaned up (kill switch engaged - internet blocked)");
        } else {
            info!("Routes, DNS, and IPv6 restored");
        }

        // Signal that cleanup is complete
        let _ = cleanup_tx.send(());
    });

    Ok(())
}

/// Send a system notification to the user.
///
/// This shows a Windows notification that appears even when the app is in the background.
#[cfg(windows)]
fn send_notification(app: &AppHandle, title: &str, body: &str) {
    if let Err(e) = app.notification().builder().title(title).body(body).show() {
        warn!("Failed to send notification: {}", e);
    }
}

#[cfg(windows)]
/// Handle VPN client events and update tray status.
fn handle_client_event(app: &AppHandle, state: &AppStateRef, event: ClientEvent) {
    let mut state = state.write();

    match event {
        ClientEvent::StateChanged(client_state) => {
            debug!("Client state changed: {:?}", client_state);
        }
        ClientEvent::Connected(_info) => {
            state.add_log(LogLevel::Info, "Tunnel active");
        }
        ClientEvent::Disconnected(reason) => {
            let msg = reason.unwrap_or_else(|| "Unknown reason".into());
            state.set_disconnected(Some(&msg));
            // Drop the write lock before calling update_tray_status to avoid potential deadlock
            drop(state);
            update_tray_status(app, ConnectionStatus::Disconnected);
            return; // state already dropped
        }
        ClientEvent::Keepalive { sequence, rtt_ms } => {
            state.stats.rtt = rtt_ms;
            debug!("Keepalive seq={} rtt={}ms", sequence, rtt_ms);
        }
        ClientEvent::Error(msg) => {
            state.add_log(LogLevel::Error, msg);
        }
        ClientEvent::BytesTransferred { sent, received } => {
            state.stats.tx = sent;
            state.stats.rx = received;
        }
        ClientEvent::RekeyComplete { new_key_id } => {
            state.stats.key_id = new_key_id;
            state.add_log(
                LogLevel::Info,
                format!("Key rotation complete (key_id={})", new_key_id),
            );
        }
        ClientEvent::ControlReceived {
            control_type,
            message,
        } => {
            let msg = message.unwrap_or_else(|| format!("{:?}", control_type));
            state.add_log(LogLevel::Info, format!("Server: {}", msg));
        }
        ClientEvent::KeepaliveTimeout { missed_count } => {
            state.add_log(
                LogLevel::Warn,
                format!("Keepalive timeout (missed: {})", missed_count),
            );
            // Send notification when server stops responding (3+ missed keepalives is critical)
            if missed_count >= 3 {
                send_notification(
                    app,
                    "VPN Connection Issue",
                    &format!("Server not responding ({} missed keepalives)", missed_count),
                );
            }
        }
        ClientEvent::Reconnecting {
            attempt,
            max_attempts,
        } => {
            state.status = ConnectionStatus::Reconnecting;
            let msg = if max_attempts > 0 {
                format!("Reconnecting ({}/{})", attempt, max_attempts)
            } else {
                format!("Reconnecting (attempt {})", attempt)
            };
            state.add_log(LogLevel::Info, &msg);
            // Update tray to show reconnecting
            update_tray_status(app, ConnectionStatus::Reconnecting);
            // Notify on first reconnection attempt
            if attempt == 1 {
                send_notification(app, "VPN Reconnecting", &msg);
            }
        }
        ClientEvent::ReconnectionFailed { reason } => {
            let msg = format!("Reconnection failed: {}", reason);
            state.set_disconnected(Some(&msg));
            // Update tray to show disconnected
            update_tray_status(app, ConnectionStatus::Disconnected);
            // Critical: reconnection failed - user needs to know
            send_notification(app, "VPN Disconnected", &msg);
        }
        ClientEvent::EndpointChanged { new_addr } => {
            state.add_log(
                LogLevel::Info,
                format!("Server endpoint changed: {}", new_addr),
            );
        }
        ClientEvent::NatDiscovered(nat_info) => {
            if let Some(endpoint) = &nat_info.public_endpoint {
                state.add_log(
                    LogLevel::Info,
                    format!(
                        "NAT discovered: {}:{}",
                        endpoint.public_ip, endpoint.public_port
                    ),
                );
            }
        }
        ClientEvent::RebindRequested { new_endpoint } => {
            state.add_log(
                LogLevel::Info,
                format!("Rebind requested: {}", new_endpoint),
            );
        }
        ClientEvent::RebindAcknowledged => {
            state.add_log(LogLevel::Info, "Rebind acknowledged");
        }
    }
}

/// Disconnect from VPN.
#[cfg(not(windows))]
#[tauri::command]
pub async fn disconnect(_state: State<'_, AppStateRef>) -> Result<(), CommandError> {
    connection::disconnect(_state).await
}

/// Disconnect from VPN.
#[cfg(windows)]
#[tauri::command]
pub async fn disconnect(app: AppHandle, state: State<'_, AppStateRef>) -> Result<(), CommandError> {
    connection::disconnect(app, state).await
}

/// Get current connection status.
#[tauri::command]
pub fn get_status(state: State<'_, AppStateRef>) -> ConnectionStatus {
    connection::get_status(state)
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

    /// All tests in this module poke at process-global atomics
    /// (`CONNECT_IN_PROGRESS`, `LAST_CONNECT_ATTEMPT`). Cargo runs
    /// `#[test]` functions on a thread pool, so without
    /// serialisation two of these tests race on the same atomic and
    /// flake. Holding this mutex across each test body forces them
    /// to execute sequentially regardless of the runner's
    /// scheduling decisions.
    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    fn reset_rate_limit_to(ms_since_epoch: u64) {
        LAST_CONNECT_ATTEMPT.store(ms_since_epoch, Ordering::Relaxed);
    }

    #[test]
    fn test_rate_limit_first_attempt_passes() {
        let _guard = TEST_LOCK.lock();
        reset_rate_limit_to(0);
        let result = check_connect_rate_limit();
        assert!(result.is_ok(), "first attempt after reset must pass");
    }

    #[test]
    fn test_rate_limit_blocks_immediate_retry() {
        let _guard = TEST_LOCK.lock();
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
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        reset_rate_limit_to(now_ms.saturating_sub(MIN_CONNECT_INTERVAL_MS + 100));
        let result = check_connect_rate_limit();
        assert!(
            result.is_ok(),
            "attempt outside the rate-limit window must pass"
        );
    }

    #[test]
    fn test_connect_in_progress_compare_exchange() {
        let _guard = TEST_LOCK.lock();
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

        reset_connect_in_progress();
    }

    #[cfg(windows)]
    #[test]
    fn test_bootstrap_ipv6_guard_disarmed_does_nothing_on_drop() {
        // The disarmed guard must NOT call into RouteManager on drop.
        // We can't easily verify "no syscalls happened" here, but we
        // can assert the guard goes out of scope without panicking.
        {
            let mut guard = BootstrapIpv6BlockGuard::disarmed();
            // Toggle on then off — final state is disarmed.
            guard.arm();
            guard.disarm();
        }
        // Reaching this line means Drop did not panic and did not
        // attempt any privileged operations on a disarmed guard.
    }

    #[cfg(windows)]
    #[test]
    fn test_bootstrap_ipv4_guard_disarmed_does_nothing_on_drop() {
        {
            let mut guard = BootstrapIpv4BlockGuard::disarmed();
            guard.arm();
            guard.disarm();
        }
    }

    #[cfg(windows)]
    #[test]
    fn test_buffer_pool_lease_and_return() {
        let pool = Arc::new(BufferPool::new(4, 2048));
        // Lease a buffer.
        let mut buf = pool.get();
        assert_eq!(buf.as_mut_slice().len(), 2048);
        buf.set_len(1024);
        assert_eq!(buf.len(), 1024);
        // Drop the buffer; it should return to the pool.
        drop(buf);
        // Lease again — should reuse the same backing Vec.
        let buf2 = pool.get();
        assert_eq!(buf2.as_mut_slice().len(), 2048);
    }

    #[cfg(windows)]
    #[test]
    fn test_buffer_pool_caps_pool_size() {
        // The pool's max is `initial_size.max(4096)`, which for
        // `initial_size=2` is 4096. Drop a 5000-buffer batch: the
        // first 4096 stay in the pool, the rest are dropped to
        // prevent unbounded growth. We don't assert exact pool
        // bookkeeping (private state) but we DO assert the pool
        // continues to function correctly under bursty churn.
        let pool = Arc::new(BufferPool::new(2, 1024));
        let mut bufs = Vec::with_capacity(5000);
        for _ in 0..5000 {
            bufs.push(pool.get());
        }
        // Drop them all in one go.
        drop(bufs);
        // Pool is still usable.
        let _ = pool.get();
    }
}
