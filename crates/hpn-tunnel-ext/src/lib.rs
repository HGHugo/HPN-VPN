//! FFI bridge for the macOS Packet Tunnel Extension.
//!
//! This staticlib exposes C-ABI functions that the Swift `PacketTunnelProvider`
//! calls to start/stop the VPN engine, exchange packets, and query network
//! settings after the handshake completes.

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
// Numeric (FFI casts):
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]
// FFI/unsafe:
#![allow(unsafe_code)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::ptr_as_ptr)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]
// Crate-specific:
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::manual_let_else)]

use std::os::raw::{c_char, c_int};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::Mutex;
use tokio::runtime::Runtime;
use tracing::{error, info};

use hpn_client_core::transport::TransportTrait;
use hpn_client_core::{ClientConfig, UdpConnection, VpnClient};

// ---------------------------------------------------------------------------
// Cached handles for lock-free hot path (set once at start, cleared at stop).
// ---------------------------------------------------------------------------

/// Fixed-size packet buffer to avoid per-packet heap allocation.
/// Sized for MTU (1500) + overhead. Much smaller than 65535.
const PACKET_BUF_SIZE: usize = 2048;

/// A stack-allocated packet buffer with length tracking.
struct PacketBuf {
    data: [u8; PACKET_BUF_SIZE],
    len: u16,
}

impl PacketBuf {
    #[inline]
    fn new(src: &[u8]) -> Self {
        let len = src.len().min(PACKET_BUF_SIZE);
        let mut data = [0u8; PACKET_BUF_SIZE];
        data[..len].copy_from_slice(&src[..len]);
        Self {
            data,
            len: len as u16,
        }
    }

    #[inline]
    fn as_slice(&self) -> &[u8] {
        &self.data[..self.len as usize]
    }
}

/// Cached client handle for packet write/read (avoids mutex per-packet).
static CACHED_CLIENT: Mutex<Option<Arc<VpnClient>>> = Mutex::new(None);
static CACHED_CONNECTION: Mutex<Option<Arc<UdpConnection>>> = Mutex::new(None);
/// Uplink channel: Swift TUN packets -> dedicated encrypt+send thread.
static UPLINK_TX: Mutex<Option<crossbeam_channel::Sender<PacketBuf>>> = Mutex::new(None);
/// Downlink channel: decrypted server packets -> Swift TUN.
static DOWNLINK_RX: Mutex<Option<crossbeam_channel::Receiver<PacketBuf>>> = Mutex::new(None);
/// Condvar to wake Swift's readFromRust thread when a packet arrives.
static DOWNLINK_NOTIFY: std::sync::Condvar = std::sync::Condvar::new();
static DOWNLINK_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct TunnelState {
    client: Arc<VpnClient>,
    connection: Arc<UdpConnection>,
    runtime: Runtime,
    shutdown: Arc<AtomicBool>,
    /// JSON-serialized network settings produced after handshake.
    network_settings_json: String,
}

static TUNNEL: Mutex<Option<TunnelState>> = Mutex::new(None);
static REKEY_REQUESTED: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// Provider config deserialization (matches what the Tauri app writes)
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct ProviderCredentials {
    /// Wrapped in `Zeroizing` to mirror the host-app side (audit H8).
    /// The username is privacy-sensitive PII and reaching the JSON via
    /// the FFI is precisely the boundary where we want it wiped on
    /// drop. Without this wrapper, a heap snapshot of the Network
    /// Extension process during a crash dump would still contain the
    /// last login username in clear.
    #[serde(deserialize_with = "deserialize_zeroizing_string")]
    username: zeroize::Zeroizing<String>,
    #[serde(deserialize_with = "deserialize_zeroizing_string")]
    password: zeroize::Zeroizing<String>,
}

fn deserialize_zeroizing_string<'de, D>(
    deserializer: D,
) -> Result<zeroize::Zeroizing<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    let s = String::deserialize(deserializer)?;
    Ok(zeroize::Zeroizing::new(s))
}

#[derive(serde::Deserialize)]
struct ProviderConfig {
    client_config: ClientConfig,
    server_endpoint: String,
    full_tunnel: bool,
    allow_lan: bool,
    #[serde(default)]
    split_routes: Vec<String>,
    credentials: Option<ProviderCredentials>,
}

#[derive(serde::Serialize)]
struct NetworkSettingsOut {
    remote_address: String,
    mtu: u16,
    ipv4_address: String,
    ipv4_netmask: String,
    ipv6_address: Option<String>,
    ipv6_prefix_length: Option<u8>,
    dns_servers: Vec<String>,
    split_routes: Vec<String>,
    full_tunnel: bool,
    allow_lan: bool,
}

// ---------------------------------------------------------------------------
// FFI exports
// ---------------------------------------------------------------------------

/// Verify an HMAC-authenticated provider-config envelope and copy the
/// inner JSON bytes into a caller-provided buffer (audit H15).
///
/// The Swift Packet Tunnel Extension calls this on the bytes it just
/// read from `provider-config.json` in the shared App Group container,
/// passing the 32-byte master key it fetched from the App Group
/// Keychain. Once the JSON is in `out_buf`, the Swift side performs
/// the credential injection (see `injectKeychainCredentials`) and
/// hands the result back to [`hpn_tunnel_start`].
///
/// Splitting verification from `hpn_tunnel_start` keeps the credential
/// flow entirely in Swift — Rust never touches the password, which
/// is exactly the property the post-CRED-1 architecture demands.
///
/// # Wire format
///
/// `envelope_buf` / `envelope_len` MUST be in the layout defined by
/// [`hpn_core::provider_envelope`]: `MAGIC || version || reserved ||
/// HMAC || json_len || json_bytes`.
///
/// `hmac_key_buf` / `hmac_key_len` MUST be exactly 32 bytes (the
/// master Keychain entry).
///
/// # Returns
///
/// - On success: number of JSON bytes written to `out_buf` (always
///   `> 0`, capped by `MAX_PAYLOAD_LEN`).
/// - `-1` if any pointer is null or any length is negative.
/// - `-30` if the envelope is malformed (bad magic, wrong version,
///   truncated buffer, oversized `json_len`, etc.).
/// - `-31` if the HMAC tag does not match — the canonical "tampered
///   provider-config or wrong Keychain entry" error.
/// - `-32` if the caller-provided `out_buf` is smaller than the
///   payload that was about to be written.
///
/// # Safety
///
/// All four pointers are `*const` / `*mut` and must remain valid for
/// the duration of the call. The function performs no aliasing
/// beyond `out_buf`.
#[unsafe(no_mangle)]
pub extern "C" fn hpn_envelope_unwrap_to_buf(
    envelope_buf: *const c_char,
    envelope_len: c_int,
    hmac_key_buf: *const u8,
    hmac_key_len: c_int,
    out_buf: *mut c_char,
    out_buf_len: c_int,
) -> c_int {
    if envelope_buf.is_null()
        || envelope_len <= 0
        || hmac_key_buf.is_null()
        || hmac_key_len <= 0
        || out_buf.is_null()
        || out_buf_len <= 0
    {
        return -1;
    }

    // SAFETY: caller guarantees valid pointers and lengths.
    let envelope_bytes =
        unsafe { std::slice::from_raw_parts(envelope_buf as *const u8, envelope_len as usize) };
    let hmac_key = unsafe { std::slice::from_raw_parts(hmac_key_buf, hmac_key_len as usize) };

    if hmac_key.len() != hpn_core::provider_envelope::MASTER_KEY_LEN {
        error!(
            "hpn_envelope_unwrap_to_buf: hmac_key length is {}, expected {}",
            hmac_key.len(),
            hpn_core::provider_envelope::MASTER_KEY_LEN
        );
        return -31;
    }

    let json_bytes = match hpn_core::provider_envelope::unwrap_payload(hmac_key, envelope_bytes) {
        Ok(b) => b,
        Err(hpn_core::provider_envelope::EnvelopeError::BadHmac) => {
            error!(
                "hpn_envelope_unwrap_to_buf: HMAC verification failed — \
                 provider config has been tampered with or the master \
                 Keychain entry is mismatched"
            );
            return -31;
        }
        Err(e) => {
            error!("hpn_envelope_unwrap_to_buf: envelope parse failed: {}", e);
            return -30;
        }
    };

    if json_bytes.len() > out_buf_len as usize {
        error!(
            "hpn_envelope_unwrap_to_buf: out_buf too small ({} < {})",
            out_buf_len,
            json_bytes.len()
        );
        return -32;
    }

    // SAFETY: out_buf is non-null, capacity-checked, and json_bytes is
    // a non-overlapping live borrow.
    unsafe {
        std::ptr::copy_nonoverlapping(json_bytes.as_ptr(), out_buf as *mut u8, json_bytes.len());
    }
    info!(
        "Provider config envelope verified ({} JSON bytes returned)",
        json_bytes.len()
    );
    json_bytes.len() as c_int
}

/// Start the VPN tunnel engine.
///
/// `config_json` / `config_len`: UTF-8 JSON provider config that has
/// already been envelope-verified and credential-injected by the Swift
/// caller (the App-side host writes an envelope-wrapped JSON; the
/// extension's Swift unwraps via [`hpn_envelope_unwrap_to_buf`],
/// injects the password from Keychain, then calls this function).
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn hpn_tunnel_start(config_json: *const c_char, config_len: c_int) -> c_int {
    if config_json.is_null() || config_len <= 0 {
        return -1;
    }

    // SAFETY: caller guarantees valid pointer + length.
    let json_bytes =
        unsafe { std::slice::from_raw_parts(config_json as *const u8, config_len as usize) };

    start_with_json_bytes(json_bytes)
}

/// Common implementation shared by [`hpn_tunnel_start`]: takes
/// already-validated JSON bytes and drives the connect path.
fn start_with_json_bytes(json_bytes: &[u8]) -> c_int {
    let Ok(json_str) = std::str::from_utf8(json_bytes) else {
        return -2;
    };

    let Ok(provider_config) = serde_json::from_str::<ProviderConfig>(json_str) else {
        return -3;
    };

    let Ok(server_addr) = provider_config.server_endpoint.parse() else {
        return -4;
    };

    let runtime = match Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return -5,
    };

    let result = runtime.block_on(async {
        let (client, _event_rx) =
            VpnClient::new(provider_config.client_config.clone()).map_err(|e| {
                error!("VpnClient::new failed: {}", e);
                -6_i32
            })?;

        let client = Arc::new(client);

        let connection = Arc::new(UdpConnection::connect(server_addr).await.map_err(|e| {
            error!("UdpConnection::connect failed: {}", e);
            -7_i32
        })?);

        let credentials = provider_config.credentials.map(|c| {
            // Use `with_zeroizing_credentials` so neither field has to
            // be unwrapped → re-wrapped (which would materialise a
            // non-zeroized intermediate `String` on the heap). Audit H8.
            hpn_client_core::config::Credentials::with_zeroizing_credentials(c.username, c.password)
        });

        let tunnel_info = client
            .connect_with_credentials(&*connection, credentials)
            .await
            .map_err(|e| {
                error!("Handshake failed: {}", e);
                -8_i32
            })?;

        info!(
            "Handshake completed, tunnel IP: {}",
            tunnel_info.client_ip_str()
        );

        let settings = NetworkSettingsOut {
            remote_address: server_addr.ip().to_string(),
            mtu: tunnel_info.mtu,
            ipv4_address: tunnel_info.client_ip_str(),
            ipv4_netmask: hpn_client_core::TunnelInfo::format_ip(&tunnel_info.netmask),
            ipv6_address: tunnel_info.client_ipv6_str(),
            ipv6_prefix_length: tunnel_info.prefix_len_ipv6,
            dns_servers: tunnel_info
                .dns_servers
                .iter()
                .map(hpn_client_core::TunnelInfo::format_ip)
                .chain(
                    tunnel_info
                        .dns_servers_v6
                        .iter()
                        .map(hpn_client_core::TunnelInfo::format_ipv6),
                )
                .collect(),
            split_routes: provider_config.split_routes.clone(),
            full_tunnel: provider_config.full_tunnel,
            allow_lan: provider_config.allow_lan,
        };

        let network_settings_json = serde_json::to_string(&settings).map_err(|_| -9_i32)?;

        Ok::<_, i32>((client, connection, network_settings_json))
    });

    let (client, connection, network_settings_json) = match result {
        Ok(v) => v,
        Err(code) => return code,
    };

    let (downlink_tx, downlink_rx) = crossbeam_channel::bounded::<PacketBuf>(8192);
    let (uplink_tx, uplink_rx) = crossbeam_channel::bounded::<PacketBuf>(8192);
    let shutdown = Arc::new(AtomicBool::new(false));

    // ── Downlink: server → decrypt → Swift TUN ──────────────────────────────
    {
        let client = Arc::clone(&client);
        let connection = Arc::clone(&connection);
        let shutdown = Arc::clone(&shutdown);
        let tx = downlink_tx;

        runtime.spawn(async move {
            let mut recv_buf = vec![0u8; 65536];
            let mut output_buf = vec![0u8; 65536];

            while !shutdown.load(Ordering::Relaxed) {
                let (len, _addr) = match connection.recv(&mut recv_buf).await {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                if len == 0 {
                    continue;
                }

                match client
                    .process_packet(&recv_buf[..len], &mut output_buf)
                    .await
                {
                    Ok(Some((hpn_core::types::MessageType::Data, out_len))) if out_len > 0 => {
                        let _ = tx.try_send(PacketBuf::new(&output_buf[..out_len]));
                        // Wake the Swift read thread immediately.
                        DOWNLINK_NOTIFY.notify_one();
                    }
                    _ => {}
                }
            }
        });
    }

    // ── Uplink: dedicated thread draining the uplink channel → encrypt → send
    {
        let client = Arc::clone(&client);
        let connection = Arc::clone(&connection);
        let shutdown = Arc::clone(&shutdown);
        let rt_handle = runtime.handle().clone();

        let shutdown_for_err = Arc::clone(&shutdown);
        let spawn_result = std::thread::Builder::new()
            .name("vpn-uplink".into())
            .spawn(move || {
                while !shutdown.load(Ordering::Relaxed) {
                    // Drain up to 64 packets per iteration for batching.
                    let mut batch: Vec<PacketBuf> = Vec::with_capacity(64);
                    match uplink_rx.recv_timeout(std::time::Duration::from_millis(50)) {
                        Ok(pkt) => batch.push(pkt),
                        Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
                        Err(_) => break,
                    }
                    // Drain any additional queued packets (non-blocking).
                    while batch.len() < 64 {
                        match uplink_rx.try_recv() {
                            Ok(pkt) => batch.push(pkt),
                            Err(_) => break,
                        }
                    }

                    // Encrypt + send all packets in one runtime block.
                    let client = Arc::clone(&client);
                    let connection = Arc::clone(&connection);
                    rt_handle.block_on(async {
                        for pkt in &batch {
                            let _ = client.send_data(&*connection, pkt.as_slice()).await;
                        }
                    });
                }
            });
        if let Err(e) = spawn_result {
            tracing::error!("Failed to spawn uplink thread: {}", e);
            shutdown_for_err.store(true, Ordering::SeqCst);
            return -12;
        }
    }

    // ── Keepalive + rekey + auto-reconnect loop ─────────────────────────────
    {
        let client = Arc::clone(&client);
        let connection = Arc::clone(&connection);
        let shutdown = Arc::clone(&shutdown);
        let auto_reconnect = provider_config.client_config.auto_reconnect;

        runtime.spawn(async move {
            let keepalive_secs = provider_config.client_config.keepalive_interval_secs.max(5);
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(keepalive_secs));

            loop {
                interval.tick().await;
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }

                if client.should_send_keepalive() {
                    let _ = client.send_keepalive(&*connection).await;
                }

                if let Some(missed) = client.check_keepalive_timeout() {
                    if client.is_connection_dead() {
                        tracing::warn!(
                            "Connection dead ({} missed keepalives). {}",
                            missed,
                            if auto_reconnect {
                                "Attempting reconnect..."
                            } else {
                                "Giving up."
                            }
                        );

                        if auto_reconnect {
                            match client.attempt_reconnect(&*connection).await {
                                Ok(_) => info!("Auto-reconnect successful"),
                                Err(e) => {
                                    error!("Auto-reconnect failed: {}", e);
                                    break;
                                }
                            }
                        } else {
                            break;
                        }
                    }
                }

                if client.should_rekey() {
                    let _ = client.initiate_rekey(&*connection).await;
                }

                if REKEY_REQUESTED.swap(false, Ordering::SeqCst) {
                    info!("Force rekey requested");
                    let _ = client.initiate_rekey(&*connection).await;
                }
            }
        });
    }

    // ── Store cached handles for lock-free hot path ─────────────────────────
    *CACHED_CLIENT.lock() = Some(Arc::clone(&client));
    *CACHED_CONNECTION.lock() = Some(Arc::clone(&connection));
    *UPLINK_TX.lock() = Some(uplink_tx);
    *DOWNLINK_RX.lock() = Some(downlink_rx);

    let mut slot = TUNNEL.lock();
    *slot = Some(TunnelState {
        client,
        connection,
        runtime,
        shutdown,
        network_settings_json,
    });

    0
}

/// Stop the tunnel engine and release all resources.
#[unsafe(no_mangle)]
pub extern "C" fn hpn_tunnel_stop() -> c_int {
    // Clear cached handles first to stop hot-path access.
    *UPLINK_TX.lock() = None;
    *DOWNLINK_RX.lock() = None;
    *CACHED_CLIENT.lock() = None;
    *CACHED_CONNECTION.lock() = None;
    DOWNLINK_NOTIFY.notify_all();

    let mut slot = TUNNEL.lock();
    if let Some(state) = slot.take() {
        state.shutdown.store(true, Ordering::SeqCst);
        let _ = state
            .runtime
            .block_on(async { state.client.disconnect(&*state.connection).await });
    }
    0
}

/// Copy the JSON network settings (produced after handshake) into the
/// caller-provided buffer.
///
/// Returns the number of bytes written, or negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn hpn_tunnel_get_settings_json(out_buf: *mut c_char, out_buf_len: c_int) -> c_int {
    let slot = TUNNEL.lock();
    let Some(state) = slot.as_ref() else {
        return -1;
    };

    let json = state.network_settings_json.as_bytes();
    if json.len() > out_buf_len as usize {
        return -2;
    }

    // SAFETY: caller owns out_buf with at least out_buf_len bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(json.as_ptr(), out_buf as *mut u8, json.len());
    }

    json.len() as c_int
}

/// Write a packet from Swift (TUN -> server).
///
/// Pushes the packet into the uplink channel. A dedicated thread drains
/// the channel, encrypts, and sends — no mutex or tokio spawn per packet.
#[unsafe(no_mangle)]
pub extern "C" fn hpn_tunnel_write_packets(buf: *const u8, len: c_int) -> c_int {
    if buf.is_null() || len <= 0 {
        return -1;
    }

    // Fast path: read the cached uplink sender (set once at start).
    let tx = {
        let guard = UPLINK_TX.lock();
        match guard.as_ref() {
            Some(tx) => tx.clone(),
            None => return -2,
        }
    };

    // SAFETY: caller guarantees valid pointer + length.
    let data = unsafe { std::slice::from_raw_parts(buf, len as usize) };
    let _ = tx.try_send(PacketBuf::new(data));

    0
}

/// Read a decrypted packet from the Rust engine (server -> TUN).
///
/// If no packet is available, blocks up to 5ms (condvar) instead of
/// busy-polling. Returns the packet length, 0 if timeout, or negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn hpn_tunnel_read_packets(buf: *mut u8, buf_len: c_int) -> c_int {
    if buf.is_null() || buf_len <= 0 {
        return -1;
    }

    let rx = {
        let guard = DOWNLINK_RX.lock();
        match guard.as_ref() {
            Some(rx) => rx.clone(),
            None => return -2,
        }
    };

    // Try non-blocking first (fast path).
    match rx.try_recv() {
        Ok(packet) => {
            let pkt = packet.as_slice();
            let copy_len = pkt.len().min(buf_len as usize);
            unsafe {
                std::ptr::copy_nonoverlapping(pkt.as_ptr(), buf, copy_len);
            }
            return copy_len as c_int;
        }
        Err(crossbeam_channel::TryRecvError::Disconnected) => return -3,
        Err(crossbeam_channel::TryRecvError::Empty) => {}
    }

    // No packet available — wait up to 5ms on condvar (avoids busy-polling).
    let lock = DOWNLINK_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _guard = DOWNLINK_NOTIFY
        .wait_timeout(lock, std::time::Duration::from_millis(5))
        .unwrap_or_else(|e| e.into_inner());

    // Try again after wakeup.
    match rx.try_recv() {
        Ok(packet) => {
            let pkt = packet.as_slice();
            let copy_len = pkt.len().min(buf_len as usize);
            unsafe {
                std::ptr::copy_nonoverlapping(pkt.as_ptr(), buf, copy_len);
            }
            copy_len as c_int
        }
        Err(_) => 0,
    }
}

/// Get tunnel stats as JSON into caller buffer.
/// Returns bytes written, or negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn hpn_tunnel_get_stats_json(out_buf: *mut c_char, out_buf_len: c_int) -> c_int {
    if out_buf.is_null() || out_buf_len <= 0 {
        return -1;
    }

    let client_stats = {
        let slot = TUNNEL.lock();
        slot.as_ref().map(|state| state.client.stats())
    };

    let stats = if let Some(cs) = client_stats {
        serde_json::json!({
            "tx": cs.bytes_sent,
            "rx": cs.bytes_received,
            "packets_tx": cs.packets_sent,
            "packets_rx": cs.packets_received,
            "rtt_us": cs.rtt_ms * 1000,
            "session_key": format!("{:016x}-k{}", cs.session_id, cs.key_id),
        })
    } else {
        serde_json::json!({
            "tx": 0, "rx": 0, "packets_tx": 0, "packets_rx": 0,
            "rtt_us": 0, "session_key": "",
        })
    };

    let json = stats.to_string();
    let bytes = json.as_bytes();
    if bytes.len() > out_buf_len as usize {
        return -2;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf as *mut u8, bytes.len());
    }
    bytes.len() as c_int
}

/// Request a force rekey. The keepalive loop will pick it up.
#[unsafe(no_mangle)]
pub extern "C" fn hpn_tunnel_force_rekey() -> c_int {
    REKEY_REQUESTED.store(true, Ordering::SeqCst);
    0
}

/// Notify the tunnel engine that the system is going to sleep.
///
/// Called from Swift `PacketTunnelProvider.sleep(completionHandler:)`.
/// The extension is about to be frozen; we do not tear down the tunnel
/// (that would force a full handshake on every wake — painful UX when
/// the laptop wakes just long enough to check mail). We just log the
/// event and let the keepalive loop go quiet until `hpn_tunnel_on_wake`
/// is called.
///
/// Returns 0 unconditionally. Never blocks.
#[unsafe(no_mangle)]
pub extern "C" fn hpn_tunnel_on_sleep() -> c_int {
    info!("macOS sleep notification received — keepalives will naturally pause");
    0
}

/// Notify the tunnel engine that the system just woke from sleep.
///
/// Called from Swift `PacketTunnelProvider.wake()`. On macOS the kernel
/// frequently invalidates UDP sockets during deep sleep: our handle
/// still looks valid (`local_addr()` returns the old port), but the
/// next `send_to` fails with ENETUNREACH / EBADF and the keepalive
/// loop has to run its full 3× RTO (~90 s by default) before it gives
/// up and triggers reconnection. That is a miserable UX.
///
/// This entry point shortcuts that detection by:
///   1. flipping `REKEY_REQUESTED` so the next keepalive produces a
///      fresh handshake exchange, and
///   2. rebinding the UDP socket to a fresh ephemeral port right now,
///      so the rekey packets go out on a kernel-valid fd.
///
/// Returns 0 on success, -1 if no tunnel is running or rebind failed.
/// Never panics (errors are logged and translated to the return code).
#[unsafe(no_mangle)]
pub extern "C" fn hpn_tunnel_on_wake() -> c_int {
    info!("macOS wake notification received — rebinding UDP socket + forcing rekey");

    // Always request rekey: even if rebind fails (e.g., network not up
    // yet), a later keepalive will pick the flag up once connectivity
    // returns.
    REKEY_REQUESTED.store(true, Ordering::SeqCst);

    let connection = match CACHED_CONNECTION.lock().as_ref() {
        Some(c) => Arc::clone(c),
        None => {
            info!("No cached connection; tunnel not running — wake handler is a no-op");
            return 0;
        }
    };

    // Run the async rebind on the tunnel's tokio runtime. We cannot
    // `.await` from a C-ABI function, so `block_on` on the existing
    // runtime handle is the right primitive here. The rebind itself is
    // fast (one `bind()` syscall + two `Arc::swap` equivalents).
    let runtime_handle = {
        let guard = TUNNEL.lock();
        match guard.as_ref() {
            Some(state) => state.runtime.handle().clone(),
            None => {
                // Race: CACHED_CONNECTION existed but TUNNEL is gone.
                // Swift can call wake() during teardown; treat as no-op.
                info!("TUNNEL state already cleared — wake handler skipped");
                return 0;
            }
        }
    };

    match runtime_handle.block_on(connection.rebind()) {
        Ok(()) => {
            info!("UDP socket rebound successfully after wake");
            0
        }
        Err(e) => {
            error!("UDP socket rebind after wake failed: {}", e);
            -1
        }
    }
}

/// Free a string allocated by this library (unused for now, reserved).
#[unsafe(no_mangle)]
pub extern "C" fn hpn_tunnel_free_string(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let _ = std::ffi::CString::from_raw(ptr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hpn_core::provider_envelope;

    fn fresh_master_key() -> [u8; provider_envelope::MASTER_KEY_LEN] {
        // Deterministic for reproducible tests; production uses
        // SecRandomCopyBytes via Swift.
        [0x42u8; provider_envelope::MASTER_KEY_LEN]
    }

    #[test]
    fn test_unwrap_to_buf_round_trips_valid_envelope() {
        let key = fresh_master_key();
        let json = br#"{"server_endpoint":"203.0.113.10:51820"}"#;
        let envelope = provider_envelope::wrap(&key, json).unwrap();
        let mut out = vec![0i8; 4096];

        let n = hpn_envelope_unwrap_to_buf(
            envelope.as_ptr() as *const c_char,
            envelope.len() as c_int,
            key.as_ptr(),
            key.len() as c_int,
            out.as_mut_ptr(),
            out.len() as c_int,
        );

        assert!(n > 0, "expected positive length, got {n}");
        assert_eq!(n as usize, json.len());
        let written = unsafe { std::slice::from_raw_parts(out.as_ptr() as *const u8, n as usize) };
        assert_eq!(written, json);
    }

    #[test]
    fn test_unwrap_to_buf_rejects_null_pointers() {
        let key = fresh_master_key();
        let mut out = vec![0i8; 64];
        // Null envelope buf
        let n = hpn_envelope_unwrap_to_buf(
            std::ptr::null(),
            10,
            key.as_ptr(),
            32,
            out.as_mut_ptr(),
            64,
        );
        assert_eq!(n, -1);

        // Null hmac key buf
        let dummy = [0u8; 64];
        let n = hpn_envelope_unwrap_to_buf(
            dummy.as_ptr() as *const c_char,
            64,
            std::ptr::null(),
            32,
            out.as_mut_ptr(),
            64,
        );
        assert_eq!(n, -1);

        // Null out buf
        let n = hpn_envelope_unwrap_to_buf(
            dummy.as_ptr() as *const c_char,
            64,
            key.as_ptr(),
            32,
            std::ptr::null_mut(),
            64,
        );
        assert_eq!(n, -1);
    }

    #[test]
    fn test_unwrap_to_buf_rejects_wrong_key_size() {
        let envelope = provider_envelope::wrap(&fresh_master_key(), b"hi").unwrap();
        let bad_key = [0u8; 16]; // 16 bytes, not 32
        let mut out = [0i8; 64];

        let n = hpn_envelope_unwrap_to_buf(
            envelope.as_ptr() as *const c_char,
            envelope.len() as c_int,
            bad_key.as_ptr(),
            bad_key.len() as c_int,
            out.as_mut_ptr(),
            out.len() as c_int,
        );
        assert_eq!(n, -31);
    }

    #[test]
    fn test_unwrap_to_buf_rejects_tampered_envelope() {
        let key = fresh_master_key();
        let mut envelope = provider_envelope::wrap(&key, b"hello world").unwrap();
        let last = envelope.len() - 1;
        envelope[last] ^= 0xFF; // flip last byte of payload
        let mut out = vec![0i8; 64];

        let n = hpn_envelope_unwrap_to_buf(
            envelope.as_ptr() as *const c_char,
            envelope.len() as c_int,
            key.as_ptr(),
            key.len() as c_int,
            out.as_mut_ptr(),
            out.len() as c_int,
        );
        assert_eq!(n, -31);
    }

    #[test]
    fn test_unwrap_to_buf_rejects_bad_magic() {
        let key = fresh_master_key();
        let mut envelope = provider_envelope::wrap(&key, b"hello").unwrap();
        envelope[0] = b'X'; // break magic
        let mut out = vec![0i8; 64];

        let n = hpn_envelope_unwrap_to_buf(
            envelope.as_ptr() as *const c_char,
            envelope.len() as c_int,
            key.as_ptr(),
            key.len() as c_int,
            out.as_mut_ptr(),
            out.len() as c_int,
        );
        assert_eq!(n, -30);
    }

    #[test]
    fn test_unwrap_to_buf_rejects_short_output_buffer() {
        let key = fresh_master_key();
        let json = b"this is more than four bytes";
        let envelope = provider_envelope::wrap(&key, json).unwrap();
        let mut tiny_out = vec![0i8; 4]; // smaller than payload

        let n = hpn_envelope_unwrap_to_buf(
            envelope.as_ptr() as *const c_char,
            envelope.len() as c_int,
            key.as_ptr(),
            key.len() as c_int,
            tiny_out.as_mut_ptr(),
            tiny_out.len() as c_int,
        );
        assert_eq!(n, -32);
    }

    #[test]
    fn test_unwrap_to_buf_with_wrong_key_does_not_leak_payload() {
        // Audit H15 invariant: `hpn_envelope_unwrap_to_buf` must NOT
        // touch `out_buf` when verification fails. We pre-fill the
        // output buffer with a known sentinel pattern (0xCC) and
        // assert every byte still equals the sentinel after the
        // failed call. This is strictly stronger than the previous
        // test which started from zeros and only checked the *full*
        // payload didn't appear — a partial copy of, say, the first
        // 8 bytes would have slipped through.
        const SENTINEL: u8 = 0xCC;
        let json = b"sensitive payload";
        let real_key = fresh_master_key();
        let envelope = provider_envelope::wrap(&real_key, json).unwrap();

        let bad_key = [0xA5u8; 32];
        let out_len = 64usize;
        // Use u8 buffer (sentinel is u8) and cast to *mut c_char at
        // the FFI boundary — c_char is i8 on most platforms but the
        // bit pattern of 0xCC survives the reinterpret unchanged.
        let mut out = vec![SENTINEL; out_len];
        let n = hpn_envelope_unwrap_to_buf(
            envelope.as_ptr() as *const c_char,
            envelope.len() as c_int,
            bad_key.as_ptr(),
            bad_key.len() as c_int,
            out.as_mut_ptr() as *mut c_char,
            out_len as c_int,
        );
        assert_eq!(n, -31);

        // Strict invariant: every single byte of out_buf must be
        // unchanged. ring's `hmac::verify` runs in constant time
        // and returns Err BEFORE we copy_nonoverlapping; this
        // assertion locks that ordering down so a future refactor
        // that splits verification from the buffer write would
        // immediately flunk this test.
        assert!(
            out.iter().all(|&b| b == SENTINEL),
            "out_buf was modified despite HMAC verification failure"
        );
    }
}
