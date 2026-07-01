//! HPN VPN macOS Desktop Client - Tauri Application
//!
//! This is the main entry point for the macOS desktop client.
//! It provides a Tauri-based GUI that connects to the HPN VPN backend.

#![cfg_attr(
    all(not(debug_assertions), target_os = "macos"),
    windows_subsystem = "windows"
)]
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
// Crate-specific:
#![allow(clippy::derivable_impls)]

mod commands;
mod config;
mod error;
mod keychain;
mod native_vpn;
mod state;
mod updater;
mod validation;

use parking_lot::RwLock;
use std::sync::Arc;
use tauri::{
    Emitter, Manager,
    menu::{MenuBuilder, MenuItemBuilder},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
};
use tracing::{Level, info};
use tracing_subscriber::FmtSubscriber;

use state::AppState;

fn main() {
    // Initialize logging - INFO level for production, DEBUG for dev builds
    let log_level = if cfg!(debug_assertions) {
        Level::DEBUG
    } else {
        Level::INFO
    };

    FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .compact()
        .init();

    info!("Starting HPN VPN macOS Client");

    // Disconnect VPN on any process exit (SIGTERM, SIGINT, normal exit).
    let _ = ctrlc::set_handler(|| {
        let _ = std::process::Command::new("scutil")
            .args(["--nc", "stop", "HPN VPN"])
            .status();
        std::process::exit(0);
    });

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_notification::init())
        // Audit H14: signed Tauri updater. The pubkey lives in
        // `tauri.conf.json::plugins.updater.pubkey` and is enforced
        // by the plugin on every downloaded artefact.
        .plugin(tauri_plugin_updater::Builder::new().build())
        // Required by the updater install flow on Windows; harmless
        // on macOS but kept symmetric with the Windows build for
        // a uniform `relaunch()` API on the JS side.
        .plugin(tauri_plugin_process::init())
        .manage(Arc::new(RwLock::new(AppState::new())))
        .manage(tokio::sync::Mutex::new(()))
        .manage(updater::PendingUpdate::default())
        .invoke_handler(tauri::generate_handler![
            commands::connect,
            commands::connect_with_auth,
            commands::disconnect,
            commands::get_status,
            commands::get_stats,
            commands::get_profiles,
            commands::save_profile,
            commands::delete_profile,
            commands::get_settings,
            commands::save_settings,
            commands::force_rekey,
            commands::get_logs,
            commands::clear_logs,
            commands::export_logs,
            updater::check_for_updates,
            updater::install_update,
        ])
        .setup(|app| {
            info!("HPN VPN Client initialized");

            // Clear any stale state left by a prior unclean shutdown.
            //
            // The `NETunnelProviderManager`-based tunnel (see
            // `native_vpn.rs` and the Packet Tunnel Extension) stores
            // its own recovery state in the system — macOS itself
            // tears the tunnel down cleanly if we crash, so there is
            // no per-app network state to restore. We only need to
            // scrub transient files that may still contain sensitive
            // data (provider-config with credentials, stats).
            //
            // Historically this block also called
            // `hpn_client_macos::RecoveryState::check_and_perform_recovery`,
            // which was designed for a pre-NetworkExtension CLI path
            // that manipulated PF rules and host routes directly. That
            // path is no longer invoked by any connect flow, so the
            // recovery file is never written during normal operation;
            // the call was at best a no-op and at worst could re-
            // apply stale PF / route fragments from a very old
            // install. It has been removed; the `hpn-client-macos`
            // crate remains on the workspace for the CLI-only build
            // but is no longer a runtime dependency of the Tauri app.
            commands::clear_provider_config_full();
            commands::clear_tunnel_temp_files();

            // Audit H14 (auto-check at launch): spawn a background
            // task that hits the updater endpoint 3 s after the
            // window first paints, so the user's first interactive
            // moment is not blocked by an HTTP round-trip. When an
            // update is found, the task stashes the `Update` handle
            // in `PendingUpdate` state and emits an
            // `update-available` event with the metadata; the React
            // side listens for that event and renders the popup
            // modal.
            //
            // The 3 s delay is empirical — enough to let the WebView
            // load and the tray icon to appear, short enough that an
            // update is surfaced before the user dismisses the app
            // and forgets about it. On a slow network,
            // `updater().check()` may take longer than 3 s itself;
            // the popup simply appears whenever the request
            // completes.
            //
            // Failures (network down, manifest parse error,
            // signature mismatch, ...) are logged at `warn!` and
            // silently swallowed — the user does NOT need an error
            // toast for a background check that failed. The next
            // launch will retry.
            let app_handle_for_updater = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;

                match updater::perform_check(&app_handle_for_updater).await {
                    Ok(Some(metadata)) => {
                        if let Err(e) = app_handle_for_updater.emit("update-available", &metadata) {
                            tracing::warn!(
                                "auto-check: failed to emit update-available event: {}",
                                e
                            );
                        }
                    }
                    Ok(None) => tracing::info!("auto-check: already up-to-date"),
                    Err(e) => tracing::warn!("auto-check: update check failed: {}", e),
                }
            });

            // Background stats poller.
            //
            // ARCHITECTURAL NOTE: the React UI polls `get_stats` at
            // ~1 Hz to refresh the RX/TX/Latency/Rate widgets in the
            // status pane. Each call ultimately needs to round-trip
            // to the Packet Tunnel Extension via
            // `NETunnelProviderSession.sendProviderMessage`, which
            // includes a synchronous `loadAllFromPreferences` step
            // that can take 100-300 ms on Tahoe (system-wide query
            // hitting `/Library/Preferences/com.apple.networkextension.plist`).
            //
            // Doing this round-trip on the React-facing Tauri command
            // thread blocks the UI for the duration of every poll —
            // visible to the user as a 250 ms freeze every second.
            //
            // Solution: a dedicated background thread polls the FFI
            // every ~1 s and updates the in-process stats cache (see
            // `native_vpn::get_tunnel_stats_json`). React's
            // `get_stats` command reads ONLY the cache, never the
            // FFI directly, so it returns instantly. The user sees
            // a smooth UI with stats refreshing at the poller's
            // cadence.
            //
            // Cost when disconnected: the FFI returns -2 (no manager)
            // in <5 ms; this thread is idle the rest of the second.
            // Negligible.
            std::thread::Builder::new()
                .name("hpn-stats-poller".to_string())
                .spawn(|| {
                    loop {
                        // Fire-and-forget — the cache is updated as
                        // a side effect inside `get_tunnel_stats_json`.
                        let _ = native_vpn::get_tunnel_stats_json();
                        std::thread::sleep(std::time::Duration::from_secs(1));
                    }
                })
                .expect("failed to spawn stats poller thread");

            // Load saved profiles and settings
            let state = app.state::<Arc<RwLock<AppState>>>();
            if let Err(e) = state.write().load_config() {
                tracing::warn!("Failed to load config: {}", e);
            }

            // Build system tray menu
            let show_item = MenuItemBuilder::with_id("show", "Open HPN VPN").build(app)?;
            let separator1 = tauri::menu::PredefinedMenuItem::separator(app)?;
            let status_item =
                MenuItemBuilder::with_id("status", "Status: Disconnected").build(app)?;
            // Store the status menu item for tray updates from commands.
            let _ = commands::TRAY_STATUS_ITEM.set(status_item.clone());
            let separator2 = tauri::menu::PredefinedMenuItem::separator(app)?;
            let quit_item = MenuItemBuilder::with_id("quit", "Quit").build(app)?;

            let menu = MenuBuilder::new(app)
                .items(&[
                    &show_item,
                    &separator1,
                    &status_item,
                    &separator2,
                    &quit_item,
                ])
                .build()?;

            // Build system tray with menu and event handlers.
            // Use the round logo for the tray icon (different from the app icon).
            let tray_icon = {
                let png_bytes = include_bytes!("../icons/tray-icon.png");
                let decoder = png::Decoder::new(std::io::Cursor::new(png_bytes.as_slice()));
                if let Ok(reader) = decoder.read_info() {
                    let mut reader = reader;
                    let mut buf = vec![0u8; reader.output_buffer_size()];
                    if let Ok(info) = reader.next_frame(&mut buf) {
                        buf.truncate(info.buffer_size());
                        tauri::image::Image::new_owned(buf, info.width, info.height)
                    } else {
                        app.default_window_icon().cloned().expect("No default icon")
                    }
                } else {
                    app.default_window_icon().cloned().expect("No default icon")
                }
            };
            let _tray = TrayIconBuilder::with_id("main")
                .icon(tray_icon)
                .tooltip("HPN VPN - Disconnected")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(move |app, event| {
                    match event.id().as_ref() {
                        "show" => {
                            // Show and focus the main window
                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.unminimize();
                                let _ = window.show();
                                let _ = window.set_focus();
                            }
                        }
                        "quit" => {
                            // Stop VPN in a separate thread, then exit.
                            let app_handle = app.clone();
                            std::thread::spawn(move || {
                                let _ = std::process::Command::new("scutil")
                                    .args(["--nc", "stop", "HPN VPN"])
                                    .status();
                                std::thread::sleep(std::time::Duration::from_secs(1));
                                app_handle.exit(0);
                            });
                        }
                        _ => {}
                    }
                })
                .on_tray_icon_event(|tray, event| {
                    // Left click opens the window
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.unminimize();
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                })
                .build(app)?;

            Ok(())
        })
        .on_window_event(|_window, event| {
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                // On macOS, closing the window quits the app and disconnects VPN.
                let _ = std::process::Command::new("scutil")
                    .args(["--nc", "stop", "HPN VPN"])
                    .status();
            }
        })
        .build(tauri::generate_context!())
        .unwrap_or_else(|e| {
            tracing::error!("Failed to build Tauri application: {}", e);
            std::process::exit(1);
        })
        .run(|_app, event| match event {
            tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit => {
                let _ = std::process::Command::new("scutil")
                    .args(["--nc", "stop", "HPN VPN"])
                    .status();
            }
            _ => {}
        });
}
