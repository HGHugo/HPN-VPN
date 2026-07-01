//! HPN VPN Windows Desktop Client - Tauri Application
//!
//! This is the main entry point for the Windows desktop client.
//! It provides a Tauri-based GUI that connects to the HPN VPN backend.

#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
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
#[cfg(windows)]
mod dpapi;
mod error;
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
use tracing::{Level, info, warn};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use state::{AppState, ConnectionStatus, LogLevel};

#[cfg(windows)]
use hpn_client_windows::RecoveryState;

fn main() {
    // Initialize logging - write to file for debugging
    // Use DEBUG in debug builds, INFO in release builds
    let log_level = if cfg!(debug_assertions) {
        Level::DEBUG
    } else {
        Level::INFO
    };

    // Create log file in temp directory
    let log_path = std::env::temp_dir().join("hpn-client-debug.log");
    let file_logging_ready = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    {
        Ok(log_file) => {
            let stdout_layer = fmt::layer()
                .with_writer(std::io::stdout)
                .with_target(false)
                .compact();
            let file_layer = fmt::layer()
                .with_writer(Arc::new(log_file))
                .with_ansi(false)
                .with_target(true)
                .with_thread_ids(true)
                .with_line_number(true);

            tracing_subscriber::registry()
                .with(EnvFilter::from_default_env().add_directive(log_level.into()))
                .with(file_layer)
                .with(stdout_layer)
                .init();
            true
        }
        Err(e) => {
            let stdout_layer = fmt::layer()
                .with_writer(std::io::stdout)
                .with_target(false)
                .compact();
            tracing_subscriber::registry()
                .with(EnvFilter::from_default_env().add_directive(log_level.into()))
                .with(stdout_layer)
                .init();
            warn!(
                "Failed to open log file {}: {}. Continuing with stdout logging only.",
                log_path.display(),
                e
            );
            false
        }
    };

    info!("Starting HPN VPN Windows Client");
    if file_logging_ready {
        info!("Debug logs writing to: {}", log_path.display());
    }

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_notification::init())
        // Audit H14: signed Tauri updater. The pubkey lives in
        // `tauri.conf.json::plugins.updater.pubkey` and is enforced
        // by the plugin on every downloaded artefact.
        .plugin(tauri_plugin_updater::Builder::new().build())
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

            // Check for and perform recovery if needed (crash recovery).
            // Uses check_and_perform_recovery() to avoid TOCTOU race.
            #[cfg(windows)]
            let recovery_was_needed = match RecoveryState::check_and_perform_recovery() {
                Ok(true) => {
                    info!("Network recovery completed successfully after unclean shutdown");
                    true
                }
                Ok(false) => false,
                Err(e) => {
                    warn!("Network recovery completed with errors: {}", e);
                    true
                }
            };
            #[cfg(not(windows))]
            let recovery_was_needed = false;

            // Audit H14 (auto-check at launch): spawn a background
            // task that hits the updater endpoint 3 s after the
            // window first paints. Mirror of the macOS sibling — see
            // `hpn-ui-macos/src/main.rs` for the full rationale.
            //
            // Windows-specific: if the user has minimised the app
            // to the tray before the check completes, the popup
            // will appear the next time they click the tray icon to
            // show the window. We deliberately do NOT force
            // `window.show()` here — surfacing a window unexpectedly
            // from the tray on Windows is jarring and would override
            // the user's explicit choice to hide.
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

            // Load saved profiles and settings
            let state = app.state::<Arc<RwLock<AppState>>>();
            {
                let mut state_guard = state.write();
                info!(
                    "Initial status before load_config: {:?}",
                    state_guard.status
                );
                if let Err(e) = state_guard.load_config() {
                    tracing::warn!("Failed to load config: {}", e);
                }
                info!("Status after load_config: {:?}", state_guard.status);

                // Log recovery status to UI
                if recovery_was_needed {
                    state_guard.add_log(
                        LogLevel::Info,
                        "Network settings restored after unexpected shutdown",
                    );
                }
            }

            // Build system tray menu
            let show_item = MenuItemBuilder::with_id("show", "Open HPN VPN").build(app)?;
            let separator1 = tauri::menu::PredefinedMenuItem::separator(app)?;
            let status_item =
                MenuItemBuilder::with_id("status", "Status: Disconnected").build(app)?;
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

            // Build system tray with menu and event handlers
            let icon = app
                .default_window_icon()
                .cloned()
                .ok_or_else(|| tauri::Error::AssetNotFound("window icon".to_string()))?;
            let _tray = TrayIconBuilder::with_id("main")
                .icon(icon)
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
                            // Check if connected before quitting
                            let state = app.state::<Arc<RwLock<AppState>>>();
                            let status = state.read().status;

                            if status == ConnectionStatus::Connected
                                || status == ConnectionStatus::Connecting
                                || status == ConnectionStatus::Reconnecting
                            {
                                // Disconnect first, then quit
                                let state_clone = state.inner().clone();
                                let app_handle = app.clone();
                                tauri::async_runtime::spawn(async move {
                                    // Send shutdown signal
                                    let shutdown_tx = {
                                        let mut state = state_clone.write();
                                        state.shutdown_tx.take()
                                    };
                                    if let Some(tx) = shutdown_tx {
                                        let _ = tx.send(()).await;
                                        // Wait for cleanup to complete (routes/DNS restoration)
                                        // The RouteManager and DnsLeakProtection Drop handlers need time
                                        tokio::time::sleep(tokio::time::Duration::from_secs(2))
                                            .await;
                                    }
                                    app_handle.exit(0);
                                });
                            } else {
                                app.exit(0);
                            }
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
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                // Hide to tray instead of closing
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .run(tauri::generate_context!())
        .unwrap_or_else(|e| {
            tracing::error!("Failed to run Tauri application: {}", e);
            std::process::exit(1);
        });
}
