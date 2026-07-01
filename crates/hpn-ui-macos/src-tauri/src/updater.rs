//! Tauri updater integration (audit H14).
//!
//! Wraps `tauri-plugin-updater` so the React frontend can drive the
//! check / download / install flow through plain Tauri commands. The
//! updater plugin itself enforces the minisign signature on every
//! downloaded artefact (see `tauri.conf.json::plugins.updater.pubkey`),
//! so even an attacker who controls the update endpoint URL — DNS
//! hijack, BGP, malicious mirror, compromised CDN — cannot push a
//! payload that the user's installed binary will accept.
//!
//! # Threat model
//!
//! 1. The host app validates the embedded `pubkey` against every
//!    downloaded `.sig` file BEFORE the installer runs. The pubkey is
//!    baked into the signed `.exe` / `.app` bundle, so an attacker
//!    that swaps it has already broken Authenticode / Apple
//!    Notarisation — at which point the user has bigger problems
//!    than the updater path.
//!
//! 2. The updater endpoint MUST be HTTPS. Tauri rejects HTTP unless
//!    the explicit `dangerousInsecureTransportProtocol = true` flag
//!    is set in the config (which we never do). HTTPS termination
//!    happens at the operator-controlled `pkg.hpn.hmsx.io` reverse
//!    proxy (see OPERATIONS.md §8) which presents a Cloudflare Origin
//!    Certificate.
//!
//! 3. The updater **never** auto-installs without explicit consent.
//!    The frontend is expected to surface the available version, the
//!    release notes, and a `Install update` button; this module
//!    exposes the discrete steps so the UI can sequence them.
//!
//! # Why not call `app.updater()?.check().await?` directly?
//!
//! That would force the React side to depend on Tauri's JS plugin
//! implementation details (Channel events, etc.). Wrapping the flow
//! in our own commands keeps the IPC surface stable across plugin
//! version bumps and lets us add HPN-specific telemetry / logging in
//! one place.

use serde::Serialize;
use tauri::ipc::Channel;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_updater::{Update, UpdaterExt};
use tracing::{info, warn};

/// Holder for the most recently fetched [`Update`].
///
/// The fetch step is separate from the install step so the frontend
/// can render release notes / version diff before the user commits
/// to a download. The update has its own internal HTTP client so we
/// keep ownership in this State container until install.
pub struct PendingUpdate(pub parking_lot::Mutex<Option<Update>>);

impl PendingUpdate {
    #[must_use]
    pub fn new() -> Self {
        Self(parking_lot::Mutex::new(None))
    }
}

impl Default for PendingUpdate {
    fn default() -> Self {
        Self::new()
    }
}

/// Lightweight metadata returned to the frontend after a successful
/// update check. We deliberately do NOT return the `Update` itself —
/// the type is plugin-private, not `Send`-safe across IPC, and the
/// frontend doesn't need anything beyond the version diff.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateMetadata {
    /// Version string of the available update (e.g. `"0.2.0"`).
    pub version: String,
    /// Currently-installed version, for the frontend to display
    /// "0.1.0 → 0.2.0".
    pub current_version: String,
    /// Optional release notes (RFC-3339-formatted dates, free text).
    pub notes: Option<String>,
}

/// Progress event streamed to the frontend during `install_update`.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "event", content = "data")]
pub enum DownloadEvent {
    /// Download just started; `content_length` may be `None` if the
    /// server did not include a `Content-Length` header.
    #[serde(rename_all = "camelCase")]
    Started {
        /// Total content length in bytes, when known.
        content_length: Option<u64>,
    },
    /// One chunk written. The frontend accumulates `chunk_length`
    /// against `content_length` to show a progress bar.
    #[serde(rename_all = "camelCase")]
    Progress {
        /// Bytes added since the previous `Progress` event.
        chunk_length: usize,
    },
    /// Download finished; the installer is about to run (and on
    /// Windows, the app will exit shortly after this event).
    Finished,
}

/// Errors surfaced over the IPC boundary. We map the plugin's
/// internal error type to a single `String` to keep the JS side
/// schema simple.
#[derive(Debug)]
pub struct UpdaterError(String);

impl std::fmt::Display for UpdaterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for UpdaterError {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

// Specific `From` impls (a blanket `impl<E: Display>` would conflict
// with `impl<T> From<T> for T` in std).
impl From<tauri_plugin_updater::Error> for UpdaterError {
    fn from(e: tauri_plugin_updater::Error) -> Self {
        Self(e.to_string())
    }
}

impl From<tauri::Error> for UpdaterError {
    fn from(e: tauri::Error) -> Self {
        Self(e.to_string())
    }
}

/// Internal helper that performs the actual update check.
///
/// Extracted from [`check_for_updates`] so the same logic can be
/// invoked from the [`tauri::Builder::setup`] block at app launch
/// (auto-check) without going through the IPC layer. The Tauri
/// command is a thin wrapper around this function.
///
/// On success with a fresh update, the [`Update`] handle is stashed
/// in the [`PendingUpdate`] state (resolved via [`AppHandle::state`])
/// so a subsequent [`install_update`] call can pick it up.
///
/// Audit H14-F1: the pending slot is overwritten ONLY when a fresh
/// update was returned. If the user clicks "check" twice and the
/// second request comes back as 204 (e.g. transient CDN issue
/// resolves between the calls), keeping the first manifest in the
/// slot lets the subsequent `install_update` succeed instead of
/// erroring with "no pending update". `None` simply leaves the
/// slot untouched.
pub async fn perform_check(app: &AppHandle) -> Result<Option<UpdateMetadata>, UpdaterError> {
    let updater = app.updater().map_err(UpdaterError::from)?;
    let result = updater.check().await.map_err(UpdaterError::from)?;

    let metadata = result.as_ref().map(|update| UpdateMetadata {
        version: update.version.clone(),
        current_version: update.current_version.clone(),
        // The plugin exposes notes as Option<String>.
        notes: update.body.clone(),
    });

    if let Some(ref m) = metadata {
        info!(
            "Update available: current={} -> latest={}",
            m.current_version, m.version
        );
    } else {
        info!("No update available");
    }

    if let Some(update) = result {
        let state = app.state::<PendingUpdate>();
        *state.0.lock() = Some(update);
    }
    Ok(metadata)
}

/// Check the configured `endpoints` for an update strictly newer
/// than the installed version.
///
/// Returns `Ok(None)` when the user is already on the latest version
/// (the server replied 204), `Ok(Some(metadata))` when an update is
/// available (the [`Update`] handle is stashed in `PendingUpdate`
/// state for a follow-up [`install_update`] call), or an error when
/// the request itself failed (network, malformed manifest, signature
/// mismatch on the manifest, ...).
///
/// The `_pending` argument is kept for backwards compatibility with
/// the previous command signature but is unused — the state is
/// resolved via [`AppHandle::state`] inside [`perform_check`]. The
/// JS-side IPC contract is unchanged.
#[tauri::command]
pub async fn check_for_updates(
    app: AppHandle,
    _pending: State<'_, PendingUpdate>,
) -> Result<Option<UpdateMetadata>, UpdaterError> {
    info!("check_for_updates: hitting configured updater endpoints");
    perform_check(&app).await
}

/// Download AND install the update previously cached by
/// [`check_for_updates`]. `on_event` is a Tauri channel the frontend
/// uses to render a progress bar.
///
/// On Windows, the running process exits as part of the install step
/// (see Tauri docs for the underlying limitation). On macOS the
/// install just unpacks the new bundle and returns; the caller
/// invokes the [`tauri_plugin_process`] `relaunch` command to swap
/// in the new binary.
#[tauri::command]
pub async fn install_update(
    pending: State<'_, PendingUpdate>,
    on_event: Channel<DownloadEvent>,
) -> Result<(), UpdaterError> {
    let update = match pending.0.lock().take() {
        Some(u) => u,
        None => {
            warn!("install_update called with no pending update");
            return Err(UpdaterError(
                "no pending update — call check_for_updates first".into(),
            ));
        }
    };

    info!("install_update: starting download + install");

    // The plugin's progress callbacks are invoked synchronously
    // from the download task. We use an `AtomicBool` (not `Cell`)
    // so the closure stays `Send` across the tokio runtime boundary,
    // and we clone `on_event` once per closure since `Channel` is
    // cheaply cloneable (Arc-backed under the hood).
    use std::sync::atomic::{AtomicBool, Ordering};
    let started = std::sync::Arc::new(AtomicBool::new(false));
    let on_event_chunk = on_event.clone();
    let on_event_done = on_event;

    update
        .download_and_install(
            move |chunk_length, content_length| {
                if !started.swap(true, Ordering::AcqRel) {
                    let _ = on_event_chunk.send(DownloadEvent::Started { content_length });
                }
                let _ = on_event_chunk.send(DownloadEvent::Progress { chunk_length });
            },
            move || {
                let _ = on_event_done.send(DownloadEvent::Finished);
            },
        )
        .await
        .map_err(UpdaterError::from)?;

    info!("install_update: completed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_metadata_serialises_camel_case() {
        let m = UpdateMetadata {
            version: "0.2.0".into(),
            current_version: "0.1.0".into(),
            notes: Some("perf fixes".into()),
        };
        let json = serde_json::to_string(&m).unwrap();
        // The JS side reads `currentVersion`, not `current_version`.
        assert!(
            json.contains("\"currentVersion\":\"0.1.0\""),
            "expected camelCase, got {json}"
        );
        assert!(json.contains("\"version\":\"0.2.0\""));
    }

    #[test]
    fn test_download_event_started_serialises_with_tag_and_data() {
        let e = DownloadEvent::Started {
            content_length: Some(1024),
        };
        let json = serde_json::to_string(&e).unwrap();
        // The JS side does `if (event.event === "Started")`.
        assert!(json.contains("\"event\":\"Started\""));
        assert!(json.contains("\"contentLength\":1024"));
    }

    #[test]
    fn test_download_event_progress_serialises() {
        let e = DownloadEvent::Progress { chunk_length: 256 };
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("\"event\":\"Progress\""));
        assert!(json.contains("\"chunkLength\":256"));
    }

    #[test]
    fn test_download_event_finished_serialises() {
        let e = DownloadEvent::Finished;
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("\"event\":\"Finished\""));
    }

    #[test]
    fn test_pending_update_default_is_empty() {
        let p = PendingUpdate::default();
        assert!(p.0.lock().is_none());
    }

    #[test]
    fn test_updater_error_serialises_as_plain_string() {
        let e = UpdaterError("boom".into());
        let json = serde_json::to_string(&e).unwrap();
        assert_eq!(json, "\"boom\"");
    }
}
