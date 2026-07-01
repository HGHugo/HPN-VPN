//! Tauri updater integration (audit H14).
//!
//! Mirror of `hpn-ui-macos/src/updater.rs` — see that file for the
//! full threat-model rationale. Both crates use the same
//! `tauri-plugin-updater` plugin with platform-specific bundle
//! formats; the Tauri-command surface is identical so the React
//! frontend can share its `Updater` UI component across both apps.
//!
//! On Windows specifically, the install step exits the running
//! process to let the MSI/NSIS installer take over (see Tauri docs
//! on Windows install limitations).

use serde::Serialize;
use tauri::ipc::Channel;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_updater::{Update, UpdaterExt};
use tracing::{info, warn};

/// Holder for the most recently fetched [`Update`].
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

/// Lightweight metadata for the React `Updater` component.
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

/// Progress event streamed during `install_update`.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "event", content = "data")]
pub enum DownloadEvent {
    /// Download just started.
    #[serde(rename_all = "camelCase")]
    Started {
        /// Total content length in bytes, when known.
        content_length: Option<u64>,
    },
    /// One chunk written.
    #[serde(rename_all = "camelCase")]
    Progress {
        /// Bytes added since the previous `Progress` event.
        chunk_length: usize,
    },
    /// Download finished.
    Finished,
}

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
/// Mirror of `hpn-ui-macos/src/updater.rs::perform_check` — see that
/// file for the full rationale. Extracted from [`check_for_updates`]
/// so the same logic can be invoked from the [`tauri::Builder::setup`]
/// block at app launch (auto-check) without going through the IPC
/// layer.
pub async fn perform_check(app: &AppHandle) -> Result<Option<UpdateMetadata>, UpdaterError> {
    let updater = app.updater().map_err(UpdaterError::from)?;
    let result = updater.check().await.map_err(UpdaterError::from)?;

    let metadata = result.as_ref().map(|update| UpdateMetadata {
        version: update.version.clone(),
        current_version: update.current_version.clone(),
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

#[tauri::command]
pub async fn check_for_updates(
    app: AppHandle,
    _pending: State<'_, PendingUpdate>,
) -> Result<Option<UpdateMetadata>, UpdaterError> {
    info!("check_for_updates: hitting configured updater endpoints");
    perform_check(&app).await
}

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
        assert!(
            json.contains("\"currentVersion\":\"0.1.0\""),
            "expected camelCase, got {json}"
        );
        assert!(json.contains("\"version\":\"0.2.0\""));
    }

    #[test]
    fn test_download_event_started_serialises() {
        let e = DownloadEvent::Started {
            content_length: Some(1024),
        };
        let json = serde_json::to_string(&e).unwrap();
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
