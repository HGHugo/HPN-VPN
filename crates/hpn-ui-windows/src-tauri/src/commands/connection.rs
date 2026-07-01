use tauri::State;

use crate::error::{AppError, CommandError};
use crate::state::{ConnectionStats, ConnectionStatus, LogLevel};

use super::AppStateRef;

#[cfg(windows)]
use tauri::AppHandle;
#[cfg(windows)]
use tracing::{info, warn};

#[cfg(not(windows))]
pub async fn disconnect(_state: State<'_, AppStateRef>) -> Result<(), CommandError> {
    Err(CommandError::from(AppError::InvalidState(
        "Not supported on this platform".to_string(),
    )))
}

#[cfg(windows)]
pub async fn disconnect(app: AppHandle, state: State<'_, AppStateRef>) -> Result<(), CommandError> {
    let (shutdown_tx, cleanup_rx) = {
        let mut state = state.write();

        if state.status != ConnectionStatus::Connected
            && state.status != ConnectionStatus::Reconnecting
        {
            return Err(CommandError::from(AppError::NotConnected));
        }

        state.status = ConnectionStatus::Disconnecting;
        state.add_log(LogLevel::Info, "Disconnecting...");
        super::update_tray_status(&app, ConnectionStatus::Disconnecting);
        (state.shutdown_tx.take(), state.cleanup_complete_rx.take())
    };

    if let Some(tx) = shutdown_tx {
        let _ = tx.send(()).await;
    }

    if let Some(rx) = cleanup_rx {
        match tokio::time::timeout(std::time::Duration::from_secs(5), rx).await {
            Ok(Ok(())) => info!("Cleanup completed successfully"),
            Ok(Err(_)) => warn!("Cleanup channel was dropped without sending"),
            Err(_) => warn!("Cleanup timed out after 5 seconds"),
        }
    }

    {
        let mut state = state.write();
        state.set_disconnected(Some("User requested"));
    }
    super::update_tray_status(&app, ConnectionStatus::Disconnected);

    Ok(())
}

pub fn get_status(state: State<'_, AppStateRef>) -> ConnectionStatus {
    state.read().status
}

pub fn get_stats(state: State<'_, AppStateRef>) -> ConnectionStats {
    let mut state = state.write();
    state.update_uptime();
    state.stats.clone()
}

pub async fn force_rekey(state: State<'_, AppStateRef>) -> Result<(), CommandError> {
    let rekey_tx = {
        let state = state.read();

        if state.status != ConnectionStatus::Connected {
            return Err(CommandError::from(AppError::NotConnected));
        }

        state.rekey_tx.clone().ok_or_else(|| {
            CommandError::from(AppError::InvalidState("No active connection".into()))
        })?
    };

    {
        let mut state = state.write();
        state.add_log(LogLevel::Info, "Forcing key rotation...");
    }

    rekey_tx.send(()).await.map_err(|_| {
        CommandError::from(AppError::Connection("Failed to send rekey request".into()))
    })?;

    {
        let mut state = state.write();
        state.add_log(LogLevel::Info, "Key rotation initiated");
    }

    Ok(())
}
