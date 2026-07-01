use tauri::State;

use crate::error::{AppError, CommandError};

use super::{AppStateRef, LogEntry, LogLevel};

/// Get all log entries.
pub fn get_logs(state: State<'_, AppStateRef>) -> Vec<LogEntry> {
    state.read().get_logs()
}

/// Clear all logs.
pub fn clear_logs(state: State<'_, AppStateRef>) {
    let mut state = state.write();
    state.clear_logs();
    state.add_log(LogLevel::Info, "Logs cleared");
}

/// Export logs to file.
pub fn export_logs(state: State<'_, AppStateRef>) -> Result<String, CommandError> {
    let logs = state.read().get_logs();

    let logs_dir = crate::config::get_logs_dir().map_err(CommandError::from)?;
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let filename = format!("hpn_logs_{}.txt", timestamp);
    let path = logs_dir.join(&filename);

    let content: String = logs
        .iter()
        .map(|log| format!("[{}] [{:?}] {}", log.timestamp, log.level, log.message))
        .collect::<Vec<_>>()
        .join("\n");

    std::fs::write(&path, content).map_err(|e| CommandError::from(AppError::Io(e)))?;

    {
        let mut state = state.write();
        state.add_log(LogLevel::Info, format!("Logs exported to {}", filename));
    }

    Ok(path.to_string_lossy().to_string())
}
