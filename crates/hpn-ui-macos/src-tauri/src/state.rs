//! Application state management.

use std::collections::VecDeque;
use std::time::Instant;

use serde::Serialize;
use tokio::sync::mpsc;

use crate::commands::reset_connect_in_progress;
use crate::config::{self, Profile, Settings};
use crate::error::AppResult;

/// Maximum number of log entries to keep.
const MAX_LOG_ENTRIES: usize = 1000;

/// Connection status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionStatus {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    Reconnecting,
    Error,
}

/// Connection statistics.
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionStats {
    /// Bytes sent.
    pub tx: u64,
    /// Bytes received.
    pub rx: u64,
    /// Round-trip time in milliseconds.
    pub rtt: u64,
    /// Connection uptime in seconds.
    pub uptime: u64,
    /// Current transfer rate (bytes/sec).
    pub rate: u64,
    /// Current key ID.
    pub key_id: u32,
    /// Session ID (hex string).
    pub session_id: String,
}

impl Default for ConnectionStats {
    fn default() -> Self {
        Self {
            tx: 0,
            rx: 0,
            rtt: 0,
            uptime: 0,
            rate: 0,
            key_id: 0,
            session_id: String::new(),
        }
    }
}

/// Log entry.
#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    /// Unique ID.
    pub id: String,
    /// Timestamp (HH:MM:SS format).
    pub timestamp: String,
    /// Log level.
    pub level: LogLevel,
    /// Log message.
    pub message: String,
}

/// Log level.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
#[allow(dead_code)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
}

/// Application state.
pub struct AppState {
    /// Current connection status.
    pub status: ConnectionStatus,
    /// Active profile ID.
    pub active_profile_id: Option<String>,
    /// Saved profiles.
    pub profiles: Vec<Profile>,
    /// Application settings.
    pub settings: Settings,
    /// Connection statistics.
    pub stats: ConnectionStats,
    /// Connection start time.
    pub connected_at: Option<Instant>,
    /// Log entries.
    pub logs: VecDeque<LogEntry>,
    /// Log ID counter.
    log_counter: u64,
    /// VPN client shutdown signal.
    pub shutdown_tx: Option<mpsc::Sender<()>>,
    /// Channel to request rekey from VPN task.
    pub rekey_tx: Option<mpsc::Sender<()>>,
    /// Channel to receive cleanup completion signal.
    pub cleanup_complete_rx: Option<tokio::sync::oneshot::Receiver<()>>,
}

impl AppState {
    /// Create a new application state.
    /// Always starts disconnected - any previous "Connecting" state is invalid after restart.
    pub fn new() -> Self {
        Self {
            status: ConnectionStatus::Disconnected,
            active_profile_id: None,
            profiles: Vec::new(),
            settings: Settings::default(),
            stats: ConnectionStats::default(),
            connected_at: None,
            logs: VecDeque::with_capacity(MAX_LOG_ENTRIES),
            log_counter: 0,
            shutdown_tx: None,
            rekey_tx: None,
            cleanup_complete_rx: None,
        }
    }

    /// Reset status to disconnected if it's in an invalid state.
    /// Call this after loading config to ensure clean state.
    pub fn sanitize_status(&mut self) {
        // If status is Connecting/Disconnecting/Reconnecting but we have no channels,
        // it means the app was restarted mid-operation - reset to Disconnected
        if matches!(
            self.status,
            ConnectionStatus::Connecting
                | ConnectionStatus::Disconnecting
                | ConnectionStatus::Reconnecting
        ) && self.shutdown_tx.is_none()
        {
            self.status = ConnectionStatus::Disconnected;
            self.add_log(LogLevel::Info, "Reset stale connection status");
            // Also reset the connect-in-progress flag
            reset_connect_in_progress();
        }
    }

    /// Load configuration from disk.
    pub fn load_config(&mut self) -> AppResult<()> {
        self.profiles = config::load_profiles()?;
        self.settings = config::load_settings()?;
        // Ensure status is valid (reset Connecting/etc if no active connection)
        self.sanitize_status();
        self.add_log(LogLevel::Info, "Configuration loaded");
        Ok(())
    }

    /// Save profiles to disk.
    pub fn save_profiles(&self) -> AppResult<()> {
        config::save_profiles(&self.profiles)
    }

    /// Save settings to disk.
    pub fn save_settings(&self) -> AppResult<()> {
        config::save_settings_to_disk(&self.settings)
    }

    /// Add a log entry.
    pub fn add_log(&mut self, level: LogLevel, message: impl Into<String>) {
        self.log_counter += 1;

        let now = chrono::Local::now();
        let entry = LogEntry {
            id: format!("{}", self.log_counter),
            timestamp: now.format("%H:%M:%S").to_string(),
            level,
            message: message.into(),
        };

        if self.logs.len() >= MAX_LOG_ENTRIES {
            self.logs.pop_front();
        }

        self.logs.push_back(entry);
    }

    /// Clear all logs.
    pub fn clear_logs(&mut self) {
        self.logs.clear();
    }

    /// Get logs as a vector.
    pub fn get_logs(&self) -> Vec<LogEntry> {
        self.logs.iter().cloned().collect()
    }

    /// Get a profile by ID.
    pub fn get_profile(&self, id: &str) -> Option<&Profile> {
        self.profiles.iter().find(|p| p.id == id)
    }

    /// Update connection uptime.
    pub fn update_uptime(&mut self) {
        if let Some(start) = self.connected_at {
            self.stats.uptime = start.elapsed().as_secs();
        }
    }

    /// Reset stats on disconnect.
    pub fn reset_stats(&mut self) {
        self.stats = ConnectionStats::default();
        self.connected_at = None;
    }

    /// Set connected state.
    pub fn set_connected(&mut self, session_id: u64) {
        self.status = ConnectionStatus::Connected;
        self.connected_at = Some(Instant::now());
        self.stats.session_id = format!("{:016x}", session_id);
        self.add_log(LogLevel::Info, "Tunnel established");
        // Reset the connect-in-progress flag now that we've reached Connected
        reset_connect_in_progress();
    }

    /// Set disconnected state.
    pub fn set_disconnected(&mut self, reason: Option<&str>) {
        self.status = ConnectionStatus::Disconnected;
        self.active_profile_id = None;
        self.shutdown_tx = None;
        self.rekey_tx = None;
        self.cleanup_complete_rx = None;
        self.reset_stats();

        let msg = match reason {
            Some(r) => format!("Disconnected: {}", r),
            None => "Disconnected".to_string(),
        };
        self.add_log(LogLevel::Info, msg);
        // Reset the connect-in-progress flag now that we've reached Disconnected
        reset_connect_in_progress();
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_state_new_defaults() {
        let state = AppState::new();
        assert_eq!(state.status, ConnectionStatus::Disconnected);
        assert!(state.active_profile_id.is_none());
        assert!(state.profiles.is_empty());
        assert!(state.connected_at.is_none());
        assert!(state.logs.is_empty());
        assert!(state.shutdown_tx.is_none());
        assert!(state.rekey_tx.is_none());
    }

    #[test]
    fn test_connection_stats_default() {
        let stats = ConnectionStats::default();
        assert_eq!(stats.tx, 0);
        assert_eq!(stats.rx, 0);
        assert_eq!(stats.rtt, 0);
        assert_eq!(stats.uptime, 0);
        assert_eq!(stats.rate, 0);
        assert_eq!(stats.key_id, 0);
        assert!(stats.session_id.is_empty());
    }

    #[test]
    fn test_add_log() {
        let mut state = AppState::new();
        state.add_log(LogLevel::Info, "test message");
        assert_eq!(state.logs.len(), 1);
        assert_eq!(state.logs[0].message, "test message");
        assert_eq!(state.logs[0].id, "1");
    }

    #[test]
    fn test_add_log_ring_buffer_eviction() {
        let mut state = AppState::new();
        for i in 0..1001 {
            state.add_log(LogLevel::Info, format!("msg {}", i));
        }
        assert_eq!(state.logs.len(), 1000);
        assert_eq!(state.logs[0].message, "msg 1");
        assert_eq!(state.logs[999].message, "msg 1000");
    }

    #[test]
    fn test_clear_and_get_logs() {
        let mut state = AppState::new();
        state.add_log(LogLevel::Info, "a");
        state.add_log(LogLevel::Warn, "b");
        assert_eq!(state.get_logs().len(), 2);
        state.clear_logs();
        assert!(state.get_logs().is_empty());
    }

    #[test]
    fn test_set_connected() {
        let mut state = AppState::new();
        state.set_connected(0x1234_5678_9ABC_DEF0);
        assert_eq!(state.status, ConnectionStatus::Connected);
        assert!(state.connected_at.is_some());
        assert_eq!(state.stats.session_id, "123456789abcdef0");
        assert!(
            state
                .logs
                .iter()
                .any(|l| l.message.contains("Tunnel established"))
        );
    }

    #[test]
    fn test_set_disconnected() {
        let mut state = AppState::new();
        state.set_connected(1);
        state.set_disconnected(Some("user requested"));
        assert_eq!(state.status, ConnectionStatus::Disconnected);
        assert!(state.active_profile_id.is_none());
        assert!(state.shutdown_tx.is_none());
        assert!(state.connected_at.is_none());
        assert_eq!(state.stats.tx, 0);
        assert!(
            state
                .logs
                .iter()
                .any(|l| l.message.contains("user requested"))
        );
    }

    #[test]
    fn test_set_disconnected_no_reason() {
        let mut state = AppState::new();
        state.set_disconnected(None);
        assert!(state.logs.iter().any(|l| l.message == "Disconnected"));
    }

    #[test]
    fn test_reset_stats() {
        let mut state = AppState::new();
        state.stats.tx = 1000;
        state.stats.rx = 2000;
        state.connected_at = Some(Instant::now());
        state.reset_stats();
        assert_eq!(state.stats.tx, 0);
        assert_eq!(state.stats.rx, 0);
        assert!(state.connected_at.is_none());
    }

    #[test]
    fn test_update_uptime() {
        let mut state = AppState::new();
        state.update_uptime();
        assert_eq!(state.stats.uptime, 0);
        state.connected_at = Some(Instant::now());
        std::thread::sleep(std::time::Duration::from_millis(10));
        state.update_uptime();
        assert!(state.stats.uptime < 5);
    }

    #[test]
    fn test_get_profile() {
        let mut state = AppState::new();
        state.profiles.push(crate::config::Profile {
            id: "test-1".into(),
            name: "Test".into(),
            server: "10.0.0.1".into(),
            port: 51820,
            server_public_key: "key".into(),
            verified: false,
            security_level: crate::config::SecurityLevel::default(),
            server_kem_public_key: None,
            requires_auth: false,
            username: None,
            split_tunnel: None,
        });
        assert!(state.get_profile("test-1").is_some());
        assert!(state.get_profile("nonexistent").is_none());
    }

    #[test]
    fn test_sanitize_status_resets_stale() {
        let mut state = AppState::new();
        state.status = ConnectionStatus::Connecting;
        state.sanitize_status();
        assert_eq!(state.status, ConnectionStatus::Disconnected);
    }

    #[test]
    fn test_sanitize_status_keeps_connected() {
        let mut state = AppState::new();
        state.status = ConnectionStatus::Connected;
        state.sanitize_status();
        assert_eq!(state.status, ConnectionStatus::Connected);
    }
}
