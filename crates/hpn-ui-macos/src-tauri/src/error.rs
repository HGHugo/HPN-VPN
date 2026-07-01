//! Error types for the Tauri application.

use serde::Serialize;
use thiserror::Error;

/// Application error type.
#[derive(Debug, Error)]
pub enum AppError {
    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("VPN client error: {0}")]
    Client(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Not connected")]
    NotConnected,

    #[error("Already connected")]
    AlreadyConnected,

    #[error("Profile not found: {0}")]
    ProfileNotFound(String),

    #[error("Invalid state: {0}")]
    InvalidState(String),
}

/// Serializable error for Tauri commands.
#[derive(Debug, Serialize)]
pub struct CommandError {
    pub code: String,
    pub message: String,
}

impl From<AppError> for CommandError {
    fn from(err: AppError) -> Self {
        let code = match &err {
            AppError::Connection(_) => "CONNECTION_ERROR",
            AppError::Config(_) => "CONFIG_ERROR",
            AppError::Client(_) => "CLIENT_ERROR",
            AppError::Io(_) => "IO_ERROR",
            AppError::Serialization(_) => "SERIALIZATION_ERROR",
            AppError::NotConnected => "NOT_CONNECTED",
            AppError::AlreadyConnected => "ALREADY_CONNECTED",
            AppError::ProfileNotFound(_) => "PROFILE_NOT_FOUND",
            AppError::InvalidState(_) => "INVALID_STATE",
        };

        CommandError {
            code: code.to_string(),
            message: err.to_string(),
        }
    }
}

impl From<AppError> for tauri::ipc::InvokeError {
    fn from(err: AppError) -> Self {
        let cmd_err = CommandError::from(err);
        // Use unwrap_or to provide fallback instead of panicking
        let json = serde_json::to_string(&cmd_err).unwrap_or_else(|_| {
            format!(
                r#"{{"code":"{}","message":"{}"}}"#,
                cmd_err.code, cmd_err.message
            )
        });
        tauri::ipc::InvokeError::from(json)
    }
}

pub type AppResult<T> = Result<T, AppError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_error_codes() {
        let cases = vec![
            (AppError::Connection("x".into()), "CONNECTION_ERROR"),
            (AppError::Config("x".into()), "CONFIG_ERROR"),
            (AppError::Client("x".into()), "CLIENT_ERROR"),
            (AppError::NotConnected, "NOT_CONNECTED"),
            (AppError::AlreadyConnected, "ALREADY_CONNECTED"),
            (AppError::ProfileNotFound("x".into()), "PROFILE_NOT_FOUND"),
            (AppError::InvalidState("x".into()), "INVALID_STATE"),
        ];

        for (err, expected_code) in cases {
            let cmd_err = CommandError::from(err);
            assert_eq!(cmd_err.code, expected_code);
        }
    }

    #[test]
    fn test_error_display() {
        let err = AppError::Connection("timeout".into());
        assert_eq!(err.to_string(), "Connection error: timeout");

        let err = AppError::ProfileNotFound("abc".into());
        assert_eq!(err.to_string(), "Profile not found: abc");

        let err = AppError::NotConnected;
        assert_eq!(err.to_string(), "Not connected");
    }

    #[test]
    fn test_command_error_serialization() {
        let cmd_err = CommandError {
            code: "TEST".into(),
            message: "test msg".into(),
        };
        let json = serde_json::to_string(&cmd_err).unwrap();
        assert!(json.contains("TEST"));
        assert!(json.contains("test msg"));
    }
}
