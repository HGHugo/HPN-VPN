//! Relay error types.

use std::io;
use thiserror::Error;

/// Relay-specific errors.
#[derive(Debug, Error)]
pub enum RelayError {
    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Result type for relay operations.
pub type RelayResult<T> = Result<T, RelayError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_error_display() {
        let err = RelayError::Config("invalid address".to_string());
        assert!(err.to_string().contains("configuration error"));
        assert!(err.to_string().contains("invalid address"));
    }

    #[test]
    fn test_relay_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionReset, "reset");
        let err: RelayError = io_err.into();
        assert!(err.to_string().contains("I/O error"));
    }

    #[test]
    fn test_relay_error_debug() {
        let err = RelayError::Config("debug test".to_string());
        let debug = format!("{:?}", err);
        assert!(debug.contains("Config"));
    }

    #[test]
    fn test_relay_result_ok() {
        fn produce_ok() -> RelayResult<i32> {
            Ok(100)
        }
        let result = produce_ok();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 100);
    }

    #[test]
    fn test_relay_result_err() {
        let result: RelayResult<i32> = Err(RelayError::Config("failed".to_string()));
        assert!(result.is_err());
    }
}
