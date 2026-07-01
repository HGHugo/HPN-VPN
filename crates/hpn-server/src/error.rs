//! Server error types.

use std::io;

use thiserror::Error;

/// Server errors.
#[derive(Debug, Error)]
pub enum ServerError {
    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// IO error.
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// Protocol error.
    #[error("protocol error: {0}")]
    Protocol(#[from] hpn_core::error::ProtocolError),

    /// Cryptographic error.
    #[error("crypto error: {0}")]
    Crypto(#[from] hpn_core::error::CryptoError),

    /// TUN device error.
    #[error("tun error: {0}")]
    Tun(String),

    /// Session error.
    #[error("session error: {0}")]
    Session(String),

    /// IP allocation error.
    #[error("ip allocation error: {0}")]
    IpAllocation(String),

    /// NAT error.
    #[error("nat error: {0}")]
    Nat(String),

    /// Internal server error.
    #[error("internal error: {0}")]
    Internal(String),

    /// Server is shutting down.
    #[error("server is shutting down")]
    Shutdown,
}

/// Result type for server operations.
pub type ServerResult<T> = Result<T, ServerError>;

#[cfg(test)]
#[allow(clippy::unnecessary_literal_unwrap)]
mod tests {
    use super::*;
    use hpn_core::error::{CryptoError, ProtocolError};

    #[test]
    fn test_server_error_display() {
        let err = ServerError::Config("invalid port".to_string());
        assert!(err.to_string().contains("configuration error"));
        assert!(err.to_string().contains("invalid port"));

        let err = ServerError::Tun("failed to create".to_string());
        assert!(err.to_string().contains("tun error"));
        assert!(err.to_string().contains("failed to create"));

        let err = ServerError::Shutdown;
        assert_eq!(err.to_string(), "server is shutting down");
    }

    #[test]
    fn test_server_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let err: ServerError = io_err.into();
        assert!(err.to_string().contains("io error"));
    }

    #[test]
    fn test_server_error_from_protocol() {
        let proto_err = ProtocolError::InvalidHeader;
        let err: ServerError = proto_err.into();
        assert!(err.to_string().contains("protocol error"));
    }

    #[test]
    fn test_server_error_from_crypto() {
        let crypto_err = CryptoError::Encryption;
        let err: ServerError = crypto_err.into();
        assert!(err.to_string().contains("crypto error"));
    }

    #[test]
    fn test_server_error_all_variants() {
        let errors = vec![
            ServerError::Config("test".to_string()),
            ServerError::Tun("test".to_string()),
            ServerError::Session("test".to_string()),
            ServerError::IpAllocation("test".to_string()),
            ServerError::Nat("test".to_string()),
            ServerError::Internal("test".to_string()),
            ServerError::Shutdown,
        ];

        for err in errors {
            let _ = format!("{:?}", err);
            let _ = err.to_string();
        }
    }

    #[test]
    fn test_server_error_debug() {
        let err = ServerError::Config("debug test".to_string());
        let debug = format!("{:?}", err);
        assert!(debug.contains("Config"));

        let err = ServerError::Shutdown;
        let debug = format!("{:?}", err);
        assert!(debug.contains("Shutdown"));
    }

    #[test]
    fn test_server_result_ok() {
        let result: ServerResult<i32> = Ok(42);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_server_result_err() {
        let result: ServerResult<i32> = Err(ServerError::Shutdown);
        assert!(result.is_err());
    }

    #[test]
    fn test_error_conversions() {
        // Test all From implementations
        let _: ServerError = io::Error::other("test").into();
        let _: ServerError = ProtocolError::InvalidHeader.into();
        let _: ServerError = CryptoError::KeyGeneration.into();
    }
}
