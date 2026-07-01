//! Client error types.

use std::io;

use thiserror::Error;

/// Client errors.
#[derive(Debug, Error)]
pub enum ClientError {
    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// Connection IO error.
    #[error("connection error: {0}")]
    ConnectionIo(#[from] io::Error),

    /// Connection error (non-IO).
    #[error("connection error: {0}")]
    Connection(String),

    /// Handshake failed.
    #[error("handshake failed: {0}")]
    Handshake(String),

    /// Protocol error.
    #[error("protocol error: {0}")]
    Protocol(#[from] hpn_core::error::ProtocolError),

    /// Cryptographic error.
    #[error("crypto error: {0}")]
    Crypto(#[from] hpn_core::error::CryptoError),

    /// Tunnel error.
    #[error("tunnel error: {0}")]
    Tunnel(String),

    /// Timeout error.
    #[error("operation timed out: {0}")]
    Timeout(String),

    /// Keepalive timeout (no response from server).
    #[error("keepalive timeout: {0}")]
    KeepaliveTimeout(String),

    /// Session not established.
    #[error("session not established")]
    NotConnected,

    /// Reconnection failed.
    #[error("reconnection failed: {0}")]
    ReconnectionFailed(String),

    /// Client is shutting down.
    #[error("client is shutting down")]
    Shutdown,

    /// Invalid state for operation.
    #[error("invalid state: {0}")]
    InvalidState(String),

    /// Network error (STUN, NAT traversal, etc.).
    #[error("network error: {0}")]
    Network(String),

    /// Authentication error (invalid credentials, locked account, etc.).
    #[error("authentication error: {0}")]
    Auth(String),
}

/// Result type for client operations.
pub type ClientResult<T> = Result<T, ClientError>;

#[cfg(test)]
#[allow(clippy::unnecessary_literal_unwrap)]
mod tests {
    use super::*;
    use hpn_core::error::{CryptoError, ProtocolError};

    #[test]
    fn test_client_error_display() {
        let err = ClientError::Config("invalid server".to_string());
        assert!(err.to_string().contains("configuration error"));
        assert!(err.to_string().contains("invalid server"));

        let err = ClientError::Handshake("auth failed".to_string());
        assert!(err.to_string().contains("handshake failed"));
        assert!(err.to_string().contains("auth failed"));

        let err = ClientError::NotConnected;
        assert_eq!(err.to_string(), "session not established");

        let err = ClientError::Shutdown;
        assert_eq!(err.to_string(), "client is shutting down");
    }

    #[test]
    fn test_client_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "refused");
        let err: ClientError = io_err.into();
        assert!(err.to_string().contains("connection error"));
    }

    #[test]
    fn test_client_error_from_protocol() {
        let proto_err = ProtocolError::InvalidVersion(2);
        let err: ClientError = proto_err.into();
        assert!(err.to_string().contains("protocol error"));
    }

    #[test]
    fn test_client_error_from_crypto() {
        let crypto_err = CryptoError::Decryption;
        let err: ClientError = crypto_err.into();
        assert!(err.to_string().contains("crypto error"));
    }

    #[test]
    fn test_client_error_all_variants() {
        let errors = vec![
            ClientError::Config("test".to_string()),
            ClientError::Connection("test".to_string()),
            ClientError::Handshake("test".to_string()),
            ClientError::Tunnel("test".to_string()),
            ClientError::Timeout("test".to_string()),
            ClientError::KeepaliveTimeout("test".to_string()),
            ClientError::NotConnected,
            ClientError::ReconnectionFailed("test".to_string()),
            ClientError::Shutdown,
            ClientError::InvalidState("test".to_string()),
            ClientError::Network("test".to_string()),
            ClientError::Auth("test".to_string()),
        ];

        for err in errors {
            let _ = format!("{:?}", err);
            let _ = err.to_string();
        }
    }

    #[test]
    fn test_client_error_debug() {
        let err = ClientError::Config("debug".to_string());
        let debug = format!("{:?}", err);
        assert!(debug.contains("Config"));

        let err = ClientError::KeepaliveTimeout("30s".to_string());
        let debug = format!("{:?}", err);
        assert!(debug.contains("KeepaliveTimeout"));
    }

    #[test]
    fn test_client_result_ok() {
        let result: ClientResult<String> = Ok("success".to_string());
        assert!(result.is_ok());
        assert_eq!(result.expect("should succeed"), "success");
    }

    #[test]
    fn test_client_result_err() {
        let result: ClientResult<i32> = Err(ClientError::NotConnected);
        assert!(result.is_err());
    }

    #[test]
    fn test_error_conversions() {
        let _: ClientError = io::Error::new(io::ErrorKind::TimedOut, "timeout").into();
        let _: ClientError = ProtocolError::InvalidHeader.into();
        let _: ClientError = CryptoError::SignatureVerification.into();
    }

    #[test]
    fn test_timeout_errors() {
        let err = ClientError::Timeout("10s".to_string());
        assert!(err.to_string().contains("timed out"));
        assert!(err.to_string().contains("10s"));

        let err = ClientError::KeepaliveTimeout("no response".to_string());
        assert!(err.to_string().contains("keepalive timeout"));
        assert!(err.to_string().contains("no response"));
    }
}
