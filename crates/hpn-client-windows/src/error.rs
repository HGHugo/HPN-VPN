//! Windows client error types.

use thiserror::Error;

/// Windows client error type.
#[derive(Debug, Error)]
pub enum WindowsClientError {
    /// Adapter error.
    #[error("adapter error: {0}")]
    Adapter(String),

    /// Signature verification error.
    #[error("signature verification failed: {0}")]
    SignatureVerification(String),

    /// Routing error.
    #[error("routing error: {0}")]
    Routing(String),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Client core error.
    #[error("client error: {0}")]
    Client(#[from] hpn_client_core::ClientError),

    /// Platform not supported.
    #[error("platform not supported")]
    PlatformNotSupported,

    /// Split tunnel error.
    #[error("split tunnel error: {0}")]
    SplitTunnel(String),

    /// Windows API error.
    #[cfg(windows)]
    #[error("Windows API error: {0}")]
    WindowsApi(#[from] crate::windows_api::WindowsApiError),
}
