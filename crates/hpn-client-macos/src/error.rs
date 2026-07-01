//! macOS client error types.

use thiserror::Error;

/// Errors specific to the macOS client.
#[derive(Debug, Error)]
pub enum MacosClientError {
    /// Adapter error.
    #[error("adapter error: {0}")]
    Adapter(String),

    /// Routing error.
    #[error("routing error: {0}")]
    Routing(String),

    /// System configuration error.
    #[error("system configuration error: {0}")]
    SystemConfig(String),

    /// DNS configuration error.
    #[error("DNS error: {0}")]
    Dns(String),

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Client core error.
    #[error("client error: {0}")]
    Client(#[from] hpn_client_core::error::ClientError),
}
