//! Error types for AF_XDP operations.

use std::io;

use thiserror::Error;

/// Errors that can occur during AF_XDP operations.
#[derive(Error, Debug)]
pub enum AfXdpError {
    /// Failed to create AF_XDP socket.
    #[error("failed to create AF_XDP socket: {0}")]
    SocketCreation(io::Error),

    /// Failed to bind socket to interface.
    #[error("failed to bind to interface {interface} queue {queue}: {source}")]
    Bind {
        interface: String,
        queue: u32,
        source: io::Error,
    },

    /// Failed to allocate UMEM.
    #[error("failed to allocate UMEM: {0}")]
    UmemAllocation(io::Error),

    /// Failed to register UMEM with socket.
    #[error("failed to register UMEM: {0}")]
    UmemRegistration(io::Error),

    /// Failed to create ring buffer.
    #[error("failed to create {ring_type} ring: {source}")]
    RingCreation {
        ring_type: String,
        source: io::Error,
    },

    /// Failed to map ring buffer.
    #[error("failed to map {ring_type} ring: {source}")]
    RingMapping {
        ring_type: String,
        source: io::Error,
    },

    /// Interface not found.
    #[error("interface not found: {0}")]
    InterfaceNotFound(String),

    /// Failed to get interface index.
    #[error("failed to get interface index for {interface}: {source}")]
    InterfaceIndex {
        interface: String,
        source: io::Error,
    },

    /// Invalid ring size (must be power of 2).
    #[error("ring size must be power of 2, got {0}")]
    InvalidRingSize(u32),

    /// Invalid frame size.
    #[error("invalid frame size {size}: must be >= {min} and <= {max}")]
    InvalidFrameSize { size: u32, min: u32, max: u32 },

    /// UMEM exhausted (no free frames).
    #[error("UMEM exhausted: no free frames available")]
    UmemExhausted,

    /// Invalid frame address.
    #[error("invalid frame address: {0:#x}")]
    InvalidFrameAddress(u64),

    /// XDP program load failed.
    #[error("failed to load XDP program: {0}")]
    XdpProgramLoad(io::Error),

    /// XDP program attach failed.
    #[error("failed to attach XDP program to {interface}: {source}")]
    XdpProgramAttach {
        interface: String,
        source: io::Error,
    },

    /// Socket option error.
    #[error("socket option {option} failed: {source}")]
    SocketOption { option: String, source: io::Error },

    /// Poll error.
    #[error("poll error: {0}")]
    Poll(io::Error),

    /// Transmit error.
    #[error("transmit failed: {0}")]
    Transmit(io::Error),

    /// Receive error.
    #[error("receive failed: {0}")]
    Receive(io::Error),

    /// Operation not supported on this kernel.
    #[error("AF_XDP not supported: requires Linux kernel >= 4.18")]
    NotSupported,

    /// Permission denied (needs CAP_NET_ADMIN or root).
    #[error("permission denied: AF_XDP requires CAP_NET_ADMIN or root")]
    PermissionDenied,

    /// Crypto error during packet processing.
    #[error("crypto error: {0}")]
    Crypto(#[from] hpn_core::error::CryptoError),

    /// Protocol error during packet processing.
    #[error("protocol error: {0}")]
    Protocol(#[from] hpn_core::error::ProtocolError),

    /// Session not found for packet.
    #[error("session not found for session_id {0:#x}")]
    SessionNotFound(u64),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),
}

/// Result type for AF_XDP operations.
pub type Result<T> = std::result::Result<T, AfXdpError>;
