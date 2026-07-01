//! HPN Client Core
//!
//! Platform-agnostic client logic for the HPN VPN.
//!
//! This crate provides the core VPN client functionality that is shared
//! across all platforms. Platform-specific implementations (Windows, Linux, etc.)
//! build on top of this crate.
//!
//! # Architecture
//!
//! - [`client`]: Main VPN client state machine
//! - [`config`]: Client configuration handling
//! - [`connection`]: UDP socket management (legacy, use [`transport`] for new code)
//! - [`transport`]: Transport abstraction (UDP/TCP with fallback support)
//! - [`tunnel`]: Tunnel device trait for platform abstraction
//! - [`error`]: Client error types

// Pedantic lint policy: intentional suppressions.
// Structural:
#![allow(clippy::too_many_lines)]
#![allow(clippy::cognitive_complexity)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::cast_possible_truncation)]
// Style:
#![allow(clippy::similar_names)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::struct_field_names)]
#![allow(clippy::single_match_else)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
// Numeric:
#![allow(clippy::cast_lossless)]
#![allow(clippy::cast_precision_loss)]
// Async:
#![allow(clippy::await_holding_lock)]
#![allow(clippy::future_not_send)]
#![allow(clippy::unused_async)]
// API:
#![allow(clippy::struct_excessive_bools)]
// Crate-specific:
#![allow(clippy::missing_fields_in_debug)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::derivable_impls)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::match_same_arms)]
// Pervasive in client code:
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::map_unwrap_or)]
#![allow(clippy::unused_self)]
#![allow(clippy::question_mark)]
#![allow(clippy::redundant_pattern_matching)]
#![allow(clippy::use_self)]
#![allow(clippy::unnested_or_patterns)]

pub mod buffer_pool;
pub mod client;
pub mod config;
pub mod connection;
pub mod error;
pub mod ipc;
pub mod kill_switch;
pub mod nat;
pub mod stats;
pub mod transport;
pub mod tunnel;

pub use buffer_pool::{
    BufferPool, BytesPool, PooledBuffer, PooledBytesMut, SharedBufferPool, SharedBytesPool,
    create_shared_bytes_pool, create_shared_pool,
};
pub use bytes::Bytes;
pub use client::{ClientEvent, ClientState, VpnClient};
pub use config::{ClientConfig, Credentials};
pub use connection::UdpConnection;
pub use error::ClientError;
pub use ipc::{ClientRequest, ClientResponse, ConnectionState as IpcConnectionState, IpcTransport};
pub use kill_switch::{
    DisconnectReason, KillSwitchManager, KillSwitchMode, KillSwitchState, NetworkChangeDetector,
    SystemEvent,
};
pub use nat::{
    HolePunchConfig, HolePunchMessage, HolePunchMessageType, HolePunchResult, HolePuncher, NatInfo,
    NatType, PeerInfo, RendezvousInfo, StunClient, StunResult, discover_nat_info,
};
pub use stats::{ConnectionHealth, ConnectionStats, StatsTracker};
pub use transport::{
    TcpTransport, Transport, TransportConfig, TransportFallback, TransportTrait, TransportType,
    UdpTransport,
};
pub use tunnel::{TunnelDevice, TunnelInfo};
