//! HPN protocol implementation.
//!
//! This module provides:
//! - [`header`]: Packet header format
//! - [`messages`]: Protocol message types
//! - `codec`: Serialization/deserialization
//! - [`handshake`]: Handshake state machine
//! - [`session`]: Session state management
//! - [`fragment`]: Application-layer handshake fragmentation + reassembly

pub mod codec;
pub mod fragment;
pub mod handshake;
pub mod header;
pub mod messages;
pub mod session;

pub use codec::{Decode, Encode};
pub use fragment::{
    FRAGMENT_HEADER_SIZE, FragmentError, HandshakeFragment, MAX_FRAGMENT_PAYLOAD,
    MAX_FRAGMENTS_PER_HANDSHAKE, ReassemblerConfig, ReassemblerStats, Reassembly,
    build_handshake_fragments, split_payload,
};
pub use handshake::{ClientHandshake, ClientRekey, HandshakeState, ServerHandshake};
pub use header::{HEADER_SIZE, HEADER_SIZE_WITH_TIMESTAMP, HeaderFlags, PacketHeader};
pub use messages::{
    ControlMessage, DataMessage, EncryptedHandshakeInit, HandshakeInit, HandshakeResponse,
    KeepaliveMessage, KeepaliveReplyMessage, MAX_REBIND_ACK_AGE_SECS,
    MAX_REBIND_ACK_FUTURE_SKEW_SECS, Message, RekeyMessage, RekeyResponse, SignedRebindAckPayload,
    TunnelConfig,
};
pub use session::{AntiReplayWindow, Session, SessionState};
