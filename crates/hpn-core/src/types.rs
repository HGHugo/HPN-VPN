//! Common types used throughout the HPN library.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Protocol version constant.
pub const PROTOCOL_VERSION: u8 = 1;

/// Maximum transmission unit for the tunnel.
pub const DEFAULT_MTU: u16 = 1420;

/// Session identifier (8 bytes).
///
/// Uniquely identifies a VPN session. Independent of IP/port for roaming support.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub u64);

impl SessionId {
    /// Size in bytes.
    pub const SIZE: usize = 8;

    /// Generate a new random session ID.
    #[must_use]
    pub fn generate() -> Self {
        use rand::Rng;
        Self(rand::thread_rng().r#gen())
    }

    /// Create from bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(u64::from_be_bytes(bytes))
    }

    /// Convert to bytes.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SessionId({:016x})", self.0)
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

/// Key identifier for key rotation.
///
/// Incremented with each rekey operation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyId(pub u32);

impl KeyId {
    /// Size in bytes.
    pub const SIZE: usize = 4;

    /// Create the initial key ID.
    #[must_use]
    pub const fn initial() -> Self {
        Self(0)
    }

    /// Increment the key ID for rekeying.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.wrapping_add(1))
    }

    /// Create from bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 4]) -> Self {
        Self(u32::from_be_bytes(bytes))
    }

    /// Convert to bytes.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

/// Packet counter for anti-replay protection.
///
/// Monotonically increasing counter sent with each packet.
/// WARNING: Counter overflow would cause nonce reuse, which is catastrophic for AEAD security.
/// Always check `is_near_exhaustion()` and rekey before the counter approaches the limit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Counter(pub u64);

impl Counter {
    /// Size in bytes.
    pub const SIZE: usize = 8;

    /// Maximum safe counter value before rekey is required.
    /// Set to 2^60 to provide a huge safety margin while still allowing detection.
    /// At 10 million packets/second, this is ~3,600 years of traffic.
    pub const MAX_SAFE: u64 = 1 << 60;

    /// Threshold for warning that rekey should happen soon.
    /// Set to 2^59 to give plenty of time to complete rekey.
    pub const REKEY_WARNING: u64 = 1 << 59;

    /// Create an initial counter.
    #[must_use]
    pub const fn initial() -> Self {
        Self(0)
    }

    /// Increment the counter with overflow check.
    ///
    /// Returns `None` if the counter would exceed MAX_SAFE (counter exhaustion).
    /// This is a critical security check to prevent nonce reuse.
    /// Always rekey before reaching this point.
    #[must_use]
    pub fn try_next(self) -> Option<Self> {
        let next = self.0.checked_add(1)?;
        if next > Self::MAX_SAFE {
            return None;
        }
        Some(Self(next))
    }

    /// Increment the counter with overflow check.
    ///
    /// # Errors
    /// Returns `CryptoError::CounterExhausted` if the counter would exceed `MAX_SAFE`.
    /// This is a critical security check to prevent nonce reuse. Always rekey before
    /// reaching this point.
    pub fn next(self) -> Result<Self, crate::error::CryptoError> {
        self.try_next()
            .ok_or(crate::error::CryptoError::CounterExhausted)
    }

    /// Check if the counter is approaching exhaustion and rekey should happen.
    #[must_use]
    pub const fn should_rekey(&self) -> bool {
        self.0 >= Self::REKEY_WARNING
    }

    /// Check if the counter is near exhaustion (critical - must rekey immediately).
    #[must_use]
    pub const fn is_near_exhaustion(&self) -> bool {
        self.0 >= Self::MAX_SAFE
    }

    /// Create from bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(u64::from_be_bytes(bytes))
    }

    /// Convert to bytes.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }
}

/// Message type identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    /// Client initiates handshake with ephemeral public keys.
    HandshakeInit = 1,
    /// Server responds with encapsulated secret and signature.
    HandshakeResponse = 2,
    /// Encrypted tunnel data.
    Data = 3,
    /// Keep-alive ping to maintain NAT bindings.
    Keepalive = 4,
    /// Keep-alive reply with RTT measurement.
    KeepaliveReply = 5,
    /// Control messages (errors, rebind, config).
    Control = 6,
    /// Key rotation request from client.
    Rekey = 7,
    /// Key rotation response from server.
    RekeyResponse = 8,
    /// Cookie challenge request (anti-DoS).
    CookieRequest = 9,
    /// Cookie challenge reply with proof-of-work.
    CookieReply = 10,
    /// Encrypted handshake init (identity hiding enabled).
    /// Client's ephemeral public key is encrypted using server's KEM public key.
    EncryptedHandshakeInit = 11,
    /// Application-layer fragment of a handshake message.
    ///
    /// Used to split `HandshakeInit`, `EncryptedHandshakeInit`, or
    /// `HandshakeResponse` payloads across multiple UDP datagrams when the
    /// whole message would require IP-level fragmentation. Some deployments
    /// filter fragmented UDP (DDoS protection on the hoster side), so we
    /// fragment at the protocol level and reassemble before parsing. See
    /// [`crate::protocol::fragment`] for the format and reassembler.
    HandshakeFragment = 12,
}

impl MessageType {
    /// Convert from u8.
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::HandshakeInit),
            2 => Some(Self::HandshakeResponse),
            3 => Some(Self::Data),
            4 => Some(Self::Keepalive),
            5 => Some(Self::KeepaliveReply),
            6 => Some(Self::Control),
            7 => Some(Self::Rekey),
            8 => Some(Self::RekeyResponse),
            9 => Some(Self::CookieRequest),
            10 => Some(Self::CookieReply),
            11 => Some(Self::EncryptedHandshakeInit),
            12 => Some(Self::HandshakeFragment),
            _ => None,
        }
    }

    /// Convert to u8.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Control message subtypes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ControlType {
    /// Error notification.
    Error = 1,
    /// Client endpoint rebind request.
    Rebind = 2,
    /// Rebind acknowledgment.
    RebindAck = 3,
    /// Configuration update.
    Config = 4,
    /// Session termination.
    Close = 5,
}

impl ControlType {
    /// Convert from u8.
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Error),
            2 => Some(Self::Rebind),
            3 => Some(Self::RebindAck),
            4 => Some(Self::Config),
            5 => Some(Self::Close),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_id_roundtrip() {
        let id = SessionId::generate();
        let bytes = id.to_bytes();
        let recovered = SessionId::from_bytes(bytes);
        assert_eq!(id, recovered);
    }

    #[test]
    fn test_key_id_increment() {
        let id = KeyId::initial();
        assert_eq!(id.0, 0);
        let next = id.next();
        assert_eq!(next.0, 1);
    }

    #[test]
    fn test_counter_increment() {
        let counter = Counter::initial();
        assert_eq!(counter.0, 0);
        let next = counter.next().unwrap();
        assert_eq!(next.0, 1);
    }

    #[test]
    fn test_message_type_roundtrip() {
        // Test all valid message types (1-12).
        // NB: 12 = `HandshakeFragment`, added with application-layer
        // handshake fragmentation.
        for i in 1..=12 {
            let msg_type = MessageType::from_u8(i).unwrap();
            assert_eq!(msg_type.as_u8(), i);
        }
        // Test invalid values
        assert!(MessageType::from_u8(0).is_none());
        assert!(MessageType::from_u8(13).is_none());
    }

    #[test]
    fn test_session_id_uniqueness() {
        let id1 = SessionId::generate();
        let id2 = SessionId::generate();
        let id3 = SessionId::generate();

        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_session_id_from_bytes() {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8];
        let id = SessionId::from_bytes(bytes);
        assert_eq!(id.to_bytes(), bytes);
    }

    #[test]
    fn test_key_id_initial() {
        let id = KeyId::initial();
        assert_eq!(id.0, 0);
    }

    #[test]
    fn test_key_id_multiple_increments() {
        let id = KeyId::initial();
        let id2 = id.next();
        let id3 = id2.next();
        let id4 = id3.next();

        assert_eq!(id.0, 0);
        assert_eq!(id2.0, 1);
        assert_eq!(id3.0, 2);
        assert_eq!(id4.0, 3);
    }

    #[test]
    fn test_counter_initial() {
        let counter = Counter::initial();
        assert_eq!(counter.0, 0);
    }

    #[test]
    fn test_counter_multiple_increments() {
        let c1 = Counter::initial();
        let c2 = c1.next().unwrap();
        let c3 = c2.next().unwrap();

        assert_eq!(c1.0, 0);
        assert_eq!(c2.0, 1);
        assert_eq!(c3.0, 2);
    }

    #[test]
    fn test_counter_max_safe() {
        // Verify MAX_SAFE is in expected range
        // Using comparison operations to avoid constant assertions
        let max_safe = Counter::MAX_SAFE;
        assert!(max_safe >= 1); // Not zero
        assert!(max_safe < u64::MAX); // Less than maximum
    }

    #[test]
    fn test_message_type_all_variants() {
        assert_eq!(MessageType::HandshakeInit.as_u8(), 1);
        assert_eq!(MessageType::HandshakeResponse.as_u8(), 2);
        assert_eq!(MessageType::Data.as_u8(), 3);
        assert_eq!(MessageType::Keepalive.as_u8(), 4);
        assert_eq!(MessageType::KeepaliveReply.as_u8(), 5);
        assert_eq!(MessageType::Control.as_u8(), 6);
        assert_eq!(MessageType::Rekey.as_u8(), 7);
        assert_eq!(MessageType::RekeyResponse.as_u8(), 8);
        assert_eq!(MessageType::CookieRequest.as_u8(), 9);
        assert_eq!(MessageType::CookieReply.as_u8(), 10);
        assert_eq!(MessageType::EncryptedHandshakeInit.as_u8(), 11);
        assert_eq!(MessageType::HandshakeFragment.as_u8(), 12);
    }

    #[test]
    fn test_control_type_all_variants() {
        assert_eq!(ControlType::from_u8(1), Some(ControlType::Error));
        assert_eq!(ControlType::from_u8(2), Some(ControlType::Rebind));
        assert_eq!(ControlType::from_u8(3), Some(ControlType::RebindAck));
        assert_eq!(ControlType::from_u8(4), Some(ControlType::Config));
        assert_eq!(ControlType::from_u8(5), Some(ControlType::Close));
    }

    #[test]
    fn test_control_type_invalid() {
        assert!(ControlType::from_u8(0).is_none());
        assert!(ControlType::from_u8(6).is_none());
        assert!(ControlType::from_u8(255).is_none());
    }

    #[test]
    fn test_session_id_clone() {
        let id1 = SessionId::generate();
        let id2 = id1;

        assert_eq!(id1, id2);
    }

    #[test]
    fn test_key_id_clone() {
        let id1 = KeyId::initial();
        let id2 = id1;

        assert_eq!(id1, id2);
    }

    #[test]
    fn test_counter_clone() {
        let c1 = Counter::initial();
        let c2 = c1;

        assert_eq!(c1, c2);
    }

    #[test]
    fn test_message_type_clone() {
        let mt1 = MessageType::Data;
        let mt2 = mt1;

        assert_eq!(mt1, mt2);
    }

    #[test]
    fn test_session_id_display() {
        let id = SessionId(0x1234_5678_9ABC_DEF0);
        let display = format!("{}", id);
        assert_eq!(display, "123456789abcdef0");
    }

    #[test]
    fn test_session_id_debug() {
        let id = SessionId(0xABCD);
        let debug = format!("{:?}", id);
        assert!(debug.contains("SessionId"));
        assert!(debug.contains("abcd"));
    }

    #[test]
    fn test_session_id_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();

        set.insert(SessionId(1));
        set.insert(SessionId(2));
        set.insert(SessionId(1)); // Duplicate

        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_key_id_default() {
        let id = KeyId::default();
        assert_eq!(id.0, 0);
        assert_eq!(id, KeyId::initial());
    }

    #[test]
    fn test_counter_default() {
        let counter = Counter::default();
        assert_eq!(counter.0, 0);
        assert_eq!(counter, Counter::initial());
    }

    #[test]
    fn test_protocol_version_constant() {
        assert_eq!(PROTOCOL_VERSION, 1);
    }

    #[test]
    fn test_default_mtu_constant() {
        assert_eq!(DEFAULT_MTU, 1420);
    }

    #[test]
    fn test_message_type_equality_checks() {
        assert_eq!(MessageType::Data, MessageType::Data);
        assert_ne!(MessageType::Data, MessageType::Keepalive);
        assert_ne!(MessageType::HandshakeInit, MessageType::HandshakeResponse);
        assert_ne!(MessageType::Rekey, MessageType::RekeyResponse);
    }

    #[test]
    fn test_session_id_zero() {
        let id = SessionId(0);
        assert_eq!(id.0, 0);
    }

    #[test]
    fn test_session_id_max() {
        let id = SessionId(u64::MAX);
        assert_eq!(id.0, u64::MAX);
    }

    #[test]
    fn test_key_id_values() {
        let id1 = KeyId(0);
        assert_eq!(id1.0, 0);

        let id2 = KeyId(100);
        assert_eq!(id2.0, 100);

        let id3 = KeyId(u32::MAX);
        assert_eq!(id3.0, u32::MAX);
    }

    #[test]
    fn test_counter_values() {
        let c1 = Counter(0);
        assert_eq!(c1.0, 0);

        let c2 = Counter(1000);
        assert_eq!(c2.0, 1000);

        let c3 = Counter(u64::MAX);
        assert_eq!(c3.0, u64::MAX);
    }

    #[test]
    fn test_message_type_equality_comprehensive() {
        // Test all combinations to ensure proper PartialEq implementation
        let types = [
            (MessageType::HandshakeInit, "HandshakeInit"),
            (MessageType::HandshakeResponse, "HandshakeResponse"),
            (MessageType::Data, "Data"),
            (MessageType::Keepalive, "Keepalive"),
            (MessageType::Rekey, "Rekey"),
            (MessageType::Control, "Control"),
        ];

        for (i, (type_a, name_a)) in types.iter().enumerate() {
            for (j, (type_b, name_b)) in types.iter().enumerate() {
                if i == j {
                    assert_eq!(type_a, type_b, "{} should equal {}", name_a, name_b);
                } else {
                    assert_ne!(type_a, type_b, "{} should not equal {}", name_a, name_b);
                }
            }
        }
    }

    #[test]
    fn test_session_id_formatting_comprehensive() {
        let test_cases = vec![
            (SessionId(0), "0000000000000000"),
            (SessionId(1), "0000000000000001"),
            (SessionId(0xABCD), "000000000000abcd"),
            (SessionId(u64::MAX), "ffffffffffffffff"),
        ];

        for (id, expected) in test_cases {
            assert_eq!(format!("{}", id), expected);
        }
    }

    #[test]
    fn test_session_id_equality() {
        let id1 = SessionId(12345);
        let id2 = SessionId(12345);
        let id3 = SessionId(67890);

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_key_id_equality() {
        let id1 = KeyId(100);
        let id2 = KeyId(100);
        let id3 = KeyId(200);

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_counter_equality() {
        let c1 = Counter(5000);
        let c2 = Counter(5000);
        let c3 = Counter(10000);

        assert_eq!(c1, c2);
        assert_ne!(c1, c3);
    }

    #[test]
    fn test_message_type_copy() {
        let mt1 = MessageType::Data;
        let mt2 = mt1;

        assert_eq!(mt1, mt2);
    }

    #[test]
    fn test_session_id_inner_value() {
        let id = SessionId(0x1234_5678_9ABC_DEF0);
        assert_eq!(id.0, 0x1234_5678_9ABC_DEF0);
    }

    #[test]
    fn test_key_id_inner_value() {
        let id = KeyId(42);
        assert_eq!(id.0, 42);
    }

    #[test]
    fn test_counter_inner_value() {
        let counter = Counter(999);
        assert_eq!(counter.0, 999);
    }

    #[test]
    fn test_session_id_not_equal() {
        let id1 = SessionId(100);
        let id2 = SessionId(200);
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_key_id_not_equal() {
        let id1 = KeyId(10);
        let id2 = KeyId(20);
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_counter_not_equal() {
        let c1 = Counter(1000);
        let c2 = Counter(2000);
        assert_ne!(c1, c2);
    }
}
