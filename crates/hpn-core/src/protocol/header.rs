//! HPN packet header format.
//!
//! All HPN packets start with a fixed-size header that identifies
//! the session, message type, and provides anti-replay protection.

use bitflags::bitflags;

use crate::error::ProtocolError;
use crate::types::{Counter, KeyId, MessageType, PROTOCOL_VERSION, SessionId};

/// Packet header size in bytes (without optional timestamp).
pub const HEADER_SIZE: usize = 24;

/// Packet header size with optional timestamp.
pub const HEADER_SIZE_WITH_TIMESTAMP: usize = 32;

bitflags! {
    /// Header flags byte.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct HeaderFlags: u8 {
        /// Packet includes a timestamp for RTT measurement.
        const HAS_TIMESTAMP = 0b0000_0001;
        /// Rekey is being requested.
        const REKEY_REQUEST = 0b0000_0010;
        /// This is an acknowledgment packet.
        const ACK = 0b0000_0100;
        /// Reserved for future use.
        const RESERVED_1 = 0b0001_0000;
        const RESERVED_2 = 0b0010_0000;
        const RESERVED_3 = 0b0100_0000;
        const RESERVED_4 = 0b1000_0000;
    }
}

/// HPN packet header.
///
/// # Wire Format (24 bytes, 32 with timestamp)
///
/// ```text
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Version   |    Type     |    Flags    |    Reserved       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Session ID                          |
/// |                           (8 bytes)                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          Key ID                             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          Counter                            |
/// |                          (8 bytes)                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                     Timestamp (optional)                    |
/// |                          (8 bytes)                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketHeader {
    /// Protocol version (must be PROTOCOL_VERSION).
    pub version: u8,
    /// Message type.
    pub msg_type: MessageType,
    /// Header flags.
    pub flags: HeaderFlags,
    /// Reserved byte (must be 0).
    pub reserved: u8,
    /// Session identifier.
    pub session_id: SessionId,
    /// Key identifier for key rotation.
    pub key_id: KeyId,
    /// Packet counter for anti-replay.
    pub counter: Counter,
    /// Optional timestamp for RTT measurement.
    pub timestamp: Option<u64>,
}

impl PacketHeader {
    /// Create a new packet header.
    #[must_use]
    pub fn new(
        msg_type: MessageType,
        session_id: SessionId,
        key_id: KeyId,
        counter: Counter,
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            msg_type,
            flags: HeaderFlags::empty(),
            reserved: 0,
            session_id,
            key_id,
            counter,
            timestamp: None,
        }
    }

    /// Create a header with timestamp.
    #[must_use]
    pub fn with_timestamp(mut self, timestamp: u64) -> Self {
        self.flags |= HeaderFlags::HAS_TIMESTAMP;
        self.timestamp = Some(timestamp);
        self
    }

    /// Get the encoded size of this header.
    #[must_use]
    pub const fn encoded_size(&self) -> usize {
        if self.timestamp.is_some() {
            HEADER_SIZE_WITH_TIMESTAMP
        } else {
            HEADER_SIZE
        }
    }

    /// Encode the header to bytes.
    ///
    /// # Returns
    ///
    /// The number of bytes written.
    #[inline]
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, ProtocolError> {
        let size = self.encoded_size();
        if buf.len() < size {
            return Err(ProtocolError::PacketTooShort {
                needed: size,
                available: buf.len(),
            });
        }

        buf[0] = self.version;
        buf[1] = self.msg_type.as_u8();

        // Set HAS_TIMESTAMP flag if timestamp is present
        let mut flags = self.flags;
        if self.timestamp.is_some() {
            flags.insert(HeaderFlags::HAS_TIMESTAMP);
        }
        buf[2] = flags.bits();

        buf[3] = self.reserved;

        buf[4..12].copy_from_slice(&self.session_id.to_bytes());
        buf[12..16].copy_from_slice(&self.key_id.to_bytes());
        buf[16..24].copy_from_slice(&self.counter.to_bytes());

        if let Some(ts) = self.timestamp {
            buf[24..32].copy_from_slice(&ts.to_be_bytes());
        }

        Ok(size)
    }

    /// Decode a header from bytes.
    #[inline]
    pub fn decode(buf: &[u8]) -> Result<Self, ProtocolError> {
        if buf.len() < HEADER_SIZE {
            return Err(ProtocolError::PacketTooShort {
                needed: HEADER_SIZE,
                available: buf.len(),
            });
        }

        let version = buf[0];
        if version != PROTOCOL_VERSION {
            return Err(ProtocolError::InvalidVersion(version));
        }

        let msg_type =
            MessageType::from_u8(buf[1]).ok_or(ProtocolError::InvalidMessageType(buf[1]))?;

        // FIX-024: reject flag bits we have not allocated yet. The previous
        // `from_bits_truncate` call silently dropped unknown bits, which let a
        // forward-compatible client set a future flag in `buf[2]` and have
        // the current server interpret it as "no flags set" — semantic drift
        // that can become a downgrade vector once the bit is repurposed.
        //
        // `HeaderFlags::from_bits` returns `None` when the raw byte contains
        // bits NOT defined in the bitflags! macro above (currently
        // `HAS_TIMESTAMP | REKEY_REQUEST | ACK | RESERVED_{1..4}` = 0b1111_0111;
        // bit 3 — 0b0000_1000 — is intentionally undefined). Treat that as
        // a hard parse error rather than coerce to a partial flag set.
        let flags =
            HeaderFlags::from_bits(buf[2]).ok_or(ProtocolError::InvalidHeaderFlags(buf[2]))?;
        // Reserved byte MUST be zero on the wire. A non-zero value here is
        // either a wire-format extension we have not implemented yet (treat
        // as a parse error so older servers don't silently drop the
        // semantics) or a packet from an entirely different protocol that
        // happens to share the message-type prefix.
        let reserved = buf[3];
        if reserved != 0 {
            return Err(ProtocolError::InvalidReservedByte(reserved));
        }

        let mut session_id_bytes = [0u8; 8];
        session_id_bytes.copy_from_slice(&buf[4..12]);
        let session_id = SessionId::from_bytes(session_id_bytes);

        let mut key_id_bytes = [0u8; 4];
        key_id_bytes.copy_from_slice(&buf[12..16]);
        let key_id = KeyId::from_bytes(key_id_bytes);

        let mut counter_bytes = [0u8; 8];
        counter_bytes.copy_from_slice(&buf[16..24]);
        let counter = Counter::from_bytes(counter_bytes);

        let timestamp = if flags.contains(HeaderFlags::HAS_TIMESTAMP) {
            if buf.len() < HEADER_SIZE_WITH_TIMESTAMP {
                return Err(ProtocolError::PacketTooShort {
                    needed: HEADER_SIZE_WITH_TIMESTAMP,
                    available: buf.len(),
                });
            }
            let mut ts_bytes = [0u8; 8];
            ts_bytes.copy_from_slice(&buf[24..32]);
            Some(u64::from_be_bytes(ts_bytes))
        } else {
            None
        };

        Ok(Self {
            version,
            msg_type,
            flags,
            reserved,
            session_id,
            key_id,
            counter,
            timestamp,
        })
    }

    /// Get the header bytes as a slice (for AAD in encryption).
    ///
    /// # Safety
    ///
    /// The buffer must have been encoded with `encode()` first.
    pub fn as_aad<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        &buf[..self.encoded_size()]
    }
}

impl Default for PacketHeader {
    fn default() -> Self {
        Self {
            version: PROTOCOL_VERSION,
            msg_type: MessageType::Data,
            flags: HeaderFlags::empty(),
            reserved: 0,
            session_id: SessionId(0),
            key_id: KeyId::initial(),
            counter: Counter::initial(),
            timestamp: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_encode_decode_roundtrip() {
        let header = PacketHeader::new(
            MessageType::Data,
            SessionId(0x1234_5678_9ABC_DEF0),
            KeyId(42),
            Counter(12345),
        );

        let mut buf = [0u8; HEADER_SIZE];
        let size = header.encode(&mut buf).unwrap();
        assert_eq!(size, HEADER_SIZE);

        let decoded = PacketHeader::decode(&buf).unwrap();
        assert_eq!(header, decoded);
    }

    #[test]
    fn test_header_with_timestamp() {
        let header = PacketHeader::new(
            MessageType::Keepalive,
            SessionId(0x1234_5678_9ABC_DEF0),
            KeyId(1),
            Counter(100),
        )
        .with_timestamp(0xDEAD_BEEF_CAFE_BABE);

        assert!(header.flags.contains(HeaderFlags::HAS_TIMESTAMP));
        assert_eq!(header.encoded_size(), HEADER_SIZE_WITH_TIMESTAMP);

        let mut buf = [0u8; HEADER_SIZE_WITH_TIMESTAMP];
        let size = header.encode(&mut buf).unwrap();
        assert_eq!(size, HEADER_SIZE_WITH_TIMESTAMP);

        let decoded = PacketHeader::decode(&buf).unwrap();
        assert_eq!(header.timestamp, decoded.timestamp);
        assert_eq!(decoded.timestamp, Some(0xDEAD_BEEF_CAFE_BABE));
    }

    #[test]
    fn test_invalid_version() {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0] = 99; // Invalid version

        let result = PacketHeader::decode(&buf);
        assert!(matches!(result, Err(ProtocolError::InvalidVersion(99))));
    }

    #[test]
    fn test_invalid_message_type() {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0] = PROTOCOL_VERSION;
        buf[1] = 0; // Invalid message type

        let result = PacketHeader::decode(&buf);
        assert!(matches!(result, Err(ProtocolError::InvalidMessageType(0))));
    }

    #[test]
    fn test_buffer_too_short() {
        let buf = [0u8; 10];
        let result = PacketHeader::decode(&buf);
        assert!(matches!(result, Err(ProtocolError::PacketTooShort { .. })));
    }

    #[test]
    fn test_all_message_types() {
        for msg_type in [
            MessageType::HandshakeInit,
            MessageType::HandshakeResponse,
            MessageType::Data,
            MessageType::Keepalive,
            MessageType::KeepaliveReply,
            MessageType::Control,
            MessageType::Rekey,
        ] {
            let header = PacketHeader::new(msg_type, SessionId(1), KeyId(0), Counter(0));

            let mut buf = [0u8; HEADER_SIZE];
            header.encode(&mut buf).unwrap();

            let decoded = PacketHeader::decode(&buf).unwrap();
            assert_eq!(decoded.msg_type, msg_type);
        }
    }

    #[test]
    fn test_flags() {
        let header = PacketHeader {
            flags: HeaderFlags::REKEY_REQUEST | HeaderFlags::ACK,
            ..Default::default()
        };

        let mut buf = [0u8; HEADER_SIZE];
        header.encode(&mut buf).unwrap();

        let decoded = PacketHeader::decode(&buf).unwrap();
        assert!(decoded.flags.contains(HeaderFlags::REKEY_REQUEST));
        assert!(decoded.flags.contains(HeaderFlags::ACK));
        assert!(!decoded.flags.contains(HeaderFlags::HAS_TIMESTAMP));
    }

    #[test]
    fn test_header_flags_empty() {
        let flags = HeaderFlags::empty();
        assert!(!flags.contains(HeaderFlags::HAS_TIMESTAMP));
        assert!(!flags.contains(HeaderFlags::ACK));
    }

    #[test]
    fn test_header_flags_has_timestamp() {
        let flags = HeaderFlags::HAS_TIMESTAMP;
        assert!(flags.contains(HeaderFlags::HAS_TIMESTAMP));
        assert!(!flags.contains(HeaderFlags::ACK));
    }

    #[test]
    fn test_header_flags_ack() {
        let flags = HeaderFlags::ACK;
        assert!(flags.contains(HeaderFlags::ACK));
        assert!(!flags.contains(HeaderFlags::HAS_TIMESTAMP));
    }

    #[test]
    fn test_header_flags_combined() {
        let flags = HeaderFlags::HAS_TIMESTAMP | HeaderFlags::ACK;
        assert!(flags.contains(HeaderFlags::HAS_TIMESTAMP));
        assert!(flags.contains(HeaderFlags::ACK));
    }

    #[test]
    fn test_header_version_constant() {
        assert_eq!(PROTOCOL_VERSION, 1);
    }

    #[test]
    fn test_header_size_constant() {
        assert_eq!(HEADER_SIZE, 24);
    }

    #[test]
    fn test_header_size_with_timestamp_constant() {
        assert_eq!(HEADER_SIZE_WITH_TIMESTAMP, 32);
    }

    #[test]
    fn test_header_new_defaults() {
        let header = PacketHeader::new(MessageType::Data, SessionId(123), KeyId(1), Counter(100));

        assert_eq!(header.version, PROTOCOL_VERSION);
        assert_eq!(header.msg_type, MessageType::Data);
        assert_eq!(header.session_id.0, 123);
        assert_eq!(header.key_id.0, 1);
        assert_eq!(header.counter.0, 100);
        assert_eq!(header.timestamp, None);
        assert!(header.flags.is_empty());
    }

    #[test]
    fn test_header_with_timestamp_sets_flag() {
        let header = PacketHeader::new(MessageType::Keepalive, SessionId(1), KeyId(0), Counter(1))
            .with_timestamp(12345);

        assert_eq!(header.timestamp, Some(12345));
        assert!(header.flags.contains(HeaderFlags::HAS_TIMESTAMP));
    }

    #[test]
    fn test_header_encoded_size_without_timestamp() {
        let header = PacketHeader::new(MessageType::Data, SessionId(1), KeyId(0), Counter(1));

        assert_eq!(header.encoded_size(), HEADER_SIZE);
    }

    #[test]
    fn test_header_encoded_size_with_timestamp() {
        let header = PacketHeader::new(MessageType::Data, SessionId(1), KeyId(0), Counter(1))
            .with_timestamp(999);

        assert_eq!(header.encoded_size(), HEADER_SIZE_WITH_TIMESTAMP);
    }

    #[test]
    fn test_header_decode_buffer_too_short() {
        let short_buf = [0u8; 10];
        let result = PacketHeader::decode(&short_buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_header_encode_all_message_types() {
        let message_types = vec![
            MessageType::HandshakeInit,
            MessageType::HandshakeResponse,
            MessageType::Data,
            MessageType::Keepalive,
            MessageType::KeepaliveReply,
            MessageType::Control,
            MessageType::Rekey,
            MessageType::RekeyResponse,
        ];

        for msg_type in message_types {
            let header = PacketHeader::new(msg_type, SessionId(1), KeyId(0), Counter(1));

            let mut buf = [0u8; HEADER_SIZE];
            assert!(header.encode(&mut buf).is_ok());

            let decoded = PacketHeader::decode(&buf).unwrap();
            assert_eq!(decoded.msg_type, msg_type);
        }
    }

    #[test]
    fn test_header_max_values() {
        let header = PacketHeader::new(
            MessageType::Data,
            SessionId(u64::MAX),
            KeyId(u32::MAX),
            Counter(u64::MAX - 1),
        );

        let mut buf = [0u8; HEADER_SIZE];
        header.encode(&mut buf).unwrap();

        let decoded = PacketHeader::decode(&buf).unwrap();
        assert_eq!(decoded.session_id.0, u64::MAX);
        assert_eq!(decoded.key_id.0, u32::MAX);
        assert_eq!(decoded.counter.0, u64::MAX - 1);
    }

    #[test]
    fn test_header_zero_values() {
        let header = PacketHeader::new(MessageType::Data, SessionId(0), KeyId(0), Counter(0));

        let mut buf = [0u8; HEADER_SIZE];
        header.encode(&mut buf).unwrap();

        let decoded = PacketHeader::decode(&buf).unwrap();
        assert_eq!(decoded.session_id.0, 0);
        assert_eq!(decoded.key_id.0, 0);
        assert_eq!(decoded.counter.0, 0);
    }

    // Property-based tests using proptest
    #[cfg(test)]
    #[allow(clippy::match_same_arms)]
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn prop_header_encode_decode_roundtrip(
                session_id in any::<u64>(),
                key_id in 0u32..=255,
                counter in 0u64..1_000_000,
                msg_type_val in 1u8..=7  // MessageType enum values
            ) {
                // PROPERTY TEST: Header serialization roundtrip
                // Property: encode(decode(x)) == x for all valid headers

                let msg_type = match msg_type_val {
                    1 => MessageType::HandshakeInit,
                    2 => MessageType::HandshakeResponse,
                    4 => MessageType::Keepalive,
                    5 => MessageType::KeepaliveReply,
                    6 => MessageType::Control,
                    7 => MessageType::Rekey,
                    _ => MessageType::Data, // 3 and other values map to Data
                };

                let header = PacketHeader::new(
                    msg_type,
                    SessionId(session_id),
                    KeyId(key_id),
                    Counter(counter),
                );

                let mut buf = [0u8; HEADER_SIZE];
                let encode_result = header.encode(&mut buf);
                prop_assert!(encode_result.is_ok(), "Encoding should succeed");

                let decoded = PacketHeader::decode(&buf)?;

                prop_assert_eq!(decoded.version, header.version, "Version mismatch");
                prop_assert_eq!(decoded.msg_type, header.msg_type, "Message type mismatch");
                prop_assert_eq!(decoded.session_id, header.session_id, "Session ID mismatch");
                prop_assert_eq!(decoded.key_id, header.key_id, "Key ID mismatch");
                prop_assert_eq!(decoded.counter, header.counter, "Counter mismatch");
            }

            #[test]
            fn prop_header_with_timestamp_roundtrip(
                session_id in any::<u64>(),
                timestamp in any::<u64>()
            ) {
                // PROPERTY TEST: Header with timestamp serialization
                // Property: Timestamp is correctly preserved in encode/decode

                let header = PacketHeader::new(
                    MessageType::Keepalive,
                    SessionId(session_id),
                    KeyId(1),
                    Counter(100),
                ).with_timestamp(timestamp);

                prop_assert!(header.flags.contains(HeaderFlags::HAS_TIMESTAMP));

                let mut buf = [0u8; HEADER_SIZE_WITH_TIMESTAMP];
                header.encode(&mut buf)?;

                let decoded = PacketHeader::decode(&buf)?;
                prop_assert_eq!(decoded.timestamp, Some(timestamp), "Timestamp should be preserved");
            }

            #[test]
            fn prop_header_size_consistency(
                has_timestamp in any::<bool>()
            ) {
                // PROPERTY TEST: Header size consistency
                // Property: encoded_size() matches actual encoded size

                let mut header = PacketHeader::new(
                    MessageType::Data,
                    SessionId(12345),
                    KeyId(1),
                    Counter(100),
                );

                if has_timestamp {
                    header = header.with_timestamp(0xDEAD_BEEF);
                }

                let expected_size = header.encoded_size();
                let mut buf = vec![0u8; expected_size];

                let actual_size = header.encode(&mut buf)?;
                prop_assert_eq!(actual_size, expected_size, "Encoded size should match encoded_size()");
            }
        }
    }
}
