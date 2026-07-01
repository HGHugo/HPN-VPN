//! Error types for the HPN library.

use thiserror::Error;

/// Result type alias using the HPN error type.
pub type Result<T> = std::result::Result<T, Error>;

/// Main error type for the HPN library.
#[derive(Debug, Error)]
pub enum Error {
    /// Cryptographic operation failed.
    #[error("cryptographic error: {0}")]
    Crypto(#[from] CryptoError),

    /// Protocol error.
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Session error.
    #[error("session error: {0}")]
    Session(#[from] SessionError),
}

/// Cryptographic errors.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Key generation failed.
    #[error("key generation failed")]
    KeyGeneration,

    /// Key encapsulation failed.
    #[error("key encapsulation failed")]
    Encapsulation,

    /// Key decapsulation failed.
    #[error("key decapsulation failed")]
    Decapsulation,

    /// Signature generation failed.
    #[error("signature generation failed")]
    SignatureGeneration,

    /// Signature verification failed.
    #[error("signature verification failed")]
    SignatureVerification,

    /// Encryption failed.
    #[error("encryption failed")]
    Encryption,

    /// Decryption failed.
    #[error("decryption failed")]
    Decryption,

    /// Key derivation failed.
    #[error("key derivation failed")]
    KeyDerivation,

    /// Invalid key length.
    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    /// Invalid nonce.
    #[error("invalid nonce")]
    InvalidNonce,

    /// Buffer too small.
    #[error("buffer too small: need {needed}, have {available}")]
    BufferTooSmall { needed: usize, available: usize },

    /// Counter exhausted - nonce reuse would occur.
    #[error("counter exhausted - rekey required to prevent nonce reuse")]
    CounterExhausted,

    /// Invalid public key (weak or malicious key detected).
    #[error("invalid public key: weak or low-order point detected")]
    InvalidPublicKey,
}

/// Protocol errors.
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// Invalid protocol version.
    #[error("invalid protocol version: {0}")]
    InvalidVersion(u8),

    /// Invalid message type.
    #[error("invalid message type: {0}")]
    InvalidMessageType(u8),

    /// Invalid packet length.
    #[error("invalid packet length: {0}")]
    InvalidLength(usize),

    /// Packet too short.
    #[error("packet too short: need {needed}, have {available}")]
    PacketTooShort { needed: usize, available: usize },

    /// Invalid header.
    #[error("invalid header")]
    InvalidHeader,

    /// Unknown bits set in the header flags byte (FIX-024).
    ///
    /// A peer set a flag bit that this protocol revision has not allocated.
    /// Forwards-compat is opt-in: we refuse the packet rather than
    /// silently dropping the unknown bits.
    #[error("invalid header flags byte: 0x{0:02x} contains undefined bits")]
    InvalidHeaderFlags(u8),

    /// Non-zero `reserved` byte in the header (FIX-024).
    ///
    /// The wire format pins the reserved byte to zero; any other value is
    /// either a future extension we have not implemented yet or a packet
    /// from a different protocol that happens to share the version byte.
    #[error("invalid header reserved byte: 0x{0:02x} (must be 0)")]
    InvalidReservedByte(u8),

    /// Unexpected message type.
    #[error("unexpected message type: expected {expected:?}, got {actual:?}")]
    UnexpectedMessageType {
        expected: crate::types::MessageType,
        actual: crate::types::MessageType,
    },

    /// Handshake failed.
    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    /// Invalid state transition.
    #[error("invalid state transition")]
    InvalidStateTransition,

    /// Replay attack detected.
    #[error("replay attack detected: counter {0}")]
    ReplayDetected(u64),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Invalid data in message.
    #[error("invalid data: {0}")]
    InvalidData(String),
}

/// Session errors.
#[derive(Debug, Error)]
pub enum SessionError {
    /// Session not found.
    #[error("session not found: {0}")]
    NotFound(crate::types::SessionId),

    /// Session expired.
    #[error("session expired")]
    Expired,

    /// Session limit reached.
    #[error("session limit reached")]
    LimitReached,

    /// Invalid session state.
    #[error("invalid session state")]
    InvalidState,

    /// Key ID mismatch.
    #[error("key ID mismatch: expected {expected}, got {actual}")]
    KeyIdMismatch { expected: u32, actual: u32 },

    /// IP pool exhausted.
    #[error("IP address pool exhausted")]
    IpPoolExhausted,

    /// Counter exhausted (requires rekey to prevent nonce reuse).
    #[error("counter exhausted - rekey required to prevent nonce reuse")]
    CounterExhausted,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_error_display() {
        let err = CryptoError::KeyGeneration;
        assert_eq!(err.to_string(), "key generation failed");

        let err = CryptoError::InvalidKeyLength {
            expected: 32,
            actual: 16,
        };
        assert!(err.to_string().contains("expected 32"));
        assert!(err.to_string().contains("got 16"));

        let err = CryptoError::BufferTooSmall {
            needed: 100,
            available: 50,
        };
        assert!(err.to_string().contains("need 100"));
        assert!(err.to_string().contains("have 50"));
    }

    #[test]
    fn test_protocol_error_display() {
        let err = ProtocolError::InvalidVersion(99);
        assert!(err.to_string().contains("99"));

        let err = ProtocolError::PacketTooShort {
            needed: 256,
            available: 128,
        };
        assert!(err.to_string().contains("256"));
        assert!(err.to_string().contains("128"));

        let err = ProtocolError::HandshakeFailed("test failure".to_string());
        assert!(err.to_string().contains("test failure"));

        let err = ProtocolError::ReplayDetected(12345);
        assert!(err.to_string().contains("12345"));
    }

    #[test]
    fn test_session_error_display() {
        use crate::types::SessionId;

        let session_id = SessionId::generate();
        let err = SessionError::NotFound(session_id);
        assert!(err.to_string().contains("not found"));

        let err = SessionError::KeyIdMismatch {
            expected: 5,
            actual: 3,
        };
        assert!(err.to_string().contains("expected 5"));
        assert!(err.to_string().contains("got 3"));

        let err = SessionError::CounterExhausted;
        assert!(err.to_string().contains("counter exhausted"));
        assert!(err.to_string().contains("rekey required"));
    }

    #[test]
    fn test_error_from_crypto() {
        let crypto_err = CryptoError::Encryption;
        let err: Error = crypto_err.into();
        assert!(err.to_string().contains("cryptographic error"));
        assert!(err.to_string().contains("encryption failed"));
    }

    #[test]
    fn test_error_from_protocol() {
        let protocol_err = ProtocolError::InvalidHeader;
        let err: Error = protocol_err.into();
        assert!(err.to_string().contains("protocol error"));
        assert!(err.to_string().contains("invalid header"));
    }

    #[test]
    fn test_error_from_session() {
        let session_err = SessionError::Expired;
        let err: Error = session_err.into();
        assert!(err.to_string().contains("session error"));
        assert!(err.to_string().contains("expired"));
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err: Error = io_err.into();
        assert!(err.to_string().contains("I/O error"));
    }

    #[test]
    fn test_all_crypto_errors() {
        let errors = vec![
            CryptoError::KeyGeneration,
            CryptoError::Encapsulation,
            CryptoError::Decapsulation,
            CryptoError::SignatureGeneration,
            CryptoError::SignatureVerification,
            CryptoError::Encryption,
            CryptoError::Decryption,
            CryptoError::KeyDerivation,
            CryptoError::InvalidNonce,
        ];

        for err in errors {
            let s = err.to_string();
            assert!(!s.is_empty(), "Error message should not be empty");
        }
    }

    #[test]
    fn test_all_protocol_errors() {
        use crate::types::MessageType;

        let errors: Vec<ProtocolError> = vec![
            ProtocolError::InvalidVersion(1),
            ProtocolError::InvalidMessageType(255),
            ProtocolError::InvalidLength(0),
            ProtocolError::InvalidHeader,
            ProtocolError::UnexpectedMessageType {
                expected: MessageType::Data,
                actual: MessageType::Keepalive,
            },
            ProtocolError::InvalidStateTransition,
            ProtocolError::Serialization("test".to_string()),
            ProtocolError::InvalidData("test data".to_string()),
        ];

        for err in errors {
            let s = err.to_string();
            assert!(!s.is_empty(), "Error message should not be empty");
        }
    }

    #[test]
    fn test_all_session_errors() {
        use crate::types::SessionId;

        let errors = vec![
            SessionError::NotFound(SessionId::generate()),
            SessionError::Expired,
            SessionError::LimitReached,
            SessionError::InvalidState,
            SessionError::IpPoolExhausted,
            SessionError::CounterExhausted,
        ];

        for err in errors {
            let s = err.to_string();
            assert!(!s.is_empty(), "Error message should not be empty");
        }
    }

    #[test]
    fn test_error_debug() {
        let err = CryptoError::KeyGeneration;
        let debug = format!("{:?}", err);
        assert!(debug.contains("KeyGeneration"));

        let err = ProtocolError::InvalidHeader;
        let debug = format!("{:?}", err);
        assert!(debug.contains("InvalidHeader"));

        let err = SessionError::Expired;
        let debug = format!("{:?}", err);
        assert!(debug.contains("Expired"));
    }

    #[test]
    fn test_result_type_alias() {
        fn returns_result() -> Result<i32> {
            Ok(42)
        }

        fn returns_error() -> Result<i32> {
            Err(CryptoError::KeyGeneration.into())
        }

        assert_eq!(returns_result().unwrap(), 42);
        assert!(returns_error().is_err());
    }

    #[test]
    fn test_crypto_error_variants_exhaustive() {
        // Test all CryptoError variants to ensure complete coverage
        let errors = vec![
            CryptoError::KeyGeneration,
            CryptoError::Encapsulation,
            CryptoError::Decapsulation,
            CryptoError::SignatureGeneration,
            CryptoError::SignatureVerification,
            CryptoError::Encryption,
            CryptoError::Decryption,
            CryptoError::KeyDerivation,
            CryptoError::InvalidKeyLength {
                expected: 32,
                actual: 16,
            },
            CryptoError::InvalidNonce,
            CryptoError::BufferTooSmall {
                needed: 100,
                available: 50,
            },
            CryptoError::CounterExhausted,
            CryptoError::InvalidPublicKey,
        ];

        for err in errors {
            // Ensure Debug works
            let _ = format!("{:?}", err);
            // Ensure Display works
            let _ = err.to_string();
        }
    }

    #[test]
    fn test_protocol_error_variants_exhaustive() {
        use crate::types::MessageType;

        let errors = vec![
            ProtocolError::InvalidVersion(1),
            ProtocolError::InvalidMessageType(255),
            ProtocolError::InvalidLength(9999),
            ProtocolError::PacketTooShort {
                needed: 100,
                available: 50,
            },
            ProtocolError::InvalidHeader,
            ProtocolError::UnexpectedMessageType {
                expected: MessageType::HandshakeInit,
                actual: MessageType::HandshakeResponse,
            },
            ProtocolError::HandshakeFailed("reason".to_string()),
            ProtocolError::InvalidStateTransition,
            ProtocolError::ReplayDetected(12345),
            ProtocolError::Serialization("error".to_string()),
            ProtocolError::InvalidData("bad data".to_string()),
        ];

        for err in errors {
            let _ = format!("{:?}", err);
            let _ = err.to_string();
        }
    }

    #[test]
    fn test_session_error_variants_exhaustive() {
        use crate::types::SessionId;

        let errors = vec![
            SessionError::NotFound(SessionId::generate()),
            SessionError::Expired,
            SessionError::LimitReached,
            SessionError::InvalidState,
            SessionError::KeyIdMismatch {
                expected: 1,
                actual: 2,
            },
            SessionError::IpPoolExhausted,
            SessionError::CounterExhausted,
        ];

        for err in errors {
            let _ = format!("{:?}", err);
            let _ = err.to_string();
        }
    }

    #[test]
    fn test_error_source_chain() {
        let crypto_err = CryptoError::Encryption;
        let err: Error = crypto_err.into();

        // Test that error can be downcast
        assert!(format!("{:?}", err).contains("Crypto"));
    }

    #[test]
    fn test_error_conversions() {
        // Test all From implementations
        let _: Error = CryptoError::KeyGeneration.into();
        let _: Error = ProtocolError::InvalidHeader.into();
        let _: Error = SessionError::Expired.into();
        let _: Error = std::io::Error::other("test").into();
    }

    #[test]
    fn test_crypto_error_equality() {
        let err1 = CryptoError::Encryption;
        let err2 = CryptoError::Encryption;
        assert_eq!(format!("{:?}", err1), format!("{:?}", err2));
    }

    #[test]
    fn test_protocol_error_serialization_display() {
        let err = ProtocolError::Serialization("test error".to_string());
        assert!(err.to_string().contains("serialization error"));
        assert!(err.to_string().contains("test error"));
    }

    #[test]
    fn test_protocol_error_invalid_data_display() {
        let err = ProtocolError::InvalidData("corrupted".to_string());
        assert!(err.to_string().contains("invalid data"));
        assert!(err.to_string().contains("corrupted"));
    }
}
