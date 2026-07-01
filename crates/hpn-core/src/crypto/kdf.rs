//! Key derivation using HKDF-SHA-512.
//!
//! Derives traffic encryption keys from the combined handshake secret.

use ring::hkdf;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::keys::HandshakeSecret;
use crate::error::CryptoError;

/// Salt for handshake key derivation.
pub const HANDSHAKE_SALT: &[u8] = b"HPN-HYBRID-KEM-v1";

/// Info string for traffic key derivation.
pub const TRAFFIC_KEY_INFO: &[u8] = b"HPN-TRAFFIC-KEYS-v1";

/// Info string for send key derivation.
const SEND_KEY_INFO: &[u8] = b"send-key";

/// Info string for receive key derivation.
const RECV_KEY_INFO: &[u8] = b"recv-key";

/// Info string for send nonce prefix derivation.
const SEND_NONCE_PREFIX_INFO: &[u8] = b"send-nonce-prefix";

/// Info string for receive nonce prefix derivation.
const RECV_NONCE_PREFIX_INFO: &[u8] = b"recv-nonce-prefix";

/// Derived session keys for traffic encryption.
///
/// SECURITY NOTE: Nonce prefixes are now 4 bytes (not 12).
/// The full 96-bit nonce is constructed as: prefix(4 bytes) || counter(8 bytes).
/// This ensures nonce uniqueness across all sessions.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    /// AES-256 key for sending (32 bytes).
    pub send_key: [u8; 32],
    /// AES-256 key for receiving (32 bytes).
    pub recv_key: [u8; 32],
    /// Session-specific nonce prefix for sending (4 bytes).
    /// Full nonce = prefix || counter (96 bits total).
    pub send_nonce_prefix: [u8; 4],
    /// Session-specific nonce prefix for receiving (4 bytes).
    pub recv_nonce_prefix: [u8; 4],
}

impl SessionKeys {
    /// Total size of all keys (32 + 32 + 4 + 4 = 72 bytes).
    pub const SIZE: usize = 32 + 32 + 4 + 4;

    /// Swap send/recv keys (used to get the peer's perspective).
    #[must_use]
    pub fn swap(&self) -> Self {
        Self {
            send_key: self.recv_key,
            recv_key: self.send_key,
            send_nonce_prefix: self.recv_nonce_prefix,
            recv_nonce_prefix: self.send_nonce_prefix,
        }
    }
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKeys")
            .field("send_key", &"[REDACTED]")
            .field("recv_key", &"[REDACTED]")
            .field("send_nonce_prefix", &"[REDACTED]")
            .field("recv_nonce_prefix", &"[REDACTED]")
            .finish()
    }
}

/// Helper type for HKDF output length.
#[derive(Clone, Copy)]
struct HkdfKeyType(usize);

impl hkdf::KeyType for HkdfKeyType {
    fn len(&self) -> usize {
        self.0
    }
}

/// Derive session keys from the handshake secret with session context.
///
/// Uses HKDF-SHA-512:
/// 1. Extract: PRK = HKDF-Extract(salt=HANDSHAKE_SALT, IKM=handshake_secret)
/// 2. Expand: keys = HKDF-Expand(PRK, info=context || specific_label, length)
///
/// The session context (session_id || timestamp) is mixed into the info parameter
/// to ensure session isolation even if the same handshake secret were somehow reused.
///
/// # Arguments
///
/// * `handshake_secret` - The combined hybrid KEM secret
/// * `session_id` - Unique session identifier (8 bytes)
/// * `timestamp` - Unix timestamp in seconds (8 bytes, big-endian)
///
/// # Errors
///
/// Returns an error if key derivation fails.
pub fn derive_session_keys_with_context(
    handshake_secret: &HandshakeSecret,
    session_id: &crate::types::SessionId,
    timestamp: u64,
) -> Result<SessionKeys, CryptoError> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA512, HANDSHAKE_SALT);
    let prk = salt.extract(handshake_secret.as_bytes());

    // Build session context: session_id (8 bytes) || timestamp (8 bytes)
    let mut context = Vec::with_capacity(16);
    context.extend_from_slice(&session_id.to_bytes());
    context.extend_from_slice(&timestamp.to_be_bytes());

    // Derive send key (32 bytes) - include session context
    let mut send_key = [0u8; 32];
    prk.expand(
        &[TRAFFIC_KEY_INFO, &context, SEND_KEY_INFO],
        HkdfKeyType(32),
    )
    .map_err(|_| CryptoError::KeyDerivation)?
    .fill(&mut send_key)
    .map_err(|_| CryptoError::KeyDerivation)?;

    // Derive receive key (32 bytes) - include session context
    let mut recv_key = [0u8; 32];
    prk.expand(
        &[TRAFFIC_KEY_INFO, &context, RECV_KEY_INFO],
        HkdfKeyType(32),
    )
    .map_err(|_| CryptoError::KeyDerivation)?
    .fill(&mut recv_key)
    .map_err(|_| CryptoError::KeyDerivation)?;

    // Derive send nonce prefix (4 bytes) - include session context
    // This is session-specific and combined with 64-bit counter to form 96-bit nonce
    let mut send_nonce_prefix = [0u8; 4];
    prk.expand(
        &[TRAFFIC_KEY_INFO, &context, SEND_NONCE_PREFIX_INFO],
        HkdfKeyType(4),
    )
    .map_err(|_| CryptoError::KeyDerivation)?
    .fill(&mut send_nonce_prefix)
    .map_err(|_| CryptoError::KeyDerivation)?;

    // Derive receive nonce prefix (4 bytes) - include session context
    let mut recv_nonce_prefix = [0u8; 4];
    prk.expand(
        &[TRAFFIC_KEY_INFO, &context, RECV_NONCE_PREFIX_INFO],
        HkdfKeyType(4),
    )
    .map_err(|_| CryptoError::KeyDerivation)?
    .fill(&mut recv_nonce_prefix)
    .map_err(|_| CryptoError::KeyDerivation)?;

    Ok(SessionKeys {
        send_key,
        recv_key,
        send_nonce_prefix,
        recv_nonce_prefix,
    })
}

/// Derive session keys from the handshake secret using a **fixed**, null
/// context.
///
/// ⚠️ **Not for production code.** This variant feeds
/// `session_id = [0; 8]` and `timestamp = 0` into
/// [`derive_session_keys_with_context`]. Any two derivations sharing the
/// same [`HandshakeSecret`] therefore produce identical session keys,
/// which is catastrophic for rekey / handshake-retry paths where the
/// same `HandshakeSecret` may legitimately be derived twice (different
/// session IDs).
///
/// The production handshake and rekey paths both call
/// [`derive_session_keys_with_context`] with a real `session_id` and
/// `timestamp`. This shim exists only so that the in-crate unit tests
/// and the public criterion benchmarks (in `benches/`) do not need to
/// rebuild a synthetic context on every call. It is hidden from the
/// rustdoc surface.
///
/// # Errors
///
/// Returns an error if key derivation fails.
#[doc(hidden)]
pub fn derive_session_keys(handshake_secret: &HandshakeSecret) -> Result<SessionKeys, CryptoError> {
    // Use a fixed (all-zero) context. The name `dummy_` makes the hazard
    // explicit for anyone who stumbles into this function. Production
    // callers must use `derive_session_keys_with_context` directly.
    let dummy_session_id = crate::types::SessionId::from_bytes([0u8; 8]);
    let dummy_timestamp = 0u64;
    derive_session_keys_with_context(handshake_secret, &dummy_session_id, dummy_timestamp)
}

/// Derive a single key of arbitrary length.
///
/// # Errors
///
/// Returns an error if key derivation fails.
pub fn derive_key(
    handshake_secret: &HandshakeSecret,
    info: &[u8],
    output: &mut [u8],
) -> Result<(), CryptoError> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA512, HANDSHAKE_SALT);
    let prk = salt.extract(handshake_secret.as_bytes());

    prk.expand(&[info], HkdfKeyType(output.len()))
        .map_err(|_| CryptoError::KeyDerivation)?
        .fill(output)
        .map_err(|_| CryptoError::KeyDerivation)?;

    Ok(())
}

/// HKDF-Expand to derive key material from input key material.
///
/// This is a standalone function that can be used with any input key material
/// (not just HandshakeSecret). Used for identity hiding encryption.
///
/// # Arguments
///
/// * `ikm` - Input key material (e.g., shared secret from KEM)
/// * `info` - Context/application-specific info string
/// * `output` - Output buffer for derived key material
///
/// # Errors
///
/// Returns an error if key derivation fails.
pub fn hkdf_expand(ikm: &[u8], info: &[u8], output: &mut [u8]) -> Result<(), CryptoError> {
    // Use HKDF-SHA256 for identity hiding (32-byte output is typical)
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"HPN-IDENTITY-HIDING");
    let prk = salt.extract(ikm);

    prk.expand(&[info], HkdfKeyType(output.len()))
        .map_err(|_| CryptoError::KeyDerivation)?
        .fill(output)
        .map_err(|_| CryptoError::KeyDerivation)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::SharedSecret;

    fn test_handshake_secret() -> HandshakeSecret {
        let x25519 = SharedSecret::from_bytes([0x11u8; 32]);
        let mlkem = SharedSecret::from_bytes([0x22u8; 32]);
        HandshakeSecret::combine(&x25519, &mlkem)
    }

    #[test]
    fn test_derive_session_keys() {
        let hs = test_handshake_secret();
        let keys = derive_session_keys(&hs).unwrap();

        // Keys should be non-zero
        assert_ne!(keys.send_key, [0u8; 32]);
        assert_ne!(keys.recv_key, [0u8; 32]);
        assert_ne!(keys.send_nonce_prefix, [0u8; 4]);
        assert_ne!(keys.recv_nonce_prefix, [0u8; 4]);

        // Send and receive keys should be different
        assert_ne!(keys.send_key, keys.recv_key);
        assert_ne!(keys.send_nonce_prefix, keys.recv_nonce_prefix);
    }

    #[test]
    fn test_derive_deterministic() {
        let hs = test_handshake_secret();

        let keys1 = derive_session_keys(&hs).unwrap();
        let keys2 = derive_session_keys(&hs).unwrap();

        // Same input should produce same output
        assert_eq!(keys1.send_key, keys2.send_key);
        assert_eq!(keys1.recv_key, keys2.recv_key);
        assert_eq!(keys1.send_nonce_prefix, keys2.send_nonce_prefix);
        assert_eq!(keys1.recv_nonce_prefix, keys2.recv_nonce_prefix);
    }

    #[test]
    fn test_derive_different_inputs() {
        let hs1 = HandshakeSecret::combine(
            &SharedSecret::from_bytes([0x11u8; 32]),
            &SharedSecret::from_bytes([0x22u8; 32]),
        );
        let hs2 = HandshakeSecret::combine(
            &SharedSecret::from_bytes([0x33u8; 32]),
            &SharedSecret::from_bytes([0x44u8; 32]),
        );

        let keys1 = derive_session_keys(&hs1).unwrap();
        let keys2 = derive_session_keys(&hs2).unwrap();

        // Different inputs should produce different outputs
        assert_ne!(keys1.send_key, keys2.send_key);
        assert_ne!(keys1.recv_key, keys2.recv_key);
    }

    #[test]
    fn test_swap_keys() {
        let hs = test_handshake_secret();
        let keys = derive_session_keys(&hs).unwrap();
        let swapped = keys.swap();

        assert_eq!(keys.send_key, swapped.recv_key);
        assert_eq!(keys.recv_key, swapped.send_key);
        assert_eq!(keys.send_nonce_prefix, swapped.recv_nonce_prefix);
        assert_eq!(keys.recv_nonce_prefix, swapped.send_nonce_prefix);
    }

    #[test]
    fn test_derive_arbitrary_key() {
        let hs = test_handshake_secret();
        let mut output = [0u8; 64];

        derive_key(&hs, b"test-key", &mut output).unwrap();
        assert_ne!(output, [0u8; 64]);
    }

    #[test]
    fn test_derive_session_keys_with_context() {
        let hs = test_handshake_secret();
        let session_id = crate::types::SessionId::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]);
        let timestamp = 1_234_567_890u64;

        let keys = derive_session_keys_with_context(&hs, &session_id, timestamp).unwrap();

        assert_ne!(keys.send_key, [0u8; 32]);
        assert_ne!(keys.recv_key, [0u8; 32]);
    }

    #[test]
    fn test_derive_keys_different_contexts() {
        let hs = test_handshake_secret();
        let session_id1 = crate::types::SessionId::from_bytes([1, 0, 0, 0, 0, 0, 0, 0]);
        let session_id2 = crate::types::SessionId::from_bytes([2, 0, 0, 0, 0, 0, 0, 0]);

        let keys1 = derive_session_keys_with_context(&hs, &session_id1, 1000).unwrap();
        let keys2 = derive_session_keys_with_context(&hs, &session_id2, 1000).unwrap();

        // Different session IDs should produce different keys
        assert_ne!(keys1.send_key, keys2.send_key);
        assert_ne!(keys1.recv_key, keys2.recv_key);
    }

    #[test]
    fn test_derive_keys_different_timestamps() {
        let hs = test_handshake_secret();
        let session_id = crate::types::SessionId::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]);

        let keys1 = derive_session_keys_with_context(&hs, &session_id, 1000).unwrap();
        let keys2 = derive_session_keys_with_context(&hs, &session_id, 2000).unwrap();

        // Different timestamps should produce different keys
        assert_ne!(keys1.send_key, keys2.send_key);
        assert_ne!(keys1.recv_key, keys2.recv_key);
    }

    #[test]
    fn test_derive_arbitrary_key_different_info() {
        let hs = test_handshake_secret();
        let mut output1 = [0u8; 32];
        let mut output2 = [0u8; 32];

        derive_key(&hs, b"info1", &mut output1).unwrap();
        derive_key(&hs, b"info2", &mut output2).unwrap();

        // Different info strings should produce different keys
        assert_ne!(output1, output2);
    }

    #[test]
    fn test_derive_arbitrary_key_same_info() {
        let hs = test_handshake_secret();
        let mut output1 = [0u8; 32];
        let mut output2 = [0u8; 32];

        derive_key(&hs, b"same-info", &mut output1).unwrap();
        derive_key(&hs, b"same-info", &mut output2).unwrap();

        // Same info string should produce same keys
        assert_eq!(output1, output2);
    }

    #[test]
    fn test_derive_arbitrary_key_various_lengths() {
        let hs = test_handshake_secret();

        let mut out16 = [0u8; 16];
        let mut out32 = [0u8; 32];
        let mut out64 = [0u8; 64];
        let mut out128 = [0u8; 128];

        assert!(derive_key(&hs, b"test", &mut out16).is_ok());
        assert!(derive_key(&hs, b"test", &mut out32).is_ok());
        assert!(derive_key(&hs, b"test", &mut out64).is_ok());
        assert!(derive_key(&hs, b"test", &mut out128).is_ok());

        assert_ne!(out16, [0u8; 16]);
        assert_ne!(out32, [0u8; 32]);
        assert_ne!(out64, [0u8; 64]);
        assert_ne!(out128, [0u8; 128]);
    }

    #[test]
    fn test_session_keys_swap_twice() {
        let hs = test_handshake_secret();
        let keys = derive_session_keys(&hs).unwrap();
        let swapped_twice = keys.swap().swap();

        // Swapping twice should return original
        assert_eq!(keys.send_key, swapped_twice.send_key);
        assert_eq!(keys.recv_key, swapped_twice.recv_key);
        assert_eq!(keys.send_nonce_prefix, swapped_twice.send_nonce_prefix);
        assert_eq!(keys.recv_nonce_prefix, swapped_twice.recv_nonce_prefix);
    }

    #[test]
    fn test_derive_key_empty_info() {
        let hs = test_handshake_secret();
        let mut output = [0u8; 32];

        derive_key(&hs, b"", &mut output).unwrap();
        assert_ne!(output, [0u8; 32]);
    }

    #[test]
    fn test_session_keys_all_fields_initialized() {
        let hs = test_handshake_secret();
        let keys = derive_session_keys(&hs).unwrap();

        // Verify all fields are non-zero (properly initialized)
        assert!(keys.send_key.iter().any(|&b| b != 0));
        assert!(keys.recv_key.iter().any(|&b| b != 0));
        assert!(keys.send_nonce_prefix.iter().any(|&b| b != 0));
        assert!(keys.recv_nonce_prefix.iter().any(|&b| b != 0));
    }
}
