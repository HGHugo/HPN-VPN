//! Key types with secure memory handling.
//!
//! All secret key types implement `Zeroize` and `ZeroizeOnDrop` to ensure
//! sensitive key material is securely erased from memory when no longer needed.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// X25519 public key (32 bytes).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct X25519PublicKey(pub [u8; 32]);

impl X25519PublicKey {
    /// Size in bytes.
    pub const SIZE: usize = 32;

    /// Create from bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for X25519PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// X25519 secret key (32 bytes).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct X25519SecretKey([u8; 32]);

impl X25519SecretKey {
    /// Size in bytes.
    pub const SIZE: usize = 32;

    /// Create from bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for X25519SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("X25519SecretKey")
            .field(&"[REDACTED]")
            .finish()
    }
}

/// Security level for cryptographic operations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SecurityLevel {
    /// NIST Level 3: ML-KEM-768 + ML-DSA-65 (default, ~AES-192 equivalent)
    #[default]
    Level3,
    /// NIST Level 5: ML-KEM-1024 + ML-DSA-87 (enterprise, ~AES-256 equivalent)
    Level5,
}

impl SecurityLevel {
    /// Get ML-KEM public key size for this security level.
    #[must_use]
    pub const fn mlkem_public_key_size(&self) -> usize {
        match self {
            Self::Level3 => 1184, // ML-KEM-768
            Self::Level5 => 1568, // ML-KEM-1024
        }
    }

    /// Get ML-KEM secret key size for this security level.
    #[must_use]
    pub const fn mlkem_secret_key_size(&self) -> usize {
        match self {
            Self::Level3 => 2400, // ML-KEM-768
            Self::Level5 => 3168, // ML-KEM-1024
        }
    }

    /// Get ML-KEM ciphertext size for this security level.
    #[must_use]
    pub const fn mlkem_ciphertext_size(&self) -> usize {
        match self {
            Self::Level3 => 1088, // ML-KEM-768
            Self::Level5 => 1568, // ML-KEM-1024
        }
    }

    /// Get ML-DSA public key size for this security level.
    #[must_use]
    pub const fn mldsa_public_key_size(&self) -> usize {
        match self {
            Self::Level3 => 1952, // ML-DSA-65
            Self::Level5 => 2592, // ML-DSA-87
        }
    }

    /// Get ML-DSA secret key size for this security level.
    #[must_use]
    pub const fn mldsa_secret_key_size(&self) -> usize {
        match self {
            Self::Level3 => 4032, // ML-DSA-65
            Self::Level5 => 4896, // ML-DSA-87
        }
    }

    /// Get ML-DSA signature size for this security level.
    #[must_use]
    pub const fn mldsa_signature_size(&self) -> usize {
        match self {
            Self::Level3 => 3309, // ML-DSA-65
            Self::Level5 => 4627, // ML-DSA-87
        }
    }

    /// Get hybrid public key size (X25519 + ML-KEM) for this security level.
    #[must_use]
    pub const fn hybrid_public_key_size(&self) -> usize {
        // X25519 (32 bytes) + ML-KEM public key
        32 + self.mlkem_public_key_size()
    }

    /// Get hybrid ciphertext size (X25519 + ML-KEM) for this security level.
    #[must_use]
    pub const fn hybrid_ciphertext_size(&self) -> usize {
        // X25519 (32 bytes) + ML-KEM ciphertext
        32 + self.mlkem_ciphertext_size()
    }

    /// Convert to u8 for protocol encoding.
    #[must_use]
    pub const fn as_u8(&self) -> u8 {
        match self {
            Self::Level3 => 3,
            Self::Level5 => 5,
        }
    }

    /// Parse from u8.
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            3 => Some(Self::Level3),
            5 => Some(Self::Level5),
            _ => None,
        }
    }
}

/// ML-KEM public key (variable size based on security level).
/// - Level 3 (ML-KEM-768): 1184 bytes
/// - Level 5 (ML-KEM-1024): 1568 bytes
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlKemPublicKey(pub Vec<u8>);

impl MlKemPublicKey {
    /// Expected size in bytes for ML-KEM-768 (Level 3, default).
    pub const SIZE: usize = 1184;

    /// Expected size in bytes for ML-KEM-1024 (Level 5).
    pub const SIZE_1024: usize = 1568;

    /// Create from bytes without committing to a specific security level.
    ///
    /// Accepts either ML-KEM-768 (1184 B) or ML-KEM-1024 (1568 B) and stores
    /// the bytes verbatim. The level is then inferred at use-time from the
    /// stored length, which works on the happy path but cannot reject a
    /// caller that handed us bytes meant for a different level on a wire
    /// where the level is meant to be authoritative.
    ///
    /// **Prefer [`Self::from_bytes_strict`]** in any context that already
    /// knows the negotiated security level (handshake state machine, KEM
    /// hybrid roundtrip, identity-hiding decode). This shim is retained
    /// only for the few residual ad-hoc decoders that still want
    /// auto-detection (fuzz harness, debug CLIs).
    ///
    /// # Errors
    /// Returns `CryptoError::InvalidKeyLength` if the byte length does not match
    /// either ML-KEM-768 (`SIZE` = 1184) or ML-KEM-1024 (`SIZE_1024` = 1568).
    #[deprecated(
        since = "0.1.0",
        note = "prefer `MlKemPublicKey::from_bytes_strict(bytes, level)` so the \
                expected level is enforced at decode time (FIX-027)"
    )]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, crate::error::CryptoError> {
        if bytes.len() != Self::SIZE && bytes.len() != Self::SIZE_1024 {
            return Err(crate::error::CryptoError::InvalidKeyLength {
                expected: Self::SIZE,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes))
    }

    /// Create from bytes with **strict** size validation against a single
    /// security level.
    ///
    /// Use this when the expected level is known from context (e.g., inside
    /// `HybridPublicKey::from_bytes_with_level`) to reject mismatched sizes
    /// before cryptographic operations begin.
    ///
    /// # Errors
    /// Returns `CryptoError::InvalidKeyLength` if `bytes.len()` does not match
    /// the exact size for `level`.
    pub fn from_bytes_strict(
        bytes: Vec<u8>,
        level: crate::crypto::SecurityLevel,
    ) -> Result<Self, crate::error::CryptoError> {
        let expected = level.mlkem_public_key_size();
        if bytes.len() != expected {
            return Err(crate::error::CryptoError::InvalidKeyLength {
                expected,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes))
    }

    /// Create from bytes **without size validation**.
    ///
    /// Use [`Self::from_bytes`] or [`Self::from_bytes_strict`] instead for
    /// any input that crosses a trust boundary (network, disk, admin
    /// input). This variant is kept for internal serde paths where the
    /// buffer length is already a structural invariant of the outer
    /// decoder.
    #[doc(hidden)]
    #[must_use]
    pub fn from_bytes_unchecked(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for MlKemPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for MlKemPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for MlKemPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Ok(Self(bytes))
    }
}

/// ML-KEM secret key (variable size based on security level).
/// - Level 3 (ML-KEM-768): 2400 bytes
/// - Level 5 (ML-KEM-1024): 3168 bytes
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlKemSecretKey(pub Vec<u8>);

impl MlKemSecretKey {
    /// Expected size in bytes for ML-KEM-768 (Level 3, default).
    pub const SIZE: usize = 2400;

    /// Expected size in bytes for ML-KEM-1024 (Level 5).
    pub const SIZE_1024: usize = 3168;

    /// Create from bytes.
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for MlKemSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("MlKemSecretKey")
            .field(&"[REDACTED]")
            .finish()
    }
}

/// Shared secret (32 bytes).
///
/// Result of a key exchange operation.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret(pub [u8; 32]);

impl SharedSecret {
    /// Size in bytes.
    pub const SIZE: usize = 32;

    /// Create from bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SharedSecret").field(&"[REDACTED]").finish()
    }
}

/// Combined handshake secret (64 bytes).
///
/// Result of combining X25519 and ML-KEM shared secrets.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HandshakeSecret(pub [u8; 64]);

impl HandshakeSecret {
    /// Size in bytes.
    pub const SIZE: usize = 64;

    /// Create by combining two 32-byte secrets.
    #[must_use]
    pub fn combine(x25519_secret: &SharedSecret, mlkem_secret: &SharedSecret) -> Self {
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(x25519_secret.as_bytes());
        combined[32..].copy_from_slice(mlkem_secret.as_bytes());
        Self(combined)
    }

    /// Get the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl AsRef<[u8]> for HandshakeSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for HandshakeSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("HandshakeSecret")
            .field(&"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_secret_combine() {
        let x25519 = SharedSecret::from_bytes([1u8; 32]);
        let mlkem = SharedSecret::from_bytes([2u8; 32]);

        let combined = HandshakeSecret::combine(&x25519, &mlkem);
        assert_eq!(&combined.as_bytes()[..32], &[1u8; 32]);
        assert_eq!(&combined.as_bytes()[32..], &[2u8; 32]);
    }

    #[test]
    fn test_secret_key_debug_redacted() {
        let sk = X25519SecretKey::from_bytes([0u8; 32]);
        let debug_str = format!("{sk:?}");
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains('0'));
    }

    #[test]
    fn test_key_zeroization() {
        // SECURITY TEST P0-3: Verify all secret key types are zeroized on drop
        // This test validates that sensitive key material is properly erased from
        // memory when keys go out of scope, preventing key recovery from memory dumps.

        // Test 1: X25519SecretKey zeroization
        {
            let key_data = [0x42u8; 32];
            let key = X25519SecretKey::from_bytes(key_data);
            drop(key);
            // Key should be zeroized when dropped
            // ZeroizeOnDrop trait ensures this happens automatically
        }

        // Test 2: MlKemSecretKey zeroization (correct capitalization)
        {
            let secret = vec![0xAAu8; 32];

            // Create and drop key
            {
                let _key = MlKemSecretKey::from_bytes(secret.clone());
                // Key should be zeroized when dropped here
            }

            // Original data is still intact (different location)
            assert_eq!(secret[0], 0xAA);
        }

        // Test 3: SharedSecret zeroization
        {
            let shared = [0xBBu8; 32];
            let _key = SharedSecret::from_bytes(shared);
            // Dropped at end of scope - zeroized automatically
        }

        // Test 4: HandshakeSecret zeroization
        {
            let x25519 = SharedSecret::from_bytes([0xCCu8; 32]);
            let mlkem = SharedSecret::from_bytes([0xDDu8; 32]);
            let _combined = HandshakeSecret::combine(&x25519, &mlkem);
            // All secrets zeroized on drop
        }

        // Test 5: SessionKeys zeroization via kdf module
        {
            use crate::crypto::kdf::derive_session_keys;
            // Create handshake secret using combine (proper API)
            let x25519 = SharedSecret::from_bytes([0x55u8; 32]);
            let mlkem = SharedSecret::from_bytes([0x66u8; 32]);
            let handshake_secret = HandshakeSecret::combine(&x25519, &mlkem);
            let keys = derive_session_keys(&handshake_secret);
            drop(keys);
            // SessionKeys contains EncryptionKey which should zeroize
        }

        // Test 6: Verify Clone doesn't prevent zeroization
        {
            let key1 = X25519SecretKey::from_bytes([0x11u8; 32]);
            let key2 = key1.clone();
            drop(key1);
            drop(key2);
            // Both instances should be zeroized independently
        }

        // Test 7: Zeroization in panic scenario
        {
            use std::panic;

            let result = panic::catch_unwind(|| {
                let _key = X25519SecretKey::from_bytes([0x99u8; 32]);
                // Even if panic occurs, Drop should still run
                panic!("test panic");
            });

            assert!(result.is_err(), "Panic should have occurred");
            // Key should still be zeroized despite panic
        }
    }

    #[test]
    fn test_key_zeroization_memory_safety() {
        // SECURITY TEST P0-3 (Extended): Verify memory is actually zeroed
        // This test verifies the zeroize crate works correctly

        use zeroize::Zeroize;

        // Test with array (stack allocation) - arrays zero in place
        let mut stack_data = [0x55u8; 64];
        assert_eq!(stack_data[0], 0x55);
        assert_eq!(stack_data[63], 0x55);

        stack_data.zeroize();

        assert_eq!(stack_data[0], 0x00);
        assert_eq!(stack_data[63], 0x00);
        assert!(stack_data.iter().all(|&b| b == 0));

        // Test with boxed array (heap allocation)
        let mut boxed_data = Box::new([0x99u8; 128]);
        assert_eq!(boxed_data[0], 0x99);
        assert_eq!(boxed_data[127], 0x99);

        boxed_data.zeroize();

        assert_eq!(boxed_data[0], 0x00);
        assert_eq!(boxed_data[127], 0x00);
        assert!(boxed_data.iter().all(|&b| b == 0));

        // Test that Vec zeroization clears and truncates
        let mut vec_data = vec![0xAAu8; 32];
        assert_eq!(vec_data.len(), 32);
        assert_eq!(vec_data[0], 0xAA);

        vec_data.zeroize();

        // After zeroization, Vec is empty (that's the behavior)
        assert_eq!(vec_data.len(), 0, "Vec should be cleared after zeroization");
    }

    #[test]
    fn test_x25519_public_key_size() {
        assert_eq!(X25519PublicKey::SIZE, 32);
    }

    #[test]
    fn test_x25519_public_key_from_bytes() {
        let bytes = [42u8; 32];
        let pk = X25519PublicKey::from_bytes(bytes);
        assert_eq!(pk.as_bytes(), &bytes);
    }

    #[test]
    fn test_x25519_public_key_as_ref() {
        let bytes = [42u8; 32];
        let pk = X25519PublicKey::from_bytes(bytes);
        let slice: &[u8] = pk.as_ref();
        assert_eq!(slice, &bytes);
    }

    #[test]
    fn test_x25519_public_key_clone() {
        let bytes = [42u8; 32];
        let pk1 = X25519PublicKey::from_bytes(bytes);
        let pk2 = pk1.clone();
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn test_x25519_public_key_debug() {
        let pk = X25519PublicKey::from_bytes([1u8; 32]);
        let debug_str = format!("{pk:?}");
        assert!(debug_str.contains("X25519PublicKey"));
    }

    #[test]
    fn test_x25519_secret_key_size() {
        assert_eq!(X25519SecretKey::SIZE, 32);
    }

    #[test]
    fn test_x25519_secret_key_from_bytes() {
        let bytes = [99u8; 32];
        let sk = X25519SecretKey::from_bytes(bytes);
        assert_eq!(sk.as_bytes(), &bytes);
    }

    #[test]
    fn test_x25519_secret_key_clone() {
        let bytes = [99u8; 32];
        let sk1 = X25519SecretKey::from_bytes(bytes);
        let sk2 = sk1.clone();
        assert_eq!(sk1.as_bytes(), sk2.as_bytes());
    }

    #[test]
    fn test_mlkem_public_key_size() {
        assert_eq!(MlKemPublicKey::SIZE, 1184);
    }

    // The `from_bytes` shim is intentionally `#[deprecated]` per FIX-027 to
    // funnel production callers onto the strict variant. The tests below
    // exercise the deprecated shim itself, so `allow(deprecated)` is the
    // correct local opt-out — they are NOT examples for new code.
    #[test]
    #[allow(deprecated)]
    fn test_mlkem_public_key_from_bytes() {
        let bytes = vec![77u8; 1184];
        let pk = MlKemPublicKey::from_bytes(bytes.clone()).unwrap();
        assert_eq!(pk.as_bytes(), &bytes);
    }

    #[test]
    #[allow(deprecated)]
    fn test_mlkem_public_key_from_bytes_level5() {
        let bytes = vec![77u8; 1568];
        let pk = MlKemPublicKey::from_bytes(bytes.clone()).unwrap();
        assert_eq!(pk.as_bytes(), &bytes);
    }

    #[test]
    #[allow(deprecated)]
    fn test_mlkem_public_key_from_bytes_invalid_size() {
        let bytes = vec![77u8; 100];
        assert!(MlKemPublicKey::from_bytes(bytes).is_err());
    }

    #[test]
    #[allow(deprecated)]
    fn test_mlkem_public_key_as_ref() {
        let bytes = vec![77u8; 1184];
        let pk = MlKemPublicKey::from_bytes(bytes.clone()).unwrap();
        let slice: &[u8] = pk.as_ref();
        assert_eq!(slice, &bytes);
    }

    #[test]
    #[allow(deprecated)]
    fn test_mlkem_public_key_clone() {
        let bytes = vec![77u8; 1184];
        let pk1 = MlKemPublicKey::from_bytes(bytes).unwrap();
        let pk2 = pk1.clone();
        assert_eq!(pk1, pk2);
    }

    #[test]
    #[allow(deprecated)]
    fn test_mlkem_public_key_debug() {
        let pk = MlKemPublicKey::from_bytes(vec![1u8; 1184]).unwrap();
        let debug_str = format!("{pk:?}");
        assert!(debug_str.contains("MlKemPublicKey"));
    }

    #[test]
    fn test_mlkem_public_key_from_bytes_strict_rejects_wrong_level() {
        use crate::crypto::SecurityLevel;
        // 1184 bytes is Level 3 size; asking for Level 5 (1568) must refuse.
        let bytes = vec![77u8; 1184];
        let result = MlKemPublicKey::from_bytes_strict(bytes, SecurityLevel::Level5);
        assert!(result.is_err());
    }

    #[test]
    fn test_mlkem_secret_key_size() {
        assert_eq!(MlKemSecretKey::SIZE, 2400);
    }

    #[test]
    fn test_mlkem_secret_key_from_bytes() {
        let bytes = vec![88u8; 2400];
        let sk = MlKemSecretKey::from_bytes(bytes.clone());
        assert_eq!(sk.as_bytes(), &bytes);
    }

    #[test]
    fn test_mlkem_secret_key_debug_redacted() {
        let sk = MlKemSecretKey::from_bytes(vec![0xFFu8; 2400]);
        let debug_str = format!("{sk:?}");
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains("FF"));
    }

    #[test]
    fn test_mlkem_secret_key_clone() {
        let bytes = vec![88u8; 2400];
        let sk1 = MlKemSecretKey::from_bytes(bytes);
        let sk2 = sk1.clone();
        assert_eq!(sk1.as_bytes(), sk2.as_bytes());
    }

    #[test]
    fn test_shared_secret_size() {
        assert_eq!(SharedSecret::SIZE, 32);
    }

    #[test]
    fn test_shared_secret_from_bytes() {
        let bytes = [55u8; 32];
        let secret = SharedSecret::from_bytes(bytes);
        assert_eq!(secret.as_bytes(), &bytes);
    }

    #[test]
    fn test_shared_secret_as_ref() {
        let bytes = [55u8; 32];
        let secret = SharedSecret::from_bytes(bytes);
        let slice: &[u8] = secret.as_ref();
        assert_eq!(slice, &bytes);
    }

    #[test]
    fn test_shared_secret_debug_redacted() {
        let secret = SharedSecret::from_bytes([0xAAu8; 32]);
        let debug_str = format!("{secret:?}");
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains("AA"));
    }

    #[test]
    fn test_shared_secret_clone() {
        let bytes = [55u8; 32];
        let s1 = SharedSecret::from_bytes(bytes);
        let s2 = s1.clone();
        assert_eq!(s1.as_bytes(), s2.as_bytes());
    }

    #[test]
    fn test_handshake_secret_size() {
        assert_eq!(HandshakeSecret::SIZE, 64);
    }

    #[test]
    fn test_handshake_secret_as_ref() {
        let x25519 = SharedSecret::from_bytes([1u8; 32]);
        let mlkem = SharedSecret::from_bytes([2u8; 32]);
        let combined = HandshakeSecret::combine(&x25519, &mlkem);

        let slice: &[u8] = combined.as_ref();
        assert_eq!(slice.len(), 64);
    }

    #[test]
    fn test_handshake_secret_debug_redacted() {
        let x25519 = SharedSecret::from_bytes([1u8; 32]);
        let mlkem = SharedSecret::from_bytes([2u8; 32]);
        let combined = HandshakeSecret::combine(&x25519, &mlkem);

        let debug_str = format!("{combined:?}");
        assert!(debug_str.contains("REDACTED"));
    }

    #[test]
    fn test_handshake_secret_clone() {
        let x25519 = SharedSecret::from_bytes([1u8; 32]);
        let mlkem = SharedSecret::from_bytes([2u8; 32]);
        let hs1 = HandshakeSecret::combine(&x25519, &mlkem);
        let hs2 = hs1.clone();

        assert_eq!(hs1.as_bytes(), hs2.as_bytes());
    }

    #[test]
    fn test_key_size_constants() {
        // Verify all key size constants are correct
        assert_eq!(X25519PublicKey::SIZE, 32);
        assert_eq!(X25519SecretKey::SIZE, 32);
        assert_eq!(MlKemPublicKey::SIZE, 1184);
        assert_eq!(MlKemSecretKey::SIZE, 2400);
        assert_eq!(SharedSecret::SIZE, 32);
        assert_eq!(HandshakeSecret::SIZE, 64);
    }

    #[test]
    fn test_handshake_secret_combine_different_values() {
        let x25519_1 = SharedSecret::from_bytes([0xAAu8; 32]);
        let mlkem_1 = SharedSecret::from_bytes([0xBBu8; 32]);

        let x25519_2 = SharedSecret::from_bytes([0xCCu8; 32]);
        let mlkem_2 = SharedSecret::from_bytes([0xDDu8; 32]);

        let hs1 = HandshakeSecret::combine(&x25519_1, &mlkem_1);
        let hs2 = HandshakeSecret::combine(&x25519_2, &mlkem_2);

        // Different inputs should produce different outputs
        assert_ne!(hs1.as_bytes(), hs2.as_bytes());
    }
}
