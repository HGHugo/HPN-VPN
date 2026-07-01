//! ML-DSA digital signatures for server authentication.
//!
//! Supports both ML-DSA-65 (Level 3) and ML-DSA-87 (Level 5).
//! The server signs the handshake transcript to prove its identity
//! to the client.

use pqcrypto_mldsa::{mldsa65, mldsa87};
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as _, SecretKey as _};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::keys::SecurityLevel;
use crate::error::CryptoError;

/// ML-DSA public key (variable size based on security level).
/// - Level 3 (ML-DSA-65): 1952 bytes
/// - Level 5 (ML-DSA-87): 2592 bytes
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlDsaPublicKey(pub Vec<u8>);

impl MlDsaPublicKey {
    /// Expected size in bytes for ML-DSA-65 (Level 3, default).
    pub const SIZE: usize = 1952;

    /// Expected size in bytes for ML-DSA-87 (Level 5).
    pub const SIZE_87: usize = 2592;

    /// Get the public key size for a given security level.
    #[must_use]
    pub const fn size_for_level(level: SecurityLevel) -> usize {
        match level {
            SecurityLevel::Level3 => Self::SIZE,
            SecurityLevel::Level5 => Self::SIZE_87,
        }
    }

    /// Create from bytes (owned) **without size validation**.
    ///
    /// This constructor is reserved for callers that own the bytes
    /// and can guarantee the length matches either `SIZE` (Level 3) or
    /// `SIZE_87` (Level 5) — typically the output of `pqcrypto`'s
    /// `keypair()` or key material read from a memory-resident buffer of
    /// known provenance.
    ///
    /// **For anything that crosses a trust boundary** (disk, network,
    /// admin input, a downloaded update, …) use [`Self::from_bytes`] instead —
    /// it validates the length up-front, preventing later `pqcrypto`
    /// FFI paths from returning opaque errors or operating on
    /// under-sized input.
    #[doc(hidden)]
    #[must_use]
    pub fn from_bytes_owned(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Create from bytes (slice).
    ///
    /// Accepts both ML-DSA-65 (1952 bytes) and ML-DSA-87 (2592 bytes) public keys.
    ///
    /// # Errors
    ///
    /// Returns an error if the slice length doesn't match either expected size.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::CryptoError> {
        if bytes.len() != Self::SIZE && bytes.len() != Self::SIZE_87 {
            return Err(crate::error::CryptoError::InvalidKeyLength {
                expected: Self::SIZE, // Primary size in error message
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Get the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for MlDsaPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// ML-DSA secret key (variable size based on security level).
/// - Level 3 (ML-DSA-65): 4032 bytes
/// - Level 5 (ML-DSA-87): 4896 bytes
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlDsaSecretKey(pub Vec<u8>);

impl MlDsaSecretKey {
    /// Expected size in bytes for ML-DSA-65 (Level 3, default).
    pub const SIZE: usize = 4032;

    /// Expected size in bytes for ML-DSA-87 (Level 5).
    pub const SIZE_87: usize = 4896;

    /// Create from bytes (owned) **without size validation**.
    ///
    /// See [`MlDsaPublicKey::from_bytes_owned`] for the same caveats: use
    /// [`Self::from_bytes`] whenever the input crosses a trust boundary.
    #[doc(hidden)]
    #[must_use]
    pub fn from_bytes_owned(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Create from bytes (slice).
    ///
    /// Accepts both ML-DSA-65 (4032 bytes) and ML-DSA-87 (4896 bytes) secret keys.
    ///
    /// # Errors
    ///
    /// Returns an error if the slice length doesn't match either expected size.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::CryptoError> {
        if bytes.len() != Self::SIZE && bytes.len() != Self::SIZE_87 {
            return Err(crate::error::CryptoError::InvalidKeyLength {
                expected: Self::SIZE, // Primary size in error message
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Get the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

// Security: Redact secret key in debug output to prevent accidental logging
impl std::fmt::Debug for MlDsaSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlDsaSecretKey")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// ML-DSA signature (variable size based on security level).
/// - Level 3 (ML-DSA-65): 3309 bytes
/// - Level 5 (ML-DSA-87): 4627 bytes
#[derive(Clone, Debug)]
pub struct MlDsaSignature {
    /// Raw signature bytes.
    pub bytes: Vec<u8>,
    /// Security level used for this signature.
    pub security_level: SecurityLevel,
}

impl PartialEq for MlDsaSignature {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;

        // `security_level` and `bytes.len()` are part of the public ML-DSA
        // parameter set (a Level-3 signature is always 3309 bytes, a Level-5
        // one is always 4627 bytes — both fully determined by the level).
        // Short-circuiting on those two fields leaks no secret material; the
        // constant-time `ct_eq` is the only comparison that ever touches the
        // signature bytes themselves.
        self.security_level == other.security_level
            && self.bytes.len() == other.bytes.len()
            && bool::from(self.bytes.as_slice().ct_eq(other.bytes.as_slice()))
    }
}

impl Eq for MlDsaSignature {}

impl MlDsaSignature {
    /// Expected size in bytes for ML-DSA-65 signature (Level 3, default).
    pub const SIZE: usize = 3309;

    /// Expected size in bytes for ML-DSA-87 signature (Level 5).
    pub const SIZE_87: usize = 4627;

    /// Get the signature size for a given security level.
    #[must_use]
    pub const fn size_for_level(level: SecurityLevel) -> usize {
        match level {
            SecurityLevel::Level3 => Self::SIZE,
            SecurityLevel::Level5 => Self::SIZE_87,
        }
    }

    /// Create from bytes (owned) with auto-detected security level.
    ///
    /// Detects Level3 for 3309-byte signatures, Level5 for 4627-byte signatures.
    /// Returns `None` for unrecognized sizes.
    #[must_use]
    pub fn from_bytes_owned(bytes: Vec<u8>) -> Option<Self> {
        let security_level = match bytes.len() {
            Self::SIZE => SecurityLevel::Level3,
            Self::SIZE_87 => SecurityLevel::Level5,
            _ => return None,
        };
        Some(Self {
            bytes,
            security_level,
        })
    }

    /// Create from bytes (owned) with explicit security level.
    ///
    /// Returns `None` if `bytes.len()` does not match the expected signature
    /// length for the given security level. This prevents downstream
    /// verification from panicking or silently truncating on malformed input
    /// (e.g., an untrusted config file or forged handshake message).
    #[must_use]
    pub fn from_bytes_with_level(bytes: Vec<u8>, security_level: SecurityLevel) -> Option<Self> {
        if bytes.len() != Self::size_for_level(security_level) {
            return None;
        }
        Some(Self {
            bytes,
            security_level,
        })
    }

    /// Create from bytes (slice) with auto-detected security level.
    ///
    /// Detects Level3 for 3309-byte signatures, Level5 for 4627-byte signatures.
    /// Returns `None` for unrecognized sizes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let security_level = match bytes.len() {
            Self::SIZE => SecurityLevel::Level3,
            Self::SIZE_87 => SecurityLevel::Level5,
            _ => return None,
        };
        Some(Self {
            bytes: bytes.to_vec(),
            security_level,
        })
    }

    /// Get the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl AsRef<[u8]> for MlDsaSignature {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// ML-DSA keypair (supports both ML-DSA-65 and ML-DSA-87).
#[derive(Clone)]
pub struct MlDsaKeypair {
    /// Public key.
    pub public_key: MlDsaPublicKey,
    /// Secret key.
    pub secret_key: MlDsaSecretKey,
    /// Security level.
    pub security_level: SecurityLevel,
}

impl MlDsaKeypair {
    /// Generate a new ML-DSA-65 keypair (default, Level 3).
    #[must_use]
    pub fn generate() -> Self {
        Self::generate_with_level(SecurityLevel::Level3)
    }

    /// Generate a new ML-DSA keypair with specified security level.
    #[must_use]
    pub fn generate_with_level(level: SecurityLevel) -> Self {
        match level {
            SecurityLevel::Level3 => {
                let (pk, sk) = mldsa65::keypair();
                Self {
                    public_key: MlDsaPublicKey::from_bytes_owned(pk.as_bytes().to_vec()),
                    secret_key: MlDsaSecretKey::from_bytes_owned(sk.as_bytes().to_vec()),
                    security_level: level,
                }
            }
            SecurityLevel::Level5 => {
                let (pk, sk) = mldsa87::keypair();
                Self {
                    public_key: MlDsaPublicKey::from_bytes_owned(pk.as_bytes().to_vec()),
                    secret_key: MlDsaSecretKey::from_bytes_owned(sk.as_bytes().to_vec()),
                    security_level: level,
                }
            }
        }
    }

    /// Sign a message.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign(&self, message: &[u8]) -> Result<MlDsaSignature, CryptoError> {
        match self.security_level {
            SecurityLevel::Level3 => {
                let sk = mldsa65::SecretKey::from_bytes(&self.secret_key.0)
                    .map_err(|_| CryptoError::SignatureGeneration)?;
                let sig = mldsa65::detached_sign(message, &sk);
                // The signature is produced by pqcrypto and is guaranteed
                // to be exactly `SIZE` bytes; from_bytes_with_level cannot
                // fail here.
                MlDsaSignature::from_bytes_with_level(
                    sig.as_bytes().to_vec(),
                    SecurityLevel::Level3,
                )
                .ok_or(CryptoError::SignatureGeneration)
            }
            SecurityLevel::Level5 => {
                let sk = mldsa87::SecretKey::from_bytes(&self.secret_key.0)
                    .map_err(|_| CryptoError::SignatureGeneration)?;
                let sig = mldsa87::detached_sign(message, &sk);
                MlDsaSignature::from_bytes_with_level(
                    sig.as_bytes().to_vec(),
                    SecurityLevel::Level5,
                )
                .ok_or(CryptoError::SignatureGeneration)
            }
        }
    }

    /// Verify a signature using the public key.
    ///
    /// # Errors
    ///
    /// Returns an error if verification fails.
    pub fn verify(&self, message: &[u8], signature: &MlDsaSignature) -> Result<(), CryptoError> {
        verify(&self.public_key, message, signature, self.security_level)
    }
}

impl std::fmt::Debug for MlDsaKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlDsaKeypair")
            .field("public_key", &self.public_key)
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

/// Sign a message with an ML-DSA secret key (auto-detects level from key size).
///
/// # Errors
///
/// Returns an error if signing fails.
pub fn sign(
    secret_key: &MlDsaSecretKey,
    message: &[u8],
    security_level: SecurityLevel,
) -> Result<MlDsaSignature, CryptoError> {
    match security_level {
        SecurityLevel::Level3 => {
            let sk = mldsa65::SecretKey::from_bytes(&secret_key.0)
                .map_err(|_| CryptoError::SignatureGeneration)?;
            let sig = mldsa65::detached_sign(message, &sk);
            MlDsaSignature::from_bytes_with_level(sig.as_bytes().to_vec(), SecurityLevel::Level3)
                .ok_or(CryptoError::SignatureGeneration)
        }
        SecurityLevel::Level5 => {
            let sk = mldsa87::SecretKey::from_bytes(&secret_key.0)
                .map_err(|_| CryptoError::SignatureGeneration)?;
            let sig = mldsa87::detached_sign(message, &sk);
            MlDsaSignature::from_bytes_with_level(sig.as_bytes().to_vec(), SecurityLevel::Level5)
                .ok_or(CryptoError::SignatureGeneration)
        }
    }
}

/// Verify a signature with an ML-DSA public key.
///
/// # Errors
///
/// Returns an error if verification fails.
pub fn verify(
    public_key: &MlDsaPublicKey,
    message: &[u8],
    signature: &MlDsaSignature,
    security_level: SecurityLevel,
) -> Result<(), CryptoError> {
    match security_level {
        SecurityLevel::Level3 => {
            let pk = mldsa65::PublicKey::from_bytes(&public_key.0)
                .map_err(|_| CryptoError::SignatureVerification)?;
            let detached_sig = mldsa65::DetachedSignature::from_bytes(&signature.bytes)
                .map_err(|_| CryptoError::SignatureVerification)?;
            mldsa65::verify_detached_signature(&detached_sig, message, &pk)
                .map_err(|_| CryptoError::SignatureVerification)
        }
        SecurityLevel::Level5 => {
            let pk = mldsa87::PublicKey::from_bytes(&public_key.0)
                .map_err(|_| CryptoError::SignatureVerification)?;
            let detached_sig = mldsa87::DetachedSignature::from_bytes(&signature.bytes)
                .map_err(|_| CryptoError::SignatureVerification)?;
            mldsa87::verify_detached_signature(&detached_sig, message, &pk)
                .map_err(|_| CryptoError::SignatureVerification)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = MlDsaKeypair::generate();
        assert_eq!(keypair.public_key.as_bytes().len(), MlDsaPublicKey::SIZE);
        assert_eq!(keypair.secret_key.as_bytes().len(), MlDsaSecretKey::SIZE);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let keypair = MlDsaKeypair::generate();
        let message = b"Hello, HPN VPN!";

        let signature = keypair.sign(message).unwrap();
        assert_eq!(signature.as_bytes().len(), MlDsaSignature::SIZE);

        // Verification should succeed
        assert!(keypair.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_wrong_message_fails() {
        let keypair = MlDsaKeypair::generate();
        let message = b"Hello, HPN VPN!";
        let wrong_message = b"Wrong message!";

        let signature = keypair.sign(message).unwrap();

        // Verification with wrong message should fail
        assert!(keypair.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let keypair1 = MlDsaKeypair::generate();
        let keypair2 = MlDsaKeypair::generate();
        let message = b"Hello, HPN VPN!";

        let signature = keypair1.sign(message).unwrap();

        // Verification with wrong public key should fail
        assert!(keypair2.verify(message, &signature).is_err());
    }

    #[test]
    fn test_standalone_sign_verify() {
        let keypair = MlDsaKeypair::generate();
        let message = b"Standalone test message";

        let signature = sign(&keypair.secret_key, message, SecurityLevel::Level3).unwrap();
        assert!(
            verify(
                &keypair.public_key,
                message,
                &signature,
                SecurityLevel::Level3
            )
            .is_ok()
        );
    }

    #[test]
    fn test_modified_signature_fails() {
        let keypair = MlDsaKeypair::generate();
        let message = b"Test message";

        let mut signature = keypair.sign(message).unwrap();

        // Modify the signature
        if !signature.bytes.is_empty() {
            signature.bytes[0] ^= 0xFF;
        }

        // Verification should fail
        assert!(keypair.verify(message, &signature).is_err());
    }

    #[test]
    fn test_signature_empty_message() {
        // PHASE 2 CRYPTO TEST 7: Empty message signing
        let keypair = MlDsaKeypair::generate();
        let empty_message = b"";

        let signature = keypair.sign(empty_message).unwrap();
        assert_eq!(signature.as_bytes().len(), MlDsaSignature::SIZE);

        // Verification should succeed even for empty message
        assert!(keypair.verify(empty_message, &signature).is_ok());
    }

    #[test]
    fn test_signature_large_message() {
        // PHASE 2 CRYPTO TEST 8: Large message signing (10MB)
        let keypair = MlDsaKeypair::generate();
        let large_message = vec![0x42u8; 10 * 1024 * 1024]; // 10 MB

        let signature = keypair.sign(&large_message).unwrap();
        assert!(keypair.verify(&large_message, &signature).is_ok());

        // Modify one byte in large message - should fail
        let mut modified = large_message;
        modified[5 * 1024 * 1024] ^= 0xFF;
        assert!(keypair.verify(&modified, &signature).is_err());
    }

    #[test]
    fn test_signature_uniqueness() {
        // PHASE 2 CRYPTO TEST 9: Signature uniqueness (ML-DSA is randomized)
        let keypair = MlDsaKeypair::generate();
        let message = b"Test uniqueness";

        // ML-DSA uses randomization - same message produces different signatures
        let sig1 = keypair.sign(message).unwrap();
        let sig2 = keypair.sign(message).unwrap();

        // Signatures should be different (randomized)
        assert_ne!(
            sig1.as_bytes(),
            sig2.as_bytes(),
            "ML-DSA signatures should use randomization"
        );

        // But both should verify correctly
        assert!(keypair.verify(message, &sig1).is_ok());
        assert!(keypair.verify(message, &sig2).is_ok());
    }

    #[test]
    fn test_signature_multiple_verification() {
        // PHASE 2 CRYPTO TEST 10: Multiple verifications
        let keypair = MlDsaKeypair::generate();
        let message = b"Verify multiple times";

        let signature = keypair.sign(message).unwrap();

        // Verify same signature multiple times - should always succeed
        for _ in 0..100 {
            assert!(keypair.verify(message, &signature).is_ok());
        }

        // Verify with different keypair - should always fail
        let other_keypair = MlDsaKeypair::generate();
        for _ in 0..100 {
            assert!(other_keypair.verify(message, &signature).is_err());
        }
    }

    #[test]
    fn test_public_key_size() {
        assert_eq!(MlDsaPublicKey::SIZE, 1952);
    }

    #[test]
    fn test_secret_key_size() {
        assert_eq!(MlDsaSecretKey::SIZE, 4032);
    }

    #[test]
    fn test_signature_size() {
        assert_eq!(MlDsaSignature::SIZE, 3309);
    }

    #[test]
    fn test_public_key_from_bytes() {
        let keypair = MlDsaKeypair::generate();
        let bytes = keypair.public_key.as_bytes().to_vec();

        let pk = MlDsaPublicKey::from_bytes_owned(bytes);
        assert_eq!(pk.as_bytes().len(), MlDsaPublicKey::SIZE);
    }

    #[test]
    fn test_secret_key_from_bytes() {
        let keypair = MlDsaKeypair::generate();
        let bytes = keypair.secret_key.as_bytes().to_vec();

        let sk = MlDsaSecretKey::from_bytes_owned(bytes);
        assert_eq!(sk.as_bytes().len(), MlDsaSecretKey::SIZE);
    }

    #[test]
    fn test_signature_from_bytes() {
        let keypair = MlDsaKeypair::generate();
        let signature = keypair.sign(b"test").unwrap();
        let bytes = signature.as_bytes().to_vec();

        let sig = MlDsaSignature::from_bytes_owned(bytes).expect("valid signature size");
        assert_eq!(sig.as_bytes().len(), MlDsaSignature::SIZE);
    }

    #[test]
    fn test_public_key_clone() {
        let keypair = MlDsaKeypair::generate();
        let pk1 = keypair.public_key;
        let pk2 = pk1.clone();

        assert_eq!(pk1.as_bytes(), pk2.as_bytes());
    }

    #[test]
    fn test_signature_clone() {
        let keypair = MlDsaKeypair::generate();
        let sig1 = keypair.sign(b"test").unwrap();
        let sig2 = sig1.clone();

        assert_eq!(sig1.as_bytes(), sig2.as_bytes());
    }

    #[test]
    fn test_secret_key_debug_redacted() {
        let keypair = MlDsaKeypair::generate();
        let debug_str = format!("{:?}", keypair.secret_key);

        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains("0x"));
    }

    #[test]
    fn test_keypair_clone() {
        let kp1 = MlDsaKeypair::generate();
        let kp2 = kp1.clone();

        assert_eq!(kp1.public_key.as_bytes(), kp2.public_key.as_bytes());
        assert_eq!(kp1.secret_key.as_bytes(), kp2.secret_key.as_bytes());
    }

    #[test]
    fn test_sign_verify_different_messages() {
        let keypair = MlDsaKeypair::generate();

        let msg1000 = vec![0xAAu8; 1000];
        let msg500 = vec![0x00u8; 500];

        let messages = vec![
            b"short".as_slice(),
            b"a medium length message for testing".as_slice(),
            msg1000.as_slice(),
            msg500.as_slice(),
        ];

        for msg in messages {
            let signature = keypair.sign(msg).unwrap();
            assert!(keypair.verify(msg, &signature).is_ok());
        }
    }

    #[test]
    fn test_signature_with_all_zero_message() {
        let keypair = MlDsaKeypair::generate();
        let zero_message = vec![0u8; 1024];

        let signature = keypair.sign(&zero_message).unwrap();
        assert!(keypair.verify(&zero_message, &signature).is_ok());
    }

    #[test]
    fn test_signature_with_all_ones_message() {
        let keypair = MlDsaKeypair::generate();
        let ones_message = vec![0xFFu8; 1024];

        let signature = keypair.sign(&ones_message).unwrap();
        assert!(keypair.verify(&ones_message, &signature).is_ok());
    }

    #[test]
    fn test_standalone_verify_with_wrong_key() {
        let keypair1 = MlDsaKeypair::generate();
        let keypair2 = MlDsaKeypair::generate();
        let message = b"test message";

        let signature = sign(&keypair1.secret_key, message, SecurityLevel::Level3).unwrap();

        // Should fail with wrong public key
        assert!(
            verify(
                &keypair2.public_key,
                message,
                &signature,
                SecurityLevel::Level3
            )
            .is_err()
        );
    }

    #[test]
    fn test_multiple_keypairs_independent() {
        let kp1 = MlDsaKeypair::generate();
        let kp2 = MlDsaKeypair::generate();
        let kp3 = MlDsaKeypair::generate();

        // All public keys should be different
        assert_ne!(kp1.public_key.as_bytes(), kp2.public_key.as_bytes());
        assert_ne!(kp2.public_key.as_bytes(), kp3.public_key.as_bytes());
        assert_ne!(kp1.public_key.as_bytes(), kp3.public_key.as_bytes());
    }

    // ========== ML-DSA-87 (Level 5) Tests ==========

    #[test]
    fn test_keypair_generation_level5() {
        let keypair = MlDsaKeypair::generate_with_level(SecurityLevel::Level5);
        assert_eq!(keypair.public_key.as_bytes().len(), MlDsaPublicKey::SIZE_87);
        assert_eq!(keypair.secret_key.as_bytes().len(), MlDsaSecretKey::SIZE_87);
        assert_eq!(keypair.security_level, SecurityLevel::Level5);
    }

    #[test]
    fn test_sign_verify_roundtrip_level5() {
        let keypair = MlDsaKeypair::generate_with_level(SecurityLevel::Level5);
        let message = b"Hello, HPN VPN with Level 5!";

        let signature = keypair.sign(message).unwrap();
        assert_eq!(signature.as_bytes().len(), MlDsaSignature::SIZE_87);
        assert_eq!(signature.security_level, SecurityLevel::Level5);

        // Verification should succeed
        assert!(keypair.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_wrong_message_fails_level5() {
        let keypair = MlDsaKeypair::generate_with_level(SecurityLevel::Level5);
        let message = b"Hello, HPN VPN!";
        let wrong_message = b"Wrong message!";

        let signature = keypair.sign(message).unwrap();

        // Verification with wrong message should fail
        assert!(keypair.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_wrong_key_fails_level5() {
        let keypair1 = MlDsaKeypair::generate_with_level(SecurityLevel::Level5);
        let keypair2 = MlDsaKeypair::generate_with_level(SecurityLevel::Level5);
        let message = b"Hello, HPN VPN!";

        let signature = keypair1.sign(message).unwrap();

        // Verification with wrong public key should fail
        assert!(keypair2.verify(message, &signature).is_err());
    }

    #[test]
    fn test_standalone_sign_verify_level5() {
        let keypair = MlDsaKeypair::generate_with_level(SecurityLevel::Level5);
        let message = b"Standalone test message Level 5";

        let signature = sign(&keypair.secret_key, message, SecurityLevel::Level5).unwrap();
        assert!(
            verify(
                &keypair.public_key,
                message,
                &signature,
                SecurityLevel::Level5
            )
            .is_ok()
        );
    }

    #[test]
    fn test_level5_sizes() {
        assert_eq!(MlDsaPublicKey::SIZE_87, 2592);
        assert_eq!(MlDsaSecretKey::SIZE_87, 4896);
        assert_eq!(MlDsaSignature::SIZE_87, 4627);
    }

    #[test]
    fn test_level3_and_level5_produce_different_sizes() {
        let kp3 = MlDsaKeypair::generate_with_level(SecurityLevel::Level3);
        let kp5 = MlDsaKeypair::generate_with_level(SecurityLevel::Level5);

        // Level 5 keys should be larger
        assert!(kp5.public_key.as_bytes().len() > kp3.public_key.as_bytes().len());
        assert!(kp5.secret_key.as_bytes().len() > kp3.secret_key.as_bytes().len());

        let sig3 = kp3.sign(b"test").unwrap();
        let sig5 = kp5.sign(b"test").unwrap();

        // Level 5 signatures should be larger
        assert!(sig5.as_bytes().len() > sig3.as_bytes().len());
    }

    #[test]
    fn test_signature_uniqueness_level5() {
        let keypair = MlDsaKeypair::generate_with_level(SecurityLevel::Level5);
        let message = b"Test uniqueness Level 5";

        // ML-DSA uses randomization - same message produces different signatures
        let sig1 = keypair.sign(message).unwrap();
        let sig2 = keypair.sign(message).unwrap();

        // Signatures should be different (randomized)
        assert_ne!(
            sig1.as_bytes(),
            sig2.as_bytes(),
            "ML-DSA-87 signatures should use randomization"
        );

        // But both should verify correctly
        assert!(keypair.verify(message, &sig1).is_ok());
        assert!(keypair.verify(message, &sig2).is_ok());
    }

    #[test]
    fn test_security_level_in_signature() {
        let kp3 = MlDsaKeypair::generate_with_level(SecurityLevel::Level3);
        let kp5 = MlDsaKeypair::generate_with_level(SecurityLevel::Level5);

        let sig3 = kp3.sign(b"test").unwrap();
        let sig5 = kp5.sign(b"test").unwrap();

        assert_eq!(sig3.security_level, SecurityLevel::Level3);
        assert_eq!(sig5.security_level, SecurityLevel::Level5);
    }

    #[test]
    fn test_signature_equality_matches_bytes_and_level() {
        let keypair = MlDsaKeypair::generate_with_level(SecurityLevel::Level3);
        let signature = keypair.sign(b"equality test").unwrap();
        let mut same = signature.clone();

        assert_eq!(signature, same);

        same.bytes[0] ^= 0x01;
        assert_ne!(signature, same);
    }

    #[test]
    fn test_signature_equality_rejects_different_lengths() {
        let signature = MlDsaSignature {
            bytes: vec![0xAA; MlDsaSignature::SIZE],
            security_level: SecurityLevel::Level3,
        };
        let shorter = MlDsaSignature {
            bytes: vec![0xAA; MlDsaSignature::SIZE - 1],
            security_level: SecurityLevel::Level3,
        };

        assert_ne!(signature, shorter);
    }

    #[test]
    fn test_signature_equality_rejects_different_levels() {
        let bytes = vec![0xAA; MlDsaSignature::SIZE];
        let level3 = MlDsaSignature {
            bytes: bytes.clone(),
            security_level: SecurityLevel::Level3,
        };
        let level5 = MlDsaSignature {
            bytes,
            security_level: SecurityLevel::Level5,
        };

        assert_ne!(level3, level5);
    }

    #[test]
    fn test_size_for_level() {
        assert_eq!(
            MlDsaSignature::size_for_level(SecurityLevel::Level3),
            MlDsaSignature::SIZE
        );
        assert_eq!(
            MlDsaSignature::size_for_level(SecurityLevel::Level5),
            MlDsaSignature::SIZE_87
        );
    }
}
