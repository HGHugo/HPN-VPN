//! Hybrid KEM (Key Encapsulation Mechanism) implementation.
//!
//! Combines X25519 (classical) with ML-KEM-768 (post-quantum) for
//! hybrid key exchange. The shared secrets are concatenated into a HandshakeSecret
//! which is then mixed via HKDF-SHA-512 during session key derivation (see kdf.rs).

use pqcrypto_mlkem::{mlkem768, mlkem1024};
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as X25519Pk, StaticSecret};
use zeroize::Zeroizing;

use crate::crypto::keys::{
    HandshakeSecret, MlKemPublicKey, MlKemSecretKey, SecurityLevel, SharedSecret, X25519PublicKey,
    X25519SecretKey,
};

/// ML-KEM-768 public key size in bytes (Level 3).
const ML_KEM_768_PUBLIC_KEY_SIZE: usize = 1184;

/// ML-KEM-1024 public key size in bytes (Level 5).
const ML_KEM_1024_PUBLIC_KEY_SIZE: usize = 1568;

/// X25519 public key size in bytes.
const X25519_PUBLIC_KEY_SIZE: usize = 32;
use crate::error::CryptoError;

/// Hybrid public key combining X25519 and ML-KEM (768 or 1024).
#[derive(Clone, Debug)]
pub struct HybridPublicKey {
    /// X25519 public key.
    pub x25519: X25519PublicKey,
    /// ML-KEM public key (768 or 1024 based on security level).
    pub ml_kem: MlKemPublicKey,
    /// Security level (determines ML-KEM variant).
    pub security_level: SecurityLevel,
}

impl HybridPublicKey {
    /// Total size when serialized for Level 3 (ML-KEM-768).
    pub const SIZE: usize = X25519PublicKey::SIZE + MlKemPublicKey::SIZE;

    /// Total size when serialized for Level 5 (ML-KEM-1024).
    pub const SIZE_LEVEL5: usize = X25519PublicKey::SIZE + MlKemPublicKey::SIZE_1024;

    /// Get the size for a given security level.
    #[must_use]
    pub const fn size_for_level(level: SecurityLevel) -> usize {
        match level {
            SecurityLevel::Level3 => Self::SIZE,
            SecurityLevel::Level5 => Self::SIZE_LEVEL5,
        }
    }

    /// Serialize to bytes (includes security level byte at the start).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let size = Self::size_for_level(self.security_level);
        let mut bytes = Vec::with_capacity(1 + size);
        bytes.push(self.security_level.as_u8());
        bytes.extend_from_slice(self.x25519.as_bytes());
        bytes.extend_from_slice(self.ml_kem.as_bytes());
        bytes
    }

    /// Serialize to bytes without security level prefix (for backward compatibility).
    #[must_use]
    pub fn to_bytes_raw(&self) -> Vec<u8> {
        let size = Self::size_for_level(self.security_level);
        let mut bytes = Vec::with_capacity(size);
        bytes.extend_from_slice(self.x25519.as_bytes());
        bytes.extend_from_slice(self.ml_kem.as_bytes());
        bytes
    }

    /// Deserialize from bytes (expects security level byte at start).
    ///
    /// # Errors
    ///
    /// Returns an error if the input is invalid.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.is_empty() {
            return Err(CryptoError::InvalidKeyLength {
                expected: 1,
                actual: 0,
            });
        }

        let security_level =
            SecurityLevel::from_u8(bytes[0]).ok_or(CryptoError::InvalidPublicKey)?;
        let expected_size = 1 + Self::size_for_level(security_level);

        if bytes.len() < expected_size {
            return Err(CryptoError::InvalidKeyLength {
                expected: expected_size,
                actual: bytes.len(),
            });
        }

        let mut x25519_bytes = [0u8; 32];
        x25519_bytes.copy_from_slice(&bytes[1..33]);

        let mlkem_end = 1 + 32 + security_level.mlkem_public_key_size();
        Ok(Self {
            x25519: X25519PublicKey::from_bytes(x25519_bytes),
            ml_kem: MlKemPublicKey::from_bytes_strict(
                bytes[33..mlkem_end].to_vec(),
                security_level,
            )?,
            security_level,
        })
    }

    /// Deserialize from bytes with known security level (no prefix).
    ///
    /// # Errors
    ///
    /// Returns an error if the input is too short.
    pub fn from_bytes_with_level(
        bytes: &[u8],
        security_level: SecurityLevel,
    ) -> Result<Self, CryptoError> {
        let expected_size = Self::size_for_level(security_level);

        if bytes.len() < expected_size {
            return Err(CryptoError::InvalidKeyLength {
                expected: expected_size,
                actual: bytes.len(),
            });
        }

        let mut x25519_bytes = [0u8; 32];
        x25519_bytes.copy_from_slice(&bytes[..32]);

        let mlkem_end = 32 + security_level.mlkem_public_key_size();
        Ok(Self {
            x25519: X25519PublicKey::from_bytes(x25519_bytes),
            ml_kem: MlKemPublicKey::from_bytes_strict(
                bytes[32..mlkem_end].to_vec(),
                security_level,
            )?,
            security_level,
        })
    }
}

/// Hybrid secret key combining X25519 and ML-KEM (768 or 1024).
pub struct HybridSecretKey {
    /// X25519 secret key.
    pub x25519: X25519SecretKey,
    /// ML-KEM secret key (768 or 1024 based on security level).
    pub ml_kem: MlKemSecretKey,
    /// Security level (determines ML-KEM variant).
    pub security_level: SecurityLevel,
}

impl HybridSecretKey {
    /// Serialize to bytes (includes security level byte at start).
    ///
    /// Returns `Zeroizing<Vec<u8>>` to ensure secret key bytes are erased on drop.
    #[must_use]
    pub fn to_bytes(&self) -> zeroize::Zeroizing<Vec<u8>> {
        let mlkem_size = match self.security_level {
            SecurityLevel::Level3 => MlKemSecretKey::SIZE,
            SecurityLevel::Level5 => MlKemSecretKey::SIZE_1024,
        };
        let mut bytes = Vec::with_capacity(1 + 32 + mlkem_size);
        bytes.push(self.security_level.as_u8());
        bytes.extend_from_slice(self.x25519.as_bytes());
        bytes.extend_from_slice(self.ml_kem.as_bytes());
        zeroize::Zeroizing::new(bytes)
    }

    /// Deserialize from bytes (expects security level byte at start).
    ///
    /// # Errors
    ///
    /// Returns an error if the input is invalid.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.is_empty() {
            return Err(CryptoError::InvalidKeyLength {
                expected: 1,
                actual: 0,
            });
        }

        let security_level =
            SecurityLevel::from_u8(bytes[0]).ok_or(CryptoError::InvalidPublicKey)?;
        let mlkem_sk_size = match security_level {
            SecurityLevel::Level3 => MlKemSecretKey::SIZE,
            SecurityLevel::Level5 => MlKemSecretKey::SIZE_1024,
        };
        let expected_size = 1 + 32 + mlkem_sk_size;

        if bytes.len() < expected_size {
            return Err(CryptoError::InvalidKeyLength {
                expected: expected_size,
                actual: bytes.len(),
            });
        }

        let mut x25519_bytes = [0u8; 32];
        x25519_bytes.copy_from_slice(&bytes[1..33]);

        let mlkem_end = 33 + mlkem_sk_size;
        Ok(Self {
            x25519: X25519SecretKey::from_bytes(x25519_bytes),
            ml_kem: MlKemSecretKey::from_bytes(bytes[33..mlkem_end].to_vec()),
            security_level,
        })
    }
}

impl std::fmt::Debug for HybridSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridSecretKey")
            .field("x25519", &"[REDACTED]")
            .field("ml_kem", &"[REDACTED]")
            .finish()
    }
}

/// Hybrid ciphertext containing both X25519 public key and ML-KEM ciphertext.
#[derive(Clone, Debug)]
pub struct HybridCiphertext {
    /// X25519 ephemeral public key (used as "ciphertext" for DH).
    pub x25519_public: X25519PublicKey,
    /// ML-KEM ciphertext (768 or 1024 based on security level).
    pub ml_kem_ct: Vec<u8>,
    /// Security level (determines ML-KEM variant).
    pub security_level: SecurityLevel,
}

impl HybridCiphertext {
    /// ML-KEM-768 ciphertext size (Level 3).
    pub const ML_KEM_CT_SIZE: usize = 1088;

    /// ML-KEM-1024 ciphertext size (Level 5).
    pub const ML_KEM_CT_SIZE_1024: usize = 1568;

    /// Total size when serialized for Level 3.
    pub const SIZE: usize = X25519PublicKey::SIZE + Self::ML_KEM_CT_SIZE;

    /// Total size when serialized for Level 5.
    pub const SIZE_LEVEL5: usize = X25519PublicKey::SIZE + Self::ML_KEM_CT_SIZE_1024;

    /// Get the size for a given security level.
    #[must_use]
    pub const fn size_for_level(level: SecurityLevel) -> usize {
        match level {
            SecurityLevel::Level3 => Self::SIZE,
            SecurityLevel::Level5 => Self::SIZE_LEVEL5,
        }
    }

    /// Serialize to bytes (includes security level byte at start).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let size = Self::size_for_level(self.security_level);
        let mut bytes = Vec::with_capacity(1 + size);
        bytes.push(self.security_level.as_u8());
        bytes.extend_from_slice(self.x25519_public.as_bytes());
        bytes.extend_from_slice(&self.ml_kem_ct);
        bytes
    }

    /// Serialize to bytes without security level prefix (for backward compatibility).
    #[must_use]
    pub fn to_bytes_raw(&self) -> Vec<u8> {
        let size = Self::size_for_level(self.security_level);
        let mut bytes = Vec::with_capacity(size);
        bytes.extend_from_slice(self.x25519_public.as_bytes());
        bytes.extend_from_slice(&self.ml_kem_ct);
        bytes
    }

    /// Deserialize from bytes (expects security level byte at start).
    ///
    /// # Errors
    ///
    /// Returns an error if the input is invalid.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.is_empty() {
            return Err(CryptoError::InvalidKeyLength {
                expected: 1,
                actual: 0,
            });
        }

        let security_level =
            SecurityLevel::from_u8(bytes[0]).ok_or(CryptoError::InvalidPublicKey)?;
        let expected_size = 1 + Self::size_for_level(security_level);

        if bytes.len() < expected_size {
            return Err(CryptoError::InvalidKeyLength {
                expected: expected_size,
                actual: bytes.len(),
            });
        }

        let mut x25519_bytes = [0u8; 32];
        x25519_bytes.copy_from_slice(&bytes[1..33]);

        let ct_end = 1 + 32 + security_level.mlkem_ciphertext_size();
        Ok(Self {
            x25519_public: X25519PublicKey::from_bytes(x25519_bytes),
            ml_kem_ct: bytes[33..ct_end].to_vec(),
            security_level,
        })
    }

    /// Deserialize from bytes with known security level (no prefix).
    ///
    /// # Errors
    ///
    /// Returns an error if the input is too short.
    pub fn from_bytes_with_level(
        bytes: &[u8],
        security_level: SecurityLevel,
    ) -> Result<Self, CryptoError> {
        let expected_size = Self::size_for_level(security_level);

        if bytes.len() < expected_size {
            return Err(CryptoError::InvalidKeyLength {
                expected: expected_size,
                actual: bytes.len(),
            });
        }

        let mut x25519_bytes = [0u8; 32];
        x25519_bytes.copy_from_slice(&bytes[..32]);

        let ct_end = 32 + security_level.mlkem_ciphertext_size();
        Ok(Self {
            x25519_public: X25519PublicKey::from_bytes(x25519_bytes),
            ml_kem_ct: bytes[32..ct_end].to_vec(),
            security_level,
        })
    }
}

/// Hybrid KEM combining X25519 and ML-KEM (768 or 1024).
pub struct HybridKem;

impl HybridKem {
    /// Generate a new hybrid keypair with default security level (Level 3).
    ///
    /// # Errors
    ///
    /// Returns an error if key generation fails.
    pub fn generate_keypair() -> Result<(HybridSecretKey, HybridPublicKey), CryptoError> {
        Self::generate_keypair_with_level(SecurityLevel::Level3)
    }

    /// Generate a new hybrid keypair with specified security level.
    ///
    /// # Errors
    ///
    /// Returns an error if key generation fails.
    pub fn generate_keypair_with_level(
        level: SecurityLevel,
    ) -> Result<(HybridSecretKey, HybridPublicKey), CryptoError> {
        // Generate X25519 keypair using StaticSecret (allows serialization)
        let x25519_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let x25519_public = X25519Pk::from(&x25519_secret);

        // Generate ML-KEM keypair based on security level
        let (ml_kem_pk_bytes, ml_kem_sk_bytes) = match level {
            SecurityLevel::Level3 => {
                let (pk, sk) = mlkem768::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            SecurityLevel::Level5 => {
                let (pk, sk) = mlkem1024::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
        };

        let secret_key = HybridSecretKey {
            x25519: X25519SecretKey::from_bytes(x25519_secret.to_bytes()),
            ml_kem: MlKemSecretKey::from_bytes(ml_kem_sk_bytes),
            security_level: level,
        };

        let public_key = HybridPublicKey {
            x25519: X25519PublicKey::from_bytes(x25519_public.to_bytes()),
            // The bytes were produced by the matching `mlkem*::keypair()`
            // primitive selected by `level` immediately above, so we know
            // exactly which security level applies here. Use the strict
            // decoder (FIX-027) to reject any future regression that swaps
            // levels mid-function without updating the matching arm.
            ml_kem: MlKemPublicKey::from_bytes_strict(ml_kem_pk_bytes, level)?,
            security_level: level,
        };

        Ok((secret_key, public_key))
    }

    /// Encapsulate: generate a shared secret and ciphertext for the given public key.
    ///
    /// This is called by the client during handshake initiation.
    /// The security level is determined by the public key.
    ///
    /// # Errors
    ///
    /// Returns an error if encapsulation fails.
    pub fn encapsulate(
        public_key: &HybridPublicKey,
    ) -> Result<(HandshakeSecret, HybridCiphertext), CryptoError> {
        let level = public_key.security_level;

        // Validate X25519 public key size
        if public_key.x25519.as_bytes().len() != X25519_PUBLIC_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: X25519_PUBLIC_KEY_SIZE,
                actual: public_key.x25519.as_bytes().len(),
            });
        }

        // Validate ML-KEM public key size based on security level
        let expected_mlkem_size = match level {
            SecurityLevel::Level3 => ML_KEM_768_PUBLIC_KEY_SIZE,
            SecurityLevel::Level5 => ML_KEM_1024_PUBLIC_KEY_SIZE,
        };
        if public_key.ml_kem.0.len() != expected_mlkem_size {
            return Err(CryptoError::InvalidPublicKey);
        }

        // X25519: generate ephemeral keypair and compute shared secret
        let x25519_ephemeral = StaticSecret::random_from_rng(rand::thread_rng());
        let x25519_ephemeral_public = X25519Pk::from(&x25519_ephemeral);

        let peer_x25519_bytes: [u8; 32] = public_key
            .x25519
            .as_bytes()
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength {
                expected: 32,
                actual: public_key.x25519.as_bytes().len(),
            })?;
        let peer_x25519_public = X25519Pk::from(peer_x25519_bytes);
        let x25519_shared = x25519_ephemeral.diffie_hellman(&peer_x25519_public);

        // Reject weak shared secrets (all zeros indicates low-order point attack)
        if x25519_shared.as_bytes().ct_eq(&[0u8; 32]).into() {
            return Err(CryptoError::InvalidPublicKey);
        }

        // ML-KEM: encapsulate based on security level.
        // The ML-KEM shared secret is the critical post-quantum half of the
        // hybrid KEM and must be wiped from memory as soon as it has been
        // mixed into `HandshakeSecret`. `Zeroizing<Vec<u8>>` ensures the
        // drop path overwrites the bytes even on early return / panic, which
        // `Vec<u8>` alone does not guarantee.
        let (ml_kem_ss_bytes, ml_kem_ct_bytes): (Zeroizing<Vec<u8>>, Vec<u8>) = match level {
            SecurityLevel::Level3 => {
                let ml_kem_pk = mlkem768::PublicKey::from_bytes(&public_key.ml_kem.0)
                    .map_err(|_| CryptoError::Encapsulation)?;
                let (ss, ct) = mlkem768::encapsulate(&ml_kem_pk);
                (
                    Zeroizing::new(ss.as_bytes().to_vec()),
                    ct.as_bytes().to_vec(),
                )
            }
            SecurityLevel::Level5 => {
                let ml_kem_pk = mlkem1024::PublicKey::from_bytes(&public_key.ml_kem.0)
                    .map_err(|_| CryptoError::Encapsulation)?;
                let (ss, ct) = mlkem1024::encapsulate(&ml_kem_pk);
                (
                    Zeroizing::new(ss.as_bytes().to_vec()),
                    ct.as_bytes().to_vec(),
                )
            }
        };

        // Combine shared secrets
        let x25519_secret = SharedSecret::from_bytes(x25519_shared.to_bytes());
        let mlkem_secret = SharedSecret::from_bytes(
            ml_kem_ss_bytes[..32]
                .try_into()
                .map_err(|_| CryptoError::Encapsulation)?,
        );
        let combined = HandshakeSecret::combine(&x25519_secret, &mlkem_secret);

        let ciphertext = HybridCiphertext {
            x25519_public: X25519PublicKey::from_bytes(x25519_ephemeral_public.to_bytes()),
            ml_kem_ct: ml_kem_ct_bytes,
            security_level: level,
        };

        Ok((combined, ciphertext))
    }

    /// Decapsulate: recover the shared secret from a ciphertext using the secret key.
    ///
    /// This is called by the server to derive the same shared secret.
    /// Security levels of secret key and ciphertext must match.
    ///
    /// # Errors
    ///
    /// Returns an error if decapsulation fails or security levels mismatch.
    pub fn decapsulate(
        secret_key: &HybridSecretKey,
        ciphertext: &HybridCiphertext,
    ) -> Result<HandshakeSecret, CryptoError> {
        // Verify security levels match
        if secret_key.security_level != ciphertext.security_level {
            return Err(CryptoError::Decapsulation);
        }
        let level = secret_key.security_level;

        // X25519: compute shared secret using our secret key and their ephemeral public
        let our_x25519_secret = StaticSecret::from(*secret_key.x25519.as_bytes());
        let their_x25519_bytes: [u8; 32] = ciphertext
            .x25519_public
            .as_bytes()
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength {
                expected: 32,
                actual: ciphertext.x25519_public.as_bytes().len(),
            })?;
        let their_x25519_public = X25519Pk::from(their_x25519_bytes);
        let x25519_shared = our_x25519_secret.diffie_hellman(&their_x25519_public);

        // Reject weak shared secrets (all zeros indicates low-order point attack)
        if x25519_shared.as_bytes().ct_eq(&[0u8; 32]).into() {
            return Err(CryptoError::InvalidPublicKey);
        }

        // ML-KEM: decapsulate based on security level.
        // Wrapped in `Zeroizing` so the raw shared-secret bytes are wiped on
        // drop even if the subsequent `try_into` / `combine` panics or
        // returns early. Without this wrapper the plain `Vec<u8>` would
        // leave the ML-KEM secret in the heap until it gets overwritten by
        // a later allocation.
        let ml_kem_ss_bytes: Zeroizing<Vec<u8>> = match level {
            SecurityLevel::Level3 => {
                let ml_kem_sk = mlkem768::SecretKey::from_bytes(&secret_key.ml_kem.0)
                    .map_err(|_| CryptoError::Decapsulation)?;
                let ml_kem_ct = mlkem768::Ciphertext::from_bytes(&ciphertext.ml_kem_ct)
                    .map_err(|_| CryptoError::Decapsulation)?;
                Zeroizing::new(
                    mlkem768::decapsulate(&ml_kem_ct, &ml_kem_sk)
                        .as_bytes()
                        .to_vec(),
                )
            }
            SecurityLevel::Level5 => {
                let ml_kem_sk = mlkem1024::SecretKey::from_bytes(&secret_key.ml_kem.0)
                    .map_err(|_| CryptoError::Decapsulation)?;
                let ml_kem_ct = mlkem1024::Ciphertext::from_bytes(&ciphertext.ml_kem_ct)
                    .map_err(|_| CryptoError::Decapsulation)?;
                Zeroizing::new(
                    mlkem1024::decapsulate(&ml_kem_ct, &ml_kem_sk)
                        .as_bytes()
                        .to_vec(),
                )
            }
        };

        // Combine shared secrets
        let x25519_secret = SharedSecret::from_bytes(x25519_shared.to_bytes());
        let mlkem_secret = SharedSecret::from_bytes(
            ml_kem_ss_bytes[..32]
                .try_into()
                .map_err(|_| CryptoError::Decapsulation)?,
        );
        let combined = HandshakeSecret::combine(&x25519_secret, &mlkem_secret);

        Ok(combined)
    }

    /// Perform a static key exchange (server side during handshake response).
    ///
    /// The server uses this to compute the shared secret with the client's
    /// ephemeral public keys. Uses the security level from `their_public`.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn static_exchange(
        our_secret: &HybridSecretKey,
        their_public: &HybridPublicKey,
    ) -> Result<(HandshakeSecret, HybridCiphertext), CryptoError> {
        // Use the client's security level
        let level = their_public.security_level;

        // Validate X25519 public key size
        if their_public.x25519.as_bytes().len() != X25519_PUBLIC_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: X25519_PUBLIC_KEY_SIZE,
                actual: their_public.x25519.as_bytes().len(),
            });
        }

        // Validate ML-KEM public key size based on security level
        let expected_mlkem_size = match level {
            SecurityLevel::Level3 => ML_KEM_768_PUBLIC_KEY_SIZE,
            SecurityLevel::Level5 => ML_KEM_1024_PUBLIC_KEY_SIZE,
        };
        if their_public.ml_kem.0.len() != expected_mlkem_size {
            return Err(CryptoError::InvalidPublicKey);
        }

        // X25519: use our static secret with their ephemeral public
        let our_x25519_secret = StaticSecret::from(*our_secret.x25519.as_bytes());
        let their_x25519_bytes: [u8; 32] = their_public
            .x25519
            .as_bytes()
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength {
                expected: 32,
                actual: their_public.x25519.as_bytes().len(),
            })?;
        let their_x25519_public = X25519Pk::from(their_x25519_bytes);
        let x25519_shared = our_x25519_secret.diffie_hellman(&their_x25519_public);

        // Reject weak shared secrets (all zeros indicates low-order point attack)
        if x25519_shared.as_bytes().ct_eq(&[0u8; 32]).into() {
            return Err(CryptoError::InvalidPublicKey);
        }

        // Our X25519 public key for the response
        let our_x25519_public = X25519Pk::from(&our_x25519_secret);

        // ML-KEM: encapsulate based on security level.
        // See the `encapsulate` / `decapsulate` paths above: the ML-KEM shared
        // secret is wrapped in `Zeroizing` so its raw bytes get wiped on
        // drop, even on early return. Keeps the post-quantum half of the
        // hybrid secret out of any freed-but-not-yet-overwritten heap slot.
        let (ml_kem_ss_bytes, ml_kem_ct_bytes): (Zeroizing<Vec<u8>>, Vec<u8>) = match level {
            SecurityLevel::Level3 => {
                let ml_kem_pk = mlkem768::PublicKey::from_bytes(&their_public.ml_kem.0)
                    .map_err(|_| CryptoError::Encapsulation)?;
                let (ss, ct) = mlkem768::encapsulate(&ml_kem_pk);
                (
                    Zeroizing::new(ss.as_bytes().to_vec()),
                    ct.as_bytes().to_vec(),
                )
            }
            SecurityLevel::Level5 => {
                let ml_kem_pk = mlkem1024::PublicKey::from_bytes(&their_public.ml_kem.0)
                    .map_err(|_| CryptoError::Encapsulation)?;
                let (ss, ct) = mlkem1024::encapsulate(&ml_kem_pk);
                (
                    Zeroizing::new(ss.as_bytes().to_vec()),
                    ct.as_bytes().to_vec(),
                )
            }
        };

        // Combine shared secrets
        let x25519_secret = SharedSecret::from_bytes(x25519_shared.to_bytes());
        let mlkem_secret = SharedSecret::from_bytes(
            ml_kem_ss_bytes[..32]
                .try_into()
                .map_err(|_| CryptoError::Encapsulation)?,
        );
        let combined = HandshakeSecret::combine(&x25519_secret, &mlkem_secret);

        let ciphertext = HybridCiphertext {
            x25519_public: X25519PublicKey::from_bytes(our_x25519_public.to_bytes()),
            ml_kem_ct: ml_kem_ct_bytes,
            security_level: level,
        };

        Ok((combined, ciphertext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let (sk, pk) = HybridKem::generate_keypair().unwrap();
        assert_eq!(pk.x25519.as_bytes().len(), 32);
        assert_eq!(pk.ml_kem.as_bytes().len(), MlKemPublicKey::SIZE);
        assert_eq!(sk.x25519.as_bytes().len(), 32);
        assert_eq!(sk.ml_kem.as_bytes().len(), MlKemSecretKey::SIZE);
    }

    #[test]
    fn test_encapsulate_decapsulate_roundtrip() {
        let (sk, pk) = HybridKem::generate_keypair().unwrap();

        let (ss_enc, ct) = HybridKem::encapsulate(&pk).unwrap();
        let ss_dec = HybridKem::decapsulate(&sk, &ct).unwrap();

        assert_eq!(ss_enc.as_bytes(), ss_dec.as_bytes());
    }

    #[test]
    fn test_public_key_serialization() {
        let (_, pk) = HybridKem::generate_keypair().unwrap();

        let bytes = pk.to_bytes();
        // +1 for security level byte
        assert_eq!(bytes.len(), 1 + HybridPublicKey::SIZE);

        let recovered = HybridPublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(pk.x25519.as_bytes(), recovered.x25519.as_bytes());
        assert_eq!(pk.ml_kem.as_bytes(), recovered.ml_kem.as_bytes());
        assert_eq!(pk.security_level, recovered.security_level);
    }

    #[test]
    fn test_ciphertext_serialization() {
        let (_, pk) = HybridKem::generate_keypair().unwrap();
        let (_, ct) = HybridKem::encapsulate(&pk).unwrap();

        let bytes = ct.to_bytes();
        // +1 for security level byte
        assert_eq!(bytes.len(), 1 + HybridCiphertext::SIZE);

        let recovered = HybridCiphertext::from_bytes(&bytes).unwrap();
        assert_eq!(
            ct.x25519_public.as_bytes(),
            recovered.x25519_public.as_bytes()
        );
        assert_eq!(ct.ml_kem_ct, recovered.ml_kem_ct);
        assert_eq!(ct.security_level, recovered.security_level);
    }

    #[test]
    fn test_different_keypairs_different_secrets() {
        let (sk1, pk1) = HybridKem::generate_keypair().unwrap();
        let (_sk2, pk2) = HybridKem::generate_keypair().unwrap();

        let (ss1, ct1) = HybridKem::encapsulate(&pk1).unwrap();
        let (ss2, _ct2) = HybridKem::encapsulate(&pk2).unwrap();

        // Different public keys should produce different shared secrets
        assert_ne!(ss1.as_bytes(), ss2.as_bytes());

        // Decapsulating with correct key should match
        let ss_correct = HybridKem::decapsulate(&sk1, &ct1).unwrap();
        assert_eq!(ss1.as_bytes(), ss_correct.as_bytes());
    }

    #[test]
    fn test_kem_invalid_public_key_length() {
        // PHASE 2 CRYPTO TEST 1: Invalid public key length
        // With security level byte, minimum is 1 + SIZE
        let mut too_short = vec![SecurityLevel::Level3.as_u8()]; // Valid level byte
        too_short.extend_from_slice(&vec![0u8; HybridPublicKey::SIZE - 1]);
        let result = HybridPublicKey::from_bytes(&too_short);
        assert!(result.is_err());

        // Empty input
        let empty = vec![];
        let result = HybridPublicKey::from_bytes(&empty);
        assert!(result.is_err());

        // Invalid security level byte
        let invalid_level = vec![99u8; HybridPublicKey::SIZE + 1];
        let result = HybridPublicKey::from_bytes(&invalid_level);
        assert!(result.is_err());
    }

    #[test]
    fn test_kem_invalid_ciphertext_length() {
        // PHASE 2 CRYPTO TEST 2: Invalid ciphertext length
        // With security level byte, minimum is 1 + SIZE
        let mut too_short = vec![SecurityLevel::Level3.as_u8()];
        too_short.extend_from_slice(&vec![0u8; HybridCiphertext::SIZE - 1]);
        let result = HybridCiphertext::from_bytes(&too_short);
        assert!(result.is_err());

        // Invalid security level byte
        let invalid_level = vec![99u8; HybridCiphertext::SIZE + 1];
        let result = HybridCiphertext::from_bytes(&invalid_level);
        assert!(result.is_err());
    }

    #[test]
    fn test_kem_corrupted_ciphertext() {
        // PHASE 2 CRYPTO TEST 3: Corrupted ciphertext handling
        let (sk, pk) = HybridKem::generate_keypair().unwrap();
        let (ss_original, ct) = HybridKem::encapsulate(&pk).unwrap();

        // Corrupt the ciphertext bytes (using raw format)
        let mut corrupted_bytes = ct.to_bytes_raw();
        // Flip some bits in the ML-KEM ciphertext part (after X25519 public key)
        corrupted_bytes[50] ^= 0xFF; // Corrupt in ML-KEM ciphertext area
        corrupted_bytes[100] ^= 0x55; // Corrupt middle byte

        let corrupted_ct =
            HybridCiphertext::from_bytes_with_level(&corrupted_bytes, SecurityLevel::Level3)
                .unwrap();

        // Decapsulation with corrupted ciphertext should succeed
        // (ML-KEM has implicit rejection, returns pseudorandom output)
        let ss_corrupted = HybridKem::decapsulate(&sk, &corrupted_ct).unwrap();

        // But the shared secret should be different
        assert_ne!(
            ss_original.as_bytes(),
            ss_corrupted.as_bytes(),
            "Corrupted ciphertext should produce different shared secret"
        );
    }

    #[test]
    fn test_kem_static_exchange() {
        // PHASE 2 CRYPTO TEST 4: Static-static key exchange
        let (sk1, pk1) = HybridKem::generate_keypair().unwrap();
        let (sk2, pk2) = HybridKem::generate_keypair().unwrap();

        // Static exchange: only X25519 part is used (ML-KEM doesn't support static-static)
        let (ss_1_to_2, ct1) = HybridKem::static_exchange(&sk1, &pk2).unwrap();
        let (ss_2_to_1, ct2) = HybridKem::static_exchange(&sk2, &pk1).unwrap();

        // Secrets will be different because ML-KEM uses random encapsulation
        // (Only X25519 component is deterministic)
        assert_ne!(
            ss_1_to_2.as_bytes(),
            ss_2_to_1.as_bytes(),
            "Hybrid static exchange uses randomized ML-KEM"
        );

        // Each should produce a valid ciphertext (+1 for security level byte)
        assert_eq!(ct1.to_bytes().len(), 1 + HybridCiphertext::SIZE);
        assert_eq!(ct2.to_bytes().len(), 1 + HybridCiphertext::SIZE);

        // Verify decapsulation works with correct secret key
        let ss_1_dec = HybridKem::decapsulate(&sk2, &ct1).unwrap();
        assert_eq!(ss_1_to_2.as_bytes(), ss_1_dec.as_bytes());

        let ss_2_dec = HybridKem::decapsulate(&sk1, &ct2).unwrap();
        assert_eq!(ss_2_to_1.as_bytes(), ss_2_dec.as_bytes());
    }

    #[test]
    fn test_kem_zero_key_rejected() {
        // PHASE 2 CRYPTO TEST 5: Zero/weak keys detection
        // X25519 has weak keys (all zeros, low-order points)
        let zero_x25519 = [0u8; 32];
        let zero_pk = X25519PublicKey::from_bytes(zero_x25519);

        // Generate a valid ML-KEM key but use zero X25519
        let (_, valid_pk) = HybridKem::generate_keypair().unwrap();
        let hybrid_with_zero = HybridPublicKey {
            x25519: zero_pk,
            ml_kem: valid_pk.ml_kem,
            security_level: SecurityLevel::Level3,
        };

        // Encapsulation should fail with weak X25519 public key
        // (all-zeros key produces all-zeros shared secret, indicating low-order point attack)
        let result = HybridKem::encapsulate(&hybrid_with_zero);
        assert!(
            result.is_err(),
            "Encapsulation should fail with zero/weak X25519 public key"
        );
        match result.unwrap_err() {
            CryptoError::InvalidPublicKey => {} // Expected
            e => panic!("Expected InvalidPublicKey error, got: {:?}", e),
        }
    }

    #[test]
    fn test_kem_serialization_roundtrip_boundary() {
        // PHASE 2 CRYPTO TEST 6: Serialization boundary conditions
        let (_, pk) = HybridKem::generate_keypair().unwrap();

        // Exact size - should work (1 + SIZE for security level byte)
        let bytes = pk.to_bytes();
        assert_eq!(bytes.len(), 1 + HybridPublicKey::SIZE);
        let recovered = HybridPublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(pk.x25519.as_bytes(), recovered.x25519.as_bytes());

        // Extra bytes - should still work (only reads what it needs)
        let mut extended = bytes.clone();
        extended.extend_from_slice(&[0xFF; 100]);
        let recovered_extended = HybridPublicKey::from_bytes(&extended).unwrap();
        assert_eq!(pk.x25519.as_bytes(), recovered_extended.x25519.as_bytes());

        // One byte short - should fail
        let too_short = &bytes[0..bytes.len() - 1];
        assert!(HybridPublicKey::from_bytes(too_short).is_err());
    }

    #[test]
    fn test_hybrid_public_key_size() {
        assert_eq!(HybridPublicKey::SIZE, 32 + 1184); // X25519 + ML-KEM-768
    }

    #[test]
    fn test_hybrid_ciphertext_size() {
        assert_eq!(HybridCiphertext::SIZE, 32 + 1088); // X25519 + ML-KEM-768
    }

    #[test]
    fn test_public_key_clone() {
        let (_, pk) = HybridKem::generate_keypair().unwrap();

        let pk2 = pk.clone();

        assert_eq!(pk.x25519.as_bytes(), pk2.x25519.as_bytes());
        assert_eq!(pk.ml_kem.as_bytes(), pk2.ml_kem.as_bytes());
    }
    #[test]
    fn test_ciphertext_clone() {
        let (_, pk) = HybridKem::generate_keypair().unwrap();
        let (_, ct1) = HybridKem::encapsulate(&pk).unwrap();
        let ct2 = ct1.clone();

        assert_eq!(ct1.to_bytes(), ct2.to_bytes());
    }

    #[test]
    fn test_public_key_from_bytes_empty() {
        let empty: &[u8] = &[];
        assert!(HybridPublicKey::from_bytes(empty).is_err());
    }

    #[test]
    fn test_ciphertext_from_bytes_empty() {
        let empty: &[u8] = &[];
        assert!(HybridCiphertext::from_bytes(empty).is_err());
    }

    #[test]
    fn test_encapsulate_produces_correct_size_ciphertext() {
        let (_, pk) = HybridKem::generate_keypair().unwrap();
        let (_, ct) = HybridKem::encapsulate(&pk).unwrap();

        // +1 for security level byte
        assert_eq!(ct.to_bytes().len(), 1 + HybridCiphertext::SIZE);
    }

    #[test]
    fn test_shared_secret_is_64_bytes() {
        let (sk, pk) = HybridKem::generate_keypair().unwrap();
        let (ss1, ct) = HybridKem::encapsulate(&pk).unwrap();
        let ss2 = HybridKem::decapsulate(&sk, &ct).unwrap();

        assert_eq!(ss1.as_bytes().len(), 64);
        assert_eq!(ss2.as_bytes().len(), 64);
    }

    #[test]
    fn test_multiple_keypairs_are_unique() {
        let (_, pk1) = HybridKem::generate_keypair().unwrap();
        let (_, pk2) = HybridKem::generate_keypair().unwrap();
        let (_, pk3) = HybridKem::generate_keypair().unwrap();

        // All public keys should be different
        assert_ne!(pk1.to_bytes(), pk2.to_bytes());
        assert_ne!(pk2.to_bytes(), pk3.to_bytes());
        assert_ne!(pk1.to_bytes(), pk3.to_bytes());
    }

    #[test]
    fn test_hybrid_public_key_to_bytes_roundtrip() {
        let (_, pk) = HybridKem::generate_keypair().unwrap();
        let bytes = pk.to_bytes();
        let pk2 = HybridPublicKey::from_bytes(&bytes).unwrap();

        assert_eq!(pk.to_bytes(), pk2.to_bytes());
    }

    // ========== ML-KEM-1024 (Level 5) Tests ==========

    #[test]
    fn test_keypair_generation_level5() {
        let (sk, pk) = HybridKem::generate_keypair_with_level(SecurityLevel::Level5).unwrap();
        assert_eq!(pk.x25519.as_bytes().len(), 32);
        assert_eq!(pk.ml_kem.as_bytes().len(), MlKemPublicKey::SIZE_1024);
        assert_eq!(sk.x25519.as_bytes().len(), 32);
        assert_eq!(sk.ml_kem.as_bytes().len(), MlKemSecretKey::SIZE_1024);
        assert_eq!(pk.security_level, SecurityLevel::Level5);
        assert_eq!(sk.security_level, SecurityLevel::Level5);
    }

    #[test]
    fn test_encapsulate_decapsulate_roundtrip_level5() {
        let (sk, pk) = HybridKem::generate_keypair_with_level(SecurityLevel::Level5).unwrap();

        let (ss_enc, ct) = HybridKem::encapsulate(&pk).unwrap();
        assert_eq!(ct.security_level, SecurityLevel::Level5);

        let ss_dec = HybridKem::decapsulate(&sk, &ct).unwrap();

        assert_eq!(ss_enc.as_bytes(), ss_dec.as_bytes());
    }

    #[test]
    fn test_public_key_serialization_level5() {
        let (_, pk) = HybridKem::generate_keypair_with_level(SecurityLevel::Level5).unwrap();

        let bytes = pk.to_bytes();
        // +1 for security level byte
        assert_eq!(bytes.len(), 1 + HybridPublicKey::SIZE_LEVEL5);
        assert_eq!(bytes[0], SecurityLevel::Level5.as_u8());

        let recovered = HybridPublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(pk.x25519.as_bytes(), recovered.x25519.as_bytes());
        assert_eq!(pk.ml_kem.as_bytes(), recovered.ml_kem.as_bytes());
        assert_eq!(recovered.security_level, SecurityLevel::Level5);
    }

    #[test]
    fn test_ciphertext_serialization_level5() {
        let (_, pk) = HybridKem::generate_keypair_with_level(SecurityLevel::Level5).unwrap();
        let (_, ct) = HybridKem::encapsulate(&pk).unwrap();

        let bytes = ct.to_bytes();
        // +1 for security level byte
        assert_eq!(bytes.len(), 1 + HybridCiphertext::SIZE_LEVEL5);
        assert_eq!(bytes[0], SecurityLevel::Level5.as_u8());

        let recovered = HybridCiphertext::from_bytes(&bytes).unwrap();
        assert_eq!(
            ct.x25519_public.as_bytes(),
            recovered.x25519_public.as_bytes()
        );
        assert_eq!(ct.ml_kem_ct, recovered.ml_kem_ct);
        assert_eq!(recovered.security_level, SecurityLevel::Level5);
    }

    #[test]
    fn test_static_exchange_level5() {
        let (sk1, pk1) = HybridKem::generate_keypair_with_level(SecurityLevel::Level5).unwrap();
        let (sk2, pk2) = HybridKem::generate_keypair_with_level(SecurityLevel::Level5).unwrap();

        let (ss_1_to_2, ct1) = HybridKem::static_exchange(&sk1, &pk2).unwrap();
        let (ss_2_to_1, ct2) = HybridKem::static_exchange(&sk2, &pk1).unwrap();

        // Ciphertext should have correct security level
        assert_eq!(ct1.security_level, SecurityLevel::Level5);
        assert_eq!(ct2.security_level, SecurityLevel::Level5);

        // Verify decapsulation works
        let ss_1_dec = HybridKem::decapsulate(&sk2, &ct1).unwrap();
        assert_eq!(ss_1_to_2.as_bytes(), ss_1_dec.as_bytes());

        let ss_2_dec = HybridKem::decapsulate(&sk1, &ct2).unwrap();
        assert_eq!(ss_2_to_1.as_bytes(), ss_2_dec.as_bytes());
    }

    #[test]
    fn test_level5_sizes() {
        assert_eq!(HybridPublicKey::SIZE_LEVEL5, 32 + 1568); // X25519 + ML-KEM-1024
        assert_eq!(HybridCiphertext::SIZE_LEVEL5, 32 + 1568); // X25519 + ML-KEM-1024 CT
        assert_eq!(MlKemPublicKey::SIZE_1024, 1568);
        assert_eq!(MlKemSecretKey::SIZE_1024, 3168);
    }

    #[test]
    fn test_security_level_encoding() {
        assert_eq!(SecurityLevel::Level3.as_u8(), 3);
        assert_eq!(SecurityLevel::Level5.as_u8(), 5);
        assert_eq!(SecurityLevel::from_u8(3), Some(SecurityLevel::Level3));
        assert_eq!(SecurityLevel::from_u8(5), Some(SecurityLevel::Level5));
        assert_eq!(SecurityLevel::from_u8(0), None);
        assert_eq!(SecurityLevel::from_u8(4), None);
    }

    #[test]
    fn test_from_bytes_with_level() {
        // Test Level 3
        let (_, pk3) = HybridKem::generate_keypair_with_level(SecurityLevel::Level3).unwrap();
        let raw_bytes = pk3.to_bytes_raw();
        let recovered =
            HybridPublicKey::from_bytes_with_level(&raw_bytes, SecurityLevel::Level3).unwrap();
        assert_eq!(pk3.x25519.as_bytes(), recovered.x25519.as_bytes());
        assert_eq!(pk3.ml_kem.as_bytes(), recovered.ml_kem.as_bytes());

        // Test Level 5
        let (_, pk5) = HybridKem::generate_keypair_with_level(SecurityLevel::Level5).unwrap();
        let raw_bytes = pk5.to_bytes_raw();
        let recovered =
            HybridPublicKey::from_bytes_with_level(&raw_bytes, SecurityLevel::Level5).unwrap();
        assert_eq!(pk5.x25519.as_bytes(), recovered.x25519.as_bytes());
        assert_eq!(pk5.ml_kem.as_bytes(), recovered.ml_kem.as_bytes());
    }

    #[test]
    fn test_ciphertext_from_bytes_with_level() {
        // Test Level 3
        let (_, pk3) = HybridKem::generate_keypair_with_level(SecurityLevel::Level3).unwrap();
        let (_, ct3) = HybridKem::encapsulate(&pk3).unwrap();
        let raw_bytes = ct3.to_bytes_raw();
        let recovered =
            HybridCiphertext::from_bytes_with_level(&raw_bytes, SecurityLevel::Level3).unwrap();
        assert_eq!(
            ct3.x25519_public.as_bytes(),
            recovered.x25519_public.as_bytes()
        );
        assert_eq!(ct3.ml_kem_ct, recovered.ml_kem_ct);

        // Test Level 5
        let (_, pk5) = HybridKem::generate_keypair_with_level(SecurityLevel::Level5).unwrap();
        let (_, ct5) = HybridKem::encapsulate(&pk5).unwrap();
        let raw_bytes = ct5.to_bytes_raw();
        let recovered =
            HybridCiphertext::from_bytes_with_level(&raw_bytes, SecurityLevel::Level5).unwrap();
        assert_eq!(
            ct5.x25519_public.as_bytes(),
            recovered.x25519_public.as_bytes()
        );
        assert_eq!(ct5.ml_kem_ct, recovered.ml_kem_ct);
    }

    #[test]
    fn test_level3_and_level5_produce_different_sizes() {
        let (_, pk3) = HybridKem::generate_keypair_with_level(SecurityLevel::Level3).unwrap();
        let (_, pk5) = HybridKem::generate_keypair_with_level(SecurityLevel::Level5).unwrap();

        // Level 5 keys should be larger
        assert!(pk5.ml_kem.as_bytes().len() > pk3.ml_kem.as_bytes().len());
        assert!(pk5.to_bytes().len() > pk3.to_bytes().len());

        let (_, ct3) = HybridKem::encapsulate(&pk3).unwrap();
        let (_, ct5) = HybridKem::encapsulate(&pk5).unwrap();

        // Level 5 ciphertexts should be larger
        assert!(ct5.ml_kem_ct.len() > ct3.ml_kem_ct.len());
        assert!(ct5.to_bytes().len() > ct3.to_bytes().len());
    }
}
