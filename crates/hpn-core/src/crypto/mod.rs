//! Cryptographic primitives for the HPN VPN.
//!
//! This module provides:
//! - [`keys`]: Key types with secure memory handling
//! - [`kem`]: Hybrid KEM (X25519 + ML-KEM-768)
//! - [`signature`]: ML-DSA-65 digital signatures
//! - [`kdf`]: HKDF-SHA-512 key derivation
//! - [`aead`]: AES-256-GCM authenticated encryption
//! - [`pki`]: Certificate management and PKI

pub mod aead;
pub mod kdf;
pub mod kem;
pub mod keys;
pub mod pki;
pub mod signature;

pub use aead::{NONCE_SIZE, PrecomputedKey, TAG_SIZE, decrypt, encrypt};
pub use kdf::{SessionKeys, derive_session_keys, derive_session_keys_with_context};
pub use kem::{HybridCiphertext, HybridKem, HybridPublicKey, HybridSecretKey};
pub use keys::{
    HandshakeSecret, MlKemPublicKey, MlKemSecretKey, SecurityLevel, SharedSecret, X25519PublicKey,
    X25519SecretKey,
};
pub use pki::{
    Certificate, CertificateBuilder, CertificateError, CertificateStore, CertificateType,
};
pub use signature::{MlDsaKeypair, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature};
