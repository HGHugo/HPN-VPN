//! HPN protocol message types.
//!
//! Defines the payload structures for each message type.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Maximum number of DNS servers allowed in TunnelConfig.
/// This prevents excessive memory allocation from malicious packets.
pub const MAX_DNS_SERVERS: usize = 8;

/// Maximum length of control message strings.
/// This prevents memory exhaustion from oversized control messages.
pub const MAX_CONTROL_MESSAGE_LEN: usize = 1024;

/// Maximum length of username in credentials.
pub const MAX_USERNAME_LEN: usize = 64;

/// Maximum length of password in credentials.
pub const MAX_PASSWORD_LEN: usize = 256;

use crate::crypto::{
    HybridCiphertext, HybridKem, HybridPublicKey, HybridSecretKey, MlDsaPublicKey, MlDsaSignature,
    SecurityLevel, aead,
};
use crate::types::{ControlType, SessionId};

/// High-level message enum containing all possible message payloads.
#[derive(Clone, Debug)]
pub enum Message {
    /// Handshake initiation from client (unencrypted, for backward compatibility).
    HandshakeInit(HandshakeInit),
    /// Encrypted handshake initiation from client (identity hiding enabled).
    EncryptedHandshakeInit(EncryptedHandshakeInit),
    /// Handshake response from server.
    HandshakeResponse(HandshakeResponse),
    /// Encrypted data packet.
    Data(DataMessage),
    /// Keep-alive ping.
    Keepalive(KeepaliveMessage),
    /// Keep-alive reply.
    KeepaliveReply(KeepaliveReplyMessage),
    /// Control message.
    Control(ControlMessage),
    /// Rekey request from client.
    Rekey(RekeyMessage),
    /// Rekey response from server.
    RekeyResponse(RekeyResponse),
    /// Cookie challenge request (anti-DoS).
    CookieRequest(CookieRequest),
    /// Cookie challenge reply with proof-of-work.
    CookieReply(CookieReply),
}

/// Encrypted handshake initiation message (client -> server).
///
/// Provides identity hiding by encrypting the client's ephemeral public key
/// using the server's static KEM public key. This prevents passive observers
/// from identifying clients by their key patterns.
///
/// Wire format:
/// - `security_level` (1 byte): Requested security level
/// - `encapsulation_ciphertext` (variable): KEM ciphertext for key derivation
/// - `encrypted_init` (variable): AES-GCM encrypted `HandshakeInit` payload
/// - `auth_tag` (16 bytes): AES-GCM authentication tag (included in encrypted_init)
///
/// The client:
/// 1. Encapsulates to server's static KEM public key to get (shared_secret, ciphertext)
/// 2. Derives encryption key from shared_secret using HKDF
/// 3. Encrypts the inner `HandshakeInit` with AES-256-GCM
///
/// The server:
/// 1. Decapsulates using its static KEM secret key
/// 2. Derives the same encryption key
/// 3. Decrypts to recover the inner `HandshakeInit`
#[derive(Clone, Debug)]
pub struct EncryptedHandshakeInit {
    /// Requested security level (sent in clear for server to know which KEM key to use).
    pub security_level: SecurityLevel,
    /// KEM ciphertext for deriving the encryption key.
    pub encapsulation_ciphertext: HybridCiphertext,
    /// AES-GCM encrypted inner `HandshakeInit` (includes auth tag).
    pub encrypted_payload: Vec<u8>,
}

impl EncryptedHandshakeInit {
    /// Domain separator for identity hiding key derivation.
    const DOMAIN_SEPARATOR: &'static [u8] = b"HPN-IDENTITY-HIDING-V1";

    /// Create an encrypted handshake init by encrypting the inner init message.
    ///
    /// # Arguments
    ///
    /// * `inner` - The `HandshakeInit` to encrypt
    /// * `server_kem_pk` - Server's static KEM public key for identity hiding
    ///
    /// # Errors
    ///
    /// Returns an error if encapsulation or encryption fails.
    pub fn encrypt(
        inner: &HandshakeInit,
        server_kem_pk: &HybridPublicKey,
    ) -> Result<Self, crate::error::ProtocolError> {
        // 1. Encapsulate to server's KEM public key
        let (handshake_secret, ciphertext) =
            HybridKem::encapsulate(server_kem_pk).map_err(|e| {
                crate::error::ProtocolError::HandshakeFailed(format!(
                    "identity hiding encapsulation failed: {:?}",
                    e
                ))
            })?;

        // 2. Derive encryption key using HKDF
        let mut encryption_key = [0u8; 32];
        crate::crypto::kdf::hkdf_expand(
            handshake_secret.as_bytes(),
            Self::DOMAIN_SEPARATOR,
            &mut encryption_key,
        )
        .map_err(|e| {
            crate::error::ProtocolError::HandshakeFailed(format!(
                "identity hiding key derivation failed: {:?}",
                e
            ))
        })?;

        // 3. Serialize the inner HandshakeInit
        let inner_bytes = inner.to_bytes();

        // 4. Encrypt with AES-256-GCM.
        //
        // Nonce construction: the nonce is derived deterministically from the
        // KEM ciphertext (SHA-256 of the ciphertext, truncated to 96 bits).
        //
        // SECURITY INVARIANT: this is sound ONLY because the encryption key is
        // derived from the same KEM shared secret and used exactly once. The
        // KEM encapsulation uses fresh randomness (X25519 ephemeral + ML-KEM
        // internal randomness) on every call, so two encryptions with the same
        // key are cryptographically infeasible. If a future refactor caches
        // the encryption key or makes the KEM deterministic (e.g. for tests
        // with a fixed seed), AES-GCM nonce reuse becomes possible and is
        // CATASTROPHIC (forgery + key recovery).
        //
        // See `test_encrypted_handshake_init_unique_ciphertexts` for a regression guard.
        let mut nonce = [0u8; aead::NONCE_SIZE];
        let nonce_material = ring::digest::digest(&ring::digest::SHA256, &ciphertext.to_bytes());
        nonce.copy_from_slice(&nonce_material.as_ref()[..aead::NONCE_SIZE]);

        // Build AAD: bind ciphertext to encrypted payload to prevent mix-and-match
        let ct_bytes = ciphertext.to_bytes();
        let mut aad = Vec::with_capacity(1 + ct_bytes.len());
        aad.push(inner.security_level.as_u8());
        aad.extend_from_slice(&ct_bytes);

        // Allocate buffer and copy plaintext, then encrypt in place
        let mut encrypted_payload = vec![0u8; inner_bytes.len() + aead::TAG_SIZE];
        encrypted_payload[..inner_bytes.len()].copy_from_slice(&inner_bytes);
        let encrypted_len = aead::encrypt_in_place(
            &encryption_key,
            &nonce,
            &aad,
            &mut encrypted_payload,
            inner_bytes.len(),
        )
        .map_err(|e| {
            crate::error::ProtocolError::HandshakeFailed(format!(
                "identity hiding encryption failed: {:?}",
                e
            ))
        })?;
        encrypted_payload.truncate(encrypted_len);

        // Zeroize the encryption key
        use zeroize::Zeroize;
        encryption_key.zeroize();

        Ok(Self {
            security_level: inner.security_level,
            encapsulation_ciphertext: ciphertext,
            encrypted_payload,
        })
    }

    /// Decrypt the encrypted handshake init using the server's KEM secret key.
    ///
    /// # Arguments
    ///
    /// * `server_kem_sk` - Server's static KEM secret key
    ///
    /// # Errors
    ///
    /// Returns an error if decapsulation or decryption fails.
    pub fn decrypt(
        &self,
        server_kem_sk: &HybridSecretKey,
    ) -> Result<HandshakeInit, crate::error::ProtocolError> {
        // 1. Decapsulate to get shared secret
        let handshake_secret =
            HybridKem::decapsulate(server_kem_sk, &self.encapsulation_ciphertext).map_err(|e| {
                crate::error::ProtocolError::HandshakeFailed(format!(
                    "identity hiding decapsulation failed: {:?}",
                    e
                ))
            })?;

        // 2. Derive encryption key using HKDF
        let mut encryption_key = [0u8; 32];
        crate::crypto::kdf::hkdf_expand(
            handshake_secret.as_bytes(),
            Self::DOMAIN_SEPARATOR,
            &mut encryption_key,
        )
        .map_err(|e| {
            crate::error::ProtocolError::HandshakeFailed(format!(
                "identity hiding key derivation failed: {:?}",
                e
            ))
        })?;

        // 3. Derive nonce (same method as encryption)
        let mut nonce = [0u8; aead::NONCE_SIZE];
        let nonce_material = ring::digest::digest(
            &ring::digest::SHA256,
            &self.encapsulation_ciphertext.to_bytes(),
        );
        nonce.copy_from_slice(&nonce_material.as_ref()[..aead::NONCE_SIZE]);

        // 4. Decrypt with AES-256-GCM
        // Build AAD: must match encryption side
        let ct_bytes = self.encapsulation_ciphertext.to_bytes();
        let mut aad = Vec::with_capacity(1 + ct_bytes.len());
        aad.push(self.security_level.as_u8());
        aad.extend_from_slice(&ct_bytes);

        let mut decrypted = self.encrypted_payload.clone();
        let decrypted_len = aead::decrypt_in_place(&encryption_key, &nonce, &aad, &mut decrypted)
            .map_err(|e| {
            crate::error::ProtocolError::HandshakeFailed(format!(
                "identity hiding decryption failed: {:?}",
                e
            ))
        })?;

        // Zeroize the encryption key
        use zeroize::Zeroize;
        encryption_key.zeroize();

        // 5. Parse the inner HandshakeInit
        HandshakeInit::from_bytes(&decrypted[..decrypted_len])
    }

    /// Encode to bytes.
    ///
    /// Wire format: [security_level (1)] [ciphertext_len (2)] [ciphertext] [encrypted_payload]
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let ct_bytes = self.encapsulation_ciphertext.to_bytes();
        let ct_len = ct_bytes.len().min(u16::MAX as usize);
        let mut bytes = Vec::with_capacity(1 + 2 + ct_len + self.encrypted_payload.len());

        bytes.push(self.security_level.as_u8());
        bytes.extend_from_slice(&(ct_len as u16).to_be_bytes());
        bytes.extend_from_slice(&ct_bytes[..ct_len]);
        bytes.extend_from_slice(&self.encrypted_payload);

        bytes
    }

    /// Decode from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer is too short or malformed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::ProtocolError> {
        // Need at least: security_level (1) + ciphertext_len (2) + min_ciphertext + min_payload
        if bytes.len() < 3 {
            return Err(crate::error::ProtocolError::PacketTooShort {
                needed: 3,
                available: bytes.len(),
            });
        }

        let security_level = SecurityLevel::from_u8(bytes[0]).ok_or_else(|| {
            crate::error::ProtocolError::HandshakeFailed(format!(
                "invalid security level: {}",
                bytes[0]
            ))
        })?;

        let ct_len = u16::from_be_bytes([bytes[1], bytes[2]]) as usize;

        // Upper-bound `ct_len` before any slicing. A legitimate
        // `HybridCiphertext` is at most 1 (security level) + 32 (X25519)
        // + 1568 (ML-KEM-1024 ct for Level5) = 1601 bytes. We accept up
        // to 2048 to keep a margin for future KEM variants. Anything
        // larger is a malformed or malicious packet: reject it upfront
        // rather than letting `HybridCiphertext::from_bytes` walk a
        // caller-controlled length before the size mismatch is caught
        // internally.
        const MAX_HYBRID_CIPHERTEXT_LEN: usize = 2048;
        if ct_len > MAX_HYBRID_CIPHERTEXT_LEN {
            return Err(crate::error::ProtocolError::HandshakeFailed(format!(
                "ciphertext_len {} exceeds maximum {}",
                ct_len, MAX_HYBRID_CIPHERTEXT_LEN
            )));
        }

        if bytes.len() < 3 + ct_len {
            return Err(crate::error::ProtocolError::PacketTooShort {
                needed: 3 + ct_len,
                available: bytes.len(),
            });
        }

        let encapsulation_ciphertext = HybridCiphertext::from_bytes(&bytes[3..3 + ct_len])
            .map_err(|_| {
                crate::error::ProtocolError::HandshakeFailed(
                    "invalid encapsulation ciphertext".into(),
                )
            })?;

        let encrypted_payload = bytes[3 + ct_len..].to_vec();

        if encrypted_payload.len() < aead::TAG_SIZE {
            return Err(crate::error::ProtocolError::PacketTooShort {
                needed: aead::TAG_SIZE,
                available: encrypted_payload.len(),
            });
        }

        Ok(Self {
            security_level,
            encapsulation_ciphertext,
            encrypted_payload,
        })
    }
}

/// Encrypted user credentials for authentication.
///
/// Credentials are encrypted using the server's KEM public key to protect
/// them even in the standard (non-identity-hiding) handshake mode.
///
/// Wire format:
/// - `ciphertext_len` (2 bytes): Length of KEM ciphertext
/// - `ciphertext` (variable): KEM ciphertext for key derivation
/// - `encrypted_payload_len` (2 bytes): Length of encrypted payload
/// - `encrypted_payload` (variable): AES-GCM encrypted "username\0password" with 16-byte tag
#[derive(Clone, Debug)]
pub struct EncryptedCredentials {
    /// KEM ciphertext for deriving the decryption key.
    pub ciphertext: HybridCiphertext,
    /// AES-GCM encrypted payload: "username\0password" + 16-byte auth tag.
    pub encrypted_payload: Vec<u8>,
}

/// Decrypted credentials from an authenticated handshake.
pub struct DecryptedCredentials {
    /// Username for account lookup.
    pub username: String,
    /// Password wrapped in zeroizing memory.
    pub password: Zeroizing<String>,
}

impl EncryptedCredentials {
    /// Domain separator for credential encryption key derivation.
    const DOMAIN_SEPARATOR: &'static [u8] = b"HPN-CREDENTIALS-V1";

    /// Encrypt credentials using the server's KEM public key.
    ///
    /// # Arguments
    ///
    /// * `username` - User's username
    /// * `password` - User's password
    /// * `server_kem_pk` - Server's KEM public key
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails.
    pub fn encrypt(
        username: &str,
        password: &str,
        server_kem_pk: &HybridPublicKey,
    ) -> Result<Self, crate::error::ProtocolError> {
        // Validate lengths
        if username.len() > MAX_USERNAME_LEN {
            return Err(crate::error::ProtocolError::InvalidData(format!(
                "username too long: {} (max {})",
                username.len(),
                MAX_USERNAME_LEN
            )));
        }
        if password.len() > MAX_PASSWORD_LEN {
            return Err(crate::error::ProtocolError::InvalidData(format!(
                "password too long: {} (max {})",
                password.len(),
                MAX_PASSWORD_LEN
            )));
        }

        // 1. Encapsulate to server's KEM public key
        let (shared_secret, ciphertext) = HybridKem::encapsulate(server_kem_pk).map_err(|e| {
            crate::error::ProtocolError::HandshakeFailed(format!(
                "credential encapsulation failed: {:?}",
                e
            ))
        })?;

        // 2. Derive encryption key using HKDF
        let mut encryption_key = [0u8; 32];
        crate::crypto::kdf::hkdf_expand(
            shared_secret.as_bytes(),
            Self::DOMAIN_SEPARATOR,
            &mut encryption_key,
        )
        .map_err(|e| {
            crate::error::ProtocolError::HandshakeFailed(format!(
                "credential key derivation failed: {:?}",
                e
            ))
        })?;

        // 3. Build plaintext: "username\0password"
        let mut plaintext = Vec::with_capacity(username.len() + 1 + password.len());
        plaintext.extend_from_slice(username.as_bytes());
        plaintext.push(0); // Null separator
        plaintext.extend_from_slice(password.as_bytes());

        // 4. Encrypt with AES-256-GCM
        //
        // Nonce construction: same scheme as `EncryptedHandshakeInit`,
        // `nonce = SHA-256(KEM_ciphertext)[..12]`.
        //
        // SECURITY INVARIANT: this is sound ONLY because the encryption
        // key derived above is used exactly once (each call generates
        // a fresh KEM ciphertext via `HybridKem::encapsulate`, so the
        // derived key is never reused). If a future refactor caches
        // the encryption key, accepts a KEM ciphertext as a parameter,
        // or makes the KEM deterministic (e.g. tests with a fixed
        // seed), AES-GCM nonce reuse becomes possible — and AES-GCM
        // nonce reuse is CATASTROPHIC (full key recovery via the
        // forbidden-attack on GHASH).
        //
        // See `test_encrypted_credentials_distinct_inner_produce_distinct_kem_ct`
        // for the regression guard that enforces this invariant at CI time.
        let mut nonce = [0u8; aead::NONCE_SIZE];
        let nonce_material = ring::digest::digest(&ring::digest::SHA256, &ciphertext.to_bytes());
        nonce.copy_from_slice(&nonce_material.as_ref()[..aead::NONCE_SIZE]);

        // AAD binds ciphertext to encrypted payload
        let ct_bytes = ciphertext.to_bytes();

        let mut encrypted_payload = vec![0u8; plaintext.len() + aead::TAG_SIZE];
        encrypted_payload[..plaintext.len()].copy_from_slice(&plaintext);

        let encrypt_result = aead::encrypt_in_place(
            &encryption_key,
            &nonce,
            &ct_bytes,
            &mut encrypted_payload,
            plaintext.len(),
        );

        // Zeroize sensitive data as early as possible.
        use zeroize::Zeroize;
        encryption_key.zeroize();
        plaintext.zeroize();

        let encrypted_len = encrypt_result.map_err(|e| {
            crate::error::ProtocolError::HandshakeFailed(format!(
                "credential encryption failed: {:?}",
                e
            ))
        })?;

        encrypted_payload.truncate(encrypted_len);

        Ok(Self {
            ciphertext,
            encrypted_payload,
        })
    }

    /// Decrypt credentials using the server's KEM secret key.
    ///
    /// # Arguments
    ///
    /// * `server_kem_sk` - Server's KEM secret key
    ///
    /// # Returns
    ///
    /// Returns decrypted credentials on success.
    ///
    /// # Errors
    ///
    /// Returns an error if decryption fails.
    pub fn decrypt(
        &self,
        server_kem_sk: &HybridSecretKey,
    ) -> Result<DecryptedCredentials, crate::error::ProtocolError> {
        // 1. Decapsulate to get shared secret
        let shared_secret =
            HybridKem::decapsulate(server_kem_sk, &self.ciphertext).map_err(|e| {
                crate::error::ProtocolError::HandshakeFailed(format!(
                    "credential decapsulation failed: {:?}",
                    e
                ))
            })?;

        // 2. Derive decryption key
        let mut decryption_key = [0u8; 32];
        crate::crypto::kdf::hkdf_expand(
            shared_secret.as_bytes(),
            Self::DOMAIN_SEPARATOR,
            &mut decryption_key,
        )
        .map_err(|e| {
            crate::error::ProtocolError::HandshakeFailed(format!(
                "credential key derivation failed: {:?}",
                e
            ))
        })?;

        // 3. Derive nonce from ciphertext
        let mut nonce = [0u8; aead::NONCE_SIZE];
        let nonce_material =
            ring::digest::digest(&ring::digest::SHA256, &self.ciphertext.to_bytes());
        nonce.copy_from_slice(&nonce_material.as_ref()[..aead::NONCE_SIZE]);

        // 4. Decrypt
        let ct_bytes = self.ciphertext.to_bytes();
        let mut decrypted = self.encrypted_payload.clone();
        let decrypt_result =
            aead::decrypt_in_place(&decryption_key, &nonce, &ct_bytes, &mut decrypted);

        // Zeroize derived key immediately after decryption attempt.
        use zeroize::Zeroize;
        decryption_key.zeroize();

        let plaintext_len = decrypt_result.map_err(|e| {
            crate::error::ProtocolError::HandshakeFailed(format!(
                "credential decryption failed: {:?}",
                e
            ))
        })?;

        // 5. Parse "username\0password"
        let plaintext = &decrypted[..plaintext_len];
        let Some(null_pos) = plaintext.iter().position(|&b| b == 0) else {
            decrypted.zeroize();
            return Err(crate::error::ProtocolError::HandshakeFailed(
                "invalid credential format: missing separator".into(),
            ));
        };

        let username_bytes = plaintext[..null_pos].to_vec();
        let password_bytes = plaintext[null_pos + 1..].to_vec();

        let Ok(username) = String::from_utf8(username_bytes) else {
            decrypted.zeroize();
            return Err(crate::error::ProtocolError::HandshakeFailed(
                "invalid credential format: bad username".into(),
            ));
        };

        let Ok(password_raw) = String::from_utf8(password_bytes) else {
            decrypted.zeroize();
            return Err(crate::error::ProtocolError::HandshakeFailed(
                "invalid credential format: bad password".into(),
            ));
        };
        let password = Zeroizing::new(password_raw);

        // Validate lengths
        if username.len() > MAX_USERNAME_LEN || password.len() > MAX_PASSWORD_LEN {
            decrypted.zeroize();
            return Err(crate::error::ProtocolError::HandshakeFailed(
                "invalid credential format: fields too long".into(),
            ));
        }

        decrypted.zeroize();

        Ok(DecryptedCredentials { username, password })
    }

    /// Encode to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let ct_bytes = self.ciphertext.to_bytes();
        let mut bytes = Vec::with_capacity(2 + ct_bytes.len() + 2 + self.encrypted_payload.len());

        // Ciphertext length (2 bytes) + ciphertext
        bytes.extend_from_slice(&(ct_bytes.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&ct_bytes);

        // Encrypted payload length (2 bytes) + payload
        bytes.extend_from_slice(&(self.encrypted_payload.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.encrypted_payload);

        bytes
    }

    /// Decode from bytes.
    pub fn from_bytes(
        bytes: &[u8],
        _security_level: SecurityLevel,
    ) -> Result<Self, crate::error::ProtocolError> {
        if bytes.len() < 4 {
            return Err(crate::error::ProtocolError::PacketTooShort {
                needed: 4,
                available: bytes.len(),
            });
        }

        let mut offset = 0;

        // Ciphertext length
        let ct_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2;

        // Upper-bound `ct_len`. Same rationale as in
        // `EncryptedHandshakeInit::from_bytes`: a legitimate
        // `HybridCiphertext` is at most ~1601 bytes (Level5). Reject
        // anything beyond 2048 before we ever slice, to keep parser
        // behaviour predictable on adversarial inputs.
        const MAX_CREDENTIALS_CIPHERTEXT_LEN: usize = 2048;
        if ct_len > MAX_CREDENTIALS_CIPHERTEXT_LEN {
            return Err(crate::error::ProtocolError::HandshakeFailed(format!(
                "credentials ciphertext_len {} exceeds maximum {}",
                ct_len, MAX_CREDENTIALS_CIPHERTEXT_LEN
            )));
        }

        if bytes.len() < offset + ct_len + 2 {
            return Err(crate::error::ProtocolError::PacketTooShort {
                needed: offset + ct_len + 2,
                available: bytes.len(),
            });
        }

        // Ciphertext (includes security level byte)
        let ciphertext =
            HybridCiphertext::from_bytes(&bytes[offset..offset + ct_len]).map_err(|e| {
                crate::error::ProtocolError::HandshakeFailed(format!(
                    "invalid credential ciphertext: {:?}",
                    e
                ))
            })?;
        offset += ct_len;

        // Encrypted payload length
        let payload_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2;

        // Upper-bound the encrypted payload. Credentials are a small
        // serialized struct + AEAD tag (<= a few hundred bytes even with
        // generous headroom for future fields). 4096 is a very loose cap
        // that still rules out 16-bit-field nonsense.
        const MAX_CREDENTIALS_PAYLOAD_LEN: usize = 4096;
        if payload_len > MAX_CREDENTIALS_PAYLOAD_LEN {
            return Err(crate::error::ProtocolError::HandshakeFailed(format!(
                "credentials payload_len {} exceeds maximum {}",
                payload_len, MAX_CREDENTIALS_PAYLOAD_LEN
            )));
        }

        if bytes.len() < offset + payload_len {
            return Err(crate::error::ProtocolError::PacketTooShort {
                needed: offset + payload_len,
                available: bytes.len(),
            });
        }

        // Encrypted payload
        let encrypted_payload = bytes[offset..offset + payload_len].to_vec();

        Ok(Self {
            ciphertext,
            encrypted_payload,
        })
    }
}

/// Handshake initiation message (client -> server).
///
/// Contains the client's ephemeral public keys for the hybrid KEM.
/// This is the inner message that gets encrypted by `EncryptedHandshakeInit`
/// when identity hiding is enabled.
#[derive(Clone, Debug)]
pub struct HandshakeInit {
    /// Client's ephemeral hybrid public key.
    pub client_ephemeral_pk: HybridPublicKey,
    /// Random bytes for session uniqueness.
    pub client_random: [u8; 32],
    /// Requested security level for this session.
    pub security_level: SecurityLevel,
    /// Optional encrypted credentials for user authentication.
    /// Credentials are encrypted using the server's KEM public key.
    pub credentials: Option<EncryptedCredentials>,
}

impl HandshakeInit {
    /// Create a new handshake init message with default security level (Level3).
    #[must_use]
    pub fn new(client_ephemeral_pk: HybridPublicKey) -> Self {
        Self::with_security_level(client_ephemeral_pk, SecurityLevel::default())
    }

    /// Create a new handshake init message with specified security level.
    #[must_use]
    pub fn with_security_level(
        client_ephemeral_pk: HybridPublicKey,
        security_level: SecurityLevel,
    ) -> Self {
        let mut client_random = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut client_random);
        Self {
            client_ephemeral_pk,
            client_random,
            security_level,
            credentials: None,
        }
    }

    /// Create a new handshake init message with credentials.
    ///
    /// # Arguments
    ///
    /// * `client_ephemeral_pk` - Client's ephemeral public key
    /// * `security_level` - Requested security level
    /// * `username` - Username for authentication
    /// * `password` - Password for authentication
    /// * `server_kem_pk` - Server's KEM public key for encrypting credentials
    ///
    /// # Errors
    ///
    /// Returns an error if credential encryption fails.
    pub fn with_credentials(
        client_ephemeral_pk: HybridPublicKey,
        security_level: SecurityLevel,
        username: &str,
        password: &str,
        server_kem_pk: &HybridPublicKey,
    ) -> Result<Self, crate::error::ProtocolError> {
        let mut client_random = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut client_random);

        let credentials = EncryptedCredentials::encrypt(username, password, server_kem_pk)?;

        Ok(Self {
            client_ephemeral_pk,
            client_random,
            security_level,
            credentials: Some(credentials),
        })
    }

    /// Add credentials to an existing handshake init.
    ///
    /// # Errors
    ///
    /// Returns an error if credential encryption fails.
    pub fn add_credentials(
        &mut self,
        username: &str,
        password: &str,
        server_kem_pk: &HybridPublicKey,
    ) -> Result<(), crate::error::ProtocolError> {
        self.credentials = Some(EncryptedCredentials::encrypt(
            username,
            password,
            server_kem_pk,
        )?);
        Ok(())
    }

    /// Check if this handshake has credentials.
    #[must_use]
    pub fn has_credentials(&self) -> bool {
        self.credentials.is_some()
    }

    /// Encode to bytes.
    ///
    /// Wire format:
    /// - `security_level` (1 byte)
    /// - `client_ephemeral_pk` (variable)
    /// - `client_random` (32 bytes)
    /// - `has_credentials` (1 byte): 0 or 1
    /// - `credentials` (variable, if present)
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let pk_size = self.security_level.hybrid_public_key_size();
        let credentials_bytes = self.credentials.as_ref().map(|c| c.to_bytes());
        let credentials_len = credentials_bytes.as_ref().map_or(0, |b| b.len());

        let mut bytes = Vec::with_capacity(1 + pk_size + 32 + 1 + credentials_len);

        // Security level byte first (allows receiver to know key sizes)
        bytes.push(self.security_level.as_u8());
        // Use raw encoding without security level prefix for protocol messages
        bytes.extend_from_slice(&self.client_ephemeral_pk.to_bytes_raw());
        bytes.extend_from_slice(&self.client_random);

        // Credentials flag and data
        if let Some(ref creds_bytes) = credentials_bytes {
            bytes.push(1); // Has credentials
            bytes.extend_from_slice(creds_bytes);
        } else {
            bytes.push(0); // No credentials
        }

        bytes
    }

    /// Decode from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer is too short or security level is invalid.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::ProtocolError> {
        // Need at least 1 byte for security level
        if bytes.is_empty() {
            return Err(crate::error::ProtocolError::PacketTooShort {
                needed: 1,
                available: 0,
            });
        }

        // Parse security level
        let security_level = SecurityLevel::from_u8(bytes[0]).ok_or_else(|| {
            crate::error::ProtocolError::HandshakeFailed(format!(
                "invalid security level: {}",
                bytes[0]
            ))
        })?;

        let pk_size = security_level.hybrid_public_key_size();
        // Minimum: security_level + pk + client_random + has_credentials flag
        let min_size = 1 + pk_size + 32 + 1;

        if bytes.len() < min_size {
            // Check for legacy format (without credentials flag)
            let legacy_size = 1 + pk_size + 32;
            if bytes.len() >= legacy_size {
                // Legacy format without credentials - allow for backward compatibility
                let client_ephemeral_pk =
                    HybridPublicKey::from_bytes_with_level(&bytes[1..=pk_size], security_level)
                        .map_err(|_| {
                            crate::error::ProtocolError::HandshakeFailed(
                                "invalid public key".into(),
                            )
                        })?;

                let mut client_random = [0u8; 32];
                client_random.copy_from_slice(&bytes[1 + pk_size..legacy_size]);

                return Ok(Self {
                    client_ephemeral_pk,
                    client_random,
                    security_level,
                    credentials: None,
                });
            }

            return Err(crate::error::ProtocolError::PacketTooShort {
                needed: min_size,
                available: bytes.len(),
            });
        }

        let client_ephemeral_pk =
            HybridPublicKey::from_bytes_with_level(&bytes[1..=pk_size], security_level).map_err(
                |_| crate::error::ProtocolError::HandshakeFailed("invalid public key".into()),
            )?;

        let mut client_random = [0u8; 32];
        client_random.copy_from_slice(&bytes[1 + pk_size..1 + pk_size + 32]);

        // Parse credentials flag
        let has_credentials = bytes[1 + pk_size + 32] != 0;
        let credentials = if has_credentials {
            let creds_offset = 1 + pk_size + 32 + 1;
            if bytes.len() <= creds_offset {
                return Err(crate::error::ProtocolError::PacketTooShort {
                    needed: creds_offset + 1,
                    available: bytes.len(),
                });
            }
            Some(EncryptedCredentials::from_bytes(
                &bytes[creds_offset..],
                security_level,
            )?)
        } else {
            None
        };

        Ok(Self {
            client_ephemeral_pk,
            client_random,
            security_level,
            credentials,
        })
    }
}

/// Handshake response message (server -> client).
///
/// Contains the server's response to complete the key exchange,
/// including the ciphertext and signature.
#[derive(Clone, Debug)]
pub struct HandshakeResponse {
    /// Session ID assigned by server.
    pub session_id: SessionId,
    /// Server's hybrid ciphertext (encapsulated secrets).
    pub server_ciphertext: HybridCiphertext,
    /// Server's static public key for signature verification.
    pub server_static_pk: MlDsaPublicKey,
    /// Server's signature over the handshake transcript.
    pub signature: MlDsaSignature,
    /// Server's random bytes.
    pub server_random: [u8; 32],
    /// Tunnel configuration.
    pub config: TunnelConfig,
    /// Key confirmation MAC (HMAC-SHA256 of transcript using derived send key).
    /// This proves the server has correctly derived the session keys.
    pub key_confirmation: [u8; 32],
    /// Key derivation timestamp (Unix seconds) for session context binding.
    /// Both client and server use this to derive identical keys.
    pub kdf_timestamp: u64,
}

impl HandshakeResponse {
    /// Read the leading `session_id` field from a serialised
    /// `HandshakeResponse` payload without decoding the rest.
    ///
    /// The relay uses this to bind a reassembled handshake response to the
    /// `SessionId` actually allocated by the upstream server, without
    /// having to know the negotiated security level or carry around the
    /// rest of the parsed message.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::PacketTooShort`] when the payload does not
    /// even cover the 8-byte session-id prefix. Callers should treat that
    /// as a protocol violation and drop the (re)assembled buffer.
    pub fn session_id_from_bytes(bytes: &[u8]) -> Result<SessionId, crate::error::ProtocolError> {
        if bytes.len() < SessionId::SIZE {
            return Err(crate::error::ProtocolError::PacketTooShort {
                needed: SessionId::SIZE,
                available: bytes.len(),
            });
        }
        let mut session_id_bytes = [0u8; SessionId::SIZE];
        session_id_bytes.copy_from_slice(&bytes[..SessionId::SIZE]);
        Ok(SessionId::from_bytes(session_id_bytes))
    }

    /// Encode to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let config_bytes = self.config.to_bytes();
        let config_len = config_bytes.len().min(u32::MAX as usize);
        let level = self.signature.security_level;
        let mut bytes = Vec::with_capacity(
            SessionId::SIZE
                + HybridCiphertext::size_for_level(level)
                + MlDsaPublicKey::size_for_level(level)
                + MlDsaSignature::size_for_level(level)
                + 32
                + 4
                + config_len
                + 32 // key_confirmation
                + 8, // kdf_timestamp
        );

        bytes.extend_from_slice(&self.session_id.to_bytes());
        // Use raw encoding without security level prefix for protocol messages
        bytes.extend_from_slice(&self.server_ciphertext.to_bytes_raw());
        bytes.extend_from_slice(self.server_static_pk.as_bytes());
        bytes.extend_from_slice(self.signature.as_bytes());
        bytes.extend_from_slice(&self.server_random);

        // Config with length prefix
        bytes.extend_from_slice(&(config_len as u32).to_be_bytes());
        bytes.extend_from_slice(&config_bytes[..config_len]);

        // Key confirmation MAC
        bytes.extend_from_slice(&self.key_confirmation);

        // KDF timestamp
        bytes.extend_from_slice(&self.kdf_timestamp.to_be_bytes());

        bytes
    }

    /// Decode from bytes assuming Level 3 sizes.
    ///
    /// ⚠️ **Prefer [`Self::from_bytes_with_level`]** on any real code path.
    /// This helper silently defaults to Level 3 and will therefore misparse
    /// a Level 5 buffer as a truncated Level 3 message. Every production
    /// call site in `hpn-core` / `hpn-server` / `hpn-client-core` already
    /// uses the explicit-level variant; this shim exists only so that the
    /// in-crate unit tests and the `fuzz/` targets can exercise the
    /// Level 3 decoder without re-specifying the constant.
    ///
    /// # Errors
    ///
    /// Returns an error if decoding fails.
    #[doc(hidden)]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::ProtocolError> {
        Self::from_bytes_with_level(bytes, SecurityLevel::Level3)
    }

    /// Decode from bytes with explicit security level.
    ///
    /// The security level determines the expected sizes for ciphertext,
    /// public key, and signature fields in the wire format.
    ///
    /// # Errors
    ///
    /// Returns an error if decoding fails.
    pub fn from_bytes_with_level(
        bytes: &[u8],
        level: SecurityLevel,
    ) -> Result<Self, crate::error::ProtocolError> {
        let ct_size = HybridCiphertext::size_for_level(level);
        let pk_size = MlDsaPublicKey::size_for_level(level);
        let sig_size = MlDsaSignature::size_for_level(level);

        let mut offset = 0;

        // Session ID
        if bytes.len() < offset + SessionId::SIZE {
            return Err(crate::error::ProtocolError::PacketTooShort {
                needed: offset + SessionId::SIZE,
                available: bytes.len(),
            });
        }
        let mut session_id_bytes = [0u8; 8];
        session_id_bytes.copy_from_slice(&bytes[offset..offset + 8]);
        let session_id = SessionId::from_bytes(session_id_bytes);
        offset += SessionId::SIZE;

        // Server ciphertext
        if bytes.len() < offset + ct_size {
            return Err(crate::error::ProtocolError::PacketTooShort {
                needed: offset + ct_size,
                available: bytes.len(),
            });
        }
        let server_ciphertext =
            HybridCiphertext::from_bytes_with_level(&bytes[offset..offset + ct_size], level)
                .map_err(|_| {
                    crate::error::ProtocolError::HandshakeFailed("invalid ciphertext".into())
                })?;
        offset += ct_size;

        // Server static public key
        if bytes.len() < offset + pk_size {
            return Err(crate::error::ProtocolError::PacketTooShort {
                needed: offset + pk_size,
                available: bytes.len(),
            });
        }
        let server_static_pk = MlDsaPublicKey::from_bytes(&bytes[offset..offset + pk_size])
            .map_err(|_| {
                crate::error::ProtocolError::HandshakeFailed("invalid server public key".into())
            })?;
        offset += pk_size;

        // Signature
        if bytes.len() < offset + sig_size {
            return Err(crate::error::ProtocolError::PacketTooShort {
                needed: offset + sig_size,
                available: bytes.len(),
            });
        }
        let signature =
            MlDsaSignature::from_bytes_with_level(bytes[offset..offset + sig_size].to_vec(), level)
                .ok_or_else(|| {
                    crate::error::ProtocolError::HandshakeFailed(format!(
                        "signature size mismatch for level {:?}",
                        level
                    ))
                })?;
        offset += sig_size;

        // Server random
        if bytes.len() < offset + 32 {
            return Err(crate::error::ProtocolError::PacketTooShort {
                needed: offset + 32,
                available: bytes.len(),
            });
        }
        let mut server_random = [0u8; 32];
        server_random.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;

        // Config length
        if bytes.len() < offset + 4 {
            return Err(crate::error::ProtocolError::PacketTooShort {
                needed: offset + 4,
                available: bytes.len(),
            });
        }
        let config_len = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        offset += 4;

        // Cap config_len to a sane upper bound (4 KiB is well above the
        // largest realistic TunnelConfig even with many routes/DNS servers).
        // This prevents integer overflow on 32-bit targets when computing
        // `offset + config_len`, and guards against adversarial values that
        // would otherwise pass the length check on 64-bit by trivially
        // satisfying `bytes.len() < u32::MAX`.
        const MAX_CONFIG_LEN: usize = 4096;
        if config_len > MAX_CONFIG_LEN {
            return Err(crate::error::ProtocolError::HandshakeFailed(format!(
                "config_len {} exceeds maximum {}",
                config_len, MAX_CONFIG_LEN
            )));
        }

        // Config data
        if bytes.len() < offset + config_len {
            return Err(crate::error::ProtocolError::PacketTooShort {
                needed: offset + config_len,
                available: bytes.len(),
            });
        }
        let config = TunnelConfig::from_bytes(&bytes[offset..offset + config_len])?;
        offset += config_len;

        // Key confirmation MAC
        if bytes.len() < offset + 32 {
            return Err(crate::error::ProtocolError::PacketTooShort {
                needed: offset + 32,
                available: bytes.len(),
            });
        }
        let mut key_confirmation = [0u8; 32];
        key_confirmation.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;

        // KDF timestamp
        if bytes.len() < offset + 8 {
            return Err(crate::error::ProtocolError::PacketTooShort {
                needed: offset + 8,
                available: bytes.len(),
            });
        }
        let kdf_timestamp = u64::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]);

        Ok(Self {
            session_id,
            server_ciphertext,
            server_static_pk,
            signature,
            server_random,
            config,
            key_confirmation,
            kdf_timestamp,
        })
    }
}

/// Tunnel configuration sent by server.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TunnelConfig {
    /// Client's assigned tunnel IPv4 address.
    pub client_ipv4: [u8; 4],
    /// Tunnel IPv4 netmask.
    pub netmask_ipv4: [u8; 4],
    /// Gateway IPv4 address (server's tunnel address).
    pub gateway_ipv4: [u8; 4],
    /// DNS server IPv4 addresses.
    pub dns_ipv4: Vec<[u8; 4]>,
    /// Client's assigned tunnel IPv6 address (optional).
    #[serde(default)]
    pub client_ipv6: Option<[u8; 16]>,
    /// IPv6 prefix length (typically 64 or 128).
    #[serde(default)]
    pub prefix_len_ipv6: Option<u8>,
    /// Gateway IPv6 address (server's tunnel address).
    #[serde(default)]
    pub gateway_ipv6: Option<[u8; 16]>,
    /// DNS server IPv6 addresses.
    #[serde(default)]
    pub dns_ipv6: Vec<[u8; 16]>,
    /// MTU for the tunnel.
    pub mtu: u16,
}

impl TunnelConfig {
    /// Encode to bytes.
    ///
    /// Format (v2 with IPv6):
    /// - IPv4 section: client_ipv4[4] + netmask_ipv4[4] + gateway_ipv4[4] + dns_count[1] + dns_ipv4[4*n]
    /// - IPv6 section: has_ipv6[1] + (if has_ipv6: client_ipv6[16] + prefix_len[1] + gateway_ipv6[16] + dns6_count[1] + dns_ipv6[16*n])
    /// - MTU: mtu[2]
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let ipv6_size = if self.client_ipv6.is_some() {
            1 + 16 + 1 + 16 + 1 + self.dns_ipv6.len() * 16
        } else {
            1
        };
        let mut bytes = Vec::with_capacity(4 + 4 + 4 + 1 + self.dns_ipv4.len() * 4 + ipv6_size + 2);

        // IPv4 section
        bytes.extend_from_slice(&self.client_ipv4);
        bytes.extend_from_slice(&self.netmask_ipv4);
        bytes.extend_from_slice(&self.gateway_ipv4);

        bytes.push(self.dns_ipv4.len() as u8);
        for dns in &self.dns_ipv4 {
            bytes.extend_from_slice(dns);
        }

        // IPv6 section
        if let Some(client_ipv6) = &self.client_ipv6 {
            bytes.push(1); // has_ipv6 = true
            bytes.extend_from_slice(client_ipv6);
            bytes.push(self.prefix_len_ipv6.unwrap_or(64));
            if let Some(gateway_ipv6) = &self.gateway_ipv6 {
                bytes.extend_from_slice(gateway_ipv6);
            } else {
                bytes.extend_from_slice(&[0u8; 16]);
            }
            bytes.push(self.dns_ipv6.len() as u8);
            for dns in &self.dns_ipv6 {
                bytes.extend_from_slice(dns);
            }
        } else {
            bytes.push(0); // has_ipv6 = false
        }

        // MTU
        bytes.extend_from_slice(&self.mtu.to_be_bytes());

        bytes
    }

    /// Decode from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if decoding fails.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::ProtocolError> {
        if bytes.len() < 16 {
            // Minimum: 4 + 4 + 4 + 1 + 1 (has_ipv6) + 2 (mtu)
            return Err(crate::error::ProtocolError::PacketTooShort {
                needed: 16,
                available: bytes.len(),
            });
        }

        let mut offset = 0;

        // IPv4 section
        let mut client_ipv4 = [0u8; 4];
        client_ipv4.copy_from_slice(&bytes[offset..offset + 4]);
        offset += 4;

        let mut netmask_ipv4 = [0u8; 4];
        netmask_ipv4.copy_from_slice(&bytes[offset..offset + 4]);
        offset += 4;

        let mut gateway_ipv4 = [0u8; 4];
        gateway_ipv4.copy_from_slice(&bytes[offset..offset + 4]);
        offset += 4;

        let dns_count = bytes[offset] as usize;
        offset += 1;

        // Validate DNS server count to prevent excessive allocation
        if dns_count > MAX_DNS_SERVERS {
            return Err(crate::error::ProtocolError::InvalidData(format!(
                "too many IPv4 DNS servers: {} (max {})",
                dns_count, MAX_DNS_SERVERS
            )));
        }

        if bytes.len() < offset + dns_count * 4 + 1 + 2 {
            return Err(crate::error::ProtocolError::PacketTooShort {
                needed: offset + dns_count * 4 + 1 + 2,
                available: bytes.len(),
            });
        }

        let mut dns_ipv4 = Vec::with_capacity(dns_count);
        for _ in 0..dns_count {
            let mut dns = [0u8; 4];
            dns.copy_from_slice(&bytes[offset..offset + 4]);
            dns_ipv4.push(dns);
            offset += 4;
        }

        // IPv6 section
        let has_ipv6 = bytes[offset] != 0;
        offset += 1;

        let (client_ipv6, prefix_len_ipv6, gateway_ipv6, dns_ipv6) = if has_ipv6 {
            if bytes.len() < offset + 16 + 1 + 16 + 1 + 2 {
                return Err(crate::error::ProtocolError::PacketTooShort {
                    needed: offset + 16 + 1 + 16 + 1 + 2,
                    available: bytes.len(),
                });
            }

            let mut client_ipv6 = [0u8; 16];
            client_ipv6.copy_from_slice(&bytes[offset..offset + 16]);
            offset += 16;

            let prefix_len = bytes[offset];
            offset += 1;

            let mut gateway_ipv6 = [0u8; 16];
            gateway_ipv6.copy_from_slice(&bytes[offset..offset + 16]);
            offset += 16;

            let dns6_count = bytes[offset] as usize;
            offset += 1;

            // Validate DNS server count to prevent excessive allocation
            if dns6_count > MAX_DNS_SERVERS {
                return Err(crate::error::ProtocolError::InvalidData(format!(
                    "too many IPv6 DNS servers: {} (max {})",
                    dns6_count, MAX_DNS_SERVERS
                )));
            }

            if bytes.len() < offset + dns6_count * 16 + 2 {
                return Err(crate::error::ProtocolError::PacketTooShort {
                    needed: offset + dns6_count * 16 + 2,
                    available: bytes.len(),
                });
            }

            let mut dns_ipv6 = Vec::with_capacity(dns6_count);
            for _ in 0..dns6_count {
                let mut dns = [0u8; 16];
                dns.copy_from_slice(&bytes[offset..offset + 16]);
                dns_ipv6.push(dns);
                offset += 16;
            }

            (
                Some(client_ipv6),
                Some(prefix_len),
                Some(gateway_ipv6),
                dns_ipv6,
            )
        } else {
            (None, None, None, Vec::new())
        };

        // MTU
        if bytes.len() < offset + 2 {
            return Err(crate::error::ProtocolError::PacketTooShort {
                needed: offset + 2,
                available: bytes.len(),
            });
        }
        let mtu = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);

        Ok(Self {
            client_ipv4,
            netmask_ipv4,
            gateway_ipv4,
            dns_ipv4,
            client_ipv6,
            prefix_len_ipv6,
            gateway_ipv6,
            dns_ipv6,
            mtu,
        })
    }
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            client_ipv4: [10, 99, 0, 2],
            netmask_ipv4: [255, 255, 255, 0],
            gateway_ipv4: [10, 99, 0, 1],
            dns_ipv4: vec![[10, 99, 0, 1]],
            client_ipv6: None,
            prefix_len_ipv6: None,
            gateway_ipv6: None,
            dns_ipv6: Vec::new(),
            mtu: 1420,
        }
    }
}

impl TunnelConfig {
    /// Helper to format IPv6 address from bytes.
    pub fn format_ipv6(addr: &[u8; 16]) -> String {
        let segments: Vec<String> = (0..8)
            .map(|i| {
                let val = u16::from_be_bytes([addr[i * 2], addr[i * 2 + 1]]);
                format!("{:x}", val)
            })
            .collect();
        segments.join(":")
    }

    /// Helper to parse IPv6 address string to bytes.
    pub fn parse_ipv6(s: &str) -> Option<[u8; 16]> {
        use std::net::Ipv6Addr;
        s.parse::<Ipv6Addr>().ok().map(|addr| addr.octets())
    }

    /// Check if this config has IPv6 enabled.
    pub fn has_ipv6(&self) -> bool {
        self.client_ipv6.is_some()
    }

    /// Get client IPv6 address as string.
    pub fn client_ipv6_str(&self) -> Option<String> {
        self.client_ipv6.as_ref().map(Self::format_ipv6)
    }

    /// Get gateway IPv6 address as string.
    pub fn gateway_ipv6_str(&self) -> Option<String> {
        self.gateway_ipv6.as_ref().map(Self::format_ipv6)
    }
}

/// Encrypted data message payload.
#[derive(Clone, Debug)]
pub struct DataMessage {
    /// Encrypted payload (IP packet).
    pub ciphertext: Vec<u8>,
}

impl DataMessage {
    /// Create a new data message.
    #[must_use]
    pub fn new(ciphertext: Vec<u8>) -> Self {
        Self { ciphertext }
    }
}

/// Keep-alive message (client -> server).
#[derive(Clone, Debug, Default)]
pub struct KeepaliveMessage {
    /// Ping sequence number.
    pub sequence: u32,
}

impl KeepaliveMessage {
    /// Encoded size.
    pub const SIZE: usize = 4;

    /// Encode to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        self.sequence.to_be_bytes()
    }

    /// Decode from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::ProtocolError> {
        if bytes.len() < Self::SIZE {
            return Err(crate::error::ProtocolError::PacketTooShort {
                needed: Self::SIZE,
                available: bytes.len(),
            });
        }
        Ok(Self {
            sequence: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        })
    }
}

/// Keep-alive reply message (server -> client).
#[derive(Clone, Debug, Default)]
pub struct KeepaliveReplyMessage {
    /// Echo of the ping sequence number.
    pub sequence: u32,
    /// Server timestamp for RTT calculation.
    pub server_timestamp: u64,
}

impl KeepaliveReplyMessage {
    /// Encoded size.
    pub const SIZE: usize = 12;

    /// Encode to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[0..4].copy_from_slice(&self.sequence.to_be_bytes());
        bytes[4..12].copy_from_slice(&self.server_timestamp.to_be_bytes());
        bytes
    }

    /// Decode from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::ProtocolError> {
        if bytes.len() < Self::SIZE {
            return Err(crate::error::ProtocolError::PacketTooShort {
                needed: Self::SIZE,
                available: bytes.len(),
            });
        }
        Ok(Self {
            sequence: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            server_timestamp: u64::from_be_bytes([
                bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
            ]),
        })
    }
}

/// Maximum age (seconds) accepted on a `SignedRebindAckPayload`.
///
/// Older payloads are rejected as a possible replay. The clock skew
/// between client and server is bounded by the handshake's
/// `kdf_timestamp` exchange, which already enforces a few-minute
/// envelope; we re-use the same order of magnitude here so a
/// legitimate roaming + RTT round-trip is always well within the
/// window.
pub const MAX_REBIND_ACK_AGE_SECS: u64 = 300;

/// Maximum forward clock skew (server timestamp ahead of client clock).
/// Tighter than the backward window so a misconfigured server clock
/// cannot extend the replay validity arbitrarily into the future.
pub const MAX_REBIND_ACK_FUTURE_SKEW_SECS: u64 = 60;

/// Domain-separated transcript prefix for [`SignedRebindAckPayload`].
///
/// Including a unique magic string in the signed transcript prevents the
/// signature from being mistaken for a signature on any other HPN
/// protocol message that happens to share a numeric layout.
const REBIND_ACK_TRANSCRIPT_DOMAIN: &[u8] = b"HPN-REBIND-ACK-V1";

/// Signed `RebindAck` payload binding the server's commitment that
/// `session_id` is now bound to a specific endpoint at a specific time.
///
/// # Threat model (audit H11)
///
/// The data-plane is already protected by AEAD with the per-session
/// keys: an attacker without those keys cannot forge a `ControlMessage`
/// of any kind, including a `RebindAck`. This signature is *defence in
/// depth* against the scenario where an attacker has somehow obtained
/// the symmetric session keys (memory disclosure, cold-boot,
/// compromised crypto module) but does NOT hold the server's ML-DSA
/// secret key:
///
/// - Without the signature, such an attacker could craft a fake
///   `RebindAck` that the client would accept, then redirect the
///   client's traffic to an attacker-controlled endpoint by also
///   sending a forged data plane.
/// - With the signature, the client verifies the ack against the
///   server's static `MlDsaPublicKey` (the same one it learned during
///   the handshake — see [`HandshakeResponse::server_static_pk`]). The
///   ML-DSA secret key never leaves the server, so the signature
///   cannot be forged even with full session-key compromise.
///
/// The signature also prevents a more subtle replay vector: a recorded
/// `RebindAck` from a previous session being injected into a new
/// session. The transcript binds `session_id`, so a sig from a different
/// session does not validate.
///
/// # Wire format
///
/// ```text
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | sec_level (1) | timestamp (8) ........................        |
/// |                                                                |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | addr_family (1: 4 or 6) | ip (4 or 16) | port (2)             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | signature (3309 for L3, 4627 for L5) ........................ |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// # Transcript signed by the server
///
/// ```text
/// "HPN-REBIND-ACK-V1" || session_id (8) || timestamp (8)
///   || addr_family (1) || ip (4 or 16) || port (2)
/// ```
#[derive(Clone, Debug)]
pub struct SignedRebindAckPayload {
    /// Security level (drives signature size).
    pub security_level: SecurityLevel,
    /// Unix-seconds timestamp when the server signed the ack.
    pub timestamp: u64,
    /// Endpoint the server has now bound the session to.
    pub endpoint: std::net::SocketAddr,
    /// ML-DSA signature over the transcript.
    pub signature: MlDsaSignature,
}

impl SignedRebindAckPayload {
    /// Build the byte transcript that gets signed/verified.
    ///
    /// The transcript binds:
    /// - a fixed domain separator (`HPN-REBIND-ACK-V1`),
    /// - the session id (anti cross-session replay),
    /// - the unix timestamp (anti same-session replay window),
    /// - the endpoint family + ip + port (the actual commitment).
    fn build_transcript(
        session_id: SessionId,
        timestamp: u64,
        endpoint: std::net::SocketAddr,
    ) -> Vec<u8> {
        // Conservative size: domain (17) + session (8) + ts (8) + family (1)
        // + ip (16, max v6) + port (2) = 52 bytes.
        let mut transcript = Vec::with_capacity(64);
        transcript.extend_from_slice(REBIND_ACK_TRANSCRIPT_DOMAIN);
        transcript.extend_from_slice(&session_id.to_bytes());
        transcript.extend_from_slice(&timestamp.to_be_bytes());
        match endpoint.ip() {
            std::net::IpAddr::V4(v4) => {
                transcript.push(4u8);
                transcript.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                transcript.push(6u8);
                transcript.extend_from_slice(&v6.octets());
            }
        }
        transcript.extend_from_slice(&endpoint.port().to_be_bytes());
        transcript
    }

    /// Sign a freshly-built payload binding `session_id` and `endpoint`
    /// to the current wall-clock time, using the server's ML-DSA keypair.
    ///
    /// The keypair's `security_level` determines the signature size on
    /// the wire (3309 bytes for Level3, 4627 bytes for Level5).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying ML-DSA signing operation
    /// fails OR if the system clock is set before UNIX_EPOCH (a
    /// misconfigured server should NOT be allowed to silently sign
    /// timestamp=0 acks that the client would later compare against
    /// its own current time and accept as 1970-01-01-fresh). ML-DSA
    /// signing is deterministic from `(secret_key, message)` and
    /// cannot fail for well-formed input on any platform supported
    /// by `pqcrypto`, but the result type is preserved for forward
    /// compatibility with future signing backends.
    pub fn sign(
        keypair: &crate::crypto::MlDsaKeypair,
        session_id: SessionId,
        endpoint: std::net::SocketAddr,
    ) -> Result<Self, crate::error::ProtocolError> {
        // Audit H11-F2: refuse to sign on a backwards-set system clock.
        // `duration_since(UNIX_EPOCH)` returns Err when the clock is
        // before 1970-01-01, which only happens on misconfigured
        // installs — but signing with `timestamp = 0` would produce
        // an ack that, on a client whose own clock is past 1970,
        // freshly looks 55+ years old and gets rejected — so the
        // server side is harmless. The verify side, however, uses
        // `unwrap_or(Duration::MAX)` (see `verify`) to fail-CLOSED
        // on the same condition, so the asymmetry is intentional.
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| {
                crate::error::ProtocolError::HandshakeFailed(
                    "rebind-ack signing failed: system clock before UNIX_EPOCH".into(),
                )
            })?
            .as_secs();

        let transcript = Self::build_transcript(session_id, timestamp, endpoint);
        let signature = keypair.sign(&transcript).map_err(|e| {
            crate::error::ProtocolError::HandshakeFailed(format!(
                "rebind-ack signing failed: {:?}",
                e
            ))
        })?;

        Ok(Self {
            security_level: keypair.security_level,
            timestamp,
            endpoint,
            signature,
        })
    }

    /// Verify the signature against `server_static_pk`, ensure the
    /// payload binds `expected_session_id`, and check the freshness
    /// window.
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success: signature is valid AND the timestamp is
    ///   within `MAX_REBIND_ACK_AGE_SECS` of `now` (i.e. not a replay).
    /// - `Err(ProtocolError::InvalidData)` if the timestamp is outside
    ///   the freshness window.
    /// - `Err(ProtocolError::HandshakeFailed)` if the cryptographic
    ///   verification fails.
    ///
    /// The transcript that ML-DSA validates against is built from
    /// `expected_session_id` (caller-supplied — anti-cross-session
    /// replay) plus `self.timestamp` and `self.endpoint` (taken from the
    /// signed payload). A signature crafted for a different
    /// session_id, timestamp, or endpoint will fail verification
    /// because every transcript byte is covered by the ML-DSA
    /// signature.
    pub fn verify(
        &self,
        server_static_pk: &MlDsaPublicKey,
        expected_session_id: SessionId,
    ) -> Result<(), crate::error::ProtocolError> {
        // Freshness check first — cheap and prevents any signature
        // CPU work on stale messages.
        //
        // Audit H11-F2: a misconfigured client clock set BEFORE
        // UNIX_EPOCH would make `duration_since(UNIX_EPOCH)` fail.
        // We fail-CLOSED by treating that as `Duration::MAX`, which
        // forces the "signed timestamp is in the future" branch and
        // rejects every ack — better than silently accepting a
        // captured stale ack on a client that has just rebooted
        // before NTP sync.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::MAX)
            .as_secs();
        if self.timestamp > now {
            // Future-dated ack: clamp by max future skew to avoid
            // accepting a server with a wildly-misconfigured clock as
            // a way to extend the replay window forward.
            if self.timestamp.saturating_sub(now) > MAX_REBIND_ACK_FUTURE_SKEW_SECS {
                return Err(crate::error::ProtocolError::InvalidData(format!(
                    "rebind-ack timestamp {} is {} s in the future (max {} s)",
                    self.timestamp,
                    self.timestamp.saturating_sub(now),
                    MAX_REBIND_ACK_FUTURE_SKEW_SECS
                )));
            }
        } else if now.saturating_sub(self.timestamp) > MAX_REBIND_ACK_AGE_SECS {
            return Err(crate::error::ProtocolError::InvalidData(format!(
                "rebind-ack timestamp {} is {} s old (max {} s)",
                self.timestamp,
                now.saturating_sub(self.timestamp),
                MAX_REBIND_ACK_AGE_SECS
            )));
        }

        let transcript = Self::build_transcript(expected_session_id, self.timestamp, self.endpoint);

        crate::crypto::signature::verify(
            server_static_pk,
            &transcript,
            &self.signature,
            self.security_level,
        )
        .map_err(|e| {
            crate::error::ProtocolError::HandshakeFailed(format!(
                "rebind-ack signature verification failed: {:?}",
                e
            ))
        })
    }

    /// Encode to bytes (NOT including any outer length prefix; that is
    /// added by `ControlMessage::to_bytes`).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let sig_bytes = self.signature.as_bytes();
        // sec_level (1) + ts (8) + family (1) + ip (4 or 16) + port (2)
        // + signature.
        let ip_size = match self.endpoint {
            std::net::SocketAddr::V4(_) => 4,
            std::net::SocketAddr::V6(_) => 16,
        };
        let mut bytes = Vec::with_capacity(1 + 8 + 1 + ip_size + 2 + sig_bytes.len());
        bytes.push(self.security_level.as_u8());
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        match self.endpoint.ip() {
            std::net::IpAddr::V4(v4) => {
                bytes.push(4u8);
                bytes.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                bytes.push(6u8);
                bytes.extend_from_slice(&v6.octets());
            }
        }
        bytes.extend_from_slice(&self.endpoint.port().to_be_bytes());
        bytes.extend_from_slice(sig_bytes);
        bytes
    }

    /// Decode from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer is malformed, the security level
    /// is unknown, the address family is invalid, or the signature size
    /// does not match the security level.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::ProtocolError> {
        // Minimum size: sec_level (1) + ts (8) + family (1) + ipv4 (4)
        // + port (2) + ML-DSA-65 sig (3309) = 3325 bytes.
        const MIN_PAYLOAD_SIZE: usize = 1 + 8 + 1 + 4 + 2 + MlDsaSignature::SIZE;
        if bytes.len() < MIN_PAYLOAD_SIZE {
            return Err(crate::error::ProtocolError::PacketTooShort {
                needed: MIN_PAYLOAD_SIZE,
                available: bytes.len(),
            });
        }

        let security_level = SecurityLevel::from_u8(bytes[0]).ok_or_else(|| {
            crate::error::ProtocolError::InvalidData(format!(
                "invalid security level in rebind-ack: {}",
                bytes[0]
            ))
        })?;

        let timestamp = u64::from_be_bytes([
            bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8],
        ]);

        let mut offset = 9;
        let family = bytes[offset];
        offset += 1;

        let endpoint = match family {
            4u8 => {
                if bytes.len() < offset + 4 + 2 {
                    return Err(crate::error::ProtocolError::PacketTooShort {
                        needed: offset + 4 + 2,
                        available: bytes.len(),
                    });
                }
                let mut ip = [0u8; 4];
                ip.copy_from_slice(&bytes[offset..offset + 4]);
                offset += 4;
                let port = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
                offset += 2;
                std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip)), port)
            }
            6u8 => {
                if bytes.len() < offset + 16 + 2 {
                    return Err(crate::error::ProtocolError::PacketTooShort {
                        needed: offset + 16 + 2,
                        available: bytes.len(),
                    });
                }
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&bytes[offset..offset + 16]);
                offset += 16;
                let port = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
                offset += 2;
                std::net::SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip)), port)
            }
            other => {
                return Err(crate::error::ProtocolError::InvalidData(format!(
                    "invalid address family in rebind-ack: {}",
                    other
                )));
            }
        };

        let expected_sig_size = MlDsaSignature::size_for_level(security_level);
        if bytes.len() < offset + expected_sig_size {
            return Err(crate::error::ProtocolError::PacketTooShort {
                needed: offset + expected_sig_size,
                available: bytes.len(),
            });
        }
        let signature = MlDsaSignature::from_bytes_with_level(
            bytes[offset..offset + expected_sig_size].to_vec(),
            security_level,
        )
        .ok_or_else(|| {
            crate::error::ProtocolError::HandshakeFailed(format!(
                "rebind-ack signature size mismatch for level {:?}",
                security_level
            ))
        })?;

        Ok(Self {
            security_level,
            timestamp,
            endpoint,
            signature,
        })
    }
}

/// Control message for session management.
#[derive(Clone, Debug)]
pub struct ControlMessage {
    /// Control message type.
    pub control_type: ControlType,
    /// Optional error code.
    pub error_code: Option<u16>,
    /// Optional message.
    pub message: Option<String>,
    /// Optional ML-DSA-signed payload.
    ///
    /// Currently only used for `RebindAck` (audit H11). Carried as a
    /// trailing extension after the legacy `[type|err|msg_len|msg]`
    /// block so old decoders that pre-date this field continue to
    /// parse the message correctly — they simply ignore the trailing
    /// bytes. New decoders read a `[sig_len: u16][sig_bytes]` block if
    /// any bytes remain after the legacy fields.
    pub signed_payload: Option<SignedRebindAckPayload>,
}

impl ControlMessage {
    /// Create an error control message.
    #[must_use]
    pub fn error(code: u16, message: impl Into<String>) -> Self {
        Self {
            control_type: ControlType::Error,
            error_code: Some(code),
            message: Some(message.into()),
            signed_payload: None,
        }
    }

    /// Create a close control message.
    #[must_use]
    pub fn close() -> Self {
        Self {
            control_type: ControlType::Close,
            error_code: None,
            message: None,
            signed_payload: None,
        }
    }

    /// Create a `RebindAck` carrying a server-signed payload.
    ///
    /// Used by the server side of the rebind handshake (audit H11). The
    /// client verifies `signed_payload` against the server's static
    /// ML-DSA public key in [`SignedRebindAckPayload::verify`] before
    /// considering the new endpoint authoritative.
    #[must_use]
    pub fn rebind_ack_signed(signed_payload: SignedRebindAckPayload) -> Self {
        Self {
            control_type: ControlType::RebindAck,
            error_code: None,
            message: None,
            signed_payload: Some(signed_payload),
        }
    }

    /// Encode to bytes.
    ///
    /// Wire format:
    ///
    /// ```text
    /// [type (1)] [error_code (2)] [msg_len (2)] [msg_bytes]
    ///   [signed_len (2)] [signed_bytes]              ← optional, audit H11
    /// ```
    ///
    /// The `signed_*` block is appended ONLY when `signed_payload` is
    /// `Some`. Decoders that pre-date the signed-payload extension
    /// (audit H11) stop reading after `msg_bytes`, so the wire format
    /// stays backward-compatible.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.control_type as u8);

        if let Some(code) = self.error_code {
            bytes.extend_from_slice(&code.to_be_bytes());
        } else {
            bytes.extend_from_slice(&0u16.to_be_bytes());
        }

        if let Some(ref msg) = self.message {
            let msg_bytes = msg.as_bytes();
            let bounded_len = msg_bytes.len().min(MAX_CONTROL_MESSAGE_LEN);
            let msg_len = bounded_len as u16;
            bytes.extend_from_slice(&msg_len.to_be_bytes());
            bytes.extend_from_slice(&msg_bytes[..bounded_len]);
        } else {
            bytes.extend_from_slice(&0u16.to_be_bytes());
        }

        // Trailing signed-payload block. Only appended when present so
        // the legacy wire size is unchanged for old encoders.
        if let Some(ref sig_payload) = self.signed_payload {
            let sig_bytes = sig_payload.to_bytes();
            // u16 length prefix is enough: even Level5 sigs are
            // < 5 KiB and the whole block is bounded by ML-DSA-87
            // signature size (4627) + ~32 header bytes < 65535.
            let sig_len_u16 = u16::try_from(sig_bytes.len()).unwrap_or(u16::MAX);
            bytes.extend_from_slice(&sig_len_u16.to_be_bytes());
            bytes.extend_from_slice(&sig_bytes[..sig_len_u16 as usize]);
        }

        bytes
    }

    /// Decode from bytes.
    ///
    /// Backward-compatible with pre-H11 encoders: if no bytes remain
    /// after the legacy `msg_len` block, `signed_payload` is `None` and
    /// the remaining behaviour is identical. New encoders append the
    /// `[sig_len: u16][sig_bytes]` block; if `sig_len == 0` we treat it
    /// as "no signed payload" rather than an error to keep the format
    /// future-extensible.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::ProtocolError> {
        if bytes.len() < 5 {
            return Err(crate::error::ProtocolError::PacketTooShort {
                needed: 5,
                available: bytes.len(),
            });
        }

        let control_type =
            ControlType::from_u8(bytes[0]).ok_or(crate::error::ProtocolError::InvalidHeader)?;

        let error_code = u16::from_be_bytes([bytes[1], bytes[2]]);
        let error_code = if error_code > 0 {
            Some(error_code)
        } else {
            None
        };

        let msg_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;

        // Validate message length to prevent memory exhaustion
        if msg_len > MAX_CONTROL_MESSAGE_LEN {
            return Err(crate::error::ProtocolError::InvalidData(format!(
                "control message too long: {} bytes (max {})",
                msg_len, MAX_CONTROL_MESSAGE_LEN
            )));
        }

        if msg_len > 0 && bytes.len() < 5 + msg_len {
            return Err(crate::error::ProtocolError::PacketTooShort {
                needed: 5 + msg_len,
                available: bytes.len(),
            });
        }

        let message = if msg_len > 0 {
            Some(String::from_utf8_lossy(&bytes[5..5 + msg_len]).into_owned())
        } else {
            None
        };

        // Optional trailing signed-payload block (audit H11). Old
        // encoders never produced these bytes, so absence is the
        // legacy-compatible path.
        let signed_payload_offset = 5 + msg_len;
        let signed_payload = if bytes.len() >= signed_payload_offset + 2 {
            let sig_len = u16::from_be_bytes([
                bytes[signed_payload_offset],
                bytes[signed_payload_offset + 1],
            ]) as usize;
            if sig_len == 0 {
                None
            } else if bytes.len() < signed_payload_offset + 2 + sig_len {
                return Err(crate::error::ProtocolError::PacketTooShort {
                    needed: signed_payload_offset + 2 + sig_len,
                    available: bytes.len(),
                });
            } else {
                let sig_block =
                    &bytes[signed_payload_offset + 2..signed_payload_offset + 2 + sig_len];
                Some(SignedRebindAckPayload::from_bytes(sig_block)?)
            }
        } else {
            None
        };

        Ok(Self {
            control_type,
            error_code,
            message,
            signed_payload,
        })
    }
}

/// Rekey message for key rotation (client -> server).
#[derive(Clone, Debug)]
pub struct RekeyMessage {
    /// New client ephemeral public key.
    pub client_ephemeral_pk: HybridPublicKey,
    /// New random bytes.
    pub client_random: [u8; 32],
}

impl RekeyMessage {
    /// Create a new rekey message.
    #[must_use]
    pub fn new(client_ephemeral_pk: HybridPublicKey) -> Self {
        let mut client_random = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut client_random);
        Self {
            client_ephemeral_pk,
            client_random,
        }
    }

    /// Encode to bytes.
    ///
    /// Wire format: [security_level (1 byte)] [client_ephemeral_pk (variable)] [client_random (32 bytes)]
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let pk_size = HybridPublicKey::size_for_level(self.client_ephemeral_pk.security_level);
        let mut bytes = Vec::with_capacity(1 + pk_size + 32);
        bytes.push(self.client_ephemeral_pk.security_level.as_u8());
        bytes.extend_from_slice(&self.client_ephemeral_pk.to_bytes_raw());
        bytes.extend_from_slice(&self.client_random);
        bytes
    }

    /// Decode from bytes.
    ///
    /// Reads the security level byte from the wire format to determine
    /// the expected public key size. Falls back to Level3 if the first
    /// byte is not a valid security level (backward compatibility with
    /// old clients that don't include the level byte).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::ProtocolError> {
        if bytes.is_empty() {
            return Err(crate::error::ProtocolError::PacketTooShort {
                needed: 1,
                available: 0,
            });
        }

        // Try to parse security level from first byte
        let (level, offset) = match SecurityLevel::from_u8(bytes[0]) {
            Some(level) => (level, 1),
            // Backward compatibility: old wire format without level byte
            None => (SecurityLevel::Level3, 0),
        };

        let pk_size = HybridPublicKey::size_for_level(level);
        let min_size = offset + pk_size + 32;
        if bytes.len() < min_size {
            return Err(crate::error::ProtocolError::PacketTooShort {
                needed: min_size,
                available: bytes.len(),
            });
        }

        let client_ephemeral_pk =
            HybridPublicKey::from_bytes_with_level(&bytes[offset..offset + pk_size], level)
                .map_err(|_| {
                    crate::error::ProtocolError::HandshakeFailed("invalid public key".into())
                })?;

        let mut client_random = [0u8; 32];
        client_random.copy_from_slice(&bytes[offset + pk_size..min_size]);

        Ok(Self {
            client_ephemeral_pk,
            client_random,
        })
    }
}

/// Rekey response message (server -> client).
///
/// Contains the server's ciphertext and signature to complete the rekey.
/// Includes key confirmation MAC to prove the server has derived correct keys.
#[derive(Clone, Debug)]
pub struct RekeyResponse {
    /// Server's hybrid ciphertext (encapsulated new secret).
    pub server_ciphertext: HybridCiphertext,
    /// Server's signature over the rekey transcript.
    pub signature: MlDsaSignature,
    /// Server's random bytes.
    pub server_random: [u8; 32],
    /// New key ID after rekey.
    pub new_key_id: u32,
    /// Key confirmation MAC (HMAC-SHA256 of transcript using derived send key).
    /// This proves the server has correctly derived the new session keys.
    pub key_confirmation: [u8; 32],
    /// Key derivation timestamp (Unix seconds) for session context binding.
    /// Used with session_id for proper key derivation with context.
    pub kdf_timestamp: u64,
    /// Session ID for key derivation context.
    /// Ensures rekeyed sessions have the same binding as initial handshake.
    pub session_id: SessionId,
}

impl RekeyResponse {
    /// Encode to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let level = self.signature.security_level;
        // Size: ciphertext + signature + server_random + new_key_id + key_confirmation + kdf_timestamp + session_id
        let mut bytes = Vec::with_capacity(
            HybridCiphertext::size_for_level(level)
                + MlDsaSignature::size_for_level(level)
                + 32
                + 4
                + 32
                + 8
                + SessionId::SIZE,
        );
        // Use raw encoding without security level prefix for protocol messages
        bytes.extend_from_slice(&self.server_ciphertext.to_bytes_raw());
        bytes.extend_from_slice(self.signature.as_bytes());
        bytes.extend_from_slice(&self.server_random);
        bytes.extend_from_slice(&self.new_key_id.to_be_bytes());
        bytes.extend_from_slice(&self.key_confirmation);
        bytes.extend_from_slice(&self.kdf_timestamp.to_be_bytes());
        bytes.extend_from_slice(&self.session_id.to_bytes());
        bytes
    }

    /// Decode from bytes assuming Level 3 sizes.
    ///
    /// ⚠️ Prefer [`Self::from_bytes_with_level`] on any real code path —
    /// see the identical warning on `HandshakeResponse::from_bytes`. Kept
    /// for tests and fuzz targets only.
    #[doc(hidden)]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::ProtocolError> {
        Self::from_bytes_with_level(bytes, SecurityLevel::Level3)
    }

    /// Decode from bytes with explicit security level.
    ///
    /// The security level determines the expected sizes for ciphertext
    /// and signature fields in the wire format.
    pub fn from_bytes_with_level(
        bytes: &[u8],
        level: SecurityLevel,
    ) -> Result<Self, crate::error::ProtocolError> {
        let ct_size = HybridCiphertext::size_for_level(level);
        let sig_size = MlDsaSignature::size_for_level(level);

        // Minimum size includes all fields
        let min_size = ct_size + sig_size + 32 + 4 + 32 + 8 + SessionId::SIZE;
        if bytes.len() < min_size {
            return Err(crate::error::ProtocolError::PacketTooShort {
                needed: min_size,
                available: bytes.len(),
            });
        }

        let mut offset = 0;

        // Server ciphertext
        let server_ciphertext =
            HybridCiphertext::from_bytes_with_level(&bytes[offset..offset + ct_size], level)
                .map_err(|_| {
                    crate::error::ProtocolError::HandshakeFailed("invalid ciphertext".into())
                })?;
        offset += ct_size;

        // Signature
        let signature =
            MlDsaSignature::from_bytes_with_level(bytes[offset..offset + sig_size].to_vec(), level)
                .ok_or_else(|| {
                    crate::error::ProtocolError::HandshakeFailed(format!(
                        "rekey signature size mismatch for level {:?}",
                        level
                    ))
                })?;
        offset += sig_size;

        // Server random
        let mut server_random = [0u8; 32];
        server_random.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;

        // New key ID
        let new_key_id = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        offset += 4;

        // Key confirmation MAC
        let mut key_confirmation = [0u8; 32];
        key_confirmation.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;

        // KDF timestamp
        let kdf_timestamp = u64::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]);
        offset += 8;

        // Session ID
        let mut session_id_bytes = [0u8; 8];
        session_id_bytes.copy_from_slice(&bytes[offset..offset + SessionId::SIZE]);
        let session_id = SessionId::from_bytes(session_id_bytes);

        Ok(Self {
            server_ciphertext,
            signature,
            server_random,
            new_key_id,
            key_confirmation,
            kdf_timestamp,
            session_id,
        })
    }
}

/// Default maximum age for cookie challenges (60 seconds).
pub const DEFAULT_COOKIE_MAX_AGE_SECS: u64 = 60;

/// Cookie challenge request (server -> client) for anti-DoS protection.
///
/// Requires client to solve a proof-of-work puzzle before proceeding with
/// expensive ML-KEM operations. This prevents handshake flood DoS attacks.
#[derive(Clone, Debug)]
pub struct CookieRequest {
    /// Server-generated challenge nonce (32 bytes).
    pub challenge: [u8; 32],
    /// Difficulty level (number of leading zero bits required).
    /// Typical values: 8-16 (8 = ~256 hashes, 16 = ~65K hashes).
    pub difficulty: u8,
    /// Server's source address (IP:port hash) to prevent spoofing.
    pub server_addr_hash: [u8; 16],
    /// Unix timestamp (seconds) when the cookie was created.
    /// Used to prevent replay attacks by rejecting old cookies.
    pub timestamp: u64,
}

impl CookieRequest {
    /// Encoded size in bytes: challenge(32) + difficulty(1) + server_addr_hash(16) + timestamp(8)
    pub const SIZE: usize = 32 + 1 + 16 + 8;

    /// Create a new cookie request with specified difficulty.
    ///
    /// # Arguments
    ///
    /// * `difficulty` - Number of leading zero bits required (8-24 range)
    /// * `client_addr` - Client's socket address for binding
    #[must_use]
    pub fn new(difficulty: u8, client_addr: &std::net::SocketAddr) -> Self {
        use rand::RngCore;
        use std::time::{SystemTime, UNIX_EPOCH};

        let mut challenge = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut challenge);

        // Hash client address to prevent cookie reuse across different connections
        let addr_str = client_addr.to_string();
        let mut server_addr_hash = [0u8; 16];
        use ring::digest;
        let hash = digest::digest(&digest::SHA256, addr_str.as_bytes());
        server_addr_hash.copy_from_slice(&hash.as_ref()[0..16]);

        // Get current unix timestamp (use 0 if system clock is before epoch)
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(std::time::Duration::ZERO)
            .as_secs();

        Self {
            challenge,
            difficulty,
            server_addr_hash,
            timestamp,
        }
    }

    /// Check if the cookie has expired.
    ///
    /// # Arguments
    ///
    /// * `max_age_secs` - Maximum allowed age in seconds
    ///
    /// # Returns
    ///
    /// Returns `true` if the cookie is older than `max_age_secs`, `false` otherwise.
    #[must_use]
    pub fn is_expired(&self, max_age_secs: u64) -> bool {
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        // Check if timestamp is in the future (clock skew tolerance: allow up to 5 seconds)
        if self.timestamp > now + 5 {
            return true;
        }

        // Check if cookie is too old
        now.saturating_sub(self.timestamp) > max_age_secs
    }

    /// Check if the cookie has expired using the default max age (60 seconds).
    #[must_use]
    pub fn is_expired_default(&self) -> bool {
        self.is_expired(DEFAULT_COOKIE_MAX_AGE_SECS)
    }

    /// Encode to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::SIZE);
        bytes.extend_from_slice(&self.challenge);
        bytes.push(self.difficulty);
        bytes.extend_from_slice(&self.server_addr_hash);
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        bytes
    }

    /// Decode from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer is too short.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::ProtocolError> {
        if bytes.len() < Self::SIZE {
            return Err(crate::error::ProtocolError::PacketTooShort {
                needed: Self::SIZE,
                available: bytes.len(),
            });
        }

        let mut challenge = [0u8; 32];
        challenge.copy_from_slice(&bytes[0..32]);

        let difficulty = bytes[32];

        let mut server_addr_hash = [0u8; 16];
        server_addr_hash.copy_from_slice(&bytes[33..49]);

        let timestamp = u64::from_be_bytes([
            bytes[49], bytes[50], bytes[51], bytes[52], bytes[53], bytes[54], bytes[55], bytes[56],
        ]);

        Ok(Self {
            challenge,
            difficulty,
            server_addr_hash,
            timestamp,
        })
    }
}

/// Cookie challenge reply (client -> server) with proof-of-work solution.
#[derive(Clone, Debug)]
pub struct CookieReply {
    /// Original challenge from server.
    pub challenge: [u8; 32],
    /// Nonce that satisfies the proof-of-work puzzle.
    pub solution_nonce: u64,
    /// Original HandshakeInit that was deferred.
    pub handshake_init: HandshakeInit,
}

impl CookieReply {
    /// Create a new cookie reply by solving the puzzle.
    ///
    /// # Arguments
    ///
    /// * `challenge` - The challenge from the server
    /// * `difficulty` - Number of leading zero bits required (valid range: 1-32)
    /// * `handshake_init` - The original handshake init message
    ///
    /// # Returns
    ///
    /// Returns the reply with a valid proof-of-work solution.
    pub fn solve(
        challenge: [u8; 32],
        difficulty: u8,
        handshake_init: HandshakeInit,
    ) -> Result<Self, crate::error::ProtocolError> {
        // Validate difficulty range to prevent DoS via unreasonable difficulty
        // and ensure difficulty > 0 (difficulty 0 provides no protection)
        if difficulty == 0 || difficulty > 32 {
            return Err(crate::error::ProtocolError::HandshakeFailed(format!(
                "invalid puzzle difficulty: {} (must be 1-32)",
                difficulty
            )));
        }

        // Absolute cap on PoW iterations, independent of the advertised
        // `difficulty`. This guards the client against a malicious or
        // compromised server that sends e.g. `difficulty = 24` (no longer
        // gated by the previous `difficulty > 24` escape hatch) and keeps
        // the client spinning SHA-256 for tens of seconds to minutes. At
        // 2^26 hashes we're well above the ~2^difficulty expected work
        // for any legitimate difficulty up to 24 (so false positives are
        // vanishingly rare for honest servers), while still capping worst
        // case at a few seconds of CPU on modern hardware.
        const MAX_POW_ITERATIONS: u64 = 1 << 26;

        // Try nonces until we find one that satisfies the difficulty
        let required_zeros = difficulty as usize;
        for nonce in 0..MAX_POW_ITERATIONS {
            use ring::digest;

            // Compute SHA256(challenge || nonce)
            let mut input = Vec::with_capacity(32 + 8);
            input.extend_from_slice(&challenge);
            input.extend_from_slice(&nonce.to_be_bytes());
            let hash = digest::digest(&digest::SHA256, &input);

            // Check leading zeros in hash
            let hash_bytes = hash.as_ref();
            let mut leading_zeros = 0usize;
            for byte in hash_bytes {
                let byte_zeros = byte.leading_zeros() as usize;
                leading_zeros += byte_zeros;
                if byte_zeros < 8 {
                    break;
                }
            }

            if leading_zeros >= required_zeros {
                return Ok(Self {
                    challenge,
                    solution_nonce: nonce,
                    handshake_init,
                });
            }
        }

        Err(crate::error::ProtocolError::HandshakeFailed(
            "puzzle too difficult (exceeded MAX_POW_ITERATIONS)".into(),
        ))
    }

    /// Verify that the solution is valid.
    #[must_use]
    pub fn verify(&self, difficulty: u8) -> bool {
        use ring::digest;

        // Compute SHA256(challenge || nonce)
        let mut input = Vec::with_capacity(32 + 8);
        input.extend_from_slice(&self.challenge);
        input.extend_from_slice(&self.solution_nonce.to_be_bytes());
        let hash = digest::digest(&digest::SHA256, &input);

        // Check leading zeros
        let hash_bytes = hash.as_ref();
        let mut leading_zeros = 0usize;
        for byte in hash_bytes {
            let byte_zeros = byte.leading_zeros() as usize;
            leading_zeros += byte_zeros;
            if byte_zeros < 8 {
                break;
            }
        }

        leading_zeros >= difficulty as usize
    }

    /// Encode to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let init_bytes = self.handshake_init.to_bytes();
        let mut bytes = Vec::with_capacity(32 + 8 + init_bytes.len());
        bytes.extend_from_slice(&self.challenge);
        bytes.extend_from_slice(&self.solution_nonce.to_be_bytes());
        bytes.extend_from_slice(&init_bytes);
        bytes
    }

    /// Decode from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer is too short.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::ProtocolError> {
        const MIN_SIZE: usize = 32 + 8;
        if bytes.len() < MIN_SIZE {
            return Err(crate::error::ProtocolError::PacketTooShort {
                needed: MIN_SIZE,
                available: bytes.len(),
            });
        }

        let mut challenge = [0u8; 32];
        challenge.copy_from_slice(&bytes[0..32]);

        let solution_nonce = u64::from_be_bytes([
            bytes[32], bytes[33], bytes[34], bytes[35], bytes[36], bytes[37], bytes[38], bytes[39],
        ]);

        let handshake_init = HandshakeInit::from_bytes(&bytes[40..])?;

        Ok(Self {
            challenge,
            solution_nonce,
            handshake_init,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::HybridKem;

    #[test]
    fn test_handshake_response_session_id_from_bytes() {
        let expected = SessionId(0x1122_3344_5566_7788);
        let mut bytes = expected.to_bytes().to_vec();
        // Append arbitrary trailer to make sure the helper ignores it.
        bytes.extend_from_slice(&[0xAA; 64]);

        let id = HandshakeResponse::session_id_from_bytes(&bytes)
            .expect("8 bytes is enough to read the session id");
        assert_eq!(id, expected);
    }

    #[test]
    fn test_handshake_response_session_id_from_bytes_too_short() {
        let short = [0u8; SessionId::SIZE - 1];
        let err = HandshakeResponse::session_id_from_bytes(&short).unwrap_err();
        assert!(
            matches!(err, crate::error::ProtocolError::PacketTooShort { .. }),
            "unexpected error variant: {:?}",
            err
        );
    }

    #[test]
    fn test_tunnel_config_roundtrip() {
        let config = TunnelConfig {
            client_ipv4: [10, 0, 0, 2],
            netmask_ipv4: [255, 255, 255, 0],
            gateway_ipv4: [10, 0, 0, 1],
            dns_ipv4: vec![[8, 8, 8, 8], [8, 8, 4, 4]],
            client_ipv6: None,
            prefix_len_ipv6: None,
            gateway_ipv6: None,
            dns_ipv6: Vec::new(),
            mtu: 1400,
        };

        let bytes = config.to_bytes();
        let decoded = TunnelConfig::from_bytes(&bytes).unwrap();

        assert_eq!(config.client_ipv4, decoded.client_ipv4);
        assert_eq!(config.dns_ipv4.len(), decoded.dns_ipv4.len());
        assert_eq!(config.mtu, decoded.mtu);
        assert!(!decoded.has_ipv6());
    }

    #[test]
    fn test_tunnel_config_with_ipv6_roundtrip() {
        // fd99:hpn::2
        let client_ipv6 = [
            0xfd, 0x99, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ];
        // fd99:hpn::1
        let gateway_ipv6 = [
            0xfd, 0x99, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        // 2001:4860:4860::8888 (Google DNS)
        let dns_ipv6 = [
            0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x88, 0x88,
        ];

        let config = TunnelConfig {
            client_ipv4: [10, 0, 0, 2],
            netmask_ipv4: [255, 255, 255, 0],
            gateway_ipv4: [10, 0, 0, 1],
            dns_ipv4: vec![[8, 8, 8, 8]],
            client_ipv6: Some(client_ipv6),
            prefix_len_ipv6: Some(64),
            gateway_ipv6: Some(gateway_ipv6),
            dns_ipv6: vec![dns_ipv6],
            mtu: 1400,
        };

        let bytes = config.to_bytes();
        let decoded = TunnelConfig::from_bytes(&bytes).unwrap();

        assert_eq!(config.client_ipv4, decoded.client_ipv4);
        assert_eq!(config.dns_ipv4.len(), decoded.dns_ipv4.len());
        assert_eq!(config.mtu, decoded.mtu);
        assert!(decoded.has_ipv6());
        assert_eq!(decoded.client_ipv6, Some(client_ipv6));
        assert_eq!(decoded.prefix_len_ipv6, Some(64));
        assert_eq!(decoded.gateway_ipv6, Some(gateway_ipv6));
        assert_eq!(decoded.dns_ipv6.len(), 1);
        assert_eq!(decoded.dns_ipv6[0], dns_ipv6);
    }

    #[test]
    fn test_tunnel_config_ipv6_helpers() {
        let ipv6_addr = TunnelConfig::parse_ipv6("fd99::1").unwrap();
        let formatted = TunnelConfig::format_ipv6(&ipv6_addr);
        assert_eq!(formatted, "fd99:0:0:0:0:0:0:1");
    }

    #[test]
    fn test_handshake_init_roundtrip() {
        let (_, pk) = HybridKem::generate_keypair().unwrap();
        let init = HandshakeInit::new(pk);

        let bytes = init.to_bytes();
        let decoded = HandshakeInit::from_bytes(&bytes).unwrap();

        assert_eq!(
            init.client_ephemeral_pk.x25519.as_bytes(),
            decoded.client_ephemeral_pk.x25519.as_bytes()
        );
        assert_eq!(init.client_random, decoded.client_random);
    }

    #[test]
    fn test_keepalive_roundtrip() {
        let msg = KeepaliveMessage { sequence: 12345 };
        let bytes = msg.to_bytes();
        let decoded = KeepaliveMessage::from_bytes(&bytes).unwrap();
        assert_eq!(msg.sequence, decoded.sequence);
    }

    #[test]
    fn test_keepalive_reply_roundtrip() {
        let msg = KeepaliveReplyMessage {
            sequence: 12345,
            server_timestamp: 0xDEAD_BEEF_CAFE_BABE,
        };
        let bytes = msg.to_bytes();
        let decoded = KeepaliveReplyMessage::from_bytes(&bytes).unwrap();
        assert_eq!(msg.sequence, decoded.sequence);
        assert_eq!(msg.server_timestamp, decoded.server_timestamp);
    }

    #[test]
    fn test_control_message_roundtrip() {
        let msg = ControlMessage::error(500, "Internal error");
        let bytes = msg.to_bytes();
        let decoded = ControlMessage::from_bytes(&bytes).unwrap();
        assert_eq!(msg.error_code, decoded.error_code);
        assert_eq!(msg.message, decoded.message);
    }

    #[test]
    fn test_rekey_message_roundtrip() {
        let (_, pk) = HybridKem::generate_keypair().unwrap();
        let msg = RekeyMessage::new(pk);

        let bytes = msg.to_bytes();
        let decoded = RekeyMessage::from_bytes(&bytes).unwrap();

        assert_eq!(
            msg.client_ephemeral_pk.x25519.as_bytes(),
            decoded.client_ephemeral_pk.x25519.as_bytes()
        );
        assert_eq!(msg.client_random, decoded.client_random);
    }

    #[test]
    fn test_rekey_response_roundtrip() {
        use crate::crypto::MlDsaKeypair;

        let (client_sk, client_pk) = HybridKem::generate_keypair().unwrap();
        let (_, ciphertext) = HybridKem::encapsulate(&client_pk).unwrap();

        let keypair = MlDsaKeypair::generate();
        let signature = keypair.sign(b"test data").unwrap();

        let response = RekeyResponse {
            server_ciphertext: ciphertext,
            signature,
            server_random: [0x42u8; 32],
            new_key_id: 5,
            key_confirmation: [0xAAu8; 32],
            kdf_timestamp: 1_234_567_890,
            session_id: SessionId::generate(),
        };

        let bytes = response.to_bytes();
        let decoded = RekeyResponse::from_bytes(&bytes).unwrap();

        assert_eq!(response.server_random, decoded.server_random);
        assert_eq!(response.new_key_id, decoded.new_key_id);
        assert_eq!(response.key_confirmation, decoded.key_confirmation);
        assert_eq!(response.kdf_timestamp, decoded.kdf_timestamp);
        assert_eq!(response.session_id, decoded.session_id);

        // Verify ciphertext matches by decapsulating
        let _ = HybridKem::decapsulate(&client_sk, &decoded.server_ciphertext).unwrap();
    }

    #[test]
    fn test_cookie_request_roundtrip() {
        let client_addr = "127.0.0.1:1234".parse().unwrap();
        let request = CookieRequest::new(12, &client_addr);

        let bytes = request.to_bytes();
        let decoded = CookieRequest::from_bytes(&bytes).unwrap();

        assert_eq!(request.challenge, decoded.challenge);
        assert_eq!(request.difficulty, decoded.difficulty);
        assert_eq!(request.server_addr_hash, decoded.server_addr_hash);
        assert_eq!(request.timestamp, decoded.timestamp);
    }

    #[test]
    fn test_cookie_reply_solve_and_verify() {
        let challenge = [0x42u8; 32];
        let difficulty = 8; // Easy puzzle for test
        let (_, pk) = HybridKem::generate_keypair().unwrap();
        let handshake_init = HandshakeInit::new(pk);

        let reply = CookieReply::solve(challenge, difficulty, handshake_init).unwrap();

        // Verify solution
        assert!(reply.verify(difficulty));
        assert_eq!(reply.challenge, challenge);

        // Should fail with higher difficulty
        assert!(!reply.verify(difficulty + 4));
    }

    #[test]
    fn test_cookie_reply_roundtrip() {
        let challenge = [0x55u8; 32];
        let difficulty = 8;
        let (_, pk) = HybridKem::generate_keypair().unwrap();
        let handshake_init = HandshakeInit::new(pk);

        let reply = CookieReply::solve(challenge, difficulty, handshake_init).unwrap();

        let bytes = reply.to_bytes();
        let decoded = CookieReply::from_bytes(&bytes).unwrap();

        assert_eq!(reply.challenge, decoded.challenge);
        assert_eq!(reply.solution_nonce, decoded.solution_nonce);
        assert!(decoded.verify(difficulty));
    }

    #[test]
    fn test_control_message_error() {
        let msg = ControlMessage::error(404, "Not found");
        assert_eq!(msg.control_type, ControlType::Error);
        assert_eq!(msg.error_code, Some(404));
        assert_eq!(msg.message.as_deref(), Some("Not found"));
    }

    #[test]
    fn test_control_message_no_message() {
        let msg = ControlMessage {
            control_type: ControlType::Error,
            error_code: Some(500),
            message: None,
            signed_payload: None,
        };
        let bytes = msg.to_bytes();
        let decoded = ControlMessage::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.message, None);
        assert_eq!(decoded.error_code, Some(500));
    }

    #[test]
    fn test_control_message_max_length() {
        let long_msg = "a".repeat(MAX_CONTROL_MESSAGE_LEN);
        let msg = ControlMessage::error(500, long_msg);
        let bytes = msg.to_bytes();
        let decoded = ControlMessage::from_bytes(&bytes).unwrap();
        assert_eq!(
            decoded.message.as_ref().unwrap().len(),
            MAX_CONTROL_MESSAGE_LEN
        );
    }

    #[test]
    fn test_control_message_encode_truncates_oversized_message() {
        let long_msg = "b".repeat(MAX_CONTROL_MESSAGE_LEN + 500);
        let msg = ControlMessage::error(500, long_msg);
        let bytes = msg.to_bytes();
        let decoded = ControlMessage::from_bytes(&bytes).unwrap();
        assert_eq!(
            decoded.message.as_ref().map(std::string::String::len),
            Some(MAX_CONTROL_MESSAGE_LEN)
        );
    }

    #[test]
    fn test_control_message_too_long_error() {
        // Create a message that claims to be too long
        let mut bytes = vec![
            ControlType::Error as u8,
            0,
            1, // error_code = 1
            0xFF,
            0xFF, // msg_len = 65535 (> MAX_CONTROL_MESSAGE_LEN)
        ];
        bytes.extend_from_slice(b"test");

        let result = ControlMessage::from_bytes(&bytes);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            crate::error::ProtocolError::InvalidData(_)
        ));
    }

    // ─── Audit H11: SignedRebindAckPayload + ControlMessage extension ────────

    fn test_endpoint_v4() -> std::net::SocketAddr {
        "203.0.113.42:51820".parse().unwrap()
    }

    fn test_endpoint_v6() -> std::net::SocketAddr {
        "[2001:db8::1]:51820".parse().unwrap()
    }

    #[test]
    fn test_signed_rebind_ack_sign_verify_v4_l3() {
        let keypair =
            crate::crypto::MlDsaKeypair::generate_with_level(crate::crypto::SecurityLevel::Level3);
        let session_id = SessionId(0xDEAD_BEEF_CAFE_F00D);
        let signed =
            SignedRebindAckPayload::sign(&keypair, session_id, test_endpoint_v4()).unwrap();

        assert_eq!(signed.security_level, crate::crypto::SecurityLevel::Level3);
        assert_eq!(signed.endpoint, test_endpoint_v4());
        assert!(signed.verify(&keypair.public_key, session_id).is_ok());
    }

    #[test]
    fn test_signed_rebind_ack_sign_verify_v6_l5() {
        let keypair =
            crate::crypto::MlDsaKeypair::generate_with_level(crate::crypto::SecurityLevel::Level5);
        let session_id = SessionId(0x1234_5678_9ABC_DEF0);
        let signed =
            SignedRebindAckPayload::sign(&keypair, session_id, test_endpoint_v6()).unwrap();

        assert_eq!(signed.security_level, crate::crypto::SecurityLevel::Level5);
        assert!(signed.verify(&keypair.public_key, session_id).is_ok());
    }

    #[test]
    fn test_signed_rebind_ack_wrong_session_id_rejected() {
        let keypair = crate::crypto::MlDsaKeypair::generate();
        let signed_for = SessionId(1);
        let signed =
            SignedRebindAckPayload::sign(&keypair, signed_for, test_endpoint_v4()).unwrap();

        // Verifying with a different session_id rebuilds a different
        // transcript, so ML-DSA verification fails.
        let result = signed.verify(&keypair.public_key, SessionId(2));
        assert!(result.is_err());
    }

    #[test]
    fn test_signed_rebind_ack_wrong_pubkey_rejected() {
        let keypair_a = crate::crypto::MlDsaKeypair::generate();
        let keypair_b = crate::crypto::MlDsaKeypair::generate();
        let session_id = SessionId(7);
        let signed =
            SignedRebindAckPayload::sign(&keypair_a, session_id, test_endpoint_v4()).unwrap();

        // Verifying against the wrong public key fails (the whole point
        // of audit H11 is that the signature is non-repudiable).
        assert!(signed.verify(&keypair_b.public_key, session_id).is_err());
    }

    #[test]
    fn test_signed_rebind_ack_tampered_endpoint_rejected() {
        let keypair = crate::crypto::MlDsaKeypair::generate();
        let session_id = SessionId(11);
        let mut signed =
            SignedRebindAckPayload::sign(&keypair, session_id, test_endpoint_v4()).unwrap();

        // An attacker who can flip self.endpoint after signing would
        // change the transcript that `verify` rebuilds, so the
        // signature no longer matches.
        signed.endpoint = "192.0.2.99:1234".parse().unwrap();
        assert!(signed.verify(&keypair.public_key, session_id).is_err());
    }

    #[test]
    fn test_signed_rebind_ack_stale_timestamp_rejected() {
        let keypair = crate::crypto::MlDsaKeypair::generate();
        let session_id = SessionId(13);
        let mut signed =
            SignedRebindAckPayload::sign(&keypair, session_id, test_endpoint_v4()).unwrap();

        // Force the timestamp to look like a replayed ack from far in
        // the past. This MUST be rejected even though the ML-DSA
        // signature itself would still verify (we deliberately do not
        // re-sign here): the freshness check kicks in first.
        signed.timestamp = signed
            .timestamp
            .saturating_sub(MAX_REBIND_ACK_AGE_SECS + 60);
        assert!(matches!(
            signed.verify(&keypair.public_key, session_id),
            Err(crate::error::ProtocolError::InvalidData(_))
        ));
    }

    #[test]
    fn test_signed_rebind_ack_future_skew_rejected() {
        let keypair = crate::crypto::MlDsaKeypair::generate();
        let session_id = SessionId(17);
        let mut signed =
            SignedRebindAckPayload::sign(&keypair, session_id, test_endpoint_v4()).unwrap();
        signed.timestamp = signed
            .timestamp
            .saturating_add(MAX_REBIND_ACK_FUTURE_SKEW_SECS + 60);
        assert!(matches!(
            signed.verify(&keypair.public_key, session_id),
            Err(crate::error::ProtocolError::InvalidData(_))
        ));
    }

    #[test]
    fn test_signed_rebind_ack_bytes_roundtrip_v4() {
        let keypair =
            crate::crypto::MlDsaKeypair::generate_with_level(crate::crypto::SecurityLevel::Level3);
        let session_id = SessionId(0xAABB_CCDD_1122_3344);
        let signed =
            SignedRebindAckPayload::sign(&keypair, session_id, test_endpoint_v4()).unwrap();

        let bytes = signed.to_bytes();
        let decoded = SignedRebindAckPayload::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.security_level, signed.security_level);
        assert_eq!(decoded.timestamp, signed.timestamp);
        assert_eq!(decoded.endpoint, signed.endpoint);
        assert_eq!(decoded.signature.as_bytes(), signed.signature.as_bytes());
        assert!(decoded.verify(&keypair.public_key, session_id).is_ok());
    }

    #[test]
    fn test_signed_rebind_ack_bytes_roundtrip_v6_l5() {
        let keypair =
            crate::crypto::MlDsaKeypair::generate_with_level(crate::crypto::SecurityLevel::Level5);
        let session_id = SessionId(0xFEED_FACE_DEAD_BEEF);
        let signed =
            SignedRebindAckPayload::sign(&keypair, session_id, test_endpoint_v6()).unwrap();

        let bytes = signed.to_bytes();
        let decoded = SignedRebindAckPayload::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.security_level, signed.security_level);
        assert_eq!(decoded.endpoint, signed.endpoint);
        assert!(decoded.verify(&keypair.public_key, session_id).is_ok());
    }

    #[test]
    fn test_signed_rebind_ack_truncated_buffer_rejected() {
        let keypair = crate::crypto::MlDsaKeypair::generate();
        let signed =
            SignedRebindAckPayload::sign(&keypair, SessionId(1), test_endpoint_v4()).unwrap();
        let bytes = signed.to_bytes();
        for cut in [0, 5, 10, 20, bytes.len() - 1] {
            assert!(SignedRebindAckPayload::from_bytes(&bytes[..cut]).is_err());
        }
    }

    #[test]
    fn test_signed_rebind_ack_invalid_address_family_rejected() {
        // Build a buffer with a bogus address family byte. We use
        // SecurityLevel::Level3 sizing so the buffer is otherwise
        // structurally plausible and only the family byte trips the
        // parser.
        let mut bytes = Vec::new();
        bytes.push(crate::crypto::SecurityLevel::Level3.as_u8());
        bytes.extend_from_slice(&0u64.to_be_bytes()); // timestamp
        bytes.push(99u8); // invalid family
        bytes.extend_from_slice(&[0u8; 4 + 2]); // ip + port
        bytes.extend_from_slice(&[0u8; MlDsaSignature::SIZE]); // sig placeholder

        let result = SignedRebindAckPayload::from_bytes(&bytes);
        assert!(matches!(
            result,
            Err(crate::error::ProtocolError::InvalidData(_))
        ));
    }

    #[test]
    fn test_control_message_signed_payload_roundtrip() {
        let keypair = crate::crypto::MlDsaKeypair::generate();
        let session_id = SessionId(42);
        let signed =
            SignedRebindAckPayload::sign(&keypair, session_id, test_endpoint_v4()).unwrap();
        let msg = ControlMessage::rebind_ack_signed(signed.clone());

        let bytes = msg.to_bytes();
        let decoded = ControlMessage::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.control_type, ControlType::RebindAck);
        assert!(decoded.signed_payload.is_some());
        let sp = decoded.signed_payload.as_ref().unwrap();
        assert_eq!(sp.endpoint, signed.endpoint);
        assert!(sp.verify(&keypair.public_key, session_id).is_ok());
    }

    #[test]
    fn test_control_message_legacy_decoder_compat() {
        // A pre-H11 encoder would emit the 5-byte header + msg only.
        // A post-H11 decoder must still parse that legacy form into
        // `signed_payload = None` so we don't break the wire format
        // for fleets that mix old and new servers/clients.
        let legacy = ControlMessage::error(500, "internal");
        let bytes = legacy.to_bytes();
        let decoded = ControlMessage::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.control_type, ControlType::Error);
        assert_eq!(decoded.error_code, Some(500));
        assert!(decoded.signed_payload.is_none());
    }

    #[test]
    fn test_control_message_signed_payload_zero_length_treated_as_none() {
        // An encoder that emits `[..msg..][sig_len = 0]` should be
        // handled gracefully — sig_len = 0 means "no signed payload",
        // not a parse error. This keeps the format extensible.
        let mut bytes = ControlMessage::close().to_bytes();
        bytes.extend_from_slice(&0u16.to_be_bytes());
        let decoded = ControlMessage::from_bytes(&bytes).unwrap();
        assert!(decoded.signed_payload.is_none());
    }

    #[test]
    fn test_control_message_signed_payload_truncated_rejected() {
        // sig_len claims more bytes than are present → truncated.
        let mut bytes = ControlMessage::close().to_bytes();
        bytes.extend_from_slice(&100u16.to_be_bytes()); // claim 100 bytes
        bytes.extend_from_slice(&[0u8; 50]); // only provide 50
        assert!(ControlMessage::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_signed_rebind_ack_cross_keypair_does_not_validate() {
        // Two servers with distinct keypairs. A signature from server A
        // for a session must NOT validate against server B's public key
        // even if the session_id matches. This is the multi-tenant
        // scenario: a malicious server in a federation cannot forge an
        // ack that the client trusts as coming from THE server it
        // handshook with.
        let keypair_a = crate::crypto::MlDsaKeypair::generate();
        let keypair_b = crate::crypto::MlDsaKeypair::generate();
        let session_id = SessionId(0xCAFE_BABE_FACE_F00D);
        let signed_a =
            SignedRebindAckPayload::sign(&keypair_a, session_id, test_endpoint_v4()).unwrap();
        assert!(signed_a.verify(&keypair_b.public_key, session_id).is_err());
    }

    #[test]
    fn test_control_message_packet_too_short() {
        let bytes = vec![1, 2, 3]; // Too short
        let result = ControlMessage::from_bytes(&bytes);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            crate::error::ProtocolError::PacketTooShort { .. }
        ));
    }

    #[test]
    fn test_keepalive_message_zero_sequence() {
        let msg = KeepaliveMessage { sequence: 0 };
        let bytes = msg.to_bytes();
        let decoded = KeepaliveMessage::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.sequence, 0);
    }

    #[test]
    fn test_keepalive_message_max_sequence() {
        let msg = KeepaliveMessage { sequence: u32::MAX };
        let bytes = msg.to_bytes();
        let decoded = KeepaliveMessage::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.sequence, u32::MAX);
    }

    #[test]
    fn test_keepalive_message_too_short() {
        let bytes = vec![1, 2, 3]; // Too short for u64
        let result = KeepaliveMessage::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_keepalive_reply_message_zero_values() {
        let msg = KeepaliveReplyMessage {
            sequence: 0,
            server_timestamp: 0,
        };
        let bytes = msg.to_bytes();
        let decoded = KeepaliveReplyMessage::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.sequence, 0);
        assert_eq!(decoded.server_timestamp, 0);
    }

    #[test]
    fn test_keepalive_reply_message_max_values() {
        let msg = KeepaliveReplyMessage {
            sequence: u32::MAX,
            server_timestamp: u64::MAX,
        };
        let bytes = msg.to_bytes();
        let decoded = KeepaliveReplyMessage::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.sequence, u32::MAX);
        assert_eq!(decoded.server_timestamp, u64::MAX);
    }

    #[test]
    fn test_keepalive_reply_message_too_short() {
        let bytes = vec![1, 2, 3, 4, 5, 6, 7]; // Too short for 2 x u64
        let result = KeepaliveReplyMessage::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_rekey_message_too_short() {
        let bytes = vec![1, 2, 3]; // Way too short
        let result = RekeyMessage::from_bytes(&bytes);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            crate::error::ProtocolError::PacketTooShort { .. }
        ));
    }

    #[test]
    fn test_rekey_response_too_short() {
        let bytes = vec![1, 2, 3]; // Way too short
        let result = RekeyResponse::from_bytes(&bytes);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            crate::error::ProtocolError::PacketTooShort { .. }
        ));
    }

    #[test]
    fn test_rekey_response_rejects_wrong_level_sizes() {
        use crate::crypto::MlDsaKeypair;

        let (_, client_pk) = HybridKem::generate_keypair().unwrap();
        let (_, ciphertext) = HybridKem::encapsulate(&client_pk).unwrap();
        let signature = MlDsaKeypair::generate().sign(b"level3").unwrap();

        let response = RekeyResponse {
            server_ciphertext: ciphertext,
            signature,
            server_random: [0x11u8; 32],
            new_key_id: 1,
            key_confirmation: [0x22u8; 32],
            kdf_timestamp: 42,
            session_id: SessionId::generate(),
        };

        // Encoded with default Level3 wire sizes
        let bytes = response.to_bytes();

        // Decoding as Level5 must fail (expects bigger ct/sig fields)
        let result = RekeyResponse::from_bytes_with_level(&bytes, SecurityLevel::Level5);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            crate::error::ProtocolError::PacketTooShort { .. }
        ));
    }

    #[test]
    fn test_rekey_response_level5_roundtrip_with_explicit_level() {
        use crate::crypto::MlDsaKeypair;

        let (client_sk, client_pk) =
            HybridKem::generate_keypair_with_level(SecurityLevel::Level5).unwrap();
        let (_, ciphertext) = HybridKem::encapsulate(&client_pk).unwrap();

        let keypair = MlDsaKeypair::generate_with_level(SecurityLevel::Level5);
        let signature = keypair.sign(b"test data level5").unwrap();

        let response = RekeyResponse {
            server_ciphertext: ciphertext,
            signature,
            server_random: [0x52u8; 32],
            new_key_id: 7,
            key_confirmation: [0xABu8; 32],
            kdf_timestamp: 1_111_222_333,
            session_id: SessionId::generate(),
        };

        let bytes = response.to_bytes();
        let decoded = RekeyResponse::from_bytes_with_level(&bytes, SecurityLevel::Level5).unwrap();

        assert_eq!(response.server_random, decoded.server_random);
        assert_eq!(response.new_key_id, decoded.new_key_id);
        assert_eq!(response.kdf_timestamp, decoded.kdf_timestamp);
        assert_eq!(response.session_id, decoded.session_id);

        let _ = HybridKem::decapsulate(&client_sk, &decoded.server_ciphertext).unwrap();
    }

    #[test]
    fn test_cookie_request_too_short() {
        let bytes = vec![1, 2, 3]; // Too short
        let result = CookieRequest::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_cookie_request_timestamp() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let client_addr = "127.0.0.1:1234".parse().unwrap();
        let request = CookieRequest::new(12, &client_addr);

        // Timestamp should be recent (within last second)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(request.timestamp <= now);
        assert!(request.timestamp >= now - 1);

        // Fresh cookie should not be expired
        assert!(!request.is_expired(60));
        assert!(!request.is_expired_default());
    }

    #[test]
    fn test_cookie_request_is_expired() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let client_addr = "127.0.0.1:1234".parse().unwrap();
        let mut request = CookieRequest::new(12, &client_addr);

        // Fresh cookie is not expired
        assert!(!request.is_expired(60));

        // Simulate an old cookie by setting timestamp to 100 seconds ago
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        request.timestamp = now - 100;

        // Should be expired with 60 second max age
        assert!(request.is_expired(60));
        assert!(request.is_expired_default());

        // Should not be expired with 120 second max age
        assert!(!request.is_expired(120));
    }

    #[test]
    fn test_cookie_request_future_timestamp_rejected() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let client_addr = "127.0.0.1:1234".parse().unwrap();
        let mut request = CookieRequest::new(12, &client_addr);

        // Set timestamp 10 seconds in the future (beyond 5 second tolerance)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        request.timestamp = now + 10;

        // Should be considered expired (future timestamp = clock skew attack)
        assert!(request.is_expired(60));
    }

    #[test]
    fn test_cookie_request_timestamp_roundtrip() {
        let client_addr = "127.0.0.1:1234".parse().unwrap();
        let request = CookieRequest::new(12, &client_addr);

        let bytes = request.to_bytes();
        assert_eq!(bytes.len(), CookieRequest::SIZE);

        let decoded = CookieRequest::from_bytes(&bytes).unwrap();
        assert_eq!(request.timestamp, decoded.timestamp);
    }

    #[test]
    fn test_cookie_reply_too_short() {
        let bytes = vec![1, 2, 3]; // Too short
        let result = CookieReply::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_tunnel_config_ipv4_only() {
        let config = TunnelConfig {
            client_ipv4: [10, 0, 0, 100],
            gateway_ipv4: [10, 0, 0, 1],
            netmask_ipv4: [255, 255, 255, 0],
            dns_ipv4: vec![[8, 8, 8, 8]],
            client_ipv6: None,
            prefix_len_ipv6: None,
            gateway_ipv6: None,
            dns_ipv6: vec![],
            mtu: 1420,
        };

        let bytes = config.to_bytes();
        let decoded = TunnelConfig::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.client_ipv4, config.client_ipv4);
        assert_eq!(decoded.gateway_ipv4, config.gateway_ipv4);
        assert_eq!(decoded.netmask_ipv4, config.netmask_ipv4);
        assert_eq!(decoded.dns_ipv4.len(), 1);
        assert!(decoded.client_ipv6.is_none());
        assert_eq!(decoded.mtu, 1420);
    }

    #[test]
    fn test_tunnel_config_max_dns_servers() {
        let mut dns_ipv4 = Vec::new();
        for i in 0..MAX_DNS_SERVERS {
            dns_ipv4.push([8, 8, 8, i as u8]);
        }

        let config = TunnelConfig {
            client_ipv4: [10, 0, 0, 100],
            gateway_ipv4: [10, 0, 0, 1],
            netmask_ipv4: [255, 255, 255, 0],
            dns_ipv4: dns_ipv4.clone(),
            client_ipv6: None,
            prefix_len_ipv6: None,
            gateway_ipv6: None,
            dns_ipv6: vec![],
            mtu: 1500,
        };

        let bytes = config.to_bytes();
        let decoded = TunnelConfig::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.dns_ipv4.len(), MAX_DNS_SERVERS);
    }

    #[test]
    fn test_tunnel_config_no_dns_servers() {
        let config = TunnelConfig {
            client_ipv4: [10, 0, 0, 100],
            gateway_ipv4: [10, 0, 0, 1],
            netmask_ipv4: [255, 255, 255, 0],
            dns_ipv4: vec![],
            client_ipv6: None,
            prefix_len_ipv6: None,
            gateway_ipv6: None,
            dns_ipv6: vec![],
            mtu: 1420,
        };

        let bytes = config.to_bytes();
        let decoded = TunnelConfig::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.dns_ipv4.len(), 0);
    }

    #[test]
    fn test_tunnel_config_too_short() {
        let bytes = vec![1, 2, 3, 4]; // Too short
        let result = TunnelConfig::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_handshake_init_from_bytes_too_short() {
        let bytes = vec![0u8; 10]; // Too short
        let result = HandshakeInit::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_handshake_init_exact_min_size() {
        // Test with exactly the minimum size (no extra bytes)
        // Format: [security_level (1 byte)] [client_ephemeral_pk (1216 bytes for Level3)]
        //         [client_random (32 bytes)] [has_credentials (1 byte)]
        let (_, pk) = HybridKem::generate_keypair().unwrap();
        let init = HandshakeInit::new(pk);

        let bytes = init.to_bytes();
        // 1 byte security level + HybridPublicKey::SIZE + 32 bytes client_random + 1 byte has_credentials
        assert_eq!(bytes.len(), 1 + HybridPublicKey::SIZE + 32 + 1);

        let decoded = HandshakeInit::from_bytes(&bytes).unwrap();
        assert_eq!(
            init.client_ephemeral_pk.x25519.as_bytes(),
            decoded.client_ephemeral_pk.x25519.as_bytes()
        );
        assert_eq!(init.security_level, decoded.security_level);
    }

    #[test]
    fn test_control_message_close() {
        let msg = ControlMessage::close();
        assert_eq!(msg.control_type, ControlType::Close);
        assert!(msg.error_code.is_none());
        assert!(msg.message.is_none());

        let bytes = msg.to_bytes();
        let decoded = ControlMessage::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.control_type, ControlType::Close);
    }

    #[test]
    fn test_control_message_error_zero_code() {
        let msg = ControlMessage::error(0, "Zero error code");
        assert_eq!(msg.error_code, Some(0));

        let bytes = msg.to_bytes();
        let decoded = ControlMessage::from_bytes(&bytes).unwrap();
        // Zero error code is treated as None by from_bytes
        assert_eq!(decoded.error_code, None);
        assert_eq!(decoded.message, Some("Zero error code".to_string()));
    }

    #[test]
    fn test_control_message_error_max_code() {
        let msg = ControlMessage::error(u16::MAX, "Max error code");
        assert_eq!(msg.error_code, Some(u16::MAX));

        let bytes = msg.to_bytes();
        let decoded = ControlMessage::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.error_code, Some(u16::MAX));
    }

    #[test]
    fn test_control_message_empty_string() {
        let msg = ControlMessage::error(404, "");
        let bytes = msg.to_bytes();
        let decoded = ControlMessage::from_bytes(&bytes).unwrap();
        // Empty message is treated as None by from_bytes (msg_len = 0)
        assert_eq!(decoded.message, None);
    }

    #[test]
    fn test_control_message_from_bytes_too_short() {
        let bytes = vec![0u8; 3]; // Too short, needs at least 5 bytes
        let result = ControlMessage::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_control_message_truncated_message() {
        let mut bytes = vec![0u8; 7]; // type(1) + error_code(2) + msg_len(2) + partial message
        bytes[0] = ControlType::Error as u8;
        bytes[1..3].copy_from_slice(&100u16.to_be_bytes());
        bytes[3..5].copy_from_slice(&10u16.to_be_bytes()); // Claims 10 bytes but only 2 provided
        bytes[5] = b'H';
        bytes[6] = b'i';

        let result = ControlMessage::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_rekey_message_from_bytes_too_short() {
        let bytes = vec![0u8; 10]; // Too short
        let result = RekeyMessage::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_tunnel_config_extreme_mtu() {
        let config = TunnelConfig {
            client_ipv4: [192, 168, 1, 100],
            gateway_ipv4: [192, 168, 1, 1],
            netmask_ipv4: [255, 255, 255, 0],
            dns_ipv4: vec![[8, 8, 8, 8]],
            client_ipv6: None,
            prefix_len_ipv6: None,
            gateway_ipv6: None,
            dns_ipv6: vec![],
            mtu: u16::MAX,
        };

        let bytes = config.to_bytes();
        let decoded = TunnelConfig::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.mtu, u16::MAX);
    }

    #[test]
    fn test_tunnel_config_min_mtu() {
        let config = TunnelConfig {
            client_ipv4: [192, 168, 1, 100],
            gateway_ipv4: [192, 168, 1, 1],
            netmask_ipv4: [255, 255, 255, 0],
            dns_ipv4: vec![],
            client_ipv6: None,
            prefix_len_ipv6: None,
            gateway_ipv6: None,
            dns_ipv6: vec![],
            mtu: 576, // IPv4 minimum MTU
        };

        let bytes = config.to_bytes();
        let decoded = TunnelConfig::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.mtu, 576);
    }

    #[test]
    fn test_tunnel_config_ipv6_without_gateway() {
        let client_ipv6 = [0xfd, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

        let config = TunnelConfig {
            client_ipv4: [10, 0, 0, 2],
            gateway_ipv4: [10, 0, 0, 1],
            netmask_ipv4: [255, 255, 255, 0],
            dns_ipv4: vec![],
            client_ipv6: Some(client_ipv6),
            prefix_len_ipv6: Some(64),
            gateway_ipv6: None, // No gateway
            dns_ipv6: vec![],
            mtu: 1400,
        };

        let bytes = config.to_bytes();
        let decoded = TunnelConfig::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.client_ipv6, Some(client_ipv6));
        assert_eq!(decoded.gateway_ipv6, Some([0u8; 16])); // Should be zeros
    }

    #[test]
    fn test_tunnel_config_ipv6_max_dns_servers() {
        let dns_ipv6 = vec![[1u8; 16]; MAX_DNS_SERVERS];

        let config = TunnelConfig {
            client_ipv4: [10, 0, 0, 2],
            gateway_ipv4: [10, 0, 0, 1],
            netmask_ipv4: [255, 255, 255, 0],
            dns_ipv4: vec![],
            client_ipv6: Some([0xfd, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
            prefix_len_ipv6: Some(64),
            gateway_ipv6: Some([0xfd, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            dns_ipv6,
            mtu: 1400,
        };

        let bytes = config.to_bytes();
        let decoded = TunnelConfig::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.dns_ipv6.len(), MAX_DNS_SERVERS);
    }

    // ========== Identity Hiding (EncryptedHandshakeInit) Tests ==========

    #[test]
    fn test_encrypted_handshake_init_roundtrip_level3() {
        // Generate server's static KEM keypair (for identity hiding)
        let (server_kem_sk, server_kem_pk) = HybridKem::generate_keypair().unwrap();

        // Generate client's ephemeral keypair
        let (_, client_pk) = HybridKem::generate_keypair().unwrap();
        let inner_init = HandshakeInit::new(client_pk);

        // Encrypt the handshake init
        let encrypted = EncryptedHandshakeInit::encrypt(&inner_init, &server_kem_pk).unwrap();

        // Verify the encrypted message has correct security level
        assert_eq!(encrypted.security_level, SecurityLevel::Level3);

        // Server decrypts
        let decrypted = encrypted.decrypt(&server_kem_sk).unwrap();

        // Verify roundtrip
        assert_eq!(
            inner_init.client_ephemeral_pk.x25519.as_bytes(),
            decrypted.client_ephemeral_pk.x25519.as_bytes()
        );
        assert_eq!(inner_init.client_random, decrypted.client_random);
        assert_eq!(inner_init.security_level, decrypted.security_level);
    }

    #[test]
    fn test_encrypted_handshake_init_roundtrip_level5() {
        // Generate server's static KEM keypair at Level 5
        let (server_kem_sk, server_kem_pk) =
            HybridKem::generate_keypair_with_level(SecurityLevel::Level5).unwrap();

        // Generate client's ephemeral keypair at Level 5
        let (_, client_pk) = HybridKem::generate_keypair_with_level(SecurityLevel::Level5).unwrap();
        let inner_init = HandshakeInit::with_security_level(client_pk, SecurityLevel::Level5);

        // Encrypt the handshake init
        let encrypted = EncryptedHandshakeInit::encrypt(&inner_init, &server_kem_pk).unwrap();

        // Verify the encrypted message has correct security level
        assert_eq!(encrypted.security_level, SecurityLevel::Level5);

        // Server decrypts
        let decrypted = encrypted.decrypt(&server_kem_sk).unwrap();

        // Verify roundtrip
        assert_eq!(
            inner_init.client_ephemeral_pk.x25519.as_bytes(),
            decrypted.client_ephemeral_pk.x25519.as_bytes()
        );
        assert_eq!(inner_init.client_random, decrypted.client_random);
        assert_eq!(inner_init.security_level, decrypted.security_level);
    }

    #[test]
    fn test_encrypted_handshake_init_serialization() {
        let (server_kem_sk, server_kem_pk) = HybridKem::generate_keypair().unwrap();
        let (_, client_pk) = HybridKem::generate_keypair().unwrap();
        let inner_init = HandshakeInit::new(client_pk);

        let encrypted = EncryptedHandshakeInit::encrypt(&inner_init, &server_kem_pk).unwrap();

        // Serialize
        let bytes = encrypted.to_bytes();

        // Deserialize
        let recovered = EncryptedHandshakeInit::from_bytes(&bytes).unwrap();

        // Decrypt and verify
        let decrypted = recovered.decrypt(&server_kem_sk).unwrap();
        assert_eq!(inner_init.client_random, decrypted.client_random);
    }

    #[test]
    fn test_encrypted_handshake_init_wrong_key_fails() {
        let (_, server_kem_pk) = HybridKem::generate_keypair().unwrap();
        let (wrong_sk, _) = HybridKem::generate_keypair().unwrap(); // Different keypair

        let (_, client_pk) = HybridKem::generate_keypair().unwrap();
        let inner_init = HandshakeInit::new(client_pk);

        let encrypted = EncryptedHandshakeInit::encrypt(&inner_init, &server_kem_pk).unwrap();

        // Decryption with wrong key should fail
        let result = encrypted.decrypt(&wrong_sk);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_handshake_init_tampered_ciphertext_fails() {
        let (server_kem_sk, server_kem_pk) = HybridKem::generate_keypair().unwrap();
        let (_, client_pk) = HybridKem::generate_keypair().unwrap();
        let inner_init = HandshakeInit::new(client_pk);

        let mut encrypted = EncryptedHandshakeInit::encrypt(&inner_init, &server_kem_pk).unwrap();

        // Tamper with the encrypted payload
        if !encrypted.encrypted_payload.is_empty() {
            encrypted.encrypted_payload[0] ^= 0xFF;
        }

        // Decryption should fail due to authentication
        let result = encrypted.decrypt(&server_kem_sk);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_handshake_init_unique_ciphertexts() {
        // Each encryption should produce different ciphertext (due to random KEM)
        let (_, server_kem_pk) = HybridKem::generate_keypair().unwrap();
        let (_, client_pk) = HybridKem::generate_keypair().unwrap();
        let inner_init = HandshakeInit::new(client_pk);

        let encrypted1 = EncryptedHandshakeInit::encrypt(&inner_init, &server_kem_pk).unwrap();
        let encrypted2 = EncryptedHandshakeInit::encrypt(&inner_init, &server_kem_pk).unwrap();

        // KEM ciphertexts should be different (randomized)
        assert_ne!(
            encrypted1.encapsulation_ciphertext.to_bytes(),
            encrypted2.encapsulation_ciphertext.to_bytes()
        );

        // Encrypted payloads should also be different (different derived keys)
        assert_ne!(encrypted1.encrypted_payload, encrypted2.encrypted_payload);
    }

    #[test]
    fn test_encrypted_handshake_init_distinct_inner_produce_distinct_kem_ct() {
        // IDENTITY-HIDING INVARIANT (regression guard).
        //
        // The AEAD nonce used to seal `EncryptedHandshakeInit` is derived
        // as `SHA-256(KEM_ciphertext)[..12]` (see `build_identity_hiding_
        // nonce_from_ct` / the doc comment near line 135). This is only
        // safe as long as a given KEM ciphertext is used to seal EXACTLY
        // ONE inner plaintext: if `EncryptedHandshakeInit::encrypt` ever
        // started reusing the KEM ciphertext while varying the inner
        // init (e.g. adding a retry counter), we would immediately hit
        // AES-GCM nonce reuse — a catastrophic failure.
        //
        // The safety invariant is: whenever the inner `HandshakeInit`
        // differs between two calls, the outer KEM ciphertext MUST
        // also differ. The current implementation delivers this for free
        // because `encrypt()` always calls `HybridKem::encapsulate` with
        // fresh randomness. This test enforces the invariant so any
        // future refactor that accidentally breaks it (for instance by
        // caching the KEM output, or by accepting a KEM ciphertext
        // parameter) fails loudly at CI time.
        let (_, server_kem_pk) = HybridKem::generate_keypair().unwrap();

        let (_, client_pk_a) = HybridKem::generate_keypair().unwrap();
        let (_, client_pk_b) = HybridKem::generate_keypair().unwrap();
        let init_a = HandshakeInit::new(client_pk_a);
        let mut init_b = HandshakeInit::new(client_pk_b);
        // Also perturb a non-keypair field so we cover "only metadata
        // changed" refactors, not just "client key changed".
        init_b.client_random = [0xAAu8; 32];

        let enc_a = EncryptedHandshakeInit::encrypt(&init_a, &server_kem_pk).unwrap();
        let enc_b = EncryptedHandshakeInit::encrypt(&init_b, &server_kem_pk).unwrap();

        assert_ne!(
            enc_a.encapsulation_ciphertext.to_bytes(),
            enc_b.encapsulation_ciphertext.to_bytes(),
            "Identity-hiding invariant broken: distinct inner HandshakeInit \
             values produced the SAME KEM ciphertext. This would cause \
             AES-GCM nonce reuse because the outer nonce is derived from \
             the KEM ciphertext. Do NOT land a refactor that breaks this."
        );
        assert_ne!(enc_a.encrypted_payload, enc_b.encrypted_payload);
    }

    #[test]
    fn test_encrypted_credentials_roundtrip() {
        // Sanity check that encrypt() + decrypt() agree on a happy path.
        // Without this baseline test, a regression that breaks the
        // serializer or AAD binding would also break the nonce-uniqueness
        // tests below — and we'd lose the ability to localise the fault.
        let (server_kem_sk, server_kem_pk) = HybridKem::generate_keypair().unwrap();
        let username = "alice";
        let password = "S3curePass!";

        let encrypted = EncryptedCredentials::encrypt(username, password, &server_kem_pk).unwrap();
        let decrypted = encrypted.decrypt(&server_kem_sk).unwrap();

        assert_eq!(decrypted.username, username);
        assert_eq!(decrypted.password.as_str(), password);
    }

    #[test]
    fn test_encrypted_credentials_unique_ciphertexts() {
        // Each `encrypt()` call must derive a fresh KEM ciphertext via
        // `HybridKem::encapsulate`. Two encryptions of the SAME plaintext
        // therefore produce different KEM ciphertexts and (because the
        // key derivation, the AEAD nonce, and the AAD are all bound to
        // the KEM ciphertext) different encrypted payloads. This is the
        // direct counterpart of `test_encrypted_handshake_init_unique_ciphertexts`.
        let (_, server_kem_pk) = HybridKem::generate_keypair().unwrap();

        let enc_a = EncryptedCredentials::encrypt("alice", "pwd", &server_kem_pk).unwrap();
        let enc_b = EncryptedCredentials::encrypt("alice", "pwd", &server_kem_pk).unwrap();

        assert_ne!(
            enc_a.ciphertext.to_bytes(),
            enc_b.ciphertext.to_bytes(),
            "EncryptedCredentials::encrypt produced the same KEM ciphertext \
             twice for the same plaintext — KEM is not properly randomised"
        );
        assert_ne!(enc_a.encrypted_payload, enc_b.encrypted_payload);
    }

    #[test]
    fn test_encrypted_credentials_distinct_inner_produce_distinct_kem_ct() {
        // CRED-NONCE INVARIANT (regression guard).
        //
        // The AES-GCM nonce sealing `EncryptedCredentials` is derived
        // as `SHA-256(KEM_ciphertext)[..12]`. This is safe ONLY as
        // long as a given KEM ciphertext is used to seal EXACTLY one
        // (username, password) plaintext: if `encrypt()` ever started
        // reusing the KEM ciphertext while varying the inner plaintext
        // (e.g. by accepting a precomputed ciphertext, by caching the
        // KEM output for "performance", or by being driven from a
        // deterministic test seed), we would immediately hit AES-GCM
        // nonce reuse — a CATASTROPHIC failure that yields full
        // GHASH key recovery and credential disclosure.
        //
        // The current implementation upholds the invariant for free
        // because every `encrypt()` call invokes
        // `HybridKem::encapsulate` with fresh randomness from `OsRng`
        // (see `crypto/kem.rs`). This test enforces the invariant at
        // CI time so any refactor that breaks it fails loudly here
        // instead of silently in production.
        let (_, server_kem_pk) = HybridKem::generate_keypair().unwrap();

        let enc_a = EncryptedCredentials::encrypt("alice", "secretA", &server_kem_pk).unwrap();
        let enc_b = EncryptedCredentials::encrypt("alice", "secretB", &server_kem_pk).unwrap();
        let enc_c = EncryptedCredentials::encrypt("bob", "secretA", &server_kem_pk).unwrap();

        assert_ne!(
            enc_a.ciphertext.to_bytes(),
            enc_b.ciphertext.to_bytes(),
            "CRED nonce invariant broken: same username + different password \
             produced the SAME KEM ciphertext, which would cause AES-GCM nonce \
             reuse. Do NOT land a refactor that breaks this."
        );
        assert_ne!(
            enc_a.ciphertext.to_bytes(),
            enc_c.ciphertext.to_bytes(),
            "CRED nonce invariant broken: same password + different username \
             produced the SAME KEM ciphertext."
        );
        // Sanity: the encrypted payloads must also differ.
        assert_ne!(enc_a.encrypted_payload, enc_b.encrypted_payload);
        assert_ne!(enc_a.encrypted_payload, enc_c.encrypted_payload);
    }

    #[test]
    fn test_encrypted_handshake_init_from_bytes_too_short() {
        let bytes = vec![0u8; 2]; // Too short
        let result = EncryptedHandshakeInit::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_handshake_init_invalid_security_level() {
        let mut bytes = vec![99u8]; // Invalid security level
        bytes.extend_from_slice(&100u16.to_be_bytes()); // ciphertext len
        bytes.extend_from_slice(&[0u8; 200]); // fake data

        let result = EncryptedHandshakeInit::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_handshake_init_truncated_ciphertext_payload() {
        let mut bytes = vec![SecurityLevel::Level3.as_u8()];
        bytes.extend_from_slice(&100u16.to_be_bytes());
        // Provide fewer bytes than advertised ciphertext length.
        bytes.extend_from_slice(&[0u8; 20]);

        let result = EncryptedHandshakeInit::from_bytes(&bytes);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            crate::error::ProtocolError::PacketTooShort { .. }
        ));
    }

    #[test]
    fn test_encrypted_handshake_init_empty_after_ciphertext_rejected() {
        // Valid level + ciphertext length prefix, but missing encrypted payload bytes.
        let mut bytes = vec![SecurityLevel::Level3.as_u8()];
        bytes.extend_from_slice(&32u16.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 32]);

        let result = EncryptedHandshakeInit::from_bytes(&bytes);
        assert!(result.is_err());
    }
}
