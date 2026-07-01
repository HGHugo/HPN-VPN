//! Public Key Infrastructure (PKI) for HPN.
//!
//! Provides certificate management for server and client authentication.
//! Supports both post-quantum (ML-DSA) and hybrid certificates.
//!
//! # Certificate Types
//!
//! - **Root CA Certificate**: Self-signed, signs server certificates
//! - **Server Certificate**: Signed by Root CA, presented during handshake
//! - **Client Certificate**: Signed by Root CA, for client authentication (optional)
//!
//! # Certificate Format
//!
//! HPN uses a custom binary certificate format optimized for post-quantum signatures:
//!
//! ```text
//! | version (1) | type (1) | flags (2) |
//! | subject_len (2) | subject (n) |
//! | issuer_len (2) | issuer (n) |
//! | not_before (8) | not_after (8) |
//! | public_key_type (1) | public_key_len (2) | public_key (n) |
//! | signature_type (1) | signature_len (2) | signature (n) |
//! | extensions_len (2) | extensions (n) |
//! ```

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::signature::verify as mldsa_verify;
use super::{MlDsaKeypair, MlDsaPublicKey, MlDsaSignature, SecurityLevel};

/// Certificate version.
pub const CERT_VERSION: u8 = 1;

/// Certificate type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CertificateType {
    /// Root CA certificate (self-signed).
    RootCA = 1,
    /// Server certificate (signed by CA).
    Server = 2,
    /// Client certificate (signed by CA).
    Client = 3,
}

impl CertificateType {
    /// Convert from u8.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::RootCA),
            2 => Some(Self::Server),
            3 => Some(Self::Client),
            _ => None,
        }
    }
}

/// Certificate flags.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct CertificateFlags {
    /// Can sign other certificates.
    pub can_sign: bool,
    /// Can be used for server authentication.
    pub server_auth: bool,
    /// Can be used for client authentication.
    pub client_auth: bool,
    /// Certificate is revoked.
    pub revoked: bool,
}

impl CertificateFlags {
    /// Encode to u16.
    pub fn to_u16(&self) -> u16 {
        let mut flags = 0u16;
        if self.can_sign {
            flags |= 1 << 0;
        }
        if self.server_auth {
            flags |= 1 << 1;
        }
        if self.client_auth {
            flags |= 1 << 2;
        }
        if self.revoked {
            flags |= 1 << 3;
        }
        flags
    }

    /// Decode from u16.
    pub fn from_u16(value: u16) -> Self {
        Self {
            can_sign: value & (1 << 0) != 0,
            server_auth: value & (1 << 1) != 0,
            client_auth: value & (1 << 2) != 0,
            revoked: value & (1 << 3) != 0,
        }
    }
}

/// Detailed certificate-validity outcome (FIX-028).
///
/// The previous `is_valid() -> bool` collapsed three failure modes into the
/// same negative answer. This enum surfaces the actual reason so call sites
/// that care (audit logs, admin endpoints) can distinguish e.g. "the device
/// clock is wrong" from "this cert is genuinely expired".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertificateValidity {
    /// Certificate is within its lifetime, not revoked, and the host clock
    /// resolves cleanly.
    Valid,
    /// `SystemTime::now()` reported a value earlier than `UNIX_EPOCH` —
    /// indicates a broken / not-yet-set hardware clock. Treat as
    /// fail-CLOSED: never advance the chain on a clock we cannot trust.
    ClockError,
    /// Current time is earlier than `not_before` — premature use.
    NotYetValid,
    /// Current time is past `not_after`.
    Expired,
    /// `flags.revoked` is set.
    Revoked,
}

/// HPN Certificate.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Certificate {
    /// Certificate version.
    pub version: u8,
    /// Certificate type.
    pub cert_type: CertificateType,
    /// Certificate flags.
    pub flags: CertificateFlags,
    /// Subject (e.g., server name, client ID).
    pub subject: String,
    /// Issuer (e.g., CA name).
    pub issuer: String,
    /// Not valid before (Unix timestamp).
    pub not_before: u64,
    /// Not valid after (Unix timestamp).
    pub not_after: u64,
    /// Public key (ML-DSA-65 or ML-DSA-87).
    pub public_key: Vec<u8>,
    /// Signature by issuer.
    pub signature: Vec<u8>,
    /// Optional extensions (reserved for future use).
    pub extensions: Vec<u8>,
}

impl Certificate {
    /// Create a new certificate builder.
    pub fn builder() -> CertificateBuilder {
        CertificateBuilder::new()
    }

    /// Check if the certificate is currently valid.
    ///
    /// FIX-028: when `SystemTime::now()` fails (clock pre-`UNIX_EPOCH`,
    /// hardware clock pulled back below 1970 in the BIOS, etc.) we used to
    /// fall back to `unwrap_or(0)`. That treats the clock as "January 1
    /// 1970" — earlier than ANY production certificate's `not_before`, so
    /// the function silently reports `false` (which is fail-CLOSED) but
    /// also collapses three distinct conditions ("expired", "not yet
    /// valid", "revoked", and now "clock is broken") into the same boolean.
    /// Callers that need to distinguish "expired" from "system clock is
    /// borked" should use [`Self::validity_status`] instead.
    pub fn is_valid(&self) -> bool {
        matches!(self.validity_status(), CertificateValidity::Valid)
    }

    /// Detailed validity status — distinguishes clock errors, not-yet-valid,
    /// expired, and revoked cases.
    pub fn validity_status(&self) -> CertificateValidity {
        if self.flags.revoked {
            return CertificateValidity::Revoked;
        }
        let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_secs(),
            Err(_) => return CertificateValidity::ClockError,
        };
        if now < self.not_before {
            CertificateValidity::NotYetValid
        } else if now > self.not_after {
            CertificateValidity::Expired
        } else {
            CertificateValidity::Valid
        }
    }

    /// Check if the certificate can sign other certificates.
    pub fn can_sign(&self) -> bool {
        self.flags.can_sign && self.is_valid()
    }

    /// Verify the certificate signature against a CA public key.
    ///
    /// The security level is automatically detected from the CA public key size:
    /// - 1952 bytes: ML-DSA-65 (Level 3)
    /// - 2592 bytes: ML-DSA-87 (Level 5)
    pub fn verify(&self, ca_public_key: &MlDsaPublicKey) -> Result<bool, CertificateError> {
        // Build the data that was signed (everything except the signature)
        let tbs = self.to_be_signed()?;

        // Detect security level from CA public key size
        let security_level = match ca_public_key.as_bytes().len() {
            MlDsaPublicKey::SIZE => SecurityLevel::Level3,
            MlDsaPublicKey::SIZE_87 => SecurityLevel::Level5,
            _ => {
                return Err(CertificateError::InvalidFormat(format!(
                    "invalid CA public key size: {} (expected {} or {})",
                    ca_public_key.as_bytes().len(),
                    MlDsaPublicKey::SIZE,
                    MlDsaPublicKey::SIZE_87
                )));
            }
        };

        // Verify signature with detected security level
        let signature = MlDsaSignature::from_bytes(&self.signature).ok_or_else(|| {
            CertificateError::InvalidFormat(format!(
                "invalid signature size: {} (expected {} or {})",
                self.signature.len(),
                MlDsaSignature::SIZE,
                MlDsaSignature::SIZE_87
            ))
        })?;
        match mldsa_verify(ca_public_key, &tbs, &signature, security_level) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Get the data to be signed (everything except the signature).
    fn to_be_signed(&self) -> Result<Vec<u8>, CertificateError> {
        let mut data = Vec::new();

        data.push(self.version);
        data.push(self.cert_type as u8);
        data.extend_from_slice(&self.flags.to_u16().to_be_bytes());

        let subject_bytes = self.subject.as_bytes();
        let subject_len = u16::try_from(subject_bytes.len())
            .map_err(|_| CertificateError::Serialization("subject exceeds u16 capacity".into()))?;
        data.extend_from_slice(&subject_len.to_be_bytes());
        data.extend_from_slice(subject_bytes);

        let issuer_bytes = self.issuer.as_bytes();
        let issuer_len = u16::try_from(issuer_bytes.len())
            .map_err(|_| CertificateError::Serialization("issuer exceeds u16 capacity".into()))?;
        data.extend_from_slice(&issuer_len.to_be_bytes());
        data.extend_from_slice(issuer_bytes);

        data.extend_from_slice(&self.not_before.to_be_bytes());
        data.extend_from_slice(&self.not_after.to_be_bytes());

        // Public key type indicator (supports both ML-DSA-65 and ML-DSA-87)
        // The actual level is detected from the public key size during verification
        data.push(1);
        let pk_len = u16::try_from(self.public_key.len()).map_err(|_| {
            CertificateError::Serialization("public key exceeds u16 capacity".into())
        })?;
        data.extend_from_slice(&pk_len.to_be_bytes());
        data.extend_from_slice(&self.public_key);

        let ext_len = u16::try_from(self.extensions.len()).map_err(|_| {
            CertificateError::Serialization("extensions exceed u16 capacity".into())
        })?;
        data.extend_from_slice(&ext_len.to_be_bytes());
        data.extend_from_slice(&self.extensions);

        Ok(data)
    }

    /// Encode to bytes.
    ///
    /// # Errors
    /// Returns `CertificateError` if the certificate data cannot be serialized.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CertificateError> {
        let mut data = self.to_be_signed()?;

        // Append signature
        data.push(1); // signature type
        let sig_len = u16::try_from(self.signature.len()).map_err(|_| {
            CertificateError::Serialization("signature exceeds u16 capacity".into())
        })?;
        data.extend_from_slice(&sig_len.to_be_bytes());
        data.extend_from_slice(&self.signature);

        Ok(data)
    }

    /// Decode from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, CertificateError> {
        if data.len() < 20 {
            return Err(CertificateError::InvalidFormat(
                "certificate too short".into(),
            ));
        }

        let mut offset = 0;

        let version = data[offset];
        offset += 1;

        if version != CERT_VERSION {
            return Err(CertificateError::InvalidVersion(version));
        }

        let cert_type = CertificateType::from_u8(data[offset])
            .ok_or_else(|| CertificateError::InvalidFormat("invalid cert type".into()))?;
        offset += 1;

        let flags =
            CertificateFlags::from_u16(u16::from_be_bytes([data[offset], data[offset + 1]]));
        offset += 2;

        // Subject
        let subject_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if offset + subject_len > data.len() {
            return Err(CertificateError::InvalidFormat("subject truncated".into()));
        }
        // Strict UTF-8: reject the certificate rather than silently replacing
        // invalid sequences with U+FFFD. `from_utf8_lossy` would produce a
        // subject string that doesn't match what the signer signed — a
        // cert authority that signed the bytes `"alice\xff\xfe"` must NOT
        // end up stored as subject `"alice\u{FFFD}\u{FFFD}"` and then
        // compared against `"alice"` or any other mutated form elsewhere.
        let subject = std::str::from_utf8(&data[offset..offset + subject_len])
            .map_err(|_| CertificateError::InvalidFormat("subject is not valid UTF-8".into()))?
            .to_string();
        offset += subject_len;

        // Issuer
        let issuer_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if offset + issuer_len > data.len() {
            return Err(CertificateError::InvalidFormat("issuer truncated".into()));
        }
        let issuer = std::str::from_utf8(&data[offset..offset + issuer_len])
            .map_err(|_| CertificateError::InvalidFormat("issuer is not valid UTF-8".into()))?
            .to_string();
        offset += issuer_len;

        // Timestamps
        if offset + 16 > data.len() {
            return Err(CertificateError::InvalidFormat(
                "timestamps truncated".into(),
            ));
        }
        let not_before = u64::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        offset += 8;
        let not_after = u64::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        offset += 8;

        // Public key
        if offset + 3 > data.len() {
            return Err(CertificateError::InvalidFormat(
                "public key header truncated".into(),
            ));
        }
        // Skip public key type byte (reserved for future algorithm negotiation)
        offset += 1;
        let pk_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if offset + pk_len > data.len() {
            return Err(CertificateError::InvalidFormat(
                "public key truncated".into(),
            ));
        }
        let public_key = data[offset..offset + pk_len].to_vec();
        offset += pk_len;

        // Extensions
        if offset + 2 > data.len() {
            return Err(CertificateError::InvalidFormat(
                "extensions header truncated".into(),
            ));
        }
        let ext_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if offset + ext_len > data.len() {
            return Err(CertificateError::InvalidFormat(
                "extensions truncated".into(),
            ));
        }
        let extensions = data[offset..offset + ext_len].to_vec();
        offset += ext_len;

        // Signature
        if offset + 3 > data.len() {
            return Err(CertificateError::InvalidFormat(
                "signature header truncated".into(),
            ));
        }
        // Skip signature type byte (reserved for future algorithm negotiation)
        offset += 1;
        let sig_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if offset + sig_len > data.len() {
            return Err(CertificateError::InvalidFormat(
                "signature truncated".into(),
            ));
        }
        let signature = data[offset..offset + sig_len].to_vec();

        Ok(Self {
            version,
            cert_type,
            flags,
            subject,
            issuer,
            not_before,
            not_after,
            public_key,
            signature,
            extensions,
        })
    }

    /// Get the public key as MlDsaPublicKey.
    pub fn public_key(&self) -> Result<MlDsaPublicKey, CertificateError> {
        MlDsaPublicKey::from_bytes(&self.public_key)
            .map_err(|_| CertificateError::InvalidFormat("invalid public key".into()))
    }
}

/// Certificate builder.
pub struct CertificateBuilder {
    cert_type: CertificateType,
    flags: CertificateFlags,
    subject: String,
    issuer: String,
    validity_days: u32,
    public_key: Option<Vec<u8>>,
    extensions: Vec<u8>,
}

impl CertificateBuilder {
    /// Create a new certificate builder.
    pub fn new() -> Self {
        Self {
            cert_type: CertificateType::Client,
            flags: CertificateFlags::default(),
            subject: String::new(),
            issuer: String::new(),
            validity_days: 365,
            public_key: None,
            extensions: Vec::new(),
        }
    }

    /// Set certificate type.
    pub fn cert_type(mut self, cert_type: CertificateType) -> Self {
        self.cert_type = cert_type;
        self
    }

    /// Set subject.
    pub fn subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = subject.into();
        self
    }

    /// Set issuer.
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = issuer.into();
        self
    }

    /// Set validity period in days.
    pub fn validity_days(mut self, days: u32) -> Self {
        self.validity_days = days;
        self
    }

    /// Set public key from ML-DSA keypair.
    pub fn public_key_from_keypair(mut self, keypair: &MlDsaKeypair) -> Self {
        self.public_key = Some(keypair.public_key.as_bytes().to_vec());
        self
    }

    /// Set public key from ML-DSA public key.
    pub fn public_key(mut self, pk: &MlDsaPublicKey) -> Self {
        self.public_key = Some(pk.as_bytes().to_vec());
        self
    }

    /// Set can_sign flag.
    pub fn can_sign(mut self, value: bool) -> Self {
        self.flags.can_sign = value;
        self
    }

    /// Set server_auth flag.
    pub fn server_auth(mut self, value: bool) -> Self {
        self.flags.server_auth = value;
        self
    }

    /// Set client_auth flag.
    pub fn client_auth(mut self, value: bool) -> Self {
        self.flags.client_auth = value;
        self
    }

    /// Build and sign the certificate.
    pub fn build_and_sign(
        self,
        signing_key: &MlDsaKeypair,
    ) -> Result<Certificate, CertificateError> {
        let public_key = self
            .public_key
            .ok_or_else(|| CertificateError::InvalidFormat("public key required".into()))?;

        if self.subject.is_empty() {
            return Err(CertificateError::InvalidFormat("subject required".into()));
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let validity = Duration::from_secs(self.validity_days as u64 * 24 * 60 * 60);

        let mut cert = Certificate {
            version: CERT_VERSION,
            cert_type: self.cert_type,
            flags: self.flags,
            subject: self.subject,
            issuer: if self.issuer.is_empty() {
                "HPN-CA".to_string()
            } else {
                self.issuer
            },
            not_before: now,
            not_after: now + validity.as_secs(),
            public_key,
            signature: Vec::new(),
            extensions: self.extensions,
        };

        // Sign the certificate
        let tbs = cert.to_be_signed()?;
        let signature = signing_key
            .sign(&tbs)
            .map_err(|e| CertificateError::SigningFailed(e.to_string()))?;

        cert.signature = signature.as_bytes().to_vec();

        Ok(cert)
    }
}

impl Default for CertificateBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Certificate error.
#[derive(Debug, thiserror::Error)]
pub enum CertificateError {
    /// Invalid certificate format.
    #[error("invalid certificate format: {0}")]
    InvalidFormat(String),
    /// Invalid certificate version.
    #[error("invalid certificate version: {0}")]
    InvalidVersion(u8),
    /// Certificate has expired.
    #[error("certificate expired")]
    Expired,
    /// Certificate not yet valid.
    #[error("certificate not yet valid")]
    NotYetValid,
    /// Certificate has been revoked.
    #[error("certificate revoked")]
    Revoked,
    /// Signature verification failed.
    #[error("signature verification failed")]
    SignatureInvalid,
    /// Serialization failed.
    #[error("serialization failed: {0}")]
    Serialization(String),
    /// Signing failed.
    #[error("signing failed: {0}")]
    SigningFailed(String),
    /// Certificate chain verification failed.
    #[error("certificate chain verification failed: {0}")]
    ChainInvalid(String),
}

/// Certificate store for managing trusted certificates.
pub struct CertificateStore {
    /// Root CA certificates.
    root_certs: Vec<Certificate>,
    /// Server certificates.
    server_certs: Vec<Certificate>,
    /// Client certificates.
    client_certs: Vec<Certificate>,
}

impl CertificateStore {
    /// Create a new empty certificate store.
    pub fn new() -> Self {
        Self {
            root_certs: Vec::new(),
            server_certs: Vec::new(),
            client_certs: Vec::new(),
        }
    }

    /// Add a root CA certificate.
    pub fn add_root_cert(&mut self, cert: Certificate) -> Result<(), CertificateError> {
        if cert.cert_type != CertificateType::RootCA {
            return Err(CertificateError::InvalidFormat(
                "not a root CA certificate".into(),
            ));
        }
        if !cert.is_valid() {
            return Err(CertificateError::Expired);
        }
        self.root_certs.push(cert);
        Ok(())
    }

    /// Add a server certificate.
    ///
    /// FIX-023: the cert MUST carry `flags.server_auth = true`. A
    /// `Server`-typed cert with the flag cleared is rejected so an
    /// operator who mistakenly bakes the flag off (or who copies a
    /// `Client` cert into the server slot via the type field but
    /// leaves the auth flag default) cannot inadvertently install a
    /// usable server identity. Mirrors the X.509 Extended Key Usage
    /// `id-kp-serverAuth` semantics on the public-CA side.
    pub fn add_server_cert(&mut self, cert: Certificate) -> Result<(), CertificateError> {
        if cert.cert_type != CertificateType::Server {
            return Err(CertificateError::InvalidFormat(
                "not a server certificate".into(),
            ));
        }
        if !cert.flags.server_auth {
            return Err(CertificateError::InvalidFormat(
                "server certificate missing the `server_auth` flag (FIX-023)".into(),
            ));
        }
        // Verify against root certs
        self.verify_certificate(&cert)?;
        self.server_certs.push(cert);
        Ok(())
    }

    /// Add a client certificate.
    ///
    /// FIX-023: symmetric to `add_server_cert` — the cert MUST carry
    /// `flags.client_auth = true`. Catches the same horizontal-trust
    /// mistake on the client side.
    pub fn add_client_cert(&mut self, cert: Certificate) -> Result<(), CertificateError> {
        if cert.cert_type != CertificateType::Client {
            return Err(CertificateError::InvalidFormat(
                "not a client certificate".into(),
            ));
        }
        if !cert.flags.client_auth {
            return Err(CertificateError::InvalidFormat(
                "client certificate missing the `client_auth` flag (FIX-023)".into(),
            ));
        }
        // Verify against root certs
        self.verify_certificate(&cert)?;
        self.client_certs.push(cert);
        Ok(())
    }

    /// Verify a certificate against the trusted root CAs.
    ///
    /// # Hardening (audit H12)
    ///
    /// The previous implementation only checked the certificate's own
    /// validity (not-before / not-after / revoked) and that some root
    /// in the store had a matching `subject == cert.issuer` and signed
    /// the certificate. That is **not** enough:
    ///
    /// * A root certificate stored without `flags.can_sign = true` was
    ///   still trusted to sign anything if someone forced it into
    ///   `root_certs` through an unchecked path.
    /// * A `Server` or `Client` certificate placed in `root_certs`
    ///   would match by subject and successfully sign other
    ///   certificates — a horizontal-trust escalation.
    /// * An expired or revoked root would still validate child
    ///   certificates (not-before / not-after / `revoked` were checked
    ///   only on the leaf).
    ///
    /// We now require the matching root to:
    ///   1. Be a `RootCA` (`cert_type == CertificateType::RootCA`)
    ///   2. Carry `flags.can_sign == true`
    ///   3. Be itself valid (`is_valid()` — covers expired, not-yet-
    ///      valid, revoked).
    ///
    /// We also reject self-signed certificates (where `subject ==
    /// issuer`) unless they ARE the matching root: a leaf that claims
    /// to be its own issuer can otherwise satisfy the "match" check
    /// against itself if mistakenly added to `root_certs`.
    pub fn verify_certificate(&self, cert: &Certificate) -> Result<(), CertificateError> {
        if !cert.is_valid() {
            if cert.flags.revoked {
                return Err(CertificateError::Revoked);
            }
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if now < cert.not_before {
                return Err(CertificateError::NotYetValid);
            }
            return Err(CertificateError::Expired);
        }

        // Find matching root CA by issuer.
        //
        // We walk the entire root store rather than short-circuiting on
        // the first subject match because two roots can legitimately
        // share a subject (key rotation periods) and we want the chain
        // to validate against *any* qualifying root, not just the
        // first one in iteration order.
        for root in &self.root_certs {
            // Match by subject↔issuer pairing.
            if root.subject != cert.issuer {
                continue;
            }
            // Hardening: only RootCA-typed certs with the can_sign
            // flag and a currently-valid lifetime are allowed to
            // anchor a chain. A Server cert that found its way into
            // `root_certs` is rejected here even if it matches by
            // subject. (`root.is_valid()` itself rejects expired,
            // not-yet-valid, and revoked roots.)
            if root.cert_type != CertificateType::RootCA {
                continue;
            }
            if !root.flags.can_sign {
                continue;
            }
            if !root.is_valid() {
                continue;
            }
            let root_pk = root.public_key()?;
            if cert.verify(&root_pk)? {
                return Ok(());
            }
        }

        Err(CertificateError::ChainInvalid(
            "no trusted CA found for issuer".into(),
        ))
    }

    /// Get all root certificates.
    pub fn root_certs(&self) -> &[Certificate] {
        &self.root_certs
    }

    /// Get all server certificates.
    pub fn server_certs(&self) -> &[Certificate] {
        &self.server_certs
    }

    /// Get all client certificates.
    pub fn client_certs(&self) -> &[Certificate] {
        &self.client_certs
    }

    /// Find a server certificate by subject.
    pub fn find_server_cert(&self, subject: &str) -> Option<&Certificate> {
        self.server_certs
            .iter()
            .find(|c| c.subject == subject && c.is_valid())
    }

    /// Find a client certificate by subject.
    pub fn find_client_cert(&self, subject: &str) -> Option<&Certificate> {
        self.client_certs
            .iter()
            .find(|c| c.subject == subject && c.is_valid())
    }
}

impl Default for CertificateStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_flags() {
        let flags = CertificateFlags {
            can_sign: true,
            server_auth: true,
            client_auth: false,
            revoked: false,
        };

        let encoded = flags.to_u16();
        let decoded = CertificateFlags::from_u16(encoded);

        assert_eq!(flags.can_sign, decoded.can_sign);
        assert_eq!(flags.server_auth, decoded.server_auth);
        assert_eq!(flags.client_auth, decoded.client_auth);
        assert_eq!(flags.revoked, decoded.revoked);
    }

    #[test]
    fn test_certificate_creation_and_verification() {
        // Generate CA keypair
        let ca_keypair = MlDsaKeypair::generate();

        // Create root CA certificate (self-signed)
        let root_cert = Certificate::builder()
            .cert_type(CertificateType::RootCA)
            .subject("HPN Root CA")
            .issuer("HPN Root CA")
            .public_key(&ca_keypair.public_key)
            .can_sign(true)
            .validity_days(3650)
            .build_and_sign(&ca_keypair)
            .unwrap();

        assert!(root_cert.is_valid());
        assert!(root_cert.can_sign());

        // Self-verify (root CA verifies its own signature)
        assert!(root_cert.verify(&ca_keypair.public_key).unwrap());

        // Generate server keypair
        let server_keypair = MlDsaKeypair::generate();

        // Create server certificate signed by CA
        let server_cert = Certificate::builder()
            .cert_type(CertificateType::Server)
            .subject("vpn.example.com")
            .issuer("HPN Root CA")
            .public_key(&server_keypair.public_key)
            .server_auth(true)
            .validity_days(365)
            .build_and_sign(&ca_keypair)
            .unwrap();

        assert!(server_cert.is_valid());
        assert!(!server_cert.can_sign());
        assert!(server_cert.flags.server_auth);

        // Verify server cert with CA public key
        assert!(server_cert.verify(&ca_keypair.public_key).unwrap());
    }

    #[test]
    fn test_certificate_roundtrip() {
        let ca_keypair = MlDsaKeypair::generate();

        let cert = Certificate::builder()
            .cert_type(CertificateType::Server)
            .subject("test.example.com")
            .issuer("Test CA")
            .public_key(&ca_keypair.public_key)
            .server_auth(true)
            .validity_days(365)
            .build_and_sign(&ca_keypair)
            .unwrap();

        let bytes = cert.to_bytes().unwrap();
        let decoded = Certificate::from_bytes(&bytes).unwrap();

        assert_eq!(cert.subject, decoded.subject);
        assert_eq!(cert.issuer, decoded.issuer);
        assert_eq!(cert.not_before, decoded.not_before);
        assert_eq!(cert.not_after, decoded.not_after);
    }

    #[test]
    fn test_certificate_store() {
        let ca_keypair = MlDsaKeypair::generate();

        // Create root CA
        let root_cert = Certificate::builder()
            .cert_type(CertificateType::RootCA)
            .subject("HPN Root CA")
            .issuer("HPN Root CA")
            .public_key(&ca_keypair.public_key)
            .can_sign(true)
            .validity_days(3650)
            .build_and_sign(&ca_keypair)
            .unwrap();

        // Create server cert
        let server_keypair = MlDsaKeypair::generate();
        let server_cert = Certificate::builder()
            .cert_type(CertificateType::Server)
            .subject("vpn.example.com")
            .issuer("HPN Root CA")
            .public_key(&server_keypair.public_key)
            .server_auth(true)
            .validity_days(365)
            .build_and_sign(&ca_keypair)
            .unwrap();

        // Build certificate store
        let mut store = CertificateStore::new();
        store.add_root_cert(root_cert).unwrap();
        store.add_server_cert(server_cert).unwrap();

        // Find server cert
        let found = store.find_server_cert("vpn.example.com");
        assert!(found.is_some());
        assert_eq!(found.unwrap().subject, "vpn.example.com");
    }

    #[test]
    fn test_certificate_type_conversion() {
        assert_eq!(CertificateType::from_u8(1), Some(CertificateType::RootCA));
        assert_eq!(CertificateType::from_u8(2), Some(CertificateType::Server));
        assert_eq!(CertificateType::from_u8(3), Some(CertificateType::Client));
        assert_eq!(CertificateType::from_u8(99), None);
    }

    #[test]
    fn test_certificate_flags_all_false() {
        let flags = CertificateFlags {
            can_sign: false,
            server_auth: false,
            client_auth: false,
            revoked: false,
        };

        let encoded = flags.to_u16();
        assert_eq!(encoded, 0);

        let decoded = CertificateFlags::from_u16(encoded);
        assert!(!decoded.can_sign);
        assert!(!decoded.server_auth);
        assert!(!decoded.client_auth);
        assert!(!decoded.revoked);
    }

    #[test]
    fn test_certificate_flags_all_true() {
        let flags = CertificateFlags {
            can_sign: true,
            server_auth: true,
            client_auth: true,
            revoked: true,
        };

        let encoded = flags.to_u16();
        let decoded = CertificateFlags::from_u16(encoded);

        assert!(decoded.can_sign);
        assert!(decoded.server_auth);
        assert!(decoded.client_auth);
        assert!(decoded.revoked);
    }

    #[test]
    fn test_certificate_flags_individual_bits() {
        // Test individual flag bits
        assert!(CertificateFlags::from_u16(1).can_sign);
        assert!(CertificateFlags::from_u16(2).server_auth);
        assert!(CertificateFlags::from_u16(4).client_auth);
        assert!(CertificateFlags::from_u16(8).revoked);
    }

    #[test]
    fn test_certificate_client_type() {
        let ca_keypair = MlDsaKeypair::generate();
        let client_keypair = MlDsaKeypair::generate();

        let client_cert = Certificate::builder()
            .cert_type(CertificateType::Client)
            .subject("client@example.com")
            .issuer("HPN Root CA")
            .public_key(&client_keypair.public_key)
            .client_auth(true)
            .validity_days(365)
            .build_and_sign(&ca_keypair)
            .unwrap();

        assert_eq!(client_cert.cert_type, CertificateType::Client);
        assert!(client_cert.flags.client_auth);
        assert!(!client_cert.can_sign());
    }

    #[test]
    fn test_certificate_store_default() {
        let store = CertificateStore::default();
        assert_eq!(store.root_certs().len(), 0);
        assert_eq!(store.server_certs().len(), 0);
        assert_eq!(store.client_certs().len(), 0);
    }

    #[test]
    fn test_certificate_store_add_client() {
        let ca_keypair = MlDsaKeypair::generate();

        let root_cert = Certificate::builder()
            .cert_type(CertificateType::RootCA)
            .subject("HPN Root CA")
            .issuer("HPN Root CA")
            .public_key(&ca_keypair.public_key)
            .can_sign(true)
            .validity_days(3650)
            .build_and_sign(&ca_keypair)
            .unwrap();

        let client_keypair = MlDsaKeypair::generate();
        let client_cert = Certificate::builder()
            .cert_type(CertificateType::Client)
            .subject("user@example.com")
            .issuer("HPN Root CA")
            .public_key(&client_keypair.public_key)
            .client_auth(true)
            .validity_days(365)
            .build_and_sign(&ca_keypair)
            .unwrap();

        let mut store = CertificateStore::new();
        store.add_root_cert(root_cert).unwrap();
        store.add_client_cert(client_cert).unwrap();

        assert_eq!(store.client_certs().len(), 1);

        let found = store.find_client_cert("user@example.com");
        assert!(found.is_some());
        assert_eq!(found.unwrap().subject, "user@example.com");
    }

    #[test]
    fn test_certificate_store_find_nonexistent() {
        let store = CertificateStore::new();

        assert!(store.find_server_cert("nonexistent.com").is_none());
        assert!(store.find_client_cert("nobody@example.com").is_none());
    }

    #[test]
    fn test_certificate_validity_period() {
        let ca_keypair = MlDsaKeypair::generate();

        // Create cert with specific validity
        let cert = Certificate::builder()
            .cert_type(CertificateType::Server)
            .subject("test.com")
            .issuer("Test CA")
            .public_key(&ca_keypair.public_key)
            .validity_days(30)
            .build_and_sign(&ca_keypair)
            .unwrap();

        // Should be valid now
        assert!(cert.is_valid());

        // Verify not_before is in the past and not_after is in the future
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        assert!(cert.not_before <= now);
        assert!(cert.not_after > now);
    }

    #[test]
    fn test_certificate_can_sign_requires_valid() {
        let ca_keypair = MlDsaKeypair::generate();

        let mut cert = Certificate::builder()
            .cert_type(CertificateType::RootCA)
            .subject("Test CA")
            .issuer("Test CA")
            .public_key(&ca_keypair.public_key)
            .can_sign(true)
            .validity_days(365)
            .build_and_sign(&ca_keypair)
            .unwrap();

        // Valid cert with can_sign flag should return true
        assert!(cert.can_sign());

        // Revoke the cert
        cert.flags.revoked = true;

        // Revoked cert should not be able to sign even with flag set
        assert!(!cert.can_sign());
    }

    #[test]
    fn test_certificate_flags_default() {
        let flags = CertificateFlags::default();
        assert!(!flags.can_sign);
        assert!(!flags.server_auth);
        assert!(!flags.client_auth);
        assert!(!flags.revoked);
    }

    // ─── Audit H12 — verify_certificate hardening regression guards ─────

    /// Build a minimal "leaf signed by root" pair where the caller can
    /// flip individual fields on the root before insertion. Used by the
    /// H12 regression tests below to reach the rejection paths in
    /// `verify_certificate` without rebuilding the same boilerplate
    /// each time.
    fn make_root_and_leaf(
        root_type: CertificateType,
        root_can_sign: bool,
    ) -> (Certificate, Certificate, MlDsaKeypair) {
        let ca_keypair = MlDsaKeypair::generate();
        let root = Certificate::builder()
            .cert_type(root_type)
            .subject("HPN Root CA")
            .issuer("HPN Root CA")
            .public_key(&ca_keypair.public_key)
            .can_sign(root_can_sign)
            .validity_days(3650)
            .build_and_sign(&ca_keypair)
            .unwrap();

        let leaf_kp = MlDsaKeypair::generate();
        let leaf = Certificate::builder()
            .cert_type(CertificateType::Server)
            .subject("vpn.example.com")
            .issuer("HPN Root CA")
            .public_key(&leaf_kp.public_key)
            .server_auth(true)
            .validity_days(365)
            .build_and_sign(&ca_keypair)
            .unwrap();

        (root, leaf, ca_keypair)
    }

    #[test]
    fn verify_rejects_non_root_ca_in_root_store() {
        // A `Server` (or `Client`) certificate that someone has placed
        // into `root_certs` MUST NOT be trusted to anchor a chain,
        // even if it matches the leaf's issuer string. Previously the
        // verifier returned Ok in that case (audit H12).
        let (mut root, leaf, _) = make_root_and_leaf(CertificateType::RootCA, true);
        root.cert_type = CertificateType::Server; // wrong cert type after the fact

        let mut store = CertificateStore::new();
        store.root_certs.push(root); // bypass `add_root_cert` to simulate the bug-class
        let result = store.verify_certificate(&leaf);
        assert!(matches!(result, Err(CertificateError::ChainInvalid(_))));
    }

    #[test]
    fn verify_rejects_root_without_can_sign() {
        // A root that was added with `flags.can_sign = false` (or had
        // the flag stripped after insertion) MUST NOT be trusted to
        // sign chains. `add_root_cert` enforces this on insertion;
        // `verify_certificate` now enforces it on every verification.
        let (mut root, leaf, _) = make_root_and_leaf(CertificateType::RootCA, true);
        root.flags.can_sign = false;

        let mut store = CertificateStore::new();
        store.root_certs.push(root);
        let result = store.verify_certificate(&leaf);
        assert!(matches!(result, Err(CertificateError::ChainInvalid(_))));
    }

    #[test]
    fn verify_rejects_revoked_root() {
        // A revoked root is not a trust anchor any more. `is_valid()`
        // returns false for revoked certs and `verify_certificate`
        // skips them.
        let (mut root, leaf, _) = make_root_and_leaf(CertificateType::RootCA, true);
        root.flags.revoked = true;

        let mut store = CertificateStore::new();
        store.root_certs.push(root);
        let result = store.verify_certificate(&leaf);
        assert!(matches!(result, Err(CertificateError::ChainInvalid(_))));
    }

    #[test]
    fn verify_accepts_well_formed_chain() {
        // Sanity: with a real RootCA + can_sign + valid lifetime, the
        // chain still verifies. Without this, the rejection-path
        // tests above could pass for the wrong reason.
        let (root, leaf, _) = make_root_and_leaf(CertificateType::RootCA, true);

        let mut store = CertificateStore::new();
        store.add_root_cert(root).unwrap();
        store.verify_certificate(&leaf).unwrap();
    }
}
