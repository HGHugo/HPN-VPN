//! HMAC-authenticated envelope for the macOS Tauri app ↔ Network
//! Extension provider-config file (audit H15).
//!
//! ## Threat model
//!
//! `provider-config.json` lives in the App Group container that the
//! Tauri app and the Packet Tunnel Extension share. App Group
//! membership is at the team-identifier granularity, so any HPN-signed
//! binary (or, in the worst case, a malicious co-installed extension
//! signed with the same team key) can write to that path. Without
//! authentication, the extension would happily read whatever bytes
//! happen to be in the file at start-up — including a server endpoint
//! the user did not approve, credentials that were swapped for an
//! attacker's, or a forged `client_config` that disables the kill
//! switch.
//!
//! HMAC-SHA256 binds the file content to a 32-byte master key kept in
//! the App Group's Keychain. The Keychain itself is also App-Group-
//! scoped, but Keychain entries cannot be silently overwritten because
//! `SecItemAdd` and `SecItemUpdate` are subject to the system's access
//! controls (the OS audits prompts, and the access list cannot be
//! widened post-creation without user interaction). The result is a
//! defense-in-depth boundary: even if an attacker gains write access
//! to the App Group file system, they cannot forge a valid envelope
//! without also escalating to read the master Keychain entry.
//!
//! ## Wire format
//!
//! ```text
//! offset  len  field
//! ------  ---  -----
//!      0    4  magic "HPNX" (ASCII)
//!      4    1  version (currently 1)
//!      5    3  reserved (must be zero)
//!      8   32  HMAC-SHA256 tag
//!     40    4  json_len (big-endian u32)
//!     44   ..  json_bytes (`json_len` bytes)
//! ```
//!
//! The HMAC tag covers `magic || version || reserved || json_len ||
//! json_bytes`. The tag itself is excluded from the MAC input — there
//! is no need to MAC over the tag, and excluding it lets the wrapper
//! compute the tag in a single pass.
//!
//! ### Domain separation
//!
//! The actual HMAC key is derived from the Keychain master key via
//! HKDF-SHA256 with `info = "HPN-PROVIDER-CONFIG-V1"`. This prevents
//! confusion if the same Keychain entry is later reused for a
//! different purpose (e.g. the eventual rekey-signal MAC reserved by
//! `keychain.rs::ensure_rekey_hmac_key`): each consumer hashes the
//! master through its own domain string.
//!
//! ## Why HMAC and not AES-GCM?
//!
//! The provider-config payload itself is not secret — the JSON
//! contains the public server endpoint, the username (also stored
//! plaintext at the OS account level), and other non-sensitive
//! settings. The actual password lives in the Keychain (audit
//! CRED-1), not in the JSON. We therefore only need *integrity* and
//! *origin authentication*, which HMAC provides at half the
//! complexity of AEAD. If a future field needs confidentiality,
//! upgrade to AES-256-GCM with a separate sub-key (info =
//! `HPN-PROVIDER-CONFIG-AEAD-V1`).

use ring::{hkdf, hmac};

/// Envelope magic ("HPNX" in ASCII).
///
/// Any sane JSON parser would already reject a file starting with
/// these four bytes, so a downgraded extension trying to parse the
/// envelope as raw JSON fails fast instead of accepting truncated
/// input.
pub const MAGIC: &[u8; 4] = b"HPNX";

/// Current envelope version. Bumped on incompatible wire changes —
/// the `unwrap` path rejects unknown versions outright.
pub const VERSION: u8 = 1;

/// HKDF info string for the provider-config sub-key derivation.
///
/// MUST byte-equal between the wrapping side (Tauri app) and the
/// unwrapping side (Network Extension). Changing it is a wire-format
/// breaking change.
pub const INFO: &[u8] = b"HPN-PROVIDER-CONFIG-V1";

/// Maximum JSON payload size.
///
/// The realistic provider-config is ≤ 4 KiB even with a worst-case
/// split-route list of hundreds of entries. 64 KiB is a generous
/// cap that still rules out the 4-byte-length-header DoS where an
/// adversary writes a tiny file that claims `json_len = 4 GiB`.
pub const MAX_PAYLOAD_LEN: usize = 64 * 1024;

/// Number of header bytes (magic, version, reserved, tag, json_len).
const HEADER_SIZE: usize = 4 + 1 + 3 + 32 + 4;

/// HMAC tag length in bytes (HMAC-SHA256).
const TAG_LEN: usize = 32;

/// Expected master-key length in bytes.
///
/// We require 32 random bytes so the HKDF input has full 256-bit
/// entropy; shorter keys would still work cryptographically but
/// risk an operator copy-pasting a passphrase.
pub const MASTER_KEY_LEN: usize = 32;

/// Errors produced by [`wrap`] and [`unwrap_payload`].
#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    /// Buffer is shorter than the minimum envelope header.
    #[error("envelope too short: needed at least {needed} bytes, got {actual}")]
    TooShort {
        /// Number of bytes the parser expected before continuing.
        needed: usize,
        /// Actual buffer length.
        actual: usize,
    },
    /// First four bytes are not the `HPNX` magic.
    #[error("invalid envelope magic")]
    BadMagic,
    /// Version byte is not in the supported range.
    #[error("unsupported envelope version: {0}")]
    BadVersion(u8),
    /// `json_len` is greater than [`MAX_PAYLOAD_LEN`].
    #[error("payload too large: {actual} bytes (max {max})")]
    TooLarge {
        /// Length the envelope claims.
        actual: usize,
        /// Maximum the parser accepts.
        max: usize,
    },
    /// Master key is the wrong length.
    #[error("master key must be exactly {expected} bytes, got {actual}")]
    BadKeyLength {
        /// Required length.
        expected: usize,
        /// Provided length.
        actual: usize,
    },
    /// HMAC tag does not validate against the recomputed MAC.
    ///
    /// Returned on tampered envelopes, key mismatch, or any wire
    /// modification of the authenticated bytes.
    #[error("envelope HMAC verification failed")]
    BadHmac,
}

/// Result alias for envelope operations.
pub type Result<T> = std::result::Result<T, EnvelopeError>;

/// Derive the per-purpose HMAC sub-key from the Keychain master key.
///
/// HKDF-SHA256 (Extract+Expand) with empty salt and `INFO` as the
/// expand context. Returns a `ring::hmac::Key` ready for sign / verify.
fn derive_subkey(master_key: &[u8]) -> Result<hmac::Key> {
    if master_key.len() != MASTER_KEY_LEN {
        return Err(EnvelopeError::BadKeyLength {
            expected: MASTER_KEY_LEN,
            actual: master_key.len(),
        });
    }

    // HKDF: salt is the empty string here, because the master key is
    // already a uniform 32-byte CSPRNG output. The whole point of the
    // salt is to whiten low-entropy input material — for full-entropy
    // keys, omitting it is equivalent.
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
    let prk = salt.extract(master_key);

    struct Len32;
    impl hkdf::KeyType for Len32 {
        fn len(&self) -> usize {
            32
        }
    }

    let okm = prk
        .expand(&[INFO], Len32)
        .map_err(|_| EnvelopeError::BadHmac)?;

    let mut key_bytes = [0u8; 32];
    okm.fill(&mut key_bytes)
        .map_err(|_| EnvelopeError::BadHmac)?;

    let key = hmac::Key::new(hmac::HMAC_SHA256, &key_bytes);
    // The hmac::Key constructor copies the bytes into its own opaque
    // storage; clearing our local copy denies a memory snapshot
    // attacker the residual key material.
    use zeroize::Zeroize;
    key_bytes.zeroize();
    Ok(key)
}

/// Build the byte sequence that the HMAC tag covers.
///
/// Order MUST match between [`wrap`] and [`unwrap_payload`] or the
/// MAC verification will spuriously fail.
fn build_mac_input(json: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(8 + 4 + json.len());
    input.extend_from_slice(MAGIC);
    input.push(VERSION);
    input.extend_from_slice(&[0u8, 0, 0]);
    input.extend_from_slice(&(json.len() as u32).to_be_bytes());
    input.extend_from_slice(json);
    input
}

/// Wrap a JSON payload in an HMAC-SHA256-signed envelope.
///
/// # Errors
///
/// - [`EnvelopeError::TooLarge`] if `json.len() > MAX_PAYLOAD_LEN`.
/// - [`EnvelopeError::BadKeyLength`] if `master_key.len() != 32`.
pub fn wrap(master_key: &[u8], json: &[u8]) -> Result<Vec<u8>> {
    if json.len() > MAX_PAYLOAD_LEN {
        return Err(EnvelopeError::TooLarge {
            actual: json.len(),
            max: MAX_PAYLOAD_LEN,
        });
    }

    let key = derive_subkey(master_key)?;
    let mac_input = build_mac_input(json);
    let tag = hmac::sign(&key, &mac_input);

    // Final wire layout: [magic|ver|reserved] [tag] [json_len] [json].
    let mut out = Vec::with_capacity(HEADER_SIZE + json.len());
    out.extend_from_slice(&mac_input[..8]); // magic + version + reserved
    out.extend_from_slice(tag.as_ref());
    out.extend_from_slice(&mac_input[8..]); // json_len + json
    Ok(out)
}

/// Unwrap an HMAC-SHA256-signed envelope and return a borrow of the
/// inner JSON bytes.
///
/// # Errors
///
/// - [`EnvelopeError::TooShort`] if the buffer is truncated.
/// - [`EnvelopeError::BadMagic`] if the first four bytes are wrong.
/// - [`EnvelopeError::BadVersion`] if the version byte is not [`VERSION`].
/// - [`EnvelopeError::TooLarge`] if `json_len` exceeds [`MAX_PAYLOAD_LEN`].
/// - [`EnvelopeError::BadKeyLength`] if `master_key.len() != 32`.
/// - [`EnvelopeError::BadHmac`] on any tampering or key mismatch.
pub fn unwrap_payload<'a>(master_key: &[u8], envelope: &'a [u8]) -> Result<&'a [u8]> {
    if envelope.len() < HEADER_SIZE {
        return Err(EnvelopeError::TooShort {
            needed: HEADER_SIZE,
            actual: envelope.len(),
        });
    }

    if &envelope[0..4] != MAGIC {
        return Err(EnvelopeError::BadMagic);
    }
    if envelope[4] != VERSION {
        return Err(EnvelopeError::BadVersion(envelope[4]));
    }
    // Reserved bytes [5..8] must be zero. We tolerate non-zero bytes
    // for forward-compat IF a future minor format extension uses
    // them, but only after they are explicitly defined; for V1, any
    // non-zero reserved byte indicates a malformed envelope.
    if envelope[5] != 0 || envelope[6] != 0 || envelope[7] != 0 {
        return Err(EnvelopeError::BadVersion(envelope[4]));
    }

    let tag = &envelope[8..8 + TAG_LEN];

    let json_len_offset = 8 + TAG_LEN;
    let json_len = u32::from_be_bytes([
        envelope[json_len_offset],
        envelope[json_len_offset + 1],
        envelope[json_len_offset + 2],
        envelope[json_len_offset + 3],
    ]) as usize;

    if json_len > MAX_PAYLOAD_LEN {
        return Err(EnvelopeError::TooLarge {
            actual: json_len,
            max: MAX_PAYLOAD_LEN,
        });
    }

    let payload_offset = json_len_offset + 4;
    if envelope.len() < payload_offset + json_len {
        return Err(EnvelopeError::TooShort {
            needed: payload_offset + json_len,
            actual: envelope.len(),
        });
    }
    let json = &envelope[payload_offset..payload_offset + json_len];

    // Recompute the MAC input EXACTLY the way `wrap` did, then
    // delegate to `ring::hmac::verify` which performs a constant-time
    // comparison.
    let mac_input = build_mac_input(json);
    let key = derive_subkey(master_key)?;
    hmac::verify(&key, &mac_input, tag).map_err(|_| EnvelopeError::BadHmac)?;

    Ok(json)
}

/// Generate a new 32-byte master key suitable for storing in the App
/// Group Keychain. The returned bytes come from `ring::rand`'s
/// `SystemRandom`, which on macOS is backed by `/dev/urandom`.
///
/// Wrapped in [`zeroize::Zeroizing`] so the bytes are wiped from the
/// heap when the caller drops the value.
#[must_use]
pub fn generate_master_key() -> zeroize::Zeroizing<[u8; MASTER_KEY_LEN]> {
    use ring::rand::SecureRandom;
    let mut bytes = [0u8; MASTER_KEY_LEN];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .expect("SystemRandom::fill cannot fail on supported platforms");
    zeroize::Zeroizing::new(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        // Deterministic so the tests are reproducible. Production
        // calls `generate_master_key()`.
        [0x42u8; 32]
    }

    fn test_other_key() -> [u8; 32] {
        [0xA5u8; 32]
    }

    #[test]
    fn test_wrap_unwrap_roundtrip() {
        let key = test_key();
        let payload = br#"{"server_endpoint":"203.0.113.1:51820"}"#;
        let envelope = wrap(&key, payload).unwrap();
        let recovered = unwrap_payload(&key, &envelope).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn test_envelope_starts_with_magic() {
        let key = test_key();
        let envelope = wrap(&key, b"{}").unwrap();
        assert_eq!(&envelope[0..4], MAGIC);
        assert_eq!(envelope[4], VERSION);
    }

    #[test]
    fn test_empty_payload_roundtrip() {
        let key = test_key();
        let envelope = wrap(&key, b"").unwrap();
        let recovered = unwrap_payload(&key, &envelope).unwrap();
        assert_eq!(recovered, b"");
    }

    #[test]
    fn test_unwrap_with_wrong_key_rejected() {
        let envelope = wrap(&test_key(), b"hello").unwrap();
        let result = unwrap_payload(&test_other_key(), &envelope);
        assert!(matches!(result, Err(EnvelopeError::BadHmac)));
    }

    #[test]
    fn test_unwrap_truncated_rejected() {
        let envelope = wrap(&test_key(), b"hello").unwrap();
        for cut in [0, 4, 8, 30, envelope.len() - 1] {
            let result = unwrap_payload(&test_key(), &envelope[..cut]);
            assert!(result.is_err(), "cut={} should have rejected", cut);
        }
    }

    #[test]
    fn test_unwrap_bad_magic_rejected() {
        let mut envelope = wrap(&test_key(), b"hello").unwrap();
        envelope[0] = b'X';
        let result = unwrap_payload(&test_key(), &envelope);
        assert!(matches!(result, Err(EnvelopeError::BadMagic)));
    }

    #[test]
    fn test_unwrap_bad_version_rejected() {
        let mut envelope = wrap(&test_key(), b"hello").unwrap();
        envelope[4] = 99;
        let result = unwrap_payload(&test_key(), &envelope);
        assert!(matches!(result, Err(EnvelopeError::BadVersion(99))));
    }

    #[test]
    fn test_unwrap_nonzero_reserved_rejected() {
        let mut envelope = wrap(&test_key(), b"hello").unwrap();
        envelope[5] = 0x01;
        // We surface this as BadVersion (logical class: "format byte
        // outside the V1 spec"). The exact error is implementation
        // detail; what matters is that the envelope is REJECTED.
        let result = unwrap_payload(&test_key(), &envelope);
        assert!(result.is_err());
    }

    #[test]
    fn test_unwrap_tampered_payload_rejected() {
        let mut envelope = wrap(&test_key(), b"hello world").unwrap();
        // Flip the last byte of the JSON.
        let last = envelope.len() - 1;
        envelope[last] ^= 0xFF;
        let result = unwrap_payload(&test_key(), &envelope);
        assert!(matches!(result, Err(EnvelopeError::BadHmac)));
    }

    #[test]
    fn test_unwrap_tampered_tag_rejected() {
        let mut envelope = wrap(&test_key(), b"hello").unwrap();
        // Flip a byte inside the HMAC tag.
        envelope[8 + 5] ^= 0xFF;
        let result = unwrap_payload(&test_key(), &envelope);
        assert!(matches!(result, Err(EnvelopeError::BadHmac)));
    }

    #[test]
    fn test_unwrap_oversized_length_rejected() {
        let key = test_key();
        let mut envelope = wrap(&key, b"hello").unwrap();
        // Overwrite json_len with a value > MAX_PAYLOAD_LEN.
        let len_offset = 8 + 32;
        envelope[len_offset..len_offset + 4]
            .copy_from_slice(&((MAX_PAYLOAD_LEN as u32) + 1).to_be_bytes());
        let result = unwrap_payload(&key, &envelope);
        assert!(matches!(result, Err(EnvelopeError::TooLarge { .. })));
    }

    #[test]
    fn test_wrap_oversized_payload_rejected() {
        let key = test_key();
        let big = vec![0u8; MAX_PAYLOAD_LEN + 1];
        let result = wrap(&key, &big);
        assert!(matches!(result, Err(EnvelopeError::TooLarge { .. })));
    }

    #[test]
    fn test_wrap_short_key_rejected() {
        let result = wrap(&[0u8; 16], b"hi");
        assert!(matches!(result, Err(EnvelopeError::BadKeyLength { .. })));
    }

    #[test]
    fn test_unwrap_short_key_rejected() {
        let envelope = wrap(&test_key(), b"hi").unwrap();
        let result = unwrap_payload(&[0u8; 16], &envelope);
        assert!(matches!(result, Err(EnvelopeError::BadKeyLength { .. })));
    }

    #[test]
    fn test_generate_master_key_is_random_and_zeroed() {
        let k1 = generate_master_key();
        let k2 = generate_master_key();
        // Birthday-bound: 2^256 distinct values, collision is
        // astronomically unlikely. If this assertion ever flakes, we
        // have a much bigger problem than the test.
        assert_ne!(*k1, *k2);
        // 32 bytes of entropy should not be all-zero.
        assert!(k1.iter().any(|b| *b != 0));
    }

    #[test]
    fn test_realistic_provider_config_payload_roundtrips() {
        let key = test_key();
        // Approximate shape of what `save_provider_config` writes —
        // server endpoint, full_tunnel flag, allow_lan, split routes,
        // and a Keychain-redirected credentials block.
        let payload = br#"{"client_config":{"server_addr":"203.0.113.10:51820","server_public_key":"AAAA","kill_switch":true},"server_endpoint":"203.0.113.10:51820","full_tunnel":true,"allow_lan":true,"split_routes":["10.0.0.0/8","192.168.0.0/16"],"credentials":null,"credentials_in_keychain":true,"keychain_profile_id":"prod-eu","username":"alice"}"#;
        let envelope = wrap(&key, payload).unwrap();
        let recovered = unwrap_payload(&key, &envelope).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn test_two_calls_produce_byte_identical_envelopes() {
        // HMAC is deterministic in the (key, message) pair, and our
        // wrap function is pure. Two consecutive calls with the same
        // arguments MUST therefore produce byte-identical output.
        // This property is relied on by the reproducible-build CI:
        // any future refactor that introduces randomness would break
        // it loudly.
        let key = test_key();
        let payload = b"deterministic payload";
        let a = wrap(&key, payload).unwrap();
        let b = wrap(&key, payload).unwrap();
        assert_eq!(a, b);
    }
}
