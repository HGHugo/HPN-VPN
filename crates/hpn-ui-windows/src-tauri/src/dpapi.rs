//! Windows DPAPI (Data Protection API) helpers for at-rest encryption of
//! profile secrets (e.g. VPN credentials stored in `profiles.enc`).
//!
//! # Threat model
//!
//! DPAPI wraps the plaintext under a key derived from the current user's
//! credentials. Any process running as the SAME user can still call
//! `CryptUnprotectData` on the ciphertext, so DPAPI is not a defence against
//! same-user malware. What it DOES defend against:
//!
//! - A file-level dump of `%APPDATA%` / `%LOCALAPPDATA%` copied to another
//!   machine or another user account — the ciphertext is useless there.
//! - Backups, sync agents (OneDrive, etc.) and support bundles that include
//!   the profile file — secrets no longer visible in plaintext.
//! - Reading the file with a low-integrity process that cannot impersonate
//!   the user (e.g. a limited service account).
//!
//! A fixed entropy blob (`ENTROPY`) is mixed into the wrapping so that a
//! blob taken from this application cannot be transparently unwrapped by a
//! different application running as the same user, which would otherwise be
//! possible with a zero-entropy DPAPI blob.
//!
//! # UI behaviour
//!
//! All calls pass `CRYPTPROTECT_UI_FORBIDDEN`: DPAPI will NEVER prompt the
//! user. If the user profile is roaming or the key is unavailable the call
//! fails cleanly instead of blocking the UI thread.

#![cfg(windows)]

use std::slice;

use windows::Win32::Foundation::HLOCAL;
use windows::Win32::Foundation::LocalFree;
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use windows::core::PCWSTR;

/// Application-specific entropy ("secondary entropy") mixed into the DPAPI
/// wrapping. This is NOT secret — it is a domain separator so that other
/// applications running as the same user cannot transparently unwrap our
/// blobs.
const ENTROPY: &[u8] = b"HPN-VPN-Profile-v1";

/// DPAPI operation error.
#[derive(Debug, thiserror::Error)]
pub enum DpapiError {
    #[error("CryptProtectData failed: {0}")]
    Protect(windows::core::Error),
    #[error("CryptUnprotectData failed: {0}")]
    Unprotect(windows::core::Error),
}

/// Wrap `plaintext` with DPAPI under the current user's key.
///
/// Returns the opaque ciphertext blob. The blob contains its own integrity
/// check and salt; callers do not need to add their own.
pub fn encrypt(plaintext: &[u8]) -> Result<Vec<u8>, DpapiError> {
    // SAFETY: We construct `CRYPT_INTEGER_BLOB`s pointing into `plaintext`
    // and `ENTROPY`; DPAPI only reads from them. The output blob's buffer
    // is allocated by Windows via LocalAlloc and we free it with LocalFree
    // after copying into a Rust-owned Vec on every return path.
    unsafe {
        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: plaintext.len() as u32,
            pbData: plaintext.as_ptr() as *mut u8,
        };
        let entropy_blob = CRYPT_INTEGER_BLOB {
            cbData: ENTROPY.len() as u32,
            pbData: ENTROPY.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB::default();

        CryptProtectData(
            &in_blob,
            PCWSTR::null(),
            Some(&entropy_blob),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
        .map_err(DpapiError::Protect)?;

        // Copy the returned buffer into a Rust-owned Vec before freeing the
        // LocalAlloc'd pointer that DPAPI handed back.
        let slice = slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
        let ciphertext = slice.to_vec();
        let _ = LocalFree(HLOCAL(out_blob.pbData as *mut _));
        Ok(ciphertext)
    }
}

/// Unwrap a DPAPI-protected blob produced by [`encrypt`].
///
/// Returns the plaintext as a plain `Vec<u8>`. The caller is responsible for
/// moving it into a [`zeroize::Zeroizing`] wrapper if the plaintext is
/// sensitive (it almost always is — this crate uses it for credentials).
pub fn decrypt(ciphertext: &[u8]) -> Result<Vec<u8>, DpapiError> {
    // SAFETY: Same argument as `encrypt`: DPAPI only reads from the input
    // blobs, and we free the LocalAlloc'd output buffer after copying it
    // into a Rust-owned Vec.
    unsafe {
        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: ciphertext.len() as u32,
            pbData: ciphertext.as_ptr() as *mut u8,
        };
        let entropy_blob = CRYPT_INTEGER_BLOB {
            cbData: ENTROPY.len() as u32,
            pbData: ENTROPY.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB::default();

        CryptUnprotectData(
            &in_blob,
            None,
            Some(&entropy_blob),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
        .map_err(DpapiError::Unprotect)?;

        let slice = slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
        let plaintext = slice.to_vec();
        let _ = LocalFree(HLOCAL(out_blob.pbData as *mut _));
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip only runs on Windows (DPAPI requires a user profile).
    #[test]
    fn roundtrip_empty_and_small() {
        // Empty payload: DPAPI accepts it and returns a valid, opaque blob.
        let ct = encrypt(&[]).expect("encrypt empty");
        let pt = decrypt(&ct).expect("decrypt empty");
        assert!(pt.is_empty());

        let msg = b"hpn-vpn test secret";
        let ct = encrypt(msg).expect("encrypt");
        let pt = decrypt(&ct).expect("decrypt");
        assert_eq!(&pt[..], &msg[..]);
    }

    #[test]
    fn foreign_blob_rejected() {
        // Arbitrary bytes are not a valid DPAPI blob; the API must reject
        // rather than return something.
        let garbage = vec![0u8; 64];
        assert!(decrypt(&garbage).is_err());
    }
}
