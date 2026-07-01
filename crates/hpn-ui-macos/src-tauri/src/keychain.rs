//! Keychain bridge for the macOS app.
//!
//! This module USED to stash VPN credentials and an HMAC master key in
//! the shared Keychain. Field investigation on macOS Tahoe Developer-ID
//! showed that the Packet Tunnel System Extension running as root cannot
//! reliably reach a Keychain entry owned by the user-context host (returns
//! `errSecNotAvailable -25291` even with the right `keychain-access-groups`
//! entitlement). The whole sharing scheme was therefore retired: the host
//! now hands credentials inline through `providerConfiguration` and macOS
//! persists them in its own root-only `com.apple.networkextension.plist`.
//!
//! What this module still does:
//!   - `purge_all_profile_credentials` — best-effort deletion of any
//!     `io.hpn.vpn.profile.*` items that older builds may have left on
//!     disk. This is called on app startup, on connect-failure, and on
//!     disconnect so an upgrade from an older install cleans up cleanly.
//!
//! The write/read entry points (`set_password`, `delete_password`,
//! `ensure_master_hmac_key`, `get_master_hmac_key`) are kept compiled but
//! `#[allow(dead_code)]` — no live code path calls them anymore. They are
//! preserved as a thin Rust shim over the Swift FFI so that a future
//! release wanting to bring Keychain usage back has a vetted starting
//! point instead of re-writing the FFI from scratch.

use std::os::raw::c_char;

use tracing::{debug, warn};
use zeroize::Zeroizing;

unsafe extern "C" {
    fn hpn_keychain_set_password(
        profile_id: *const c_char,
        profile_id_len: usize,
        password: *const u8,
        password_len: usize,
    ) -> i32;

    fn hpn_keychain_delete_password(profile_id: *const c_char, profile_id_len: usize) -> i32;

    fn hpn_keychain_purge_all() -> i32;

    // Master 32-byte HMAC key used as the HKDF root for both:
    //
    //   - the audit-H15 provider-config envelope (`provider_envelope::wrap`,
    //     domain "HPN-PROVIDER-CONFIG-V1") — wired at the call site below,
    //
    //   - and the future audit-APP-3 IPC-message MAC for the rekey
    //     signal (still stubbed; the Swift bridge already exposes the
    //     Keychain entry so flipping APP-3 on later requires no further
    //     `libHPNVPNManager.a` recompile).
    fn hpn_keychain_ensure_rekey_hmac_key() -> i32;

    fn hpn_keychain_get_rekey_hmac_key(out_buf: *mut u8, out_buf_len: usize) -> i32;
}

/// Store the VPN password for a profile in the shared Keychain.
///
/// The password bytes are passed by reference and never copied into a
/// standard `String` inside this function — the caller should already be
/// holding them in a `Zeroizing<String>` / similar.
///
/// **NOT CALLED in this build.** Retained as a compiled-but-unused shim;
/// see the module-level doc comment.
#[allow(dead_code)]
pub fn set_password(profile_id: &str, password: &[u8]) -> Result<(), String> {
    if profile_id.is_empty() {
        return Err("profile_id is empty".into());
    }
    if password.is_empty() {
        return Err("password is empty".into());
    }

    // SAFETY: pointers are valid for the stated lengths; Swift makes
    // internal copies before SecItemAdd returns.
    let rc = unsafe {
        hpn_keychain_set_password(
            profile_id.as_ptr() as *const c_char,
            profile_id.len(),
            password.as_ptr(),
            password.len(),
        )
    };
    if rc == 0 {
        debug!("Keychain: stored password for profile");
        Ok(())
    } else {
        Err(format!("Keychain SecItemAdd failed (OSStatus {rc})"))
    }
}

/// Delete the VPN password for a profile from the shared Keychain. Absent
/// items are treated as success.
///
/// **NOT CALLED in this build.** Retained as a compiled-but-unused shim;
/// see the module-level doc comment.
#[allow(dead_code)]
pub fn delete_password(profile_id: &str) {
    if profile_id.is_empty() {
        return;
    }
    // SAFETY: profile_id is a valid UTF-8 byte slice; Swift does not mutate.
    let rc = unsafe {
        hpn_keychain_delete_password(profile_id.as_ptr() as *const c_char, profile_id.len())
    };
    if rc != 0 {
        warn!("Keychain: delete_password returned OSStatus {rc}");
    }
}

/// Delete every Keychain item owned by this app (profile passwords + HMAC
/// key). Used defensively on startup after a crash.
pub fn purge_all_profile_credentials() {
    // SAFETY: no arguments.
    let rc = unsafe { hpn_keychain_purge_all() };
    if rc != 0 {
        warn!("Keychain: purge_all returned OSStatus {rc}");
    }
}

/// Ensure the master HMAC key exists in the shared Keychain (creates a
/// fresh 32-byte CSPRNG entry on first use). Idempotent.
///
/// **NOT CALLED in this build.** The provider-config envelope was retired
/// on Tahoe (the root extension cannot share the master key with the user
/// host), so this entry is no longer needed. Retained as a compiled-but-
/// unused shim; see the module-level doc comment.
#[allow(dead_code)]
pub fn ensure_master_hmac_key() -> Result<(), String> {
    // SAFETY: no arguments.
    let rc = unsafe { hpn_keychain_ensure_rekey_hmac_key() };
    if rc == 0 {
        Ok(())
    } else {
        Err(format!("ensure_master_hmac_key failed (OSStatus {rc})"))
    }
}

/// Fetch the master HMAC key from the Keychain.
///
/// **NOT CALLED in this build.** See [`ensure_master_hmac_key`].
#[allow(dead_code)]
pub fn get_master_hmac_key() -> Result<Zeroizing<Vec<u8>>, String> {
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; 32]);
    // SAFETY: buf has capacity 32 and Swift writes at most buf.len bytes.
    let n = unsafe { hpn_keychain_get_rekey_hmac_key(buf.as_mut_ptr(), buf.len()) };
    if n <= 0 {
        return Err(format!("get_master_hmac_key failed (code {n})"));
    }
    buf.truncate(n as usize);
    Ok(buf)
}

// Backwards-compat shims for any module that still references the
// old name. `keychain.rs` was the only consumer; we keep the alias to
// reduce churn in case an out-of-tree branch picks the change up
// asymmetrically.

/// Deprecated alias for [`ensure_master_hmac_key`]. Use the new name.
#[deprecated(
    note = "use ensure_master_hmac_key (audit H15 wires this Keychain entry to multiple HMAC purposes)"
)]
#[allow(dead_code)]
pub fn ensure_rekey_hmac_key() -> Result<(), String> {
    ensure_master_hmac_key()
}

/// Deprecated alias for [`get_master_hmac_key`]. Use the new name.
#[deprecated(
    note = "use get_master_hmac_key (audit H15 wires this Keychain entry to multiple HMAC purposes)"
)]
#[allow(dead_code)]
pub fn get_rekey_hmac_key() -> Result<Zeroizing<Vec<u8>>, String> {
    get_master_hmac_key()
}
