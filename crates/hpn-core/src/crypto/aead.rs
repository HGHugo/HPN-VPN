//! AES-256-GCM authenticated encryption.
//!
//! Provides authenticated encryption with associated data (AEAD) for
//! encrypting tunnel traffic.

use ring::aead::{self, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};

use crate::error::CryptoError;

/// Pre-computed AES-256-GCM key for high-performance encryption/decryption.
///
/// Creating a `LessSafeKey` involves key schedule computation (~200 CPU cycles).
/// By pre-computing the key once per session, we avoid this overhead on every packet.
///
/// # Security Considerations
///
/// **Zeroization Limitation**: This struct wraps `ring::aead::LessSafeKey`, which does
/// not implement the `Zeroize` trait. As a result, the key material (including the
/// expanded AES key schedule) may remain in memory after this struct is dropped.
///
/// Mitigations in place:
/// - Sessions are short-lived and keys are rotated frequently via rekeying
/// - The original key bytes (`[u8; 32]`) passed to `new()` should be zeroized by the caller
/// - Process memory is protected by OS-level isolation
///
/// This is a known limitation of the `ring` cryptography library. Future versions may
/// switch to a library that supports zeroization (e.g., `aes-gcm` with `zeroize` feature)
/// if this becomes a critical security requirement.
pub struct PrecomputedKey {
    inner: LessSafeKey,
}

impl PrecomputedKey {
    /// Create a pre-computed key from raw key bytes.
    ///
    /// # Errors
    /// Returns error if key size is invalid.
    pub fn new(key: &[u8; KEY_SIZE]) -> Result<Self, CryptoError> {
        let unbound =
            UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| CryptoError::Encryption)?;
        Ok(Self {
            inner: LessSafeKey::new(unbound),
        })
    }

    /// Encrypt using pre-computed key (faster than aead::encrypt).
    ///
    /// Saves ~200 CPU cycles per packet by avoiding key schedule computation.
    #[inline]
    pub fn encrypt(
        &self,
        nonce_prefix: &[u8; 4],
        counter: u64,
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, CryptoError> {
        // SECURITY: Prevent counter exhaustion which would cause nonce reuse.
        // AES-GCM security catastrophically fails if nonces are ever reused.
        if counter >= u64::MAX - 1 {
            return Err(CryptoError::CounterExhausted);
        }

        let output_len = plaintext.len() + TAG_SIZE;

        if ciphertext.len() < output_len {
            return Err(CryptoError::BufferTooSmall {
                needed: output_len,
                available: ciphertext.len(),
            });
        }

        // Copy plaintext to output buffer (will be encrypted in-place)
        ciphertext[..plaintext.len()].copy_from_slice(plaintext);

        let nonce_bytes = build_nonce(nonce_prefix, counter);
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| CryptoError::InvalidNonce)?;

        let tag = self
            .inner
            .seal_in_place_separate_tag(nonce, Aad::from(aad), &mut ciphertext[..plaintext.len()])
            .map_err(|_| CryptoError::Encryption)?;

        ciphertext[plaintext.len()..output_len].copy_from_slice(tag.as_ref());

        Ok(output_len)
    }

    /// Encrypt in-place using pre-computed key.
    #[inline]
    pub fn encrypt_in_place(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        buffer: &mut [u8],
        plaintext_len: usize,
    ) -> Result<usize, CryptoError> {
        if buffer.len() < plaintext_len + TAG_SIZE {
            return Err(CryptoError::BufferTooSmall {
                needed: plaintext_len + TAG_SIZE,
                available: buffer.len(),
            });
        }

        let nonce_obj =
            Nonce::try_assume_unique_for_key(nonce).map_err(|_| CryptoError::InvalidNonce)?;

        let tag = self
            .inner
            .seal_in_place_separate_tag(nonce_obj, Aad::from(aad), &mut buffer[..plaintext_len])
            .map_err(|_| CryptoError::Encryption)?;

        let output_len = plaintext_len + TAG_SIZE;
        buffer[plaintext_len..output_len].copy_from_slice(tag.as_ref());

        Ok(output_len)
    }

    /// Decrypt using pre-computed key (faster than aead::decrypt).
    #[inline]
    pub fn decrypt(
        &self,
        nonce_prefix: &[u8; 4],
        counter: u64,
        aad: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, CryptoError> {
        if ciphertext.len() < TAG_SIZE {
            return Err(CryptoError::Decryption);
        }

        let plaintext_len = ciphertext.len() - TAG_SIZE;

        if plaintext.len() < ciphertext.len() {
            return Err(CryptoError::BufferTooSmall {
                needed: ciphertext.len(),
                available: plaintext.len(),
            });
        }

        // Copy ciphertext for in-place decryption
        plaintext[..ciphertext.len()].copy_from_slice(ciphertext);

        let nonce_bytes = build_nonce(nonce_prefix, counter);
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| CryptoError::InvalidNonce)?;

        let decrypted = self
            .inner
            .open_in_place(nonce, Aad::from(aad), &mut plaintext[..ciphertext.len()])
            .map_err(|_| CryptoError::Decryption)?;

        debug_assert_eq!(decrypted.len(), plaintext_len);

        Ok(plaintext_len)
    }

    /// Decrypt in-place using pre-computed key.
    #[inline]
    pub fn decrypt_in_place(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<usize, CryptoError> {
        if buffer.len() < TAG_SIZE {
            return Err(CryptoError::Decryption);
        }

        let nonce_obj =
            Nonce::try_assume_unique_for_key(nonce).map_err(|_| CryptoError::InvalidNonce)?;

        let decrypted = self
            .inner
            .open_in_place(nonce_obj, Aad::from(aad), buffer)
            .map_err(|_| CryptoError::Decryption)?;

        Ok(decrypted.len())
    }
}

/// Nonce size in bytes (96 bits for AES-GCM).
pub const NONCE_SIZE: usize = NONCE_LEN;

/// Authentication tag size in bytes (128 bits for AES-GCM).
pub const TAG_SIZE: usize = 16;

/// AES-256 key size in bytes.
pub const KEY_SIZE: usize = 32;

/// Encrypt plaintext using AES-256-GCM.
///
/// The ciphertext will be `plaintext.len() + TAG_SIZE` bytes.
///
/// # Arguments
///
/// * `key` - 32-byte AES-256 key
/// * `nonce_prefix` - 4-byte session-specific nonce prefix
/// * `counter` - Counter value for nonce construction
/// * `aad` - Additional authenticated data (e.g., packet header)
/// * `plaintext` - Data to encrypt
/// * `ciphertext` - Output buffer (must be at least `plaintext.len() + TAG_SIZE`)
///
/// # Errors
///
/// Returns an error if encryption fails.
///
/// # Returns
///
/// The number of bytes written to `ciphertext`.
///
/// # Security
///
/// The full 96-bit nonce is constructed as: nonce_prefix(4 bytes) || counter(8 bytes).
/// This ensures nonce uniqueness across all sessions and counters.
pub fn encrypt(
    key: &[u8; KEY_SIZE],
    nonce_prefix: &[u8; 4],
    counter: u64,
    aad: &[u8],
    plaintext: &[u8],
    ciphertext: &mut [u8],
) -> Result<usize, CryptoError> {
    // SECURITY: Prevent counter exhaustion which would cause nonce reuse.
    // AES-GCM security catastrophically fails if nonces are ever reused.
    if counter >= u64::MAX - 1 {
        return Err(CryptoError::CounterExhausted);
    }

    let output_len = plaintext.len() + TAG_SIZE;

    if ciphertext.len() < output_len {
        return Err(CryptoError::BufferTooSmall {
            needed: output_len,
            available: ciphertext.len(),
        });
    }

    // Copy plaintext to output buffer (will be encrypted in-place)
    ciphertext[..plaintext.len()].copy_from_slice(plaintext);

    let unbound_key =
        UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| CryptoError::Encryption)?;
    let less_safe_key = LessSafeKey::new(unbound_key);

    let nonce_bytes = build_nonce(nonce_prefix, counter);
    let nonce =
        Nonce::try_assume_unique_for_key(&nonce_bytes).map_err(|_| CryptoError::InvalidNonce)?;

    let aad = Aad::from(aad);

    let tag = less_safe_key
        .seal_in_place_separate_tag(nonce, aad, &mut ciphertext[..plaintext.len()])
        .map_err(|_| CryptoError::Encryption)?;

    // Append tag
    ciphertext[plaintext.len()..output_len].copy_from_slice(tag.as_ref());

    Ok(output_len)
}

/// Decrypt ciphertext using AES-256-GCM.
///
/// # Arguments
///
/// * `key` - 32-byte AES-256 key
/// * `nonce_prefix` - 4-byte session-specific nonce prefix
/// * `counter` - Counter value for nonce construction
/// * `aad` - Additional authenticated data (must match encryption)
/// * `ciphertext` - Data to decrypt (including tag)
/// * `plaintext` - Output buffer (must be at least `ciphertext.len() - TAG_SIZE`)
///
/// # Errors
///
/// Returns an error if decryption or authentication fails.
///
/// # Returns
///
/// The number of bytes written to `plaintext`.
///
/// # Security
///
/// The full 96-bit nonce is constructed as: nonce_prefix(4 bytes) || counter(8 bytes).
/// This must match the nonce used during encryption.
pub fn decrypt(
    key: &[u8; KEY_SIZE],
    nonce_prefix: &[u8; 4],
    counter: u64,
    aad: &[u8],
    ciphertext: &[u8],
    plaintext: &mut [u8],
) -> Result<usize, CryptoError> {
    if ciphertext.len() < TAG_SIZE {
        return Err(CryptoError::Decryption);
    }

    let plaintext_len = ciphertext.len() - TAG_SIZE;

    // Need buffer large enough for ciphertext (plaintext + tag) for in-place decryption
    if plaintext.len() < ciphertext.len() {
        return Err(CryptoError::BufferTooSmall {
            needed: ciphertext.len(),
            available: plaintext.len(),
        });
    }

    // Copy ciphertext to plaintext buffer for in-place decryption (zero extra allocation)
    plaintext[..ciphertext.len()].copy_from_slice(ciphertext);

    let unbound_key =
        UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| CryptoError::Decryption)?;
    let less_safe_key = LessSafeKey::new(unbound_key);

    let nonce_bytes = build_nonce(nonce_prefix, counter);
    let nonce =
        Nonce::try_assume_unique_for_key(&nonce_bytes).map_err(|_| CryptoError::InvalidNonce)?;

    let aad = Aad::from(aad);
    let decrypted = less_safe_key
        .open_in_place(nonce, aad, &mut plaintext[..ciphertext.len()])
        .map_err(|_| CryptoError::Decryption)?;

    // decrypted is a slice into plaintext, verify length matches
    debug_assert_eq!(decrypted.len(), plaintext_len);

    Ok(plaintext_len)
}

/// Encrypt in-place with explicit nonce.
///
/// The buffer must have `TAG_SIZE` extra bytes at the end for the tag.
///
/// # Errors
///
/// Returns an error if encryption fails.
pub fn encrypt_in_place(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    aad: &[u8],
    buffer: &mut [u8],
    plaintext_len: usize,
) -> Result<usize, CryptoError> {
    if buffer.len() < plaintext_len + TAG_SIZE {
        return Err(CryptoError::BufferTooSmall {
            needed: plaintext_len + TAG_SIZE,
            available: buffer.len(),
        });
    }

    let unbound_key =
        UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| CryptoError::Encryption)?;
    let less_safe_key = LessSafeKey::new(unbound_key);

    let nonce_obj =
        Nonce::try_assume_unique_for_key(nonce).map_err(|_| CryptoError::InvalidNonce)?;
    let aad = Aad::from(aad);

    let tag = less_safe_key
        .seal_in_place_separate_tag(nonce_obj, aad, &mut buffer[..plaintext_len])
        .map_err(|_| CryptoError::Encryption)?;

    // Append tag
    let output_len = plaintext_len + TAG_SIZE;
    buffer[plaintext_len..output_len].copy_from_slice(tag.as_ref());

    Ok(output_len)
}

/// Decrypt in-place with explicit nonce.
///
/// # Errors
///
/// Returns an error if decryption or authentication fails.
pub fn decrypt_in_place(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    aad: &[u8],
    buffer: &mut [u8],
) -> Result<usize, CryptoError> {
    if buffer.len() < TAG_SIZE {
        return Err(CryptoError::Decryption);
    }

    let unbound_key =
        UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| CryptoError::Decryption)?;
    let less_safe_key = LessSafeKey::new(unbound_key);

    let nonce_obj =
        Nonce::try_assume_unique_for_key(nonce).map_err(|_| CryptoError::InvalidNonce)?;
    let aad = Aad::from(aad);

    let decrypted = less_safe_key
        .open_in_place(nonce_obj, aad, buffer)
        .map_err(|_| CryptoError::Decryption)?;

    Ok(decrypted.len())
}

/// Build a 96-bit nonce from session-specific prefix and counter.
///
/// Nonce construction: prefix(4 bytes) || counter(8 bytes) = 96 bits total
///
/// This ensures nonce uniqueness:
/// - Session-specific prefix (derived from handshake secret)
/// - Counter provides 2^64 unique values per session
/// - Combined: 2^96 total nonce space
///
/// SECURITY: This prevents nonce reuse across sessions.
#[must_use]
#[inline]
pub fn build_nonce(nonce_prefix: &[u8; 4], counter: u64) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    // First 4 bytes: session-specific prefix
    nonce[0..4].copy_from_slice(nonce_prefix);
    // Last 8 bytes: counter
    nonce[4..12].copy_from_slice(&counter.to_be_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; KEY_SIZE];
        let nonce_prefix = [0x00u8; 4]; // 4-byte prefix
        let counter = 1u64;
        let aad = b"header";
        let plaintext = b"Hello, HPN VPN!";

        let mut ciphertext = vec![0u8; plaintext.len() + TAG_SIZE];
        let ct_len = encrypt(
            &key,
            &nonce_prefix,
            counter,
            aad,
            plaintext,
            &mut ciphertext,
        )
        .unwrap();
        assert_eq!(ct_len, plaintext.len() + TAG_SIZE);

        // Decrypt buffer must be at least ciphertext.len() for in-place decryption
        let mut decrypted = vec![0u8; ciphertext.len()];
        let pt_len = decrypt(
            &key,
            &nonce_prefix,
            counter,
            aad,
            &ciphertext,
            &mut decrypted,
        )
        .unwrap();
        assert_eq!(pt_len, plaintext.len());
        assert_eq!(&decrypted[..pt_len], plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = [0x42u8; KEY_SIZE];
        let key2 = [0x43u8; KEY_SIZE];
        let nonce_prefix = [0x00u8; 4];
        let counter = 1u64;
        let aad = b"header";
        let plaintext = b"Secret message";

        let mut ciphertext = vec![0u8; plaintext.len() + TAG_SIZE];
        encrypt(
            &key1,
            &nonce_prefix,
            counter,
            aad,
            plaintext,
            &mut ciphertext,
        )
        .unwrap();

        let mut decrypted = vec![0u8; ciphertext.len()];
        let result = decrypt(
            &key2,
            &nonce_prefix,
            counter,
            aad,
            &ciphertext,
            &mut decrypted,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_counter_fails() {
        let key = [0x42u8; KEY_SIZE];
        let nonce_prefix = [0x00u8; 4];
        let aad = b"header";
        let plaintext = b"Secret message";

        let mut ciphertext = vec![0u8; plaintext.len() + TAG_SIZE];
        encrypt(&key, &nonce_prefix, 1, aad, plaintext, &mut ciphertext).unwrap();

        let mut decrypted = vec![0u8; ciphertext.len()];
        let result = decrypt(&key, &nonce_prefix, 2, aad, &ciphertext, &mut decrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let key = [0x42u8; KEY_SIZE];
        let nonce_prefix = [0x00u8; 4];
        let counter = 1u64;
        let plaintext = b"Secret message";

        let mut ciphertext = vec![0u8; plaintext.len() + TAG_SIZE];
        encrypt(
            &key,
            &nonce_prefix,
            counter,
            b"header1",
            plaintext,
            &mut ciphertext,
        )
        .unwrap();

        let mut decrypted = vec![0u8; ciphertext.len()];
        let result = decrypt(
            &key,
            &nonce_prefix,
            counter,
            b"header2",
            &ciphertext,
            &mut decrypted,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_modified_ciphertext_fails() {
        let key = [0x42u8; KEY_SIZE];
        let nonce_prefix = [0x00u8; 4];
        let counter = 1u64;
        let aad = b"header";
        let plaintext = b"Secret message";

        let mut ciphertext = vec![0u8; plaintext.len() + TAG_SIZE];
        encrypt(
            &key,
            &nonce_prefix,
            counter,
            aad,
            plaintext,
            &mut ciphertext,
        )
        .unwrap();

        // Modify ciphertext
        ciphertext[0] ^= 0xFF;

        let mut decrypted = vec![0u8; ciphertext.len()];
        let result = decrypt(
            &key,
            &nonce_prefix,
            counter,
            aad,
            &ciphertext,
            &mut decrypted,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_in_place() {
        let key = [0x42u8; KEY_SIZE];
        let nonce = [0x12u8; NONCE_SIZE];
        let aad = b"header";
        let plaintext = b"Hello, HPN!";

        let mut buffer = vec![0u8; plaintext.len() + TAG_SIZE];
        buffer[..plaintext.len()].copy_from_slice(plaintext);

        let ct_len = encrypt_in_place(&key, &nonce, aad, &mut buffer, plaintext.len()).unwrap();
        assert_eq!(ct_len, plaintext.len() + TAG_SIZE);

        let pt_len = decrypt_in_place(&key, &nonce, aad, &mut buffer[..ct_len]).unwrap();
        assert_eq!(pt_len, plaintext.len());
        assert_eq!(&buffer[..pt_len], plaintext);
    }

    #[test]
    fn test_build_nonce() {
        let nonce_prefix = [0x01, 0x02, 0x03, 0x04];
        let counter = 0x0102_0304_0506_0708u64;

        let nonce = build_nonce(&nonce_prefix, counter);

        // First 4 bytes: nonce prefix
        assert_eq!(&nonce[..4], &[0x01, 0x02, 0x03, 0x04]);

        // Last 8 bytes: counter (big-endian)
        assert_eq!(
            &nonce[4..],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }

    #[test]
    fn test_empty_plaintext() {
        let key = [0x42u8; KEY_SIZE];
        let nonce_prefix = [0x00u8; 4];
        let counter = 1u64;
        let aad = b"header";
        let plaintext = b"";

        let mut ciphertext = vec![0u8; TAG_SIZE];
        let ct_len = encrypt(
            &key,
            &nonce_prefix,
            counter,
            aad,
            plaintext,
            &mut ciphertext,
        )
        .unwrap();
        assert_eq!(ct_len, TAG_SIZE);

        // Decrypt buffer must be at least ciphertext.len() for in-place decryption
        let mut decrypted = vec![0u8; ciphertext.len()];
        let pt_len = decrypt(
            &key,
            &nonce_prefix,
            counter,
            aad,
            &ciphertext,
            &mut decrypted,
        )
        .unwrap();
        assert_eq!(pt_len, 0);
    }

    #[test]
    fn test_nonce_uniqueness_across_sessions() {
        // SECURITY TEST: Verify that different session prefixes + counters = unique nonces

        let prefix1 = [0x11, 0x22, 0x33, 0x44];
        let prefix2 = [0x55, 0x66, 0x77, 0x88];
        let counter1 = 42u64;
        let counter2 = 99u64;

        let nonce_s1_c1 = build_nonce(&prefix1, counter1);
        let nonce_s1_c2 = build_nonce(&prefix1, counter2);
        let nonce_s2_c1 = build_nonce(&prefix2, counter1);
        let nonce_s2_c2 = build_nonce(&prefix2, counter2);

        // All nonces must be unique
        assert_ne!(nonce_s1_c1, nonce_s1_c2, "Same session, different counter");
        assert_ne!(nonce_s1_c1, nonce_s2_c1, "Different session, same counter");
        assert_ne!(
            nonce_s1_c1, nonce_s2_c2,
            "Different session, different counter"
        );
        assert_ne!(nonce_s1_c2, nonce_s2_c1, "Crossed session/counter");
        assert_ne!(nonce_s1_c2, nonce_s2_c2, "All different");
        assert_ne!(
            nonce_s2_c1, nonce_s2_c2,
            "Same session 2, different counter"
        );
    }

    #[test]
    fn test_nonce_prefix_isolation() {
        // SECURITY TEST: Even with same counter, different prefixes = different nonces

        let counter = 1_234_567_890_u64;

        // Collect nonces from 1000 different prefixes (simulating many sessions)
        let mut nonces = std::collections::HashSet::new();
        for i in 0u32..1000 {
            let prefix = [
                (i & 0xFF) as u8,
                ((i >> 8) & 0xFF) as u8,
                ((i >> 16) & 0xFF) as u8,
                ((i >> 24) & 0xFF) as u8,
            ];
            let nonce = build_nonce(&prefix, counter);

            // Ensure no collision
            assert!(
                nonces.insert(nonce),
                "Nonce collision detected at iteration {}",
                i
            );
        }

        // We should have 1000 unique nonces
        assert_eq!(nonces.len(), 1000);
    }

    #[test]
    fn test_nonce_uniqueness_concurrent() {
        // SECURITY TEST P0-1: Concurrent nonce generation must be unique
        // This test simulates multiple threads encrypting simultaneously
        // across multiple sessions, ensuring no nonce collisions occur.

        use std::collections::HashSet;
        use std::sync::{Arc, Mutex};
        use std::thread;

        const NUM_SESSIONS: u32 = 10;
        const NUM_THREADS_PER_SESSION: u32 = 4;
        const ENCRYPTIONS_PER_THREAD: u64 = 100;

        let all_nonces = Arc::new(Mutex::new(HashSet::new()));
        let mut handles = vec![];

        for session_id in 0..NUM_SESSIONS {
            // Each session gets a unique prefix (simulating different handshake secrets)
            let prefix = [
                (session_id & 0xFF) as u8,
                ((session_id >> 8) & 0xFF) as u8,
                ((session_id >> 16) & 0xFF) as u8,
                ((session_id >> 24) & 0xFF) as u8,
            ];

            for thread_id in 0..NUM_THREADS_PER_SESSION {
                let prefix_copy = prefix;
                let nonces_clone = Arc::clone(&all_nonces);

                let handle = thread::spawn(move || {
                    let mut local_nonces = Vec::new();

                    // Each thread generates sequential counters
                    let start_counter = thread_id as u64 * ENCRYPTIONS_PER_THREAD;
                    for i in 0..ENCRYPTIONS_PER_THREAD {
                        let counter = start_counter + i;
                        let nonce = build_nonce(&prefix_copy, counter);
                        local_nonces.push(nonce);
                    }

                    // Add all nonces to global set (lock only once per thread)
                    let mut global_nonces = nonces_clone.lock().unwrap();
                    for nonce in local_nonces {
                        assert!(
                            global_nonces.insert(nonce),
                            "Nonce collision detected in concurrent test!"
                        );
                    }
                });

                handles.push(handle);
            }
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify total unique nonces
        let final_nonces = all_nonces.lock().unwrap();
        let expected_total = NUM_SESSIONS * NUM_THREADS_PER_SESSION * ENCRYPTIONS_PER_THREAD as u32;
        assert_eq!(
            final_nonces.len(),
            expected_total as usize,
            "Expected {} unique nonces, got {}",
            expected_total,
            final_nonces.len()
        );
    }

    #[test]
    fn test_encrypt_decrypt_high_counter() {
        let key = [0x42u8; 32];
        let nonce_prefix = [0x99, 0xAA, 0xBB, 0xCC];
        let counter = u64::MAX - 100; // High but valid counter
        let plaintext = b"test message";
        let aad = b"additional data";

        let mut ciphertext = vec![0u8; plaintext.len() + TAG_SIZE];
        let ct_len = encrypt(
            &key,
            &nonce_prefix,
            counter,
            aad,
            plaintext,
            &mut ciphertext,
        )
        .unwrap();

        let mut decrypted = vec![0u8; ct_len];
        let pt_len = decrypt(
            &key,
            &nonce_prefix,
            counter,
            aad,
            &ciphertext,
            &mut decrypted,
        )
        .unwrap();

        assert_eq!(&decrypted[..pt_len], plaintext);
    }

    #[test]
    fn test_counter_exhaustion_rejected() {
        // SECURITY TEST: Verify that near-max counters are rejected to prevent nonce reuse
        let key = [0x42u8; 32];
        let nonce_prefix = [0x99, 0xAA, 0xBB, 0xCC];
        let plaintext = b"test message";
        let aad = b"additional data";
        let mut ciphertext = vec![0u8; plaintext.len() + TAG_SIZE];

        // u64::MAX - 1 should be rejected
        let result = encrypt(
            &key,
            &nonce_prefix,
            u64::MAX - 1,
            aad,
            plaintext,
            &mut ciphertext,
        );
        assert!(
            matches!(result, Err(CryptoError::CounterExhausted)),
            "Counter u64::MAX - 1 should be rejected"
        );

        // u64::MAX should also be rejected
        let result = encrypt(
            &key,
            &nonce_prefix,
            u64::MAX,
            aad,
            plaintext,
            &mut ciphertext,
        );
        assert!(
            matches!(result, Err(CryptoError::CounterExhausted)),
            "Counter u64::MAX should be rejected"
        );

        // u64::MAX - 2 should still work
        let result = encrypt(
            &key,
            &nonce_prefix,
            u64::MAX - 2,
            aad,
            plaintext,
            &mut ciphertext,
        );
        assert!(result.is_ok(), "Counter u64::MAX - 2 should be accepted");
    }

    #[test]
    fn test_precomputed_key_counter_exhaustion() {
        // SECURITY TEST: Verify PrecomputedKey also rejects exhausted counters
        let key = [0x42u8; 32];
        let precomputed = PrecomputedKey::new(&key).unwrap();
        let nonce_prefix = [0x99, 0xAA, 0xBB, 0xCC];
        let plaintext = b"test message";
        let aad = b"additional data";
        let mut ciphertext = vec![0u8; plaintext.len() + TAG_SIZE];

        let result =
            precomputed.encrypt(&nonce_prefix, u64::MAX - 1, aad, plaintext, &mut ciphertext);
        assert!(
            matches!(result, Err(CryptoError::CounterExhausted)),
            "PrecomputedKey should reject exhausted counter"
        );
    }

    #[test]
    fn test_encrypt_decrypt_zero_counter() {
        let key = [0x42u8; 32];
        let nonce_prefix = [0x11, 0x22, 0x33, 0x44];
        let counter = 0u64;
        let plaintext = b"zero counter test";
        let aad = b"aad";

        let mut ciphertext = vec![0u8; plaintext.len() + TAG_SIZE];
        encrypt(
            &key,
            &nonce_prefix,
            counter,
            aad,
            plaintext,
            &mut ciphertext,
        )
        .unwrap();

        let mut decrypted = vec![0u8; ciphertext.len()];
        let pt_len = decrypt(
            &key,
            &nonce_prefix,
            counter,
            aad,
            &ciphertext,
            &mut decrypted,
        )
        .unwrap();

        assert_eq!(&decrypted[..pt_len], plaintext);
    }

    #[test]
    fn test_encryption_key_size() {
        assert_eq!(KEY_SIZE, 32);
    }

    #[test]
    fn test_tag_size_constant() {
        assert_eq!(TAG_SIZE, 16);
    }

    #[test]
    fn test_nonce_size_constant() {
        assert_eq!(NONCE_SIZE, 12);
    }

    #[test]
    fn test_build_nonce_structure() {
        let prefix = [0xAA, 0xBB, 0xCC, 0xDD];
        let counter = 0x0102_0304_0506_0708u64;
        let nonce = build_nonce(&prefix, counter);

        // Verify nonce structure: prefix (4 bytes) + counter (8 bytes)
        assert_eq!(nonce.len(), 12);
        assert_eq!(&nonce[0..4], &prefix);
        // Counter should be in big-endian
        assert_eq!(&nonce[4..12], &counter.to_be_bytes());
    }

    #[test]
    fn test_decrypt_with_wrong_aad() {
        let key = [0x42u8; 32];
        let nonce_prefix = [1, 2, 3, 4];
        let counter = 42;
        let plaintext = b"secret message";
        let correct_aad = b"correct aad";
        let wrong_aad = b"wrong aad";

        let mut ciphertext = vec![0u8; plaintext.len() + TAG_SIZE];
        encrypt(
            &key,
            &nonce_prefix,
            counter,
            correct_aad,
            plaintext,
            &mut ciphertext,
        )
        .unwrap();

        let mut decrypted = vec![0u8; ciphertext.len()];
        let result = decrypt(
            &key,
            &nonce_prefix,
            counter,
            wrong_aad,
            &ciphertext,
            &mut decrypted,
        );

        // Should fail authentication
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_with_truncated_ciphertext() {
        let key = [0x42u8; 32];
        let nonce_prefix = [1, 2, 3, 4];
        let counter = 42;
        let plaintext = b"test";
        let aad = b"aad";

        let mut ciphertext = vec![0u8; plaintext.len() + TAG_SIZE];
        let ct_len = encrypt(
            &key,
            &nonce_prefix,
            counter,
            aad,
            plaintext,
            &mut ciphertext,
        )
        .unwrap();

        // Truncate ciphertext (remove last byte of tag)
        let truncated = &ciphertext[..ct_len - 1];

        let mut decrypted = vec![0u8; truncated.len()];
        let result = decrypt(&key, &nonce_prefix, counter, aad, truncated, &mut decrypted);

        // Should fail
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_large_message() {
        let key = [0x42u8; 32];
        let nonce_prefix = [0xFF, 0xEE, 0xDD, 0xCC];
        let counter = 1000;
        let large_plaintext = vec![0x42u8; 64 * 1024]; // 64 KB
        let aad = b"large message test";

        let mut ciphertext = vec![0u8; large_plaintext.len() + TAG_SIZE];
        let ct_len = encrypt(
            &key,
            &nonce_prefix,
            counter,
            aad,
            &large_plaintext,
            &mut ciphertext,
        )
        .unwrap();

        let mut decrypted = vec![0u8; ct_len];
        let pt_len = decrypt(
            &key,
            &nonce_prefix,
            counter,
            aad,
            &ciphertext,
            &mut decrypted,
        )
        .unwrap();

        assert_eq!(&decrypted[..pt_len], &large_plaintext[..]);
    }
}
