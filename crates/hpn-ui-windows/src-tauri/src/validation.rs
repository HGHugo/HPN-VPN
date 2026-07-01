//! Input validation for Tauri commands.
//!
//! Provides validation functions for user input to prevent injection attacks,
//! buffer overflows, and malformed data from reaching the VPN client.

use base64::{Engine, engine::general_purpose::STANDARD};
use regex::Regex;
use std::sync::LazyLock;

/// Pre-compiled regex for hostname validation (RFC 1123).
static HOSTNAME_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$")
        .expect("Invalid hostname regex")
});

/// Validate profile ID format.
///
/// Profile IDs must be alphanumeric with hyphens and underscores, 1-100 characters.
/// This prevents path traversal and injection attacks.
///
/// # Arguments
/// * `id` - The profile ID to validate
///
/// # Returns
/// * `Ok(())` if valid
/// * `Err(String)` with a user-friendly error message if invalid
pub fn validate_profile_id(id: &str) -> Result<(), String> {
    if id.is_empty() || id.len() > 100 {
        return Err("Profile ID must be 1-100 characters".to_string());
    }
    if !id
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err("Profile ID contains invalid characters".to_string());
    }
    Ok(())
}

/// Validate server address (hostname or IP).
///
/// Accepts valid IPv4, IPv6 addresses, or RFC 1123 hostnames.
/// Maximum length of 253 characters (DNS limit).
///
/// # Arguments
/// * `addr` - The server address to validate
///
/// # Returns
/// * `Ok(())` if valid
/// * `Err(String)` with a user-friendly error message if invalid
pub fn validate_server_address(addr: &str) -> Result<(), String> {
    if addr.is_empty() || addr.len() > 253 {
        return Err("Server address must be 1-253 characters".to_string());
    }

    // Check if valid IP address first
    if addr.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }

    // Not an IP, validate as hostname
    if !HOSTNAME_REGEX.is_match(addr) {
        return Err("Invalid server address format".to_string());
    }

    Ok(())
}

/// Validate port number.
///
/// Port must be between 1 and 65535 (0 is reserved).
///
/// # Arguments
/// * `port` - The port number to validate
///
/// # Returns
/// * `Ok(())` if valid
/// * `Err(String)` with a user-friendly error message if invalid
pub fn validate_port(port: u16) -> Result<(), String> {
    if port == 0 {
        return Err("Port must be between 1 and 65535".to_string());
    }
    Ok(())
}

/// Validate public key (base64 format).
///
/// Public keys must be valid base64-encoded data, 1-5000 characters.
/// The upper limit accommodates post-quantum key sizes (ML-KEM, ML-DSA).
///
/// # Arguments
/// * `key` - The base64-encoded public key to validate
///
/// # Returns
/// * `Ok(())` if valid
/// * `Err(String)` with a user-friendly error message if invalid
pub fn validate_public_key(key: &str) -> Result<(), String> {
    if key.is_empty() || key.len() > 5000 {
        return Err("Public key must be 1-5000 characters".to_string());
    }

    // Check base64 validity
    if STANDARD.decode(key).is_err() {
        return Err("Invalid public key format (must be base64)".to_string());
    }

    Ok(())
}

/// Validate profile name.
///
/// Profile names must be 1-100 characters. No character restrictions
/// to allow international names, but length is limited.
///
/// # Arguments
/// * `name` - The profile name to validate
///
/// # Returns
/// * `Ok(())` if valid
/// * `Err(String)` with a user-friendly error message if invalid
pub fn validate_profile_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 100 {
        return Err("Profile name must be 1-100 characters".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_profile_id() {
        // Valid IDs
        assert!(validate_profile_id("abc123").is_ok());
        assert!(validate_profile_id("my-profile").is_ok());
        assert!(validate_profile_id("my_profile").is_ok());
        assert!(validate_profile_id("a").is_ok());
        assert!(validate_profile_id("a".repeat(100).as_str()).is_ok());

        // Invalid IDs
        assert!(validate_profile_id("").is_err());
        assert!(validate_profile_id("a".repeat(101).as_str()).is_err());
        assert!(validate_profile_id("my profile").is_err());
        assert!(validate_profile_id("my/profile").is_err());
        assert!(validate_profile_id("../etc/passwd").is_err());
    }

    #[test]
    fn test_validate_server_address() {
        // Valid addresses
        assert!(validate_server_address("192.168.1.1").is_ok());
        assert!(validate_server_address("::1").is_ok());
        assert!(validate_server_address("2001:db8::1").is_ok());
        assert!(validate_server_address("example.com").is_ok());
        assert!(validate_server_address("vpn.example.com").is_ok());
        assert!(validate_server_address("vpn-1.example.com").is_ok());

        // Invalid addresses
        assert!(validate_server_address("").is_err());
        assert!(validate_server_address("a".repeat(254).as_str()).is_err());
        assert!(validate_server_address("-invalid.com").is_err());
        assert!(validate_server_address("invalid-.com").is_err());
        assert!(validate_server_address("inva lid.com").is_err());
    }

    #[test]
    fn test_validate_port() {
        // Valid ports
        assert!(validate_port(1).is_ok());
        assert!(validate_port(80).is_ok());
        assert!(validate_port(443).is_ok());
        assert!(validate_port(51820).is_ok());
        assert!(validate_port(65535).is_ok());

        // Invalid ports
        assert!(validate_port(0).is_err());
    }

    #[test]
    fn test_validate_public_key() {
        // Valid base64 keys
        assert!(validate_public_key("SGVsbG8gV29ybGQ=").is_ok());
        assert!(validate_public_key("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=").is_ok());

        // Invalid keys
        assert!(validate_public_key("").is_err());
        assert!(validate_public_key("not-base64!@#").is_err());
        assert!(validate_public_key("a".repeat(5001).as_str()).is_err());
    }

    #[test]
    fn test_validate_profile_name() {
        // Valid names
        assert!(validate_profile_name("My Profile").is_ok());
        assert!(validate_profile_name("Work VPN").is_ok());
        assert!(validate_profile_name("a").is_ok());
        assert!(validate_profile_name("a".repeat(100).as_str()).is_ok());

        // Invalid names
        assert!(validate_profile_name("").is_err());
        assert!(validate_profile_name("a".repeat(101).as_str()).is_err());
    }

    // ─── Audit H17 — adversarial input regression guards ─────────────────
    //
    // These tests pin the rejection paths that protect the IPC boundary
    // against malformed / malicious input from the webview. Each one
    // reproduces a concrete attack vector reviewers will think of first
    // (path traversal, NUL injection, RTL override homoglyphs, command
    // separators, etc.); a regression that opens any of them breaks the
    // test loudly at CI time.

    #[test]
    fn validate_profile_id_rejects_path_traversal() {
        // The id is used downstream as part of file paths (Keychain
        // service name on macOS, profiles store key on Windows). A
        // ../ component would let an attacker reach into other apps'
        // Keychain entries or the system store.
        for id in [
            "../etc/passwd",
            "..\\windows\\system32",
            "../../../../../",
            "./../../config",
            "%2e%2e%2fpasswd", // url-encoded
        ] {
            assert!(
                validate_profile_id(id).is_err(),
                "must reject path-traversal id: {id:?}"
            );
        }
    }

    #[test]
    fn validate_profile_id_rejects_nul_bytes_and_control_chars() {
        // NUL terminates C strings and is a classic way to truncate
        // logs / Keychain queries. Other control characters are
        // never legitimate in an id.
        for id in [
            "ok\0evil",
            "tab\there",
            "newline\nin\nid",
            "carriage\rreturn",
            "bell\x07",
            "delete\x7f",
        ] {
            assert!(
                validate_profile_id(id).is_err(),
                "must reject control-char id: {id:?}"
            );
        }
    }

    #[test]
    fn validate_profile_id_rejects_special_separators() {
        // Forward / backward slash, quotes, semicolons, pipes — every
        // shell / SQL / TOML-injection-flavoured separator. We allow
        // only [A-Za-z0-9_-].
        for id in [
            "a/b", "a\\b", "a;b", "a|b", "a&b", "a$b", "a`b", "a'b", "a\"b", "a:b", "a*b", "a?b",
            "a<b", "a>b", "a%b", "a@b", "a#b",
        ] {
            assert!(
                validate_profile_id(id).is_err(),
                "must reject separator id: {id:?}"
            );
        }
    }

    #[test]
    fn validate_profile_name_rejects_only_when_too_long_or_empty() {
        // Names allow Unicode (international users) so we deliberately
        // permit characters that look adversarial in a profile_id but
        // are legitimate in a display name.
        assert!(validate_profile_name("Maison ❤️").is_ok());
        assert!(validate_profile_name("会社 VPN").is_ok());
        assert!(validate_profile_name("Москва VPN").is_ok());
        // Boundary cases.
        assert!(validate_profile_name("").is_err());
        assert!(validate_profile_name(&"x".repeat(101)).is_err());
    }

    #[test]
    fn validate_server_address_rejects_double_dots_and_leading_dots() {
        // RFC 1123 forbids consecutive dots and leading dots. The
        // hostname regex must reject them — a helper that accepted
        // ".com" or "a..com" would let an attacker probe DNS
        // resolution paths the OS resolver would otherwise refuse.
        for addr in ["..com", "a..b.com", ".leading.com", "trailing.com.", "a.."] {
            assert!(
                validate_server_address(addr).is_err(),
                "must reject malformed hostname: {addr:?}"
            );
        }
    }

    #[test]
    fn validate_server_address_rejects_special_chars_in_hostname() {
        // A working hostname can only contain [A-Za-z0-9-.]. Anything
        // else is a typo at best, an injection attempt at worst.
        for addr in [
            "host name.com",
            "host_name.com", // underscores are not RFC 1123
            "host;.com",
            "host<.com",
            "host'.com",
            "host\".com",
            "host\\.com",
            "host`.com",
            "host\0.com",
        ] {
            assert!(
                validate_server_address(addr).is_err(),
                "must reject special-char hostname: {addr:?}"
            );
        }
    }

    #[test]
    fn validate_server_address_accepts_loopback_and_link_local() {
        // The validator is intentionally permissive on the *kind* of
        // address (we don't refuse private / loopback / link-local —
        // operators sometimes legitimately point HPN at a LAN endpoint
        // for testing). Anti-leak policy is enforced elsewhere.
        for addr in ["127.0.0.1", "::1", "10.0.0.1", "169.254.1.1", "fe80::1"] {
            assert!(
                validate_server_address(addr).is_ok(),
                "expected acceptance: {addr:?}"
            );
        }
    }

    #[test]
    fn validate_public_key_rejects_obvious_non_base64() {
        // Base64 alphabet is [A-Za-z0-9+/=]. Anything outside is
        // either a copy-paste corruption or a deliberate attempt to
        // smuggle bytes through the IPC.
        for key in [
            "not base64 with spaces!!!",
            "key with\nnewlines",
            "key\twith\ttabs",
            "AAAA\0BBBB",
            "key\u{202E}with-rtl-override", // Right-to-left override
            "<script>alert(1)</script>",
            "'; DROP TABLE profiles; --",
        ] {
            assert!(
                validate_public_key(key).is_err(),
                "must reject non-base64: {key:?}"
            );
        }
    }

    #[test]
    fn validate_public_key_accepts_realistic_pq_sizes() {
        // ML-DSA-87 public key is ~2592 bytes ≈ 3460 base64 chars.
        // ML-KEM-1024 public key is ~1568 bytes ≈ 2092 base64 chars.
        // The hybrid bundle (X25519 + ML-KEM) plus the 1-byte security
        // level prefix is currently ~2135 base64 chars at Level 5.
        // 5000 is the cap — generous enough for a future ML-DSA-87
        // certificate envelope.
        let large = "A".repeat(3500);
        assert!(
            validate_public_key(&large).is_ok(),
            "must accept realistic PQ key sizes"
        );
    }

    #[test]
    fn validate_port_rejects_only_zero() {
        // Privileged ports (1-1023) are accepted because the user may
        // legitimately point HPN at port 53 / 443 / 853 for TCP-fallback
        // testing. Only port 0 (= "ask the OS for any port") is
        // rejected — it's nonsensical for a remote endpoint and is
        // sometimes used as a probe value by malformed clients.
        assert!(validate_port(0).is_err());
        for p in [1u16, 53, 443, 853, 1024, 51820, 65535] {
            assert!(validate_port(p).is_ok(), "must accept port {p}");
        }
    }
}
