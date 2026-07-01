//! Input validation for Tauri commands.

use base64::{Engine, engine::general_purpose::STANDARD};
use regex::Regex;
use std::sync::LazyLock;

static HOSTNAME_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$",
    )
    .expect("Invalid hostname regex")
});

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

pub fn validate_server_address(addr: &str) -> Result<(), String> {
    if addr.is_empty() || addr.len() > 253 {
        return Err("Server address must be 1-253 characters".to_string());
    }
    if addr.parse::<std::net::IpAddr>().is_err() && !HOSTNAME_REGEX.is_match(addr) {
        return Err("Invalid server address format".to_string());
    }
    Ok(())
}

pub fn validate_port(port: u16) -> Result<(), String> {
    if port == 0 {
        return Err("Port must be between 1 and 65535".to_string());
    }
    Ok(())
}

pub fn validate_public_key(key: &str) -> Result<(), String> {
    if key.is_empty() || key.len() > 5000 {
        return Err("Public key must be 1-5000 characters".to_string());
    }
    if STANDARD.decode(key).is_err() {
        return Err("Invalid public key format (must be base64)".to_string());
    }
    Ok(())
}

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
        assert!(validate_profile_id("abc123").is_ok());
        assert!(validate_profile_id("my-profile").is_ok());
        assert!(validate_profile_id("").is_err());
        assert!(validate_profile_id("a".repeat(101).as_str()).is_err());
        assert!(validate_profile_id("bad id").is_err());
    }

    #[test]
    fn test_validate_server_address() {
        assert!(validate_server_address("192.168.1.1").is_ok());
        assert!(validate_server_address("2001:db8::1").is_ok());
        assert!(validate_server_address("vpn.example.com").is_ok());
        assert!(validate_server_address("").is_err());
        assert!(validate_server_address("-invalid.com").is_err());
    }

    #[test]
    fn test_validate_port() {
        assert!(validate_port(1).is_ok());
        assert!(validate_port(65535).is_ok());
        assert!(validate_port(0).is_err());
    }

    #[test]
    fn test_validate_public_key() {
        assert!(validate_public_key("SGVsbG8=").is_ok());
        assert!(validate_public_key("").is_err());
        assert!(validate_public_key("not-base64").is_err());
    }

    #[test]
    fn test_validate_profile_name() {
        assert!(validate_profile_name("Work VPN").is_ok());
        assert!(validate_profile_name("").is_err());
        assert!(validate_profile_name("a".repeat(101).as_str()).is_err());
    }

    // ─── Audit H17 — adversarial input regression guards ─────────────────
    //
    // Same coverage as the Windows side (hpn-ui-windows::validation). See
    // that file's matching block for the per-test rationale.

    #[test]
    fn validate_profile_id_rejects_path_traversal() {
        for id in [
            "../etc/passwd",
            "..\\windows\\system32",
            "../../../../../",
            "./../../config",
            "%2e%2e%2fpasswd",
        ] {
            assert!(
                validate_profile_id(id).is_err(),
                "must reject path-traversal id: {id:?}"
            );
        }
    }

    #[test]
    fn validate_profile_id_rejects_nul_bytes_and_control_chars() {
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
    fn validate_profile_name_accepts_unicode() {
        // Names allow Unicode (international users).
        assert!(validate_profile_name("Maison ❤️").is_ok());
        assert!(validate_profile_name("会社 VPN").is_ok());
        assert!(validate_profile_name("Москва VPN").is_ok());
    }

    #[test]
    fn validate_server_address_rejects_double_dots_and_leading_dots() {
        for addr in ["..com", "a..b.com", ".leading.com", "trailing.com.", "a.."] {
            assert!(
                validate_server_address(addr).is_err(),
                "must reject malformed hostname: {addr:?}"
            );
        }
    }

    #[test]
    fn validate_server_address_rejects_special_chars_in_hostname() {
        for addr in [
            "host name.com",
            "host_name.com",
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
        for addr in ["127.0.0.1", "::1", "10.0.0.1", "169.254.1.1", "fe80::1"] {
            assert!(
                validate_server_address(addr).is_ok(),
                "expected acceptance: {addr:?}"
            );
        }
    }

    #[test]
    fn validate_public_key_rejects_obvious_non_base64() {
        for key in [
            "not base64 with spaces!!!",
            "key with\nnewlines",
            "key\twith\ttabs",
            "AAAA\0BBBB",
            "key\u{202E}with-rtl-override",
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
        let large = "A".repeat(3500);
        assert!(
            validate_public_key(&large).is_ok(),
            "must accept realistic PQ key sizes"
        );
    }

    #[test]
    fn validate_port_rejects_only_zero() {
        assert!(validate_port(0).is_err());
        for p in [1u16, 53, 443, 853, 1024, 51820, 65535] {
            assert!(validate_port(p).is_ok(), "must accept port {p}");
        }
    }
}
