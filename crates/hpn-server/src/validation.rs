//! Input validation for shell command parameters.
//!
//! This module provides validation functions to prevent command injection
//! and ensure parameters passed to system commands are safe.

use crate::error::{ServerError, ServerResult};

/// Maximum length for interface names (Linux IFNAMSIZ is 16 including null).
const MAX_INTERFACE_NAME_LEN: usize = 15;

/// Maximum length for an IPv4 CIDR string (e.g., "255.255.255.255/32").
const MAX_IPV4_CIDR_LEN: usize = 18;

/// Maximum length for an IPv6 CIDR string.
const MAX_IPV6_CIDR_LEN: usize = 49; // "xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx/128"

/// Validate a network interface name.
///
/// Interface names must:
/// - Be non-empty
/// - Be at most 15 characters (Linux IFNAMSIZ - 1)
/// - Contain only alphanumeric characters, hyphens, and underscores
///
/// # Examples
///
/// ```ignore
/// validate_interface_name("eth0")?;      // OK
/// validate_interface_name("hpn-tun0")?;  // OK
/// validate_interface_name("wg_vpn")?;    // OK
/// validate_interface_name("eth0; rm -rf /")?;  // Error
/// ```
pub fn validate_interface_name(name: &str) -> ServerResult<()> {
    if name.is_empty() {
        return Err(ServerError::Config(
            "interface name cannot be empty".to_string(),
        ));
    }

    if name.len() > MAX_INTERFACE_NAME_LEN {
        return Err(ServerError::Config(format!(
            "interface name '{}' exceeds maximum length of {} characters",
            name, MAX_INTERFACE_NAME_LEN
        )));
    }

    // Check each character: only allow alphanumeric, hyphen, underscore
    for (i, c) in name.chars().enumerate() {
        if !c.is_ascii_alphanumeric() && c != '-' && c != '_' {
            return Err(ServerError::Config(format!(
                "interface name '{}' contains invalid character '{}' at position {}; \
                 only alphanumeric characters, hyphens, and underscores are allowed",
                name, c, i
            )));
        }
    }

    // Interface names shouldn't start with a hyphen
    if name.starts_with('-') {
        return Err(ServerError::Config(format!(
            "interface name '{}' cannot start with a hyphen",
            name
        )));
    }

    Ok(())
}

/// Validate an IPv4 address in CIDR notation.
///
/// Format must be: `A.B.C.D/prefix` where:
/// - A, B, C, D are 0-255
/// - prefix is 0-32
///
/// # Examples
///
/// ```ignore
/// validate_ipv4_cidr("10.0.0.1/24")?;      // OK
/// validate_ipv4_cidr("192.168.1.0/16")?;   // OK
/// validate_ipv4_cidr("10.0.0.1")?;          // Error: missing prefix
/// validate_ipv4_cidr("10.0.0.1/33")?;       // Error: invalid prefix
/// validate_ipv4_cidr("256.0.0.1/24")?;      // Error: invalid octet
/// ```
pub fn validate_ipv4_cidr(cidr: &str) -> ServerResult<()> {
    if cidr.is_empty() {
        return Err(ServerError::Config("IPv4 CIDR cannot be empty".to_string()));
    }

    if cidr.len() > MAX_IPV4_CIDR_LEN {
        return Err(ServerError::Config(format!(
            "IPv4 CIDR '{}' exceeds maximum length",
            cidr
        )));
    }

    // Split into address and prefix
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(ServerError::Config(format!(
            "IPv4 CIDR '{}' must be in format 'A.B.C.D/prefix'",
            cidr
        )));
    }

    let addr = parts[0];
    let prefix_str = parts[1];

    // Validate address octets
    let octets: Vec<&str> = addr.split('.').collect();
    if octets.len() != 4 {
        return Err(ServerError::Config(format!(
            "IPv4 address '{}' must have exactly 4 octets",
            addr
        )));
    }

    for (i, octet) in octets.iter().enumerate() {
        // Check for empty octet
        if octet.is_empty() {
            return Err(ServerError::Config(format!(
                "IPv4 address '{}' has empty octet at position {}",
                addr, i
            )));
        }

        // Check for leading zeros (except for "0" itself)
        if octet.len() > 1 && octet.starts_with('0') {
            return Err(ServerError::Config(format!(
                "IPv4 address '{}' has invalid leading zero in octet at position {}",
                addr, i
            )));
        }

        // Parse and validate range
        match octet.parse::<u16>() {
            Ok(val) if val <= 255 => {}
            Ok(val) => {
                return Err(ServerError::Config(format!(
                    "IPv4 address '{}' has invalid octet {} (must be 0-255) at position {}",
                    addr, val, i
                )));
            }
            Err(_) => {
                return Err(ServerError::Config(format!(
                    "IPv4 address '{}' has non-numeric octet '{}' at position {}",
                    addr, octet, i
                )));
            }
        }
    }

    // Validate prefix length
    if prefix_str.is_empty() {
        return Err(ServerError::Config(format!(
            "IPv4 CIDR '{}' has empty prefix length",
            cidr
        )));
    }

    // Check for leading zeros in prefix
    if prefix_str.len() > 1 && prefix_str.starts_with('0') {
        return Err(ServerError::Config(format!(
            "IPv4 CIDR '{}' has invalid leading zero in prefix",
            cidr
        )));
    }

    match prefix_str.parse::<u8>() {
        Ok(prefix) if prefix <= 32 => {}
        Ok(prefix) => {
            return Err(ServerError::Config(format!(
                "IPv4 CIDR '{}' has invalid prefix {} (must be 0-32)",
                cidr, prefix
            )));
        }
        Err(_) => {
            return Err(ServerError::Config(format!(
                "IPv4 CIDR '{}' has non-numeric prefix '{}'",
                cidr, prefix_str
            )));
        }
    }

    Ok(())
}

/// Validate an IPv6 address in CIDR notation.
///
/// Supports standard IPv6 formats including:
/// - Full form: `2001:0db8:0000:0000:0000:0000:0000:0001/64`
/// - Compressed: `2001:db8::1/64`
/// - Link-local: `fe80::1/10`
/// - Unique local: `fd00::/8`
///
/// # Examples
///
/// ```ignore
/// validate_ipv6_cidr("2001:db8::1/64")?;   // OK
/// validate_ipv6_cidr("fd00::/8")?;          // OK
/// validate_ipv6_cidr("::1/128")?;           // OK
/// validate_ipv6_cidr("2001:db8::1")?;       // Error: missing prefix
/// validate_ipv6_cidr("2001:db8::1/129")?;   // Error: invalid prefix
/// ```
pub fn validate_ipv6_cidr(cidr: &str) -> ServerResult<()> {
    if cidr.is_empty() {
        return Err(ServerError::Config("IPv6 CIDR cannot be empty".to_string()));
    }

    if cidr.len() > MAX_IPV6_CIDR_LEN {
        return Err(ServerError::Config(format!(
            "IPv6 CIDR '{}' exceeds maximum length",
            cidr
        )));
    }

    // Split into address and prefix
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(ServerError::Config(format!(
            "IPv6 CIDR '{}' must be in format 'address/prefix'",
            cidr
        )));
    }

    let addr = parts[0];
    let prefix_str = parts[1];

    // Validate the IPv6 address using std::net parser
    if addr.parse::<std::net::Ipv6Addr>().is_err() {
        return Err(ServerError::Config(format!(
            "IPv6 address '{}' is not valid",
            addr
        )));
    }

    // Validate prefix length
    if prefix_str.is_empty() {
        return Err(ServerError::Config(format!(
            "IPv6 CIDR '{}' has empty prefix length",
            cidr
        )));
    }

    // Check for leading zeros in prefix (except for "0" itself)
    if prefix_str.len() > 1 && prefix_str.starts_with('0') {
        return Err(ServerError::Config(format!(
            "IPv6 CIDR '{}' has invalid leading zero in prefix",
            cidr
        )));
    }

    match prefix_str.parse::<u8>() {
        Ok(prefix) if prefix <= 128 => {}
        Ok(prefix) => {
            return Err(ServerError::Config(format!(
                "IPv6 CIDR '{}' has invalid prefix {} (must be 0-128)",
                cidr, prefix
            )));
        }
        Err(_) => {
            return Err(ServerError::Config(format!(
                "IPv6 CIDR '{}' has non-numeric prefix '{}'",
                cidr, prefix_str
            )));
        }
    }

    Ok(())
}

/// Validate an IPv4 address (without CIDR prefix).
///
/// # Examples
///
/// ```ignore
/// validate_ipv4_address("10.0.0.1")?;      // OK
/// validate_ipv4_address("192.168.1.1")?;   // OK
/// validate_ipv4_address("256.0.0.1")?;     // Error
/// ```
pub fn validate_ipv4_address(addr: &str) -> ServerResult<()> {
    if addr.is_empty() {
        return Err(ServerError::Config(
            "IPv4 address cannot be empty".to_string(),
        ));
    }

    // Use std::net parser for validation
    if addr.parse::<std::net::Ipv4Addr>().is_err() {
        return Err(ServerError::Config(format!(
            "IPv4 address '{}' is not valid",
            addr
        )));
    }

    Ok(())
}

/// Validate an IPv6 address (without CIDR prefix).
///
/// # Examples
///
/// ```ignore
/// validate_ipv6_address("2001:db8::1")?;   // OK
/// validate_ipv6_address("::1")?;           // OK
/// validate_ipv6_address("invalid")?;       // Error
/// ```
pub fn validate_ipv6_address(addr: &str) -> ServerResult<()> {
    if addr.is_empty() {
        return Err(ServerError::Config(
            "IPv6 address cannot be empty".to_string(),
        ));
    }

    // Use std::net parser for validation
    if addr.parse::<std::net::Ipv6Addr>().is_err() {
        return Err(ServerError::Config(format!(
            "IPv6 address '{}' is not valid",
            addr
        )));
    }

    Ok(())
}

/// Validate a network CIDR (either IPv4 or IPv6).
///
/// Automatically detects the IP version and validates accordingly.
pub fn validate_network_cidr(cidr: &str) -> ServerResult<()> {
    if cidr.contains(':') {
        validate_ipv6_cidr(cidr)
    } else {
        validate_ipv4_cidr(cidr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Interface name tests
    #[test]
    fn test_validate_interface_name_valid() {
        assert!(validate_interface_name("eth0").is_ok());
        assert!(validate_interface_name("hpn0").is_ok());
        assert!(validate_interface_name("wg0").is_ok());
        assert!(validate_interface_name("tun-vpn").is_ok());
        assert!(validate_interface_name("tun_vpn").is_ok());
        assert!(validate_interface_name("eth0-1_2").is_ok());
        assert!(validate_interface_name("a").is_ok());
        assert!(validate_interface_name("123456789012345").is_ok()); // 15 chars
    }

    #[test]
    fn test_validate_interface_name_empty() {
        assert!(validate_interface_name("").is_err());
    }

    #[test]
    fn test_validate_interface_name_too_long() {
        assert!(validate_interface_name("1234567890123456").is_err()); // 16 chars
        assert!(validate_interface_name("this_is_way_too_long").is_err());
    }

    #[test]
    fn test_validate_interface_name_invalid_chars() {
        assert!(validate_interface_name("eth0; rm -rf /").is_err());
        assert!(validate_interface_name("eth0`whoami`").is_err());
        assert!(validate_interface_name("eth0$(id)").is_err());
        assert!(validate_interface_name("eth0\neth1").is_err());
        assert!(validate_interface_name("eth0 ").is_err());
        assert!(validate_interface_name(" eth0").is_err());
        assert!(validate_interface_name("eth.0").is_err());
        assert!(validate_interface_name("eth/0").is_err());
        assert!(validate_interface_name("eth:0").is_err());
    }

    #[test]
    fn test_validate_interface_name_starts_with_hyphen() {
        assert!(validate_interface_name("-eth0").is_err());
    }

    // IPv4 CIDR tests
    #[test]
    fn test_validate_ipv4_cidr_valid() {
        assert!(validate_ipv4_cidr("10.0.0.1/24").is_ok());
        assert!(validate_ipv4_cidr("192.168.1.0/16").is_ok());
        assert!(validate_ipv4_cidr("0.0.0.0/0").is_ok());
        assert!(validate_ipv4_cidr("255.255.255.255/32").is_ok());
        assert!(validate_ipv4_cidr("172.16.0.0/12").is_ok());
    }

    #[test]
    fn test_validate_ipv4_cidr_empty() {
        assert!(validate_ipv4_cidr("").is_err());
    }

    #[test]
    fn test_validate_ipv4_cidr_no_prefix() {
        assert!(validate_ipv4_cidr("10.0.0.1").is_err());
    }

    #[test]
    fn test_validate_ipv4_cidr_invalid_prefix() {
        assert!(validate_ipv4_cidr("10.0.0.1/33").is_err());
        assert!(validate_ipv4_cidr("10.0.0.1/-1").is_err());
        assert!(validate_ipv4_cidr("10.0.0.1/abc").is_err());
        assert!(validate_ipv4_cidr("10.0.0.1/").is_err());
    }

    #[test]
    fn test_validate_ipv4_cidr_invalid_octets() {
        assert!(validate_ipv4_cidr("256.0.0.1/24").is_err());
        assert!(validate_ipv4_cidr("10.0.0.256/24").is_err());
        assert!(validate_ipv4_cidr("10.0.0/24").is_err());
        assert!(validate_ipv4_cidr("10.0.0.0.0/24").is_err());
        assert!(validate_ipv4_cidr("10..0.0/24").is_err());
        assert!(validate_ipv4_cidr("a.b.c.d/24").is_err());
    }

    #[test]
    fn test_validate_ipv4_cidr_leading_zeros() {
        assert!(validate_ipv4_cidr("10.0.0.01/24").is_err());
        assert!(validate_ipv4_cidr("10.0.0.1/01").is_err());
    }

    #[test]
    fn test_validate_ipv4_cidr_injection() {
        assert!(validate_ipv4_cidr("10.0.0.1/24; rm -rf /").is_err());
        assert!(validate_ipv4_cidr("10.0.0.1/24`whoami`").is_err());
        assert!(validate_ipv4_cidr("$(id)/24").is_err());
    }

    // IPv6 CIDR tests
    #[test]
    fn test_validate_ipv6_cidr_valid() {
        assert!(validate_ipv6_cidr("2001:db8::1/64").is_ok());
        assert!(validate_ipv6_cidr("fd00::/8").is_ok());
        assert!(validate_ipv6_cidr("::1/128").is_ok());
        assert!(validate_ipv6_cidr("::/0").is_ok());
        assert!(validate_ipv6_cidr("fe80::1/10").is_ok());
        assert!(validate_ipv6_cidr("2001:0db8:0000:0000:0000:0000:0000:0001/64").is_ok());
    }

    #[test]
    fn test_validate_ipv6_cidr_empty() {
        assert!(validate_ipv6_cidr("").is_err());
    }

    #[test]
    fn test_validate_ipv6_cidr_no_prefix() {
        assert!(validate_ipv6_cidr("2001:db8::1").is_err());
    }

    #[test]
    fn test_validate_ipv6_cidr_invalid_prefix() {
        assert!(validate_ipv6_cidr("2001:db8::1/129").is_err());
        assert!(validate_ipv6_cidr("2001:db8::1/-1").is_err());
        assert!(validate_ipv6_cidr("2001:db8::1/abc").is_err());
        assert!(validate_ipv6_cidr("2001:db8::1/").is_err());
    }

    #[test]
    fn test_validate_ipv6_cidr_invalid_address() {
        assert!(validate_ipv6_cidr("gggg::1/64").is_err());
        assert!(validate_ipv6_cidr("2001:db8:::/64").is_err());
        assert!(validate_ipv6_cidr("not-ipv6/64").is_err());
    }

    #[test]
    fn test_validate_ipv6_cidr_injection() {
        assert!(validate_ipv6_cidr("::1/64; rm -rf /").is_err());
        assert!(validate_ipv6_cidr("::1/64`whoami`").is_err());
    }

    // IPv4 address tests
    #[test]
    fn test_validate_ipv4_address_valid() {
        assert!(validate_ipv4_address("10.0.0.1").is_ok());
        assert!(validate_ipv4_address("192.168.1.1").is_ok());
        assert!(validate_ipv4_address("0.0.0.0").is_ok());
        assert!(validate_ipv4_address("255.255.255.255").is_ok());
    }

    #[test]
    fn test_validate_ipv4_address_invalid() {
        assert!(validate_ipv4_address("").is_err());
        assert!(validate_ipv4_address("256.0.0.1").is_err());
        assert!(validate_ipv4_address("10.0.0.1/24").is_err());
    }

    // IPv6 address tests
    #[test]
    fn test_validate_ipv6_address_valid() {
        assert!(validate_ipv6_address("2001:db8::1").is_ok());
        assert!(validate_ipv6_address("::1").is_ok());
        assert!(validate_ipv6_address("fe80::1").is_ok());
    }

    #[test]
    fn test_validate_ipv6_address_invalid() {
        assert!(validate_ipv6_address("").is_err());
        assert!(validate_ipv6_address("invalid").is_err());
        assert!(validate_ipv6_address("2001:db8::1/64").is_err());
    }

    // Network CIDR auto-detection tests
    #[test]
    fn test_validate_network_cidr() {
        assert!(validate_network_cidr("10.0.0.0/24").is_ok());
        assert!(validate_network_cidr("2001:db8::/32").is_ok());
        assert!(validate_network_cidr("invalid").is_err());
    }
}
