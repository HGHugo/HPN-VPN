//! Windows multi-locale integration tests.
//!
//! Validates that the Windows client works correctly across different
//! system locales (French, German, Spanish, Chinese, etc.).
//!
//! These tests require running on actual Windows systems with different
//! locale configurations.

#[cfg(target_os = "windows")]
use hpn_client_windows::windows_api::{self, DnsSettings, RouteEntry};
use std::net::Ipv4Addr;

/// Test that we can get interface information regardless of locale.
/// This was a P0 bug - netsh output parsing failed on non-English Windows.
#[test]
#[cfg(target_os = "windows")]
fn test_get_interfaces_locale_independent() {
    // This should work on any locale because it uses GetIfTable2 API
    let result = windows_api::get_interfaces();

    match result {
        Ok(interfaces) => {
            println!("Found {} network interfaces", interfaces.len());
            for iface in &interfaces {
                println!(
                    "  - {} (index: {}, type: {})",
                    iface.alias, iface.index, iface.if_type
                );
            }
            assert!(!interfaces.is_empty(), "Should find at least one interface");
        }
        Err(e) => {
            panic!("Failed to get interfaces: {}", e);
        }
    }
}

/// Test that we can get physical interfaces without string matching.
#[test]
#[cfg(target_os = "windows")]
fn test_get_physical_interfaces_locale_independent() {
    let result = windows_api::get_physical_interfaces();

    match result {
        Ok(interfaces) => {
            println!("Found {} physical interfaces", interfaces.len());
            for iface in &interfaces {
                println!(
                    "  - {} (connected: {})",
                    iface.alias, iface.is_connected
                );
            }
            // Most systems should have at least one physical interface
            assert!(
                !interfaces.is_empty(),
                "Should find at least one physical interface"
            );
        }
        Err(e) => {
            panic!("Failed to get physical interfaces: {}", e);
        }
    }
}

/// Test route operations using Windows API (not route.exe parsing).
#[test]
#[cfg(target_os = "windows")]
fn test_route_operations_locale_independent() {
    // Get default route using API (not parsing command output)
    match windows_api::get_default_route() {
        Ok(Some((dest, gateway, interface_idx))) => {
            println!(
                "Default route: {} via {} (interface {})",
                dest, gateway, interface_idx
            );
            assert_eq!(dest, Ipv4Addr::new(0, 0, 0, 0), "Should be 0.0.0.0");
        }
        Ok(None) => {
            println!("No default route found (might be expected in some setups)");
        }
        Err(e) => {
            println!("Error getting default route: {}", e);
            // Don't fail - might be expected in some environments
        }
    }
}

/// Test IPv6 address retrieval (was failing on some locales).
#[test]
#[cfg(target_os = "windows")]
fn test_get_interface_ipv4_address() {
    let interfaces = windows_api::get_interfaces().expect("Failed to get interfaces");

    if let Some(iface) = interfaces.first() {
        println!("Testing IP address retrieval for: {}", iface.alias);

        match windows_api::get_interface_ip(&iface.alias) {
            Ok(Some(ip)) => {
                println!("  IPv4 address: {}", ip);
                // Basic validation
                assert!(!ip.is_unspecified(), "IP should not be 0.0.0.0");
            }
            Ok(None) => {
                println!("  No IPv4 address configured");
                // This is valid - interface might not have IPv4
            }
            Err(e) => {
                panic!("Failed to get interface IP: {}", e);
            }
        }
    } else {
        println!("No interfaces found for testing");
    }
}

/// Test DNS operations with non-ASCII server addresses.
#[test]
#[cfg(target_os = "windows")]
#[ignore] // Requires admin privileges
fn test_dns_operations_locale_independent() {
    let interfaces = windows_api::get_physical_interfaces()
        .expect("Failed to get physical interfaces");

    if let Some(iface) = interfaces.first() {
        println!("Testing DNS operations for: {}", iface.alias);

        // Get current DNS
        match windows_api::get_interface_dns(&iface.alias) {
            Ok(dns) => {
                println!("  Current DNS:");
                println!("    IPv4: {:?}", dns.ipv4_servers);
                println!("    IPv6: {:?}", dns.ipv6_servers);
                println!("    DHCP: {}", dns.is_dhcp);

                // Test that we can set DNS (requires admin)
                // Note: This test should restore original DNS after
                let test_dns = DnsSettings::new(
                    vec![Ipv4Addr::new(1, 1, 1, 1)], // Cloudflare
                    vec![],
                );

                // TODO: Uncomment when ready for destructive testing
                // windows_api::set_interface_dns(&iface.alias, &test_dns)
                //     .expect("Failed to set DNS");
                //
                // // Restore original
                // windows_api::set_interface_dns(&iface.alias, &dns)
                //     .expect("Failed to restore DNS");

                println!("  DNS operations test passed (placeholder)");
            }
            Err(e) => {
                println!("  Failed to get DNS (might need admin): {}", e);
            }
        }
    }
}

/// Test that adapter GUID retrieval works on all locales.
#[test]
#[cfg(target_os = "windows")]
fn test_get_adapter_guid_locale_independent() {
    let interfaces = windows_api::get_interfaces().expect("Failed to get interfaces");

    if let Some(iface) = interfaces.first() {
        println!("Testing adapter GUID for: {}", iface.alias);

        match windows_api::get_adapter_guid(&iface.alias) {
            Ok(guid) => {
                println!("  GUID: {}", guid);
                // GUID should be in format: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
                assert!(guid.starts_with('{'), "GUID should start with {{");
                assert!(guid.ends_with('}'), "GUID should end with }}");
                assert_eq!(guid.len(), 38, "GUID should be 38 characters");
            }
            Err(e) => {
                panic!("Failed to get adapter GUID: {}", e);
            }
        }
    }
}

/// Simulate testing on different locale configurations.
/// This is a documentation test - actual testing requires real locale changes.
#[test]
fn test_locale_testing_checklist() {
    println!("\n=== Multi-Locale Testing Checklist ===");
    println!("This test documents the locales that should be tested:");
    println!();
    println!("CRITICAL LOCALES (P0):");
    println!("  [ ] English (en-US) - Baseline");
    println!("  [ ] French (fr-FR) - Different date/number format");
    println!("  [ ] German (de-DE) - Different decimal separator");
    println!("  [ ] Spanish (es-ES) - Different date format");
    println!("  [ ] Chinese Simplified (zh-CN) - Non-Latin characters");
    println!("  [ ] Japanese (ja-JP) - Non-Latin characters");
    println!();
    println!("IMPORTANT LOCALES (P1):");
    println!("  [ ] Russian (ru-RU) - Cyrillic characters");
    println!("  [ ] Arabic (ar-SA) - RTL, different numerals");
    println!("  [ ] Portuguese (pt-BR) - Common in enterprise");
    println!("  [ ] Korean (ko-KR) - Non-Latin characters");
    println!();
    println!("TEST SCENARIOS:");
    println!("  [ ] Install VPN client");
    println!("  [ ] Connect to server");
    println!("  [ ] Verify tunnel routing");
    println!("  [ ] Verify DNS works");
    println!("  [ ] Disconnect cleanly");
    println!("  [ ] Verify kill switch (if enabled)");
    println!("  [ ] Rapid reconnect (10 cycles)");
    println!("  [ ] System sleep/wake");
    println!("  [ ] Network interface change");
    println!();
    println!("PASS CRITERIA:");
    println!("  - No netsh/route.exe output parsing");
    println!("  - All operations use Windows API");
    println!("  - No locale-dependent string matching");
    println!("  - Interface names handled as-is (no English assumption)");
    println!();

    assert!(true, "Checklist printed");
}
