//! NAT configuration using iptables.
//!
//! Sets up MASQUERADE rules for VPN traffic.

use std::io;
#[cfg(target_os = "linux")]
use std::process::Command;

#[cfg(target_os = "linux")]
use tracing::info;
#[cfg(not(target_os = "linux"))]
use tracing::warn;

#[cfg(target_os = "linux")]
use crate::error::ServerError;
use crate::error::ServerResult;
#[cfg(target_os = "linux")]
use crate::validation::validate_ipv6_cidr;
use crate::validation::{validate_interface_name, validate_ipv4_cidr};

/// NAT manager for setting up masquerade rules.
pub struct NatManager {
    /// Source network (CIDR notation).
    #[allow(dead_code)]
    source_network: String,
    /// Output interface for NAT.
    #[allow(dead_code)]
    out_interface: Option<String>,
    /// Whether IPv4 rules are currently active.
    active: bool,
    /// IPv6 source network (optional).
    ipv6_network: Option<String>,
    /// Whether IPv6 rules are currently active.
    ipv6_active: bool,
}

impl NatManager {
    /// Create a new NAT manager.
    ///
    /// # Errors
    ///
    /// Returns an error if `source_network` is not a valid IPv4 CIDR or
    /// `out_interface` contains invalid characters.
    pub fn new(source_network: &str, out_interface: Option<String>) -> ServerResult<Self> {
        // Validate source network
        validate_ipv4_cidr(source_network)?;

        // Validate output interface if provided
        if let Some(ref iface) = out_interface {
            validate_interface_name(iface)?;
        }

        Ok(Self {
            source_network: source_network.to_string(),
            out_interface,
            active: false,
            ipv6_network: None,
            ipv6_active: false,
        })
    }

    /// Enable NAT (MASQUERADE) for the VPN network.
    #[cfg(target_os = "linux")]
    pub fn enable(&mut self) -> ServerResult<()> {
        if self.active {
            return Ok(());
        }

        let mut args = vec!["-t", "nat", "-A", "POSTROUTING", "-s", &self.source_network];

        if let Some(ref iface) = self.out_interface {
            args.push("-o");
            args.push(iface);
        }

        args.extend_from_slice(&["-j", "MASQUERADE"]);

        let output = Command::new("iptables")
            .args(&args)
            .output()
            .map_err(|e| ServerError::Nat(format!("failed to run iptables: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ServerError::Nat(format!("iptables failed: {}", stderr)));
        }

        self.active = true;
        info!("Enabled NAT for {}", self.source_network);
        Ok(())
    }

    /// Enable NAT (stub for non-Linux).
    #[cfg(not(target_os = "linux"))]
    pub fn enable(&mut self) -> ServerResult<()> {
        warn!("NAT not supported on this platform");
        self.active = true;
        Ok(())
    }

    /// Disable NAT (remove MASQUERADE rule).
    #[cfg(target_os = "linux")]
    pub fn disable(&mut self) -> ServerResult<()> {
        if !self.active {
            return Ok(());
        }

        let mut args = vec!["-t", "nat", "-D", "POSTROUTING", "-s", &self.source_network];

        if let Some(ref iface) = self.out_interface {
            args.push("-o");
            args.push(iface);
        }

        args.extend_from_slice(&["-j", "MASQUERADE"]);

        let output = Command::new("iptables")
            .args(&args)
            .output()
            .map_err(|e| ServerError::Nat(format!("failed to run iptables: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!("Failed to remove NAT rule: {}", stderr);
        }

        self.active = false;
        info!("Disabled NAT for {}", self.source_network);
        Ok(())
    }

    /// Disable NAT (stub for non-Linux).
    #[cfg(not(target_os = "linux"))]
    pub fn disable(&mut self) -> ServerResult<()> {
        self.active = false;
        Ok(())
    }

    /// Check if NAT rules are active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Enable IPv6 NAT (MASQUERADE) for the VPN network.
    #[cfg(target_os = "linux")]
    pub fn enable_ipv6(&mut self, ipv6_network: &str) -> ServerResult<()> {
        if self.ipv6_active {
            return Ok(());
        }

        // Validate IPv6 network before using in command
        validate_ipv6_cidr(ipv6_network)?;

        self.ipv6_network = Some(ipv6_network.to_string());

        let mut args = vec!["-t", "nat", "-A", "POSTROUTING", "-s", ipv6_network];

        if let Some(ref iface) = self.out_interface {
            args.push("-o");
            args.push(iface);
        }

        args.extend_from_slice(&["-j", "MASQUERADE"]);

        let output = Command::new("ip6tables")
            .args(&args)
            .output()
            .map_err(|e| ServerError::Nat(format!("failed to run ip6tables: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ServerError::Nat(format!("ip6tables failed: {}", stderr)));
        }

        self.ipv6_active = true;
        info!("Enabled IPv6 NAT for {}", ipv6_network);
        Ok(())
    }

    /// Enable IPv6 NAT (stub for non-Linux).
    #[cfg(not(target_os = "linux"))]
    pub fn enable_ipv6(&mut self, ipv6_network: &str) -> ServerResult<()> {
        use crate::validation::validate_ipv6_cidr;

        // Validate IPv6 network before storing
        validate_ipv6_cidr(ipv6_network)?;

        warn!("IPv6 NAT not supported on this platform");
        self.ipv6_network = Some(ipv6_network.to_string());
        self.ipv6_active = true;
        Ok(())
    }

    /// Disable IPv6 NAT (remove MASQUERADE rule).
    #[cfg(target_os = "linux")]
    pub fn disable_ipv6(&mut self) -> ServerResult<()> {
        if !self.ipv6_active {
            return Ok(());
        }

        let ipv6_network = match &self.ipv6_network {
            Some(n) => n.clone(),
            None => return Ok(()),
        };

        let mut args = vec!["-t", "nat", "-D", "POSTROUTING", "-s", &ipv6_network];

        if let Some(ref iface) = self.out_interface {
            args.push("-o");
            args.push(iface);
        }

        args.extend_from_slice(&["-j", "MASQUERADE"]);

        let output = Command::new("ip6tables")
            .args(&args)
            .output()
            .map_err(|e| ServerError::Nat(format!("failed to run ip6tables: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!("Failed to remove IPv6 NAT rule: {}", stderr);
        }

        self.ipv6_active = false;
        info!("Disabled IPv6 NAT for {}", ipv6_network);
        Ok(())
    }

    /// Disable IPv6 NAT (stub for non-Linux).
    #[cfg(not(target_os = "linux"))]
    pub fn disable_ipv6(&mut self) -> ServerResult<()> {
        self.ipv6_active = false;
        Ok(())
    }

    /// Check if IPv6 NAT rules are active.
    pub fn is_ipv6_active(&self) -> bool {
        self.ipv6_active
    }
}

impl Drop for NatManager {
    fn drop(&mut self) {
        if self.active {
            let _ = self.disable();
        }
        if self.ipv6_active {
            let _ = self.disable_ipv6();
        }
    }
}

/// Allow forwarding for a specific network.
#[cfg(target_os = "linux")]
pub fn allow_forward(network: &str, device: &str) -> io::Result<()> {
    // Validate inputs before using in commands
    validate_ipv4_cidr(network).map_err(|e| io::Error::other(e.to_string()))?;
    validate_interface_name(device).map_err(|e| io::Error::other(e.to_string()))?;

    // Allow forwarding from VPN network
    let output = Command::new("iptables")
        .args(["-A", "FORWARD", "-s", network, "-i", device, "-j", "ACCEPT"])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::other(stderr.to_string()));
    }

    // Allow forwarding to VPN network (established/related)
    let output = Command::new("iptables")
        .args([
            "-A",
            "FORWARD",
            "-d",
            network,
            "-o",
            device,
            "-m",
            "state",
            "--state",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::other(stderr.to_string()));
    }

    info!("Enabled forwarding for {} on {}", network, device);
    Ok(())
}

/// Allow forwarding (stub for non-Linux).
#[cfg(not(target_os = "linux"))]
pub fn allow_forward(network: &str, device: &str) -> io::Result<()> {
    // Validate inputs even on non-Linux for consistency
    validate_ipv4_cidr(network).map_err(|e| io::Error::other(e.to_string()))?;
    validate_interface_name(device).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(())
}

/// Remove forwarding rules for a network.
#[cfg(target_os = "linux")]
pub fn disallow_forward(network: &str, device: &str) -> io::Result<()> {
    // Validate inputs before using in commands
    validate_ipv4_cidr(network).map_err(|e| io::Error::other(e.to_string()))?;
    validate_interface_name(device).map_err(|e| io::Error::other(e.to_string()))?;

    let _ = Command::new("iptables")
        .args(["-D", "FORWARD", "-s", network, "-i", device, "-j", "ACCEPT"])
        .output();

    let _ = Command::new("iptables")
        .args([
            "-D",
            "FORWARD",
            "-d",
            network,
            "-o",
            device,
            "-m",
            "state",
            "--state",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ])
        .output();

    info!("Disabled forwarding for {} on {}", network, device);
    Ok(())
}

/// Remove forwarding rules (stub for non-Linux).
#[cfg(not(target_os = "linux"))]
pub fn disallow_forward(network: &str, device: &str) -> io::Result<()> {
    // Validate inputs even on non-Linux for consistency
    validate_ipv4_cidr(network).map_err(|e| io::Error::other(e.to_string()))?;
    validate_interface_name(device).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nat_manager_new() {
        let manager = NatManager::new("10.99.0.0/24", None).unwrap();
        assert!(!manager.is_active());
        assert!(!manager.is_ipv6_active());
    }

    #[test]
    fn test_nat_manager_new_with_interface() {
        let manager = NatManager::new("10.99.0.0/24", Some("eth0".to_string())).unwrap();
        assert!(!manager.is_active());
    }

    #[test]
    fn test_nat_manager_new_invalid_network() {
        // Invalid CIDR should fail
        assert!(NatManager::new("invalid", None).is_err());
        assert!(NatManager::new("10.0.0.1", None).is_err()); // Missing prefix
        assert!(NatManager::new("256.0.0.0/24", None).is_err());
    }

    #[test]
    fn test_nat_manager_new_invalid_interface() {
        // Invalid interface name should fail
        assert!(NatManager::new("10.0.0.0/24", Some("eth0; rm -rf /".to_string())).is_err());
        assert!(NatManager::new("10.0.0.0/24", Some(String::new())).is_err());
    }

    #[test]
    fn test_nat_manager_enable_disable() {
        let mut manager = NatManager::new("10.99.0.0/24", None).unwrap();

        // Enable (may fail on non-Linux or non-root, but should not panic)
        let _ = manager.enable();

        // Disable should always succeed
        assert!(manager.disable().is_ok());
        assert!(!manager.is_active());
    }

    #[test]
    fn test_nat_manager_enable_twice() {
        let mut manager = NatManager::new("10.99.0.0/24", None).unwrap();

        // First enable (may fail on non-Linux or non-root)
        let first_result = manager.enable();

        // Second enable should be idempotent IF first succeeded
        let second_result = manager.enable();

        // If first succeeded, second should succeed (idempotent)
        // If first failed, second will also fail (not on Linux/root)
        if first_result.is_ok() {
            assert!(second_result.is_ok(), "Second enable should be idempotent");
        } else {
            // Both should fail consistently on non-Linux/non-root
            assert!(
                second_result.is_err(),
                "Both enables should fail consistently"
            );
        }
    }

    #[test]
    fn test_nat_manager_disable_when_not_active() {
        let mut manager = NatManager::new("10.99.0.0/24", None).unwrap();

        // Disable when not active should succeed
        assert!(manager.disable().is_ok());
    }

    #[test]
    fn test_nat_manager_ipv6_enable_disable() {
        let mut manager = NatManager::new("10.99.0.0/24", None).unwrap();

        // Enable IPv6 (may fail on non-Linux or non-root, but should not panic)
        let _ = manager.enable_ipv6("fd99::/64");

        // Disable should always succeed
        assert!(manager.disable_ipv6().is_ok());
        assert!(!manager.is_ipv6_active());
    }

    #[test]
    fn test_nat_manager_ipv6_enable_invalid() {
        let mut manager = NatManager::new("10.99.0.0/24", None).unwrap();

        // Invalid IPv6 CIDR should fail validation
        assert!(manager.enable_ipv6("invalid").is_err());
        assert!(manager.enable_ipv6("::1").is_err()); // Missing prefix
    }

    #[test]
    fn test_nat_manager_ipv6_enable_twice() {
        let mut manager = NatManager::new("10.99.0.0/24", None).unwrap();

        // First enable (may fail on non-Linux or non-root)
        let first_result = manager.enable_ipv6("fd99::/64");

        // Second enable should be idempotent IF first succeeded
        let second_result = manager.enable_ipv6("fd99::/64");

        // If first succeeded, second should succeed (idempotent)
        // If first failed, second will also fail (not on Linux/root)
        if first_result.is_ok() {
            assert!(
                second_result.is_ok(),
                "Second enable_ipv6 should be idempotent"
            );
        } else {
            // Both should fail consistently on non-Linux/non-root
            assert!(
                second_result.is_err(),
                "Both enable_ipv6 should fail consistently"
            );
        }
    }

    #[test]
    fn test_nat_manager_ipv6_disable_when_not_active() {
        let mut manager = NatManager::new("10.99.0.0/24", None).unwrap();

        // Disable when not active should succeed
        assert!(manager.disable_ipv6().is_ok());
    }

    #[test]
    fn test_nat_manager_drop_cleanup() {
        // Create in a scope so it gets dropped
        {
            let mut manager = NatManager::new("10.99.0.0/24", None).unwrap();
            let _ = manager.enable();
            let _ = manager.enable_ipv6("fd99::/64");
            // Manager should clean up on drop
        }
        // If we get here without panic, cleanup worked
    }

    #[test]
    fn test_allow_forward() {
        // Should not panic even if iptables fails
        let result = allow_forward("10.99.0.0/24", "hpn0");
        // On non-Linux or non-root, this may fail, but that's expected
        let _ = result;
    }

    #[test]
    fn test_allow_forward_invalid_input() {
        // Invalid network should fail validation
        assert!(allow_forward("invalid", "hpn0").is_err());
        // Invalid interface should fail validation
        assert!(allow_forward("10.0.0.0/24", "eth0; rm -rf /").is_err());
    }

    #[test]
    fn test_disallow_forward() {
        // Should not panic even if iptables fails
        let result = disallow_forward("10.99.0.0/24", "hpn0");
        // On non-Linux or non-root, this may fail, but that's expected
        let _ = result;
    }

    #[test]
    fn test_disallow_forward_invalid_input() {
        // Invalid network should fail validation
        assert!(disallow_forward("invalid", "hpn0").is_err());
        // Invalid interface should fail validation
        assert!(disallow_forward("10.0.0.0/24", "eth0`id`").is_err());
    }

    #[test]
    fn test_nat_manager_with_different_networks() {
        let manager1 = NatManager::new("192.168.1.0/24", None).unwrap();
        let manager2 = NatManager::new("172.16.0.0/16", Some("wlan0".to_string())).unwrap();

        assert!(!manager1.is_active());
        assert!(!manager2.is_active());
    }
}
