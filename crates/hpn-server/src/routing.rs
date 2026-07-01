//! IP routing configuration.
//!
//! Enables IP forwarding on Linux.

use std::io;

#[cfg(not(target_os = "linux"))]
use tracing::warn;

#[cfg(target_os = "linux")]
use crate::error::ServerError;
use crate::error::ServerResult;
#[cfg(target_os = "linux")]
use crate::validation::{
    validate_interface_name, validate_ipv4_address, validate_ipv4_cidr, validate_ipv6_address,
    validate_ipv6_cidr,
};

/// Enable IP forwarding on Linux.
#[cfg(target_os = "linux")]
pub fn enable_ip_forwarding() -> ServerResult<()> {
    use std::fs;
    use tracing::info;

    // Enable IPv4 forwarding
    fs::write("/proc/sys/net/ipv4/ip_forward", "1")
        .map_err(|e| ServerError::Config(format!("failed to enable IPv4 forwarding: {}", e)))?;

    info!("Enabled IPv4 forwarding");
    Ok(())
}

/// Enable IP forwarding (stub for non-Linux).
#[cfg(not(target_os = "linux"))]
pub fn enable_ip_forwarding() -> ServerResult<()> {
    warn!("IP forwarding not supported on this platform");
    Ok(())
}

/// Disable IP forwarding (restore original state).
#[cfg(target_os = "linux")]
pub fn disable_ip_forwarding() -> ServerResult<()> {
    use std::fs;
    use tracing::info;

    fs::write("/proc/sys/net/ipv4/ip_forward", "0")
        .map_err(|e| ServerError::Config(format!("failed to disable IPv4 forwarding: {}", e)))?;

    info!("Disabled IPv4 forwarding");
    Ok(())
}

/// Disable IP forwarding (stub for non-Linux).
#[cfg(not(target_os = "linux"))]
pub fn disable_ip_forwarding() -> ServerResult<()> {
    Ok(())
}

/// Check if IP forwarding is enabled.
#[cfg(target_os = "linux")]
pub fn is_ip_forwarding_enabled() -> bool {
    use std::fs;

    fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
        .map(|s| s.trim() == "1")
        .unwrap_or(false)
}

/// Check if IP forwarding is enabled (stub for non-Linux).
#[cfg(not(target_os = "linux"))]
pub fn is_ip_forwarding_enabled() -> bool {
    false
}

/// Add a route to the routing table.
#[cfg(target_os = "linux")]
pub fn add_route(network: &str, gateway: &str, device: &str) -> io::Result<()> {
    use std::process::Command;
    use tracing::info;

    // Validate inputs before using in commands
    validate_ipv4_cidr(network).map_err(|e| io::Error::other(e.to_string()))?;
    validate_ipv4_address(gateway).map_err(|e| io::Error::other(e.to_string()))?;
    validate_interface_name(device).map_err(|e| io::Error::other(e.to_string()))?;

    let output = Command::new("ip")
        .args(["route", "add", network, "via", gateway, "dev", device])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::other(stderr.to_string()));
    }

    info!("Added route {} via {} dev {}", network, gateway, device);
    Ok(())
}

/// Add a route (stub for non-Linux).
#[cfg(not(target_os = "linux"))]
pub fn add_route(_network: &str, _gateway: &str, _device: &str) -> io::Result<()> {
    Ok(())
}

/// Delete a route from the routing table.
#[cfg(target_os = "linux")]
pub fn delete_route(network: &str) -> io::Result<()> {
    use std::process::Command;
    use tracing::info;

    // Validate input before using in command
    validate_ipv4_cidr(network).map_err(|e| io::Error::other(e.to_string()))?;

    let output = Command::new("ip")
        .args(["route", "del", network])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::other(stderr.to_string()));
    }

    info!("Deleted route {}", network);
    Ok(())
}

/// Delete a route (stub for non-Linux).
#[cfg(not(target_os = "linux"))]
pub fn delete_route(_network: &str) -> io::Result<()> {
    Ok(())
}

/// Enable IPv6 forwarding on Linux.
#[cfg(target_os = "linux")]
pub fn enable_ipv6_forwarding() -> ServerResult<()> {
    use std::fs;
    use tracing::info;

    // Enable IPv6 forwarding
    fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1")
        .map_err(|e| ServerError::Config(format!("failed to enable IPv6 forwarding: {}", e)))?;

    info!("Enabled IPv6 forwarding");
    Ok(())
}

/// Enable IPv6 forwarding (stub for non-Linux).
#[cfg(not(target_os = "linux"))]
pub fn enable_ipv6_forwarding() -> ServerResult<()> {
    warn!("IPv6 forwarding not supported on this platform");
    Ok(())
}

/// Disable IPv6 forwarding (restore original state).
#[cfg(target_os = "linux")]
pub fn disable_ipv6_forwarding() -> ServerResult<()> {
    use std::fs;
    use tracing::info;

    fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "0")
        .map_err(|e| ServerError::Config(format!("failed to disable IPv6 forwarding: {}", e)))?;

    info!("Disabled IPv6 forwarding");
    Ok(())
}

/// Disable IPv6 forwarding (stub for non-Linux).
#[cfg(not(target_os = "linux"))]
pub fn disable_ipv6_forwarding() -> ServerResult<()> {
    Ok(())
}

/// Check if IPv6 forwarding is enabled.
#[cfg(target_os = "linux")]
pub fn is_ipv6_forwarding_enabled() -> bool {
    use std::fs;

    fs::read_to_string("/proc/sys/net/ipv6/conf/all/forwarding")
        .map(|s| s.trim() == "1")
        .unwrap_or(false)
}

/// Check if IPv6 forwarding is enabled (stub for non-Linux).
#[cfg(not(target_os = "linux"))]
pub fn is_ipv6_forwarding_enabled() -> bool {
    false
}

/// Add an IPv6 route to the routing table.
#[cfg(target_os = "linux")]
pub fn add_route_v6(network: &str, gateway: &str, device: &str) -> io::Result<()> {
    use std::process::Command;
    use tracing::info;

    // Validate inputs before using in commands
    validate_ipv6_cidr(network).map_err(|e| io::Error::other(e.to_string()))?;
    validate_ipv6_address(gateway).map_err(|e| io::Error::other(e.to_string()))?;
    validate_interface_name(device).map_err(|e| io::Error::other(e.to_string()))?;

    let output = Command::new("ip")
        .args(["-6", "route", "add", network, "via", gateway, "dev", device])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::other(stderr.to_string()));
    }

    info!(
        "Added IPv6 route {} via {} dev {}",
        network, gateway, device
    );
    Ok(())
}

/// Add an IPv6 route (stub for non-Linux).
#[cfg(not(target_os = "linux"))]
pub fn add_route_v6(_network: &str, _gateway: &str, _device: &str) -> io::Result<()> {
    Ok(())
}

/// Delete an IPv6 route from the routing table.
#[cfg(target_os = "linux")]
pub fn delete_route_v6(network: &str) -> io::Result<()> {
    use std::process::Command;
    use tracing::info;

    // Validate input before using in command
    validate_ipv6_cidr(network).map_err(|e| io::Error::other(e.to_string()))?;

    let output = Command::new("ip")
        .args(["-6", "route", "del", network])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::other(stderr.to_string()));
    }

    info!("Deleted IPv6 route {}", network);
    Ok(())
}

/// Delete an IPv6 route (stub for non-Linux).
#[cfg(not(target_os = "linux"))]
pub fn delete_route_v6(_network: &str) -> io::Result<()> {
    Ok(())
}
