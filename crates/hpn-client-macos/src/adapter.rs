//! macOS utun adapter implementation.
//!
//! Uses the tun-rs crate (exposed workspace-wide as `tun`) which provides
//! cross-platform TUN support, including macOS utun interfaces.

use std::io;
use std::sync::Mutex;

use async_trait::async_trait;
use tracing::{debug, info};
use tun::{DeviceBuilder, SyncDevice};

use hpn_client_core::tunnel::TunnelDevice;

use crate::error::MacosClientError;

/// macOS utun adapter wrapper.
pub struct UtunAdapter {
    /// The TUN device.
    device: Mutex<SyncDevice>,
    /// Device name (e.g., "utun3").
    name: String,
    /// Current MTU.
    mtu: u16,
}

impl UtunAdapter {
    /// Validate that a string is a safe interface name (prevents command injection).
    /// On macOS, utun names are always "utun" followed by digits.
    fn validate_interface_name(name: &str) -> bool {
        if !name.starts_with("utun") {
            return false;
        }
        let suffix = &name[4..];
        // Must have at least one digit and only digits
        !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit())
    }

    /// Create a new utun adapter.
    ///
    /// On macOS, the system assigns utun numbers automatically (utun0, utun1, etc.).
    pub fn create(mtu: u16) -> Result<Self, MacosClientError> {
        // Create a TUN device using DeviceBuilder
        // We don't set IP here - that's done later via configure_ip
        let device = DeviceBuilder::new().mtu(mtu).build_sync().map_err(|e| {
            MacosClientError::Adapter(format!("failed to create utun device: {}", e))
        })?;

        let name = device
            .name()
            .map_err(|e| MacosClientError::Adapter(format!("failed to get device name: {}", e)))?;

        // Validate interface name to prevent command injection
        // (defensive check - system should always return valid utun names)
        if !Self::validate_interface_name(&name) {
            return Err(MacosClientError::Adapter(format!(
                "invalid interface name from system: {}",
                name
            )));
        }

        info!("Created utun adapter: {} with MTU {}", name, mtu);

        Ok(Self {
            device: Mutex::new(device),
            name,
            mtu,
        })
    }

    /// Configure the adapter's IPv4 address using ifconfig.
    pub fn configure_ip(
        &self,
        ip: [u8; 4],
        _netmask: [u8; 4],
        peer_ip: [u8; 4],
    ) -> Result<(), MacosClientError> {
        use std::process::Command;

        let ip_str = format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
        let peer_str = format!(
            "{}.{}.{}.{}",
            peer_ip[0], peer_ip[1], peer_ip[2], peer_ip[3]
        );

        // On macOS, utun devices are point-to-point, so we set local and peer addresses
        let output = Command::new("ifconfig")
            .args([&self.name, "inet", &ip_str, &peer_str, "up"])
            .output()
            .map_err(|e| MacosClientError::Adapter(format!("failed to run ifconfig: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(MacosClientError::Adapter(format!(
                "ifconfig failed: {}",
                stderr
            )));
        }

        info!(
            "Configured {} with IP {} peer {}",
            self.name, ip_str, peer_str
        );

        Ok(())
    }

    /// Configure the adapter's IPv6 address using ifconfig.
    ///
    /// On macOS, IPv6 addresses are configured with a prefix length.
    /// For point-to-point links, we use a /128 prefix for the local address.
    pub fn configure_ipv6(&self, ip: [u8; 16], prefix_len: u8) -> Result<(), MacosClientError> {
        use std::net::Ipv6Addr;
        use std::process::Command;

        let ip_addr = Ipv6Addr::from(ip);
        let ip_str = format!("{}/{}", ip_addr, prefix_len);

        // On macOS, we use "inet6" to configure IPv6 on the utun device
        let output = Command::new("ifconfig")
            .args([&self.name, "inet6", &ip_str, "alias"])
            .output()
            .map_err(|e| {
                MacosClientError::Adapter(format!("failed to run ifconfig inet6: {}", e))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(MacosClientError::Adapter(format!(
                "ifconfig inet6 failed: {}",
                stderr
            )));
        }

        info!("Configured {} with IPv6 {}", self.name, ip_str);

        Ok(())
    }

    /// Configure both IPv4 and IPv6 addresses (dual-stack).
    pub fn configure_dual_stack(
        &self,
        ip_v4: [u8; 4],
        netmask_v4: [u8; 4],
        peer_ip_v4: [u8; 4],
        ip_v6: [u8; 16],
        prefix_len_v6: u8,
    ) -> Result<(), MacosClientError> {
        // Configure IPv4 first
        self.configure_ip(ip_v4, netmask_v4, peer_ip_v4)?;

        // Then configure IPv6
        self.configure_ipv6(ip_v6, prefix_len_v6)?;

        info!("Configured {} for dual-stack (IPv4 + IPv6)", self.name);

        Ok(())
    }

    /// Set the MTU using ifconfig.
    pub fn set_mtu_via_ifconfig(&self, mtu: u16) -> Result<(), MacosClientError> {
        use std::process::Command;

        let output = Command::new("ifconfig")
            .args([&self.name, "mtu", &mtu.to_string()])
            .output()
            .map_err(|e| MacosClientError::Adapter(format!("failed to run ifconfig: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(MacosClientError::Adapter(format!(
                "ifconfig mtu failed: {}",
                stderr
            )));
        }

        debug!("Set MTU to {} on {}", mtu, self.name);

        Ok(())
    }

    /// Get the adapter name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Receive a packet from the tunnel (uses tun-rs recv method).
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let device = self
            .device
            .lock()
            .map_err(|_| io::Error::other("failed to acquire device lock"))?;
        device.recv(buf)
    }

    /// Send a packet to the tunnel (uses tun-rs send method).
    pub fn send(&self, data: &[u8]) -> io::Result<usize> {
        let device = self
            .device
            .lock()
            .map_err(|_| io::Error::other("failed to acquire device lock"))?;
        device.send(data)
    }
}

#[async_trait]
impl TunnelDevice for UtunAdapter {
    fn send(&self, data: &[u8]) -> io::Result<usize> {
        UtunAdapter::send(self, data)
    }

    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        UtunAdapter::recv(self, buf)
    }

    fn set_mtu(&self, mtu: u16) -> io::Result<()> {
        self.set_mtu_via_ifconfig(mtu)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn configure(&self, ip: [u8; 4], netmask: [u8; 4], gateway: [u8; 4]) -> io::Result<()> {
        self.configure_ip(ip, netmask, gateway)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }

    fn configure_ipv6(
        &self,
        ip: [u8; 16],
        prefix_len: u8,
        _gateway: Option<[u8; 16]>,
    ) -> io::Result<()> {
        self.configure_ipv6(ip, prefix_len)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }

    fn supports_ipv6(&self) -> bool {
        true
    }

    fn close(&self) -> io::Result<()> {
        // The device will be closed when dropped
        debug!("Closing utun adapter: {}", self.name);
        Ok(())
    }
}

impl std::fmt::Debug for UtunAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UtunAdapter")
            .field("name", &self.name)
            .field("mtu", &self.mtu)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    // Note: Tests require root privileges to create utun devices
    // They are disabled by default

    #[test]
    #[ignore = "requires root privileges"]
    fn test_create_adapter() {
        use super::*;

        let adapter = UtunAdapter::create(1420).expect("failed to create adapter");
        assert!(adapter.name().starts_with("utun"));
    }
}
