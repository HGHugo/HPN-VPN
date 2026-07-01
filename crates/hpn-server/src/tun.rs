//! TUN device wrapper for Linux.
//!
//! Creates and manages a TUN device for routing VPN traffic.
//! Supports dual-stack IPv4/IPv6.

use std::io;

use tracing::{debug, info};

use crate::error::ServerResult;

/// TUN device for VPN traffic.
pub struct TunDevice {
    /// Device name.
    name: String,
    /// TUN device handle (platform-specific).
    #[cfg(target_os = "linux")]
    device: Option<tun::SyncDevice>,
    /// MTU.
    mtu: u16,
    /// IPv6 address configured (if dual-stack).
    ipv6_addr: Option<[u8; 16]>,
    /// IPv6 prefix length.
    ipv6_prefix: Option<u8>,
}

impl TunDevice {
    /// Create a new TUN device (IPv4 only).
    #[cfg(target_os = "linux")]
    pub fn create(name: &str, ip: [u8; 4], netmask: [u8; 4], mtu: u16) -> ServerResult<Self> {
        use crate::error::ServerError;

        let ip_str = format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
        let prefix_len = netmask_to_prefix(netmask);

        let device = tun::DeviceBuilder::new()
            .name(name)
            .ipv4(ip_str, prefix_len, None)
            .mtu(mtu)
            .build_sync()
            .map_err(|e| ServerError::Tun(format!("failed to create TUN device: {}", e)))?;

        info!(
            "Created TUN device {} with IP {}.{}.{}.{}",
            name, ip[0], ip[1], ip[2], ip[3]
        );

        Ok(Self {
            name: name.to_string(),
            device: Some(device),
            mtu,
            ipv6_addr: None,
            ipv6_prefix: None,
        })
    }

    /// Create a stub TUN device (non-Linux).
    #[cfg(not(target_os = "linux"))]
    pub fn create(name: &str, ip: [u8; 4], _netmask: [u8; 4], mtu: u16) -> ServerResult<Self> {
        info!(
            "TUN device {} (stub) with IP {}.{}.{}.{}",
            name, ip[0], ip[1], ip[2], ip[3]
        );
        Ok(Self {
            name: name.to_string(),
            mtu,
            ipv6_addr: None,
            ipv6_prefix: None,
        })
    }

    /// Create a dual-stack TUN device (IPv4 + IPv6).
    #[cfg(target_os = "linux")]
    pub fn create_dual_stack(
        name: &str,
        ipv4: [u8; 4],
        netmask: [u8; 4],
        ipv6: [u8; 16],
        ipv6_prefix: u8,
        mtu: u16,
    ) -> ServerResult<Self> {
        use crate::error::ServerError;
        use std::net::Ipv6Addr;

        let ipv4_str = format!("{}.{}.{}.{}", ipv4[0], ipv4[1], ipv4[2], ipv4[3]);
        let ipv6_addr = Ipv6Addr::from(ipv6);
        let ipv6_str = ipv6_addr.to_string();
        let prefix_len = netmask_to_prefix(netmask);

        let device = tun::DeviceBuilder::new()
            .name(name)
            .ipv4(ipv4_str, prefix_len, None)
            .ipv6(ipv6_str, ipv6_prefix)
            .mtu(mtu)
            .build_sync()
            .map_err(|e| ServerError::Tun(format!("failed to create TUN device: {}", e)))?;

        info!(
            "Created dual-stack TUN device {} with IPv4 {}.{}.{}.{} and IPv6 {}",
            name, ipv4[0], ipv4[1], ipv4[2], ipv4[3], ipv6_addr
        );

        Ok(Self {
            name: name.to_string(),
            device: Some(device),
            mtu,
            ipv6_addr: Some(ipv6),
            ipv6_prefix: Some(ipv6_prefix),
        })
    }

    /// Create a dual-stack TUN device stub (non-Linux).
    #[cfg(not(target_os = "linux"))]
    pub fn create_dual_stack(
        name: &str,
        ipv4: [u8; 4],
        _netmask: [u8; 4],
        ipv6: [u8; 16],
        ipv6_prefix: u8,
        mtu: u16,
    ) -> ServerResult<Self> {
        use std::net::Ipv6Addr;

        let ipv6_addr = Ipv6Addr::from(ipv6);
        info!(
            "TUN device {} (stub) with IPv4 {}.{}.{}.{} and IPv6 {}/{}",
            name, ipv4[0], ipv4[1], ipv4[2], ipv4[3], ipv6_addr, ipv6_prefix
        );
        Ok(Self {
            name: name.to_string(),
            mtu,
            ipv6_addr: Some(ipv6),
            ipv6_prefix: Some(ipv6_prefix),
        })
    }

    /// Check if this TUN device has IPv6 configured.
    pub fn has_ipv6(&self) -> bool {
        self.ipv6_addr.is_some()
    }

    /// Get the configured IPv6 address.
    pub fn ipv6_addr(&self) -> Option<[u8; 16]> {
        self.ipv6_addr
    }

    /// Get the IPv6 prefix length.
    pub fn ipv6_prefix(&self) -> Option<u8> {
        self.ipv6_prefix
    }

    /// Get the device name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the MTU.
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Take ownership of the underlying device.
    /// After this call, the TunDevice can no longer be used for I/O.
    #[cfg(target_os = "linux")]
    pub fn take_device(&mut self) -> Option<tun::SyncDevice> {
        self.device.take()
    }

    /// Take ownership of the underlying device (stub for non-Linux).
    #[cfg(not(target_os = "linux"))]
    pub fn take_device(&mut self) -> Option<()> {
        None
    }

    /// Read a packet from the TUN device.
    #[cfg(target_os = "linux")]
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(ref device) = self.device {
            device.recv(buf)
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "device not initialized",
            ))
        }
    }

    /// Read a packet (stub for non-Linux).
    #[cfg(not(target_os = "linux"))]
    pub fn recv(&self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TUN not supported on this platform",
        ))
    }

    /// Write a packet to the TUN device.
    #[cfg(target_os = "linux")]
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        if let Some(ref device) = self.device {
            device.send(buf)
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "device not initialized",
            ))
        }
    }

    /// Write a packet (stub for non-Linux).
    #[cfg(not(target_os = "linux"))]
    pub fn send(&self, _buf: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TUN not supported on this platform",
        ))
    }

    /// Close the TUN device.
    pub fn close(&mut self) {
        debug!("Closing TUN device {}", self.name);
        #[cfg(target_os = "linux")]
        {
            self.device = None;
        }
    }
}

impl Drop for TunDevice {
    fn drop(&mut self) {
        self.close();
    }
}

/// Convert a netmask to a prefix length.
#[cfg(target_os = "linux")]
fn netmask_to_prefix(netmask: [u8; 4]) -> u8 {
    let mask = u32::from_be_bytes(netmask);
    mask.leading_ones() as u8
}

/// IP version of a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}

/// Extract IP version from a packet.
pub fn get_ip_version(packet: &[u8]) -> Option<IpVersion> {
    if packet.is_empty() {
        return None;
    }
    match packet[0] >> 4 {
        4 => Some(IpVersion::V4),
        6 => Some(IpVersion::V6),
        _ => None,
    }
}

/// Extract destination IP from an IPv4 packet.
pub fn get_destination_ip(packet: &[u8]) -> Option<[u8; 4]> {
    // IPv4 header: destination IP is at bytes 16-19
    if packet.len() >= 20 && (packet[0] >> 4) == 4 {
        let mut ip = [0u8; 4];
        ip.copy_from_slice(&packet[16..20]);
        Some(ip)
    } else {
        None
    }
}

/// Extract source IP from an IPv4 packet.
pub fn get_source_ip(packet: &[u8]) -> Option<[u8; 4]> {
    // IPv4 header: source IP is at bytes 12-15
    if packet.len() >= 20 && (packet[0] >> 4) == 4 {
        let mut ip = [0u8; 4];
        ip.copy_from_slice(&packet[12..16]);
        Some(ip)
    } else {
        None
    }
}

/// Extract destination IP from an IPv6 packet.
pub fn get_destination_ipv6(packet: &[u8]) -> Option<[u8; 16]> {
    // IPv6 header: destination IP is at bytes 24-39
    if packet.len() >= 40 && (packet[0] >> 4) == 6 {
        let mut ip = [0u8; 16];
        ip.copy_from_slice(&packet[24..40]);
        Some(ip)
    } else {
        None
    }
}

/// Extract source IP from an IPv6 packet.
pub fn get_source_ipv6(packet: &[u8]) -> Option<[u8; 16]> {
    // IPv6 header: source IP is at bytes 8-23
    if packet.len() >= 40 && (packet[0] >> 4) == 6 {
        let mut ip = [0u8; 16];
        ip.copy_from_slice(&packet[8..24]);
        Some(ip)
    } else {
        None
    }
}

/// Destination address enum for dual-stack routing.
#[derive(Debug, Clone, Copy)]
pub enum DestinationAddr {
    V4([u8; 4]),
    V6([u8; 16]),
}

/// Extract destination address from an IP packet (v4 or v6).
pub fn get_destination_addr(packet: &[u8]) -> Option<DestinationAddr> {
    match get_ip_version(packet)? {
        IpVersion::V4 => get_destination_ip(packet).map(DestinationAddr::V4),
        IpVersion::V6 => get_destination_ipv6(packet).map(DestinationAddr::V6),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_destination_ip() {
        // Minimal IPv4 header with destination 192.168.1.1
        let mut packet = [0u8; 20];
        packet[0] = 0x45; // IPv4, header length 5
        packet[16..20].copy_from_slice(&[192, 168, 1, 1]);

        let dst = get_destination_ip(&packet).unwrap();
        assert_eq!(dst, [192, 168, 1, 1]);
    }

    #[test]
    fn test_get_source_ip() {
        let mut packet = [0u8; 20];
        packet[0] = 0x45;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);

        let src = get_source_ip(&packet).unwrap();
        assert_eq!(src, [10, 0, 0, 2]);
    }

    #[test]
    fn test_get_ip_version() {
        let mut ipv4_packet = [0u8; 20];
        ipv4_packet[0] = 0x45; // IPv4
        assert_eq!(get_ip_version(&ipv4_packet), Some(IpVersion::V4));

        let mut ipv6_packet = [0u8; 40];
        ipv6_packet[0] = 0x60; // IPv6 (version 6, traffic class high bits)
        assert_eq!(get_ip_version(&ipv6_packet), Some(IpVersion::V6));

        let empty_packet: [u8; 0] = [];
        assert_eq!(get_ip_version(&empty_packet), None);
    }

    #[test]
    fn test_get_destination_ipv6() {
        // Minimal IPv6 header with destination fd99::1
        let mut packet = [0u8; 40];
        packet[0] = 0x60; // IPv6
        // Destination address at bytes 24-39
        packet[24..40].copy_from_slice(&[
            0xfd, 0x99, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]);

        let dst = get_destination_ipv6(&packet).unwrap();
        assert_eq!(dst, [0xfd, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn test_get_source_ipv6() {
        let mut packet = [0u8; 40];
        packet[0] = 0x60; // IPv6
        // Source address at bytes 8-23
        packet[8..24].copy_from_slice(&[
            0xfd, 0x99, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ]);

        let src = get_source_ipv6(&packet).unwrap();
        assert_eq!(src, [0xfd, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    }

    #[test]
    fn test_get_destination_addr() {
        // IPv4 packet
        let mut ipv4_packet = [0u8; 20];
        ipv4_packet[0] = 0x45;
        ipv4_packet[16..20].copy_from_slice(&[192, 168, 1, 1]);
        match get_destination_addr(&ipv4_packet) {
            Some(DestinationAddr::V4(addr)) => assert_eq!(addr, [192, 168, 1, 1]),
            _ => panic!("Expected IPv4 address"),
        }

        // IPv6 packet
        let mut ipv6_packet = [0u8; 40];
        ipv6_packet[0] = 0x60;
        ipv6_packet[24..40]
            .copy_from_slice(&[0xfd, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        match get_destination_addr(&ipv6_packet) {
            Some(DestinationAddr::V6(addr)) => {
                assert_eq!(addr, [0xfd, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
            }
            _ => panic!("Expected IPv6 address"),
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_netmask_to_prefix() {
        assert_eq!(netmask_to_prefix([255, 255, 255, 0]), 24);
        assert_eq!(netmask_to_prefix([255, 255, 0, 0]), 16);
        assert_eq!(netmask_to_prefix([255, 0, 0, 0]), 8);
        assert_eq!(netmask_to_prefix([255, 255, 255, 255]), 32);
        assert_eq!(netmask_to_prefix([0, 0, 0, 0]), 0);
    }
}
