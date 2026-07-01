//! Tunnel device abstraction.
//!
//! Defines the trait for platform-specific tunnel implementations.

use std::io;
use std::net::Ipv6Addr;

use async_trait::async_trait;

/// Trait for tunnel device implementations.
///
/// Platform-specific implementations (Wintun, TUN, etc.) implement this trait
/// to provide a unified interface for the VPN client.
#[async_trait]
pub trait TunnelDevice: Send + Sync {
    /// Receive a packet from the tunnel (blocking).
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize>;

    /// Send a packet to the tunnel.
    fn send(&self, buf: &[u8]) -> io::Result<usize>;

    /// Set the MTU.
    fn set_mtu(&self, mtu: u16) -> io::Result<()>;

    /// Get the device name.
    fn name(&self) -> &str;

    /// Configure the tunnel with an IPv4 address and netmask.
    fn configure(&self, ip: [u8; 4], netmask: [u8; 4], gateway: [u8; 4]) -> io::Result<()>;

    /// Configure the tunnel with an IPv6 address and prefix length (dual-stack).
    /// Default implementation does nothing (for backward compatibility).
    fn configure_ipv6(
        &self,
        _ip: [u8; 16],
        _prefix_len: u8,
        _gateway: Option<[u8; 16]>,
    ) -> io::Result<()> {
        Ok(())
    }

    /// Check if this tunnel device supports IPv6.
    fn supports_ipv6(&self) -> bool {
        false
    }

    /// Close the tunnel device.
    fn close(&self) -> io::Result<()>;
}

/// Tunnel configuration received from the server.
#[derive(Clone, Debug)]
pub struct TunnelInfo {
    /// Assigned client IPv4 address.
    pub client_ip: [u8; 4],
    /// IPv4 network mask.
    pub netmask: [u8; 4],
    /// IPv4 gateway (server's tunnel IP).
    pub gateway: [u8; 4],
    /// IPv4 DNS servers.
    pub dns_servers: Vec<[u8; 4]>,
    /// Assigned client IPv6 address (optional, for dual-stack).
    pub client_ipv6: Option<[u8; 16]>,
    /// IPv6 prefix length (e.g., 64 for /64).
    pub prefix_len_ipv6: Option<u8>,
    /// IPv6 gateway (server's tunnel IPv6).
    pub gateway_ipv6: Option<[u8; 16]>,
    /// IPv6 DNS servers.
    pub dns_servers_v6: Vec<[u8; 16]>,
    /// MTU for the tunnel.
    pub mtu: u16,
}

impl TunnelInfo {
    /// Format IPv4 address as string.
    pub fn format_ip(ip: &[u8; 4]) -> String {
        format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
    }

    /// Format IPv6 address as string.
    pub fn format_ipv6(ip: &[u8; 16]) -> String {
        Ipv6Addr::from(*ip).to_string()
    }

    /// Get client IPv4 as string.
    pub fn client_ip_str(&self) -> String {
        Self::format_ip(&self.client_ip)
    }

    /// Get IPv4 gateway as string.
    pub fn gateway_str(&self) -> String {
        Self::format_ip(&self.gateway)
    }

    /// Get client IPv6 as string (if configured).
    pub fn client_ipv6_str(&self) -> Option<String> {
        self.client_ipv6.as_ref().map(Self::format_ipv6)
    }

    /// Get IPv6 gateway as string (if configured).
    pub fn gateway_ipv6_str(&self) -> Option<String> {
        self.gateway_ipv6.as_ref().map(Self::format_ipv6)
    }

    /// Check if this tunnel has IPv6 support.
    pub fn has_ipv6(&self) -> bool {
        self.client_ipv6.is_some()
    }

    /// Get IPv6 address with prefix notation (e.g., "fd00::1/64").
    pub fn client_ipv6_cidr(&self) -> Option<String> {
        match (self.client_ipv6, self.prefix_len_ipv6) {
            (Some(ip), Some(prefix)) => Some(format!("{}/{}", Self::format_ipv6(&ip), prefix)),
            _ => None,
        }
    }
}

impl From<hpn_core::protocol::TunnelConfig> for TunnelInfo {
    fn from(config: hpn_core::protocol::TunnelConfig) -> Self {
        Self {
            client_ip: config.client_ipv4,
            netmask: config.netmask_ipv4,
            gateway: config.gateway_ipv4,
            dns_servers: config.dns_ipv4,
            client_ipv6: config.client_ipv6,
            prefix_len_ipv6: config.prefix_len_ipv6,
            gateway_ipv6: config.gateway_ipv6,
            dns_servers_v6: config.dns_ipv6,
            mtu: config.mtu,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_ipv4() {
        let ip = [192, 168, 1, 100];
        assert_eq!(TunnelInfo::format_ip(&ip), "192.168.1.100");
    }

    #[test]
    fn test_format_ipv6() {
        let ip = [0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
        assert_eq!(TunnelInfo::format_ipv6(&ip), "fd00::1");
    }

    #[test]
    fn test_tunnel_info_ipv6_helpers() {
        let info = TunnelInfo {
            client_ip: [10, 99, 0, 5],
            netmask: [255, 255, 255, 0],
            gateway: [10, 99, 0, 1],
            dns_servers: vec![[8, 8, 8, 8]],
            client_ipv6: Some([0xfd, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05]),
            prefix_len_ipv6: Some(64),
            gateway_ipv6: Some([0xfd, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]),
            dns_servers_v6: vec![],
            mtu: 1420,
        };

        assert!(info.has_ipv6());
        assert!(info.client_ipv6_str().is_some());
        assert!(info.client_ipv6_cidr().unwrap().contains("/64"));
    }

    #[test]
    fn test_tunnel_info_no_ipv6() {
        let info = TunnelInfo {
            client_ip: [10, 99, 0, 5],
            netmask: [255, 255, 255, 0],
            gateway: [10, 99, 0, 1],
            dns_servers: vec![[8, 8, 8, 8]],
            client_ipv6: None,
            prefix_len_ipv6: None,
            gateway_ipv6: None,
            dns_servers_v6: vec![],
            mtu: 1420,
        };

        assert!(!info.has_ipv6());
        assert!(info.client_ipv6_str().is_none());
        assert!(info.client_ipv6_cidr().is_none());
    }

    #[test]
    fn test_tunnel_info_ipv4_str_helpers() {
        let info = TunnelInfo {
            client_ip: [192, 168, 1, 100],
            netmask: [255, 255, 255, 0],
            gateway: [192, 168, 1, 1],
            dns_servers: vec![[8, 8, 8, 8], [8, 8, 4, 4]],
            client_ipv6: None,
            prefix_len_ipv6: None,
            gateway_ipv6: None,
            dns_servers_v6: vec![],
            mtu: 1400,
        };

        assert_eq!(info.client_ip_str(), "192.168.1.100");
        assert_eq!(info.gateway_str(), "192.168.1.1");
        assert!(info.gateway_ipv6_str().is_none());
    }

    #[test]
    fn test_tunnel_info_ipv6_full_addresses() {
        let info = TunnelInfo {
            client_ip: [10, 0, 0, 2],
            netmask: [255, 255, 255, 252],
            gateway: [10, 0, 0, 1],
            dns_servers: vec![],
            client_ipv6: Some([
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
            ]),
            prefix_len_ipv6: Some(64),
            gateway_ipv6: Some([
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
            ]),
            dns_servers_v6: vec![[
                0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88,
            ]],
            mtu: 1280,
        };

        assert!(info.has_ipv6());
        assert_eq!(info.client_ipv6_str(), Some("2001:db8::2".to_string()));
        assert_eq!(info.gateway_ipv6_str(), Some("2001:db8::1".to_string()));
        assert_eq!(info.client_ipv6_cidr(), Some("2001:db8::2/64".to_string()));
        assert_eq!(info.mtu, 1280);
    }

    #[test]
    fn test_tunnel_info_clone() {
        let info = TunnelInfo {
            client_ip: [10, 99, 0, 2],
            netmask: [255, 255, 255, 0],
            gateway: [10, 99, 0, 1],
            dns_servers: vec![[8, 8, 8, 8]],
            client_ipv6: Some([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02]),
            prefix_len_ipv6: Some(64),
            gateway_ipv6: Some([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]),
            dns_servers_v6: vec![],
            mtu: 1420,
        };

        let cloned = info.clone();
        assert_eq!(info.client_ip, cloned.client_ip);
        assert_eq!(info.client_ipv6, cloned.client_ipv6);
        assert_eq!(info.mtu, cloned.mtu);
    }

    #[test]
    fn test_tunnel_info_ipv6_cidr_partial() {
        // Test with IPv6 address but no prefix length
        let info = TunnelInfo {
            client_ip: [10, 0, 0, 1],
            netmask: [255, 255, 255, 0],
            gateway: [10, 0, 0, 254],
            dns_servers: vec![],
            client_ipv6: Some([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]),
            prefix_len_ipv6: None,
            gateway_ipv6: None,
            dns_servers_v6: vec![],
            mtu: 1500,
        };

        assert!(info.has_ipv6());
        assert!(info.client_ipv6_str().is_some());
        assert!(info.client_ipv6_cidr().is_none()); // No CIDR without prefix length
    }

    #[test]
    fn test_format_ipv4_edge_cases() {
        assert_eq!(TunnelInfo::format_ip(&[0, 0, 0, 0]), "0.0.0.0");
        assert_eq!(
            TunnelInfo::format_ip(&[255, 255, 255, 255]),
            "255.255.255.255"
        );
        assert_eq!(TunnelInfo::format_ip(&[127, 0, 0, 1]), "127.0.0.1");
    }

    #[test]
    fn test_format_ipv6_edge_cases() {
        // All zeros
        let zeros = [0u8; 16];
        assert_eq!(TunnelInfo::format_ipv6(&zeros), "::");

        // Loopback
        let loopback = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(TunnelInfo::format_ipv6(&loopback), "::1");

        // All ones (reserved)
        let ones = [255u8; 16];
        let formatted = TunnelInfo::format_ipv6(&ones);
        assert!(formatted.contains("ffff"));
    }

    #[test]
    fn test_tunnel_info_multiple_dns_servers() {
        let info = TunnelInfo {
            client_ip: [10, 0, 0, 2],
            netmask: [255, 255, 255, 0],
            gateway: [10, 0, 0, 1],
            dns_servers: vec![[8, 8, 8, 8], [8, 8, 4, 4], [1, 1, 1, 1]],
            client_ipv6: None,
            prefix_len_ipv6: None,
            gateway_ipv6: None,
            dns_servers_v6: vec![],
            mtu: 1420,
        };

        assert_eq!(info.dns_servers.len(), 3);
        assert_eq!(info.dns_servers[0], [8, 8, 8, 8]);
        assert_eq!(info.dns_servers[2], [1, 1, 1, 1]);
    }
}
