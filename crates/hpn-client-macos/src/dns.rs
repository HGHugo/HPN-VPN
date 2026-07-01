//! DNS leak protection for macOS.
//!
//! Manages DNS configuration to prevent leaks when connected to VPN.
//! On macOS, we modify /etc/resolv.conf and use scutil for network services.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::Command;

use tracing::{debug, info, warn};

use crate::error::MacosClientError;

/// DNS configuration manager.
pub struct DnsManager {
    /// Original /etc/resolv.conf content (for restoration).
    original_resolv_conf: Option<String>,
    /// Network service name (e.g., "Wi-Fi").
    network_service: Option<String>,
    /// Original DNS servers for the network service.
    original_dns_servers: Vec<String>,
    /// Whether DNS configuration is currently active.
    active: bool,
}

impl Default for DnsManager {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsManager {
    /// Create a new DNS manager.
    pub fn new() -> Self {
        Self {
            original_resolv_conf: None,
            network_service: None,
            original_dns_servers: Vec::new(),
            active: false,
        }
    }

    /// Configure DNS to use VPN servers and prevent leaks.
    ///
    /// # Arguments
    /// * `dns_servers` - DNS servers provided by VPN (e.g., `["10.99.0.1"]`)
    /// * `interface_name` - VPN interface name (e.g., `"utun3"`)
    pub fn configure(
        &mut self,
        dns_servers: &[&str],
        interface_name: &str,
    ) -> Result<(), MacosClientError> {
        if self.active {
            warn!("DNS protection already active, skipping configure");
            return Ok(());
        }

        info!("Configuring DNS protection with servers: {:?}", dns_servers);

        // Backup original /etc/resolv.conf
        self.backup_resolv_conf()?;

        // Get active network service (Wi-Fi, Ethernet, etc.)
        self.detect_network_service()?;

        // Backup original DNS servers from network service
        let service_clone = self.network_service.clone();
        if let Some(service) = service_clone {
            self.backup_network_service_dns(&service)?;
        }

        // Set DNS servers on the VPN interface with highest priority
        self.set_dns_on_interface(dns_servers, interface_name)?;

        // Override /etc/resolv.conf to use VPN DNS
        self.write_resolv_conf(dns_servers)?;

        self.active = true;
        info!("DNS leak protection enabled");

        Ok(())
    }

    /// Restore original DNS configuration.
    pub fn restore(&mut self) -> Result<(), MacosClientError> {
        if !self.active {
            return Ok(());
        }

        info!("Restoring original DNS configuration");

        // Restore /etc/resolv.conf
        if let Some(ref original) = self.original_resolv_conf {
            self.restore_resolv_conf(original)?;
        }

        // Restore network service DNS servers
        if let Some(ref service) = self.network_service
            && !self.original_dns_servers.is_empty()
        {
            self.restore_network_service_dns(service, &self.original_dns_servers)?;
        }

        self.active = false;
        self.original_resolv_conf = None;
        self.network_service = None;
        self.original_dns_servers.clear();

        info!("DNS configuration restored");

        Ok(())
    }

    /// Check if DNS protection is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    // ========================================================================
    // Private implementation methods
    // ========================================================================

    /// Backup /etc/resolv.conf content.
    fn backup_resolv_conf(&mut self) -> Result<(), MacosClientError> {
        let path = Path::new("/etc/resolv.conf");

        if !path.exists() {
            warn!("/etc/resolv.conf does not exist, skipping backup");
            return Ok(());
        }

        let content = fs::read_to_string(path).map_err(|e| {
            MacosClientError::Dns(format!("failed to read /etc/resolv.conf: {}", e))
        })?;

        self.original_resolv_conf = Some(content);
        debug!("Backed up /etc/resolv.conf");

        Ok(())
    }

    /// Write new /etc/resolv.conf with VPN DNS servers.
    fn write_resolv_conf(&self, dns_servers: &[&str]) -> Result<(), MacosClientError> {
        let path = Path::new("/etc/resolv.conf");

        use std::fmt::Write;

        let mut content = String::from("# HPN VPN DNS configuration\n");
        for server in dns_servers {
            let _ = writeln!(content, "nameserver {}", server);
        }

        // Use /var/run instead of /tmp for security (root-owned directory)
        // Generate unique temp filename to avoid conflicts
        let pid = std::process::id();
        let temp_path = format!("/var/run/hpn-resolv.conf.{}", pid);

        // Create temp file with restrictive permissions (0o600) BEFORE writing
        let temp_file = fs::OpenOptions::new()
            .write(true)
            .create_new(true) // Fail if file exists (prevents race)
            .mode(0o600) // rw------- (owner only)
            .open(&temp_path)
            .map_err(|e| {
                MacosClientError::Dns(format!("failed to create temp resolv.conf: {}", e))
            })?;

        // Write content to temp file
        use std::io::Write as IoWrite;
        let mut writer = std::io::BufWriter::new(temp_file);
        writer.write_all(content.as_bytes()).map_err(|e| {
            MacosClientError::Dns(format!("failed to write temp resolv.conf: {}", e))
        })?;

        // Ensure all data is flushed to disk
        writer.flush().map_err(|e| {
            MacosClientError::Dns(format!("failed to flush temp resolv.conf: {}", e))
        })?;
        drop(writer);

        // Atomic rename (no TOCTOU vulnerability)
        // This requires the VPN process to have appropriate privileges
        fs::rename(&temp_path, path).map_err(|e| {
            // Clean up temp file on failure
            let _ = fs::remove_file(&temp_path);
            MacosClientError::Dns(format!("failed to rename temp resolv.conf: {}", e))
        })?;

        debug!("Wrote /etc/resolv.conf with VPN DNS servers");

        Ok(())
    }

    /// Restore /etc/resolv.conf from backup.
    fn restore_resolv_conf(&self, original_content: &str) -> Result<(), MacosClientError> {
        let path = Path::new("/etc/resolv.conf");

        // SECURITY: Use /var/run instead of /tmp for security (root-owned directory)
        // Generate unique temp filename to avoid conflicts and prevent symlink attacks
        let pid = std::process::id();
        let temp_path = format!("/var/run/hpn-resolv-restore.conf.{}", pid);

        // Create temp file with restrictive permissions (0o600) BEFORE writing
        let temp_file = fs::OpenOptions::new()
            .write(true)
            .create_new(true) // Fail if file exists (prevents race)
            .mode(0o600) // rw------- (owner only)
            .open(&temp_path)
            .map_err(|e| {
                MacosClientError::Dns(format!("failed to create temp resolv.conf: {}", e))
            })?;

        // Write content to temp file
        let mut writer = std::io::BufWriter::new(temp_file);
        writer.write_all(original_content.as_bytes()).map_err(|e| {
            MacosClientError::Dns(format!("failed to write temp resolv.conf: {}", e))
        })?;

        // Ensure all data is flushed to disk
        writer.flush().map_err(|e| {
            MacosClientError::Dns(format!("failed to flush temp resolv.conf: {}", e))
        })?;
        drop(writer);

        // Atomic rename (no TOCTOU vulnerability)
        // This requires the VPN process to have appropriate privileges
        fs::rename(&temp_path, path).map_err(|e| {
            // Clean up temp file on failure
            let _ = fs::remove_file(&temp_path);
            MacosClientError::Dns(format!("failed to rename temp resolv.conf: {}", e))
        })?;

        debug!("Restored /etc/resolv.conf");

        Ok(())
    }

    /// Detect the active network service (Wi-Fi, Ethernet, etc.).
    fn detect_network_service(&mut self) -> Result<(), MacosClientError> {
        // Use `networksetup -listallnetworkservices` to get network services
        let output = Command::new("networksetup")
            .args(["-listallnetworkservices"])
            .output()
            .map_err(|e| MacosClientError::Dns(format!("failed to run networksetup: {}", e)))?;

        if !output.status.success() {
            return Err(MacosClientError::Dns(
                "networksetup failed to list network services".to_string(),
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = stdout.lines().collect();

        // Skip first line (header) and find first non-disabled service
        for line in lines.iter().skip(1) {
            let service = line.trim();
            if !service.starts_with('*') && !service.is_empty() {
                self.network_service = Some(service.to_string());
                debug!("Detected active network service: {}", service);
                return Ok(());
            }
        }

        warn!("Could not detect active network service, DNS protection may be limited");
        Ok(())
    }

    /// Backup DNS servers from a network service.
    fn backup_network_service_dns(&mut self, service: &str) -> Result<(), MacosClientError> {
        // SECURITY: Validate service name to prevent command injection
        if !Self::is_valid_service_name(service) {
            return Err(MacosClientError::Dns(format!(
                "Invalid network service name: {}",
                service
            )));
        }

        let output = Command::new("networksetup")
            .args(["-getdnsservers", service])
            .output()
            .map_err(|e| MacosClientError::Dns(format!("failed to get DNS servers: {}", e)))?;

        if !output.status.success() {
            warn!("Could not get DNS servers for {}", service);
            return Ok(());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let servers: Vec<String> = stdout
            .lines()
            .filter(|line| !line.contains("There aren't any DNS Servers"))
            .map(|line| line.trim().to_string())
            .collect();

        if !servers.is_empty() {
            self.original_dns_servers = servers;
            debug!(
                "Backed up DNS servers for {}: {:?}",
                service, self.original_dns_servers
            );
        }

        Ok(())
    }

    /// Restore DNS servers to a network service.
    fn restore_network_service_dns(
        &self,
        service: &str,
        servers: &[String],
    ) -> Result<(), MacosClientError> {
        // SECURITY: Validate service name to prevent command injection
        if !Self::is_valid_service_name(service) {
            return Err(MacosClientError::Dns(format!(
                "Invalid network service name: {}",
                service
            )));
        }

        // SECURITY: Validate all DNS server addresses
        for server in servers {
            if !Self::is_valid_ip_address(server) {
                return Err(MacosClientError::Dns(format!(
                    "Invalid DNS server address: {}",
                    server
                )));
            }
        }

        if servers.is_empty() {
            // Clear DNS servers (use DHCP)
            let output = Command::new("networksetup")
                .args(["-setdnsservers", service, "Empty"])
                .output()
                .map_err(|e| {
                    MacosClientError::Dns(format!("failed to clear DNS servers: {}", e))
                })?;

            if !output.status.success() {
                warn!("Could not clear DNS servers for {}", service);
            }
        } else {
            // Restore original DNS servers
            let mut args = vec!["-setdnsservers", service];
            let server_refs: Vec<&str> = servers.iter().map(|s| s.as_str()).collect();
            args.extend(server_refs);

            let output = Command::new("networksetup")
                .args(&args)
                .output()
                .map_err(|e| {
                    MacosClientError::Dns(format!("failed to restore DNS servers: {}", e))
                })?;

            if !output.status.success() {
                warn!("Could not restore DNS servers for {}", service);
            } else {
                debug!("Restored DNS servers for {}: {:?}", service, servers);
            }
        }

        Ok(())
    }

    /// Set DNS servers on a specific interface using scutil.
    /// Validate that a string is a valid IPv4 or IPv6 address.
    fn is_valid_ip_address(addr: &str) -> bool {
        use std::net::IpAddr;
        addr.parse::<IpAddr>().is_ok()
    }

    /// Validate network service name to prevent command injection.
    /// Network service names should only contain printable ASCII and common punctuation.
    /// Reject anything with shell metacharacters or control characters.
    fn is_valid_service_name(name: &str) -> bool {
        if name.is_empty() || name.len() > 256 {
            return false;
        }
        // Allow alphanumeric, space, hyphen, underscore, parentheses, period
        // Reject shell metacharacters: $, `, ;, |, &, <, >, \n, etc.
        name.chars().all(|c| {
            c.is_alphanumeric()
                || c == ' '
                || c == '-'
                || c == '_'
                || c == '('
                || c == ')'
                || c == '.'
        })
    }

    fn set_dns_on_interface(
        &self,
        dns_servers: &[&str],
        interface_name: &str,
    ) -> Result<(), MacosClientError> {
        // SECURITY: Validate inputs to prevent command injection via scutil
        // Validate DNS servers (must be valid IP addresses)
        for server in dns_servers {
            if !Self::is_valid_ip_address(server) {
                return Err(MacosClientError::Dns(format!(
                    "Invalid DNS server address: {}",
                    server
                )));
            }
        }

        // Validate interface name (alphanumeric + underscore/dash only)
        if !interface_name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
        {
            return Err(MacosClientError::Dns(format!(
                "Invalid interface name: {}",
                interface_name
            )));
        }

        // Build scutil commands to set DNS
        // Format:
        // d.add ServerAddresses * 10.99.0.1
        // set State:/Network/Service/<service_id>/DNS
        use std::fmt::Write;
        let mut scutil_input = "d.init\n".to_string();
        scutil_input.push_str("d.add ServerAddresses * ");
        scutil_input.push_str(&dns_servers.join(" "));
        scutil_input.push('\n');
        let _ = writeln!(
            scutil_input,
            "set State:/Network/Service/HPN-{}/DNS",
            interface_name
        );
        scutil_input.push_str("quit\n");

        let mut child = Command::new("scutil")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| MacosClientError::Dns(format!("failed to spawn scutil: {}", e)))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(scutil_input.as_bytes()).map_err(|e| {
                MacosClientError::Dns(format!("failed to write to scutil stdin: {}", e))
            })?;
        }

        let status = child
            .wait()
            .map_err(|e| MacosClientError::Dns(format!("failed to wait for scutil: {}", e)))?;

        if !status.success() {
            warn!("scutil failed to set DNS on interface");
        } else {
            debug!("Set DNS servers on {} via scutil", interface_name);
        }

        Ok(())
    }
}

impl Drop for DnsManager {
    fn drop(&mut self) {
        if self.active
            && let Err(e) = self.restore()
        {
            warn!("Failed to restore DNS configuration on drop: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_manager_creation() {
        let dns = DnsManager::new();
        assert!(!dns.is_active());
        assert!(dns.original_resolv_conf.is_none());
        assert!(dns.network_service.is_none());
    }

    #[test]
    fn test_dns_manager_default() {
        let dns = DnsManager::default();
        assert!(!dns.is_active());
    }

    // Note: Actual DNS configuration tests require root and would modify system settings
    // Integration tests should be run manually with proper permissions
}
