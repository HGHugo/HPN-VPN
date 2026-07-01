//! macOS routing table management.
//!
//! Provides functions to manage the system routing table for VPN traffic.
//! Supports full tunnel, split tunnel, kill switch, and DNS leak protection.
//! Dual-stack IPv4/IPv6 support.
//!
//! # Kill Switch Implementation
//!
//! The kill switch uses a two-layer approach for maximum protection:
//! 1. **Routing table manipulation**: Removes default routes to block traffic at the routing level
//! 2. **PF (Packet Filter) firewall**: Blocks all traffic at the kernel level, preventing bypass
//!    via raw sockets or mDNS leaks
//!
//! The PF-based kill switch provides stronger protection than routing alone because:
//! - Applications cannot bypass it using raw sockets
//! - mDNS/Bonjour traffic is blocked (prevents DNS leaks via multicast)
//! - Works even if an application manipulates routing tables

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::time::Duration;

use tracing::{debug, error, info, warn};

/// Default timeout for system commands (route, scutil, etc.)
/// Increased to 30s because scutil and route can be slow on some systems.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// Execute a command with timeout.
/// Returns the command output or an error if the command times out or fails to execute.
fn run_command_with_timeout(
    cmd: &str,
    args: &[&str],
    timeout: Duration,
) -> io::Result<std::process::Output> {
    use std::process::Stdio;

    let mut child = Command::new(cmd)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Process finished, get output
                let stdout = child
                    .stdout
                    .take()
                    .map(|mut s| {
                        let mut buf = Vec::new();
                        use std::io::Read;
                        let _ = s.read_to_end(&mut buf);
                        buf
                    })
                    .unwrap_or_default();

                let stderr = child
                    .stderr
                    .take()
                    .map(|mut s| {
                        let mut buf = Vec::new();
                        use std::io::Read;
                        let _ = s.read_to_end(&mut buf);
                        buf
                    })
                    .unwrap_or_default();

                return Ok(std::process::Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            Ok(None) => {
                // Process still running
                if start.elapsed() > timeout {
                    // Kill the process and return error
                    let _ = child.kill();
                    let _ = child.wait(); // Reap the process
                    error!("Command '{}' timed out after {:?}", cmd, timeout);
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("command '{}' timed out after {:?}", cmd, timeout),
                    ));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(e),
        }
    }
}

use crate::error::MacosClientError;

/// LAN subnets (IPv4) to allow when kill switch + allow LAN is enabled.
const LAN_SUBNETS: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16", // Link-local
];

/// LAN subnets (IPv6) to allow when kill switch + allow LAN is enabled.
const LAN_SUBNETS_V6: &[&str] = &[
    "fe80::/10", // Link-local
    "fc00::/7",  // Unique local addresses (ULA)
];

/// Known DNS-over-HTTPS (DoH) provider IPv4 addresses.
/// These are blocked to prevent DNS leaks via encrypted DNS.
const DOH_PROVIDERS_V4: &[&str] = &[
    // Google DNS
    "8.8.8.8",
    "8.8.4.4",
    // Cloudflare DNS
    "1.1.1.1",
    "1.0.0.1",
    // Quad9 DNS
    "9.9.9.9",
    "149.112.112.112",
    // OpenDNS
    "208.67.222.222",
    "208.67.220.220",
    // AdGuard DNS
    "94.140.14.14",
    "94.140.15.15",
    // NextDNS
    "45.90.28.0",
    "45.90.30.0",
    // CleanBrowsing
    "185.228.168.168",
    "185.228.169.168",
];

/// Known DNS-over-HTTPS (DoH) provider IPv6 addresses.
const DOH_PROVIDERS_V6: &[&str] = &[
    // Google DNS
    "2001:4860:4860::8888",
    "2001:4860:4860::8844",
    // Cloudflare DNS
    "2606:4700:4700::1111",
    "2606:4700:4700::1001",
    // Quad9 DNS
    "2620:fe::fe",
    "2620:fe::9",
    // OpenDNS
    "2620:119:35::35",
    "2620:119:53::53",
    // AdGuard DNS
    "2a10:50c0::ad1:ff",
    "2a10:50c0::ad2:ff",
];

/// DNS-over-TLS (DoT) port.
const DOT_PORT: u16 = 853;

/// Routing configuration for the VPN tunnel.
#[derive(Debug, Clone)]
pub struct RoutingConfig {
    /// The utun interface name.
    pub interface: String,
    /// The VPN gateway (server's tunnel IPv4).
    pub gateway: Ipv4Addr,
    /// The actual VPN server endpoint IP (for exclusion route).
    pub server_endpoint: Ipv4Addr,
    /// Original default gateway (to restore on disconnect).
    pub original_gateway: Option<Ipv4Addr>,
    /// Original default interface.
    pub original_interface: Option<String>,
    /// Kill switch enabled.
    pub kill_switch: bool,
    /// Allow LAN traffic when kill switch is active.
    pub allow_lan: bool,
    /// Routes that were deleted (for restoration).
    pub deleted_routes: Vec<(String, Ipv4Addr, String)>, // (dest, gateway, interface)
    /// IPv6 VPN gateway (for dual-stack).
    pub gateway_v6: Option<Ipv6Addr>,
    /// IPv6 prefix length.
    pub prefix_len_v6: Option<u8>,
    /// Whether IPv6 routing is enabled.
    pub ipv6_enabled: bool,
    /// Original IPv6 default gateway (to restore on disconnect).
    pub original_gateway_v6: Option<Ipv6Addr>,
    /// Original IPv6 default interface.
    pub original_interface_v6: Option<String>,
}

impl RoutingConfig {
    /// Create a new routing configuration (IPv4 only).
    pub fn new(interface: String, gateway: Ipv4Addr, server_endpoint: Ipv4Addr) -> Self {
        Self {
            interface,
            gateway,
            server_endpoint,
            original_gateway: None,
            original_interface: None,
            kill_switch: false,
            allow_lan: true,
            deleted_routes: Vec::new(),
            gateway_v6: None,
            prefix_len_v6: None,
            ipv6_enabled: false,
            original_gateway_v6: None,
            original_interface_v6: None,
        }
    }

    /// Create a routing configuration with kill switch options.
    pub fn with_kill_switch(
        interface: String,
        gateway: Ipv4Addr,
        server_endpoint: Ipv4Addr,
        kill_switch: bool,
        allow_lan: bool,
    ) -> Self {
        Self {
            interface,
            gateway,
            server_endpoint,
            original_gateway: None,
            original_interface: None,
            kill_switch,
            allow_lan,
            deleted_routes: Vec::new(),
            gateway_v6: None,
            prefix_len_v6: None,
            ipv6_enabled: false,
            original_gateway_v6: None,
            original_interface_v6: None,
        }
    }

    /// Create a dual-stack routing configuration (IPv4 + IPv6).
    pub fn new_dual_stack(
        interface: String,
        gateway: Ipv4Addr,
        server_endpoint: Ipv4Addr,
        gateway_v6: Ipv6Addr,
        prefix_len_v6: u8,
        kill_switch: bool,
        allow_lan: bool,
    ) -> Self {
        Self {
            interface,
            gateway,
            server_endpoint,
            original_gateway: None,
            original_interface: None,
            kill_switch,
            allow_lan,
            deleted_routes: Vec::new(),
            gateway_v6: Some(gateway_v6),
            prefix_len_v6: Some(prefix_len_v6),
            ipv6_enabled: true,
            original_gateway_v6: None,
            original_interface_v6: None,
        }
    }

    /// Enable IPv6 routing on an existing config.
    pub fn enable_ipv6(&mut self, gateway_v6: Ipv6Addr, prefix_len_v6: u8) {
        self.gateway_v6 = Some(gateway_v6);
        self.prefix_len_v6 = Some(prefix_len_v6);
        self.ipv6_enabled = true;
    }

    /// Set the original gateway (pre-captured before VPN adapter was created).
    ///
    /// This can be called before setup_full_tunnel() to provide the original
    /// gateway when it was captured earlier in the connection process.
    pub fn set_original_gateway(&mut self, gateway: Ipv4Addr, interface: String) {
        info!(
            "Setting pre-captured original gateway: {} via {}",
            gateway, interface
        );
        self.original_gateway = Some(gateway);
        self.original_interface = Some(interface);
    }

    /// Set the original IPv6 gateway (pre-captured before VPN adapter was created).
    ///
    /// This can be called before setup_full_tunnel() to provide the original
    /// IPv6 gateway when it was captured earlier in the connection process.
    pub fn set_original_gateway_v6(&mut self, gateway: Ipv6Addr, interface: String) {
        info!(
            "Setting pre-captured original IPv6 gateway: {} via {}",
            gateway, interface
        );
        self.original_gateway_v6 = Some(gateway);
        self.original_interface_v6 = Some(interface);
    }
}

/// Get the current default gateway.
pub fn get_default_gateway() -> Result<(Ipv4Addr, String), MacosClientError> {
    let output = run_command_with_timeout("route", &["-n", "get", "default"], COMMAND_TIMEOUT)
        .map_err(|e| MacosClientError::Routing(format!("failed to run route: {}", e)))?;

    if !output.status.success() {
        return Err(MacosClientError::Routing(
            "failed to get default route".to_string(),
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut gateway: Option<Ipv4Addr> = None;
    let mut interface: Option<String> = None;

    for line in stdout.lines() {
        let line = line.trim();
        if line.starts_with("gateway:") {
            if let Some(gw) = line.strip_prefix("gateway:") {
                let gw = gw.trim();
                if let Ok(addr) = gw.parse() {
                    gateway = Some(addr);
                }
            }
        } else if line.starts_with("interface:")
            && let Some(iface) = line.strip_prefix("interface:")
        {
            interface = Some(iface.trim().to_string());
        }
    }

    match (gateway, interface) {
        (Some(gw), Some(iface)) => {
            debug!("Current default gateway: {} via {}", gw, iface);
            Ok((gw, iface))
        }
        _ => Err(MacosClientError::Routing(
            "could not parse default gateway".to_string(),
        )),
    }
}

/// Get the current default IPv6 gateway.
///
/// Returns the IPv6 gateway address and interface name, or None if no IPv6 default route exists.
pub fn get_default_gateway_v6() -> Option<(Ipv6Addr, String)> {
    let output = run_command_with_timeout(
        "route",
        &["-n", "get", "-inet6", "default"],
        COMMAND_TIMEOUT,
    )
    .ok()?;

    if !output.status.success() {
        debug!("No IPv6 default route found");
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut gateway: Option<Ipv6Addr> = None;
    let mut interface: Option<String> = None;

    for line in stdout.lines() {
        let line = line.trim();
        if line.starts_with("gateway:") {
            if let Some(gw) = line.strip_prefix("gateway:") {
                let gw = gw.trim();
                // Handle link-local addresses with interface suffix (e.g., "fe80::1%en0")
                let gw_clean = gw.split('%').next().unwrap_or(gw);
                if let Ok(addr) = gw_clean.parse() {
                    gateway = Some(addr);
                }
            }
        } else if line.starts_with("interface:")
            && let Some(iface) = line.strip_prefix("interface:")
        {
            interface = Some(iface.trim().to_string());
        }
    }

    match (gateway, interface) {
        (Some(gw), Some(iface)) => {
            debug!("Current default IPv6 gateway: {} via {}", gw, iface);
            Some((gw, iface))
        }
        _ => {
            debug!("Could not parse IPv6 default gateway");
            None
        }
    }
}

/// Add a route to the routing table.
pub fn add_route(
    destination: &str,
    gateway: Ipv4Addr,
    interface: Option<&str>,
) -> Result<(), MacosClientError> {
    let gateway_str = gateway.to_string();
    let mut args = vec!["-n", "add", destination, &gateway_str];

    let iface_flag;
    if let Some(iface) = interface {
        args.push("-interface");
        iface_flag = iface.to_string();
        args.push(&iface_flag);
    }

    let output = run_command_with_timeout("route", &args, COMMAND_TIMEOUT)
        .map_err(|e| MacosClientError::Routing(format!("failed to run route add: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Ignore "already in table" errors
        if !stderr.contains("already in table") {
            return Err(MacosClientError::Routing(format!(
                "route add failed: {}",
                stderr
            )));
        }
    }

    debug!("Added route: {} via {}", destination, gateway);
    Ok(())
}

/// Delete a route from the routing table.
pub fn delete_route(destination: &str) -> Result<(), MacosClientError> {
    let output = run_command_with_timeout("route", &["-n", "delete", destination], COMMAND_TIMEOUT)
        .map_err(|e| MacosClientError::Routing(format!("failed to run route delete: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Ignore "not in table" errors
        if !stderr.contains("not in table") {
            warn!("route delete warning: {}", stderr);
        }
    }

    debug!("Deleted route: {}", destination);
    Ok(())
}

/// Add an IPv6 route to the routing table.
fn add_route_v6(
    destination: &str,
    gateway: Ipv6Addr,
    interface: Option<&str>,
) -> Result<(), MacosClientError> {
    let gateway_str = gateway.to_string();
    let mut args = vec!["-n", "add", "-inet6", destination, &gateway_str];

    let iface_flag;
    if let Some(iface) = interface {
        args.push("-interface");
        iface_flag = iface.to_string();
        args.push(&iface_flag);
    }

    let output = run_command_with_timeout("route", &args, COMMAND_TIMEOUT)
        .map_err(|e| MacosClientError::Routing(format!("failed to run route add (v6): {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Ignore "already in table" errors
        if !stderr.contains("already in table") {
            return Err(MacosClientError::Routing(format!(
                "route add (v6) failed: {}",
                stderr
            )));
        }
    }

    debug!("Added IPv6 route: {} via {}", destination, gateway);
    Ok(())
}

/// Delete an IPv6 route from the routing table.
pub fn delete_route_v6(destination: &str) -> Result<(), MacosClientError> {
    let output = run_command_with_timeout(
        "route",
        &["-n", "delete", "-inet6", destination],
        COMMAND_TIMEOUT,
    )
    .map_err(|e| MacosClientError::Routing(format!("failed to run route delete (v6): {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Ignore "not in table" errors
        if !stderr.contains("not in table") {
            warn!("route delete (v6) warning: {}", stderr);
        }
    }

    debug!("Deleted IPv6 route: {}", destination);
    Ok(())
}

/// Set up VPN routing (full tunnel).
///
/// This creates a "full tunnel" configuration where all traffic goes through the VPN:
/// 1. Save the current default gateway
/// 2. Add a specific route for the VPN server via the original gateway
/// 3. Delete the default route (if kill switch enabled)
/// 4. Add a new default route via the VPN gateway
/// 5. If allow LAN enabled with kill switch, add LAN routes via original gateway
/// 6. If IPv6 is enabled, set up IPv6 full tunnel routes
pub fn setup_full_tunnel(config: &mut RoutingConfig) -> Result<(), MacosClientError> {
    info!("Setting up full tunnel routing via {}", config.interface);

    // Get original default gateway (use pre-captured if available)
    let (original_gw, original_iface) =
        if let (Some(gw), Some(iface)) = (&config.original_gateway, &config.original_interface) {
            info!("Using pre-captured original gateway: {} via {}", gw, iface);
            (*gw, iface.clone())
        } else {
            // Detect now (safe on macOS since utun doesn't create default route)
            let (gw, iface) = get_default_gateway()?;
            config.original_gateway = Some(gw);
            config.original_interface = Some(iface.clone());
            info!("Detected original gateway: {} via {}", gw, iface);
            (gw, iface)
        };

    // Add route to VPN server via original gateway (so we can still reach it)
    add_route(
        &format!("{}/32", config.server_endpoint),
        original_gw,
        Some(&original_iface),
    )?;

    // If kill switch is enabled, delete the original default route
    if config.kill_switch {
        info!("Kill switch enabled: removing original default route");
        if delete_route("default").is_ok() {
            config.deleted_routes.push((
                "default".to_string(),
                original_gw,
                original_iface.clone(),
            ));
        }

        // If allow LAN is enabled, add routes for LAN subnets via original gateway
        if config.allow_lan {
            info!("Allow LAN enabled: adding LAN routes via original gateway");
            for subnet in LAN_SUBNETS {
                if let Err(e) = add_route(subnet, original_gw, Some(&original_iface)) {
                    warn!("Failed to add LAN route {}: {}", subnet, e);
                }
            }
        }
    } else {
        // Without kill switch, just delete default to add VPN routes
        let _ = delete_route("default");
    }

    // Add new default route via VPN (IPv4)
    // On macOS, we use two /1 routes instead of a single default to avoid conflicts
    add_route("0.0.0.0/1", config.gateway, Some(&config.interface))?;
    add_route("128.0.0.0/1", config.gateway, Some(&config.interface))?;

    // Set up IPv6 routes if enabled
    if config.ipv6_enabled
        && let Some(gateway_v6) = config.gateway_v6
    {
        info!("Setting up IPv6 full tunnel routing");

        // Capture original IPv6 gateway before modifying routes (use pre-captured if available)
        let original_v6 = if let (Some(gw), Some(iface)) =
            (&config.original_gateway_v6, &config.original_interface_v6)
        {
            info!(
                "Using pre-captured original IPv6 gateway: {} via {}",
                gw, iface
            );
            Some((*gw, iface.clone()))
        } else {
            // Try to detect now
            if let Some((gw, iface)) = get_default_gateway_v6() {
                config.original_gateway_v6 = Some(gw);
                config.original_interface_v6 = Some(iface.clone());
                info!("Detected original IPv6 gateway: {} via {}", gw, iface);
                Some((gw, iface))
            } else {
                debug!("No IPv6 default gateway detected");
                None
            }
        };

        // Add IPv6 full tunnel routes (two /1 routes)
        add_route_v6("::/1", gateway_v6, Some(&config.interface))?;
        add_route_v6("8000::/1", gateway_v6, Some(&config.interface))?;

        // If allow LAN is enabled with kill switch, add IPv6 LAN routes via ORIGINAL gateway
        if config.kill_switch && config.allow_lan {
            if let Some((original_gw_v6, original_iface_v6)) = original_v6 {
                info!(
                    "Adding IPv6 LAN routes via original gateway: {}",
                    original_gw_v6
                );
                for subnet in LAN_SUBNETS_V6 {
                    if let Err(e) = add_route_v6(subnet, original_gw_v6, Some(&original_iface_v6)) {
                        warn!("Failed to add IPv6 LAN route {}: {}", subnet, e);
                    }
                }
            } else {
                // No original IPv6 gateway - skip LAN routes with a warning
                // Link-local (fe80::/10) should still work as it's on-link
                warn!("No original IPv6 gateway found, IPv6 LAN routes not added");
            }
        }

        info!("IPv6 full tunnel routing established");
    }

    info!(
        "Full tunnel routing established (kill_switch={}, allow_lan={}, ipv6={})",
        config.kill_switch, config.allow_lan, config.ipv6_enabled
    );

    Ok(())
}

/// Tear down VPN routing and restore original configuration.
///
/// If kill switch is enabled, does NOT restore the default route
/// (keeps internet blocked until user reconnects or disables kill switch).
pub fn teardown_routing(config: &RoutingConfig) -> Result<(), MacosClientError> {
    info!(
        "Tearing down VPN routing (kill_switch={}, ipv6={})",
        config.kill_switch, config.ipv6_enabled
    );

    // Remove VPN routes (IPv4)
    let _ = delete_route("0.0.0.0/1");
    let _ = delete_route("128.0.0.0/1");

    // Remove server-specific route
    let _ = delete_route(&format!("{}/32", config.server_endpoint));

    // Remove LAN routes if they were added (IPv4)
    if config.kill_switch && config.allow_lan {
        for subnet in LAN_SUBNETS {
            let _ = delete_route(subnet);
        }
    }

    // Remove IPv6 routes if enabled
    if config.ipv6_enabled {
        let _ = delete_route_v6("::/1");
        let _ = delete_route_v6("8000::/1");

        // Remove IPv6 LAN routes if they were added
        if config.kill_switch && config.allow_lan {
            for subnet in LAN_SUBNETS_V6 {
                let _ = delete_route_v6(subnet);
            }
        }
    }

    // Restore original default route if we have it AND kill switch is NOT active
    if !config.kill_switch {
        if let (Some(original_gw), Some(original_iface)) =
            (&config.original_gateway, &config.original_interface)
        {
            // Delete any existing default
            let _ = delete_route("default");

            // Add back original default
            add_route("default", *original_gw, Some(original_iface))?;
            info!(
                "Restored original gateway: {} via {}",
                original_gw, original_iface
            );
        }

        // Restore original IPv6 default route if we have it
        if config.ipv6_enabled
            && let (Some(original_gw_v6), Some(original_iface_v6)) =
                (&config.original_gateway_v6, &config.original_interface_v6)
        {
            // Delete any existing IPv6 default
            let _ = delete_route_v6("default");

            // Add back original IPv6 default
            if let Err(e) = add_route_v6("default", *original_gw_v6, Some(original_iface_v6)) {
                warn!("Failed to restore IPv6 default route: {}", e);
            } else {
                info!(
                    "Restored original IPv6 gateway: {} via {}",
                    original_gw_v6, original_iface_v6
                );
            }
        }
    } else {
        info!("Kill switch active: NOT restoring default route (no internet until reconnect)");
    }

    info!("VPN routing removed");

    Ok(())
}

/// Tear down VPN routing and force restore original configuration.
///
/// Use this when user explicitly disconnects or disables kill switch.
/// Always restores the default route regardless of kill switch setting.
pub fn teardown_routing_force_restore(config: &RoutingConfig) -> Result<(), MacosClientError> {
    info!(
        "Tearing down VPN routing with force restore (ipv6={})",
        config.ipv6_enabled
    );

    // Remove VPN routes (IPv4)
    let _ = delete_route("0.0.0.0/1");
    let _ = delete_route("128.0.0.0/1");

    // Remove server-specific route
    let _ = delete_route(&format!("{}/32", config.server_endpoint));

    // Remove LAN routes if they were added (IPv4)
    if config.allow_lan {
        for subnet in LAN_SUBNETS {
            let _ = delete_route(subnet);
        }
    }

    // Remove IPv6 routes if enabled
    if config.ipv6_enabled {
        let _ = delete_route_v6("::/1");
        let _ = delete_route_v6("8000::/1");

        // Remove IPv6 LAN routes if they were added
        if config.allow_lan {
            for subnet in LAN_SUBNETS_V6 {
                let _ = delete_route_v6(subnet);
            }
        }
    }

    // Always restore original default route
    if let (Some(original_gw), Some(original_iface)) =
        (&config.original_gateway, &config.original_interface)
    {
        // Delete any existing default
        let _ = delete_route("default");

        // Add back original default
        add_route("default", *original_gw, Some(original_iface))?;
        info!(
            "Force restored original gateway: {} via {}",
            original_gw, original_iface
        );
    }

    // Always restore original IPv6 default route if we have it
    if config.ipv6_enabled
        && let (Some(original_gw_v6), Some(original_iface_v6)) =
            (&config.original_gateway_v6, &config.original_interface_v6)
    {
        // Delete any existing IPv6 default
        let _ = delete_route_v6("default");

        // Add back original IPv6 default
        if let Err(e) = add_route_v6("default", *original_gw_v6, Some(original_iface_v6)) {
            warn!("Failed to restore IPv6 default route: {}", e);
        } else {
            info!(
                "Force restored original IPv6 gateway: {} via {}",
                original_gw_v6, original_iface_v6
            );
        }
    }

    info!("VPN routing removed (forced)");

    Ok(())
}

/// Set up split tunnel routing (only specific subnets go through VPN).
///
/// This is the "include" mode - only traffic to specified subnets goes through VPN.
/// All other traffic goes through the default gateway.
pub fn setup_split_tunnel(
    config: &RoutingConfig,
    subnets: &[&str],
) -> Result<(), MacosClientError> {
    info!(
        "Setting up split tunnel routing for {} subnets",
        subnets.len()
    );

    for subnet in subnets {
        add_route(subnet, config.gateway, Some(&config.interface))?;
    }

    info!("Split tunnel routing established");

    Ok(())
}

/// Multicast addresses for LAN discovery (mDNS, SSDP, etc.)
const DISCOVERY_ROUTES: &[&str] = &[
    "224.0.0.0/4", // All IPv4 multicast (includes mDNS 224.0.0.251, SSDP 239.255.255.250)
];

/// Set up bypass tunnel routing (all traffic through VPN except specified routes).
///
/// This is the "exclude" or "bypass" mode - all traffic goes through VPN except:
/// - Traffic to specified bypass routes
/// - Optionally local network traffic (bypass_local)
/// - Optionally discovery/multicast traffic (bypass_discovery)
///
/// # Arguments
/// * `config` - Routing configuration (must have original_gateway set)
/// * `bypass_routes` - CIDR routes to exclude from VPN (go via physical interface)
/// * `bypass_local` - If true, LAN traffic bypasses VPN
/// * `bypass_discovery` - If true, multicast/discovery traffic bypasses VPN
pub fn setup_bypass_tunnel(
    config: &mut RoutingConfig,
    bypass_routes: &[&str],
    bypass_local: bool,
    bypass_discovery: bool,
) -> Result<(), MacosClientError> {
    info!(
        "Setting up bypass tunnel routing (bypass_local={}, bypass_discovery={}, {} custom routes)",
        bypass_local,
        bypass_discovery,
        bypass_routes.len()
    );

    // Get original default gateway (use pre-captured if available)
    let (original_gw, original_iface) =
        if let (Some(gw), Some(iface)) = (&config.original_gateway, &config.original_interface) {
            info!("Using pre-captured original gateway: {} via {}", gw, iface);
            (*gw, iface.clone())
        } else {
            // Detect now (safe on macOS since utun doesn't create default route)
            let (gw, iface) = get_default_gateway()?;
            config.original_gateway = Some(gw);
            config.original_interface = Some(iface.clone());
            info!("Detected original gateway: {} via {}", gw, iface);
            (gw, iface)
        };

    // Add route to VPN server via original gateway (so we can still reach it)
    add_route(
        &format!("{}/32", config.server_endpoint),
        original_gw,
        Some(&original_iface),
    )?;

    // If kill switch is enabled, delete the original default route
    if config.kill_switch {
        info!("Kill switch enabled: removing original default route");
        if delete_route("default").is_ok() {
            config.deleted_routes.push((
                "default".to_string(),
                original_gw,
                original_iface.clone(),
            ));
        }
    } else {
        // Without kill switch, just delete default to add VPN routes
        let _ = delete_route("default");
    }

    // Add VPN as default route (two /1 routes)
    add_route("0.0.0.0/1", config.gateway, Some(&config.interface))?;
    add_route("128.0.0.0/1", config.gateway, Some(&config.interface))?;

    // Add bypass routes via original gateway (these EXCLUDE from VPN)
    // Custom user-specified routes
    for route in bypass_routes {
        let route = route.trim();
        if route.is_empty() {
            continue;
        }
        info!("Adding bypass route: {} via {}", route, original_gw);
        if let Err(e) = add_route(route, original_gw, Some(&original_iface)) {
            warn!("Failed to add bypass route {}: {}", route, e);
        }
    }

    // Bypass local network traffic if enabled
    if bypass_local {
        info!("Adding LAN bypass routes");
        for subnet in LAN_SUBNETS {
            // Skip if the VPN gateway is in this subnet to avoid routing loop
            if subnet.starts_with("10.") && config.gateway.octets()[0] == 10 {
                info!("Skipping LAN route {} (VPN gateway in 10.x.x.x)", subnet);
                continue;
            }
            if let Err(e) = add_route(subnet, original_gw, Some(&original_iface)) {
                warn!("Failed to add LAN bypass route {}: {}", subnet, e);
            }
        }
    }

    // Bypass discovery/multicast traffic if enabled
    if bypass_discovery {
        info!("Adding discovery bypass routes (mDNS, SSDP, etc.)");
        for route in DISCOVERY_ROUTES {
            if let Err(e) = add_route(route, original_gw, Some(&original_iface)) {
                warn!("Failed to add discovery bypass route {}: {}", route, e);
            }
        }
    }

    info!(
        "Bypass tunnel routing established (kill_switch={}, bypass_local={}, bypass_discovery={})",
        config.kill_switch, bypass_local, bypass_discovery
    );

    Ok(())
}

/// Configure DNS servers using scutil (IPv4 only).
pub fn configure_dns(
    dns_servers: &[[u8; 4]],
    search_domains: &[&str],
) -> Result<(), MacosClientError> {
    configure_dns_dual_stack(dns_servers, &[], search_domains)
}

/// Validate that a string is a safe DNS server address (no shell injection).
fn validate_dns_string(s: &str) -> bool {
    // DNS addresses should only contain alphanumeric, dots, colons (IPv6), and nothing else
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == ':')
        && !s.is_empty()
        && s.len() <= 45 // Max IPv6 length
}

/// Validate that a string is a safe domain name (no shell injection).
fn validate_domain_string(s: &str) -> bool {
    // Domain names should only contain alphanumeric, hyphens, and dots
    s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        && !s.is_empty()
        && s.len() <= 253 // Max domain name length
        && !s.starts_with('-')
        && !s.starts_with('.')
}

/// Configure DNS servers using scutil (dual-stack IPv4 + IPv6).
pub fn configure_dns_dual_stack(
    dns_servers_v4: &[[u8; 4]],
    dns_servers_v6: &[[u8; 16]],
    search_domains: &[&str],
) -> Result<(), MacosClientError> {
    use std::io::Write;

    // Convert IPv4 addresses to strings (these are safe since they're from byte arrays)
    let dns_str_v4: Vec<String> = dns_servers_v4
        .iter()
        .map(|d| format!("{}.{}.{}.{}", d[0], d[1], d[2], d[3]))
        .collect();

    // Convert IPv6 addresses to strings (these are safe since they're from byte arrays)
    let dns_str_v6: Vec<String> = dns_servers_v6
        .iter()
        .map(|d| Ipv6Addr::from(*d).to_string())
        .collect();

    // Combine all DNS servers (IPv4 first, then IPv6)
    let all_dns: Vec<&str> = dns_str_v4
        .iter()
        .map(|s| s.as_str())
        .chain(dns_str_v6.iter().map(|s| s.as_str()))
        .collect();

    if all_dns.is_empty() {
        return Err(MacosClientError::SystemConfig(
            "no DNS servers provided".to_string(),
        ));
    }

    // Validate all DNS addresses (extra safety check)
    for dns in &all_dns {
        if !validate_dns_string(dns) {
            return Err(MacosClientError::SystemConfig(format!(
                "invalid DNS server address: {}",
                dns
            )));
        }
    }

    // Validate search domains to prevent injection
    for domain in search_domains {
        if !validate_domain_string(domain) {
            return Err(MacosClientError::SystemConfig(format!(
                "invalid search domain: {}",
                domain
            )));
        }
    }

    // Build the scutil dictionary
    let mut dns_config = String::new();
    dns_config.push_str("d.init\n");
    dns_config.push_str("d.add ServerAddresses *");
    for dns in &all_dns {
        dns_config.push(' ');
        dns_config.push_str(dns);
    }
    dns_config.push('\n');

    if !search_domains.is_empty() {
        dns_config.push_str("d.add SearchDomains *");
        for domain in search_domains {
            dns_config.push(' ');
            dns_config.push_str(domain);
        }
        dns_config.push('\n');
    }

    dns_config.push_str("set State:/Network/Service/HPN-VPN/DNS\n");
    dns_config.push_str("quit\n");

    let mut child = Command::new("scutil")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| MacosClientError::SystemConfig(format!("failed to run scutil: {}", e)))?;

    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(dns_config.as_bytes()).map_err(|e| {
            MacosClientError::SystemConfig(format!("failed to write to scutil: {}", e))
        })?;
    }

    let status = child
        .wait()
        .map_err(|e| MacosClientError::SystemConfig(format!("scutil failed: {}", e)))?;

    if !status.success() {
        return Err(MacosClientError::SystemConfig(
            "scutil DNS configuration failed".to_string(),
        ));
    }

    info!(
        "Configured DNS servers: IPv4={:?}, IPv6={:?}",
        dns_str_v4, dns_str_v6
    );

    Ok(())
}

/// Remove DNS configuration.
pub fn remove_dns() -> Result<(), MacosClientError> {
    let output = Command::new("scutil")
        .args(["--dns"])
        .stdin(std::process::Stdio::piped())
        .output()
        .map_err(|e| MacosClientError::SystemConfig(format!("failed to run scutil: {}", e)))?;

    // Just try to remove our DNS entry
    let _ = Command::new("scutil")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            if let Some(stdin) = child.stdin.as_mut() {
                use std::io::Write;
                let _ = stdin.write_all(b"remove State:/Network/Service/HPN-VPN/DNS\nquit\n");
            }
            child.wait()
        });

    if output.status.success() {
        debug!("Removed DNS configuration");
    }

    Ok(())
}

/// DNS leak protection manager for macOS.
///
/// Uses scutil to configure DNS and ensures all DNS queries go through the VPN.
/// Supports dual-stack IPv4/IPv6 DNS servers.
pub struct DnsLeakProtection {
    /// Whether protection is active.
    active: bool,
    /// VPN DNS servers (IPv4).
    vpn_dns: Vec<[u8; 4]>,
    /// VPN DNS servers (IPv6).
    vpn_dns_v6: Vec<[u8; 16]>,
}

impl DnsLeakProtection {
    /// Create a new DNS leak protection manager.
    pub fn new() -> Self {
        Self {
            active: false,
            vpn_dns: Vec::new(),
            vpn_dns_v6: Vec::new(),
        }
    }

    /// Enable DNS leak protection (IPv4 only).
    ///
    /// On macOS, this uses scutil to:
    /// 1. Set VPN DNS as the primary resolver
    /// 2. Use the system's resolver ordering to prefer our VPN DNS
    pub fn enable(&mut self, vpn_dns: &[[u8; 4]]) -> io::Result<()> {
        self.enable_dual_stack(vpn_dns, &[])
    }

    /// Enable DNS leak protection (dual-stack IPv4 + IPv6).
    ///
    /// On macOS, this uses scutil to:
    /// 1. Set VPN DNS (IPv4 and IPv6) as the primary resolver
    /// 2. Use the system's resolver ordering to prefer our VPN DNS
    pub fn enable_dual_stack(
        &mut self,
        vpn_dns_v4: &[[u8; 4]],
        vpn_dns_v6: &[[u8; 16]],
    ) -> io::Result<()> {
        if self.active {
            return Ok(());
        }

        info!("Enabling DNS leak protection (dual-stack)");

        // Store VPN DNS for later reference
        self.vpn_dns = vpn_dns_v4.to_vec();
        self.vpn_dns_v6 = vpn_dns_v6.to_vec();

        // Configure VPN DNS using scutil
        if let Err(e) = configure_dns_dual_stack(vpn_dns_v4, vpn_dns_v6, &[]) {
            warn!("Failed to configure VPN DNS: {}", e);
            return Err(io::Error::new(io::ErrorKind::Other, e.to_string()));
        }

        // Flush DNS cache
        let _ = run_command_with_timeout("dscacheutil", &["-flushcache"], COMMAND_TIMEOUT);
        let _ = run_command_with_timeout("killall", &["-HUP", "mDNSResponder"], COMMAND_TIMEOUT);

        self.active = true;
        info!("DNS leak protection enabled");

        Ok(())
    }

    /// Disable DNS leak protection and restore original settings.
    pub fn disable(&mut self) -> io::Result<()> {
        if !self.active {
            return Ok(());
        }

        info!("Disabling DNS leak protection");

        // Remove VPN DNS configuration
        if let Err(e) = remove_dns() {
            warn!("Failed to remove VPN DNS: {}", e);
        }

        // Flush DNS cache
        let _ = run_command_with_timeout("dscacheutil", &["-flushcache"], COMMAND_TIMEOUT);
        let _ = run_command_with_timeout("killall", &["-HUP", "mDNSResponder"], COMMAND_TIMEOUT);

        self.vpn_dns.clear();
        self.vpn_dns_v6.clear();
        self.active = false;
        info!("DNS leak protection disabled");

        Ok(())
    }

    /// Check if DNS leak protection is active.
    pub fn is_active(&self) -> bool {
        self.active
    }
}

impl Default for DnsLeakProtection {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for DnsLeakProtection {
    fn drop(&mut self) {
        // Always restore DNS on drop
        let _ = self.disable();
    }
}

/// IPv6 leak protection manager.
///
/// Prevents IPv6 traffic from bypassing the VPN when only IPv4 is configured.
/// This is critical because many systems prefer IPv6 over IPv4, which can leak
/// traffic outside the VPN tunnel.
pub struct Ipv6LeakProtection {
    /// Whether IPv6 is currently disabled.
    disabled: bool,
    /// Original IPv6 forwarding state.
    original_ipv6_forwarding: Option<bool>,
    /// When `true` (the default), `Drop` re-enables IPv6 globally and on
    /// the per-interface settings that were touched by `disable_ipv6`.
    /// Set to `false` on the kill-switch-engaged unexpected-disconnect
    /// path so IPv6 stays blocked until the user explicitly reconnects
    /// or disables the kill switch.
    ///
    /// Mirrors the equivalent flag on the Windows
    /// [`hpn_client_windows::routing::Ipv6LeakProtection`] for
    /// defense-in-depth: the macOS App Store build uses the OS-level
    /// kill switch via `NETunnelProviderManager` with
    /// `includeAllNetworks = true`, so this flag is dormant in
    /// production today, but a future CLI build that drives this struct
    /// directly must NOT silently re-enable IPv6 across a kill-switched
    /// disconnect — the same failure mode WIN-KS-1 covered on Windows.
    force_restore_on_drop: bool,
}

impl Ipv6LeakProtection {
    /// Create a new IPv6 leak protection manager.
    pub fn new() -> Self {
        Self {
            disabled: false,
            original_ipv6_forwarding: None,
            force_restore_on_drop: true,
        }
    }

    /// Control whether `Drop` re-enables IPv6 globally and on the
    /// per-interface settings.
    ///
    /// Pass `false` when the tunnel is tearing down into a kill-switch-
    /// engaged state so that physical-interface IPv6 is NOT restored.
    pub fn set_force_restore_on_drop(&mut self, value: bool) {
        self.force_restore_on_drop = value;
    }

    /// Disable IPv6 to prevent leaks.
    ///
    /// This disables IPv6 globally on the system to ensure all traffic
    /// goes through the IPv4 VPN tunnel.
    pub fn disable_ipv6(&mut self) -> Result<(), MacosClientError> {
        if self.disabled {
            return Ok(());
        }

        info!("Disabling IPv6 to prevent leaks");

        // Check current IPv6 forwarding state
        self.original_ipv6_forwarding = Some(self.get_ipv6_forwarding()?);

        // Disable IPv6 using sysctl
        let output = run_command_with_timeout(
            "sysctl",
            &["-w", "net.inet6.ip6.forwarding=0"],
            COMMAND_TIMEOUT,
        )
        .map_err(|e| MacosClientError::SystemConfig(format!("failed to disable IPv6: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(MacosClientError::SystemConfig(format!(
                "sysctl failed to disable IPv6: {}",
                stderr
            )));
        }

        // Also disable IPv6 on all network interfaces using networksetup
        let _ = self.disable_ipv6_on_interfaces();

        self.disabled = true;
        info!("IPv6 disabled successfully");

        Ok(())
    }

    /// Re-enable IPv6 (restore original state).
    pub fn enable_ipv6(&mut self) -> Result<(), MacosClientError> {
        if !self.disabled {
            return Ok(());
        }

        info!("Re-enabling IPv6");

        // Restore IPv6 forwarding to original state
        if let Some(forwarding) = self.original_ipv6_forwarding {
            let value = if forwarding { "1" } else { "0" };
            let output = run_command_with_timeout(
                "sysctl",
                &["-w", &format!("net.inet6.ip6.forwarding={}", value)],
                COMMAND_TIMEOUT,
            )
            .map_err(|e| {
                MacosClientError::SystemConfig(format!("failed to restore IPv6: {}", e))
            })?;

            if !output.status.success() {
                warn!("Failed to restore IPv6 forwarding state");
            }
        }

        // Re-enable IPv6 on network interfaces
        let _ = self.enable_ipv6_on_interfaces();

        self.disabled = false;
        self.original_ipv6_forwarding = None;

        info!("IPv6 re-enabled");

        Ok(())
    }

    /// Check if IPv6 is currently disabled.
    pub fn is_disabled(&self) -> bool {
        self.disabled
    }

    // ========================================================================
    // Private implementation methods
    // ========================================================================

    /// Get IPv6 forwarding state.
    fn get_ipv6_forwarding(&self) -> Result<bool, MacosClientError> {
        let output =
            run_command_with_timeout("sysctl", &["net.inet6.ip6.forwarding"], COMMAND_TIMEOUT)
                .map_err(|e| {
                    MacosClientError::SystemConfig(format!(
                        "failed to get IPv6 forwarding state: {}",
                        e
                    ))
                })?;

        if !output.status.success() {
            return Err(MacosClientError::SystemConfig(
                "sysctl failed to get IPv6 forwarding".to_string(),
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        // Output format: "net.inet6.ip6.forwarding: 0" or "1"
        let enabled = stdout.contains(": 1");

        Ok(enabled)
    }

    /// Disable IPv6 on all network interfaces.
    fn disable_ipv6_on_interfaces(&self) -> Result<(), MacosClientError> {
        // Get list of network services
        let output = run_command_with_timeout(
            "networksetup",
            &["-listallnetworkservices"],
            COMMAND_TIMEOUT,
        )
        .map_err(|e| {
            MacosClientError::SystemConfig(format!("failed to list network services: {}", e))
        })?;

        if !output.status.success() {
            return Ok(()); // Non-critical
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Disable IPv6 on each service
        for line in stdout.lines().skip(1) {
            // Skip header line
            let service = line.trim();
            if service.is_empty() || service.starts_with('*') {
                continue;
            }

            // Disable IPv6
            let _ =
                run_command_with_timeout("networksetup", &["-setv6off", service], COMMAND_TIMEOUT);
        }

        Ok(())
    }

    /// Enable IPv6 on all network interfaces.
    fn enable_ipv6_on_interfaces(&self) -> Result<(), MacosClientError> {
        // Get list of network services
        let output = run_command_with_timeout(
            "networksetup",
            &["-listallnetworkservices"],
            COMMAND_TIMEOUT,
        )
        .map_err(|e| {
            MacosClientError::SystemConfig(format!("failed to list network services: {}", e))
        })?;

        if !output.status.success() {
            return Ok(()); // Non-critical
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Enable IPv6 automatic on each service
        for line in stdout.lines().skip(1) {
            let service = line.trim();
            if service.is_empty() || service.starts_with('*') {
                continue;
            }

            // Set IPv6 to automatic
            let _ = run_command_with_timeout(
                "networksetup",
                &["-setv6automatic", service],
                COMMAND_TIMEOUT,
            );
        }

        Ok(())
    }
}

impl Default for Ipv6LeakProtection {
    fn default() -> Self {
        Self::new()
    }
}

impl Ipv6LeakProtection {
    /// Decide whether `Drop` should call `enable_ipv6` to restore the
    /// physical-interface state. Extracted for testability — see the
    /// equivalent helper on the Windows
    /// [`hpn_client_windows::routing::Ipv6LeakProtection`] for the
    /// full rationale.
    fn should_restore_ipv6_on_drop(&self) -> bool {
        self.force_restore_on_drop && self.disabled
    }
}

impl Drop for Ipv6LeakProtection {
    fn drop(&mut self) {
        // Honour the kill-switch contract: when the caller has signalled
        // that the tunnel is tearing down into an engaged kill-switch
        // state, we MUST NOT re-enable IPv6 here — doing so would leak
        // the user's real IP over every AAAA-capable destination while
        // IPv4 is (correctly) blocked elsewhere. Recovery from this
        // state is explicit (reconnect or disable kill switch).
        if self.should_restore_ipv6_on_drop() {
            if let Err(e) = self.enable_ipv6() {
                warn!("Failed to restore IPv6 on drop: {}", e);
            }
        } else if !self.force_restore_on_drop && self.disabled {
            tracing::info!(
                "Ipv6LeakProtection dropped with force_restore_on_drop=false \
                 (IPv6 kept disabled for kill-switch safety)"
            );
        }
    }
}

#[cfg(test)]
mod ipv6_leak_protection_tests {
    use super::Ipv6LeakProtection;

    #[test]
    fn force_restore_on_drop_defaults_to_true() {
        let prot = Ipv6LeakProtection::new();
        assert!(prot.force_restore_on_drop);
    }

    #[test]
    fn set_force_restore_on_drop_persists_value() {
        let mut prot = Ipv6LeakProtection::new();
        prot.set_force_restore_on_drop(false);
        assert!(!prot.force_restore_on_drop);
        prot.set_force_restore_on_drop(true);
        assert!(prot.force_restore_on_drop);
    }

    #[test]
    fn drop_decision_default_disabled_false() {
        let prot = Ipv6LeakProtection::new();
        assert!(!prot.should_restore_ipv6_on_drop());
    }

    #[test]
    fn drop_decision_disabled_true_default_restore() {
        let mut prot = Ipv6LeakProtection::new();
        prot.disabled = true;
        assert!(prot.should_restore_ipv6_on_drop());
    }

    #[test]
    fn drop_decision_disabled_true_kill_switch_engaged() {
        // Symmetric guard with the Windows test: kill-switched disconnect
        // must NOT re-enable IPv6 globally. macOS App Store build relies on
        // the OS-level kill switch via NETunnelProviderManager, so this
        // path is dormant in production today, but the contract still
        // holds for any future CLI build that drives this struct directly.
        let mut prot = Ipv6LeakProtection::new();
        prot.disabled = true;
        prot.set_force_restore_on_drop(false);
        assert!(!prot.should_restore_ipv6_on_drop());
    }
}

// ============================================================================
// PF (Packet Filter) Kill Switch
// ============================================================================

/// Default anchor name for HPN VPN pf rules.
const PF_ANCHOR_NAME: &str = "com.hpn-vpn";

/// Path to the anchor configuration file.
const PF_ANCHOR_FILE: &str = "/etc/pf.anchors/com.hpn-vpn";

/// PF-based kill switch for macOS.
///
/// Provides kernel-level traffic blocking using macOS's packet filter (pf) firewall.
/// This is more robust than routing-based kill switches because:
///
/// - Blocks raw socket traffic that can bypass routing tables
/// - Prevents mDNS/Bonjour leaks (multicast DNS)
/// - Works even if other applications modify routes
/// - Survives network interface changes
///
/// # Example
///
/// ```no_run
/// use hpn_client_macos::routing::PfKillSwitch;
///
/// let mut pf = PfKillSwitch::new();
///
/// // Enable when VPN connects
/// pf.enable("utun3", "203.0.113.1", 51820, true)?;
///
/// // Check status
/// assert!(pf.is_enabled());
///
/// // Disable on disconnect
/// pf.disable()?;
/// # Ok::<(), hpn_client_macos::error::MacosClientError>(())
/// ```
pub struct PfKillSwitch {
    /// Whether the kill switch is currently active.
    enabled: bool,
    /// The anchor name used for our pf rules.
    anchor_name: String,
    /// Path to the anchor file.
    anchor_file: String,
    /// Server IP that was allowed (for reference).
    server_ip: Option<String>,
    /// Server port that was allowed.
    server_port: Option<u16>,
    /// VPN interface name.
    vpn_interface: Option<String>,
}

impl PfKillSwitch {
    /// Create a new PF kill switch manager.
    pub fn new() -> Self {
        Self {
            enabled: false,
            anchor_name: PF_ANCHOR_NAME.to_string(),
            anchor_file: PF_ANCHOR_FILE.to_string(),
            server_ip: None,
            server_port: None,
            vpn_interface: None,
        }
    }

    /// Create a PF kill switch with a custom anchor name.
    ///
    /// Useful for testing or running multiple VPN instances.
    pub fn with_anchor_name(anchor_name: &str) -> Self {
        let anchor_file = format!("/etc/pf.anchors/{}", anchor_name);
        Self {
            enabled: false,
            anchor_name: anchor_name.to_string(),
            anchor_file,
            server_ip: None,
            server_port: None,
            vpn_interface: None,
        }
    }

    /// Enable the PF-based kill switch.
    ///
    /// This configures pf firewall rules to:
    /// 1. Block all outbound traffic by default
    /// 2. Allow loopback traffic (localhost)
    /// 3. Allow traffic to the VPN server (so the tunnel can be established)
    /// 4. Allow all traffic on the VPN interface (tunnel traffic)
    /// 5. Optionally allow LAN traffic for local network access
    ///
    /// # Arguments
    ///
    /// * `vpn_interface` - The VPN tunnel interface name (e.g., "utun3")
    /// * `server_ip` - The VPN server's IP address (IPv4 or IPv6)
    /// * `server_port` - The VPN server's UDP port
    /// * `allow_lan` - Whether to allow LAN traffic (RFC1918 + link-local)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Writing the anchor file fails (permissions)
    /// - Loading the anchor into pf fails
    /// - Enabling pf fails
    pub fn enable(
        &mut self,
        vpn_interface: &str,
        server_ip: &str,
        server_port: u16,
        allow_lan: bool,
    ) -> Result<(), MacosClientError> {
        if self.enabled {
            info!("PF kill switch already enabled, updating rules");
            // Disable first to ensure clean state
            let _ = self.disable_internal(false);
        }

        info!(
            "Enabling PF kill switch: interface={}, server={}:{}, allow_lan={}",
            vpn_interface, server_ip, server_port, allow_lan
        );

        // Validate inputs
        self.validate_interface_name(vpn_interface)?;
        self.validate_ip_address(server_ip)?;

        // Build pf rules
        let rules = self.build_rules(vpn_interface, server_ip, server_port, allow_lan)?;

        // Write rules to anchor file
        self.write_anchor_file(&rules)?;

        // Ensure the anchor is referenced in pf.conf
        self.ensure_anchor_in_pf_conf()?;

        // Load the anchor rules
        self.load_anchor()?;

        // Enable pf if not already enabled
        self.enable_pf()?;

        // Store state
        self.enabled = true;
        self.server_ip = Some(server_ip.to_string());
        self.server_port = Some(server_port);
        self.vpn_interface = Some(vpn_interface.to_string());

        info!("PF kill switch enabled successfully");
        Ok(())
    }

    /// Enable the PF kill switch with an IPv4 address.
    pub fn enable_v4(
        &mut self,
        vpn_interface: &str,
        server_ip: Ipv4Addr,
        server_port: u16,
        allow_lan: bool,
    ) -> Result<(), MacosClientError> {
        self.enable(
            vpn_interface,
            &server_ip.to_string(),
            server_port,
            allow_lan,
        )
    }

    /// Enable the PF kill switch with an IPv6 address.
    pub fn enable_v6(
        &mut self,
        vpn_interface: &str,
        server_ip: Ipv6Addr,
        server_port: u16,
        allow_lan: bool,
    ) -> Result<(), MacosClientError> {
        self.enable(
            vpn_interface,
            &server_ip.to_string(),
            server_port,
            allow_lan,
        )
    }

    /// Enable the PF kill switch with a generic IP address.
    pub fn enable_ip(
        &mut self,
        vpn_interface: &str,
        server_ip: IpAddr,
        server_port: u16,
        allow_lan: bool,
    ) -> Result<(), MacosClientError> {
        self.enable(
            vpn_interface,
            &server_ip.to_string(),
            server_port,
            allow_lan,
        )
    }

    /// Disable the PF kill switch and restore normal traffic flow.
    ///
    /// This removes the HPN VPN anchor rules from pf, allowing all traffic again.
    /// Note: This does NOT disable pf entirely, only removes our rules.
    pub fn disable(&mut self) -> Result<(), MacosClientError> {
        self.disable_internal(true)
    }

    /// Internal disable implementation.
    fn disable_internal(&mut self, log_if_not_enabled: bool) -> Result<(), MacosClientError> {
        if !self.enabled && log_if_not_enabled {
            debug!("PF kill switch not enabled, nothing to disable");
            return Ok(());
        }

        info!("Disabling PF kill switch");

        // Flush anchor rules
        let output = run_command_with_timeout(
            "pfctl",
            &["-a", &self.anchor_name, "-F", "all"],
            COMMAND_TIMEOUT,
        );

        match output {
            Ok(o) if !o.status.success() => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                // Ignore "anchor does not exist" errors
                if !stderr.contains("does not exist") && !stderr.contains("No such file") {
                    warn!("Failed to flush pf anchor: {}", stderr);
                }
            }
            Err(e) => {
                warn!("Failed to run pfctl flush: {}", e);
            }
            _ => {}
        }

        // Remove anchor file
        if std::path::Path::new(&self.anchor_file).exists()
            && let Err(e) = std::fs::remove_file(&self.anchor_file)
        {
            warn!("Failed to remove anchor file: {}", e);
        }

        // Remove anchor reference from /etc/pf.conf (prevent stale entries)
        self.remove_anchor_from_pf_conf();

        // Clear state
        self.enabled = false;
        self.server_ip = None;
        self.server_port = None;
        self.vpn_interface = None;

        info!("PF kill switch disabled");
        Ok(())
    }

    /// Check if the kill switch is currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Check if pf is currently running on the system.
    pub fn is_pf_running() -> Result<bool, MacosClientError> {
        let output =
            run_command_with_timeout("pfctl", &["-s", "info"], COMMAND_TIMEOUT).map_err(|e| {
                MacosClientError::SystemConfig(format!("failed to check pf status: {}", e))
            })?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        // Look for "Status: Enabled" in the output
        Ok(stdout.contains("Status: Enabled"))
    }

    /// Get the current server IP being allowed through the kill switch.
    pub fn server_ip(&self) -> Option<&str> {
        self.server_ip.as_deref()
    }

    /// Get the current server port being allowed through the kill switch.
    pub fn server_port(&self) -> Option<u16> {
        self.server_port
    }

    /// Get the VPN interface name.
    pub fn vpn_interface(&self) -> Option<&str> {
        self.vpn_interface.as_deref()
    }

    // ========================================================================
    // Private implementation methods
    // ========================================================================

    /// Validate that an interface name is safe (no shell injection).
    fn validate_interface_name(&self, name: &str) -> Result<(), MacosClientError> {
        // Interface names should be alphanumeric (e.g., utun0, en0)
        if name.is_empty() || name.len() > 16 {
            return Err(MacosClientError::SystemConfig(format!(
                "invalid interface name length: {}",
                name
            )));
        }

        if !name.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(MacosClientError::SystemConfig(format!(
                "invalid interface name (must be alphanumeric): {}",
                name
            )));
        }

        Ok(())
    }

    /// Validate that an IP address is valid.
    fn validate_ip_address(&self, ip: &str) -> Result<(), MacosClientError> {
        // Try parsing as IPv4 or IPv6
        if ip.parse::<Ipv4Addr>().is_ok() || ip.parse::<Ipv6Addr>().is_ok() {
            return Ok(());
        }

        Err(MacosClientError::SystemConfig(format!(
            "invalid IP address: {}",
            ip
        )))
    }

    /// Build the pf rules for the kill switch.
    fn build_rules(
        &self,
        vpn_interface: &str,
        server_ip: &str,
        server_port: u16,
        allow_lan: bool,
    ) -> Result<String, MacosClientError> {
        let mut rules = String::new();

        // Comment header
        rules.push_str("# HPN VPN Kill Switch Rules\n");
        rules.push_str("# Auto-generated - do not edit manually\n\n");

        // Block all traffic by default (in/out)
        // Using 'block drop' to silently drop packets (no ICMP response)
        rules.push_str("# Block all traffic by default\n");
        rules.push_str("block drop all\n\n");

        // Allow loopback traffic (critical for local services)
        rules.push_str("# Allow loopback traffic\n");
        rules.push_str("pass quick on lo0 all\n\n");

        // Allow DHCP (needed to maintain network connectivity)
        rules.push_str("# Allow DHCP\n");
        rules.push_str("pass out quick proto udp from any port 68 to any port 67\n");
        rules.push_str("pass in quick proto udp from any port 67 to any port 68\n\n");

        // Allow traffic to VPN server (so we can establish/maintain the tunnel)
        rules.push_str("# Allow VPN server connection\n");
        let is_ipv6 = server_ip.contains(':');
        let inet = if is_ipv6 { "inet6" } else { "inet" };
        use std::fmt::Write;
        let _ = writeln!(
            rules,
            "pass out quick {} proto udp to {} port {}",
            inet, server_ip, server_port
        );
        let _ = writeln!(
            rules,
            "pass in quick {} proto udp from {} port {}\n",
            inet, server_ip, server_port
        );

        // Allow all traffic on VPN interface (this is the secure tunnel)
        rules.push_str("# Allow all traffic on VPN interface\n");
        let _ = writeln!(rules, "pass quick on {} all\n", vpn_interface);

        // Allow LAN traffic if enabled
        if allow_lan {
            rules.push_str("# Allow LAN traffic\n");

            // IPv4 LAN subnets
            for subnet in LAN_SUBNETS {
                let _ = writeln!(rules, "pass out quick inet to {}", subnet);
                let _ = writeln!(rules, "pass in quick inet from {}", subnet);
            }

            // IPv6 LAN subnets
            for subnet in LAN_SUBNETS_V6 {
                let _ = writeln!(rules, "pass out quick inet6 to {}", subnet);
                let _ = writeln!(rules, "pass in quick inet6 from {}", subnet);
            }

            rules.push('\n');
        }

        // Block mDNS explicitly (DNS leak via multicast)
        // This is blocked even if allow_lan is enabled because mDNS can leak queries
        rules.push_str("# Block mDNS to prevent DNS leaks\n");
        rules.push_str("block drop quick proto udp to 224.0.0.251 port 5353\n");
        rules.push_str("block drop quick proto udp to ff02::fb port 5353\n\n");

        // Block DNS-over-TLS (DoT) on port 853 to prevent DNS leaks
        rules.push_str("# Block DNS-over-TLS (DoT) to prevent DNS leaks\n");
        let _ = writeln!(
            rules,
            "block drop out quick proto tcp to any port {}",
            DOT_PORT
        );
        rules.push('\n');

        // Block DNS-over-HTTPS (DoH) to known providers on port 443
        // This prevents applications from bypassing VPN DNS via encrypted DNS
        rules.push_str("# Block DNS-over-HTTPS (DoH) to known providers\n");
        for ip in DOH_PROVIDERS_V4 {
            let _ = writeln!(
                rules,
                "block drop out quick inet proto tcp to {} port 443",
                ip
            );
        }
        for ip in DOH_PROVIDERS_V6 {
            let _ = writeln!(
                rules,
                "block drop out quick inet6 proto tcp to {} port 443",
                ip
            );
        }

        Ok(rules)
    }

    /// Write the rules to the anchor file.
    fn write_anchor_file(&self, rules: &str) -> Result<(), MacosClientError> {
        // Ensure parent directory exists
        let parent = std::path::Path::new(&self.anchor_file)
            .parent()
            .ok_or_else(|| {
                MacosClientError::SystemConfig("invalid anchor file path".to_string())
            })?;

        if !parent.exists() {
            std::fs::create_dir_all(parent).map_err(|e| {
                MacosClientError::SystemConfig(format!(
                    "failed to create anchor directory {}: {}",
                    parent.display(),
                    e
                ))
            })?;
        }

        std::fs::write(&self.anchor_file, rules).map_err(|e| {
            MacosClientError::SystemConfig(format!(
                "failed to write anchor file {}: {}",
                self.anchor_file, e
            ))
        })?;

        debug!("Wrote pf anchor file: {}", self.anchor_file);
        Ok(())
    }

    /// Atomically replace the contents of `/etc/pf.conf`.
    ///
    /// Writes `new_contents` to a sibling temp file in `/etc/`, fsyncs it,
    /// then `rename(2)`s on top of `/etc/pf.conf`. POSIX guarantees the
    /// `rename` is atomic on a single filesystem, so a SIGKILL or sudden
    /// power loss between the two steps cannot leave a half-written
    /// `pf.conf` on disk — the next boot reads either the pre-write
    /// contents or the post-write contents, never garbage.
    ///
    /// This is the H6 fix: the previous implementation called
    /// `std::fs::write(pf_conf, ...)` directly, which truncates the
    /// destination first and then writes byte-by-byte. A SIGKILL
    /// between truncate and write left `/etc/pf.conf` empty, which
    /// disables ALL system PF rules at the next reboot — including
    /// firewall rules the user may have configured outside HPN.
    ///
    /// Best-effort fsync: a failure to flush the temp file is logged
    /// but not propagated as an error, matching the rest of the
    /// kill-switch code's "log + continue" posture for filesystem
    /// errors.
    fn atomic_write_pf_conf(&self, new_contents: &str) -> Result<(), MacosClientError> {
        use std::io::Write;
        let pf_conf = "/etc/pf.conf";
        // Use a fixed `.hpn-tmp` suffix in /etc/. We deliberately avoid
        // randomised tmpnam-style names: the same path is reused on
        // every call, so a crashed mid-write leaves a single
        // recognisable file behind that the next call overwrites
        // (rather than accumulating dozens of stale tempfiles in
        // /etc/).
        let pf_conf_tmp = "/etc/pf.conf.hpn-tmp";

        // Write + fsync the temp file. We open with `truncate=true` so
        // a leftover file from a previous crashed write is replaced
        // wholesale, then fsync the file descriptor before close so the
        // bytes hit the platter (or APFS commit) before we cross-link
        // into the canonical path.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(pf_conf_tmp)
            .map_err(|e| {
                MacosClientError::SystemConfig(format!(
                    "failed to open {} for atomic write: {}",
                    pf_conf_tmp, e
                ))
            })?;
        file.write_all(new_contents.as_bytes()).map_err(|e| {
            MacosClientError::SystemConfig(format!("failed to write {}: {}", pf_conf_tmp, e))
        })?;
        if let Err(e) = file.sync_all() {
            warn!(
                "fsync({}) failed: {} (continuing — rename will still be atomic, \
                 but a crash before the next pdflush could replay the old contents)",
                pf_conf_tmp, e
            );
        }
        drop(file);

        // Atomic rename on top of /etc/pf.conf. On macOS this is a
        // single APFS metadata transaction.
        std::fs::rename(pf_conf_tmp, pf_conf).map_err(|e| {
            // Best-effort cleanup so we don't leave the temp file
            // behind on a failed rename.
            let _ = std::fs::remove_file(pf_conf_tmp);
            MacosClientError::SystemConfig(format!(
                "failed to rename {} -> {}: {}",
                pf_conf_tmp, pf_conf, e
            ))
        })?;
        Ok(())
    }

    /// Ensure the anchor is referenced in /etc/pf.conf.
    fn ensure_anchor_in_pf_conf(&self) -> Result<(), MacosClientError> {
        let pf_conf = "/etc/pf.conf";
        let anchor_line = format!("anchor \"{}\"", self.anchor_name);
        let load_line = format!(
            "load anchor \"{}\" from \"{}\"",
            self.anchor_name, self.anchor_file
        );

        // Read current pf.conf
        let contents = std::fs::read_to_string(pf_conf).map_err(|e| {
            MacosClientError::SystemConfig(format!("failed to read {}: {}", pf_conf, e))
        })?;

        // Check if anchor is already referenced
        if contents.contains(&anchor_line) {
            debug!("Anchor already referenced in pf.conf");
            return Ok(());
        }

        // Append anchor reference to pf.conf
        // We need to add both the anchor declaration and the load directive
        let mut new_contents = contents;
        if !new_contents.ends_with('\n') {
            new_contents.push('\n');
        }
        new_contents.push_str("\n# HPN VPN Kill Switch\n");
        new_contents.push_str(&anchor_line);
        new_contents.push('\n');
        new_contents.push_str(&load_line);
        new_contents.push('\n');

        // Atomic temp-file + rename instead of std::fs::write — see
        // `atomic_write_pf_conf` for the full rationale (audit H6).
        self.atomic_write_pf_conf(&new_contents)?;

        info!("Added HPN VPN anchor to pf.conf");
        Ok(())
    }

    /// Remove the HPN VPN anchor reference from /etc/pf.conf to prevent stale entries.
    fn remove_anchor_from_pf_conf(&self) {
        let pf_conf = "/etc/pf.conf";

        let contents = match std::fs::read_to_string(pf_conf) {
            Ok(c) => c,
            Err(e) => {
                debug!("Could not read {} for anchor cleanup: {}", pf_conf, e);
                return;
            }
        };

        // Filter out lines containing our anchor name or our comment
        let new_contents: String = contents
            .lines()
            .filter(|line| {
                !line.contains(&self.anchor_name) && !line.contains("# HPN VPN Kill Switch")
            })
            .collect::<Vec<_>>()
            .join("\n");

        // Only write if we actually removed something
        if new_contents.len() < contents.len() {
            let final_contents = if new_contents.ends_with('\n') {
                new_contents
            } else {
                format!("{}\n", new_contents)
            };

            // Atomic temp-file + rename — see `atomic_write_pf_conf` for
            // the rationale (audit H6).
            match self.atomic_write_pf_conf(&final_contents) {
                Ok(()) => info!("Removed HPN VPN anchor from pf.conf"),
                Err(e) => warn!("Failed to clean pf.conf: {}", e),
            }
        }
    }

    /// Load the anchor rules into pf.
    fn load_anchor(&self) -> Result<(), MacosClientError> {
        // Load rules from anchor file
        let output = run_command_with_timeout(
            "pfctl",
            &["-a", &self.anchor_name, "-f", &self.anchor_file],
            COMMAND_TIMEOUT,
        )
        .map_err(|e| MacosClientError::SystemConfig(format!("failed to load pf anchor: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(MacosClientError::SystemConfig(format!(
                "pfctl failed to load anchor: {}",
                stderr
            )));
        }

        debug!("Loaded pf anchor: {}", self.anchor_name);
        Ok(())
    }

    /// Enable pf if not already enabled.
    fn enable_pf(&self) -> Result<(), MacosClientError> {
        let output = run_command_with_timeout("pfctl", &["-e"], COMMAND_TIMEOUT)
            .map_err(|e| MacosClientError::SystemConfig(format!("failed to enable pf: {}", e)))?;

        // pfctl -e returns non-zero if pf is already enabled, but writes to stderr
        // "pf enabled" or "pfctl: pf already enabled"
        // Both are acceptable outcomes
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !output.status.success() && !stderr.contains("already enabled") {
            return Err(MacosClientError::SystemConfig(format!(
                "failed to enable pf: {}",
                stderr
            )));
        }

        debug!("pf enabled");
        Ok(())
    }
}

impl Default for PfKillSwitch {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for PfKillSwitch {
    fn drop(&mut self) {
        // Always disable on drop to restore normal traffic flow
        if self.enabled
            && let Err(e) = self.disable()
        {
            error!("Failed to disable PF kill switch on drop: {}", e);
        }
    }
}

// ============================================================================
// Integrated Kill Switch Manager
// ============================================================================

/// Comprehensive kill switch manager combining routing and pf firewall.
///
/// This manager provides defense-in-depth by using both:
/// 1. Routing table manipulation (removes default routes)
/// 2. PF firewall rules (kernel-level traffic blocking)
///
/// Using both layers ensures maximum protection against traffic leaks.
///
/// # Example
///
/// ```no_run
/// use hpn_client_macos::routing::KillSwitchManager;
///
/// let mut ks = KillSwitchManager::new();
///
/// // Enable when VPN connects
/// ks.enable("utun3", "203.0.113.1", 51820, true)?;
///
/// // Check status
/// assert!(ks.is_active());
///
/// // Disable on disconnect
/// ks.disable()?;
/// # Ok::<(), hpn_client_macos::error::MacosClientError>(())
/// ```
pub struct KillSwitchManager {
    /// PF-based kill switch.
    pf: PfKillSwitch,
    /// Whether the kill switch is active.
    active: bool,
    /// Allow LAN traffic setting.
    allow_lan: bool,
}

impl KillSwitchManager {
    /// Create a new kill switch manager.
    pub fn new() -> Self {
        Self {
            pf: PfKillSwitch::new(),
            active: false,
            allow_lan: true,
        }
    }

    /// Enable the kill switch.
    ///
    /// This enables the PF firewall kill switch. Routing-level kill switch
    /// should be handled separately via `setup_full_tunnel` with `kill_switch: true`.
    pub fn enable(
        &mut self,
        vpn_interface: &str,
        server_ip: &str,
        server_port: u16,
        allow_lan: bool,
    ) -> Result<(), MacosClientError> {
        info!("Enabling comprehensive kill switch");

        self.allow_lan = allow_lan;

        // Enable PF kill switch
        self.pf
            .enable(vpn_interface, server_ip, server_port, allow_lan)?;

        self.active = true;
        info!("Comprehensive kill switch enabled");
        Ok(())
    }

    /// Enable with IPv4 server address.
    pub fn enable_v4(
        &mut self,
        vpn_interface: &str,
        server_ip: Ipv4Addr,
        server_port: u16,
        allow_lan: bool,
    ) -> Result<(), MacosClientError> {
        self.enable(
            vpn_interface,
            &server_ip.to_string(),
            server_port,
            allow_lan,
        )
    }

    /// Disable the kill switch.
    pub fn disable(&mut self) -> Result<(), MacosClientError> {
        if !self.active {
            return Ok(());
        }

        info!("Disabling comprehensive kill switch");

        // Disable PF kill switch
        self.pf.disable()?;

        self.active = false;
        info!("Comprehensive kill switch disabled");
        Ok(())
    }

    /// Check if the kill switch is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Get a reference to the PF kill switch.
    pub fn pf(&self) -> &PfKillSwitch {
        &self.pf
    }

    /// Get a mutable reference to the PF kill switch.
    pub fn pf_mut(&mut self) -> &mut PfKillSwitch {
        &mut self.pf
    }
}

impl Default for KillSwitchManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for KillSwitchManager {
    fn drop(&mut self) {
        if self.active
            && let Err(e) = self.disable()
        {
            error!("Failed to disable kill switch manager on drop: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_routing_config_new() {
        let config = RoutingConfig::new(
            "utun3".to_string(),
            "10.0.0.1".parse().unwrap(),
            "1.2.3.4".parse().unwrap(),
        );

        assert_eq!(config.interface, "utun3");
        assert_eq!(config.gateway, "10.0.0.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(
            config.server_endpoint,
            "1.2.3.4".parse::<Ipv4Addr>().unwrap()
        );
        assert!(config.original_gateway.is_none());
    }

    #[test]
    #[ignore = "requires root privileges"]
    fn test_get_default_gateway() {
        let result = get_default_gateway();
        assert!(result.is_ok());
        let (gateway, interface) = result.unwrap();
        println!("Gateway: {} Interface: {}", gateway, interface);
    }

    #[test]
    fn test_ipv6_leak_protection_creation() {
        let ipv6_protection = Ipv6LeakProtection::new();
        assert!(!ipv6_protection.is_disabled());
    }

    #[test]
    fn test_pf_kill_switch_creation() {
        let pf = PfKillSwitch::new();
        assert!(!pf.is_enabled());
        assert!(pf.server_ip().is_none());
        assert!(pf.server_port().is_none());
        assert!(pf.vpn_interface().is_none());
    }

    #[test]
    fn test_pf_kill_switch_with_custom_anchor() {
        let pf = PfKillSwitch::with_anchor_name("test-anchor");
        assert!(!pf.is_enabled());
        assert_eq!(pf.anchor_name, "test-anchor");
        assert_eq!(pf.anchor_file, "/etc/pf.anchors/test-anchor");
    }

    #[test]
    fn test_pf_kill_switch_validate_interface() {
        let pf = PfKillSwitch::new();

        // Valid interface names
        assert!(pf.validate_interface_name("utun0").is_ok());
        assert!(pf.validate_interface_name("en0").is_ok());
        assert!(pf.validate_interface_name("utun123").is_ok());

        // Invalid interface names
        assert!(pf.validate_interface_name("").is_err());
        assert!(pf.validate_interface_name("utun-0").is_err());
        assert!(pf.validate_interface_name("utun.0").is_err());
        assert!(pf.validate_interface_name("a".repeat(17).as_str()).is_err());
    }

    #[test]
    fn test_pf_kill_switch_validate_ip() {
        let pf = PfKillSwitch::new();

        // Valid IPs
        assert!(pf.validate_ip_address("192.168.1.1").is_ok());
        assert!(pf.validate_ip_address("10.0.0.1").is_ok());
        assert!(pf.validate_ip_address("::1").is_ok());
        assert!(pf.validate_ip_address("2001:db8::1").is_ok());

        // Invalid IPs
        assert!(pf.validate_ip_address("").is_err());
        assert!(pf.validate_ip_address("invalid").is_err());
        assert!(pf.validate_ip_address("192.168.1").is_err());
    }

    #[test]
    fn test_pf_kill_switch_build_rules_ipv4() {
        let pf = PfKillSwitch::new();
        let rules = pf
            .build_rules("utun3", "203.0.113.1", 51820, false)
            .unwrap();

        // Check essential rules are present
        assert!(rules.contains("block drop all"));
        assert!(rules.contains("pass quick on lo0 all"));
        assert!(rules.contains("pass out quick inet proto udp to 203.0.113.1 port 51820"));
        assert!(rules.contains("pass in quick inet proto udp from 203.0.113.1 port 51820"));
        assert!(rules.contains("pass quick on utun3 all"));
        assert!(rules.contains("block drop quick proto udp to 224.0.0.251 port 5353"));

        // LAN rules should NOT be present when allow_lan is false
        assert!(!rules.contains("10.0.0.0/8"));
    }

    #[test]
    fn test_pf_kill_switch_build_rules_ipv4_with_lan() {
        let pf = PfKillSwitch::new();
        let rules = pf.build_rules("utun3", "203.0.113.1", 51820, true).unwrap();

        // Check LAN rules are present
        assert!(rules.contains("pass out quick inet to 10.0.0.0/8"));
        assert!(rules.contains("pass in quick inet from 10.0.0.0/8"));
        assert!(rules.contains("pass out quick inet to 192.168.0.0/16"));
        assert!(rules.contains("pass out quick inet6 to fe80::/10"));
    }

    #[test]
    fn test_pf_kill_switch_build_rules_ipv6() {
        let pf = PfKillSwitch::new();
        let rules = pf
            .build_rules("utun3", "2001:db8::1", 51820, false)
            .unwrap();

        // Check IPv6-specific rules
        assert!(rules.contains("pass out quick inet6 proto udp to 2001:db8::1 port 51820"));
        assert!(rules.contains("pass in quick inet6 proto udp from 2001:db8::1 port 51820"));
    }

    #[test]
    fn test_kill_switch_manager_creation() {
        let ks = KillSwitchManager::new();
        assert!(!ks.is_active());
        assert!(!ks.pf().is_enabled());
    }
}
