//! Windows routing table management.
//!
//! Manages routes for VPN traffic on Windows.
//! Supports full tunnel, split tunnel, and kill switch functionality.
//! IPv4 and IPv6 dual-stack support.
//!
//! This module now uses native Windows APIs via the `windows_api` module
//! for better performance and reliability. The recovery system ensures
//! network settings are restored after crashes.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::windows::process::CommandExt;
use std::process::Command;
use std::time::Duration;

use tracing::{debug, error, info, warn};

use crate::recovery::RecoveryState;
use crate::windows_api;
use crate::windows_api::RouteEntry;

/// Windows flag to hide console window when spawning processes.
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Default timeout for system commands (route, netsh, etc.)
/// Increased to 30s because netsh can be very slow on some Windows machines,
/// especially when enumerating interfaces or changing DNS settings.
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
        .creation_flags(CREATE_NO_WINDOW)
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

use crate::error::WindowsClientError;

/// Execute a PowerShell firewall-rule command with timeout.
///
/// We switched the IPv6-block rule management from
/// `netsh advfirewall firewall add rule` to PowerShell's
/// `New-NetFirewallRule` / `Remove-NetFirewallRule` because netsh's
/// legacy `add rule` syntax does NOT accept `protocol=ipv6` — its
/// protocol field is a numeric ID or one of `icmpv4/icmpv6/tcp/udp`,
/// never an IP-family selector. Passing `protocol=ipv6` to netsh
/// yields "Une valeur de protocole spécifiée est non valide." /
/// "A specified protocol value is invalid." and the whole rule is
/// refused.
///
/// PowerShell's `New-NetFirewallRule -Protocol IPv6` is the
/// officially-supported way to block "all IPv6 traffic" on Windows
/// Defender Firewall. It is available since Windows 8 / Server 2012
/// via the `NetSecurity` module, which is preinstalled on every
/// supported Windows SKU — no extra feature install needed.
///
/// The helper spawns `powershell.exe` with `-NoProfile` (skips
/// `$PROFILE.ps1` — faster startup, deterministic behaviour) and
/// `-NonInteractive` (errors out instead of prompting). The script
/// passed in `command` runs in a single PowerShell session.
fn run_powershell_firewall(command: &str) -> io::Result<std::process::Output> {
    run_command_with_timeout(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
        ],
        COMMAND_TIMEOUT,
    )
}

/// Format a netsh or PowerShell firewall-rule failure into a
/// user-actionable message.
///
/// `netsh` / `powershell.exe` both have quirks that routinely trip up
/// support:
///
///   * They frequently emit their error text on STDOUT, not STDERR.
///     Our original `format!("netsh add rule failed: {}", stderr.trim())`
///     therefore produced an empty `: ` suffix on the most common
///     failure mode, leaving the user staring at
///     "netsh add rule failed:" with no clue.
///   * The most frequent failure is UAC-elevation-missing, which
///     surfaces as "Requested operation requires elevation" /
///     "Access is denied" / "Accès refusé" in the STDOUT stream.
///     We pattern-match those and append a concise admin hint rather
///     than quoting the raw Windows error verbatim.
///   * PowerShell-specific errors (execution-policy block, module
///     missing) get their own hint.
///
/// Used by every wrapper around a privileged Windows command in this
/// module (IPv6 block firewall rule, DNS setters, route adds) so every
/// caller gets the same diagnostic quality without re-implementing the
/// logic.
fn format_netsh_error(prefix: &str, stdout: &[u8], stderr: &[u8]) -> String {
    let stderr_text = String::from_utf8_lossy(stderr);
    let stdout_text = String::from_utf8_lossy(stdout);
    let stderr_trim = stderr_text.trim();
    let stdout_trim = stdout_text.trim();

    // Pick whichever stream actually contains text; the Windows
    // command surface flips between the two depending on subcommand
    // and OS build.
    let detail = if !stderr_trim.is_empty() {
        stderr_trim
    } else if !stdout_trim.is_empty() {
        stdout_trim
    } else {
        // Non-zero exit with no output — extremely rare, usually an
        // aborted command pipe. Placeholder keeps the caller message
        // parseable.
        "no output (command aborted silently)"
    };

    // Common failure modes we can turn into actionable hints.
    let lowered = detail.to_ascii_lowercase();
    let hint = if lowered.contains("requires elevation")
        || lowered.contains("access is denied")
        || lowered.contains("acces refusé")
        || lowered.contains("acces refuse")
        || lowered.contains("accès refusé")
    {
        " — run the HPN VPN client as Administrator \
           (right-click the shortcut → Run as administrator)"
    } else if lowered.contains("ipv6 is not installed")
        || lowered.contains("ipv6 transitions")
        || lowered.contains("the requested protocol has not been configured")
    {
        " — IPv6 appears disabled on this host. Re-enable IPv6 in the \
           adapter properties or run the VPN in IPv4-only mode."
    } else if lowered.contains("cannot be loaded because running scripts")
        || lowered.contains("executionpolicy")
    {
        " — PowerShell execution policy is blocking firewall management. \
           Contact your IT admin or set ExecutionPolicy to RemoteSigned."
    } else if lowered.contains("cannot be found") && lowered.contains("new-netfirewallrule") {
        " — the Windows NetSecurity PowerShell module is missing. \
           Update Windows or re-install the Windows management tools."
    } else if lowered.contains("the protocol is invalid")
        || lowered.contains("address prefixes")
        || lowered.contains("pr\u{00e9}fixes d'adresse")
        || lowered.contains("prefixes d'adresse")
        || lowered.contains("hresult 0x80070057")
        || lowered.contains("0x80070057")
    {
        // Defensive: Windows Firewall refused a parameter value we
        // thought was valid. Known historical causes:
        //   - `-Protocol IPv6` (not in the accepted list)
        //   - `-RemoteAddress ::/0` (the unspecified literal `::`
        //     is rejected on some Windows builds)
        // Both are fixed in the current code — it now uses the four
        // explicit IPv6 super-prefixes. Keep this hint so a future
        // refactor that accidentally reintroduces either value gets a
        // readable log line instead of a raw CIM exception dump.
        " — the rule was rejected by Windows Firewall (HRESULT \
           0x80070057 / E_INVALIDARG). This usually means a firewall \
           rule parameter was set to a value the kernel does not \
           accept. Check recent changes to routing.rs."
    } else {
        ""
    };

    format!("{}: {}{}", prefix, detail, hint)
}

/// LAN subnets (IPv4) to allow when kill switch + allow LAN is enabled.
const LAN_SUBNETS: &[(&str, &str)] = &[
    ("10.0.0.0", "255.0.0.0"),      // 10.0.0.0/8
    ("172.16.0.0", "255.240.0.0"),  // 172.16.0.0/12
    ("192.168.0.0", "255.255.0.0"), // 192.168.0.0/16
    ("169.254.0.0", "255.255.0.0"), // Link-local
];

/// LAN prefixes (IPv6) to allow when kill switch + allow LAN is enabled.
const LAN_SUBNETS_V6: &[(&str, u8)] = &[
    ("fe80::", 10), // Link-local
    ("fc00::", 7),  // Unique local addresses (ULA)
    ("fd00::", 8),  // ULA (more specific)
];

/// Multicast addresses for LAN discovery (mDNS, SSDP, etc.)
const DISCOVERY_SUBNETS: &[(&str, &str)] = &[
    ("224.0.0.0", "240.0.0.0"), // 224.0.0.0/4 - All IPv4 multicast
];

/// Route manager for Windows.
pub struct RouteManager {
    /// Original default gateway (for restoration).
    original_gateway: Option<String>,
    /// Original default gateway interface index.
    original_interface_idx: Option<u32>,
    /// VPN gateway IP (IPv4).
    vpn_gateway: String,
    /// VPN gateway IPv6 (if dual-stack).
    vpn_gateway_v6: Option<String>,
    /// VPN interface name.
    vpn_interface: String,
    /// Server endpoint to exclude from VPN.
    server_endpoint: String,
    /// IPv4 routes that were added.
    added_routes: Vec<String>,
    /// IPv6 routes that were added.
    added_routes_v6: Vec<String>,
    /// IPv4 routes that were deleted (for restoration).
    deleted_routes: Vec<(String, String, String)>, // (dest, mask, gateway)
    /// IPv6 routes that were deleted (for restoration).
    /// Format: (dest, prefix_len, interface, gateway)
    deleted_routes_v6: Vec<(String, u8, String, String)>,
    /// Kill switch enabled.
    kill_switch: bool,
    /// Allow LAN traffic when kill switch is active.
    allow_lan: bool,
    /// IPv6 enabled.
    ipv6_enabled: bool,
    /// Recovery state for crash recovery.
    recovery_state: Option<RecoveryState>,
    /// Force restore on drop (false = respect kill_switch, true = always restore).
    /// Set to false when kill switch should remain engaged after unexpected disconnect.
    force_restore_on_drop: bool,
    /// True if IPv6 egress was blocked at the firewall to prevent leaks on IPv4-only tunnels.
    /// Cleared on `cleanup()`.
    ipv6_blocked: bool,
    /// True if the DNS-over-HTTPS / DNS-over-TLS / mDNS egress block
    /// rules are installed. Cleared on `cleanup()`. Mirrors the macOS
    /// PF anchor's behaviour so both platforms close the same DNS-leak
    /// vectors (browser-side DoH, port-853 DoT, multicast 5353).
    dns_egress_blocked: bool,
}

/// Firewall rule name prefix used for HPN IPv6 leak protection rules.
///
/// We tag every rule we create so we can remove only our own rules on cleanup,
/// never touching user-created or system rules. Kept short to work around
/// Windows 10 `netsh advfirewall` name-length quirks.
const HPN_IPV6_BLOCK_RULE_NAME: &str = "HPN_VPN_IPv6_Block";

/// Firewall rule names for the DoH / DoT / mDNS egress blocks.
const HPN_DOH_BLOCK_RULE_NAME: &str = "HPN_VPN_DoH_Block";
const HPN_DOT_BLOCK_RULE_NAME: &str = "HPN_VPN_DoT_Block";
const HPN_MDNS_BLOCK_RULE_NAME: &str = "HPN_VPN_mDNS_Block";

/// Firewall rule names for the bootstrap IPv4 kill-switch.
///
/// Two rules are installed as a pair:
/// * `*_Allow_Server` permits outbound IPv4 to the VPN server endpoint
///   so the handshake can complete.
/// * `*_Block_All` denies every other outbound IPv4 destination.
///
/// Windows Firewall evaluates Allow rules before Block rules of the
/// same scope, so the pair behaves as "block all IPv4 except the
/// VPN server".
const HPN_IPV4_BOOTSTRAP_ALLOW_RULE_NAME: &str = "HPN_VPN_IPv4_Allow_Server";
const HPN_IPV4_BOOTSTRAP_BLOCK_RULE_NAME: &str = "HPN_VPN_IPv4_Block_All";
const HPN_IPV4_BOOTSTRAP_LOOPBACK_RULE_NAME: &str = "HPN_VPN_IPv4_Allow_Loopback";

/// Known DNS-over-HTTPS (DoH) provider IPv4 addresses.
///
/// Browsers (Chrome / Firefox / Edge) ship with built-in DoH that
/// resolves DNS over TCP/443 to one of these endpoints, completely
/// bypassing the system resolver — and therefore the VPN's DNS
/// leak-protection. We block outbound TCP/443 to the public DoH
/// resolvers so those built-in queries fail, forcing the browser back
/// onto the OS resolver (which is locked to the VPN's DNS by
/// `DnsLeakProtection`).
///
/// This is the same set the macOS PF anchor maintains in
/// `crates/hpn-client-macos/src/routing.rs::DOH_PROVIDERS_V4`. Keep
/// the two lists in sync.
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

/// DNS-over-TLS (DoT) port (RFC 7858).
const DOT_PORT: u16 = 853;

/// Multicast DNS port (RFC 6762).
const MDNS_PORT: u16 = 5353;

impl RouteManager {
    /// Create a new route manager (IPv4 only).
    pub fn new(vpn_gateway: &str, vpn_interface: &str, server_endpoint: &str) -> Self {
        Self {
            original_gateway: None,
            original_interface_idx: None,
            vpn_gateway: vpn_gateway.to_string(),
            vpn_gateway_v6: None,
            vpn_interface: vpn_interface.to_string(),
            server_endpoint: server_endpoint.to_string(),
            added_routes: Vec::new(),
            added_routes_v6: Vec::new(),
            deleted_routes: Vec::new(),
            deleted_routes_v6: Vec::new(),
            kill_switch: false,
            allow_lan: true,
            ipv6_enabled: false,
            recovery_state: None,
            force_restore_on_drop: true, // Default: always restore for safety
            ipv6_blocked: false,
            dns_egress_blocked: false,
        }
    }

    /// Create a new route manager with IPv6 support (dual-stack).
    pub fn new_dual_stack(
        vpn_gateway: &str,
        vpn_gateway_v6: &str,
        vpn_interface: &str,
        server_endpoint: &str,
    ) -> Self {
        Self {
            original_gateway: None,
            original_interface_idx: None,
            vpn_gateway: vpn_gateway.to_string(),
            vpn_gateway_v6: Some(vpn_gateway_v6.to_string()),
            vpn_interface: vpn_interface.to_string(),
            server_endpoint: server_endpoint.to_string(),
            added_routes: Vec::new(),
            added_routes_v6: Vec::new(),
            deleted_routes: Vec::new(),
            deleted_routes_v6: Vec::new(),
            kill_switch: false,
            allow_lan: true,
            ipv6_enabled: true,
            recovery_state: None,
            force_restore_on_drop: true,
            ipv6_blocked: false,
            dns_egress_blocked: false,
        }
    }

    /// Create a route manager with kill switch options.
    pub fn with_kill_switch(
        vpn_gateway: &str,
        vpn_interface: &str,
        server_endpoint: &str,
        kill_switch: bool,
        allow_lan: bool,
    ) -> Self {
        Self {
            original_gateway: None,
            original_interface_idx: None,
            vpn_gateway: vpn_gateway.to_string(),
            vpn_gateway_v6: None,
            vpn_interface: vpn_interface.to_string(),
            server_endpoint: server_endpoint.to_string(),
            added_routes: Vec::new(),
            added_routes_v6: Vec::new(),
            deleted_routes: Vec::new(),
            deleted_routes_v6: Vec::new(),
            kill_switch,
            allow_lan,
            ipv6_enabled: false,
            recovery_state: None,
            force_restore_on_drop: true,
            ipv6_blocked: false,
            dns_egress_blocked: false,
        }
    }

    /// Set whether to force restore routes on drop.
    ///
    /// When `false`, the `kill_switch` setting is respected on Drop:
    /// - If kill_switch=true, routes will NOT be restored (keeps internet blocked)
    /// - If kill_switch=false, routes WILL be restored
    ///
    /// When `true` (default), routes are always restored on Drop for safety.
    ///
    /// Call this with `false` when kill switch should remain engaged
    /// after an unexpected disconnect (network error, server down, etc).
    pub fn set_force_restore_on_drop(&mut self, force: bool) {
        self.force_restore_on_drop = force;
    }

    /// Enable IPv6 routing with the specified gateway.
    pub fn enable_ipv6(&mut self, gateway_v6: &str) {
        self.vpn_gateway_v6 = Some(gateway_v6.to_string());
        self.ipv6_enabled = true;
    }

    /// Set the original gateway (captured before VPN adapter was created).
    ///
    /// This is CRITICAL for preventing routing loops. The original gateway
    /// must be captured BEFORE the VPN adapter is created and configured,
    /// because Windows may add a default route when the VPN adapter gets
    /// a gateway configured.
    pub fn set_original_gateway(&mut self, gateway: String, interface_idx: u32) {
        info!(
            "Setting pre-captured original gateway: {} (IF={})",
            gateway, interface_idx
        );
        self.original_gateway = Some(gateway);
        self.original_interface_idx = Some(interface_idx);
    }

    /// Check if IPv6 is enabled.
    pub fn has_ipv6(&self) -> bool {
        self.ipv6_enabled && self.vpn_gateway_v6.is_some()
    }

    /// Check if kill switch is enabled.
    pub fn is_kill_switch_enabled(&self) -> bool {
        self.kill_switch
    }

    /// Get the current default gateway and interface index.
    /// Returns (gateway_ip, interface_index) where interface_index may be 0 if unknown.
    ///
    /// Uses the Windows API for reliable gateway detection.
    fn get_default_gateway() -> Option<(String, u32)> {
        // Try Windows API first
        match windows_api::get_default_gateway() {
            Ok(Some(route)) => {
                info!(
                    "Found default gateway via API: {} (IF={})",
                    route.gateway, route.interface_index
                );
                return Some((route.gateway.to_string(), route.interface_index));
            }
            Ok(None) => {
                debug!("No default gateway found via API");
            }
            Err(e) => {
                warn!(
                    "Failed to get default gateway via API: {}, falling back to route command",
                    e
                );
            }
        }

        // Fallback to route command parsing
        let output =
            run_command_with_timeout("route", &["print", "0.0.0.0"], COMMAND_TIMEOUT).ok()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        debug!("Route print output:\n{}", stdout);

        // Parse the routing table output to find default gateway
        // Format: Network Destination | Netmask | Gateway | Interface | Metric
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 && parts[0] == "0.0.0.0" && parts[1] == "0.0.0.0" {
                let gateway = parts[2].to_string();

                // Skip if gateway is "On-link" (local routes)
                if gateway == "On-link" {
                    continue;
                }

                // parts[4] is the metric, not interface index
                // parts[3] is the interface IP
                // We need to find the interface index from the interface IP
                if let Ok(interface_ip) = parts[3].parse::<Ipv4Addr>() {
                    if let Some(idx) = Self::get_interface_index_from_ip(&interface_ip.to_string())
                    {
                        info!(
                            "Found default gateway: {} via interface {} (idx={})",
                            gateway, interface_ip, idx
                        );
                        return Some((gateway, idx));
                    }
                }

                // Fallback: return gateway with 0 index (route will be added without IF)
                info!(
                    "Found default gateway: {} (interface index unknown)",
                    gateway
                );
                return Some((gateway, 0));
            }
        }

        warn!("Could not find default gateway in routing table");
        None
    }

    /// Verify that a route exists in the routing table.
    fn verify_route_exists(destination: &str) -> bool {
        let output = run_command_with_timeout("route", &["print", destination], COMMAND_TIMEOUT);

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // Check if the destination appears in the routing table
            for line in stdout.lines() {
                if line.contains(destination) && !line.contains("Active Routes:") {
                    debug!("Route verification found: {}", line.trim());
                    return true;
                }
            }
        }

        false
    }

    /// Get interface index from IP address.
    fn get_interface_index_from_ip(ip: &str) -> Option<u32> {
        let output = run_command_with_timeout(
            "netsh",
            &["interface", "ipv4", "show", "addresses"],
            COMMAND_TIMEOUT,
        )
        .ok()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut current_idx: Option<u32> = None;

        for line in stdout.lines() {
            let line = line.trim();
            if line.starts_with("Configuration for interface") {
                // Extract interface index from quotes
                if let Some(start) = line.find('"') {
                    if let Some(end) = line[start + 1..].find('"') {
                        let name = &line[start + 1..start + 1 + end];
                        current_idx = get_interface_index(name).ok();
                    }
                }
            } else if line.contains(ip) && current_idx.is_some() {
                return current_idx;
            }
        }

        None
    }

    /// Set up routes for full tunnel mode (IPv4 + IPv6 if enabled).
    pub fn setup_full_tunnel(&mut self) -> Result<(), WindowsClientError> {
        // Tear down the bootstrap IPv4 kill-switch installed by the
        // Tauri layer before the handshake. Routing is about to take
        // over the kill-switch role through the regular default-route
        // flip + DNS-egress block; if we left the bootstrap "Allow only
        // VPN server" rule in place, every other IPv4 destination
        // (including LAN) would stay blocked even after the tunnel is
        // up. Idempotent — no-op if no rule was installed.
        let _ = Self::remove_ipv4_bootstrap_rules();

        // Initialize recovery state BEFORE making any changes
        // This ensures we can restore network settings if the app crashes
        let mut recovery = RecoveryState::capture_pre_vpn_state(
            &self.vpn_interface,
            self.kill_switch,
            self.allow_lan,
        )
        .map_err(|e| {
            WindowsClientError::Routing(format!("Failed to capture recovery state: {}", e))
        })?;

        // Get original default gateway (MUST be pre-captured before adapter creation)
        // CRITICAL: The gateway MUST be captured BEFORE the VPN adapter is created
        // because Windows may add a default route via the VPN gateway, causing a
        // routing loop. If the gateway was not pre-captured, we MUST fail here.
        if self.original_gateway.is_none() {
            return Err(WindowsClientError::Routing(
                "CRITICAL: Original gateway not set. The default gateway MUST be captured \
                 BEFORE creating the VPN adapter. Call set_original_gateway() with the \
                 gateway obtained before adapter creation to prevent routing loops."
                    .into(),
            ));
        }

        // Safe to use expect() here because we verified original_gateway.is_some() above
        if let Some(ref gw) = self.original_gateway {
            info!(
                "Using pre-captured original gateway: {} (IF={})",
                gw,
                self.original_interface_idx.unwrap_or(0)
            );
        }

        // Copy to recovery state
        if let Some(ref gw) = self.original_gateway {
            recovery.original_gateway = Some(gw.clone());
        }
        if let Some(idx) = self.original_interface_idx {
            recovery.original_interface_idx = Some(idx);
        }

        // Save recovery state immediately after capturing original state
        if let Err(e) = recovery.save() {
            warn!("Failed to save recovery state: {}", e);
        }
        self.recovery_state = Some(recovery);

        // Add route for server endpoint via original gateway (exclude from VPN)
        // This MUST use the original interface, not the VPN interface, to prevent routing loop
        // THIS IS CRITICAL - if this fails, all traffic including VPN packets will loop!
        if let Some(gw) = self.original_gateway.clone() {
            let endpoint = self.server_endpoint.clone();
            info!(
                "Adding exclusion route for VPN server {} via gateway {}",
                endpoint, gw
            );
            match self.add_exclusion_route(&endpoint, "255.255.255.255", &gw) {
                Ok(_) => {
                    // Verify the route was actually added
                    if Self::verify_route_exists(&endpoint) {
                        info!("Server endpoint exclusion route verified");
                    } else {
                        warn!(
                            "Server endpoint route added but verification failed - traffic may loop!"
                        );
                    }
                }
                Err(e) => {
                    error!(
                        "CRITICAL: Failed to add server endpoint exclusion route: {}",
                        e
                    );
                    error!("This will cause all VPN traffic to loop! Aborting.");
                    return Err(e);
                }
            }
        } else {
            // No gateway found - we can't add exclusion route
            // This is dangerous but might work if the server is on the local network
            warn!("No default gateway found - server endpoint exclusion route not added!");
            warn!("VPN packets may loop if server is not on local network!");
        }

        // If kill switch is enabled, delete the original default route
        if self.kill_switch {
            if let Some(ref gw) = self.original_gateway.clone() {
                info!("Kill switch enabled: removing original default route");
                if Self::delete_route("0.0.0.0", "0.0.0.0").is_ok() {
                    self.deleted_routes.push((
                        "0.0.0.0".to_string(),
                        "0.0.0.0".to_string(),
                        gw.clone(),
                    ));
                    // Mirror into the recovery state so a crash before
                    // reconnection can restore the default route.
                    self.persist_recovered_deleted_route_v4(
                        "0.0.0.0",
                        "0.0.0.0",
                        gw,
                        self.original_interface_idx.unwrap_or(0),
                    );
                }

                // If allow LAN is enabled, add routes for LAN subnets
                if self.allow_lan {
                    info!("Allow LAN enabled: adding LAN routes via original gateway");
                    for (dest, mask) in LAN_SUBNETS {
                        // CRITICAL: Skip 10.0.0.0/8 if VPN gateway is in that range (e.g., 10.99.0.1)
                        // to prevent routing loop where VPN traffic goes via physical interface
                        if *dest == "10.0.0.0" && self.vpn_gateway.starts_with("10.") {
                            info!(
                                "Skipping LAN route 10.0.0.0/8 (conflicts with VPN gateway {})",
                                self.vpn_gateway
                            );
                            continue;
                        }

                        // Use add_exclusion_route to route LAN traffic via physical interface
                        if let Err(e) = self.add_exclusion_route(dest, mask, gw) {
                            warn!("Failed to add LAN route {}/{}: {}", dest, mask, e);
                        }
                    }
                }
            }
        }

        // Install IPv6 leak protection FIRST — before flipping the IPv4
        // default route to the tunnel. If we add IPv4 routes first, there is a
        // window where IPv4 goes through the tunnel but IPv6 still flows
        // natively outside the tunnel. Order matters here.
        if !self.has_ipv6() {
            if let Err(e) = self.enable_ipv6_leak_protection() {
                // Non-fatal: log and continue. The tunnel is still usable for
                // IPv4 traffic; only dual-stack hosts with working IPv6 could
                // leak. Most residential NATs do not expose IPv6 anyway.
                warn!(
                    "Could not enable IPv6 leak protection: {}. IPv6 traffic may bypass the tunnel.",
                    e
                );
            }
        }

        // Add default route via VPN gateway
        // Split into two /1 routes to override the existing 0.0.0.0/0 route
        self.add_route("0.0.0.0", "128.0.0.0", &self.vpn_gateway.clone())?;
        self.add_route("128.0.0.0", "128.0.0.0", &self.vpn_gateway.clone())?;

        // IPv6 routing if enabled.
        if self.has_ipv6() {
            self.setup_full_tunnel_v6()?;
        }

        // DNS egress blocking (DoH / DoT / mDNS). Mirrors the macOS PF
        // anchor: browser-side DoH bypasses the OS resolver, DoT on
        // port 853 is a known dns-leak channel, and mDNS leaks the
        // local hostname to the LAN. Best-effort — log and continue
        // on failure so we never abort connect because of an
        // ancillary firewall rule.
        if let Err(e) = self.enable_dns_egress_blocking() {
            warn!(
                "DNS egress blocking failed: {}. Browser DoH may bypass the VPN's DNS.",
                e
            );
        }

        info!(
            "Full tunnel routing configured (kill_switch={}, allow_lan={}, ipv6={}, ipv6_blocked={}, dns_egress_blocked={})",
            self.kill_switch,
            self.allow_lan,
            self.ipv6_enabled,
            self.ipv6_blocked,
            self.dns_egress_blocked
        );
        Ok(())
    }

    /// Set up IPv6 routes for full tunnel mode.
    ///
    /// Failure modes handled:
    ///
    /// * `netsh interface ipv6 add route` fails — common causes are
    ///   the process not running elevated (WFP / IPv6 route adds need
    ///   admin), IPv6 disabled at the OS level, the Wintun adapter
    ///   not fully "up" yet, or a bogus `vpn_gateway_v6` in the
    ///   profile. Previously this bubbled up as `WindowsClientError
    ///   ::Routing("netsh ipv6 route add failed: …")` which aborted
    ///   the entire `connect` with a scary "Traffic may leak" message.
    ///   That aborted connect was actively worse than the problem it
    ///   reported: the user ended up with NO tunnel at all (not IPv4,
    ///   not IPv6, just an error).
    ///
    /// Fallback strategy:
    ///
    ///  1. Try to install the two /1 IPv6 default routes through the
    ///     VPN gateway. Log each failure at `warn!` with the netsh
    ///     stderr so operators can diagnose.
    ///  2. If any of the two default routes did not go in, consider
    ///     IPv6 tunnelling broken for this session and fall back to
    ///     blocking all IPv6 egress at the Windows firewall
    ///     (`enable_ipv6_leak_protection`). That is strictly safer
    ///     than both the old hard-fail behaviour AND than shipping a
    ///     partial IPv6 route table: no leak, no aborted connect.
    ///  3. Return `Ok(())` so IPv4 tunnelling proceeds regardless.
    ///     The user gets a warning in the logs; the connection stays
    ///     up.
    fn setup_full_tunnel_v6(&mut self) -> Result<(), WindowsClientError> {
        let gateway_v6 = match &self.vpn_gateway_v6 {
            Some(gw) => gw.clone(),
            None => return Ok(()),
        };

        info!("Setting up IPv6 full tunnel routing via {}", gateway_v6);

        // Add default IPv6 routes via VPN gateway.
        // Split into two /1 routes to override the existing ::/0 route.
        let mut ipv6_routing_ok = true;
        if let Err(e) = self.add_route_v6("::", 1, &gateway_v6) {
            warn!(
                "Failed to add IPv6 default route (::) via {}: {}. \
                 Falling back to IPv6 firewall block — IPv6 traffic \
                 will not be tunnelled but will not leak either. \
                 Check that the client is running as Administrator and \
                 that IPv6 is enabled on the host.",
                gateway_v6, e
            );
            ipv6_routing_ok = false;
        }
        if let Err(e) = self.add_route_v6("8000::", 1, &gateway_v6) {
            warn!(
                "Failed to add IPv6 default route (8000::) via {}: {}. \
                 Falling back to IPv6 firewall block.",
                gateway_v6, e
            );
            ipv6_routing_ok = false;
        }

        if !ipv6_routing_ok {
            // Best-effort fallback: block all IPv6 egress at the firewall
            // so the kernel's native IPv6 stack doesn't carry user
            // traffic on the physical interface. `enable_ipv6_leak_protection`
            // is idempotent and already handles the persisted
            // `recovery.json` flag so a crash won't orphan the rule.
            if let Err(e) = self.enable_ipv6_leak_protection() {
                warn!(
                    "IPv6 routing failed AND fallback firewall block failed: {}. \
                     IPv6 traffic may leak on the physical interface. \
                     Disable IPv6 manually (Settings → Network → Adapter \
                     properties → uncheck TCP/IPv6) or run the client as \
                     Administrator.",
                    e
                );
            } else {
                info!("IPv6 egress blocked at firewall as fallback for failed IPv6 routing");
            }
            // Skip the LAN routes — they only make sense if the main
            // IPv6 default route is functional.
            return Ok(());
        }

        // Handle kill switch for IPv6
        if self.kill_switch && self.allow_lan {
            // Add IPv6 LAN routes via local interface
            for (dest, prefix) in LAN_SUBNETS_V6 {
                // For LAN, use on-link (interface route)
                if let Err(e) = self.add_route_v6_onlink(dest, *prefix) {
                    warn!("Failed to add IPv6 LAN route {}/{}: {}", dest, prefix, e);
                }
            }
        }

        Ok(())
    }

    /// Set up routes for split tunnel mode.
    pub fn setup_split_tunnel(&mut self, subnets: &[&str]) -> Result<(), WindowsClientError> {
        info!(
            "Setting up split tunnel routing for {} subnets",
            subnets.len()
        );

        // Add route for server endpoint via original gateway (exclude from VPN)
        // This MUST use the original interface to prevent routing loop
        if let Some((gw, idx)) = Self::get_default_gateway() {
            self.original_gateway = Some(gw.clone());
            self.original_interface_idx = Some(idx);
            self.add_exclusion_route(&self.server_endpoint.clone(), "255.255.255.255", &gw)?;
        }

        // Add routes for specified subnets via VPN
        for subnet in subnets {
            // Parse CIDR notation (e.g., "10.0.0.0/8")
            if let Some((dest, mask)) = Self::parse_cidr(subnet) {
                self.add_route(&dest, &mask, &self.vpn_gateway.clone())?;
            } else {
                warn!("Invalid CIDR notation: {}", subnet);
            }
        }

        info!(
            "Split tunnel routing configured for {} subnets",
            subnets.len()
        );
        Ok(())
    }

    /// Set up bypass tunnel routing (all traffic through VPN except specified routes).
    ///
    /// This is the "exclude" or "bypass" mode - all traffic goes through VPN except:
    /// - Traffic to specified bypass routes
    /// - Optionally local network traffic (bypass_local)
    /// - Optionally discovery/multicast traffic (bypass_discovery)
    ///
    /// # Arguments
    /// * `bypass_routes` - CIDR routes to exclude from VPN (go via physical interface)
    /// * `bypass_local` - If true, LAN traffic bypasses VPN
    /// * `bypass_discovery` - If true, multicast/discovery traffic bypasses VPN
    pub fn setup_bypass_tunnel(
        &mut self,
        bypass_routes: &[&str],
        bypass_local: bool,
        bypass_discovery: bool,
    ) -> Result<(), WindowsClientError> {
        info!(
            "Setting up bypass tunnel routing (bypass_local={}, bypass_discovery={}, {} custom routes)",
            bypass_local,
            bypass_discovery,
            bypass_routes.len()
        );

        // Tear down the bootstrap IPv4 kill-switch — see the same call
        // at the top of `setup_full_tunnel` for the rationale. The
        // bypass routing about to be installed defines its own
        // exclusion list, which would conflict with the bootstrap
        // "Allow only VPN server" rule.
        let _ = Self::remove_ipv4_bootstrap_rules();

        // Initialize recovery state BEFORE making any changes
        let mut recovery = RecoveryState::capture_pre_vpn_state(
            &self.vpn_interface,
            self.kill_switch,
            self.allow_lan,
        )
        .map_err(|e| {
            WindowsClientError::Routing(format!("Failed to capture recovery state: {}", e))
        })?;

        // Get original default gateway (MUST be pre-captured before adapter creation)
        if self.original_gateway.is_none() {
            return Err(WindowsClientError::Routing(
                "CRITICAL: Original gateway not set. The default gateway MUST be captured \
                 BEFORE creating the VPN adapter. Call set_original_gateway() with the \
                 gateway obtained before adapter creation to prevent routing loops."
                    .into(),
            ));
        }

        // Safety: is_none() check above guarantees this is Some
        let original_gw = self
            .original_gateway
            .clone()
            .expect("original_gateway verified as Some above");
        let original_idx = self.original_interface_idx;

        info!(
            "Using pre-captured original gateway: {} (IF={:?})",
            original_gw, original_idx
        );

        // Copy to recovery state
        recovery.original_gateway = Some(original_gw.clone());
        recovery.original_interface_idx = original_idx;

        // Save recovery state
        if let Err(e) = recovery.save() {
            warn!("Failed to save recovery state: {}", e);
        }
        self.recovery_state = Some(recovery);

        // Add route for server endpoint via original gateway (exclude from VPN)
        info!(
            "Adding exclusion route for VPN server {} via gateway {}",
            self.server_endpoint, original_gw
        );
        self.add_exclusion_route(
            &self.server_endpoint.clone(),
            "255.255.255.255",
            &original_gw,
        )?;

        // If kill switch is enabled, delete the original default route
        if self.kill_switch {
            info!("Kill switch enabled: removing original default route");
            if Self::delete_route("0.0.0.0", "0.0.0.0").is_ok() {
                self.deleted_routes.push((
                    "0.0.0.0".to_string(),
                    "0.0.0.0".to_string(),
                    original_gw.clone(),
                ));
                self.persist_recovered_deleted_route_v4(
                    "0.0.0.0",
                    "0.0.0.0",
                    &original_gw,
                    self.original_interface_idx.unwrap_or(0),
                );
            }
        }

        // Install IPv6 leak protection BEFORE installing the IPv4 VPN default
        // route. Same reasoning as in `setup_full_tunnel`: bypass mode routes
        // every non-bypassed destination through the tunnel, so a browser
        // resolving AAAA would otherwise reach an IPv6 destination natively
        // on the physical interface while IPv4 is being funnelled into the
        // tunnel. Without this block the kill-switch-enabled bypass mode
        // was actually leaking every IPv6 flow (W3 in the 2026-04-22 audit).
        // Skipped when the profile actually provides an IPv6 VPN gateway —
        // in that case IPv6 is tunnelled natively (via `setup_full_tunnel_v6`
        // below) and should not be blocked.
        if !self.has_ipv6() {
            if let Err(e) = self.enable_ipv6_leak_protection() {
                warn!(
                    "Could not enable IPv6 leak protection in bypass mode: {}. \
                     IPv6 traffic may bypass the tunnel.",
                    e
                );
            }
        }

        // Add default route via VPN gateway (two /1 routes)
        self.add_route("0.0.0.0", "128.0.0.0", &self.vpn_gateway.clone())?;
        self.add_route("128.0.0.0", "128.0.0.0", &self.vpn_gateway.clone())?;

        // IPv6 routing in bypass mode (LEAK-FIX May 2026):
        //
        // The original bypass implementation did NOT install the IPv6
        // default route when the server provided an IPv6 lease. The
        // /1 routes above only cover IPv4, so an AAAA-resolving
        // destination (Google, Cloudflare, every major CDN,
        // ifconfig.me with AAAA) flowed natively on the physical
        // interface — i.e. straight out through the ISP box, with the
        // box's public IP. This was the user-visible symptom that
        // triggered the audit.
        //
        // `setup_full_tunnel_v6` installs the two /1 IPv6 default
        // routes through the VPN gateway AND (when kill_switch +
        // allow_lan is on) the IPv6 LAN exclude routes
        // (fe80::/10, fc00::/7, fd00::/8). `self.allow_lan` is
        // initialised from `bypass_local` at `RouteManager::
        // with_kill_switch` time (see commands.rs:1338-1344), so the
        // LAN-bypass semantics line up with the IPv4 path below
        // without needing a separate parameter.
        //
        // If route installation fails, the function falls back to
        // blocking IPv6 egress at the Windows firewall (`enable_
        // ipv6_leak_protection`), strictly safer than leaking.
        if self.has_ipv6() {
            self.setup_full_tunnel_v6()?;
        }

        // Add bypass routes via original gateway (these EXCLUDE from VPN)
        for route in bypass_routes {
            let route = route.trim();
            if route.is_empty() {
                continue;
            }
            // LEAK-FIX May 2026: reject `0.0.0.0/0` (and any /0). The
            // UI validator catches this on the React side, but a
            // corrupted profile JSON or a manual config edit could
            // still smuggle a /0 here. Without this guard,
            // `add_exclusion_route("0.0.0.0", "0.0.0.0", original_gw)`
            // would install the default route via the physical
            // interface — i.e. EVERY destination bypasses the VPN
            // and the user sees their ISP/box public IP. Fail closed
            // with a warn so the operator notices.
            if let Some(stripped) = route.split('/').nth(1) {
                if stripped.trim() == "0" {
                    warn!(
                        "Refusing /0 bypass route '{}': would route all traffic via the \
                         physical interface and defeat the tunnel",
                        route
                    );
                    continue;
                }
            }
            if let Some((dest, mask)) = Self::parse_cidr(route) {
                info!("Adding bypass route: {}/{} via {}", dest, mask, original_gw);
                if let Err(e) = self.add_exclusion_route(&dest, &mask, &original_gw) {
                    warn!("Failed to add bypass route {}: {}", route, e);
                }
            } else {
                warn!("Invalid CIDR notation for bypass route: {}", route);
            }
        }

        // Bypass local network traffic if enabled
        if bypass_local {
            info!("Adding LAN bypass routes");
            for (dest, mask) in LAN_SUBNETS {
                // Skip if the VPN gateway is in this subnet to avoid routing loop
                if *dest == "10.0.0.0" && self.vpn_gateway.starts_with("10.") {
                    info!(
                        "Skipping LAN route 10.0.0.0/8 (conflicts with VPN gateway {})",
                        self.vpn_gateway
                    );
                    continue;
                }
                if let Err(e) = self.add_exclusion_route(dest, mask, &original_gw) {
                    warn!("Failed to add LAN bypass route {}/{}: {}", dest, mask, e);
                }
            }
        }

        // Bypass discovery/multicast traffic if enabled
        if bypass_discovery {
            info!("Adding discovery bypass routes (mDNS, SSDP, etc.)");
            for (dest, mask) in DISCOVERY_SUBNETS {
                if let Err(e) = self.add_exclusion_route(dest, mask, &original_gw) {
                    warn!(
                        "Failed to add discovery bypass route {}/{}: {}",
                        dest, mask, e
                    );
                }
            }
        }

        // DNS egress blocking — same rationale as in `setup_full_tunnel`.
        // Best-effort: log and continue on failure.
        if let Err(e) = self.enable_dns_egress_blocking() {
            warn!(
                "DNS egress blocking failed: {}. Browser DoH may bypass the VPN's DNS.",
                e
            );
        }

        info!(
            "Bypass tunnel routing configured (kill_switch={}, bypass_local={}, bypass_discovery={}, dns_egress_blocked={})",
            self.kill_switch, bypass_local, bypass_discovery, self.dns_egress_blocked
        );
        Ok(())
    }

    /// Parse CIDR notation to destination and netmask.
    fn parse_cidr(cidr: &str) -> Option<(String, String)> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return None;
        }

        let dest = parts[0].to_string();
        let prefix: u8 = parts[1].parse().ok()?;

        if prefix > 32 {
            return None;
        }

        // Convert prefix to netmask
        let mask_bits: u32 = if prefix == 0 {
            0
        } else {
            !0u32 << (32 - prefix)
        };
        let mask = Ipv4Addr::from(mask_bits);

        Some((dest, mask.to_string()))
    }

    /// Convert a classical IPv4 netmask string (e.g. "255.255.255.0") into a
    /// CIDR prefix length (24 in the example). Returns `None` on malformed
    /// input or non-contiguous masks.
    fn netmask_to_prefix_len(mask: &str) -> Option<u8> {
        let addr: Ipv4Addr = mask.parse().ok()?;
        let bits = u32::from(addr);
        if bits == 0 {
            return Some(0);
        }
        let leading = bits.leading_ones();
        // A valid netmask has contiguous 1s at the top and 0s below.
        let trailing_zeros = bits.trailing_zeros();
        if leading + trailing_zeros == 32 {
            Some(leading as u8)
        } else {
            None
        }
    }

    /// Persist a v4 route addition into the on-disk recovery state.
    ///
    /// Called from every `add_route_*` path so a crash mid-setup can undo
    /// the routes we actually installed. Soft-fail: a serialisation or
    /// disk-write error is logged at `warn!` but does not propagate — the
    /// route is installed and `self.added_routes` still reflects it for
    /// the normal in-process cleanup.
    fn persist_recovered_added_route_v4(
        &mut self,
        destination: &str,
        mask: &str,
        gateway: &str,
        interface_index: u32,
    ) {
        let Some(recovery) = self.recovery_state.as_mut() else {
            return;
        };
        let Ok(dest) = destination.parse::<Ipv4Addr>() else {
            warn!(
                "Recovery: could not parse v4 destination {} — route NOT recorded",
                destination
            );
            return;
        };
        let Ok(gw) = gateway.parse::<Ipv4Addr>() else {
            warn!(
                "Recovery: could not parse v4 gateway {} — route NOT recorded",
                gateway
            );
            return;
        };
        let Some(prefix_len) = Self::netmask_to_prefix_len(mask) else {
            warn!(
                "Recovery: could not convert netmask {} to prefix — route NOT recorded",
                mask
            );
            return;
        };
        let entry = RouteEntry::new_v4(dest, prefix_len, gw, interface_index);
        recovery.record_added_route(&entry);
        if let Err(e) = recovery.save() {
            warn!("Recovery: failed to persist added v4 route: {}", e);
        }
    }

    /// Persist a v4 route deletion into the on-disk recovery state.
    ///
    /// Called after deleting the original default route when the kill
    /// switch engages. Soft-fail, same rationale as the "added" helpers.
    fn persist_recovered_deleted_route_v4(
        &mut self,
        destination: &str,
        mask: &str,
        gateway: &str,
        interface_index: u32,
    ) {
        let Some(recovery) = self.recovery_state.as_mut() else {
            return;
        };
        let Ok(dest) = destination.parse::<Ipv4Addr>() else {
            warn!(
                "Recovery: could not parse v4 destination {} — deletion NOT recorded",
                destination
            );
            return;
        };
        let Ok(gw) = gateway.parse::<Ipv4Addr>() else {
            warn!(
                "Recovery: could not parse v4 gateway {} — deletion NOT recorded",
                gateway
            );
            return;
        };
        let Some(prefix_len) = Self::netmask_to_prefix_len(mask) else {
            warn!(
                "Recovery: could not convert netmask {} to prefix — deletion NOT recorded",
                mask
            );
            return;
        };
        let entry = RouteEntry::new_v4(dest, prefix_len, gw, interface_index);
        recovery.record_deleted_route(&entry);
        if let Err(e) = recovery.save() {
            warn!("Recovery: failed to persist deleted v4 route: {}", e);
        }
    }

    /// Persist a v6 route addition into the on-disk recovery state.
    ///
    /// See [`Self::persist_recovered_added_route_v4`] for the same
    /// soft-fail rationale. The `interface_index` used by recovery is
    /// `0` when not known: recovery will look up the interface by name
    /// from the persisted `vpn_interface` if necessary.
    fn persist_recovered_added_route_v6(
        &mut self,
        destination: &str,
        prefix_len: u8,
        gateway: &str,
    ) {
        let Some(recovery) = self.recovery_state.as_mut() else {
            return;
        };
        let Ok(dest) = destination.parse::<Ipv6Addr>() else {
            warn!(
                "Recovery: could not parse v6 destination {} — route NOT recorded",
                destination
            );
            return;
        };
        let Ok(gw) = gateway.parse::<Ipv6Addr>() else {
            warn!(
                "Recovery: could not parse v6 gateway {} — route NOT recorded",
                gateway
            );
            return;
        };
        let entry = RouteEntry::new_v6(dest, prefix_len, gw, 0);
        recovery.record_added_route(&entry);
        if let Err(e) = recovery.save() {
            warn!("Recovery: failed to persist added v6 route: {}", e);
        }
    }

    /// Add a route with optional interface specification.
    ///
    /// If `use_vpn_interface` is true, the route will be forced through the VPN interface.
    /// If false, the route goes through the gateway's natural interface (for exclusion routes).
    fn add_route_with_interface(
        &mut self,
        destination: &str,
        mask: &str,
        gateway: &str,
        use_vpn_interface: bool,
    ) -> Result<(), WindowsClientError> {
        let if_index = if use_vpn_interface {
            // Use VPN interface for VPN routes
            get_interface_index(&self.vpn_interface).ok()
        } else {
            // For exclusion routes, use the original interface if available
            // Filter out 0 as it's an invalid interface index (fallback from parsing failure)
            self.original_interface_idx.filter(|&idx| idx > 0)
        };

        let output = if let Some(idx) = if_index {
            let if_str = format!("{}", idx);
            info!(
                "Adding route: {} mask {} via {} IF {} (vpn_if={})",
                destination, mask, gateway, idx, use_vpn_interface
            );
            run_command_with_timeout(
                "route",
                &[
                    "add",
                    destination,
                    "mask",
                    mask,
                    gateway,
                    "metric",
                    "1",
                    "IF",
                    &if_str,
                ],
                COMMAND_TIMEOUT,
            )
        } else {
            // No interface specified - let Windows decide based on gateway
            // This is CRITICAL for exclusion routes - the gateway IP must be reachable
            // via the physical interface, not the VPN interface
            info!(
                "Adding route: {} mask {} via {} (no IF, gateway-based routing)",
                destination, mask, gateway
            );
            run_command_with_timeout(
                "route",
                &["add", destination, "mask", mask, gateway, "metric", "1"],
                COMMAND_TIMEOUT,
            )
        }
        .map_err(|e| WindowsClientError::Routing(format!("failed to run route: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(WindowsClientError::Routing(format!(
                "route add failed: {}",
                stderr
            )));
        }

        debug!(
            "Added route: {} mask {} via {} (IF {:?}, vpn_if={})",
            destination, mask, gateway, if_index, use_vpn_interface
        );
        self.added_routes
            .push(format!("{} mask {}", destination, mask));

        // Mirror the addition into the on-disk recovery state so a crash
        // mid-connection can undo every route we added (see
        // `RecoveryState::perform_recovery_with_state`). Soft-fail: a
        // recovery-state persistence failure must not abort route
        // installation — the route is already in `self.added_routes` and
        // will still be cleaned up by the normal Drop path in-process.
        self.persist_recovered_added_route_v4(destination, mask, gateway, if_index.unwrap_or(0));

        Ok(())
    }

    /// Add a route via the VPN interface.
    fn add_route(
        &mut self,
        destination: &str,
        mask: &str,
        gateway: &str,
    ) -> Result<(), WindowsClientError> {
        self.add_route_with_interface(destination, mask, gateway, true)
    }

    /// Add an exclusion route via the original (physical) interface.
    /// Used for server endpoint to prevent routing loop.
    fn add_exclusion_route(
        &mut self,
        destination: &str,
        mask: &str,
        gateway: &str,
    ) -> Result<(), WindowsClientError> {
        self.add_route_with_interface(destination, mask, gateway, false)
    }

    /// Delete a route.
    fn delete_route(destination: &str, mask: &str) -> io::Result<()> {
        let output = run_command_with_timeout(
            "route",
            &["delete", destination, "mask", mask],
            COMMAND_TIMEOUT,
        )?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(
                "Failed to delete route {} mask {}: {}",
                destination, mask, stderr
            );
        } else {
            debug!("Deleted route: {} mask {}", destination, mask);
        }

        Ok(())
    }

    /// Add an IPv6 route via gateway.
    fn add_route_v6(
        &mut self,
        destination: &str,
        prefix_len: u8,
        gateway: &str,
    ) -> Result<(), WindowsClientError> {
        // Use netsh for IPv6 routes
        let prefix = format!("{}/{}", destination, prefix_len);

        let output = run_command_with_timeout(
            "netsh",
            &[
                "interface",
                "ipv6",
                "add",
                "route",
                &prefix,
                &self.vpn_interface,
                gateway,
            ],
            COMMAND_TIMEOUT,
        )
        .map_err(|e| WindowsClientError::Routing(format!("failed to run netsh: {}", e)))?;

        if !output.status.success() {
            return Err(WindowsClientError::Routing(format_netsh_error(
                "netsh ipv6 route add failed",
                &output.stdout,
                &output.stderr,
            )));
        }

        debug!("Added IPv6 route: {} via {}", prefix, gateway);
        self.added_routes_v6.push(prefix.clone());
        self.persist_recovered_added_route_v6(destination, prefix_len, gateway);

        Ok(())
    }

    /// Add an IPv6 route as on-link (for LAN traffic).
    fn add_route_v6_onlink(
        &mut self,
        destination: &str,
        prefix_len: u8,
    ) -> Result<(), WindowsClientError> {
        let prefix = format!("{}/{}", destination, prefix_len);

        // On-link route - route via interface without specific gateway
        let output = run_command_with_timeout(
            "netsh",
            &[
                "interface",
                "ipv6",
                "add",
                "route",
                &prefix,
                &self.vpn_interface,
            ],
            COMMAND_TIMEOUT,
        )
        .map_err(|e| WindowsClientError::Routing(format!("failed to run netsh: {}", e)))?;

        if !output.status.success() {
            // First netsh form refused — try the explicit `nexthop=::`
            // form. Capture the result so we can surface a real error
            // (and avoid recording a phantom route in RecoveryState) if
            // BOTH attempts fail.
            let fallback = run_command_with_timeout(
                "netsh",
                &[
                    "interface",
                    "ipv6",
                    "add",
                    "route",
                    &prefix,
                    &self.vpn_interface,
                    "nexthop=::",
                ],
                COMMAND_TIMEOUT,
            );

            match fallback {
                Ok(fb_output) if fb_output.status.success() => {
                    // Fallback succeeded; fall through to the persist +
                    // bookkeeping below.
                }
                Ok(fb_output) => {
                    return Err(WindowsClientError::Routing(format_netsh_error(
                        "netsh ipv6 on-link route add failed (both forms)",
                        &fb_output.stdout,
                        &fb_output.stderr,
                    )));
                }
                Err(e) => {
                    return Err(WindowsClientError::Routing(format!(
                        "failed to run netsh fallback: {}",
                        e
                    )));
                }
            }
        }

        debug!("Added IPv6 on-link route: {}", prefix);
        self.added_routes_v6.push(prefix.clone());
        // Use "::" as a placeholder gateway for on-link routes — no next-hop
        // is involved, but RecoveryState needs a value and `::` is the
        // canonical IPv6 unspecified address.
        self.persist_recovered_added_route_v6(destination, prefix_len, "::");

        Ok(())
    }

    /// Delete an IPv6 route.
    fn delete_route_v6(interface: &str, destination: &str, prefix_len: u8) -> io::Result<()> {
        let prefix = format!("{}/{}", destination, prefix_len);

        let output = run_command_with_timeout(
            "netsh",
            &["interface", "ipv6", "delete", "route", &prefix, interface],
            COMMAND_TIMEOUT,
        )?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("Failed to delete IPv6 route {}: {}", prefix, stderr);
        } else {
            debug!("Deleted IPv6 route: {}", prefix);
        }

        Ok(())
    }

    /// Parse IPv6 CIDR notation.
    fn parse_cidr_v6(cidr: &str) -> Option<(String, u8)> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return None;
        }

        let dest = parts[0].to_string();
        let prefix: u8 = parts[1].parse().ok()?;

        // Validate it's a valid IPv6 address
        if dest.parse::<Ipv6Addr>().is_err() {
            return None;
        }

        if prefix > 128 {
            return None;
        }

        Some((dest, prefix))
    }

    /// Block all outbound IPv6 traffic at the Windows Firewall.
    ///
    /// Used when the tunnel is IPv4-only to prevent IPv6 leaks. On a dual-stack
    /// host, applications resolving AAAA records would otherwise reach IPv6
    /// destinations natively, bypassing the VPN entirely.
    ///
    /// Creates a single persistent WFP rule tagged `HPN_VPN_IPv6_Block`. The
    /// rule blocks IPv6 egress on ALL profiles (domain/private/public). It is
    /// removed by [`cleanup`] or [`disable_ipv6_leak_protection`]. On process
    /// crash, the rule remains until the next session either removes it (clean
    /// disconnect) or overwrites it (same rule name is idempotent).
    ///
    /// Returns `Ok(())` if the rule was created or already present. Returns
    /// `Err` if `netsh` is unavailable or reports a hard failure.
    pub fn enable_ipv6_leak_protection(&mut self) -> Result<(), WindowsClientError> {
        if self.ipv6_blocked {
            debug!("IPv6 leak protection already enabled");
            return Ok(());
        }

        // Remove any stale rule from a previous session first (idempotent).
        // Required because `New-NetFirewallRule` refuses to install a
        // second rule with the same DisplayName.
        let _ = Self::remove_ipv6_block_rule();

        info!("Enabling IPv6 leak protection (blocking all IPv6 egress at firewall)");

        // Windows Defender Firewall does not expose an "IP family"
        // selector: its `-Protocol` parameter is either a numeric IANA
        // protocol ID or one of TCP/UDP/ICMPv4/ICMPv6. Passing "IPv6"
        // — what every intuitive reading of the docs suggests — is
        // rejected with `HRESULT 0x80070057 (E_INVALIDARG)`.
        //
        // Writing `-RemoteAddress ::/0` gets rejected too ("one or
        // more address prefixes are invalid"): the Windows parser
        // appears to refuse the unspecified-address literal `::` even
        // though the Microsoft docs imply it should work.
        //
        // So we enumerate every IPv6 super-prefix that carries real
        // traffic:
        //   - 2000::/3  — global unicast (the entire routable Internet
        //                 IPv6 space; RFC 3513)
        //   - fc00::/7  — Unique Local Addresses / ULA (RFC 4193)
        //   - fe80::/10 — link-local (RFC 4291)
        //   - ff00::/8  — multicast (RFC 4291)
        //
        // Together these cover every IPv6 address a host could
        // reasonably want to reach; the remaining prefixes are
        // reserved / unassigned / loopback and never appear on the
        // wire. This is the same set of ranges `pf`, `ipfw`, and
        // `ip6tables` use internally when asked to "block all IPv6".
        const IPV6_BLOCK_PREFIXES: &str = "2000::/3,fc00::/7,fe80::/10,ff00::/8";

        let output = run_powershell_firewall(&format!(
            "New-NetFirewallRule \
                 -DisplayName '{name}' \
                 -Direction Outbound \
                 -Action Block \
                 -RemoteAddress {prefixes} \
                 -Profile Any \
                 -Description 'HPN VPN IPv6 leak prevention (IPv4-only tunnel)' \
                 | Out-Null",
            name = HPN_IPV6_BLOCK_RULE_NAME,
            prefixes = IPV6_BLOCK_PREFIXES,
        ))
        .map_err(|e| WindowsClientError::Routing(format!("powershell spawn failed: {}", e)))?;

        if !output.status.success() {
            return Err(WindowsClientError::Routing(format_netsh_error(
                "New-NetFirewallRule failed",
                &output.stdout,
                &output.stderr,
            )));
        }

        self.ipv6_blocked = true;

        // Persist the flag in the recovery file so a crash-recovery pass
        // at next start-up knows to remove the rule. Without this, a
        // process killed before cleanup leaves the rule active across
        // reboots; the user then cannot reach any IPv6 destination from
        // the physical interface until they delete the rule by hand.
        // Errors here are non-fatal — the rule is already installed and
        // the user's session is safe; only crash recovery degrades to
        // "best effort" if the recovery file is unavailable.
        if let Some(mut state) = RecoveryState::load() {
            state.ipv6_blocked = true;
            if let Err(e) = state.save() {
                warn!(
                    "Failed to persist ipv6_blocked flag to recovery file: {}",
                    e
                );
            }
        }

        Ok(())
    }

    /// Remove the IPv6 leak protection firewall rule.
    ///
    /// Safe to call even if the rule was never created (idempotent). Errors
    /// from `netsh` are logged but do not fail the call — the rule may have
    /// already been removed by the user or a previous cleanup.
    pub fn disable_ipv6_leak_protection(&mut self) {
        if !self.ipv6_blocked {
            return;
        }
        info!("Disabling IPv6 leak protection");
        if let Err(e) = Self::remove_ipv6_block_rule() {
            warn!(
                "Failed to remove IPv6 block rule (will retry on cleanup): {}",
                e
            );
        }
        self.ipv6_blocked = false;
    }

    /// Remove the HPN IPv6 block firewall rule via `netsh`.
    ///
    /// Idempotent: safe to call even when the rule does not exist. netsh
    /// returns non-zero with "No rules match the specified criteria" in
    /// that case, which is treated as success.
    ///
    /// Exposed on the public API so the recovery path (process crash,
    /// sudden reboot while VPN was up) can drop a stale rule at startup
    /// before the user tries to reconnect — otherwise the next session
    /// inherits a still-active IPv6 block and the user cannot browse IPv6
    /// sites from the physical interface while HPN is disconnected.
    pub fn remove_stale_ipv6_block_rule() -> Result<(), String> {
        Self::remove_ipv6_block_rule()
    }

    /// Internal helper — the actual PowerShell call.
    ///
    /// `Remove-NetFirewallRule` is idempotent with
    /// `-ErrorAction SilentlyContinue`: it returns success whether or
    /// not the rule existed, so this wrapper always returns `Ok(())`
    /// unless PowerShell itself failed to spawn.
    fn remove_ipv6_block_rule() -> Result<(), String> {
        let output = run_powershell_firewall(&format!(
            "Remove-NetFirewallRule -DisplayName '{name}' -ErrorAction SilentlyContinue | Out-Null",
            name = HPN_IPV6_BLOCK_RULE_NAME
        ))
        .map_err(|e| format!("powershell spawn: {}", e))?;

        // PowerShell only exits non-zero here on catastrophic failures
        // (missing module, crashed host). Regular "rule not found" is
        // swallowed by `-ErrorAction SilentlyContinue`.
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            debug!(
                "Remove-NetFirewallRule returned non-zero (will retry): stdout={} stderr={}",
                stdout, stderr
            );
        }
        Ok(())
    }

    /// Install the HPN IPv6 block firewall rule without requiring a
    /// `RouteManager` instance.
    ///
    /// Used by the bootstrap path in the Tauri connect flow: the moment the
    /// user clicks "Connect" with `kill_switch=true`, we want to refuse
    /// IPv6 egress before the handshake packets leave the client. Without
    /// this, AAAA resolvers and already-established IPv6 flows keep running
    /// natively for the ~1-3 s it takes to create the Wintun adapter and
    /// install routes (the "setup-window" leak). The rule stays in place
    /// until `remove_stale_ipv6_block_rule()` is called on disconnect.
    ///
    /// Idempotent: if the rule is already installed (e.g., from a crashed
    /// prior session that the recovery path did not clean up in time),
    /// netsh overwrites the existing rule with the same name.
    pub fn install_bootstrap_ipv6_block() -> Result<(), String> {
        // Remove any stale rule first — `New-NetFirewallRule` refuses
        // duplicate DisplayName.
        let _ = Self::remove_ipv6_block_rule();

        // See the rationale comment on `enable_ipv6_leak_protection`:
        // Windows Firewall rejects both `-Protocol IPv6` and the
        // compact `-RemoteAddress ::/0` form, so we enumerate the four
        // super-prefixes that together cover every routable IPv6
        // address (global unicast, ULA, link-local, multicast).
        const IPV6_BLOCK_PREFIXES: &str = "2000::/3,fc00::/7,fe80::/10,ff00::/8";

        let output = run_powershell_firewall(&format!(
            "New-NetFirewallRule \
                 -DisplayName '{name}' \
                 -Direction Outbound \
                 -Action Block \
                 -RemoteAddress {prefixes} \
                 -Profile Any \
                 -Description 'HPN VPN bootstrap IPv6 block (setup-window leak prevention)' \
                 | Out-Null",
            name = HPN_IPV6_BLOCK_RULE_NAME,
            prefixes = IPV6_BLOCK_PREFIXES,
        ))
        .map_err(|e| format!("powershell spawn: {}", e))?;

        if !output.status.success() {
            return Err(format_netsh_error(
                "New-NetFirewallRule failed",
                &output.stdout,
                &output.stderr,
            ));
        }
        Ok(())
    }

    /// Install the bootstrap IPv4 block: deny every outbound IPv4 packet
    /// except those targeting the VPN server (and loopback).
    ///
    /// # Why
    ///
    /// `install_bootstrap_ipv6_block` already prevents IPv6 leaks during
    /// the 1-3 s window between "user clicked Connect" and "the VPN
    /// adapter is up with default routes installed". The same window
    /// exists for IPv4: TCP/HTTPS streams already opened by Slack /
    /// Discord / mail clients keep flowing on the physical interface
    /// and continue to expose the user's real IP via Server Name
    /// Indication, IP-in-URL, etc. until the route table flips.
    ///
    /// This pair of rules closes that window symmetrically. The exception
    /// for the VPN server is required because the handshake itself must
    /// reach the server; without it, the bootstrap kill-switch deadlocks
    /// the connect attempt.
    ///
    /// # Windows Firewall precedence quirk (`OverrideBlockRules`)
    ///
    /// Windows Firewall evaluates rules in the order:
    ///
    /// 1. Authenticated bypass (rules with `OverrideBlockRules = $true`)
    /// 2. Block rules
    /// 3. Allow rules
    /// 4. Default profile behaviour
    ///
    /// An ordinary `Allow VPN server` next to a `Block 0.0.0.0/0` is
    /// therefore *not* enough: the Block rule is evaluated first and
    /// drops the handshake packet. Field reports after the P1 release
    /// confirmed exactly this: "network drops, comes back, the VPN
    /// server never sees a single handshake packet". The fix is to
    /// install the Allow rules with `-OverrideBlockRules $true`,
    /// promoting them into the Authenticated-bypass class so they
    /// beat the Block rule.
    ///
    /// # Lifetime
    ///
    /// The rules are removed automatically once `setup_full_tunnel` /
    /// `setup_bypass_tunnel` succeed (the regular default-route + IPv6-
    /// block + DNS-egress-block rules then take over the kill-switch
    /// role). On connect failure the caller MUST invoke
    /// [`Self::remove_stale_ipv4_bootstrap_rules`] explicitly so the user
    /// is not left without IPv4. The Tauri wrapper does this through a
    /// scope guard, mirroring the IPv6 path.
    ///
    /// # Idempotency
    ///
    /// Stale rules from a previous session are removed first, so calling
    /// this twice in a row is safe.
    ///
    /// # Arguments
    ///
    /// * `server_ipv4` — IPv4 address (no port) of the HPN server. Pass
    ///   the literal IP, not the hostname; Windows Firewall does not
    ///   resolve names in `-RemoteAddress`. The Tauri caller already
    ///   resolved the hostname before reaching this point.
    pub fn install_bootstrap_ipv4_block(server_ipv4: &str) -> Result<(), String> {
        // Validate up-front so we never install ANY rule when the input
        // is bad (the previous version installed the loopback Allow
        // first and only validated the server IP afterwards, which left
        // an orphan firewall rule on validation failure). PowerShell
        // silently ignores hostnames in `-RemoteAddress`, which would
        // silently fall through to the Block rule below and deadlock
        // the handshake — so we refuse anything that doesn't parse as
        // a literal IPv4.
        if server_ipv4.parse::<Ipv4Addr>().is_err() {
            return Err(format!(
                "install_bootstrap_ipv4_block: server_ipv4 must be a literal IPv4 address, got {:?}",
                server_ipv4
            ));
        }

        // Remove any stale pair first — `New-NetFirewallRule` refuses
        // duplicate DisplayName.
        let _ = Self::remove_ipv4_bootstrap_rules();

        // ── 1. Allow outbound to loopback ─────────────────────────────
        // Without this we'd break every local app that relies on
        // 127.0.0.1 (databases, browsers' devtools, etc.) for the
        // duration of the bootstrap window. Loopback never leaks
        // off-host so allowing it has no privacy impact.
        //
        // `-OverrideBlockRules $true` promotes this Allow into the
        // Authenticated-bypass precedence class so it beats the
        // `Block 0.0.0.0/0` rule installed below — see the function
        // doc for the rationale.
        let output = run_powershell_firewall(&format!(
            "New-NetFirewallRule \
                 -DisplayName '{name}' \
                 -Direction Outbound \
                 -Action Allow \
                 -RemoteAddress 127.0.0.0/8 \
                 -OverrideBlockRules $true \
                 -Profile Any \
                 -Description 'HPN VPN bootstrap allow loopback' \
                 | Out-Null",
            name = HPN_IPV4_BOOTSTRAP_LOOPBACK_RULE_NAME,
        ))
        .map_err(|e| format!("powershell spawn: {}", e))?;
        if !output.status.success() {
            // Best-effort rollback so we never leave a half-installed
            // pair behind us.
            let _ = Self::remove_ipv4_bootstrap_rules();
            return Err(format_netsh_error(
                "New-NetFirewallRule (bootstrap loopback Allow) failed",
                &output.stdout,
                &output.stderr,
            ));
        }

        // ── 2. Allow outbound to the VPN server ───────────────────────
        // Same `-OverrideBlockRules $true` promotion as above so the
        // handshake packet is not trapped by the Block-all rule.

        let output = run_powershell_firewall(&format!(
            "New-NetFirewallRule \
                 -DisplayName '{name}' \
                 -Direction Outbound \
                 -Action Allow \
                 -RemoteAddress {server} \
                 -OverrideBlockRules $true \
                 -Profile Any \
                 -Description 'HPN VPN bootstrap allow VPN server' \
                 | Out-Null",
            name = HPN_IPV4_BOOTSTRAP_ALLOW_RULE_NAME,
            server = server_ipv4,
        ))
        .map_err(|e| format!("powershell spawn: {}", e))?;
        if !output.status.success() {
            let _ = Self::remove_ipv4_bootstrap_rules();
            return Err(format_netsh_error(
                "New-NetFirewallRule (bootstrap server Allow) failed",
                &output.stdout,
                &output.stderr,
            ));
        }

        // ── 3. Block all other outbound IPv4 ──────────────────────────
        // We split 0.0.0.0/0 into 0.0.0.0/1 + 128.0.0.0/1 because
        // PowerShell `New-NetFirewallRule` rejects the literal /0
        // ("one or more address prefixes are invalid" — same Windows
        // parser quirk we hit on IPv6, see `enable_ipv6_leak_protection`).
        // The two /1 prefixes together cover every IPv4 address.
        const IPV4_BLOCK_PREFIXES: &str = "0.0.0.0/1,128.0.0.0/1";

        let output = run_powershell_firewall(&format!(
            "New-NetFirewallRule \
                 -DisplayName '{name}' \
                 -Direction Outbound \
                 -Action Block \
                 -RemoteAddress {prefixes} \
                 -Profile Any \
                 -Description 'HPN VPN bootstrap IPv4 block (setup-window leak prevention)' \
                 | Out-Null",
            name = HPN_IPV4_BOOTSTRAP_BLOCK_RULE_NAME,
            prefixes = IPV4_BLOCK_PREFIXES,
        ))
        .map_err(|e| format!("powershell spawn: {}", e))?;
        if !output.status.success() {
            let _ = Self::remove_ipv4_bootstrap_rules();
            return Err(format_netsh_error(
                "New-NetFirewallRule (bootstrap IPv4 Block) failed",
                &output.stdout,
                &output.stderr,
            ));
        }

        Ok(())
    }

    /// Remove the bootstrap IPv4 block rule pair. Idempotent.
    ///
    /// MUST be called before the regular `setup_full_tunnel` /
    /// `setup_bypass_tunnel` rules take over (otherwise the bootstrap
    /// Allow-server-only rule would shadow the proper LAN/full-tunnel
    /// routing) AND on connect failure (otherwise IPv4 stays blocked
    /// for everything other than the VPN server until next reboot).
    pub fn remove_stale_ipv4_bootstrap_rules() -> Result<(), String> {
        Self::remove_ipv4_bootstrap_rules()
    }

    fn remove_ipv4_bootstrap_rules() -> Result<(), String> {
        let output = run_powershell_firewall(&format!(
            "Remove-NetFirewallRule -DisplayName '{loopback}'  -ErrorAction SilentlyContinue | Out-Null; \
             Remove-NetFirewallRule -DisplayName '{allow}'     -ErrorAction SilentlyContinue | Out-Null; \
             Remove-NetFirewallRule -DisplayName '{block}'     -ErrorAction SilentlyContinue | Out-Null",
            loopback = HPN_IPV4_BOOTSTRAP_LOOPBACK_RULE_NAME,
            allow = HPN_IPV4_BOOTSTRAP_ALLOW_RULE_NAME,
            block = HPN_IPV4_BOOTSTRAP_BLOCK_RULE_NAME,
        ))
        .map_err(|e| format!("powershell spawn: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            debug!(
                "Remove-NetFirewallRule (IPv4 bootstrap) returned non-zero: stdout={} stderr={}",
                stdout, stderr
            );
        }
        Ok(())
    }

    /// Block outbound DNS-over-HTTPS, DNS-over-TLS, and multicast DNS
    /// traffic at the firewall.
    ///
    /// # Why this matters
    ///
    /// `DnsLeakProtection` already pins the system resolver to the VPN's
    /// DNS servers, but modern browsers (Chrome, Firefox, Edge) ship
    /// with built-in DoH that bypasses the OS resolver entirely — they
    /// open a TCP/443 connection straight to `dns.google`,
    /// `cloudflare-dns.com`, etc. and resolve there. The result is an
    /// observable DNS leak even though the OS configuration looks
    /// correct.
    ///
    /// We mitigate that the same way the macOS PF anchor does (see
    /// `crates/hpn-client-macos/src/routing.rs`):
    ///
    /// * Block outbound TCP/443 to a static list of public DoH
    ///   resolvers ([`DOH_PROVIDERS_V4`] / [`DOH_PROVIDERS_V6`]).
    ///   Browsers fall back to the OS resolver, which the VPN owns.
    /// * Block outbound TCP+UDP/853 (DNS-over-TLS, RFC 7858) to any
    ///   destination. No legitimate non-DNS traffic uses this port.
    /// * Block multicast DNS / NetBIOS-NS on UDP/5353 to `224.0.0.251`
    ///   and `[ff02::fb]`. mDNS leaks the local hostname and stub
    ///   queries to the LAN even when DNS is otherwise locked down.
    ///
    /// The rules are tagged with [`HPN_DOH_BLOCK_RULE_NAME`],
    /// [`HPN_DOT_BLOCK_RULE_NAME`], and [`HPN_MDNS_BLOCK_RULE_NAME`]
    /// so cleanup can remove only the rules HPN owns. Idempotent:
    /// stale rules from a prior session are removed first.
    pub fn enable_dns_egress_blocking(&mut self) -> Result<(), WindowsClientError> {
        if self.dns_egress_blocked {
            debug!("DNS egress blocking already enabled");
            return Ok(());
        }

        let _ = Self::remove_dns_egress_rules();

        info!("Enabling DNS egress blocking (DoH + DoT + mDNS)");

        // ── DoH block — TCP/443 to known public DoH resolvers ─────────
        let mut doh_targets = Vec::with_capacity(DOH_PROVIDERS_V4.len() + DOH_PROVIDERS_V6.len());
        doh_targets.extend(DOH_PROVIDERS_V4.iter().copied());
        doh_targets.extend(DOH_PROVIDERS_V6.iter().copied());
        let remote_addresses = doh_targets.join(",");

        let output = run_powershell_firewall(&format!(
            "New-NetFirewallRule \
                 -DisplayName '{name}' \
                 -Direction Outbound \
                 -Action Block \
                 -Protocol TCP \
                 -RemotePort 443 \
                 -RemoteAddress {remote_addresses} \
                 -Profile Any \
                 -Description 'HPN VPN DoH leak prevention (browser built-in resolvers)' \
                 | Out-Null",
            name = HPN_DOH_BLOCK_RULE_NAME,
            remote_addresses = remote_addresses,
        ))
        .map_err(|e| WindowsClientError::Routing(format!("powershell spawn failed: {}", e)))?;

        if !output.status.success() {
            // Try to roll back so we never leave a half-installed rule
            // set behind us.
            let _ = Self::remove_dns_egress_rules();
            return Err(WindowsClientError::Routing(format_netsh_error(
                "New-NetFirewallRule (DoH) failed",
                &output.stdout,
                &output.stderr,
            )));
        }

        // ── DoT block — TCP+UDP/853 to any destination ────────────────
        let output = run_powershell_firewall(&format!(
            "New-NetFirewallRule \
                 -DisplayName '{name}' \
                 -Direction Outbound \
                 -Action Block \
                 -Protocol TCP \
                 -RemotePort {port} \
                 -Profile Any \
                 -Description 'HPN VPN DoT leak prevention' \
                 | Out-Null; \
             New-NetFirewallRule \
                 -DisplayName '{name}_UDP' \
                 -Direction Outbound \
                 -Action Block \
                 -Protocol UDP \
                 -RemotePort {port} \
                 -Profile Any \
                 -Description 'HPN VPN DoT leak prevention (UDP)' \
                 | Out-Null",
            name = HPN_DOT_BLOCK_RULE_NAME,
            port = DOT_PORT,
        ))
        .map_err(|e| WindowsClientError::Routing(format!("powershell spawn failed: {}", e)))?;

        if !output.status.success() {
            let _ = Self::remove_dns_egress_rules();
            return Err(WindowsClientError::Routing(format_netsh_error(
                "New-NetFirewallRule (DoT) failed",
                &output.stdout,
                &output.stderr,
            )));
        }

        // ── mDNS block — UDP/5353 to multicast groups ─────────────────
        // We deliberately scope to the multicast addresses rather than
        // blocking every 5353/UDP destination so that LAN service
        // discovery against unicast peers (rare but legitimate) is
        // unaffected. Both `224.0.0.251` (RFC 6762 §3) and `ff02::fb`
        // (RFC 6762 §3) are blocked.
        let output = run_powershell_firewall(&format!(
            "New-NetFirewallRule \
                 -DisplayName '{name}' \
                 -Direction Outbound \
                 -Action Block \
                 -Protocol UDP \
                 -RemotePort {port} \
                 -RemoteAddress 224.0.0.251,ff02::fb \
                 -Profile Any \
                 -Description 'HPN VPN mDNS leak prevention' \
                 | Out-Null",
            name = HPN_MDNS_BLOCK_RULE_NAME,
            port = MDNS_PORT,
        ))
        .map_err(|e| WindowsClientError::Routing(format!("powershell spawn failed: {}", e)))?;

        if !output.status.success() {
            let _ = Self::remove_dns_egress_rules();
            return Err(WindowsClientError::Routing(format_netsh_error(
                "New-NetFirewallRule (mDNS) failed",
                &output.stdout,
                &output.stderr,
            )));
        }

        self.dns_egress_blocked = true;
        Ok(())
    }

    /// Remove the DoH / DoT / mDNS firewall rules.
    ///
    /// Idempotent: safe to call when the rules were never installed (e.g.
    /// if the user opted out of `dns_leak_protection`). Errors are logged
    /// but never fail the call.
    pub fn disable_dns_egress_blocking(&mut self) {
        if !self.dns_egress_blocked {
            return;
        }
        info!("Disabling DNS egress blocking");
        if let Err(e) = Self::remove_dns_egress_rules() {
            warn!(
                "Failed to remove DNS egress rules (will retry on cleanup): {}",
                e
            );
        }
        self.dns_egress_blocked = false;
    }

    /// Remove every HPN-owned DNS egress firewall rule. Used by
    /// `disable_dns_egress_blocking` AND by the crash-recovery path at
    /// startup, mirroring [`Self::remove_stale_ipv6_block_rule`].
    pub fn remove_stale_dns_egress_rules() -> Result<(), String> {
        Self::remove_dns_egress_rules()
    }

    fn remove_dns_egress_rules() -> Result<(), String> {
        // We tag each rule with a unique DisplayName so we can drop
        // exactly the four rules HPN created. `-ErrorAction
        // SilentlyContinue` makes each call idempotent.
        let output = run_powershell_firewall(&format!(
            "Remove-NetFirewallRule -DisplayName '{doh}'      -ErrorAction SilentlyContinue | Out-Null; \
             Remove-NetFirewallRule -DisplayName '{dot}'      -ErrorAction SilentlyContinue | Out-Null; \
             Remove-NetFirewallRule -DisplayName '{dot}_UDP'  -ErrorAction SilentlyContinue | Out-Null; \
             Remove-NetFirewallRule -DisplayName '{mdns}'     -ErrorAction SilentlyContinue | Out-Null",
            doh = HPN_DOH_BLOCK_RULE_NAME,
            dot = HPN_DOT_BLOCK_RULE_NAME,
            mdns = HPN_MDNS_BLOCK_RULE_NAME
        ))
        .map_err(|e| format!("powershell spawn: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            debug!(
                "Remove-NetFirewallRule (DNS egress) returned non-zero: stdout={} stderr={}",
                stdout, stderr
            );
        }
        Ok(())
    }

    /// Remove all added routes and restore deleted routes.
    pub fn cleanup(&mut self) -> Result<(), WindowsClientError> {
        info!("Cleaning up routes");

        // Remove the IPv6 leak-protection firewall rule ONLY if the kill
        // switch is not engaged. When the kill switch is engaged and the
        // tunnel drops unexpectedly, the IPv6-block rule is part of the
        // kill-switch state: removing it here re-opens IPv6 egress on
        // the physical interface while IPv4 is still blocked, which
        // silently leaks the user's real IP over every AAAA-capable
        // destination. The user will see "Kill Switch Activated" in the
        // UI while actually leaking.
        //
        // `cleanup_and_restore()` is the explicit-disconnect counterpart
        // and always removes the rule, mirroring the existing pattern
        // for IPv4 routes further down this function.
        if !self.kill_switch {
            self.disable_ipv6_leak_protection();
        } else {
            info!(
                "Kill switch active: keeping IPv6 firewall block in place \
                 to prevent leaks on physical interface"
            );
        }

        // The DoH/DoT/mDNS egress rules are tied to "we want VPN-locked
        // DNS", which is exactly what the user expects to keep when the
        // kill switch is active. Like the IPv6 rule, we therefore keep
        // them in place while the kill switch is engaged and only
        // remove them on a clean disconnect / kill_switch=false.
        if !self.kill_switch {
            self.disable_dns_egress_blocking();
        } else {
            info!(
                "Kill switch active: keeping DNS egress block (DoH / DoT / mDNS) \
                 in place to prevent DNS leaks on physical interface"
            );
        }

        // Remove all added IPv4 routes
        for route in &self.added_routes {
            let parts: Vec<&str> = route.split(" mask ").collect();
            if parts.len() == 2 {
                let _ = Self::delete_route(parts[0], parts[1]);
            }
        }
        self.added_routes.clear();

        // Remove all added IPv6 routes
        for route in &self.added_routes_v6 {
            if let Some((dest, prefix)) = Self::parse_cidr_v6(route) {
                let _ = Self::delete_route_v6(&self.vpn_interface, &dest, prefix);
            }
        }
        self.added_routes_v6.clear();

        // Restore deleted routes (only if kill switch was NOT active or we want to restore)
        // When kill switch is enabled and tunnel goes down, we keep routes deleted
        // for safety - user must explicitly disable kill switch to restore connectivity
        if !self.kill_switch {
            // Restore IPv4 routes
            for (dest, mask, gateway) in &self.deleted_routes {
                info!("Restoring route: {} mask {} via {}", dest, mask, gateway);
                let output = run_command_with_timeout(
                    "route",
                    &["add", dest, "mask", mask, gateway],
                    COMMAND_TIMEOUT,
                );

                if let Ok(output) = output {
                    if !output.status.success() {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        warn!("Failed to restore route: {}", stderr);
                    }
                }
            }
            // Restore IPv6 routes (CRITICAL: don't rely on SLAAC auto-restore)
            // Some systems have SLAAC disabled or manual IPv6 config
            for (dest, prefix, interface, gateway) in &self.deleted_routes_v6 {
                info!(
                    "Restoring IPv6 route: {}/{} via {} on {}",
                    dest, prefix, gateway, interface
                );
                let prefix_str = format!("{}/{}", dest, prefix);
                // netsh syntax: interface ipv6 add route <prefix> <interface> [nexthop=<gateway>]
                let output = run_command_with_timeout(
                    "netsh",
                    &[
                        "interface",
                        "ipv6",
                        "add",
                        "route",
                        &prefix_str,
                        interface,
                        &format!("nexthop={}", gateway),
                    ],
                    COMMAND_TIMEOUT,
                );
                if let Ok(output) = output {
                    if !output.status.success() {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        warn!("Failed to restore IPv6 route: {}", stderr);
                    }
                } else {
                    warn!("Failed to execute netsh for IPv6 route restoration");
                }
            }
        } else {
            info!(
                "Kill switch active: NOT restoring original routes (no internet until reconnect or disable kill switch)"
            );
        }
        self.deleted_routes.clear();
        self.deleted_routes_v6.clear();

        // Persist the post-cleanup state to disk so a crash AFTER this
        // point cannot trigger an incorrect recovery on next boot.
        //
        // In the kill-switch-engaged path, the in-memory `added_routes`
        // and `deleted_routes` are now empty: we deleted what we added
        // and we intentionally did NOT restore the original gateway
        // (the kill switch is enforced by route absence + the IPv6
        // firewall rule we kept installed via the gate at the top of
        // this function). The on-disk file STILL has the pre-cleanup
        // snapshot, so if the process now crashes,
        // `RecoveryState::perform_recovery_with_state` would helpfully
        // re-add the default route and undo the kill switch across the
        // reboot — exactly the failure mode WIN-4 called out.
        //
        // `mark_clean_disconnect` zeros out `vpn_active` and deletes the
        // recovery file. The user's kill-switch state survives anyway
        // because routes-not-restored + IPv6-firewall-rule are OS-level
        // and persist across our process exit. On next boot the file is
        // gone, recovery is a no-op, and the user's reconnect attempt
        // re-establishes routes from scratch.
        if let Some(ref mut recovery) = self.recovery_state {
            recovery.mark_clean_disconnect();
        }
        self.recovery_state = None;
        if let Err(e) = RecoveryState::delete() {
            debug!("Could not delete recovery file (may not exist): {}", e);
        }

        Ok(())
    }

    /// Cleanup and restore all routes (ignoring kill switch).
    /// Use this when user explicitly disconnects or disables kill switch.
    pub fn cleanup_and_restore(&mut self) -> Result<(), WindowsClientError> {
        info!("Cleaning up and restoring all routes");

        // Remove the IPv6 leak-protection firewall rule even on the
        // "restore everything" path. cleanup() already does this, but
        // cleanup_and_restore() is the explicit-disconnect path and the
        // user would be surprised if their IPv6 stays blocked after
        // disconnect. Idempotent: no-op if never enabled.
        self.disable_ipv6_leak_protection();

        // Same rationale for the DoH / DoT / mDNS egress rules: an
        // explicit disconnect means "I want my normal DNS back".
        self.disable_dns_egress_blocking();

        // Remove all added IPv4 routes
        for route in &self.added_routes {
            let parts: Vec<&str> = route.split(" mask ").collect();
            if parts.len() == 2 {
                let _ = Self::delete_route(parts[0], parts[1]);
            }
        }
        self.added_routes.clear();

        // Remove all added IPv6 routes
        for route in &self.added_routes_v6 {
            if let Some((dest, prefix)) = Self::parse_cidr_v6(route) {
                let _ = Self::delete_route_v6(&self.vpn_interface, &dest, prefix);
            }
        }
        self.added_routes_v6.clear();

        // Always restore deleted IPv4 routes
        for (dest, mask, gateway) in &self.deleted_routes {
            info!("Restoring route: {} mask {} via {}", dest, mask, gateway);
            let output = run_command_with_timeout(
                "route",
                &["add", dest, "mask", mask, gateway],
                COMMAND_TIMEOUT,
            );

            if let Ok(output) = output {
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    warn!("Failed to restore route: {}", stderr);
                }
            }
        }

        // Always restore IPv6 routes (CRITICAL FIX for P2-4)
        for (dest, prefix, interface, gateway) in &self.deleted_routes_v6 {
            info!(
                "Restoring IPv6 route: {}/{} via {} on {}",
                dest, prefix, gateway, interface
            );
            let prefix_str = format!("{}/{}", dest, prefix);
            // netsh syntax: interface ipv6 add route <prefix> <interface> [nexthop=<gateway>]
            let output = run_command_with_timeout(
                "netsh",
                &[
                    "interface",
                    "ipv6",
                    "add",
                    "route",
                    &prefix_str,
                    interface,
                    &format!("nexthop={}", gateway),
                ],
                COMMAND_TIMEOUT,
            );
            if let Ok(output) = output {
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    warn!("Failed to restore IPv6 route: {}", stderr);
                }
            } else {
                warn!("Failed to execute netsh for IPv6 route restoration");
            }
        }

        self.deleted_routes.clear();
        self.deleted_routes_v6.clear();

        // Clear recovery state after successful cleanup
        // This indicates a clean disconnect - no recovery needed on next startup
        if let Some(ref mut recovery) = self.recovery_state {
            recovery.mark_clean_disconnect();
        }
        self.recovery_state = None;

        // Also try to delete any orphaned recovery file
        if let Err(e) = RecoveryState::delete() {
            debug!("Could not delete recovery file (may not exist): {}", e);
        }

        info!("Route cleanup and restore completed");
        Ok(())
    }

    /// Enable or disable kill switch dynamically.
    pub fn set_kill_switch(&mut self, enabled: bool, allow_lan: bool) {
        self.kill_switch = enabled;
        self.allow_lan = allow_lan;
    }
}

impl Drop for RouteManager {
    fn drop(&mut self) {
        if self.force_restore_on_drop {
            // User disconnect or safety default: always restore routes
            let _ = self.cleanup_and_restore();
        } else {
            // Unexpected disconnect with kill switch - use cleanup() which respects kill_switch flag
            let _ = self.cleanup();
        }
    }
}

/// Set the IPv4 DNS servers for an interface.
pub fn set_interface_dns(interface_name: &str, dns_servers: &[[u8; 4]]) -> io::Result<()> {
    if dns_servers.is_empty() {
        return Ok(());
    }

    let primary_dns = format!(
        "{}.{}.{}.{}",
        dns_servers[0][0], dns_servers[0][1], dns_servers[0][2], dns_servers[0][3]
    );

    let output = run_command_with_timeout(
        "netsh",
        &[
            "interface",
            "ip",
            "set",
            "dns",
            interface_name,
            "static",
            &primary_dns,
        ],
        COMMAND_TIMEOUT,
    )?;

    if !output.status.success() {
        return Err(io::Error::other(format_netsh_error(
            "netsh dns failed",
            &output.stdout,
            &output.stderr,
        )));
    }

    // Add secondary DNS if available
    if dns_servers.len() > 1 {
        let secondary_dns = format!(
            "{}.{}.{}.{}",
            dns_servers[1][0], dns_servers[1][1], dns_servers[1][2], dns_servers[1][3]
        );

        let _ = run_command_with_timeout(
            "netsh",
            &[
                "interface",
                "ip",
                "add",
                "dns",
                interface_name,
                &secondary_dns,
                "index=2",
            ],
            COMMAND_TIMEOUT,
        );
    }

    info!(
        "Configured DNS for {}: {}",
        interface_name,
        dns_servers
            .iter()
            .map(|d| format!("{}.{}.{}.{}", d[0], d[1], d[2], d[3]))
            .collect::<Vec<_>>()
            .join(", ")
    );

    Ok(())
}

/// Set the IPv6 DNS servers for an interface.
pub fn set_interface_dns_v6(interface_name: &str, dns_servers: &[[u8; 16]]) -> io::Result<()> {
    if dns_servers.is_empty() {
        return Ok(());
    }

    // Format IPv6 address
    let format_ipv6 = |bytes: &[u8; 16]| -> String {
        let addr = Ipv6Addr::from(*bytes);
        addr.to_string()
    };

    let primary_dns = format_ipv6(&dns_servers[0]);

    let output = run_command_with_timeout(
        "netsh",
        &[
            "interface",
            "ipv6",
            "set",
            "dnsservers",
            interface_name,
            "static",
            &primary_dns,
        ],
        COMMAND_TIMEOUT,
    )?;

    if !output.status.success() {
        return Err(io::Error::other(format_netsh_error(
            "netsh ipv6 dns failed",
            &output.stdout,
            &output.stderr,
        )));
    }

    // Add secondary DNS if available
    if dns_servers.len() > 1 {
        let secondary_dns = format_ipv6(&dns_servers[1]);

        let _ = run_command_with_timeout(
            "netsh",
            &[
                "interface",
                "ipv6",
                "add",
                "dnsservers",
                interface_name,
                &secondary_dns,
                "index=2",
            ],
            COMMAND_TIMEOUT,
        );
    }

    info!(
        "Configured IPv6 DNS for {}: {}",
        interface_name,
        dns_servers
            .iter()
            .map(|d| format_ipv6(d))
            .collect::<Vec<_>>()
            .join(", ")
    );

    Ok(())
}

/// Set both IPv4 and IPv6 DNS servers for an interface.
pub fn set_interface_dns_dual_stack(
    interface_name: &str,
    dns_v4: &[[u8; 4]],
    dns_v6: &[[u8; 16]],
) -> io::Result<()> {
    // Set IPv4 DNS
    if !dns_v4.is_empty() {
        set_interface_dns(interface_name, dns_v4)?;
    }

    // Set IPv6 DNS
    if !dns_v6.is_empty() {
        set_interface_dns_v6(interface_name, dns_v6)?;
    }

    Ok(())
}

/// Get the interface index by name.
pub fn get_interface_index(interface_name: &str) -> io::Result<u32> {
    // Use GetAdaptersInfo or similar Win32 API
    // For simplicity, we'll use netsh to find the interface
    let output = run_command_with_timeout(
        "netsh",
        &["interface", "ipv4", "show", "interfaces"],
        COMMAND_TIMEOUT,
    )?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        if line.contains(interface_name) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(idx_str) = parts.first() {
                if let Ok(idx) = idx_str.parse() {
                    return Ok(idx);
                }
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("interface not found: {}", interface_name),
    ))
}

/// DNS leak protection manager.
pub struct DnsLeakProtection {
    /// VPN interface name.
    vpn_interface: String,
    /// Original DNS settings per interface (interface_name -> dns_servers).
    original_dns: std::collections::HashMap<String, Vec<String>>,
    /// Whether protection is active.
    active: bool,
    /// GUID of the NRPT rule installed by `enable()` so `disable()` can
    /// remove it. `None` if NRPT install failed or hasn't run yet.
    nrpt_rule_guid: Option<String>,
    /// `Some(_)` when `enable()` wrote `DisableSmartNameResolution=1` to
    /// the registry — `disable()` then rolls it back via
    /// `restore_smart_multi_homed()`. The payload is reserved for a
    /// future improvement that snapshots and restores the prior value
    /// instead of always deleting.
    smart_multi_homed_was_set: Option<bool>,
}

impl DnsLeakProtection {
    /// Create a new DNS leak protection manager.
    pub fn new(vpn_interface: &str) -> Self {
        Self {
            vpn_interface: vpn_interface.to_string(),
            original_dns: std::collections::HashMap::new(),
            active: false,
            nrpt_rule_guid: None,
            smart_multi_homed_was_set: None,
        }
    }

    /// Get all network interfaces (excluding loopback and VPN).
    ///
    /// Uses the Windows API for reliable interface enumeration.
    fn get_physical_interfaces() -> Vec<String> {
        // Try Windows API first
        match windows_api::get_physical_interfaces() {
            Ok(interfaces) => {
                let names: Vec<String> = interfaces.into_iter().map(|i| i.alias).collect();
                debug!("Got {} physical interfaces via API", names.len());
                return names;
            }
            Err(e) => {
                warn!(
                    "Failed to get interfaces via API: {}, falling back to netsh",
                    e
                );
            }
        }

        // Fallback to netsh
        let output = run_command_with_timeout(
            "netsh",
            &["interface", "ipv4", "show", "interfaces"],
            COMMAND_TIMEOUT,
        );

        let mut interfaces = Vec::new();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().skip(3) {
                // Skip header lines
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 {
                    // Format: Idx Met MTU State Name
                    let name = parts[4..].join(" ");
                    // Exclude loopback and VPN interfaces
                    if !name.contains("Loopback")
                        && !name.contains("HPN")
                        && !name.contains("WireGuard")
                        && !name.contains("TAP")
                        && !name.contains("TUN")
                    {
                        interfaces.push(name);
                    }
                }
            }
        }

        interfaces
    }

    /// Get current DNS servers for an interface.
    ///
    /// Uses the Windows API for reliable DNS retrieval.
    fn get_interface_dns(interface_name: &str) -> Vec<String> {
        // Try Windows API first
        match windows_api::get_interface_dns(interface_name) {
            Ok(settings) => {
                let servers: Vec<String> = settings
                    .ipv4_servers
                    .iter()
                    .map(|s| s.to_string())
                    .collect();
                debug!("Got DNS for {} via API: {:?}", interface_name, servers);
                return servers;
            }
            Err(e) => {
                debug!("Failed to get DNS via API: {}, falling back to netsh", e);
            }
        }

        // Fallback to netsh
        let output = run_command_with_timeout(
            "netsh",
            &["interface", "ipv4", "show", "dnsservers", interface_name],
            COMMAND_TIMEOUT,
        );

        let mut dns_servers = Vec::new();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let line = line.trim();
                // Look for IP addresses
                if let Some(ip) = line
                    .split_whitespace()
                    .find(|s| s.parse::<Ipv4Addr>().is_ok())
                {
                    dns_servers.push(ip.to_string());
                }
            }
        }

        dns_servers
    }

    /// Clear DNS servers for an interface.
    ///
    /// Uses the Windows API for reliable DNS clearing.
    fn clear_interface_dns(interface_name: &str) -> io::Result<()> {
        // Try Windows API first
        match windows_api::clear_interface_dns(interface_name) {
            Ok(()) => {
                debug!("Cleared DNS for {} via API", interface_name);
                return Ok(());
            }
            Err(e) => {
                warn!("Failed to clear DNS via API: {}, falling back to netsh", e);
            }
        }

        // Fallback: Method 1 - Try to delete all DNS servers
        let delete_result = run_command_with_timeout(
            "netsh",
            &[
                "interface",
                "ipv4",
                "delete",
                "dnsservers",
                interface_name,
                "all",
            ],
            COMMAND_TIMEOUT,
        );

        if delete_result.is_ok() {
            debug!(
                "Cleared DNS for interface: {} (delete method)",
                interface_name
            );
            return Ok(());
        }

        // Fallback: Method 2 - Set to static with address=none (Windows 10+)
        let set_result = run_command_with_timeout(
            "netsh",
            &[
                "interface",
                "ipv4",
                "set",
                "dnsservers",
                interface_name,
                "static",
                "none",
            ],
            COMMAND_TIMEOUT,
        );

        if let Ok(ref output) = set_result {
            if output.status.success() {
                debug!(
                    "Cleared DNS for interface: {} (static none method)",
                    interface_name
                );
                return Ok(());
            }
        }

        // Fallback: Method 3 - set DNS to localhost
        warn!(
            "Could not clear DNS for {} using standard methods, using localhost fallback",
            interface_name
        );
        let _ = run_command_with_timeout(
            "netsh",
            &[
                "interface",
                "ipv4",
                "set",
                "dnsservers",
                interface_name,
                "static",
                "127.0.0.1",
            ],
            COMMAND_TIMEOUT,
        );

        debug!(
            "Set DNS to localhost for interface: {} (fallback)",
            interface_name
        );
        Ok(())
    }

    /// Restore DNS servers for an interface.
    ///
    /// Uses the Windows API for reliable DNS restoration.
    fn restore_interface_dns(interface_name: &str, dns_servers: &[String]) -> io::Result<()> {
        if dns_servers.is_empty() {
            // Set back to DHCP - use API first
            match windows_api::clear_interface_dns(interface_name) {
                Ok(()) => {
                    debug!("Restored DNS to DHCP for {} via API", interface_name);
                    return Ok(());
                }
                Err(e) => {
                    debug!(
                        "Failed to restore DNS via API: {}, falling back to netsh",
                        e
                    );
                }
            }

            // Fallback to netsh
            let _ = run_command_with_timeout(
                "netsh",
                &[
                    "interface",
                    "ipv4",
                    "set",
                    "dnsservers",
                    interface_name,
                    "source=dhcp",
                ],
                COMMAND_TIMEOUT,
            );
        } else {
            // Try Windows API first
            let ipv4_servers: Vec<Ipv4Addr> =
                dns_servers.iter().filter_map(|s| s.parse().ok()).collect();

            if !ipv4_servers.is_empty() {
                let settings = windows_api::DnsSettings::with_ipv4(ipv4_servers);
                match windows_api::set_interface_dns(interface_name, &settings) {
                    Ok(()) => {
                        debug!(
                            "Restored DNS for {} via API: {:?}",
                            interface_name, dns_servers
                        );
                        return Ok(());
                    }
                    Err(e) => {
                        debug!("Failed to set DNS via API: {}, falling back to netsh", e);
                    }
                }
            }

            // Fallback to netsh
            let _ = run_command_with_timeout(
                "netsh",
                &[
                    "interface",
                    "ipv4",
                    "set",
                    "dnsservers",
                    interface_name,
                    "static",
                    &dns_servers[0],
                ],
                COMMAND_TIMEOUT,
            );

            // Add additional DNS servers
            for (i, dns) in dns_servers.iter().enumerate().skip(1) {
                let index_str = format!("index={}", i + 1);
                let _ = run_command_with_timeout(
                    "netsh",
                    &[
                        "interface",
                        "ipv4",
                        "add",
                        "dnsservers",
                        interface_name,
                        dns,
                        &index_str,
                    ],
                    COMMAND_TIMEOUT,
                );
            }
        }

        debug!(
            "Restored DNS for interface {}: {:?}",
            interface_name, dns_servers
        );
        Ok(())
    }

    /// Enable DNS leak protection.
    ///
    /// - Saves current DNS settings for all physical interfaces
    /// - Clears DNS (v4 + v6) on all physical interfaces
    /// - Disables IPv6 RA-RDNSS on physical interfaces (Free Box and other
    ///   French ISPs aggressively push ISP DNS via Router Advertisement;
    ///   without this they leak past every per-interface clear)
    /// - Sets DNS (v4 + v6) on the VPN/Wintun interface
    /// - Sets the Wintun interface metric to 1 (lower than wired/Wi-Fi
    ///   defaults) so Windows DNS path-selection prefers it
    /// - Installs an NRPT (Name Resolution Policy Table) rule that forces
    ///   ALL DNS queries through the VPN's resolvers — the canonical
    ///   countermeasure to Windows' "smart multi-homed name resolution",
    ///   used by WireGuard, Mullvad, OpenVPN-GUI, Cisco AnyConnect.
    ///   Without this, Windows queries every interface's DNS in parallel
    ///   and uses whichever responds first.
    /// - Sets `DisableSmartMultiHomedNameResolution` + `DisableParallelAandAAAA`
    ///   registry policies as a second-layer defence in case the NRPT
    ///   rule is bypassed by an app using `DnsQueryEx` with explicit
    ///   per-interface flags.
    /// - Disables LLMNR and NetBIOS-over-TCP system-wide.
    /// - Flushes the DNS resolver cache.
    pub fn enable(&mut self, vpn_dns_v4: &[[u8; 4]], vpn_dns_v6: &[[u8; 16]]) -> io::Result<()> {
        if self.active {
            return Ok(());
        }

        info!("Enabling DNS leak protection");

        // Save and clear DNS for all physical interfaces
        let interfaces = Self::get_physical_interfaces();
        for iface in &interfaces {
            if iface == &self.vpn_interface {
                continue;
            }

            let dns = Self::get_interface_dns(iface);
            if !dns.is_empty() {
                self.original_dns.insert(iface.clone(), dns);
            }

            if let Err(e) = Self::clear_interface_dns(iface) {
                warn!("Failed to clear DNS for {}: {}", iface, e);
            }

            // Disable IPv6 Router Advertisement RDNSS option so the next
            // RA from the ISP gateway (e.g. Free Box) does NOT re-populate
            // the physical interface's IPv6 DNS with the ISP resolver.
            // Without this, clearing IPv6 DNS is a one-shot fix that the
            // next RA undoes within minutes.
            if let Err(e) = Self::disable_ra_rdnss(iface) {
                debug!(
                    "Failed to disable IPv6 RA-RDNSS on {} (non-fatal): {}",
                    iface, e
                );
            }
        }

        // Set DNS on VPN interface — DUAL-STACK (v4 + v6) when the server
        // provided IPv6 servers, otherwise v4-only. Without IPv6 DNS on
        // Wintun in dual-stack mode, AAAA queries fall through to whatever
        // resolver Windows can find — usually the physical interface's
        // RA-pushed ISP resolver, which is exactly the leak we're closing.
        let dns_ipv4: Vec<std::net::Ipv4Addr> = vpn_dns_v4
            .iter()
            .map(|bytes| std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
            .collect();
        let dns_ipv6: Vec<std::net::Ipv6Addr> = vpn_dns_v6
            .iter()
            .map(|bytes| std::net::Ipv6Addr::from(*bytes))
            .collect();

        let dns_settings = if dns_ipv6.is_empty() {
            windows_api::DnsSettings::with_ipv4(dns_ipv4.clone())
        } else {
            windows_api::DnsSettings::with_dual_stack(dns_ipv4.clone(), dns_ipv6.clone())
        };
        windows_api::set_interface_dns(&self.vpn_interface, &dns_settings)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        // Force Wintun to win the metric-based interface ranking. Windows
        // DNS path-selection prefers the interface with the lowest metric;
        // wired Ethernet defaults to ~25 and Wi-Fi to ~35-50, so metric=1
        // wins deterministically. Non-fatal — Windows defaults still work
        // if this call fails (just with a higher leak probability).
        if let Ok(if_index) = windows_api::get_interface_index(&self.vpn_interface) {
            if let Err(e) = windows_api::set_interface_metric(if_index, 1, false) {
                debug!("Failed to set Wintun IPv4 metric (non-fatal): {}", e);
            }
            if !dns_ipv6.is_empty() {
                if let Err(e) = windows_api::set_interface_metric(if_index, 1, true) {
                    debug!("Failed to set Wintun IPv6 metric (non-fatal): {}", e);
                }
            }
        }

        // Install an NRPT rule that forces ALL DNS queries through the
        // VPN's resolvers. This is the SINGLE most effective leak-stop
        // mechanism on Windows — see method doc for the full rationale.
        let nrpt_servers: Vec<String> = dns_ipv4
            .iter()
            .map(|ip| ip.to_string())
            .chain(dns_ipv6.iter().map(|ip| ip.to_string()))
            .collect();
        let nrpt_guid = Self::install_nrpt_rule(&nrpt_servers);

        // Defence in depth: disable Windows' parallel-resolve behaviour
        // via Group Policy registry write. Even if an app bypasses NRPT
        // by passing per-interface query flags, this prevents the race
        // across interfaces.
        let smart_multi_homed_prior = Self::disable_smart_multi_homed();

        // Flush DNS cache using native Windows API. Must happen AFTER
        // NRPT + interface DNS are set so the cache doesn't serve stale
        // ISP-resolved names.
        let _ = windows_api::flush_dns_cache();

        // Block LLMNR (Link-Local Multicast Name Resolution) via registry
        Self::disable_llmnr();

        // Disable NetBIOS over TCP/IP on all physical interfaces
        Self::disable_netbios(&interfaces, &self.vpn_interface);

        // Update recovery state so crash recovery can roll back ALL the
        // system-wide changes (LLMNR, NetBIOS, NRPT, SmartMultiHomed).
        if let Some(mut state) = RecoveryState::load() {
            state.llmnr_disabled = true;
            state.netbios_disabled = true;
            state.nrpt_rule_guid = nrpt_guid.clone();
            state.smart_multi_homed_disabled = smart_multi_homed_prior.is_some();
            let _ = state.save();
        }

        // Remember the NRPT GUID + SmartMultiHomed prior state on the
        // protection instance so the normal `disable()` path can roll
        // them back without going through RecoveryState.
        self.nrpt_rule_guid = nrpt_guid;
        self.smart_multi_homed_was_set = smart_multi_homed_prior;

        self.active = true;
        info!(
            "DNS leak protection enabled. Cleared DNS on {} interfaces, NRPT installed, SmartMultiHomed disabled, LLMNR+NetBIOS blocked",
            interfaces.len()
        );

        Ok(())
    }

    /// Install an NRPT (Name Resolution Policy Table) rule that forces
    /// ALL DNS queries — for every namespace `"."` — through the supplied
    /// resolvers. This bypasses Windows' "smart multi-homed name
    /// resolution" which would otherwise query every interface's DNS in
    /// parallel and use whichever responds first, leaking the ISP
    /// resolver alongside the VPN's.
    ///
    /// Returns the GUID of the rule (for later removal) or `None` if the
    /// PowerShell call failed (logged, non-fatal — without NRPT the leak
    /// remains but the rest of the protection still applies).
    pub(crate) fn install_nrpt_rule(servers: &[String]) -> Option<String> {
        if servers.is_empty() {
            debug!("install_nrpt_rule: no servers provided, skipping");
            return None;
        }

        // Build the PowerShell-side comma-separated server list as a
        // string-array literal: @("1.2.3.4","2001:db8::1")
        let ps_servers = servers
            .iter()
            .map(|s| format!("\"{}\"", s))
            .collect::<Vec<_>>()
            .join(",");

        // The command emits the new rule's GUID on stdout so we can
        // persist it for later removal — both on clean disconnect and on
        // crash-recovery startup.
        let script = format!(
            "$rule = Add-DnsClientNrptRule -Namespace \".\" \
             -NameServers @({}) -Comment 'HPN VPN tunnel - force all DNS through tunnel' \
             -PassThru -ErrorAction Stop; \
             Write-Output $rule.Name",
            ps_servers
        );

        let output = run_command_with_timeout(
            "powershell",
            &["-NoProfile", "-NonInteractive", "-Command", &script],
            COMMAND_TIMEOUT,
        );

        match output {
            Ok(out) if out.status.success() => {
                let guid = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if guid.is_empty() {
                    warn!("Add-DnsClientNrptRule succeeded but returned no GUID");
                    None
                } else {
                    info!("NRPT rule installed: {}", guid);
                    Some(guid)
                }
            }
            Ok(out) => {
                warn!(
                    "Add-DnsClientNrptRule failed (exit {}): {}",
                    out.status,
                    String::from_utf8_lossy(&out.stderr).trim()
                );
                None
            }
            Err(e) => {
                warn!("Failed to run powershell for NRPT: {}", e);
                None
            }
        }
    }

    /// Remove an NRPT rule previously installed by `install_nrpt_rule`.
    /// Safe to call with a stale / unknown GUID — PowerShell reports a
    /// non-zero exit which we log and ignore.
    pub(crate) fn remove_nrpt_rule(guid: &str) {
        if guid.is_empty() {
            return;
        }

        let script = format!(
            "Remove-DnsClientNrptRule -Name '{}' -Force -ErrorAction SilentlyContinue",
            guid.replace('\'', "''")
        );

        let output = run_command_with_timeout(
            "powershell",
            &["-NoProfile", "-NonInteractive", "-Command", &script],
            COMMAND_TIMEOUT,
        );

        match output {
            Ok(out) if out.status.success() => {
                info!("NRPT rule removed: {}", guid);
            }
            Ok(out) => {
                debug!(
                    "Remove-DnsClientNrptRule returned non-zero (rule may already be gone): {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }
            Err(e) => warn!("Failed to run powershell for NRPT removal: {}", e),
        }
    }

    /// Cleanup: remove ALL HPN-VPN NRPT rules found on the system. Used
    /// by crash recovery when we don't know the specific GUID (e.g. an
    /// older client install crashed before persisting it). Matches by
    /// comment string.
    pub(crate) fn cleanup_orphaned_nrpt_rules() {
        let script = "Get-DnsClientNrptRule | \
             Where-Object { $_.Comment -like 'HPN VPN tunnel*' } | \
             ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force -ErrorAction SilentlyContinue }";

        let output = run_command_with_timeout(
            "powershell",
            &["-NoProfile", "-NonInteractive", "-Command", script],
            COMMAND_TIMEOUT,
        );

        match output {
            Ok(out) if out.status.success() => {
                debug!("Cleanup of orphaned HPN NRPT rules completed");
            }
            Ok(out) => {
                debug!(
                    "Orphaned NRPT cleanup returned non-zero: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }
            Err(e) => warn!("Failed to run powershell for orphaned NRPT cleanup: {}", e),
        }
    }

    /// Disable Windows' "smart multi-homed name resolution" + parallel
    /// A/AAAA query behaviour via the documented Group Policy registry
    /// keys. Returns the prior value of `DisableSmartNameResolution` (as
    /// the option payload) so `restore_smart_multi_homed` can put it
    /// back. `Some(true)` means "we wrote the policy and there was no
    /// prior value"; `Some(false)` means "we wrote it but there WAS a
    /// prior value of 0"; `None` means "we couldn't write the policy".
    pub(crate) fn disable_smart_multi_homed() -> Option<bool> {
        // Write both keys. Documented by Microsoft at
        //   https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-dnsclient
        // under the "DisableSmartNameResolution" and
        // "DisableParallelAandAAAA" entries.
        let key = r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";
        let values = [
            ("DisableSmartNameResolution", "1"),
            ("DisableParallelAandAAAA", "1"),
        ];

        let mut wrote_at_least_one = false;
        for (name, data) in values {
            let result = std::process::Command::new("reg")
                .args(["add", key, "/v", name, "/t", "REG_DWORD", "/d", data, "/f"])
                .output();
            match result {
                Ok(out) if out.status.success() => {
                    debug!("Set registry {}\\{} = {}", key, name, data);
                    wrote_at_least_one = true;
                }
                Ok(out) => {
                    warn!(
                        "Failed to set {}: {}",
                        name,
                        String::from_utf8_lossy(&out.stderr).trim()
                    );
                }
                Err(e) => warn!("Failed to run reg for {}: {}", name, e),
            }
        }

        if wrote_at_least_one { Some(true) } else { None }
    }

    /// Roll back the `DisableSmartMultiHomedNameResolution` policy
    /// changes made by `disable_smart_multi_homed`. Currently always
    /// DELETES the values rather than restoring them — most home and
    /// workstation systems do not set these keys at all, so the prior
    /// state was "absent". A future improvement would snapshot the
    /// prior value (read via `reg query`) and reinstate exactly that.
    pub(crate) fn restore_smart_multi_homed() {
        let key = r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";
        for name in ["DisableSmartNameResolution", "DisableParallelAandAAAA"] {
            let _ = std::process::Command::new("reg")
                .args(["delete", key, "/v", name, "/f"])
                .output();
        }
    }

    /// Disable IPv6 RA-RDNSS option processing on an interface. Without
    /// this, Free Box / Livebox / Bbox and other RA-RDNSS-pushing
    /// gateways will repopulate the physical interface's IPv6 DNS with
    /// the ISP resolver shortly after we clear it — and the leak comes
    /// back on the next RA refresh (typically every 5-30 minutes).
    pub(crate) fn disable_ra_rdnss(interface_name: &str) -> io::Result<()> {
        let output = run_command_with_timeout(
            "netsh",
            &[
                "interface",
                "ipv6",
                "set",
                "interface",
                interface_name,
                "rdnss=disabled",
                "store=active",
            ],
            COMMAND_TIMEOUT,
        )?;
        if output.status.success() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                String::from_utf8_lossy(&output.stderr).to_string(),
            ))
        }
    }

    /// Re-enable IPv6 RA-RDNSS on an interface (rollback for
    /// `disable_ra_rdnss`). Best-effort: failure is logged and ignored.
    pub(crate) fn enable_ra_rdnss(interface_name: &str) {
        let _ = run_command_with_timeout(
            "netsh",
            &[
                "interface",
                "ipv6",
                "set",
                "interface",
                interface_name,
                "rdnss=enabled",
                "store=active",
            ],
            COMMAND_TIMEOUT,
        );
    }

    /// Disable LLMNR via registry to prevent DNS leaks on local network.
    pub(crate) fn disable_llmnr() {
        let result = std::process::Command::new("reg")
            .args([
                "add",
                r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
                "/v",
                "EnableMulticast",
                "/t",
                "REG_DWORD",
                "/d",
                "0",
                "/f",
            ])
            .output();

        match result {
            Ok(output) if output.status.success() => {
                debug!("LLMNR disabled via registry");
            }
            Ok(output) => {
                warn!(
                    "Failed to disable LLMNR: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(e) => warn!("Failed to run reg command for LLMNR: {}", e),
        }
    }

    /// Re-enable LLMNR via registry.
    pub(crate) fn enable_llmnr() {
        let result = std::process::Command::new("reg")
            .args([
                "delete",
                r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
                "/v",
                "EnableMulticast",
                "/f",
            ])
            .output();

        match result {
            Ok(output) if output.status.success() => {
                debug!("LLMNR re-enabled via registry");
            }
            _ => {
                // Failing to re-enable is not critical
                debug!("LLMNR registry key removal skipped (may not exist)");
            }
        }
    }

    /// Disable NetBIOS over TCP/IP via registry on all adapters.
    /// Sets NetbiosOptions=2 (Disabled) on each TCP/IP interface GUID.
    /// Works on all Windows versions (no wmic dependency).
    pub(crate) fn disable_netbios(_interfaces: &[String], _vpn_interface: &str) {
        let base_path = r"HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces";

        // List all Tcpip_{GUID} subkeys
        let result = std::process::Command::new("reg")
            .args(["query", base_path])
            .output();

        let subkeys = match result {
            Ok(output) if output.status.success() => String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter(|l| l.contains("Tcpip_"))
                .map(|l| l.trim().to_string())
                .collect::<Vec<_>>(),
            _ => {
                debug!("Could not enumerate NetBIOS interfaces");
                return;
            }
        };

        let mut count = 0;
        for key in &subkeys {
            let result = std::process::Command::new("reg")
                .args([
                    "add",
                    key,
                    "/v",
                    "NetbiosOptions",
                    "/t",
                    "REG_DWORD",
                    "/d",
                    "2",
                    "/f",
                ])
                .output();

            if let Ok(output) = result {
                if output.status.success() {
                    count += 1;
                }
            }
        }
        debug!(
            "NetBIOS disabled on {}/{} interfaces via registry",
            count,
            subkeys.len()
        );
    }

    /// Re-enable NetBIOS over TCP/IP via registry (value 0 = default/DHCP).
    pub(crate) fn enable_netbios(_interfaces: &[String]) {
        let base_path = r"HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces";

        let result = std::process::Command::new("reg")
            .args(["query", base_path])
            .output();

        let subkeys = match result {
            Ok(output) if output.status.success() => String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter(|l| l.contains("Tcpip_"))
                .map(|l| l.trim().to_string())
                .collect::<Vec<_>>(),
            _ => return,
        };

        for key in &subkeys {
            let _ = std::process::Command::new("reg")
                .args([
                    "add",
                    key,
                    "/v",
                    "NetbiosOptions",
                    "/t",
                    "REG_DWORD",
                    "/d",
                    "0",
                    "/f",
                ])
                .output();
        }
        debug!("NetBIOS re-enabled on all interfaces via registry");
    }

    /// Disable DNS leak protection and restore original settings.
    ///
    /// Rolls back EVERY system-wide change made by `enable()`, in the
    /// reverse order of installation:
    ///   1. Remove the NRPT rule (so apps stop force-routing through
    ///      the now-defunct VPN resolvers)
    ///   2. Restore the SmartMultiHomed registry policy (delete our
    ///      override values; if the user had a prior policy of their
    ///      own, the future restore-prior-value improvement would
    ///      reinstate it)
    ///   3. Re-enable IPv6 RA-RDNSS on physical interfaces (so the
    ///      next RA can repopulate IPv6 DNS via DHCPv6/RA)
    ///   4. Restore IPv4 DNS on physical interfaces from the snapshot
    ///   5. Restore LLMNR + NetBIOS
    ///   6. Flush the DNS resolver cache
    ///
    /// On disconnect failures, we attempt every rollback step
    /// independently — partial restoration is better than aborting
    /// halfway and leaving the system stuck in a half-protected state.
    pub fn disable(&mut self) -> io::Result<()> {
        if !self.active {
            return Ok(());
        }

        info!("Disabling DNS leak protection");

        // Remove the NRPT rule first so the next DNS query is no
        // longer pinned to the VPN's (now closed) resolvers.
        if let Some(guid) = self.nrpt_rule_guid.take() {
            Self::remove_nrpt_rule(&guid);
        }

        // Restore SmartMultiHomed registry policy.
        if self.smart_multi_homed_was_set.take().is_some() {
            Self::restore_smart_multi_homed();
        }

        // Re-enable RA-RDNSS on each physical interface we touched.
        let interfaces: Vec<String> = Self::get_physical_interfaces();
        for iface in &interfaces {
            if iface == &self.vpn_interface {
                continue;
            }
            Self::enable_ra_rdnss(iface);
        }

        // Restore IPv4 DNS from snapshot.
        for (iface, dns) in &self.original_dns {
            if let Err(e) = Self::restore_interface_dns(iface, dns) {
                warn!("Failed to restore DNS for {}: {}", iface, e);
            }
        }
        self.original_dns.clear();

        // Flush DNS cache to evict any names resolved while the NRPT
        // rule was active (they're tied to the now-removed VPN DNS).
        let _ = run_command_with_timeout("ipconfig", &["/flushdns"], COMMAND_TIMEOUT);

        // Restore LLMNR
        Self::enable_llmnr();

        // Restore NetBIOS on all known interfaces
        Self::enable_netbios(&interfaces);

        self.active = false;
        info!(
            "DNS leak protection disabled, NRPT removed, SmartMultiHomed restored, LLMNR+NetBIOS re-enabled"
        );

        Ok(())
    }

    /// Check if DNS leak protection is active.
    pub fn is_active(&self) -> bool {
        self.active
    }
}

impl Drop for DnsLeakProtection {
    fn drop(&mut self) {
        // Always restore DNS on drop
        let _ = self.disable();
    }
}

/// IPv6 leak protection for Windows.
///
/// Prevents IPv6 traffic from bypassing the VPN when only IPv4 is configured.
/// This is critical because Windows may prefer IPv6 over IPv4, which can leak
/// traffic outside the VPN tunnel.
///
/// Uses netsh commands to disable IPv6 on all interfaces.
pub struct Ipv6LeakProtection {
    /// Whether IPv6 is currently disabled.
    disabled: bool,
    /// Interfaces where IPv6 was disabled.
    disabled_interfaces: Vec<String>,
    /// When `true` (the default), `Drop` re-enables IPv6 on the physical
    /// interfaces that were disabled. Set to `false` on the kill-switch-
    /// engaged unexpected-disconnect path so IPv6 stays blocked until the
    /// user explicitly reconnects or disables the kill switch.
    ///
    /// Mirrors the [`RouteManager::force_restore_on_drop`] contract so the
    /// two protections stay aligned: if we keep IPv4 routes deleted for
    /// the kill switch, we MUST also keep IPv6 disabled or the user
    /// silently leaks their real IP over every AAAA-capable destination.
    force_restore_on_drop: bool,
}

impl Ipv6LeakProtection {
    /// Create a new IPv6 leak protection manager.
    pub fn new() -> Self {
        Self {
            disabled: false,
            disabled_interfaces: Vec::new(),
            force_restore_on_drop: true,
        }
    }

    /// Control whether `Drop` re-enables IPv6 on the physical interfaces.
    ///
    /// Pass `false` when the tunnel is tearing down into a kill-switch-
    /// engaged state so that physical-interface IPv6 is NOT restored — any
    /// AAAA-capable traffic would otherwise leave the machine with the
    /// real user IP while IPv4 is (correctly) blocked by the route-based
    /// kill switch.
    pub fn set_force_restore_on_drop(&mut self, value: bool) {
        self.force_restore_on_drop = value;
    }

    /// Disable IPv6 on all network interfaces to prevent leaks.
    ///
    /// This ensures all traffic goes through the IPv4 VPN tunnel.
    pub fn disable_ipv6(&mut self) -> io::Result<()> {
        if self.disabled {
            return Ok(());
        }

        info!("Disabling IPv6 to prevent leaks");

        // Get all interfaces
        let interfaces = self.get_ipv6_interfaces();

        for interface in interfaces {
            // Disable IPv6 on this interface
            let result = run_command_with_timeout(
                "netsh",
                &[
                    "interface",
                    "ipv6",
                    "set",
                    "interface",
                    &interface,
                    "disabled",
                ],
                COMMAND_TIMEOUT,
            );

            match result {
                Ok(output) if output.status.success() => {
                    debug!("Disabled IPv6 on interface: {}", interface);
                    self.disabled_interfaces.push(interface);
                }
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    debug!("Failed to disable IPv6 on {}: {}", interface, stderr.trim());
                }
                Err(e) => {
                    debug!("Failed to disable IPv6 on {}: {}", interface, e);
                }
            }
        }

        self.disabled = true;
        info!(
            "IPv6 disabled on {} interfaces",
            self.disabled_interfaces.len()
        );

        Ok(())
    }

    /// Re-enable IPv6 on all interfaces that were disabled.
    pub fn enable_ipv6(&mut self) -> io::Result<()> {
        if !self.disabled {
            return Ok(());
        }

        info!("Re-enabling IPv6");

        for interface in &self.disabled_interfaces {
            let result = run_command_with_timeout(
                "netsh",
                &[
                    "interface",
                    "ipv6",
                    "set",
                    "interface",
                    interface,
                    "enabled",
                ],
                COMMAND_TIMEOUT,
            );

            if let Err(e) = result {
                warn!("Failed to re-enable IPv6 on {}: {}", interface, e);
            } else {
                debug!("Re-enabled IPv6 on interface: {}", interface);
            }
        }

        self.disabled_interfaces.clear();
        self.disabled = false;

        info!("IPv6 re-enabled");
        Ok(())
    }

    /// Check if IPv6 is currently disabled.
    pub fn is_disabled(&self) -> bool {
        self.disabled
    }

    /// Get all interfaces that support IPv6.
    fn get_ipv6_interfaces(&self) -> Vec<String> {
        let output = run_command_with_timeout(
            "netsh",
            &["interface", "ipv6", "show", "interfaces"],
            COMMAND_TIMEOUT,
        );

        let mut interfaces = Vec::new();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().skip(3) {
                // Skip header lines
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 {
                    // Format: Idx Met MTU State Name
                    let name = parts[4..].join(" ");
                    // Exclude loopback and VPN interfaces
                    if !name.contains("Loopback")
                        && !name.contains("HPN")
                        && !name.contains("WireGuard")
                        && !name.contains("TAP")
                        && !name.contains("TUN")
                        && parts[3] == "connected"
                    // Only disable on connected interfaces
                    {
                        interfaces.push(name);
                    }
                }
            }
        }

        interfaces
    }
}

impl Default for Ipv6LeakProtection {
    fn default() -> Self {
        Self::new()
    }
}

impl Ipv6LeakProtection {
    /// Decide whether `Drop` should call `enable_ipv6` to restore the
    /// physical-interface state.
    ///
    /// Extracted from the [`Drop`] impl so it can be unit-tested without
    /// spawning real `netsh` subprocesses. The mapping is:
    ///
    /// * `force_restore_on_drop == true` AND `disabled == true` → restore.
    /// * `force_restore_on_drop == true` AND `disabled == false` → no-op
    ///   (we never disabled anything).
    /// * `force_restore_on_drop == false` → keep IPv6 disabled regardless
    ///   of `disabled`, since a kill-switch-engaged disconnect explicitly
    ///   wants the physical-interface block to persist past `Drop`.
    fn should_restore_ipv6_on_drop(&self) -> bool {
        self.force_restore_on_drop && self.disabled
    }
}

impl Drop for Ipv6LeakProtection {
    fn drop(&mut self) {
        // Respect the `force_restore_on_drop` flag: when the caller has
        // signalled that the tunnel is tearing down into a kill-switch-
        // engaged state, we MUST NOT re-enable IPv6 — doing so would
        // silently leak the user's real IP over every AAAA-capable
        // destination while IPv4 is (correctly) blocked by the route
        // kill switch. The user can recover by reconnecting or
        // explicitly disabling the kill switch; either path disposes
        // of this instance with `force_restore_on_drop = true` again.
        if self.should_restore_ipv6_on_drop() {
            let _ = self.enable_ipv6();
        } else if !self.force_restore_on_drop && self.disabled {
            tracing::info!(
                "Ipv6LeakProtection dropped with force_restore_on_drop=false \
                 ({} interfaces kept disabled for kill-switch safety)",
                self.disabled_interfaces.len()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Ipv6LeakProtection;

    #[test]
    fn force_restore_on_drop_defaults_to_true() {
        let prot = Ipv6LeakProtection::new();
        assert!(
            prot.force_restore_on_drop,
            "default must restore on drop so an unguarded code path \
             never strands IPv6 in the disabled state"
        );
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
        // Fresh instance: disabled=false, restore=true → no-op
        let prot = Ipv6LeakProtection::new();
        assert!(!prot.should_restore_ipv6_on_drop());
    }

    #[test]
    fn drop_decision_disabled_true_default_restore() {
        // The normal path: disable_ipv6() ran, drop should restore.
        let mut prot = Ipv6LeakProtection::new();
        prot.disabled = true;
        assert!(prot.should_restore_ipv6_on_drop());
    }

    #[test]
    fn drop_decision_disabled_true_kill_switch_engaged() {
        // The kill-switch-engaged path: disable_ipv6() ran but caller
        // told us NOT to restore. WIN-KS-1 regression guard.
        let mut prot = Ipv6LeakProtection::new();
        prot.disabled = true;
        prot.set_force_restore_on_drop(false);
        assert!(
            !prot.should_restore_ipv6_on_drop(),
            "WIN-KS-1: when force_restore_on_drop=false, Drop must NOT \
             re-enable IPv6 even though it was disabled — otherwise the \
             user's real IP leaks via AAAA while IPv4 is route-blocked"
        );
    }

    #[test]
    fn drop_decision_disabled_false_force_restore_false() {
        // Edge case: never disabled, restore flag flipped → still no-op.
        let mut prot = Ipv6LeakProtection::new();
        prot.set_force_restore_on_drop(false);
        assert!(!prot.should_restore_ipv6_on_drop());
    }
}
