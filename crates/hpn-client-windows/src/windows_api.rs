//! Native Windows API wrappers for network management.
//!
//! Provides safe Rust wrappers around Windows IP Helper APIs for:
//! - Route management (IPv4/IPv6)
//! - Interface management
//! - DNS configuration
//!
//! This replaces the previous implementation that relied on spawning
//! `route.exe` and `netsh.exe` processes, providing better performance
//! and reliability.

#![allow(unsafe_code)]

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use thiserror::Error;
use tracing::{debug, info, warn};

use windows::Win32::Foundation::ERROR_NOT_FOUND;
use windows::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable, GAA_FLAG_INCLUDE_PREFIX,
    GetAdaptersAddresses, GetBestRoute2, GetIfTable2, GetIpForwardTable2, GetIpInterfaceEntry,
    IP_ADAPTER_ADDRESSES_LH, MIB_IF_ROW2, MIB_IF_TABLE2, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
    MIB_IPINTERFACE_ROW, SetIpInterfaceEntry,
};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::Networking::WinSock::{
    ADDRESS_FAMILY, AF_INET, AF_INET6, AF_UNSPEC, IN_ADDR, IN6_ADDR, NL_ROUTE_PROTOCOL,
    SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET,
};
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_MULTI_SZ, REG_SZ, REG_VALUE_TYPE,
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
};

/// Error type for Windows API operations.
#[derive(Debug, Error)]
pub enum WindowsApiError {
    /// Windows API returned an error.
    #[error("Windows API error: {0} (code: {1})")]
    Api(String, i32),

    /// Interface not found.
    #[error("interface not found: {0}")]
    InterfaceNotFound(String),

    /// Route not found.
    #[error("route not found")]
    RouteNotFound,

    /// Permission denied - requires administrator.
    #[error("permission denied - run as administrator")]
    PermissionDenied,

    /// Invalid parameter.
    #[error("invalid parameter: {0}")]
    InvalidParameter(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Registry error.
    #[error("registry error: {0}")]
    Registry(String),

    /// DNS configuration error.
    #[error("DNS error: {0}")]
    Dns(String),
}

/// RAII wrapper for Windows registry key handles.
/// Automatically closes the key when dropped.
struct RegistryKey(HKEY);

impl RegistryKey {
    /// Get the raw HKEY handle.
    fn as_hkey(&self) -> HKEY {
        self.0
    }
}

impl Drop for RegistryKey {
    fn drop(&mut self) {
        // SAFETY: self.0 is a valid HKEY that was opened with RegOpenKeyExW
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}

impl From<windows::core::Error> for WindowsApiError {
    fn from(e: windows::core::Error) -> Self {
        let code = e.code().0;
        // Check for common error codes
        if code == 5 {
            // ERROR_ACCESS_DENIED
            WindowsApiError::PermissionDenied
        } else if code == 2 || code == ERROR_NOT_FOUND.0 as i32 {
            // ERROR_FILE_NOT_FOUND or ERROR_NOT_FOUND
            WindowsApiError::RouteNotFound
        } else {
            WindowsApiError::Api(e.message().to_string(), code)
        }
    }
}

/// A route entry for IPv4 or IPv6.
#[derive(Debug, Clone)]
pub struct RouteEntry {
    /// Destination address.
    pub destination: IpAddr,
    /// Prefix length (e.g., 24 for /24, 0 for default route).
    pub prefix_length: u8,
    /// Next hop gateway address.
    pub gateway: IpAddr,
    /// Interface index.
    pub interface_index: u32,
    /// Interface LUID (for internal use).
    pub interface_luid: u64,
    /// Route metric.
    pub metric: u32,
}

impl RouteEntry {
    /// Create a new IPv4 route entry.
    pub fn new_v4(
        destination: Ipv4Addr,
        prefix_length: u8,
        gateway: Ipv4Addr,
        interface_index: u32,
    ) -> Self {
        Self {
            destination: IpAddr::V4(destination),
            prefix_length,
            gateway: IpAddr::V4(gateway),
            interface_index,
            interface_luid: 0,
            metric: 1,
        }
    }

    /// Create a new IPv6 route entry.
    pub fn new_v6(
        destination: Ipv6Addr,
        prefix_length: u8,
        gateway: Ipv6Addr,
        interface_index: u32,
    ) -> Self {
        Self {
            destination: IpAddr::V6(destination),
            prefix_length,
            gateway: IpAddr::V6(gateway),
            interface_index,
            interface_luid: 0,
            metric: 1,
        }
    }

    /// Set the route metric.
    pub fn with_metric(mut self, metric: u32) -> Self {
        self.metric = metric;
        self
    }

    /// Set the interface LUID.
    pub fn with_luid(mut self, luid: u64) -> Self {
        self.interface_luid = luid;
        self
    }

    /// Check if this is an IPv4 route.
    pub fn is_v4(&self) -> bool {
        matches!(self.destination, IpAddr::V4(_))
    }

    /// Check if this is an IPv6 route.
    pub fn is_v6(&self) -> bool {
        matches!(self.destination, IpAddr::V6(_))
    }

    /// Check if this is a default route (0.0.0.0/0 or ::/0).
    pub fn is_default(&self) -> bool {
        self.prefix_length == 0
            && match self.destination {
                IpAddr::V4(addr) => addr == Ipv4Addr::UNSPECIFIED,
                IpAddr::V6(addr) => addr == Ipv6Addr::UNSPECIFIED,
            }
    }
}

/// Network interface information.
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    /// Interface index.
    pub index: u32,
    /// Interface LUID.
    pub luid: u64,
    /// Interface alias (friendly name).
    pub alias: String,
    /// Interface description.
    pub description: String,
    /// Physical address (MAC).
    pub physical_address: [u8; 6],
    /// Interface type.
    pub if_type: u32,
    /// Is the interface connected?
    pub is_connected: bool,
}

// ============================================================================
// Route Management
// ============================================================================

/// Add a route to the system routing table.
///
/// Uses `CreateIpForwardEntry2` for both IPv4 and IPv6 routes.
pub fn add_route(entry: &RouteEntry) -> Result<(), WindowsApiError> {
    let mut row = create_forward_row(entry)?;

    // Set route properties
    row.ValidLifetime = u32::MAX;
    row.PreferredLifetime = u32::MAX;
    row.Metric = entry.metric;
    row.Protocol = NL_ROUTE_PROTOCOL(3); // MIB_IPPROTO_NETMGMT

    debug!(
        "Adding route: {}/{} via {} (IF={}, metric={})",
        entry.destination, entry.prefix_length, entry.gateway, entry.interface_index, entry.metric
    );

    // SAFETY: We've initialized the MIB_IPFORWARD_ROW2 structure correctly
    let result = unsafe { CreateIpForwardEntry2(&row) };
    if result.is_err() {
        return Err(WindowsApiError::Api(
            "CreateIpForwardEntry2 failed".to_string(),
            result.0 as i32,
        ));
    }

    info!(
        "Added route: {}/{} via {}",
        entry.destination, entry.prefix_length, entry.gateway
    );
    Ok(())
}

/// Delete a route from the system routing table.
///
/// Uses `DeleteIpForwardEntry2` for both IPv4 and IPv6 routes.
pub fn delete_route(entry: &RouteEntry) -> Result<(), WindowsApiError> {
    let row = create_forward_row(entry)?;

    debug!(
        "Deleting route: {}/{} via {} (IF={})",
        entry.destination, entry.prefix_length, entry.gateway, entry.interface_index
    );

    // SAFETY: We've initialized the MIB_IPFORWARD_ROW2 structure correctly
    let result = unsafe { DeleteIpForwardEntry2(&row) };
    if result.is_err() {
        return Err(WindowsApiError::Api(
            "DeleteIpForwardEntry2 failed".to_string(),
            result.0 as i32,
        ));
    }

    info!(
        "Deleted route: {}/{} via {}",
        entry.destination, entry.prefix_length, entry.gateway
    );
    Ok(())
}

/// Get all routes from the system routing table.
///
/// Uses `GetIpForwardTable2` to retrieve all routes.
pub fn get_routes(family: Option<u16>) -> Result<Vec<RouteEntry>, WindowsApiError> {
    let af = ADDRESS_FAMILY(family.unwrap_or(AF_UNSPEC.0));
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();

    // SAFETY: GetIpForwardTable2 allocates and returns a table pointer
    let result = unsafe { GetIpForwardTable2(af, &mut table) };
    if result.is_err() {
        return Err(WindowsApiError::Api(
            "GetIpForwardTable2 failed".to_string(),
            result.0 as i32,
        ));
    }

    if table.is_null() {
        return Ok(Vec::new());
    }

    // SAFETY: table is valid and we free it at the end
    let result = unsafe {
        let num_entries = (*table).NumEntries as usize;
        let mut routes = Vec::with_capacity(num_entries);

        for i in 0..num_entries {
            // SAFETY: Windows API uses C flexible array member pattern where Table
            // is declared as [T; 1] but actually contains NumEntries elements.
            // We must use pointer arithmetic instead of array indexing.
            let row = &*(*table).Table.as_ptr().add(i);
            if let Some(entry) = parse_forward_row(row) {
                routes.push(entry);
            }
        }

        routes
    };

    // Free the table
    // SAFETY: table was allocated by GetIpForwardTable2
    unsafe {
        FreeMibTable(table.cast());
    }

    Ok(result)
}

/// Get the default gateway for the system.
///
/// Returns the first default route (0.0.0.0/0) found.
pub fn get_default_gateway() -> Result<Option<RouteEntry>, WindowsApiError> {
    let routes = get_routes(Some(AF_INET.0))?;

    for route in routes {
        if route.is_default() {
            return Ok(Some(route));
        }
    }

    Ok(None)
}

/// Get the default IPv6 gateway for the system.
pub fn get_default_gateway_v6() -> Result<Option<RouteEntry>, WindowsApiError> {
    let routes = get_routes(Some(AF_INET6.0))?;

    for route in routes {
        if route.is_default() {
            return Ok(Some(route));
        }
    }

    Ok(None)
}

/// Get the best route for a destination address.
///
/// Uses `GetBestRoute2` to find the optimal route.
pub fn get_best_route(destination: IpAddr) -> Result<RouteEntry, WindowsApiError> {
    let mut best_route: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    let mut best_source: SOCKADDR_INET = unsafe { std::mem::zeroed() };

    let dest_addr = ip_to_sockaddr_inet(&destination);

    // SAFETY: All structures are properly initialized
    let result = unsafe {
        GetBestRoute2(
            None,
            0,
            None,
            &dest_addr,
            0,
            &mut best_route,
            &mut best_source,
        )
    };
    if result.is_err() {
        return Err(WindowsApiError::Api(
            "GetBestRoute2 failed".to_string(),
            result.0 as i32,
        ));
    }

    parse_forward_row(&best_route).ok_or(WindowsApiError::RouteNotFound)
}

// ============================================================================
// Interface Management
// ============================================================================

/// Get the interface index by name (alias).
pub fn get_interface_index(name: &str) -> Result<u32, WindowsApiError> {
    let interfaces = get_interfaces()?;

    for iface in interfaces {
        if iface.alias == name {
            return Ok(iface.index);
        }
    }

    Err(WindowsApiError::InterfaceNotFound(name.to_string()))
}

/// Get the interface LUID by name (alias).
pub fn get_interface_luid(name: &str) -> Result<u64, WindowsApiError> {
    let interfaces = get_interfaces()?;

    for iface in interfaces {
        if iface.alias == name {
            return Ok(iface.luid);
        }
    }

    Err(WindowsApiError::InterfaceNotFound(name.to_string()))
}

/// Get all network interfaces.
pub fn get_interfaces() -> Result<Vec<InterfaceInfo>, WindowsApiError> {
    let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();

    // SAFETY: GetIfTable2 allocates and returns a table pointer
    let result = unsafe { GetIfTable2(&mut table) };
    if result.is_err() {
        return Err(WindowsApiError::Api(
            "GetIfTable2 failed".to_string(),
            result.0 as i32,
        ));
    }

    if table.is_null() {
        return Ok(Vec::new());
    }

    // SAFETY: table is valid and we free it at the end
    let result = unsafe {
        let num_entries = (*table).NumEntries as usize;
        let mut interfaces = Vec::with_capacity(num_entries);

        for i in 0..num_entries {
            // SAFETY: Windows API uses C flexible array member pattern where Table
            // is declared as [T; 1] but actually contains NumEntries elements.
            // We must use pointer arithmetic instead of array indexing.
            let row = &*(*table).Table.as_ptr().add(i);
            if let Some(info) = parse_interface_row(row) {
                interfaces.push(info);
            }
        }

        interfaces
    };

    // Free the table
    // SAFETY: table was allocated by GetIfTable2
    unsafe {
        FreeMibTable(table.cast());
    }

    Ok(result)
}

/// Get physical (non-virtual) network interfaces.
///
/// Excludes loopback, VPN adapters, and other virtual interfaces.
pub fn get_physical_interfaces() -> Result<Vec<InterfaceInfo>, WindowsApiError> {
    let interfaces = get_interfaces()?;

    let physical: Vec<_> = interfaces
        .into_iter()
        .filter(|iface| {
            // Exclude loopback (type 24)
            if iface.if_type == 24 {
                return false;
            }
            // Exclude common VPN/virtual adapter names
            let name_lower = iface.alias.to_lowercase();

            // Exclude virtual sub-interfaces (WFP filters, packet drivers, QoS, etc.)
            // These inherit DNS from parent interface and don't have their own configuration
            if name_lower.contains("-wfp")
                || name_lower.contains("-npcap")
                || name_lower.contains("-qos")
                || name_lower.contains("packet driver")
                || name_lower.contains("lightweight filter")
                || name_lower.contains("kernel debugger")
            {
                return false;
            }

            !name_lower.contains("loopback")
                && !name_lower.contains("hpn")
                && !name_lower.contains("wireguard")
                && !name_lower.contains("tap")
                && !name_lower.contains("tun")
                && !name_lower.contains("wintun")
        })
        .collect();

    Ok(physical)
}

/// Get interface info by index.
pub fn get_interface_by_index(index: u32) -> Result<InterfaceInfo, WindowsApiError> {
    let interfaces = get_interfaces()?;

    for iface in interfaces {
        if iface.index == index {
            return Ok(iface);
        }
    }

    Err(WindowsApiError::InterfaceNotFound(format!(
        "index {}",
        index
    )))
}

/// Get the IPv4 address assigned to an interface.
///
/// Returns `None` if the interface exists but has no IPv4 address,
/// or an error if the interface doesn't exist.
pub fn get_interface_ip(interface_name: &str) -> Result<Option<Ipv4Addr>, WindowsApiError> {
    // Get adapters using GetAdaptersAddresses
    let mut buffer_size: u32 = 15000;
    let mut buffer: Vec<u8> = vec![0; buffer_size as usize];

    // SAFETY: We're providing a properly sized buffer
    let result = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC.0 as u32,
            GAA_FLAG_INCLUDE_PREFIX,
            None,
            Some(buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
            &mut buffer_size,
        )
    };

    if result != 0 {
        // Buffer too small, retry with the returned size
        buffer.resize(buffer_size as usize, 0);
        let result = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                GAA_FLAG_INCLUDE_PREFIX,
                None,
                Some(buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut buffer_size,
            )
        };
        if result != 0 {
            return Err(WindowsApiError::Api(
                "GetAdaptersAddresses failed".to_string(),
                result as i32,
            ));
        }
    }

    // Parse the linked list of adapters
    // SAFETY: The buffer contains valid adapter data
    unsafe {
        let mut adapter = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;

        while !adapter.is_null() {
            let friendly_name = {
                let ptr = (*adapter).FriendlyName.0;
                if ptr.is_null() {
                    String::new()
                } else {
                    let len = (0..).take_while(|&i| *ptr.add(i) != 0).count();
                    String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
                }
            };

            if friendly_name == interface_name {
                // Found the interface! Now get its first IPv4 address
                let mut unicast_addr = (*adapter).FirstUnicastAddress;

                while !unicast_addr.is_null() {
                    let addr_ptr = (*unicast_addr).Address.lpSockaddr;
                    if !addr_ptr.is_null() {
                        let addr_family = (*addr_ptr).sa_family;

                        // Check if it's IPv4 (AF_INET = 2)
                        if addr_family == AF_INET {
                            // Cast to sockaddr_in to get IPv4 address
                            let sockaddr_in = &*(addr_ptr
                                as *const windows::Win32::Networking::WinSock::SOCKADDR_IN);
                            let ip_bytes = sockaddr_in.sin_addr.S_un.S_un_b;
                            let ipv4 = Ipv4Addr::new(
                                ip_bytes.s_b1,
                                ip_bytes.s_b2,
                                ip_bytes.s_b3,
                                ip_bytes.s_b4,
                            );
                            return Ok(Some(ipv4));
                        }
                    }

                    unicast_addr = (*unicast_addr).Next;
                }

                // Interface found but no IPv4 address
                return Ok(None);
            }

            adapter = (*adapter).Next;
        }
    }

    Err(WindowsApiError::InterfaceNotFound(
        interface_name.to_string(),
    ))
}

// ============================================================================
// DNS Management
// ============================================================================

/// Flush the system DNS cache.
///
/// Equivalent to `ipconfig /flushdns`.
pub fn flush_dns_cache() -> Result<(), WindowsApiError> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let output = Command::new("ipconfig")
        .args(["/flushdns"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| WindowsApiError::Io(e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("DNS cache flush may have failed: {}", stderr);
    }

    debug!("Flushed DNS cache");
    Ok(())
}

/// Set the interface metric to influence route selection.
///
/// Lower metric = higher priority.
pub fn set_interface_metric(
    interface_index: u32,
    metric: u32,
    is_ipv6: bool,
) -> Result<(), WindowsApiError> {
    let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
    row.InterfaceIndex = interface_index;
    row.Family = if is_ipv6 { AF_INET6 } else { AF_INET };

    // Get current settings
    // SAFETY: row is properly initialized
    let result = unsafe { GetIpInterfaceEntry(&mut row) };
    if result.is_err() {
        return Err(WindowsApiError::Api(
            "GetIpInterfaceEntry failed".to_string(),
            result.0 as i32,
        ));
    }

    // Update metric
    row.Metric = metric;
    row.UseAutomaticMetric = false.into();

    // Apply changes
    // SAFETY: row is properly initialized and retrieved
    let result = unsafe { SetIpInterfaceEntry(&mut row) };
    if result.is_err() {
        return Err(WindowsApiError::Api(
            "SetIpInterfaceEntry failed".to_string(),
            result.0 as i32,
        ));
    }

    debug!(
        "Set interface {} metric to {} (IPv{})",
        interface_index,
        metric,
        if is_ipv6 { "6" } else { "4" }
    );
    Ok(())
}

/// Set the interface MTU (Maximum Transmission Unit).
///
/// This is critical for VPN performance - incorrect MTU causes:
/// - Small packets work (DNS, ping)
/// - Large packets fail (downloads, speedtest, streaming)
///
/// # Arguments
/// * `interface_index` - Interface index from GetIfTable2
/// * `mtu` - MTU in bytes (typically 1420 for VPN tunnels)
/// * `is_ipv6` - Set IPv6 MTU (false for IPv4)
pub fn set_interface_mtu(
    interface_index: u32,
    mtu: u32,
    is_ipv6: bool,
) -> Result<(), WindowsApiError> {
    let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
    row.InterfaceIndex = interface_index;
    row.Family = if is_ipv6 { AF_INET6 } else { AF_INET };

    // Get current settings
    // SAFETY: row is properly initialized
    let result = unsafe { GetIpInterfaceEntry(&mut row) };
    if result.is_err() {
        return Err(WindowsApiError::Api(
            "GetIpInterfaceEntry failed".to_string(),
            result.0 as i32,
        ));
    }

    // CRITICAL FIX: Patch SitePrefixLength bug in Windows
    // GetIpInterfaceEntry returns invalid SitePrefixLength (e.g., 255) for some interfaces
    // including Wintun. Passing this back to SetIpInterfaceEntry causes ERROR_INVALID_PARAMETER.
    // This is a well-known Windows bug affecting TUN adapters.
    if is_ipv6 {
        if row.SitePrefixLength > 128 {
            row.SitePrefixLength = 128;
        }
    } else {
        // For IPv4, SitePrefixLength > 32 is invalid
        if row.SitePrefixLength > 32 {
            row.SitePrefixLength = 0;
        }
    }

    // Update MTU
    row.NlMtu = mtu;

    // Apply changes
    // SAFETY: row is properly initialized and retrieved
    let result = unsafe { SetIpInterfaceEntry(&mut row) };
    if result.is_err() {
        return Err(WindowsApiError::Api(
            "SetIpInterfaceEntry failed".to_string(),
            result.0 as i32,
        ));
    }

    info!(
        "Set interface {} MTU to {} bytes (IPv{})",
        interface_index,
        mtu,
        if is_ipv6 { "6" } else { "4" }
    );
    Ok(())
}

/// Set interface MTU using netsh (fallback method).
///
/// This is a fallback for when SetIpInterfaceEntry fails (error 87 on some adapters).
/// Uses netsh which has broader compatibility with virtual adapters like Wintun.
pub fn set_interface_mtu_netsh(interface_name: &str, mtu: u32) -> Result<(), WindowsApiError> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    // Use CREATE_NO_WINDOW to hide the command window
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    // Set IPv4 MTU
    let output = Command::new("netsh")
        .args([
            "interface",
            "ipv4",
            "set",
            "subinterface",
            interface_name,
            &format!("mtu={}", mtu),
            "store=persistent",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| WindowsApiError::Api(format!("failed to run netsh: {}", e), 0))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Try alternative syntax for some Windows versions
        let output2 = Command::new("netsh")
            .args([
                "interface",
                "ipv4",
                "set",
                "interface",
                interface_name,
                &format!("mtu={}", mtu),
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| WindowsApiError::Api(format!("failed to run netsh: {}", e), 0))?;

        if !output2.status.success() {
            let stderr2 = String::from_utf8_lossy(&output2.stderr);
            return Err(WindowsApiError::Api(
                format!("netsh mtu failed: {} / {}", stderr.trim(), stderr2.trim()),
                0,
            ));
        }
    }

    info!(
        "Set interface {} MTU to {} bytes via netsh",
        interface_name, mtu
    );
    Ok(())
}

/// DNS settings for an interface.
#[derive(Debug, Clone, Default)]
pub struct DnsSettings {
    /// IPv4 DNS servers.
    pub ipv4_servers: Vec<Ipv4Addr>,
    /// IPv6 DNS servers.
    pub ipv6_servers: Vec<Ipv6Addr>,
    /// Whether DHCP is used for DNS (if false, static DNS).
    pub is_dhcp: bool,
}

impl DnsSettings {
    /// Create empty DNS settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create DNS settings with IPv4 servers.
    pub fn with_ipv4(servers: Vec<Ipv4Addr>) -> Self {
        Self {
            ipv4_servers: servers,
            ipv6_servers: Vec::new(),
            is_dhcp: false,
        }
    }

    /// Create DNS settings with both IPv4 and IPv6 servers.
    pub fn with_dual_stack(ipv4: Vec<Ipv4Addr>, ipv6: Vec<Ipv6Addr>) -> Self {
        Self {
            ipv4_servers: ipv4,
            ipv6_servers: ipv6,
            is_dhcp: false,
        }
    }

    /// Check if any DNS servers are configured.
    pub fn is_empty(&self) -> bool {
        self.ipv4_servers.is_empty() && self.ipv6_servers.is_empty()
    }
}

/// Get the adapter GUID from interface name.
///
/// This is needed for registry-based DNS configuration.
pub fn get_adapter_guid(interface_name: &str) -> Result<String, WindowsApiError> {
    // Get adapters using GetAdaptersAddresses
    let mut buffer_size: u32 = 15000; // Initial size
    let mut buffer: Vec<u8> = vec![0; buffer_size as usize];

    // SAFETY: We're providing a properly sized buffer
    let result = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC.0 as u32,
            GAA_FLAG_INCLUDE_PREFIX,
            None,
            Some(buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
            &mut buffer_size,
        )
    };

    if result != 0 {
        // Buffer too small, retry with the returned size
        buffer.resize(buffer_size as usize, 0);
        let result = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                GAA_FLAG_INCLUDE_PREFIX,
                None,
                Some(buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut buffer_size,
            )
        };
        if result != 0 {
            return Err(WindowsApiError::Api(
                "GetAdaptersAddresses failed".to_string(),
                result as i32,
            ));
        }
    }

    // Parse the linked list of adapters
    // SAFETY: The buffer contains valid adapter data
    unsafe {
        let mut adapter = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;

        while !adapter.is_null() {
            let friendly_name = {
                let ptr = (*adapter).FriendlyName.0;
                if ptr.is_null() {
                    String::new()
                } else {
                    let len = (0..).take_while(|&i| *ptr.add(i) != 0).count();
                    String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
                }
            };

            if friendly_name == interface_name {
                // Found it! Get the adapter name (GUID)
                let adapter_name = std::ffi::CStr::from_ptr((*adapter).AdapterName.0 as *const i8)
                    .to_string_lossy()
                    .to_string();
                return Ok(adapter_name);
            }

            adapter = (*adapter).Next;
        }
    }

    Err(WindowsApiError::InterfaceNotFound(
        interface_name.to_string(),
    ))
}

/// Get the current DNS settings for an interface.
///
/// Reads from the Windows registry.
pub fn get_interface_dns(interface_name: &str) -> Result<DnsSettings, WindowsApiError> {
    let adapter_guid = get_adapter_guid(interface_name)?;

    // Registry path for interface DNS
    // HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}
    let key_path = format!(
        "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{}",
        adapter_guid
    );

    let mut settings = DnsSettings::default();

    // Open the registry key
    let key_path_wide: Vec<u16> = key_path.encode_utf16().chain(std::iter::once(0)).collect();
    let mut hkey_raw: HKEY = HKEY::default();

    // SAFETY: We're providing valid parameters to RegOpenKeyExW
    let result = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            windows::core::PCWSTR(key_path_wide.as_ptr()),
            0,
            KEY_READ,
            &mut hkey_raw,
        )
    };

    if result.is_err() {
        // Key doesn't exist or can't be accessed - return empty settings
        return Ok(settings);
    }

    // Use RAII wrapper to ensure key is closed on all code paths
    let hkey = RegistryKey(hkey_raw);

    // Read NameServer value (static DNS)
    if let Ok(dns_string) = read_registry_string(hkey.as_hkey(), "NameServer") {
        if !dns_string.is_empty() {
            settings.is_dhcp = false;
            for server in dns_string.split(',') {
                let server = server.trim();
                if let Ok(ipv4) = server.parse::<Ipv4Addr>() {
                    settings.ipv4_servers.push(ipv4);
                }
            }
        }
    }

    // If no static DNS, check DHCP DNS
    if settings.ipv4_servers.is_empty() {
        if let Ok(dns_string) = read_registry_string(hkey.as_hkey(), "DhcpNameServer") {
            if !dns_string.is_empty() {
                settings.is_dhcp = true;
                for server in dns_string.split_whitespace() {
                    if let Ok(ipv4) = server.parse::<Ipv4Addr>() {
                        settings.ipv4_servers.push(ipv4);
                    }
                }
            }
        }
    }

    // hkey is automatically closed when it goes out of scope (Drop implementation)

    // Get IPv6 DNS from Tcpip6 registry
    let key_path_v6 = format!(
        "SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\{}",
        adapter_guid
    );
    let key_path_v6_wide: Vec<u16> = key_path_v6
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut hkey_v6_raw: HKEY = HKEY::default();

    let result_v6 = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            windows::core::PCWSTR(key_path_v6_wide.as_ptr()),
            0,
            KEY_READ,
            &mut hkey_v6_raw,
        )
    };

    if result_v6.is_ok() {
        // Use RAII wrapper for automatic cleanup
        let hkey_v6 = RegistryKey(hkey_v6_raw);
        if let Ok(dns_string) = read_registry_string(hkey_v6.as_hkey(), "NameServer") {
            if !dns_string.is_empty() {
                for server in dns_string.split(',') {
                    let server = server.trim();
                    if let Ok(ipv6) = server.parse::<Ipv6Addr>() {
                        settings.ipv6_servers.push(ipv6);
                    }
                }
            }
        }
        // hkey_v6 automatically closed when it goes out of scope
    }

    debug!(
        "Got DNS for {}: {:?} (DHCP={})",
        interface_name, settings.ipv4_servers, settings.is_dhcp
    );
    Ok(settings)
}

/// Set the DNS servers for an interface.
///
/// Uses the Windows registry to configure DNS.
/// Requires administrator privileges.
pub fn set_interface_dns(
    interface_name: &str,
    settings: &DnsSettings,
) -> Result<(), WindowsApiError> {
    let adapter_guid = get_adapter_guid(interface_name)?;

    // Set IPv4 DNS
    if !settings.ipv4_servers.is_empty() {
        let key_path = format!(
            "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{}",
            adapter_guid
        );
        let key_path_wide: Vec<u16> = key_path.encode_utf16().chain(std::iter::once(0)).collect();
        let mut hkey: HKEY = HKEY::default();

        let result = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                windows::core::PCWSTR(key_path_wide.as_ptr()),
                0,
                KEY_WRITE,
                &mut hkey,
            )
        };

        if result.is_err() {
            return Err(WindowsApiError::Registry(format!(
                "Failed to open registry key for {}: {:?}",
                interface_name, result
            )));
        }

        // Wrap in RAII - automatic cleanup on error paths
        let hkey = RegistryKey(hkey);

        // Format DNS servers as comma-separated string
        let dns_string = settings
            .ipv4_servers
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(",");

        // Write NameServer value (hkey automatically closed on error via Drop)
        write_registry_string(hkey.as_hkey(), "NameServer", &dns_string)?;

        info!("Set IPv4 DNS for {}: {}", interface_name, dns_string);
    }

    // Set IPv6 DNS
    if !settings.ipv6_servers.is_empty() {
        let key_path_v6 = format!(
            "SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\{}",
            adapter_guid
        );
        let key_path_v6_wide: Vec<u16> = key_path_v6
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut hkey_v6: HKEY = HKEY::default();

        let result_v6 = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                windows::core::PCWSTR(key_path_v6_wide.as_ptr()),
                0,
                KEY_WRITE,
                &mut hkey_v6,
            )
        };

        if result_v6.is_ok() {
            // Wrap in RAII - automatic cleanup on error paths
            let hkey_v6 = RegistryKey(hkey_v6);

            let dns_string_v6 = settings
                .ipv6_servers
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(",");

            // hkey_v6 automatically closed on error via Drop
            write_registry_string(hkey_v6.as_hkey(), "NameServer", &dns_string_v6)?;

            info!("Set IPv6 DNS for {}: {}", interface_name, dns_string_v6);
        }
    }

    // Notify the system of the DNS change
    notify_dns_change()?;

    Ok(())
}

/// Clear the DNS servers for an interface (set to DHCP).
///
/// Uses the Windows registry.
/// Requires administrator privileges.
pub fn clear_interface_dns(interface_name: &str) -> Result<(), WindowsApiError> {
    let adapter_guid = get_adapter_guid(interface_name)?;

    // Clear IPv4 DNS
    let key_path = format!(
        "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{}",
        adapter_guid
    );
    let key_path_wide: Vec<u16> = key_path.encode_utf16().chain(std::iter::once(0)).collect();
    let mut hkey_raw: HKEY = HKEY::default();

    let result = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            windows::core::PCWSTR(key_path_wide.as_ptr()),
            0,
            KEY_WRITE,
            &mut hkey_raw,
        )
    };

    if result.is_ok() {
        // Use RAII wrapper to ensure key is closed even if write_registry_string fails
        let hkey = RegistryKey(hkey_raw);
        // Set NameServer to empty string to use DHCP
        write_registry_string(hkey.as_hkey(), "NameServer", "")?;
        debug!("Cleared IPv4 DNS for {}", interface_name);
        // hkey automatically closed when it goes out of scope
    }

    // Clear IPv6 DNS
    let key_path_v6 = format!(
        "SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\{}",
        adapter_guid
    );
    let key_path_v6_wide: Vec<u16> = key_path_v6
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut hkey_v6_raw: HKEY = HKEY::default();

    let result_v6 = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            windows::core::PCWSTR(key_path_v6_wide.as_ptr()),
            0,
            KEY_WRITE,
            &mut hkey_v6_raw,
        )
    };

    if result_v6.is_ok() {
        // Use RAII wrapper for automatic cleanup
        let hkey_v6 = RegistryKey(hkey_v6_raw);
        write_registry_string(hkey_v6.as_hkey(), "NameServer", "")?;
        debug!("Cleared IPv6 DNS for {}", interface_name);
        // hkey_v6 automatically closed when it goes out of scope
    }

    // Notify the system of the DNS change
    notify_dns_change()?;

    info!("Cleared DNS for {}", interface_name);
    Ok(())
}

/// Notify the system that DNS settings have changed.
///
/// This causes Windows to re-read the DNS settings from the registry.
fn notify_dns_change() -> Result<(), WindowsApiError> {
    // Flush DNS cache
    flush_dns_cache()?;

    // The most reliable way to notify Windows of DNS changes is to
    // disable and re-enable the network adapter, but that's disruptive.
    // Instead, we rely on the DNS cache flush and let Windows pick up
    // the changes on the next DNS query.
    //
    // For more immediate effect, we could call DnsFlushResolverCache
    // from dnsapi.dll, but ipconfig /flushdns should be sufficient.

    Ok(())
}

/// Maximum registry string size to prevent excessive allocation.
const MAX_REGISTRY_STRING_SIZE: u32 = 64 * 1024; // 64KB

/// Maximum retries for registry read TOCTOU race.
const MAX_REGISTRY_RETRIES: u32 = 3;

/// Read a string value from the registry.
fn read_registry_string(hkey: HKEY, value_name: &str) -> Result<String, WindowsApiError> {
    let value_name_wide: Vec<u16> = value_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // Retry loop to handle TOCTOU race where value size changes between queries
    for attempt in 0..MAX_REGISTRY_RETRIES {
        let mut data_type: REG_VALUE_TYPE = REG_VALUE_TYPE(0);
        let mut data_size: u32 = 0;

        // First call to get the size
        let result = unsafe {
            RegQueryValueExW(
                hkey,
                windows::core::PCWSTR(value_name_wide.as_ptr()),
                None,
                Some(&mut data_type),
                None,
                Some(&mut data_size),
            )
        };

        if result.is_err() || data_size == 0 {
            return Ok(String::new());
        }

        // Validate size to prevent excessive allocation
        if data_size > MAX_REGISTRY_STRING_SIZE {
            return Err(WindowsApiError::Registry(format!(
                "Registry value {} too large: {} bytes (max {})",
                value_name, data_size, MAX_REGISTRY_STRING_SIZE
            )));
        }

        // Allocate buffer with extra space to detect growth
        let buffer_size = data_size.saturating_add(256); // Extra headroom
        let mut buffer: Vec<u8> = vec![0; buffer_size as usize];
        let mut actual_size = buffer_size;

        let result = unsafe {
            RegQueryValueExW(
                hkey,
                windows::core::PCWSTR(value_name_wide.as_ptr()),
                None,
                Some(&mut data_type),
                Some(buffer.as_mut_ptr()),
                Some(&mut actual_size),
            )
        };

        if result.is_ok() {
            // Success - truncate buffer to actual size
            buffer.truncate(actual_size as usize);
            return convert_registry_buffer_to_string(&buffer, data_type);
        }

        // Check if value grew between queries (ERROR_MORE_DATA = 234)
        if result.0 as u32 == 234 && attempt + 1 < MAX_REGISTRY_RETRIES {
            // Value grew - retry with larger buffer
            tracing::debug!(
                "Registry value {} grew between queries (attempt {}), retrying",
                value_name,
                attempt + 1
            );
            continue;
        }

        return Err(WindowsApiError::Registry(format!(
            "Failed to read registry value {}: {:?}",
            value_name, result
        )));
    }

    Err(WindowsApiError::Registry(format!(
        "Failed to read registry value {} after {} retries",
        value_name, MAX_REGISTRY_RETRIES
    )))
}

/// Convert registry buffer to string based on type.
fn convert_registry_buffer_to_string(
    buffer: &[u8],
    data_type: REG_VALUE_TYPE,
) -> Result<String, WindowsApiError> {
    if data_type == REG_SZ || data_type == REG_MULTI_SZ {
        // REG_SZ is UTF-16 null-terminated string
        let wide: Vec<u16> = buffer
            .chunks(2)
            .filter_map(|chunk| {
                if chunk.len() == 2 {
                    Some(u16::from_le_bytes([chunk[0], chunk[1]]))
                } else {
                    None
                }
            })
            .take_while(|&c| c != 0)
            .collect();
        Ok(String::from_utf16_lossy(&wide))
    } else {
        // Try to interpret as UTF-8
        Ok(String::from_utf8_lossy(buffer)
            .trim_end_matches('\0')
            .to_string())
    }
}

/// Write a string value to the registry.
fn write_registry_string(hkey: HKEY, value_name: &str, value: &str) -> Result<(), WindowsApiError> {
    let value_name_wide: Vec<u16> = value_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let value_wide: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();

    // Write as REG_SZ (null-terminated UTF-16 string)
    let result = unsafe {
        RegSetValueExW(
            hkey,
            windows::core::PCWSTR(value_name_wide.as_ptr()),
            0,
            REG_SZ,
            Some(std::slice::from_raw_parts(
                value_wide.as_ptr() as *const u8,
                value_wide.len() * 2,
            )),
        )
    };

    if result.is_err() {
        return Err(WindowsApiError::Registry(format!(
            "Failed to write registry value {}: {:?}",
            value_name, result
        )));
    }

    Ok(())
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a MIB_IPFORWARD_ROW2 from a RouteEntry.
fn create_forward_row(entry: &RouteEntry) -> Result<MIB_IPFORWARD_ROW2, WindowsApiError> {
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };

    match entry.destination {
        IpAddr::V4(dest) => {
            row.DestinationPrefix.Prefix = ip_to_sockaddr_inet(&IpAddr::V4(dest));
            row.DestinationPrefix.PrefixLength = entry.prefix_length;

            if let IpAddr::V4(gw) = entry.gateway {
                row.NextHop = ip_to_sockaddr_inet(&IpAddr::V4(gw));
            } else {
                return Err(WindowsApiError::InvalidParameter(
                    "gateway must be IPv4 for IPv4 route".to_string(),
                ));
            }
        }
        IpAddr::V6(dest) => {
            row.DestinationPrefix.Prefix = ip_to_sockaddr_inet(&IpAddr::V6(dest));
            row.DestinationPrefix.PrefixLength = entry.prefix_length;

            if let IpAddr::V6(gw) = entry.gateway {
                row.NextHop = ip_to_sockaddr_inet(&IpAddr::V6(gw));
            } else {
                return Err(WindowsApiError::InvalidParameter(
                    "gateway must be IPv6 for IPv6 route".to_string(),
                ));
            }
        }
    }

    // Set interface - prefer LUID if available, otherwise use index
    if entry.interface_luid != 0 {
        row.InterfaceLuid = luid_from_u64(entry.interface_luid);
    } else if entry.interface_index != 0 {
        row.InterfaceIndex = entry.interface_index;
    }

    row.Metric = entry.metric;

    Ok(row)
}

/// Parse a MIB_IPFORWARD_ROW2 into a RouteEntry.
fn parse_forward_row(row: &MIB_IPFORWARD_ROW2) -> Option<RouteEntry> {
    let destination = sockaddr_inet_to_ip(&row.DestinationPrefix.Prefix)?;
    let gateway = sockaddr_inet_to_ip(&row.NextHop)?;

    Some(RouteEntry {
        destination,
        prefix_length: row.DestinationPrefix.PrefixLength,
        gateway,
        interface_index: row.InterfaceIndex,
        interface_luid: luid_to_u64(&row.InterfaceLuid),
        metric: row.Metric,
    })
}

/// Parse a MIB_IF_ROW2 into an InterfaceInfo.
fn parse_interface_row(row: &MIB_IF_ROW2) -> Option<InterfaceInfo> {
    // Get alias (friendly name)
    let alias = {
        let len = row
            .Alias
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(row.Alias.len());
        String::from_utf16_lossy(&row.Alias[..len])
    };

    // Get description
    let description = {
        let len = row
            .Description
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(row.Description.len());
        String::from_utf16_lossy(&row.Description[..len])
    };

    // Get physical address
    let mut physical_address = [0u8; 6];
    let addr_len = row.PhysicalAddressLength.min(6) as usize;
    physical_address[..addr_len].copy_from_slice(&row.PhysicalAddress[..addr_len]);

    // Check if connected (MediaConnectState == 1 means connected)
    let is_connected = row.MediaConnectState.0 == 1;

    Some(InterfaceInfo {
        index: row.InterfaceIndex,
        luid: luid_to_u64(&row.InterfaceLuid),
        alias,
        description,
        physical_address,
        if_type: row.Type,
        is_connected,
    })
}

/// Convert an IP address to SOCKADDR_INET.
fn ip_to_sockaddr_inet(ip: &IpAddr) -> SOCKADDR_INET {
    let mut addr: SOCKADDR_INET = unsafe { std::mem::zeroed() };

    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            let sin_addr = IN_ADDR {
                S_un: windows::Win32::Networking::WinSock::IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes(octets),
                },
            };
            addr.Ipv4 = SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr,
                sin_zero: [0; 8],
            };
        }
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            // SAFETY: IN6_ADDR.u.Byte is [u8; 16], same layout as octets
            let mut sin6_addr: IN6_ADDR = unsafe { std::mem::zeroed() };
            unsafe {
                std::ptr::copy_nonoverlapping(octets.as_ptr(), sin6_addr.u.Byte.as_mut_ptr(), 16);
            }
            addr.Ipv6 = SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr,
                Anonymous: unsafe { std::mem::zeroed() },
            };
        }
    }

    addr
}

/// Convert SOCKADDR_INET to an IP address.
fn sockaddr_inet_to_ip(addr: &SOCKADDR_INET) -> Option<IpAddr> {
    // SAFETY: We check the family field to determine which union variant to read
    unsafe {
        if addr.si_family == AF_INET {
            let octets = addr.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes();
            Some(IpAddr::V4(Ipv4Addr::from(octets)))
        } else if addr.si_family == AF_INET6 {
            // SAFETY: IN6_ADDR.u.Byte is [u8; 16]
            let octets: [u8; 16] = addr.Ipv6.sin6_addr.u.Byte;
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        } else {
            None
        }
    }
}

/// Convert NET_LUID_LH to u64.
fn luid_to_u64(luid: &NET_LUID_LH) -> u64 {
    // SAFETY: NET_LUID_LH is a union containing a u64
    unsafe { luid.Value }
}

/// Convert u64 to NET_LUID_LH.
fn luid_from_u64(value: u64) -> NET_LUID_LH {
    NET_LUID_LH { Value: value }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_interfaces() {
        let interfaces = get_interfaces().expect("should get interfaces");
        assert!(!interfaces.is_empty(), "should have at least one interface");

        for iface in &interfaces {
            println!(
                "Interface: {} (idx={}, luid={:x}, type={}, connected={})",
                iface.alias, iface.index, iface.luid, iface.if_type, iface.is_connected
            );
        }
    }

    #[test]
    fn test_get_routes() {
        let routes = get_routes(None).expect("should get routes");

        for route in &routes {
            println!(
                "Route: {}/{} via {} (IF={}, metric={})",
                route.destination,
                route.prefix_length,
                route.gateway,
                route.interface_index,
                route.metric
            );
        }
    }

    #[test]
    fn test_get_default_gateway() {
        if let Ok(Some(gw)) = get_default_gateway() {
            println!(
                "Default gateway: {} via interface {}",
                gw.gateway, gw.interface_index
            );
        } else {
            println!("No default gateway found");
        }
    }

    #[test]
    fn test_get_physical_interfaces() {
        let interfaces = get_physical_interfaces().expect("should get physical interfaces");

        for iface in &interfaces {
            println!("Physical interface: {} (idx={})", iface.alias, iface.index);
        }
    }

    #[test]
    fn test_route_entry_creation() {
        let v4_route = RouteEntry::new_v4(
            Ipv4Addr::new(10, 0, 0, 0),
            8,
            Ipv4Addr::new(192, 168, 1, 1),
            1,
        )
        .with_metric(100);

        assert!(v4_route.is_v4());
        assert!(!v4_route.is_v6());
        assert!(!v4_route.is_default());
        assert_eq!(v4_route.metric, 100);

        let v6_route = RouteEntry::new_v6(
            Ipv6Addr::UNSPECIFIED,
            0,
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            2,
        );

        assert!(v6_route.is_v6());
        assert!(!v6_route.is_v4());
        assert!(v6_route.is_default());
    }
}
