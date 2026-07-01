//! Wintun adapter implementation for Windows.
//!
//! Wraps the Wintun driver to provide a TunnelDevice interface.

// Allow unsafe code for Wintun FFI calls
#![allow(unsafe_code)]

use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use tracing::{debug, info, warn};
use uuid::Uuid;
use windows::Win32::Foundation::{HANDLE, HWND};
use windows::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
    WTD_CHOICE_FILE, WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_VERIFY, WTD_UI_NONE, WinVerifyTrust,
};
use windows::core::GUID;
use wintun::{Adapter, Session};

use hpn_client_core::tunnel::TunnelDevice;

use crate::error::WindowsClientError;

/// Windows flag to hide console window when spawning processes.
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// GUID for the Wintun adapter (parsed at compile time for safety).
const ADAPTER_GUID: &str = "a32de018-a251-4c65-b239-1c57ef62eb09";

/// Parse the adapter GUID, returning an error instead of panicking.
fn parse_adapter_guid() -> Result<Uuid, WindowsClientError> {
    ADAPTER_GUID
        .parse()
        .map_err(|e| WindowsClientError::Adapter(format!("invalid adapter GUID: {}", e)))
}

/// Verify the Authenticode signature of a DLL file.
///
/// Uses the Windows WinVerifyTrust API to verify that the DLL is signed
/// with a valid Authenticode signature from a trusted certificate chain.
///
/// # Security
///
/// This function MUST be called before loading any DLL to prevent loading
/// tampered or malicious code. It verifies:
/// - The file has a valid Authenticode signature
/// - The signature chain leads to a trusted root CA
/// - Certificate revocation status (via OCSP/CRL)
///
/// # Errors
///
/// Returns an error if:
/// - The file is not signed
/// - The signature is invalid or has been tampered with
/// - The certificate is expired, revoked, or untrusted
/// - The file does not exist
pub fn verify_authenticode_signature(dll_path: &Path) -> Result<(), WindowsClientError> {
    // Convert path to wide string (null-terminated UTF-16)
    let wide_path: Vec<u16> = dll_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // Set up WINTRUST_FILE_INFO structure
    let file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: windows::core::PCWSTR(wide_path.as_ptr()),
        hFile: HANDLE::default(),
        pgKnownSubject: std::ptr::null_mut(),
    };

    // Set up WINTRUST_DATA structure
    // Using WTD_STATEACTION_VERIFY to verify the signature
    // WTD_REVOKE_WHOLECHAIN checks the entire certificate chain for revocation
    let mut wintrust_data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: std::ptr::null_mut(),
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &file_info as *const _ as *mut _,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: HANDLE::default(),
        pwszURLReference: windows::core::PWSTR::null(),
        dwProvFlags: Default::default(),
        dwUIContext: Default::default(),
        pSignatureSettings: std::ptr::null_mut(),
    };

    // GUID for generic verify action (Authenticode)
    let action_guid: GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    // Call WinVerifyTrust
    // SAFETY: We've properly initialized all structures and the file path is valid.
    // WinVerifyTrust is the standard Windows API for signature verification.
    let result = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &action_guid as *const GUID as *mut GUID,
            &mut wintrust_data as *mut WINTRUST_DATA as *mut std::ffi::c_void,
        )
    };

    // Interpret the result
    // 0 (ERROR_SUCCESS) means the signature is valid and trusted
    // WinVerifyTrust returns i32 directly (not a HRESULT struct)
    if result == 0 {
        info!(
            "Authenticode signature verified successfully for: {}",
            dll_path.display()
        );
        Ok(())
    } else {
        // Map common error codes to meaningful messages
        let error_code = result as u32;
        let error_msg = match error_code {
            0x800B0100 => "No signature found on the file".to_string(),
            0x800B0101 => "The signature or certificate has expired".to_string(),
            0x800B0109 => {
                "A certificate chain could not be built to a trusted root authority".to_string()
            }
            0x800B010C => "The certificate has been explicitly revoked".to_string(),
            0x800B0111 => "The certificate is not valid for the requested usage".to_string(),
            0x80096010 => "The signature of the file is invalid".to_string(),
            0x80092026 => "The specified certificate chain is not valid".to_string(),
            _ => format!(
                "Signature verification failed with error code: 0x{:08X}",
                error_code
            ),
        };

        warn!(
            "Authenticode signature verification failed for {}: {}",
            dll_path.display(),
            error_msg
        );

        Err(WindowsClientError::SignatureVerification(format!(
            "{}: {}",
            dll_path.display(),
            error_msg
        )))
    }
}

/// Wintun adapter wrapper.
pub struct WintunAdapter {
    /// The Wintun adapter (wrapped in Arc by wintun crate).
    _adapter: Arc<Adapter>,
    /// The active session.
    session: Arc<Session>,
    /// Adapter name.
    name: String,
    /// Current MTU.
    mtu: u16,
}

impl WintunAdapter {
    /// Create a new Wintun adapter.
    ///
    /// If `dll_path` is provided, loads wintun.dll from that path.
    /// Otherwise, uses the default system search paths.
    pub fn create(name: &str, mtu: u16) -> Result<Self, WindowsClientError> {
        Self::create_with_dll(name, mtu, None)
    }

    /// Create a new Wintun adapter with a specific DLL path.
    ///
    /// # Security
    ///
    /// If `dll_path` is None, the DLL is loaded from the same directory as the
    /// executable to prevent DLL hijacking attacks. The standard Windows DLL
    /// search order is NOT used.
    ///
    /// Before loading, the DLL's Authenticode signature is verified to ensure
    /// it hasn't been tampered with and is signed by a trusted publisher.
    pub fn create_with_dll(
        name: &str,
        mtu: u16,
        dll_path: Option<&std::path::Path>,
    ) -> Result<Self, WindowsClientError> {
        // Determine the DLL path
        let actual_dll_path = if let Some(path) = dll_path {
            path.to_path_buf()
        } else {
            // Load from same directory as executable (secure default)
            let exe_dir = std::env::current_exe()
                .map_err(|e| {
                    WindowsClientError::Adapter(format!("failed to get executable path: {}", e))
                })?
                .parent()
                .ok_or_else(|| {
                    WindowsClientError::Adapter("executable has no parent directory".into())
                })?
                .to_path_buf();

            exe_dir.join("wintun.dll")
        };

        // Check if DLL exists
        if !actual_dll_path.exists() {
            return Err(WindowsClientError::Adapter(format!(
                "wintun.dll not found at {}. Please ensure wintun.dll is in the same directory as the executable.",
                actual_dll_path.display()
            )));
        }

        // SECURITY: Verify Authenticode signature BEFORE loading the DLL
        // This prevents loading tampered or malicious DLLs
        info!(
            "Verifying Authenticode signature for: {}",
            actual_dll_path.display()
        );
        verify_authenticode_signature(&actual_dll_path)?;

        // SECURITY: Load Wintun from explicit path to prevent DLL hijacking.
        // Never use the default Windows DLL search order which includes CWD.
        info!(
            "Loading Wintun from verified path: {}",
            actual_dll_path.display()
        );
        // SAFETY: We've verified the DLL's Authenticode signature above.
        // Loading from a known path after signature verification is secure.
        let wintun = unsafe { wintun::load_from_path(&actual_dll_path) }
            .map_err(|e| WindowsClientError::Adapter(format!("failed to load wintun: {}", e)))?;

        // Try to delete any existing adapter first to ensure clean state.
        // This handles the case where a previous session crashed or wasn't cleaned up.
        if let Ok(existing) = Adapter::open(&wintun, name) {
            info!(
                "Found existing adapter '{}', deleting for clean state...",
                name
            );
            // Drop the adapter to release it, then it will be recreated below
            drop(existing);
            // Give Windows a moment to clean up
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        // Parse GUID safely (no panic) and convert to u128 for Wintun API
        let guid = parse_adapter_guid()?.as_u128();

        // Create new adapter (always create fresh to avoid session conflicts)
        let adapter = Adapter::create(&wintun, name, "HPN VPN", Some(guid))
            .map_err(|e| WindowsClientError::Adapter(format!("failed to create adapter: {}", e)))?;

        info!("Created Wintun adapter: {}", name);

        // Start session with ring capacity
        info!("Starting Wintun session with MAX_RING_CAPACITY...");
        let session = adapter
            .start_session(wintun::MAX_RING_CAPACITY)
            .map_err(|e| WindowsClientError::Adapter(format!("failed to start session: {}", e)))?;

        info!("Wintun session started successfully for adapter: {}", name);

        Ok(Self {
            _adapter: adapter,
            session: Arc::new(session),
            name: name.to_string(),
            mtu,
        })
    }

    /// Configure the adapter's IP address.
    pub fn configure_ip(
        &self,
        ip: [u8; 4],
        netmask: [u8; 4],
        gateway: [u8; 4],
    ) -> Result<(), WindowsClientError> {
        use std::process::Command;

        let ip_str = format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
        let mask_str = format!(
            "{}.{}.{}.{}",
            netmask[0], netmask[1], netmask[2], netmask[3]
        );
        let gw_str = format!(
            "{}.{}.{}.{}",
            gateway[0], gateway[1], gateway[2], gateway[3]
        );

        // Use netsh to configure the adapter (hidden window)
        let output = Command::new("netsh")
            .args([
                "interface",
                "ip",
                "set",
                "address",
                &self.name,
                "static",
                &ip_str,
                &mask_str,
                &gw_str,
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| WindowsClientError::Adapter(format!("failed to run netsh: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(WindowsClientError::Adapter(format!(
                "netsh failed: {}",
                stderr
            )));
        }

        info!(
            "Configured {} with IP {} netmask {} gateway {}",
            self.name, ip_str, mask_str, gw_str
        );

        // Explicitly enable the interface (critical for fresh adapters or after crashes)
        // This ensures the interface is administratively up and ready to pass traffic
        let enable_output = Command::new("netsh")
            .args(["interface", "set", "interface", &self.name, "admin=enabled"])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| {
                WindowsClientError::Adapter(format!("failed to enable interface: {}", e))
            })?;

        if !enable_output.status.success() {
            // Log warning but don't fail - interface may already be enabled
            let stderr = String::from_utf8_lossy(&enable_output.stderr);
            debug!(
                "Interface enable command returned non-zero (may already be up): {}",
                stderr
            );
        } else {
            info!("Interface {} enabled", self.name);
        }

        Ok(())
    }

    /// Configure DNS servers.
    pub fn configure_dns(&self, dns_servers: &[[u8; 4]]) -> Result<(), WindowsClientError> {
        use std::process::Command;

        for (i, dns) in dns_servers.iter().enumerate() {
            let dns_str = format!("{}.{}.{}.{}", dns[0], dns[1], dns[2], dns[3]);
            let index = if i == 0 { "1" } else { "2" };

            let output = Command::new("netsh")
                .args([
                    "interface",
                    "ip",
                    "set",
                    "dns",
                    &self.name,
                    "static",
                    &dns_str,
                    &format!("index={}", index),
                ])
                .creation_flags(CREATE_NO_WINDOW)
                .output()
                .map_err(|e| WindowsClientError::Adapter(format!("failed to run netsh: {}", e)))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(WindowsClientError::Adapter(format!(
                    "netsh dns failed: {}",
                    stderr
                )));
            }

            debug!("Configured DNS {}: {}", index, dns_str);
        }

        Ok(())
    }

    /// Get the adapter name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Wait for the interface to become operational.
    ///
    /// Polls the interface state until it's connected/enabled, or times out.
    /// This is critical after `configure_ip()` to ensure Windows has fully
    /// initialized the interface before worker threads start reading/writing.
    pub fn wait_for_ready(&self, timeout: std::time::Duration) -> Result<(), WindowsClientError> {
        use std::time::Instant;

        let start = Instant::now();
        let mut logged_waiting = false;

        loop {
            if start.elapsed() > timeout {
                return Err(WindowsClientError::Adapter(format!(
                    "timeout waiting for interface '{}' to become ready after {:?}",
                    self.name, timeout
                )));
            }

            // Use Windows API to check if interface has an IP address assigned
            // This is locale-independent and more reliable than parsing netsh output
            match crate::windows_api::get_interface_ip(&self.name) {
                Ok(Some(_ip)) => {
                    // Interface has IP assigned - it's ready
                    info!("Interface {} is ready with IP assigned", self.name);
                    return Ok(());
                }
                Ok(None) => {
                    // No IP yet, keep waiting
                    if !logged_waiting {
                        debug!("Waiting for interface {} to get IP address...", self.name);
                        logged_waiting = true;
                    }
                }
                Err(e) => {
                    // Interface not found or error - keep waiting
                    if !logged_waiting {
                        debug!("Waiting for interface {} to appear ({})", self.name, e);
                        logged_waiting = true;
                    }
                }
            }

            // Poll every 100ms
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    /// Get the configured MTU.
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Configure the adapter's IPv6 address.
    ///
    /// Uses netsh to add an IPv6 address to the Wintun adapter.
    /// On Windows, this adds the address as an additional unicast address.
    pub fn configure_ipv6(
        &self,
        ip: [u8; 16],
        prefix_len: u8,
        gateway: Option<[u8; 16]>,
    ) -> Result<(), WindowsClientError> {
        use std::net::Ipv6Addr;
        use std::process::Command;

        let ip_addr = Ipv6Addr::from(ip);
        let ip_str = ip_addr.to_string();

        // Add IPv6 address to the interface
        let output = Command::new("netsh")
            .args([
                "interface",
                "ipv6",
                "add",
                "address",
                &self.name,
                &format!("{}/{}", ip_str, prefix_len),
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| WindowsClientError::Adapter(format!("failed to run netsh ipv6: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(WindowsClientError::Adapter(format!(
                "netsh ipv6 add address failed: {}",
                stderr
            )));
        }

        info!(
            "Configured {} with IPv6 {}/{}",
            self.name, ip_str, prefix_len
        );

        // Add default route via gateway if provided
        if let Some(gw) = gateway {
            let gw_addr = Ipv6Addr::from(gw);
            let gw_str = gw_addr.to_string();

            let route_output = Command::new("netsh")
                .args([
                    "interface",
                    "ipv6",
                    "add",
                    "route",
                    "::/0",
                    &self.name,
                    &gw_str,
                ])
                .creation_flags(CREATE_NO_WINDOW)
                .output()
                .map_err(|e| {
                    WindowsClientError::Adapter(format!("failed to run netsh ipv6 route: {}", e))
                })?;

            if !route_output.status.success() {
                let stderr = String::from_utf8_lossy(&route_output.stderr);
                // Log warning but don't fail - route may already exist or gateway may not be reachable yet
                warn!(
                    "Failed to add IPv6 default route via {} (may already exist): {}",
                    gw_str, stderr
                );
            } else {
                info!("Added IPv6 default route via {}", gw_str);
            }
        }

        Ok(())
    }

    /// Configure IPv6 DNS servers.
    pub fn configure_dns_v6(&self, dns_servers: &[[u8; 16]]) -> Result<(), WindowsClientError> {
        use std::net::Ipv6Addr;
        use std::process::Command;

        for (i, dns) in dns_servers.iter().enumerate() {
            let dns_addr = Ipv6Addr::from(*dns);
            let dns_str = dns_addr.to_string();
            let index = if i == 0 { "1" } else { "2" };

            let output = Command::new("netsh")
                .args([
                    "interface",
                    "ipv6",
                    "set",
                    "dnsservers",
                    &self.name,
                    "static",
                    &dns_str,
                    &format!("register=none"),
                    &format!("validate=no"),
                ])
                .creation_flags(CREATE_NO_WINDOW)
                .output()
                .map_err(|e| {
                    WindowsClientError::Adapter(format!("failed to run netsh ipv6 dns: {}", e))
                })?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                // For secondary DNS, use "add" instead of "set"
                if i > 0 {
                    let add_output = Command::new("netsh")
                        .args([
                            "interface",
                            "ipv6",
                            "add",
                            "dnsservers",
                            &self.name,
                            &dns_str,
                            &format!("index={}", index),
                        ])
                        .creation_flags(CREATE_NO_WINDOW)
                        .output()
                        .map_err(|e| {
                            WindowsClientError::Adapter(format!(
                                "failed to run netsh ipv6 add dns: {}",
                                e
                            ))
                        })?;

                    if !add_output.status.success() {
                        let add_stderr = String::from_utf8_lossy(&add_output.stderr);
                        return Err(WindowsClientError::Adapter(format!(
                            "netsh ipv6 dns failed: {}",
                            add_stderr
                        )));
                    }
                } else {
                    return Err(WindowsClientError::Adapter(format!(
                        "netsh ipv6 dns failed: {}",
                        stderr
                    )));
                }
            }

            debug!("Configured IPv6 DNS {}: {}", index, dns_str);
        }

        Ok(())
    }
}

#[async_trait]
impl TunnelDevice for WintunAdapter {
    /// Send a packet to the TUN interface.
    /// PERFORMANCE CRITICAL - no logging in hot path!
    #[inline]
    fn send(&self, data: &[u8]) -> io::Result<usize> {
        // Allocate send packet from Wintun ring buffer
        let mut packet = self
            .session
            .allocate_send_packet(data.len() as u16)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("allocate failed: {}", e)))?;

        // Copy data and send
        packet.bytes_mut().copy_from_slice(data);
        self.session.send_packet(packet);

        Ok(data.len())
    }

    /// Receive a packet from the TUN interface (blocking).
    /// PERFORMANCE CRITICAL - no logging in hot path!
    #[inline]
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self.session.receive_blocking() {
            Ok(packet) => {
                let len = packet.bytes().len();
                if len > buf.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "packet too large for buffer",
                    ));
                }
                buf[..len].copy_from_slice(packet.bytes());
                Ok(len)
            }
            Err(e) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("receive failed: {}", e),
            )),
        }
    }

    fn set_mtu(&self, _mtu: u16) -> io::Result<()> {
        // MTU is set at creation time
        Ok(())
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
        gateway: Option<[u8; 16]>,
    ) -> io::Result<()> {
        WintunAdapter::configure_ipv6(self, ip, prefix_len, gateway)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }

    fn supports_ipv6(&self) -> bool {
        true
    }

    fn close(&self) -> io::Result<()> {
        // Session is closed on drop
        Ok(())
    }
}

impl Drop for WintunAdapter {
    fn drop(&mut self) {
        debug!("Closing Wintun adapter: {}", self.name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_authenticode_missing_file() {
        let result = verify_authenticode_signature(Path::new("C:\\nonexistent\\file.dll"));
        assert!(result.is_err());
    }
}
