//! Server configuration.
//!
//! Configuration is minimal by design - only essential settings are exposed.
//! All performance tuning is automatic.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::ServerError;

/// Server configuration.
///
/// # Example
///
/// ```toml
/// [server]
/// listen_addr = "0.0.0.0:51820"
/// ipv4_pool = "10.99.0.0/24"
/// server_tunnel_ip = "10.99.0.1"
/// dns_servers = ["1.1.1.1", "8.8.8.8"]
///
/// [keypair]
/// secret_key = "..."
/// public_key = "..."
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Listen address for UDP.
    pub listen_addr: SocketAddr,

    /// IPv4 address pool for clients (CIDR notation).
    pub ipv4_pool: String,

    /// Server's tunnel IPv4 address.
    pub server_tunnel_ip: String,

    /// DNS servers (IPv4) to provide to clients.
    pub dns_servers: Vec<String>,

    /// IPv6 address pool for clients (CIDR notation, optional).
    #[serde(default)]
    pub ipv6_pool: Option<String>,

    /// Server's tunnel IPv6 address (optional).
    #[serde(default)]
    pub server_tunnel_ipv6: Option<String>,

    /// DNS servers (IPv6) to provide to clients.
    #[serde(default)]
    pub dns_servers_v6: Vec<String>,

    /// TUN device name.
    #[serde(default = "default_tun_name")]
    pub tun_name: String,

    /// MTU for the tunnel.
    #[serde(default = "default_mtu")]
    pub mtu: u16,

    /// Session timeout in seconds.
    #[serde(default = "default_session_timeout")]
    pub session_timeout_secs: u64,

    /// Keepalive interval in seconds.
    #[serde(default = "default_keepalive_interval")]
    pub keepalive_interval_secs: u64,

    /// Enable server logging output.
    ///
    /// When set to false, logging is disabled at startup unless explicitly overridden
    /// by CLI/runtime behavior.
    #[serde(default = "default_log_enabled")]
    pub log_enabled: bool,

    /// Path to log file. When set, logs are written to this file in addition to stdout/journald.
    /// Directory must exist and be writable by the server process.
    #[serde(default)]
    pub log_file: Option<String>,

    /// Maximum log file size in MB before rotation. Default: 100 MB.
    #[serde(default = "default_log_max_size_mb")]
    pub log_max_size_mb: u64,

    /// Maximum number of rotated log files to keep. Default: 5.
    #[serde(default = "default_log_max_files")]
    pub log_max_files: u32,

    /// Maximum sessions (auto-calculated from IP pool if not set).
    #[serde(default)]
    pub max_sessions: Option<usize>,

    /// Enable NAT/masquerade.
    #[serde(default = "default_enable_nat")]
    pub enable_nat: bool,

    /// Network interface for NAT (auto-detected if not set).
    #[serde(default)]
    pub nat_interface: Option<String>,

    /// Enable metrics HTTP endpoint.
    #[serde(default)]
    pub enable_metrics: bool,

    /// Strict no-log mode (default: true).
    ///
    /// When enabled (default):
    /// - Client IP addresses are NOT logged (redacted)
    /// - No per-session traffic stats in logs
    /// - Heartbeat sends only session count + uptime (no bytes)
    /// - All session data is RAM-only (flushed on restart)
    ///
    /// Set to false to enable full monitoring (debugging, compliance).
    #[serde(default = "default_true")]
    pub no_log: bool,

    /// Metrics HTTP listen address.
    #[serde(default = "default_metrics_addr")]
    pub metrics_addr: SocketAddr,

    /// Enable admin REST API.
    #[serde(default)]
    pub enable_admin_api: bool,

    /// Admin API HTTP listen address.
    #[serde(default = "default_admin_addr")]
    pub admin_addr: SocketAddr,

    /// Admin API token for authentication (plain text).
    ///
    /// **REQUIRED in production** when `enable_admin_api` is true unless
    /// `admin_api_token_sha256` is set (see below). If neither is set, the
    /// admin API will reject all non-health-check requests.
    ///
    /// SECURITY: storing the token in plaintext leaves it in the config
    /// file (server.toml), in process memory, and in any backup that
    /// captures the config — operators looking for defence-in-depth
    /// should use `admin_api_token_sha256` instead (FIX-032). The plain
    /// variant remains as the path of least resistance for local
    /// development.
    #[serde(default)]
    pub admin_api_token: Option<String>,

    /// SHA-256 hash of the admin API token, hex-encoded (FIX-032).
    ///
    /// When set, the admin API verifies the incoming bearer token by
    /// hashing it with SHA-256 (constant-time output comparison via
    /// `subtle`) and matching against this digest. The on-disk
    /// `server.toml` no longer contains the token in plaintext, so a
    /// read leak of the config file (backup, support bundle, etc.)
    /// does not surface the token to an attacker. Generate with:
    ///
    /// ```sh
    /// printf '%s' "$YOUR_ADMIN_TOKEN" | sha256sum | awk '{print $1}'
    /// ```
    ///
    /// Takes priority over `admin_api_token`: when both are set, the
    /// hash check runs and the plaintext field is ignored (with a
    /// startup warning so the operator knows the redundancy is unused).
    #[serde(default)]
    pub admin_api_token_sha256: Option<String>,

    /// Deprecated and ignored. Retained only so pre-existing server.toml
    /// files that still contain `license_key = "..."` continue to parse.
    /// HPN is now open-source with unlimited sessions — no license is
    /// checked. This field will be removed in a future release.
    #[serde(default)]
    pub license_key: Option<String>,

    /// Path to the user authentication database (SQLite).
    /// Default: `/var/lib/hpn/users.db` when omitted.
    /// Users are managed with `hpn-server user add/remove/list`.
    #[serde(default, alias = "user_db_path")]
    pub users_db_path: Option<std::path::PathBuf>,

    /// Require user authentication for all connections.
    /// If false (default), authentication is optional (backward compatible).
    /// If true, connections without valid credentials are rejected.
    #[serde(default, alias = "requires_auth")]
    pub require_auth: bool,

    /// Minimum security level accepted on incoming handshakes.
    ///
    /// Accepted values: `"level3"` (ML-KEM-768 + ML-DSA-65) or `"level5"`
    /// (ML-KEM-1024 + ML-DSA-87). Any client that proposes a weaker level is
    /// rejected at handshake time. Default: `"level3"`.
    ///
    /// Set this to `"level5"` for deployments that must enforce maximum
    /// post-quantum security (no downgrade). Must match the security level of
    /// the server's static keypair.
    #[serde(default = "default_min_security_level")]
    pub min_security_level: String,

    /// Maximum packets per second accepted from a single session.
    ///
    /// 0 disables packet-rate limiting entirely. Default: 100_000 PPS
    /// (~1.2 Gbps at 1500 B MTU) which comfortably accommodates HD streaming,
    /// large file transfers, and online gaming for a single user. Raise this
    /// for Enterprise deployments where a single customer machine legitimately
    /// needs more throughput.
    #[serde(default = "default_session_rate_limit_pps")]
    pub session_rate_limit_pps: u32,

    /// Maximum bytes per second accepted from a single session.
    ///
    /// 0 disables byte-rate limiting entirely. Default: 125_000_000 B/s
    /// (1 Gbps) which matches the PRO tier's advertised per-session bandwidth.
    /// Raise or set to 0 for Enterprise customers with unlimited bandwidth
    /// entitlements.
    #[serde(default = "default_session_rate_limit_bps")]
    pub session_rate_limit_bps: u64,

    /// User to drop privileges to after binding sockets.
    /// This is a security best practice - the server should not run as root
    /// longer than necessary. Requires the user to exist on the system.
    /// Example: "nobody", "hpn", "vpn"
    #[serde(default)]
    pub run_as_user: Option<String>,

    /// Group to drop privileges to after binding sockets.
    /// If not specified but run_as_user is set, uses the user's primary group.
    #[serde(default)]
    pub run_as_group: Option<String>,

    // Deprecated fields - kept for backward compatibility but ignored
    #[serde(default, skip_serializing)]
    #[allow(dead_code)]
    pub(crate) security_level: Option<String>,
    #[serde(default, skip_serializing)]
    #[allow(dead_code)]
    pub(crate) private_key_path: Option<PathBuf>,
    #[serde(default, skip_serializing)]
    #[allow(dead_code)]
    pub(crate) enable_io_uring: Option<bool>,
    #[serde(default, skip_serializing)]
    #[allow(dead_code)]
    pub(crate) enable_tun_multiqueue: Option<bool>,
    #[serde(default, skip_serializing)]
    #[allow(dead_code)]
    pub(crate) tun_num_queues: Option<usize>,
    #[serde(default, skip_serializing)]
    #[allow(dead_code)]
    pub(crate) tun_queue_count: Option<usize>,
    #[serde(default, skip_serializing)]
    #[allow(dead_code)]
    pub(crate) udp_workers: Option<usize>,
    #[serde(default, skip_serializing)]
    #[allow(dead_code)]
    pub(crate) recv_buffer_size: Option<usize>,
    #[serde(default, skip_serializing)]
    #[allow(dead_code)]
    pub(crate) send_buffer_size: Option<usize>,
    #[serde(default, skip_serializing)]
    #[allow(dead_code)]
    pub(crate) recv_batch_size: Option<usize>,
    #[serde(default, skip_serializing)]
    #[allow(dead_code)]
    pub(crate) send_batch_size: Option<usize>,
    #[serde(default, skip_serializing)]
    #[allow(dead_code)]
    pub(crate) enable_afxdp: Option<bool>,
    #[serde(default, skip_serializing)]
    #[allow(dead_code)]
    pub(crate) afxdp_interface: Option<String>,
    #[serde(default, skip_serializing)]
    #[allow(dead_code)]
    pub(crate) afxdp_queues: Option<u32>,
    #[serde(default, skip_serializing)]
    #[allow(dead_code)]
    pub(crate) afxdp_ring_size: Option<u32>,
    #[serde(default, skip_serializing)]
    #[allow(dead_code)]
    pub(crate) afxdp_zero_copy: Option<bool>,
}

fn default_tun_name() -> String {
    "hpn0".into()
}

fn default_mtu() -> u16 {
    1420
}

fn default_session_timeout() -> u64 {
    180
}

fn default_keepalive_interval() -> u64 {
    25
}

fn default_log_enabled() -> bool {
    true
}

fn default_log_max_size_mb() -> u64 {
    100
}

fn default_min_security_level() -> String {
    "level3".to_string()
}

fn default_session_rate_limit_pps() -> u32 {
    100_000
}

fn default_session_rate_limit_bps() -> u64 {
    125_000_000
}

fn default_log_max_files() -> u32 {
    5
}

fn default_enable_nat() -> bool {
    true
}

fn default_metrics_addr() -> SocketAddr {
    "127.0.0.1:9100".parse().unwrap()
}

fn default_admin_addr() -> SocketAddr {
    "127.0.0.1:9101".parse().unwrap()
}

fn default_true() -> bool {
    true
}

impl ServerConfig {
    /// Default path to the user authentication database.
    pub const DEFAULT_USERS_DB_PATH: &'static str = "/var/lib/hpn/users.db";

    /// Resolve configured users DB path, falling back to the default path.
    #[must_use]
    pub fn users_db_path_or_default(&self) -> PathBuf {
        self.users_db_path
            .clone()
            .unwrap_or_else(|| PathBuf::from(Self::DEFAULT_USERS_DB_PATH))
    }

    /// Load configuration from a TOML file.
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self, ServerError> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| ServerError::Config(format!("failed to read config file: {}", e)))?;
        Self::load_from_str(&content)
    }

    /// Load configuration from a TOML string.
    ///
    /// Parse errors are deliberately summarised with location info only
    /// (kind + byte offset), never the full `toml::de::Error` Display. The
    /// full Display implementation includes a snippet of the offending
    /// line, and if that line happens to be `license_key = "..."`,
    /// `admin_api_token = "..."` or similar, the secret ends up in
    /// journald / stderr where it stays until log rotation. Paranoia is
    /// cheaper than key rotation.
    pub fn load_from_str(content: &str) -> Result<Self, ServerError> {
        toml::from_str(content).map_err(|e| ServerError::Config(Self::sanitize_toml_error(&e)))
    }

    /// Summarise a `toml::de::Error` without leaking the offending line.
    ///
    /// Keeps `.message()` (the parser's "invalid type" / "missing field"
    /// description) and, when available, the byte span where the error
    /// occurred — enough to locate the mistake in the source file from an
    /// editor without having the secret text echoed back through logs.
    fn sanitize_toml_error(err: &toml::de::Error) -> String {
        let message = err.message();
        match err.span() {
            Some(span) => format!(
                "failed to parse config: {} (at bytes {}..{})",
                message, span.start, span.end
            ),
            None => format!("failed to parse config: {}", message),
        }
    }

    /// Save configuration to a TOML file.
    pub fn save_to_file(&self, path: impl AsRef<Path>) -> Result<(), ServerError> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| ServerError::Config(format!("failed to serialize config: {}", e)))?;
        std::fs::write(path.as_ref(), content)
            .map_err(|e| ServerError::Config(format!("failed to write config file: {}", e)))
    }

    /// Get the session timeout as a Duration.
    pub fn session_timeout(&self) -> Duration {
        Duration::from_secs(self.session_timeout_secs)
    }

    /// Get the keepalive interval as a Duration.
    pub fn keepalive_interval(&self) -> Duration {
        Duration::from_secs(self.keepalive_interval_secs)
    }

    /// Get max sessions (auto-calculate from IP pool if not specified).
    ///
    /// Uses checked arithmetic throughout: `prefix` from the pool is validated
    /// to be in `1..=30` before computing host bits, and the shift uses
    /// `checked_shl` to avoid undefined behaviour on malformed configs that
    /// bypass `validate()`.
    pub fn get_max_sessions(&self) -> usize {
        if let Some(max) = self.max_sessions {
            return max;
        }
        if let Ok((_, prefix)) = self.parse_ipv4_pool() {
            // parse_ipv4_pool now rejects prefix > 32 or 0 explicitly, but we
            // double-check here in case of a stale call path.
            if !(1..=30).contains(&prefix) {
                return 1000;
            }
            let host_bits = u32::from(32u8.saturating_sub(prefix));
            let max_ips = 1u32
                .checked_shl(host_bits)
                .unwrap_or(u32::MAX)
                .saturating_sub(2) as usize;
            return max_ips.min(100_000);
        }
        1000
    }

    /// Parse the IPv4 pool into base address and prefix length.
    ///
    /// Rejects prefixes outside `1..=32` explicitly to prevent arithmetic
    /// hazards in downstream consumers like `get_max_sessions`.
    pub fn parse_ipv4_pool(&self) -> Result<([u8; 4], u8), ServerError> {
        let parts: Vec<&str> = self.ipv4_pool.split('/').collect();
        if parts.len() != 2 {
            return Err(ServerError::Config(format!(
                "invalid IPv4 pool format: {}",
                self.ipv4_pool
            )));
        }

        let addr_parts: Vec<&str> = parts[0].split('.').collect();
        if addr_parts.len() != 4 {
            return Err(ServerError::Config(format!(
                "invalid IPv4 address: {}",
                parts[0]
            )));
        }

        let mut base = [0u8; 4];
        for (i, part) in addr_parts.iter().enumerate() {
            base[i] = part
                .parse()
                .map_err(|_| ServerError::Config(format!("invalid IPv4 octet: {}", part)))?;
        }

        let prefix: u8 = parts[1]
            .parse()
            .map_err(|_| ServerError::Config(format!("invalid prefix length: {}", parts[1])))?;

        if prefix == 0 || prefix > 32 {
            return Err(ServerError::Config(format!(
                "IPv4 prefix length must be in 1..=32, got {}",
                prefix
            )));
        }

        Ok((base, prefix))
    }

    /// Parse the server tunnel IP.
    pub fn parse_server_tunnel_ip(&self) -> Result<[u8; 4], ServerError> {
        let parts: Vec<&str> = self.server_tunnel_ip.split('.').collect();
        if parts.len() != 4 {
            return Err(ServerError::Config(format!(
                "invalid server tunnel IP: {}",
                self.server_tunnel_ip
            )));
        }

        let mut ip = [0u8; 4];
        for (i, part) in parts.iter().enumerate() {
            ip[i] = part
                .parse()
                .map_err(|_| ServerError::Config(format!("invalid IP octet: {}", part)))?;
        }

        Ok(ip)
    }

    /// Parse DNS server strings into IP arrays.
    pub fn parse_dns_servers(&self) -> Result<Vec<[u8; 4]>, ServerError> {
        self.dns_servers
            .iter()
            .map(|s| {
                let parts: Vec<&str> = s.split('.').collect();
                if parts.len() != 4 {
                    return Err(ServerError::Config(format!("invalid DNS server: {}", s)));
                }
                let mut ip = [0u8; 4];
                for (i, part) in parts.iter().enumerate() {
                    ip[i] = part
                        .parse()
                        .map_err(|_| ServerError::Config(format!("invalid DNS octet: {}", part)))?;
                }
                Ok(ip)
            })
            .collect()
    }

    /// Parse the IPv6 pool into base address and prefix length.
    pub fn parse_ipv6_pool(&self) -> Result<Option<([u8; 16], u8)>, ServerError> {
        let pool = match &self.ipv6_pool {
            Some(p) => p,
            None => return Ok(None),
        };

        let parts: Vec<&str> = pool.split('/').collect();
        if parts.len() != 2 {
            return Err(ServerError::Config(format!(
                "invalid IPv6 pool format: {}",
                pool
            )));
        }

        use std::net::Ipv6Addr;
        let addr: Ipv6Addr = parts[0]
            .parse()
            .map_err(|_| ServerError::Config(format!("invalid IPv6 address: {}", parts[0])))?;

        let prefix: u8 = parts[1]
            .parse()
            .map_err(|_| ServerError::Config(format!("invalid IPv6 prefix: {}", parts[1])))?;

        Ok(Some((addr.octets(), prefix)))
    }

    /// Parse the server tunnel IPv6 address.
    pub fn parse_server_tunnel_ipv6(&self) -> Result<Option<[u8; 16]>, ServerError> {
        let addr_str = match &self.server_tunnel_ipv6 {
            Some(s) => s,
            None => return Ok(None),
        };

        use std::net::Ipv6Addr;
        let addr: Ipv6Addr = addr_str
            .parse()
            .map_err(|_| ServerError::Config(format!("invalid IPv6 address: {}", addr_str)))?;

        Ok(Some(addr.octets()))
    }

    /// Parse IPv6 DNS server strings into byte arrays.
    pub fn parse_dns_servers_v6(&self) -> Result<Vec<[u8; 16]>, ServerError> {
        use std::net::Ipv6Addr;
        self.dns_servers_v6
            .iter()
            .map(|s| {
                let addr: Ipv6Addr = s
                    .parse()
                    .map_err(|_| ServerError::Config(format!("invalid IPv6 DNS server: {}", s)))?;
                Ok(addr.octets())
            })
            .collect()
    }

    /// Check if IPv6 is enabled.
    pub fn has_ipv6(&self) -> bool {
        self.ipv6_pool.is_some() && self.server_tunnel_ipv6.is_some()
    }

    // =========================================================================
    // Auto-tune helper methods (use RuntimeConfig for new code)
    // These exist for backward compatibility with existing server code
    // =========================================================================

    /// Check if TUN multiqueue should be used.
    /// Delegates to auto_tune for detection.
    #[cfg(target_os = "linux")]
    pub fn should_use_tun_multiqueue(&self) -> bool {
        crate::auto_tune::SystemCapabilities::get().has_tun_multiqueue
            && crate::auto_tune::SystemCapabilities::get().optimal_tun_queues() > 1
    }

    #[cfg(not(target_os = "linux"))]
    pub fn should_use_tun_multiqueue(&self) -> bool {
        false
    }

    /// Get optimal number of TUN queues.
    pub fn get_tun_num_queues(&self) -> usize {
        crate::auto_tune::SystemCapabilities::get().optimal_tun_queues()
    }

    /// Get optimal number of UDP workers.
    pub fn get_udp_workers(&self) -> usize {
        crate::auto_tune::SystemCapabilities::get().optimal_workers()
    }

    /// Get optimal receive buffer size.
    pub fn get_recv_buffer_size(&self) -> usize {
        crate::auto_tune::SystemCapabilities::get().optimal_buffer_size()
    }

    /// Get optimal send buffer size.
    pub fn get_send_buffer_size(&self) -> usize {
        crate::auto_tune::SystemCapabilities::get().optimal_buffer_size()
    }

    /// Get optimal batch size.
    pub fn get_batch_size(&self) -> usize {
        crate::auto_tune::SystemCapabilities::get().optimal_batch_size()
    }

    /// Check if io_uring should be used.
    #[cfg(all(target_os = "linux", feature = "io_uring"))]
    pub fn should_use_io_uring(&self) -> bool {
        matches!(
            crate::auto_tune::SystemCapabilities::get().backend,
            crate::auto_tune::NetworkBackend::IoUring
        )
    }

    #[cfg(not(all(target_os = "linux", feature = "io_uring")))]
    pub fn should_use_io_uring(&self) -> bool {
        false
    }

    /// Check if AF_XDP should be used.
    #[cfg(all(target_os = "linux", feature = "afxdp"))]
    pub fn should_use_afxdp(&self) -> bool {
        matches!(
            crate::auto_tune::SystemCapabilities::get().backend,
            crate::auto_tune::NetworkBackend::AfXdp
        )
    }

    #[cfg(not(all(target_os = "linux", feature = "afxdp")))]
    pub fn should_use_afxdp(&self) -> bool {
        false
    }

    /// Get AF_XDP configuration if available.
    #[cfg(all(target_os = "linux", feature = "afxdp"))]
    pub fn get_afxdp_config(&self) -> Option<(String, u32, u32, bool)> {
        let caps = crate::auto_tune::SystemCapabilities::get();
        if !caps.has_afxdp {
            return None;
        }
        let interface = caps.default_interface.clone()?;
        let queues = caps.nic_rx_queues as u32;
        let ring_size = 4096u32;
        let zero_copy = true;
        Some((interface, queues, ring_size, zero_copy))
    }

    #[cfg(not(all(target_os = "linux", feature = "afxdp")))]
    pub fn get_afxdp_config(&self) -> Option<(String, u32, u32, bool)> {
        None
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), ServerError> {
        // Validate IPv4 pool
        let (base, prefix) = self.parse_ipv4_pool()?;
        if prefix < 16 || prefix > 30 {
            return Err(ServerError::Config(format!(
                "prefix must be between 16 and 30, got {}",
                prefix
            )));
        }

        // Validate server tunnel IP
        let server_ip = self.parse_server_tunnel_ip()?;

        // Check that server IP is in the pool
        let base_u32 = u32::from_be_bytes(base);
        let server_u32 = u32::from_be_bytes(server_ip);
        let mask = !((1u32 << (32 - prefix)) - 1);
        if (server_u32 & mask) != (base_u32 & mask) {
            return Err(ServerError::Config(format!(
                "server tunnel IP {} is not in pool {}",
                self.server_tunnel_ip, self.ipv4_pool
            )));
        }

        // Validate DNS servers
        self.parse_dns_servers()?;

        // Validate IPv6 if configured
        if let Some((base_v6, prefix_v6)) = self.parse_ipv6_pool()? {
            if prefix_v6 < 48 || prefix_v6 > 128 {
                return Err(ServerError::Config(format!(
                    "IPv6 prefix must be between 48 and 128, got {}",
                    prefix_v6
                )));
            }

            // Validate server tunnel IPv6
            if let Some(server_ipv6) = self.parse_server_tunnel_ipv6()? {
                let prefix_bytes = (prefix_v6 / 8) as usize;
                for i in 0..prefix_bytes.min(16) {
                    if base_v6[i] != server_ipv6[i] {
                        return Err(ServerError::Config(format!(
                            "server tunnel IPv6 {} is not in pool {:?}",
                            self.server_tunnel_ipv6.as_deref().unwrap_or("<not set>"),
                            self.ipv6_pool
                        )));
                    }
                }
            } else {
                return Err(ServerError::Config(
                    "ipv6_pool configured but server_tunnel_ipv6 is missing".into(),
                ));
            }

            self.parse_dns_servers_v6()?;
        }

        // Validate MTU (576 is the IPv4 minimum datagram size; 9000 is the
        // typical jumbo-frame ceiling; we reject anything above that since
        // we have no path MTU discovery for oversize packets).
        if self.mtu < 576 {
            return Err(ServerError::Config(format!(
                "MTU must be at least 576, got {}",
                self.mtu
            )));
        }
        if self.mtu > 9000 {
            return Err(ServerError::Config(format!(
                "MTU must be at most 9000, got {}",
                self.mtu
            )));
        }

        // Validate session_timeout (a 0-value would expire every session
        // immediately, effectively disabling the server).
        if self.session_timeout_secs == 0 {
            return Err(ServerError::Config(
                "session_timeout_secs must be > 0".into(),
            ));
        }

        // Validate keepalive_interval (a 0-value causes divide-by-zero or
        // hot-loop keepalive behaviour in the client state machine).
        if self.keepalive_interval_secs == 0 {
            return Err(ServerError::Config(
                "keepalive_interval_secs must be > 0".into(),
            ));
        }

        // Validate log rotation parameters (a 0-value on max_size_mb causes
        // a rotation storm on every write; 0 on max_files yields an empty
        // rename loop but still cycles the primary file).
        if self.log_file.is_some() {
            if self.log_max_size_mb == 0 {
                return Err(ServerError::Config(
                    "log_max_size_mb must be >= 1 when log_file is set".into(),
                ));
            }
            if self.log_max_files == 0 {
                return Err(ServerError::Config(
                    "log_max_files must be >= 1 when log_file is set".into(),
                ));
            }
        }

        // Validate min_security_level is parseable (case-insensitive accepts
        // level3, level5, 3, 5 — anything else is an operator typo).
        match self.min_security_level.to_ascii_lowercase().as_str() {
            "level3" | "level5" | "3" | "5" => {}
            other => {
                return Err(ServerError::Config(format!(
                    "min_security_level must be 'level3' or 'level5', got '{}'",
                    other
                )));
            }
        }

        // Validate max_sessions vs IP pool
        let host_bits = 32 - prefix as u32;
        let max_usable_ips = (1u32 << host_bits).saturating_sub(2) as usize;
        let max_sessions = self.get_max_sessions();
        if max_sessions > max_usable_ips {
            return Err(ServerError::Config(format!(
                "max_sessions ({}) exceeds available IPs in pool ({})",
                max_sessions, max_usable_ips
            )));
        }

        // Validate admin API token strength when admin API is enabled.
        //
        // The runtime auth check in `admin.rs` already fails closed when the
        // token is missing, so a misconfigured server with `enable_admin_api
        // = true` but no token cannot be exploited — every admin call is
        // rejected with 401. Past audits considered that "safe enough" and
        // the required-token check was rejected to avoid a breaking change.
        //
        // However, an operator who sets `admin_api_token = "admin"` (or any
        // <24-char value) thinks they are protected while a handful of
        // guesses at 100 req/min blows past the budget. Rate-limit + ct_eq
        // don't rescue entropy that isn't there. Enforce a minimum here so
        // the policy is visible at startup, not hidden in an HMAC header.
        //
        // 24 chars is the floor: a base64-encoded 128-bit secret fits in 24
        // chars, matching `openssl rand -base64 18` / `head -c 18 /dev/urandom
        // | base64`. We reject the empty string and obviously-weak literals
        // even when the length is long enough, so `"aaaaaaaaaaaaaaaaaaaaaaaa"`
        // doesn't sneak through.
        if self.enable_admin_api
            && let Some(token) = self.admin_api_token.as_deref()
        {
            const MIN_ADMIN_TOKEN_LEN: usize = 24;
            let trimmed = token.trim();
            if trimmed.len() < MIN_ADMIN_TOKEN_LEN {
                return Err(ServerError::Config(format!(
                    "admin_api_token is too short ({} chars); must be at \
                     least {} chars. Use `openssl rand -base64 32` to \
                     generate a strong token.",
                    trimmed.len(),
                    MIN_ADMIN_TOKEN_LEN
                )));
            }
            // Reject tokens that are a single repeated character — these
            // are most often left over from copy-paste placeholders
            // ("xxxxxxxx...", "aaaa...") and offer no entropy in practice.
            if let Some(first) = trimmed.chars().next()
                && trimmed.chars().all(|c| c == first)
            {
                return Err(ServerError::Config(
                    "admin_api_token is a single repeated character; \
                     generate a real random token"
                        .into(),
                ));
            }
        }

        // Audit H9 — refuse to start if Prometheus metrics are exposed on
        // a non-loopback interface without authentication.
        //
        // The standalone `MetricsHttpServer` (used when `enable_admin_api
        // = false` but `enable_metrics = true`) has NO auth at all: anyone
        // who can reach `metrics_addr` can read sessions_active,
        // handshakes_*, bytes_*, auth_lockout_* — exactly the
        // reconnaissance surface that lets an attacker time a credential-
        // stuffing wave or fingerprint the operator.
        //
        // Two paths are considered safe:
        //   1. `metrics_addr` binds to loopback (127.0.0.1 / ::1) — only
        //      processes on the same host can read it. The operator can
        //      then expose it deliberately through a reverse proxy with
        //      its own auth.
        //   2. `enable_admin_api = true` AND a strong `admin_api_token`
        //      is configured. In that mode `AdminHttpServer` (admin.rs)
        //      enforces bearer-token auth on `/metrics` before serving
        //      it. The standalone `MetricsHttpServer` is bypassed.
        //
        // Anything else hard-fails at startup so a misconfiguration cannot
        // ship to production silently.
        if self.enable_metrics && !self.metrics_addr.ip().is_loopback() {
            // Path (2): admin API enabled with a real token = OK.
            let admin_path_secure = self.enable_admin_api
                && self
                    .admin_api_token
                    .as_deref()
                    .is_some_and(|t| t.trim().len() >= 24);
            if !admin_path_secure {
                return Err(ServerError::Config(format!(
                    "enable_metrics is true and metrics_addr ({}) is not a \
                     loopback address, but no authenticated path is \
                     configured. Either bind metrics_addr to 127.0.0.1 \
                     (and front it with an authenticated reverse proxy \
                     if remote scraping is required), or set \
                     enable_admin_api = true with a strong \
                     admin_api_token (>=24 chars) so /metrics is served \
                     through the authenticated admin endpoint.",
                    self.metrics_addr
                )));
            }
        }

        Ok(())
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:51820".parse().unwrap(),
            ipv4_pool: "10.99.0.0/24".into(),
            server_tunnel_ip: "10.99.0.1".into(),
            dns_servers: vec!["1.1.1.1".into(), "8.8.8.8".into()],
            ipv6_pool: None,
            server_tunnel_ipv6: None,
            dns_servers_v6: Vec::new(),
            tun_name: default_tun_name(),
            mtu: default_mtu(),
            session_timeout_secs: default_session_timeout(),
            keepalive_interval_secs: default_keepalive_interval(),
            log_enabled: default_log_enabled(),
            max_sessions: None, // Auto-calculate
            enable_nat: default_enable_nat(),
            nat_interface: None, // Auto-detect
            enable_metrics: false,
            no_log: true,
            log_file: None,
            log_max_size_mb: default_log_max_size_mb(),
            log_max_files: default_log_max_files(),
            metrics_addr: default_metrics_addr(),
            enable_admin_api: false,
            admin_addr: default_admin_addr(),
            admin_api_token: None,
            admin_api_token_sha256: None,
            license_key: None,
            users_db_path: None,
            require_auth: false,
            min_security_level: default_min_security_level(),
            session_rate_limit_pps: default_session_rate_limit_pps(),
            session_rate_limit_bps: default_session_rate_limit_bps(),
            run_as_user: None,
            run_as_group: None,
            // Deprecated fields
            security_level: None,
            private_key_path: None,
            enable_io_uring: None,
            enable_tun_multiqueue: None,
            tun_num_queues: None,
            tun_queue_count: None,
            udp_workers: None,
            recv_buffer_size: None,
            send_buffer_size: None,
            recv_batch_size: None,
            send_batch_size: None,
            enable_afxdp: None,
            afxdp_interface: None,
            afxdp_queues: None,
            afxdp_ring_size: None,
            afxdp_zero_copy: None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4_pool() {
        let config = ServerConfig::default();
        let (base, prefix) = config.parse_ipv4_pool().unwrap();
        assert_eq!(base, [10, 99, 0, 0]);
        assert_eq!(prefix, 24);
    }

    #[test]
    fn test_parse_server_tunnel_ip() {
        let config = ServerConfig::default();
        let ip = config.parse_server_tunnel_ip().unwrap();
        assert_eq!(ip, [10, 99, 0, 1]);
    }

    #[test]
    fn test_default_config() {
        let config = ServerConfig::default();
        assert_eq!(config.listen_addr.to_string(), "0.0.0.0:51820");
        assert_eq!(config.ipv4_pool, "10.99.0.0/24");
        assert_eq!(config.server_tunnel_ip, "10.99.0.1");
        assert_eq!(config.tun_name, "hpn0");
        assert_eq!(config.mtu, 1420);
        assert!(config.log_enabled);
    }

    #[test]
    fn test_get_max_sessions_auto() {
        let config = ServerConfig::default();
        // /24 = 254 usable IPs
        assert_eq!(config.get_max_sessions(), 254);
    }

    #[test]
    fn test_get_max_sessions_explicit() {
        let mut config = ServerConfig::default();
        config.max_sessions = Some(100);
        assert_eq!(config.get_max_sessions(), 100);
    }

    #[test]
    fn test_session_timeout() {
        let config = ServerConfig::default();
        assert_eq!(config.session_timeout(), Duration::from_secs(180));
    }

    #[test]
    fn test_keepalive_interval() {
        let config = ServerConfig::default();
        assert_eq!(config.keepalive_interval(), Duration::from_secs(25));
    }

    #[test]
    fn test_config_serialization() {
        let config = ServerConfig::default();
        let serialized = toml::to_string(&config);
        assert!(serialized.is_ok());
        // Verify deprecated fields are not serialized
        let s = serialized.unwrap();
        assert!(!s.contains("enable_io_uring"));
        assert!(!s.contains("tun_num_queues"));
        assert!(!s.contains("afxdp"));
    }

    #[test]
    fn test_backward_compat_deprecated_fields() {
        // Old config with deprecated fields should still parse
        let toml = r#"
            listen_addr = "0.0.0.0:51820"
            ipv4_pool = "10.0.0.0/24"
            server_tunnel_ip = "10.0.0.1"
            dns_servers = ["8.8.8.8"]
            security_level = "level3"
            enable_io_uring = true
            tun_num_queues = 4
            enable_afxdp = true
        "#;
        let config: Result<ServerConfig, _> = toml::from_str(toml);
        assert!(config.is_ok());
    }

    #[test]
    fn test_validate_ok() {
        let config = ServerConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_server_ip_not_in_pool() {
        let mut config = ServerConfig::default();
        config.server_tunnel_ip = "192.168.1.1".into();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_invalid_mtu() {
        let mut config = ServerConfig::default();
        config.mtu = 100;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_require_auth_without_db_path_uses_default() {
        let mut config = ServerConfig::default();
        config.require_auth = true;
        config.users_db_path = None;
        assert!(config.validate().is_ok());
        assert_eq!(
            config.users_db_path_or_default(),
            PathBuf::from(ServerConfig::DEFAULT_USERS_DB_PATH)
        );
    }

    #[test]
    fn test_serde_alias_requires_auth_is_supported() {
        let toml = r#"
            listen_addr = "0.0.0.0:51820"
            ipv4_pool = "10.0.0.0/24"
            server_tunnel_ip = "10.0.0.1"
            dns_servers = ["8.8.8.8"]
            users_db_path = "/tmp/hpn-users.db"
            requires_auth = true
        "#;
        let config: ServerConfig = toml::from_str(toml).expect("config should parse");
        assert!(config.require_auth);
    }

    // ─── Audit H9 — metrics endpoint auth/loopback regression guards ───

    #[test]
    fn test_validate_rejects_metrics_non_loopback_without_admin_api() {
        // Audit H9: enable_metrics + non-loopback bind + admin API
        // disabled (= no auth path) MUST fail validation.
        let mut config = ServerConfig::default();
        config.enable_metrics = true;
        config.metrics_addr = "0.0.0.0:9100".parse().unwrap();
        config.enable_admin_api = false;
        let err = config
            .validate()
            .expect_err("non-loopback metrics without admin API must fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("metrics_addr") && msg.contains("loopback"),
            "error must mention metrics_addr + loopback, got: {msg}"
        );
    }

    #[test]
    fn test_validate_rejects_metrics_non_loopback_admin_api_no_token() {
        // Even with admin API enabled, the token must be set and >=24
        // chars; otherwise the auth path is open.
        let mut config = ServerConfig::default();
        config.enable_metrics = true;
        config.metrics_addr = "0.0.0.0:9100".parse().unwrap();
        config.enable_admin_api = true;
        config.admin_api_token = None;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_rejects_metrics_non_loopback_admin_api_short_token() {
        let mut config = ServerConfig::default();
        config.enable_metrics = true;
        config.metrics_addr = "0.0.0.0:9100".parse().unwrap();
        config.enable_admin_api = true;
        // 23 chars — one below the 24-char floor.
        config.admin_api_token = Some("x".repeat(23));
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_accepts_metrics_loopback_without_admin_api() {
        // 127.0.0.1 is the safe-by-default deployment.
        let mut config = ServerConfig::default();
        config.enable_metrics = true;
        config.metrics_addr = "127.0.0.1:9100".parse().unwrap();
        config.enable_admin_api = false;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_accepts_metrics_non_loopback_with_admin_api_token() {
        // The supported "remote scraping" path: bind anywhere AND
        // serve through an authenticated admin endpoint.
        let mut config = ServerConfig::default();
        config.enable_metrics = true;
        config.metrics_addr = "0.0.0.0:9100".parse().unwrap();
        config.enable_admin_api = true;
        config.admin_api_token = Some("sufficiently-long-32-byte-token!".into());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_accepts_disabled_metrics_regardless_of_addr() {
        let mut config = ServerConfig::default();
        config.enable_metrics = false;
        config.metrics_addr = "0.0.0.0:9100".parse().unwrap();
        config.enable_admin_api = false;
        assert!(config.validate().is_ok());
    }
}
