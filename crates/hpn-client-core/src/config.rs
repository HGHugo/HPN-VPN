//! Client configuration.

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use hpn_core::crypto::SecurityLevel;
use serde::{Deserialize, Serialize};

use crate::error::ClientError;

/// Helper to serialize/deserialize SecurityLevel as a string.
mod security_level_serde {
    use hpn_core::crypto::SecurityLevel;
    use serde::{Deserialize, Deserializer, Serializer};

    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn serialize<S>(level: &SecurityLevel, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = match level {
            SecurityLevel::Level3 => "level3",
            SecurityLevel::Level5 => "level5",
        };
        serializer.serialize_str(s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SecurityLevel, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.to_lowercase().as_str() {
            "level3" | "3" | "l3" | "768" => Ok(SecurityLevel::Level3),
            "level5" | "5" | "l5" | "1024" => Ok(SecurityLevel::Level5),
            _ => Err(serde::de::Error::custom(format!(
                "invalid security level '{}': expected 'level3' or 'level5'",
                s
            ))),
        }
    }
}

/// Client configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Server address (UDP).
    pub server_addr: SocketAddr,
    /// Server public key (base64 encoded ML-DSA-65 public key).
    pub server_public_key: String,
    /// Keepalive interval in seconds.
    #[serde(default = "default_keepalive_interval")]
    pub keepalive_interval_secs: u64,
    /// Connection timeout in seconds.
    #[serde(default = "default_connection_timeout")]
    pub connection_timeout_secs: u64,
    /// Rekey interval in seconds (how often to rotate keys).
    #[serde(default = "default_rekey_interval")]
    pub rekey_interval_secs: u64,
    /// Maximum bytes before triggering rekey.
    #[serde(default = "default_rekey_bytes")]
    pub rekey_after_bytes: u64,
    /// Number of missed keepalives before considering connection dead.
    #[serde(default = "default_keepalive_timeout_count")]
    pub keepalive_timeout_count: u32,
    /// Enable automatic reconnection on connection loss.
    #[serde(default = "default_auto_reconnect")]
    pub auto_reconnect: bool,
    /// Maximum reconnection attempts (0 = unlimited).
    #[serde(default = "default_max_reconnect_attempts")]
    pub max_reconnect_attempts: u32,
    /// Reconnect delay in seconds (with exponential backoff).
    #[serde(default = "default_reconnect_delay_secs")]
    pub reconnect_delay_secs: u64,
    /// Enable kill switch (block traffic when VPN is down).
    #[serde(default = "default_kill_switch")]
    pub kill_switch: bool,
    /// Allow LAN traffic when kill switch is active.
    #[serde(default = "default_allow_lan")]
    pub allow_lan: bool,
    /// Enable DNS leak protection.
    #[serde(default = "default_dns_leak_protection")]
    pub dns_leak_protection: bool,
    /// Split tunnel mode (false = full tunnel, true = split tunnel).
    #[serde(default)]
    pub split_tunnel: bool,
    /// IPv4 routes for split tunneling (CIDR notation).
    #[serde(default)]
    pub split_routes: Vec<String>,
    /// IPv6 routes for split tunneling (CIDR notation).
    #[serde(default)]
    pub split_routes_v6: Vec<String>,
    /// Enable TCP/443 fallback when UDP is blocked.
    #[serde(default = "default_tcp_fallback")]
    pub tcp_fallback: bool,
    /// TCP fallback server address (typically port 443).
    /// If not specified, uses server_addr with port 443.
    #[serde(default)]
    pub tcp_fallback_addr: Option<SocketAddr>,
    /// Number of UDP failures before switching to TCP fallback.
    #[serde(default = "default_tcp_fallback_threshold")]
    pub tcp_fallback_threshold: u32,
    /// Post-quantum security level for cryptographic operations.
    ///
    /// - "level3" (default): ML-KEM-768 + ML-DSA-65 (~AES-192 equivalent)
    /// - "level5": ML-KEM-1024 + ML-DSA-87 (~AES-256 equivalent, enterprise)
    ///
    /// Note: Server must support the requested level. If not, connection will fail.
    #[serde(default, with = "security_level_serde")]
    pub security_level: SecurityLevel,
    /// Server's KEM public key for identity hiding (base64 encoded, optional).
    ///
    /// If set, the client will use `EncryptedHandshakeInit` messages to hide its
    /// identity (ephemeral public key and client random) from passive observers.
    /// The server decrypts this using its KEM secret key before processing.
    ///
    /// This is a privacy enhancement that prevents network observers from
    /// fingerprinting clients based on their handshake initiation messages.
    ///
    /// **IMPORTANT**: Use the correct KEM key for your security level:
    /// - Level3 (Standard): Use `kem_keypair_level3.public_key` from server config
    /// - Level5 (High): Use `kem_keypair_level5.public_key` from server config
    ///
    /// The key includes a 1-byte security level prefix (as output by `hpn-server genkey`):
    /// - Level3: 1 + 32 (X25519) + 1184 (ML-KEM-768) = 1217 bytes (~1623 base64 chars)
    /// - Level5: 1 + 32 (X25519) + 1568 (ML-KEM-1024) = 1601 bytes (~2135 base64 chars)
    #[serde(default)]
    pub server_kem_public_key: Option<String>,
    /// Whether the server requires authentication.
    ///
    /// If true, the client must provide credentials (username/password) during connection.
    /// This flag is informational and should match the server's `require_auth` setting.
    /// When connecting to an auth-required server without credentials, the handshake will fail.
    #[serde(default)]
    pub requires_auth: bool,

    /// STUN servers used for NAT discovery / rebind detection.
    ///
    /// **Empty by default.** STUN binding requests are sent in clear text
    /// over UDP and expose the client's real IP to the listed servers,
    /// which is exactly the property a VPN is supposed to hide. To enable
    /// STUN, populate this list with servers the operator trusts —
    /// preferably self-hosted, ideally reached *through* the VPN tunnel
    /// after the handshake completes.
    ///
    /// Format: `host:port`, e.g. `stun.example.com:3478`. The first
    /// reachable server wins. When this list is empty, [`crate::nat::StunClient`]
    /// is **disabled** and `VpnClient::discover_nat` returns a
    /// `ClientError::Network`.
    #[serde(default)]
    pub stun_servers: Vec<String>,

    /// Strict mode for the audit-H11 ML-DSA-signed `RebindAck`.
    ///
    /// When `true` (default `false` for backward compatibility with
    /// servers that haven't yet rolled out the signed extension),
    /// the client REJECTS unsigned `RebindAck` messages and surfaces
    /// the rebind as failed. When `false`, an unsigned ack is logged
    /// at WARN and accepted as legacy behaviour, matching the
    /// pre-H11 protocol.
    ///
    /// Operators running an upgraded fleet (server + every relay
    /// emit signed RebindAck) should flip this to `true` to close
    /// the residual session-key-compromise vector that motivated
    /// audit H11. Mixed fleets keep the default until rollout
    /// completes.
    #[serde(default = "default_require_signed_rebind_ack")]
    pub require_signed_rebind_ack: bool,
}

fn default_keepalive_interval() -> u64 {
    25
}

fn default_connection_timeout() -> u64 {
    30
}

fn default_rekey_interval() -> u64 {
    3600 // 1 hour
}

fn default_rekey_bytes() -> u64 {
    64 * 1024 * 1024 * 1024 // 64 GB - high threshold for fast connections
}

fn default_keepalive_timeout_count() -> u32 {
    3 // 3 missed keepalives = connection dead
}

fn default_auto_reconnect() -> bool {
    true
}

fn default_max_reconnect_attempts() -> u32 {
    5 // 0 = unlimited
}

fn default_reconnect_delay_secs() -> u64 {
    5 // Initial delay, with exponential backoff
}

fn default_kill_switch() -> bool {
    true // Security: Kill switch enabled by default to prevent traffic leaks
}

fn default_allow_lan() -> bool {
    true
}

fn default_dns_leak_protection() -> bool {
    true
}

fn default_tcp_fallback() -> bool {
    false // Disabled by default, opt-in feature
}

fn default_tcp_fallback_threshold() -> u32 {
    3 // Switch to TCP after 3 UDP failures
}

fn default_require_signed_rebind_ack() -> bool {
    // Audit H11 / FIX-004: default ON. Every shipping HPN server emits
    // ML-DSA-signed `RebindAck` messages (the matching code path is in
    // `hpn-server/src/server.rs::send_rebind_ack*`). Closing the residual
    // session-key-compromise vector that motivated H11 requires the
    // client to refuse unsigned acks, which is what `true` does here.
    //
    // Operators still running an out-of-fleet server (older release that
    // never enabled signing) can opt back into the legacy behaviour by
    // setting `require_signed_rebind_ack = false` in client.toml; the
    // client then logs at WARN on every unsigned ack but accepts it.
    true
}

impl ClientConfig {
    /// Load configuration from a TOML file.
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self, ClientError> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| ClientError::Config(format!("failed to read config file: {}", e)))?;
        Self::load_from_str(&content)
    }

    /// Load configuration from a TOML string.
    pub fn load_from_str(content: &str) -> Result<Self, ClientError> {
        toml::from_str(content)
            .map_err(|e| ClientError::Config(format!("failed to parse config: {}", e)))
    }

    /// Save configuration to a TOML file.
    pub fn save_to_file(&self, path: impl AsRef<Path>) -> Result<(), ClientError> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| ClientError::Config(format!("failed to serialize config: {}", e)))?;
        std::fs::write(path.as_ref(), content)
            .map_err(|e| ClientError::Config(format!("failed to write config file: {}", e)))
    }

    /// Get the keepalive interval as a Duration.
    pub fn keepalive_interval(&self) -> Duration {
        Duration::from_secs(self.keepalive_interval_secs)
    }

    /// Get the connection timeout as a Duration.
    pub fn connection_timeout(&self) -> Duration {
        Duration::from_secs(self.connection_timeout_secs)
    }

    /// Get the rekey interval as a Duration.
    pub fn rekey_interval(&self) -> Duration {
        Duration::from_secs(self.rekey_interval_secs)
    }

    /// Get the keepalive timeout duration (keepalive_interval * keepalive_timeout_count).
    pub fn keepalive_timeout(&self) -> Duration {
        Duration::from_secs(self.keepalive_interval_secs * self.keepalive_timeout_count as u64)
    }

    /// Get the reconnect delay as a Duration.
    pub fn reconnect_delay(&self) -> Duration {
        Duration::from_secs(self.reconnect_delay_secs)
    }

    /// Calculate reconnect delay with exponential backoff.
    pub fn reconnect_delay_with_backoff(&self, attempt: u32) -> Duration {
        let base_delay = self.reconnect_delay_secs;
        let multiplier = 2u64.saturating_pow(attempt.min(5)); // Cap at 2^5 = 32x
        let delay = base_delay.saturating_mul(multiplier).min(300); // Max 5 minutes
        Duration::from_secs(delay)
    }

    /// Decode the server public key from base64.
    pub fn decode_server_public_key(&self) -> Result<Vec<u8>, ClientError> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        STANDARD
            .decode(&self.server_public_key)
            .map_err(|e| ClientError::Config(format!("invalid server public key: {}", e)))
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), ClientError> {
        if self.server_public_key.is_empty() {
            return Err(ClientError::Config("server public key is required".into()));
        }

        // Try to decode the public key to validate it
        let pk_bytes = self.decode_server_public_key()?;
        let expected_size = self.security_level.mldsa_public_key_size();
        if pk_bytes.len() != expected_size {
            return Err(ClientError::Config(format!(
                "invalid server public key length for {:?}: expected {}, got {}",
                self.security_level,
                expected_size,
                pk_bytes.len()
            )));
        }

        Ok(())
    }

    /// Get the TCP fallback address.
    ///
    /// If `tcp_fallback_addr` is set, returns it. Otherwise, derives it from
    /// `server_addr` by replacing the port with 443.
    pub fn tcp_fallback_address(&self) -> SocketAddr {
        self.tcp_fallback_addr.unwrap_or_else(|| {
            let mut addr = self.server_addr;
            addr.set_port(443);
            addr
        })
    }

    /// Create transport configuration for the primary (UDP) transport.
    pub fn primary_transport_config(&self) -> crate::transport::TransportConfig {
        crate::transport::TransportConfig::Udp {
            server_addr: self.server_addr,
        }
    }

    /// Create transport configuration for the fallback (TCP) transport.
    pub fn fallback_transport_config(&self) -> Option<crate::transport::TransportConfig> {
        if self.tcp_fallback {
            Some(crate::transport::TransportConfig::Tcp {
                server_addr: self.tcp_fallback_address(),
                connect_timeout_secs: Some(self.connection_timeout_secs),
                tls_sni: None, // Uses default SNI for DPI camouflage
            })
        } else {
            None
        }
    }

    /// Create a transport fallback manager from this configuration.
    pub fn transport_fallback(&self) -> crate::transport::TransportFallback {
        crate::transport::TransportFallback::new(
            self.primary_transport_config(),
            self.fallback_transport_config(),
        )
        .with_failure_threshold(self.tcp_fallback_threshold)
    }

    /// Get the security level for cryptographic operations.
    pub fn security_level(&self) -> SecurityLevel {
        self.security_level
    }

    /// Decode the server KEM public key from base64 (for identity hiding).
    ///
    /// The key is expected to include a 1-byte security level prefix, as output
    /// by `hpn-server genkey`. The function validates that the key's security
    /// level matches the configured `security_level`.
    ///
    /// Returns `None` if `server_kem_public_key` is not set.
    /// Returns an error if the key is set but invalid or mismatched.
    pub fn decode_server_kem_public_key(
        &self,
    ) -> Result<Option<hpn_core::crypto::HybridPublicKey>, ClientError> {
        use base64::{Engine, engine::general_purpose::STANDARD};

        let Some(ref key_str) = self.server_kem_public_key else {
            return Ok(None);
        };

        let key_bytes = STANDARD
            .decode(key_str)
            .map_err(|e| ClientError::Config(format!("invalid server KEM public key: {}", e)))?;

        // Parse the key (includes security level prefix from genkey output)
        let public_key =
            hpn_core::crypto::HybridPublicKey::from_bytes(&key_bytes).map_err(|e| {
                ClientError::Config(format!("failed to parse server KEM public key: {:?}", e))
            })?;

        // Validate that the key's security level matches the configured level
        if public_key.security_level != self.security_level {
            return Err(ClientError::Config(format!(
                "server KEM public key security level mismatch: key is {:?} but config is {:?}. \
                 Use the matching KEM key for your security level.",
                public_key.security_level, self.security_level
            )));
        }

        Ok(Some(public_key))
    }

    /// Check if identity hiding is enabled.
    ///
    /// Returns true if `server_kem_public_key` is set.
    pub fn identity_hiding_enabled(&self) -> bool {
        self.server_kem_public_key.is_some()
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server_addr: "127.0.0.1:51820".parse().unwrap(),
            server_public_key: String::new(),
            keepalive_interval_secs: default_keepalive_interval(),
            connection_timeout_secs: default_connection_timeout(),
            rekey_interval_secs: default_rekey_interval(),
            rekey_after_bytes: default_rekey_bytes(),
            keepalive_timeout_count: default_keepalive_timeout_count(),
            auto_reconnect: default_auto_reconnect(),
            max_reconnect_attempts: default_max_reconnect_attempts(),
            reconnect_delay_secs: default_reconnect_delay_secs(),
            kill_switch: default_kill_switch(),
            allow_lan: default_allow_lan(),
            dns_leak_protection: default_dns_leak_protection(),
            split_tunnel: false,
            split_routes: Vec::new(),
            split_routes_v6: Vec::new(),
            tcp_fallback: default_tcp_fallback(),
            tcp_fallback_addr: None,
            tcp_fallback_threshold: default_tcp_fallback_threshold(),
            security_level: SecurityLevel::default(),
            server_kem_public_key: None,
            requires_auth: false,
            stun_servers: Vec::new(),
            require_signed_rebind_ack: default_require_signed_rebind_ack(),
        }
    }
}

/// Runtime credentials for authentication.
///
/// This struct holds credentials that are provided at connection time,
/// NOT stored in configuration files (for security reasons).
/// Users should enter their password when connecting, and credentials
/// are zeroized after use.
///
/// Both fields are wrapped in [`zeroize::Zeroizing`]. The password is
/// the obvious secret, but the username is also wiped on drop because:
///
/// * It is privacy-sensitive PII (account-tracking surface across
///   sessions, cross-VPN correlation, etc.).
/// * Together with a password it forms a working login pair, so
///   zeroising both halves limits the window during which a memory
///   dump (post-mortem core file, hibernation image, swap) can yield
///   recoverable credentials. Zeroising only the password leaves the
///   username on the heap and gives a focused attacker the easier of
///   the two values.
///
/// Both fields keep `Deref<Target = String>` (and therefore
/// `Deref<Target = str>` transitively), so call sites that pass
/// `&creds.username` to a function taking `&str` continue to compile
/// unchanged.
#[derive(Clone)]
pub struct Credentials {
    /// Username (1-64 alphanumeric characters, `_`, `-`, `.`).
    ///
    /// Wrapped in `Zeroizing` so the underlying allocation is wiped
    /// when the struct drops — see the type-level doc for the threat
    /// model.
    pub username: zeroize::Zeroizing<String>,
    /// Password (minimum 8 characters, zeroized after use).
    pub password: zeroize::Zeroizing<String>,
}

impl Credentials {
    /// Create new credentials.
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: zeroize::Zeroizing::new(username.into()),
            password: zeroize::Zeroizing::new(password.into()),
        }
    }

    /// Create credentials with a pre-wrapped zeroizing password.
    ///
    /// Use this when the password is already in a `Zeroizing<String>` to avoid
    /// creating an unprotected copy via `.to_string()`.
    pub fn with_zeroizing_password(
        username: impl Into<String>,
        password: zeroize::Zeroizing<String>,
    ) -> Self {
        Self {
            username: zeroize::Zeroizing::new(username.into()),
            password,
        }
    }

    /// Create credentials when BOTH the username and the password are
    /// already in `Zeroizing<String>` wrappers.
    ///
    /// Used by the macOS Packet Tunnel Extension after deserialising
    /// the provider config (see `hpn-tunnel-ext::ProviderCredentials`):
    /// the username arrives wrapped from the serde deserialiser and we
    /// would otherwise have to unwrap → re-wrap, which materialises a
    /// non-zeroized intermediate `String` on the heap. Audit H8.
    pub fn with_zeroizing_credentials(
        username: zeroize::Zeroizing<String>,
        password: zeroize::Zeroizing<String>,
    ) -> Self {
        Self { username, password }
    }

    /// Validate credentials format.
    ///
    /// Returns an error if:
    /// - Username is empty or longer than 64 characters
    /// - Username contains invalid characters (only alphanumeric, `_`, `-`, `.` allowed)
    /// - Password is shorter than 8 characters or longer than 256 characters
    pub fn validate(&self) -> Result<(), ClientError> {
        // Username validation
        if self.username.is_empty() || self.username.len() > 64 {
            return Err(ClientError::Auth("username must be 1-64 characters".into()));
        }

        if !self
            .username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
        {
            return Err(ClientError::Auth(
                "username can only contain alphanumeric characters, '_', '-', '.'".into(),
            ));
        }

        // Password validation
        if self.password.len() < 8 {
            return Err(ClientError::Auth(
                "password must be at least 8 characters".into(),
            ));
        }

        if self.password.len() > 256 {
            return Err(ClientError::Auth(
                "password must be at most 256 characters".into(),
            ));
        }

        Ok(())
    }
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Show the username in Debug because it is needed for debugging
        // auth flows ("which user just failed?"), but Deref through
        // `Zeroizing<String>` so the formatted value is the inner
        // `String` (not the wrapper's Debug). The password is always
        // redacted.
        f.debug_struct("Credentials")
            .field("username", &*self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
#[allow(clippy::bool_assert_comparison)]
mod tests {
    use super::*;

    #[test]
    fn test_client_config_clone() {
        let config1 = ClientConfig::default();
        let config2 = config1.clone();

        assert_eq!(config1.server_addr, config2.server_addr);
        assert_eq!(
            config1.keepalive_interval_secs,
            config2.keepalive_interval_secs
        );
    }

    #[test]
    fn test_client_config_debug() {
        let config = ClientConfig::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("ClientConfig"));
    }

    #[test]
    fn test_load_from_str() {
        let toml = r#"
            server_addr = "10.0.0.1:51820"
            server_public_key = "dGVzdA=="
        "#;
        let config = ClientConfig::load_from_str(toml).unwrap();
        assert_eq!(config.server_addr.to_string(), "10.0.0.1:51820");
        // Default values should be applied
        assert_eq!(config.keepalive_interval_secs, 25);
    }

    #[test]
    fn test_config_durations() {
        let config = ClientConfig::default();
        assert_eq!(config.keepalive_interval(), Duration::from_secs(25));
        assert_eq!(config.connection_timeout(), Duration::from_secs(30));
        assert_eq!(config.rekey_interval(), Duration::from_secs(3600));
        assert_eq!(config.reconnect_delay(), Duration::from_secs(5));
    }

    #[test]
    fn test_keepalive_timeout() {
        let mut config = ClientConfig::default();
        config.keepalive_interval_secs = 10;
        config.keepalive_timeout_count = 3;
        assert_eq!(config.keepalive_timeout(), Duration::from_secs(30));
    }

    #[test]
    fn test_reconnect_delay_with_backoff() {
        let config = ClientConfig::default();
        // base delay = 5 seconds, multiplier capped at 2^5 = 32x
        assert_eq!(
            config.reconnect_delay_with_backoff(0),
            Duration::from_secs(5)
        ); // 5 * 2^0 = 5
        assert_eq!(
            config.reconnect_delay_with_backoff(1),
            Duration::from_secs(10)
        ); // 5 * 2^1 = 10
        assert_eq!(
            config.reconnect_delay_with_backoff(2),
            Duration::from_secs(20)
        ); // 5 * 2^2 = 20
        assert_eq!(
            config.reconnect_delay_with_backoff(3),
            Duration::from_secs(40)
        ); // 5 * 2^3 = 40
        assert_eq!(
            config.reconnect_delay_with_backoff(4),
            Duration::from_secs(80)
        ); // 5 * 2^4 = 80
        assert_eq!(
            config.reconnect_delay_with_backoff(5),
            Duration::from_secs(160)
        ); // 5 * 2^5 = 160 (capped at 2^5)
        assert_eq!(
            config.reconnect_delay_with_backoff(6),
            Duration::from_secs(160)
        ); // Still 5 * 2^5 = 160 (attempt capped)
        assert_eq!(
            config.reconnect_delay_with_backoff(10),
            Duration::from_secs(160)
        ); // Still 5 * 2^5 = 160
    }

    #[test]
    fn test_tcp_fallback_address_default() {
        let mut config = ClientConfig::default();
        config.server_addr = "10.0.0.1:51820".parse().unwrap();
        config.tcp_fallback_addr = None;

        // Should use server_addr IP with port 443
        let fallback = config.tcp_fallback_address();
        assert_eq!(fallback.to_string(), "10.0.0.1:443");
    }

    #[test]
    fn test_tcp_fallback_address_custom() {
        let mut config = ClientConfig::default();
        config.server_addr = "10.0.0.1:51820".parse().unwrap();
        config.tcp_fallback_addr = Some("10.0.0.2:8443".parse().unwrap());

        // Should use custom fallback address
        let fallback = config.tcp_fallback_address();
        assert_eq!(fallback.to_string(), "10.0.0.2:8443");
    }

    #[test]
    fn test_validate_missing_server_key() {
        let config = ClientConfig::default();
        let result = config.validate();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("server public key is required")
        );
    }

    #[test]
    fn test_decode_server_public_key() {
        let mut config = ClientConfig::default();
        // Valid base64 string
        config.server_public_key = "dGVzdA==".to_string();
        let result = config.decode_server_public_key();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"test");

        // Invalid base64
        config.server_public_key = "not-valid-base64!!!".to_string();
        let result = config.decode_server_public_key();
        assert!(result.is_err());
    }

    #[test]
    fn test_primary_transport_config() {
        let mut config = ClientConfig::default();
        config.server_addr = "192.168.1.1:51820".parse().unwrap();

        let transport = config.primary_transport_config();
        assert_eq!(transport.server_addr().to_string(), "192.168.1.1:51820");
        assert_eq!(
            transport.transport_type(),
            crate::transport::TransportType::Udp
        );
    }

    #[test]
    fn test_fallback_transport_config_disabled() {
        let mut config = ClientConfig::default();
        config.tcp_fallback = false;

        let fallback = config.fallback_transport_config();
        assert!(fallback.is_none());
    }

    #[test]
    fn test_fallback_transport_config_enabled() {
        let mut config = ClientConfig::default();
        config.server_addr = "192.168.1.1:51820".parse().unwrap();
        config.tcp_fallback = true;
        config.connection_timeout_secs = 15;

        let fallback = config.fallback_transport_config();
        assert!(fallback.is_some());

        let transport = fallback.unwrap();
        assert_eq!(transport.server_addr().to_string(), "192.168.1.1:443");
        assert_eq!(
            transport.transport_type(),
            crate::transport::TransportType::Tcp
        );
    }

    #[test]
    fn test_transport_fallback_manager() {
        let mut config = ClientConfig::default();
        config.server_addr = "192.168.1.1:51820".parse().unwrap();
        config.tcp_fallback = true;
        config.tcp_fallback_threshold = 5;

        let manager = config.transport_fallback();
        assert_eq!(manager.is_using_fallback(), false);
    }

    #[test]
    fn test_config_serialization_roundtrip() {
        let mut config = ClientConfig::default();
        config.server_addr = "192.168.1.1:51820".parse().unwrap();
        config.server_public_key = "dGVzdHB1YmxpY2tleQ==".to_string();
        config.tcp_fallback = true;
        config.kill_switch = true;
        config.split_tunnel = true;
        config.split_routes = vec!["10.0.0.0/8".to_string(), "192.168.0.0/16".to_string()];

        // Serialize to TOML
        let toml_str = toml::to_string(&config).unwrap();

        // Deserialize back
        let deserialized: ClientConfig = toml::from_str(&toml_str).unwrap();

        assert_eq!(deserialized.server_addr, config.server_addr);
        assert_eq!(deserialized.server_public_key, config.server_public_key);
        assert_eq!(deserialized.tcp_fallback, config.tcp_fallback);
        assert_eq!(deserialized.kill_switch, config.kill_switch);
        assert_eq!(deserialized.split_routes, config.split_routes);
    }

    #[test]
    fn test_config_defaults_applied() {
        let toml = r#"
            server_addr = "10.0.0.1:51820"
            server_public_key = "dGVzdA=="
        "#;
        let config = ClientConfig::load_from_str(toml).unwrap();

        // Verify defaults are applied
        assert_eq!(config.keepalive_interval_secs, 25);
        assert_eq!(config.connection_timeout_secs, 30);
        assert_eq!(config.rekey_interval_secs, 3600);
        assert_eq!(config.rekey_after_bytes, 64 * 1024 * 1024 * 1024);
        assert_eq!(config.keepalive_timeout_count, 3);
        assert_eq!(config.auto_reconnect, true);
        assert_eq!(config.max_reconnect_attempts, 5);
        assert_eq!(config.reconnect_delay_secs, 5);
        assert_eq!(config.kill_switch, true); // Security: Kill switch enabled by default
        assert_eq!(config.allow_lan, true);
        assert_eq!(config.dns_leak_protection, true);
        assert_eq!(config.tcp_fallback, false);
        assert_eq!(config.tcp_fallback_threshold, 3);
    }

    #[test]
    fn test_config_custom_values() {
        let toml = r#"
            server_addr = "10.0.0.1:51820"
            server_public_key = "dGVzdA=="
            keepalive_interval_secs = 10
            connection_timeout_secs = 60
            tcp_fallback = true
            tcp_fallback_threshold = 7
            kill_switch = true
            allow_lan = false
        "#;
        let config = ClientConfig::load_from_str(toml).unwrap();

        assert_eq!(config.keepalive_interval_secs, 10);
        assert_eq!(config.connection_timeout_secs, 60);
        assert_eq!(config.tcp_fallback, true);
        assert_eq!(config.tcp_fallback_threshold, 7);
        assert_eq!(config.kill_switch, true);
        assert_eq!(config.allow_lan, false);
    }

    #[test]
    fn test_config_invalid_toml() {
        let toml = r"
            this is not valid toml
        ";
        let result = ClientConfig::load_from_str(toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_server_kem_public_key_none() {
        let config = ClientConfig::default();
        let result = config.decode_server_kem_public_key();
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_decode_server_kem_public_key_valid_level3() {
        use base64::{Engine, engine::general_purpose::STANDARD};
        use hpn_core::crypto::{HybridKem, SecurityLevel};

        // Generate a valid Level 3 KEM keypair (like genkey does)
        let (_, public_key) = HybridKem::generate_keypair_with_level(SecurityLevel::Level3)
            .expect("keypair generation should succeed");

        // Encode with security level prefix (as genkey outputs)
        let key_b64 = STANDARD.encode(public_key.to_bytes());

        let mut config = ClientConfig::default();
        config.security_level = SecurityLevel::Level3;
        config.server_kem_public_key = Some(key_b64);

        let result = config.decode_server_kem_public_key();
        assert!(result.is_ok());
        let decoded = result.unwrap();
        assert!(decoded.is_some());
        assert_eq!(decoded.unwrap().security_level, SecurityLevel::Level3);
    }

    #[test]
    fn test_decode_server_kem_public_key_valid_level5() {
        use base64::{Engine, engine::general_purpose::STANDARD};
        use hpn_core::crypto::{HybridKem, SecurityLevel};

        // Generate a valid Level 5 KEM keypair
        let (_, public_key) = HybridKem::generate_keypair_with_level(SecurityLevel::Level5)
            .expect("keypair generation should succeed");

        // Encode with security level prefix
        let key_b64 = STANDARD.encode(public_key.to_bytes());

        let mut config = ClientConfig::default();
        config.security_level = SecurityLevel::Level5;
        config.server_kem_public_key = Some(key_b64);

        let result = config.decode_server_kem_public_key();
        assert!(result.is_ok());
        let decoded = result.unwrap();
        assert!(decoded.is_some());
        assert_eq!(decoded.unwrap().security_level, SecurityLevel::Level5);
    }

    #[test]
    fn test_decode_server_kem_public_key_mismatch() {
        use base64::{Engine, engine::general_purpose::STANDARD};
        use hpn_core::crypto::{HybridKem, SecurityLevel};

        // Generate a Level 5 key
        let (_, public_key) = HybridKem::generate_keypair_with_level(SecurityLevel::Level5)
            .expect("keypair generation should succeed");
        let key_b64 = STANDARD.encode(public_key.to_bytes());

        // But configure Level 3 in the client
        let mut config = ClientConfig::default();
        config.security_level = SecurityLevel::Level3;
        config.server_kem_public_key = Some(key_b64);

        let result = config.decode_server_kem_public_key();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("security level mismatch"),
            "expected security level mismatch error, got: {}",
            err
        );
    }

    #[test]
    fn test_decode_server_kem_public_key_invalid_base64() {
        let mut config = ClientConfig::default();
        config.server_kem_public_key = Some("not-valid-base64!!!".to_string());

        let result = config.decode_server_kem_public_key();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid server KEM public key")
        );
    }

    #[test]
    fn test_decode_server_kem_public_key_invalid_key() {
        use base64::{Engine, engine::general_purpose::STANDARD};

        let mut config = ClientConfig::default();
        // Valid base64 but not a valid key (too short)
        config.server_kem_public_key = Some(STANDARD.encode(b"tooshort"));

        let result = config.decode_server_kem_public_key();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("failed to parse server KEM public key")
        );
    }
}
