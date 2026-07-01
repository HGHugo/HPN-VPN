//! Relay configuration.

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{RelayError, RelayResult};

/// Relay server configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    /// Listen address for incoming client connections.
    pub listen_addr: SocketAddr,

    /// Upstream server/relay address to forward packets to.
    pub upstream_addr: SocketAddr,

    /// Maximum number of concurrent sessions.
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,

    /// Session timeout in seconds (idle sessions are cleaned up).
    #[serde(default = "default_session_timeout")]
    pub session_timeout_secs: u64,

    /// Buffer size for UDP packets.
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,

    /// Enable relay logging output.
    #[serde(default = "default_log_enabled")]
    pub log_enabled: bool,

    /// Path to log file (optional). When set, logs are written to file + stdout.
    #[serde(default)]
    pub log_file: Option<String>,

    /// Maximum log file size in MB before rotation. Default: 100 MB.
    #[serde(default = "default_log_max_size_mb")]
    pub log_max_size_mb: u64,

    /// Maximum number of rotated log files to keep. Default: 5.
    #[serde(default = "default_log_max_files")]
    pub log_max_files: u32,

    /// Enable logging of packet statistics.
    #[serde(default)]
    pub enable_stats: bool,

    /// Stats reporting interval in seconds.
    #[serde(default = "default_stats_interval")]
    pub stats_interval_secs: u64,

    /// Optional relay ID for multi-relay deployments.
    #[serde(default)]
    pub relay_id: Option<String>,

    /// Rate limiting: max packets per second per session.
    #[serde(default)]
    pub rate_limit_pps: Option<u32>,

    /// Rate limiting: max bytes per second per session.
    #[serde(default)]
    pub rate_limit_bps: Option<u64>,

    /// Max concurrent handshake forwarding tasks.
    #[serde(default)]
    pub max_concurrent_handshakes: Option<usize>,

    /// Max handshake packets per second per source IP.
    #[serde(default)]
    pub handshake_rate_limit_pps: Option<u32>,

    /// Max new handshakes per second across ALL source IPs combined.
    ///
    /// Independent of `handshake_rate_limit_pps`. A source-IP-based limiter
    /// alone is trivially bypassable by IP spoofing: an attacker cycling
    /// through N random source IPs can push `N × rate_limit_pps` handshakes
    /// per second, each consuming a concurrent-handshake permit for up to 10s
    /// — enough to squat every slot and deny the service to legitimate
    /// clients.
    ///
    /// This global ceiling rejects excess handshakes with a single atomic
    /// compare, before the per-IP map is ever consulted. Set to `0` to
    /// disable (not recommended on public-facing deployments). Default:
    /// 256 pps (matches the default concurrent-handshake semaphore).
    #[serde(default)]
    pub handshake_global_rate_limit_pps: Option<u32>,

    /// Enable Prometheus metrics HTTP endpoint.
    #[serde(default)]
    pub enable_metrics: bool,

    /// Metrics HTTP server address (e.g., "127.0.0.1:9101").
    #[serde(default = "default_metrics_addr")]
    pub metrics_addr: SocketAddr,

    /// Bearer token required to access the metrics endpoint.
    ///
    /// Strongly recommended whenever `metrics_addr` binds to a non-loopback
    /// interface. Clients must send `Authorization: Bearer <token>`. The
    /// server refuses to start if metrics are exposed on a public interface
    /// with no token configured (unless the operator overrides by binding
    /// to `127.0.0.1`).
    #[serde(default)]
    pub metrics_auth_token: Option<String>,

    /// No-log mode: suppress IP addresses and session details from logs.
    /// Only uptime is sent in heartbeat when enabled.
    #[serde(default = "default_true")]
    pub no_log: bool,

    /// Deprecated and ignored. Retained so pre-existing relay.toml files
    /// containing `license_key = "..."` still parse (the struct uses
    /// deny_unknown_fields). HPN is now open-source — no license checked.
    #[serde(default)]
    pub license_key: Option<String>,
}

fn default_metrics_addr() -> SocketAddr {
    "127.0.0.1:9101".parse().unwrap()
}

fn default_max_sessions() -> usize {
    10000
}

fn default_session_timeout() -> u64 {
    180
}

fn default_buffer_size() -> usize {
    65535
}

fn default_log_enabled() -> bool {
    true
}

fn default_log_max_size_mb() -> u64 {
    100
}

fn default_log_max_files() -> u32 {
    5
}

fn default_true() -> bool {
    true
}

fn default_stats_interval() -> u64 {
    60
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:51821".parse().unwrap(),
            upstream_addr: "127.0.0.1:51820".parse().unwrap(),
            max_sessions: default_max_sessions(),
            session_timeout_secs: default_session_timeout(),
            buffer_size: default_buffer_size(),
            log_enabled: default_log_enabled(),
            log_file: None,
            log_max_size_mb: default_log_max_size_mb(),
            log_max_files: default_log_max_files(),
            enable_stats: false,
            stats_interval_secs: default_stats_interval(),
            relay_id: None,
            rate_limit_pps: None,
            rate_limit_bps: None,
            max_concurrent_handshakes: None,
            handshake_rate_limit_pps: None,
            handshake_global_rate_limit_pps: None,
            enable_metrics: false,
            metrics_addr: default_metrics_addr(),
            metrics_auth_token: None,
            no_log: true,
            license_key: None,
        }
    }
}

/// Maximum config file size (1 MB) to prevent DoS via large files.
const MAX_CONFIG_FILE_SIZE: u64 = 1024 * 1024;

impl RelayConfig {
    /// Load configuration from a TOML file.
    ///
    /// Enforces a file size limit to prevent DoS attacks via large config files.
    pub fn load_from_file(path: impl AsRef<Path>) -> RelayResult<Self> {
        // Check file size before reading to prevent DoS
        let metadata = std::fs::metadata(path.as_ref())
            .map_err(|e| RelayError::Config(format!("failed to read config metadata: {}", e)))?;

        if metadata.len() > MAX_CONFIG_FILE_SIZE {
            return Err(RelayError::Config(format!(
                "config file too large: {} bytes (max: {} bytes)",
                metadata.len(),
                MAX_CONFIG_FILE_SIZE
            )));
        }

        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| RelayError::Config(format!("failed to read config: {}", e)))?;
        Self::load_from_str(&content)
    }

    /// Load configuration from a TOML string.
    pub fn load_from_str(content: &str) -> RelayResult<Self> {
        #[derive(Debug, Deserialize)]
        struct RelayConfigWrapper {
            relay: RelayConfig,
        }

        match toml::from_str::<RelayConfig>(content) {
            Ok(config) => Ok(config),
            Err(root_err) => match toml::from_str::<RelayConfigWrapper>(content) {
                Ok(wrapper) => Ok(wrapper.relay),
                Err(_) => Err(RelayError::Config(format!(
                    "failed to parse config: {}",
                    root_err
                ))),
            },
        }
    }

    /// Save configuration to a TOML file.
    pub fn save_to_file(&self, path: impl AsRef<Path>) -> RelayResult<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| RelayError::Config(format!("failed to serialize config: {}", e)))?;
        std::fs::write(path.as_ref(), content)
            .map_err(|e| RelayError::Config(format!("failed to write config: {}", e)))
    }

    /// Get the session timeout as a Duration.
    #[must_use]
    pub fn session_timeout(&self) -> Duration {
        Duration::from_secs(self.session_timeout_secs)
    }

    /// Get the stats interval as a Duration.
    #[must_use]
    pub fn stats_interval(&self) -> Duration {
        Duration::from_secs(self.stats_interval_secs)
    }

    /// Validate the configuration.
    pub fn validate(&self) -> RelayResult<()> {
        if self.max_sessions == 0 {
            return Err(RelayError::Config("max_sessions must be > 0".into()));
        }
        if self.session_timeout_secs < 10 {
            return Err(RelayError::Config(
                "session_timeout_secs must be >= 10".into(),
            ));
        }
        if self.buffer_size < 1500 {
            return Err(RelayError::Config("buffer_size must be >= 1500".into()));
        }
        if let Some(max) = self.max_concurrent_handshakes
            && max == 0
        {
            return Err(RelayError::Config(
                "max_concurrent_handshakes must be > 0 when set".into(),
            ));
        }
        if let Some(pps) = self.handshake_rate_limit_pps
            && pps == 0
        {
            return Err(RelayError::Config(
                "handshake_rate_limit_pps must be > 0 when set".into(),
            ));
        }

        // Prevent relay loopback (forwarding to itself)
        if self.listen_addr == self.upstream_addr {
            return Err(RelayError::Config(
                "upstream_addr cannot be the same as listen_addr (would create infinite loop)"
                    .into(),
            ));
        }

        // Check for localhost loopback with same port
        let listen_is_any = self.listen_addr.ip().is_unspecified();
        let upstream_is_localhost = self.upstream_addr.ip().is_loopback();
        if listen_is_any
            && upstream_is_localhost
            && self.listen_addr.port() == self.upstream_addr.port()
        {
            return Err(RelayError::Config(
                "upstream_addr points to localhost on same port as listen_addr (would create infinite loop)".into(),
            ));
        }

        // Audit H9 — refuse to start if Prometheus metrics are exposed on
        // a non-loopback interface without an auth token. Anyone able to
        // reach the metrics endpoint can fingerprint the relay (active
        // session counts, byte counters, drop counters) —
        // exactly the reconnaissance an attacker wants before launching a
        // targeted DoS or trying to time a credential-stuffing wave. The
        // earlier release only logged a `warn!`; we now hard-fail so a
        // misconfiguration cannot ship to production silently.
        if self.enable_metrics && !self.metrics_addr.ip().is_loopback() {
            let needs_auth = match self.metrics_auth_token.as_deref() {
                None => true,
                Some(t) if t.trim().len() < 16 => true,
                Some(_) => false,
            };
            if needs_auth {
                return Err(RelayError::Config(format!(
                    "enable_metrics is true and metrics_addr ({}) is not a \
                     loopback address, but metrics_auth_token is missing or \
                     shorter than 16 characters. Either bind to 127.0.0.1, \
                     or configure a strong (>=16 character) bearer token.",
                    self.metrics_addr
                )));
            }
        }

        Ok(())
    }

    /// Check if rate limiting is configured.
    /// Returns true if at least one rate limit is set.
    pub fn has_rate_limits(&self) -> bool {
        self.rate_limit_pps.is_some() || self.rate_limit_bps.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = RelayConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_roundtrip() {
        let config = RelayConfig {
            listen_addr: "0.0.0.0:51821".parse().unwrap(),
            upstream_addr: "192.168.1.1:51820".parse().unwrap(),
            max_sessions: 5000,
            session_timeout_secs: 300,
            buffer_size: 65535,
            log_enabled: true,
            log_file: None,
            log_max_size_mb: 100,
            log_max_files: 5,
            enable_stats: true,
            stats_interval_secs: 30,
            relay_id: Some("relay-1".into()),
            rate_limit_pps: Some(10000),
            rate_limit_bps: Some(100_000_000),
            max_concurrent_handshakes: Some(512),
            handshake_rate_limit_pps: Some(128),
            handshake_global_rate_limit_pps: Some(512),
            enable_metrics: true,
            metrics_addr: "127.0.0.1:9101".parse().unwrap(),
            metrics_auth_token: None,
            no_log: true,
            license_key: None,
        };

        let toml = toml::to_string_pretty(&config).unwrap();
        let parsed = RelayConfig::load_from_str(&toml).unwrap();

        assert_eq!(config.max_sessions, parsed.max_sessions);
        assert_eq!(config.relay_id, parsed.relay_id);
    }

    #[test]
    fn test_load_config_with_relay_section_wrapper() {
        let content = r#"
[relay]
listen_addr = "0.0.0.0:51821"
upstream_addr = "127.0.0.1:51820"
max_sessions = 10000
session_timeout_secs = 180
buffer_size = 65535
enable_stats = true
stats_interval_secs = 60
relay_id = "relay-compat"
"#;

        let config = RelayConfig::load_from_str(content).expect("wrapper config should parse");
        assert_eq!(config.listen_addr, "0.0.0.0:51821".parse().unwrap());
        assert_eq!(config.upstream_addr, "127.0.0.1:51820".parse().unwrap());
        assert_eq!(config.relay_id.as_deref(), Some("relay-compat"));
    }

    #[test]
    fn test_loopback_detection() {
        // Same address should fail
        let config = RelayConfig {
            listen_addr: "0.0.0.0:51820".parse().unwrap(),
            upstream_addr: "0.0.0.0:51820".parse().unwrap(),
            ..Default::default()
        };
        assert!(config.validate().is_err());

        // Localhost with same port should fail
        let config = RelayConfig {
            listen_addr: "0.0.0.0:51820".parse().unwrap(),
            upstream_addr: "127.0.0.1:51820".parse().unwrap(),
            ..Default::default()
        };
        assert!(config.validate().is_err());

        // Different ports should pass
        let config = RelayConfig {
            listen_addr: "0.0.0.0:51821".parse().unwrap(),
            upstream_addr: "127.0.0.1:51820".parse().unwrap(),
            ..Default::default()
        };
        assert!(config.validate().is_ok());

        // Different IPs should pass
        let config = RelayConfig {
            listen_addr: "0.0.0.0:51820".parse().unwrap(),
            upstream_addr: "192.168.1.1:51820".parse().unwrap(),
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_rate_limit_check() {
        let mut config = RelayConfig::default();
        assert!(!config.has_rate_limits());

        config.rate_limit_pps = Some(1000);
        assert!(config.has_rate_limits());

        config.rate_limit_pps = None;
        config.rate_limit_bps = Some(1_000_000);
        assert!(config.has_rate_limits());
    }

    #[test]
    fn test_default_values() {
        let config = RelayConfig::default();
        assert_eq!(config.listen_addr.to_string(), "0.0.0.0:51821");
        assert_eq!(config.upstream_addr.to_string(), "127.0.0.1:51820");
        assert_eq!(config.max_sessions, 10000);
        assert_eq!(config.session_timeout_secs, 180);
        assert_eq!(config.buffer_size, 65535);
        assert!(config.log_enabled);
        assert!(!config.enable_stats);
        assert_eq!(config.stats_interval_secs, 60);
        assert!(config.relay_id.is_none());
        assert!(config.rate_limit_pps.is_none());
        assert!(config.rate_limit_bps.is_none());
        assert!(!config.enable_metrics);
    }

    #[test]
    fn test_session_timeout() {
        let config = RelayConfig::default();
        let timeout = config.session_timeout();
        assert_eq!(timeout, Duration::from_secs(180));
    }

    #[test]
    fn test_stats_interval() {
        let config = RelayConfig::default();
        let interval = config.stats_interval();
        assert_eq!(interval, Duration::from_secs(60));
    }

    #[test]
    fn test_config_clone() {
        let config1 = RelayConfig::default();
        let config2 = config1.clone();

        assert_eq!(config1.listen_addr, config2.listen_addr);
        assert_eq!(config1.upstream_addr, config2.upstream_addr);
        assert_eq!(config1.max_sessions, config2.max_sessions);
    }

    #[test]
    fn test_config_debug() {
        let config = RelayConfig::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("RelayConfig"));
    }

    #[test]
    fn test_custom_buffer_size() {
        let config = RelayConfig {
            buffer_size: 32768,
            ..Default::default()
        };
        assert_eq!(config.buffer_size, 32768);
    }

    #[test]
    fn test_relay_id_optional() {
        let mut config = RelayConfig::default();
        assert!(config.relay_id.is_none());

        config.relay_id = Some("test-relay".to_string());
        assert_eq!(config.relay_id, Some("test-relay".to_string()));
    }

    #[test]
    fn test_metrics_configuration() {
        let config = RelayConfig::default();
        assert!(!config.enable_metrics);
        assert_eq!(config.metrics_addr.to_string(), "127.0.0.1:9101");

        let config_enabled = RelayConfig {
            enable_metrics: true,
            metrics_addr: "0.0.0.0:8080".parse().unwrap(),
            ..Default::default()
        };
        assert!(config_enabled.enable_metrics);
        assert_eq!(config_enabled.metrics_addr.to_string(), "0.0.0.0:8080");
    }

    #[test]
    fn test_rate_limits_both_set() {
        let config = RelayConfig {
            rate_limit_pps: Some(5000),
            rate_limit_bps: Some(50_000_000),
            ..Default::default()
        };

        assert!(config.has_rate_limits());
        assert_eq!(config.rate_limit_pps, Some(5000));
        assert_eq!(config.rate_limit_bps, Some(50_000_000));
    }

    #[test]
    fn test_validate_valid_config() {
        let config = RelayConfig {
            listen_addr: "0.0.0.0:51821".parse().unwrap(),
            upstream_addr: "10.0.0.1:51820".parse().unwrap(),
            max_sessions: 1000,
            session_timeout_secs: 60,
            buffer_size: 32768,
            log_enabled: true,
            log_file: None,
            log_max_size_mb: 100,
            log_max_files: 5,
            enable_stats: true,
            stats_interval_secs: 30,
            relay_id: Some("relay-test".into()),
            rate_limit_pps: Some(1000),
            rate_limit_bps: Some(10_000_000),
            max_concurrent_handshakes: Some(128),
            handshake_rate_limit_pps: Some(32),
            handshake_global_rate_limit_pps: Some(128),
            enable_metrics: true,
            metrics_addr: "127.0.0.1:9100".parse().unwrap(),
            metrics_auth_token: None,
            no_log: true,
            license_key: None,
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_zero_max_sessions() {
        let config = RelayConfig {
            max_sessions: 0,
            ..Default::default()
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_zero_buffer_size() {
        let config = RelayConfig {
            buffer_size: 0,
            ..Default::default()
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_load_from_str_valid() {
        let toml = r#"
            listen_addr = "0.0.0.0:51821"
            upstream_addr = "127.0.0.1:51820"
            max_sessions = 5000
            session_timeout_secs = 300
            buffer_size = 65535
            log_enabled = true
        "#;

        let result = RelayConfig::load_from_str(toml);
        assert!(result.is_ok());
    }

    #[test]
    fn test_load_from_str_invalid() {
        let toml = "this is not valid toml {{{";

        let result = RelayConfig::load_from_str(toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_has_rate_limits_neither_set() {
        let config = RelayConfig {
            rate_limit_pps: None,
            rate_limit_bps: None,
            ..Default::default()
        };

        assert!(!config.has_rate_limits());
    }

    // ─── Audit H9 — metrics endpoint auth/loopback regression guards ───

    #[test]
    fn test_validate_rejects_metrics_non_loopback_without_token() {
        // Audit H9: enable_metrics + non-loopback bind + no token
        // MUST fail validation (otherwise an attacker on the LAN can
        // scrape session counts, drop counters).
        let config = RelayConfig {
            enable_metrics: true,
            metrics_addr: "0.0.0.0:9100".parse().unwrap(),
            metrics_auth_token: None,
            ..Default::default()
        };
        let err = config
            .validate()
            .expect_err("non-loopback + no token must fail");
        assert!(format!("{err}").contains("metrics_auth_token"));
    }

    #[test]
    fn test_validate_rejects_metrics_non_loopback_with_short_token() {
        // A token with <16 effective chars (after trim) is treated as
        // "no token" — Argon2 + ct_eq don't rescue entropy that isn't
        // there.
        let config = RelayConfig {
            enable_metrics: true,
            metrics_addr: "0.0.0.0:9100".parse().unwrap(),
            metrics_auth_token: Some("   short   ".into()),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_accepts_metrics_loopback_without_token() {
        // 127.0.0.1 bind is intrinsically reachable only from the same
        // host, so the absence of a token is acceptable — the operator
        // is expected to front it with an authenticated reverse proxy.
        let config = RelayConfig {
            enable_metrics: true,
            metrics_addr: "127.0.0.1:9100".parse().unwrap(),
            metrics_auth_token: None,
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_accepts_metrics_non_loopback_with_strong_token() {
        // The escape hatch: non-loopback with a 16+ char bearer token
        // is the supported "remote scraping" path.
        let config = RelayConfig {
            enable_metrics: true,
            metrics_addr: "0.0.0.0:9100".parse().unwrap(),
            metrics_auth_token: Some("a-strong-token-32-chars-long!".into()),
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_accepts_disabled_metrics_regardless_of_addr() {
        // If metrics are disabled, the addr / token are irrelevant.
        let config = RelayConfig {
            enable_metrics: false,
            metrics_addr: "0.0.0.0:9100".parse().unwrap(),
            metrics_auth_token: None,
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }
}
