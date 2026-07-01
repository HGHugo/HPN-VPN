//! Configuration management for the HPN VPN client.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::error::{AppError, AppResult};

/// Get the configuration directory path.
pub fn get_config_dir() -> AppResult<PathBuf> {
    let config_dir = dirs::config_dir()
        .ok_or_else(|| AppError::Config("Could not find config directory".into()))?
        .join("hpn-vpn");

    if !config_dir.exists() {
        std::fs::create_dir_all(&config_dir)?;
    }

    Ok(config_dir)
}

/// Get the legacy plaintext profiles file path.
///
/// Pre-DPAPI installs wrote `profiles.json` in clear here. The current
/// build still reads it on first launch to migrate existing data into
/// the encrypted store at [`get_profiles_enc_path`], then deletes the
/// plaintext file. New writes always go through the encrypted path
/// when running on Windows; on other platforms (typically a developer
/// cross-compile build of the Tauri shell) we keep the JSON path
/// because DPAPI is unavailable.
pub fn get_profiles_path() -> AppResult<PathBuf> {
    Ok(get_config_dir()?.join("profiles.json"))
}

/// Get the DPAPI-encrypted profiles file path (Windows only).
///
/// The file contents are an opaque DPAPI blob produced by
/// [`crate::dpapi::encrypt`]. Wrapping with the current user's DPAPI
/// key prevents trivial exfiltration via `%APPDATA%` copy / OneDrive
/// sync / support bundle: the bytes are useless on a different
/// machine or under a different user account. See `dpapi.rs` for the
/// full threat model. Audit H10 (CRED-1 follow-up).
#[cfg(windows)]
pub fn get_profiles_enc_path() -> AppResult<PathBuf> {
    Ok(get_config_dir()?.join("profiles.enc"))
}

/// Get the settings file path.
pub fn get_settings_path() -> AppResult<PathBuf> {
    Ok(get_config_dir()?.join("settings.json"))
}

/// Get the logs directory path.
pub fn get_logs_dir() -> AppResult<PathBuf> {
    let logs_dir = get_config_dir()?.join("logs");

    if !logs_dir.exists() {
        std::fs::create_dir_all(&logs_dir)?;
    }

    Ok(logs_dir)
}

/// Security level for cryptographic operations.
///
/// - `standard`: NIST Level 3 - ML-KEM-768 + ML-DSA-65 (~AES-192 equivalent)
/// - `high`: NIST Level 5 - ML-KEM-1024 + ML-DSA-87 (~AES-256 equivalent)
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SecurityLevel {
    /// NIST Level 3: ML-KEM-768 + ML-DSA-65 (default, ~AES-192 equivalent)
    #[default]
    Standard,
    /// NIST Level 5: ML-KEM-1024 + ML-DSA-87 (enterprise, ~AES-256 equivalent)
    High,
}

impl SecurityLevel {
    /// Convert to hpn_core::crypto::SecurityLevel.
    #[must_use]
    #[allow(dead_code)] // Used in connect() but clippy on macOS doesn't see Windows target usage
    pub fn to_core_level(self) -> hpn_core::crypto::SecurityLevel {
        match self {
            Self::Standard => hpn_core::crypto::SecurityLevel::Level3,
            Self::High => hpn_core::crypto::SecurityLevel::Level5,
        }
    }
}

/// VPN connection profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    /// Unique profile ID.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Server hostname or IP.
    pub server: String,
    /// Server port.
    pub port: u16,
    /// Server public key (base64 encoded).
    pub server_public_key: String,
    /// Whether this profile has been verified.
    #[serde(default)]
    pub verified: bool,
    /// Security level: "standard" (ML-KEM-768) or "high" (ML-KEM-1024).
    #[serde(default)]
    pub security_level: SecurityLevel,
    /// Server KEM public key for identity hiding (base64 encoded, optional).
    #[serde(default)]
    pub server_kem_public_key: Option<String>,
    /// Whether this server requires user authentication.
    #[serde(default)]
    pub requires_auth: bool,
    /// Username for authentication (stored for display, password entered at connect).
    #[serde(default)]
    pub username: Option<String>,
    /// Split tunnel configuration.
    #[serde(default)]
    pub split_tunnel: Option<SplitTunnelConfig>,
}

/// Split tunnel configuration.
///
/// Note: App-based split tunneling is not currently supported on Windows.
/// Only route-based split tunneling (bypass mode) is available.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SplitTunnelConfig {
    /// Whether split tunneling is enabled.
    pub enabled: bool,
    /// Mode: "full" (all traffic) or "bypass" (exclude routes).
    pub mode: String,
    /// Routes to bypass (CIDR notation, comma-separated). Used in "bypass" mode.
    #[serde(default)]
    pub routes: Option<String>,
    /// Bypass local network traffic.
    #[serde(default)]
    pub bypass_local: bool,
    /// Allow LAN discovery (mDNS, Bonjour, etc.).
    #[serde(default)]
    pub bypass_discovery: bool,
}

/// Application settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    /// Dark mode enabled.
    #[serde(default = "default_true")]
    pub dark_mode: bool,
    /// Auto-reconnect on connection loss.
    #[serde(default = "default_true")]
    pub auto_reconnect: bool,
    /// Kill switch (always enabled, cannot be disabled).
    #[serde(default = "default_true")]
    pub kill_switch: bool,
    /// Automatic key rotation.
    #[serde(default = "default_true")]
    pub auto_rekey: bool,
    /// UI language ("EN" or "FR").
    #[serde(default = "default_lang")]
    pub language: String,
    /// Keepalive interval in seconds.
    #[serde(default = "default_keepalive")]
    pub keepalive_interval: u64,
    /// Connection timeout in seconds.
    #[serde(default = "default_timeout")]
    pub connection_timeout: u64,
}

fn default_true() -> bool {
    true
}
fn default_lang() -> String {
    "EN".to_string()
}
fn default_keepalive() -> u64 {
    25
}
fn default_timeout() -> u64 {
    30
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            dark_mode: true,
            auto_reconnect: true,
            kill_switch: true,
            auto_rekey: true,
            language: "EN".to_string(),
            keepalive_interval: 25,
            connection_timeout: 30,
        }
    }
}

/// Load profiles from disk.
///
/// On Windows the new encrypted `profiles.enc` is read first; if that
/// file does not exist yet, we fall back to the legacy plaintext
/// `profiles.json` and rely on the next [`save_profiles`] to migrate
/// the data. On other platforms (developer cross-compile builds) only
/// the JSON path is read because DPAPI is unavailable.
pub fn load_profiles() -> AppResult<Vec<Profile>> {
    // ── Encrypted store (Windows only, preferred) ────────────────────
    #[cfg(windows)]
    {
        let enc_path = get_profiles_enc_path()?;
        if enc_path.exists() {
            match std::fs::read(&enc_path) {
                Ok(ct) => match crate::dpapi::decrypt(&ct) {
                    Ok(pt) => {
                        let profiles: Vec<Profile> = serde_json::from_slice(&pt)?;
                        return Ok(profiles);
                    }
                    Err(e) => {
                        // DPAPI failure is unusual but recoverable: the
                        // user still has the legacy `profiles.json` to
                        // fall back to (until the next save migrates
                        // it). We log loud at warn so the failure is
                        // visible in the support bundle.
                        tracing::warn!(
                            "DPAPI decrypt of {} failed: {}. Falling back to plaintext profiles.json if present.",
                            enc_path.display(),
                            e
                        );
                    }
                },
                Err(e) => {
                    tracing::warn!(
                        "Could not read {}: {}. Falling back to plaintext profiles.json if present.",
                        enc_path.display(),
                        e
                    );
                }
            }
        }
    }

    // ── Legacy plaintext path (read-only on Windows post-migration) ──
    let path = get_profiles_path()?;

    if !path.exists() {
        return Ok(Vec::new());
    }

    let content = std::fs::read_to_string(&path)?;
    let profiles: Vec<Profile> = serde_json::from_str(&content)?;

    Ok(profiles)
}

/// Save profiles to disk.
///
/// On Windows the JSON is wrapped with DPAPI ([`crate::dpapi::encrypt`])
/// and written to `profiles.enc`; the legacy `profiles.json` is then
/// removed (only after the encrypted write has succeeded — a partial
/// failure leaves the user's data intact). On other platforms the
/// behaviour is unchanged: plaintext `profiles.json`.
pub fn save_profiles(profiles: &[Profile]) -> AppResult<()> {
    let json_bytes = serde_json::to_vec_pretty(profiles)?;

    #[cfg(windows)]
    {
        let enc_path = get_profiles_enc_path()?;
        let ciphertext = crate::dpapi::encrypt(&json_bytes).map_err(|e| {
            AppError::Config(format!("DPAPI encrypt for profiles.enc failed: {}", e))
        })?;

        // Atomic write: write to a temp file in the same directory,
        // then rename. Prevents leaving a half-written ciphertext
        // behind on a power loss / crash mid-write.
        let tmp_path = enc_path.with_extension("enc.tmp");
        std::fs::write(&tmp_path, &ciphertext)?;
        std::fs::rename(&tmp_path, &enc_path)?;

        // Migration: now that the encrypted store is up to date, drop
        // the legacy plaintext profiles file if it still exists. We
        // delete unconditionally — even if the user had hand-edited
        // it, the encrypted file we just wrote is authoritative. Best-
        // effort, never fail the save on a stale-file delete error.
        let legacy_path = get_profiles_path()?;
        if legacy_path.exists() {
            if let Err(e) = std::fs::remove_file(&legacy_path) {
                tracing::warn!(
                    "Could not remove legacy {}: {} (migration is otherwise complete)",
                    legacy_path.display(),
                    e
                );
            } else {
                tracing::info!("Migrated legacy profiles.json to encrypted profiles.enc");
            }
        }

        return Ok(());
    }

    // ── Non-Windows: plaintext fallback ──────────────────────────────
    #[cfg(not(windows))]
    {
        let path = get_profiles_path()?;
        std::fs::write(&path, json_bytes)?;
        Ok(())
    }
}

/// Load settings from disk.
pub fn load_settings() -> AppResult<Settings> {
    let path = get_settings_path()?;

    if !path.exists() {
        return Ok(Settings::default());
    }

    let content = std::fs::read_to_string(&path)?;
    let settings: Settings = serde_json::from_str(&content)?;

    Ok(settings)
}

/// Save settings to disk.
pub fn save_settings_to_disk(settings: &Settings) -> AppResult<()> {
    let path = get_settings_path()?;
    let content = serde_json::to_string_pretty(settings)?;
    std::fs::write(&path, content)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_settings_default() {
        let s = Settings::default();
        assert!(s.dark_mode);
        assert!(s.auto_reconnect);
        assert!(s.kill_switch);
        assert!(s.auto_rekey);
        assert_eq!(s.language, "EN");
        assert_eq!(s.keepalive_interval, 25);
        assert_eq!(s.connection_timeout, 30);
    }

    #[test]
    fn test_security_level_to_core() {
        assert_eq!(
            SecurityLevel::Standard.to_core_level(),
            hpn_core::crypto::SecurityLevel::Level3
        );
        assert_eq!(
            SecurityLevel::High.to_core_level(),
            hpn_core::crypto::SecurityLevel::Level5
        );
    }

    #[test]
    fn test_security_level_serde() {
        let json = r#""standard""#;
        let level: SecurityLevel = serde_json::from_str(json).unwrap();
        assert_eq!(level, SecurityLevel::Standard);

        let json = r#""high""#;
        let level: SecurityLevel = serde_json::from_str(json).unwrap();
        assert_eq!(level, SecurityLevel::High);
    }

    #[test]
    fn test_profile_serde_roundtrip() {
        let profile = Profile {
            id: "test-1".into(),
            name: "My VPN".into(),
            server: "vpn.example.com".into(),
            port: 51820,
            server_public_key: "AAAA".into(),
            verified: false,
            security_level: SecurityLevel::Standard,
            server_kem_public_key: None,
            requires_auth: false,
            username: None,
            split_tunnel: None,
        };
        let json = serde_json::to_string(&profile).unwrap();
        let restored: Profile = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.id, "test-1");
        assert_eq!(restored.port, 51820);
        assert!(!restored.requires_auth);
    }

    #[test]
    fn test_settings_serde_with_missing_fields() {
        // Simulate a JSON with only dark_mode — other fields should get defaults
        let json = r#"{"darkMode": false}"#;
        let s: Settings = serde_json::from_str(json).unwrap();
        assert!(!s.dark_mode);
        assert!(s.auto_reconnect); // default = true
        assert!(s.kill_switch); // default = true
        assert_eq!(s.language, "EN"); // default
        assert_eq!(s.keepalive_interval, 25); // default
    }
}
