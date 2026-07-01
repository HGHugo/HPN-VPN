use serde::Deserialize;
use tauri::State;

use crate::config::{Profile, SecurityLevel, SplitTunnelConfig};
use crate::error::{AppError, CommandError};
use crate::state::LogLevel;

use super::{
    AppStateRef, validate_port, validate_profile_id, validate_profile_name, validate_public_key,
    validate_server_address,
};

/// Profile input for save command.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileInput {
    pub id: Option<String>,
    pub name: String,
    pub server: String,
    pub port: u16,
    pub server_public_key: String,
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
    pub split_tunnel: Option<SplitTunnelConfig>,
}

pub fn get_profiles(state: State<'_, AppStateRef>) -> Vec<Profile> {
    state.read().profiles.clone()
}

pub fn save_profile(
    state: State<'_, AppStateRef>,
    profile: ProfileInput,
) -> Result<Profile, CommandError> {
    save_profile_to_state(&state, profile)
}

pub fn delete_profile(
    state: State<'_, AppStateRef>,
    profile_id: String,
) -> Result<(), CommandError> {
    delete_profile_from_state(&state, &profile_id)
}

/// Inner save logic — takes a `&AppStateRef` directly so unit tests
/// can drive the function without going through `tauri::State`.
///
/// Validation order (matches the original behaviour to keep the
/// tests that exercise individual rejection paths meaningful):
///   1. profile name / server / port / server_public_key
///   2. server_kem_public_key (when present)
///   3. require_auth ↔ KEM key cross-check
///   4. profile id (when caller supplied one for an update)
///   5. write into state, persist, rollback on disk failure
pub(crate) fn save_profile_to_state(
    state: &AppStateRef,
    profile: ProfileInput,
) -> Result<Profile, CommandError> {
    validate_profile_name(&profile.name).map_err(|e| CommandError::from(AppError::Config(e)))?;
    validate_server_address(&profile.server)
        .map_err(|e| CommandError::from(AppError::Config(e)))?;
    validate_port(profile.port).map_err(|e| CommandError::from(AppError::Config(e)))?;
    validate_public_key(&profile.server_public_key)
        .map_err(|e| CommandError::from(AppError::Config(e)))?;
    if let Some(ref kem_key) = profile.server_kem_public_key {
        validate_public_key(kem_key).map_err(|e| CommandError::from(AppError::Config(e)))?;
    }
    if profile.requires_auth && profile.server_kem_public_key.is_none() {
        return Err(CommandError::from(AppError::Config(
            "Authentication requires server KEM public key for identity hiding".into(),
        )));
    }

    if let Some(ref id) = profile.id {
        validate_profile_id(id).map_err(|e| CommandError::from(AppError::Config(e)))?;
    }

    let mut state = state.write();
    let previous_profiles = state.profiles.clone();

    let profile = Profile {
        id: profile
            .id
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        name: profile.name,
        server: profile.server,
        port: profile.port,
        server_public_key: profile.server_public_key,
        verified: profile.verified,
        security_level: profile.security_level,
        server_kem_public_key: profile.server_kem_public_key,
        requires_auth: profile.requires_auth,
        username: profile.username,
        split_tunnel: profile.split_tunnel,
    };

    if let Some(pos) = state.profiles.iter().position(|p| p.id == profile.id) {
        state.profiles[pos] = profile.clone();
        state.add_log(LogLevel::Info, format!("Profile updated: {}", profile.name));
    } else {
        state.profiles.push(profile.clone());
        state.add_log(LogLevel::Info, format!("Profile created: {}", profile.name));
    }

    if let Err(e) = state.save_profiles() {
        state.profiles = previous_profiles;
        state.add_log(
            LogLevel::Error,
            format!("Failed to save profile change, rollback applied: {}", e),
        );
        return Err(CommandError::from(e));
    }

    Ok(profile)
}

/// Inner delete logic — see [`save_profile_to_state`] for rationale.
pub(crate) fn delete_profile_from_state(
    state: &AppStateRef,
    profile_id: &str,
) -> Result<(), CommandError> {
    validate_profile_id(profile_id).map_err(|e| CommandError::from(AppError::Config(e)))?;

    let mut state = state.write();
    let previous_profiles = state.profiles.clone();

    let pos = state
        .profiles
        .iter()
        .position(|p| p.id == profile_id)
        .ok_or_else(|| CommandError::from(AppError::ProfileNotFound(profile_id.to_string())))?;

    let profile = state.profiles.remove(pos);
    state.add_log(LogLevel::Info, format!("Profile deleted: {}", profile.name));

    if let Err(e) = state.save_profiles() {
        state.profiles = previous_profiles;
        state.add_log(
            LogLevel::Error,
            format!("Failed to delete profile, rollback applied: {}", e),
        );
        return Err(CommandError::from(e));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AppState;
    use parking_lot::RwLock;
    use std::sync::Arc;

    /// Build an in-memory `AppStateRef` whose `save_profiles()` will
    /// write to a temp directory we discard. This is OK because the
    /// `config::save_profiles` path uses an OS-level data dir; in
    /// tests we tolerate the side effect (or it errors out, in which
    /// case `save_profile_to_state` rolls back as designed).
    fn fresh_state() -> AppStateRef {
        Arc::new(RwLock::new(AppState::new()))
    }

    fn valid_input(name: &str, id: Option<&str>) -> ProfileInput {
        ProfileInput {
            id: id.map(String::from),
            name: name.into(),
            server: "vpn.example.com".into(),
            port: 51820,
            // Validation in `validate_public_key` accepts any non-empty
            // base64-ish string; we pass a clearly-fake but
            // syntactically-valid value.
            server_public_key: "MIIBCgKCAQEAxDxYMHmtjfOGkLn3SJ87R3NrJl6cF5e7pE3+jH1aV2BlUPZx6N9CqA"
                .into(),
            verified: false,
            security_level: SecurityLevel::default(),
            server_kem_public_key: None,
            requires_auth: false,
            username: None,
            split_tunnel: None,
        }
    }

    #[test]
    fn test_save_profile_creates_new_when_id_is_none() {
        let state = fresh_state();
        let result = save_profile_to_state(&state, valid_input("Home", None));
        // Either succeeds or fails at disk-write step; in both cases
        // the in-memory write happened first. We assert on the final
        // state of the in-memory profiles list.
        if result.is_ok() {
            assert_eq!(state.read().profiles.len(), 1);
            assert_eq!(state.read().profiles[0].name, "Home");
            // UUID generated when caller didn't supply an id.
            assert!(!state.read().profiles[0].id.is_empty());
        } else {
            // save_profiles failed → rollback → no profile persisted.
            assert!(state.read().profiles.is_empty());
        }
    }

    #[test]
    fn test_save_profile_rejects_invalid_name() {
        let state = fresh_state();
        let mut input = valid_input("", None);
        input.name = "".into();
        let result = save_profile_to_state(&state, input);
        assert!(result.is_err());
        assert!(state.read().profiles.is_empty());
    }

    #[test]
    fn test_save_profile_rejects_invalid_port_zero() {
        let state = fresh_state();
        let mut input = valid_input("ZeroPort", None);
        input.port = 0;
        let result = save_profile_to_state(&state, input);
        assert!(result.is_err());
    }

    #[test]
    fn test_save_profile_rejects_auth_without_kem_key() {
        // require_auth = true must be paired with a KEM key for
        // identity hiding (the encrypted handshake init binds the
        // password). Saving without the KEM key is a config error.
        let state = fresh_state();
        let mut input = valid_input("AuthNoKem", None);
        input.requires_auth = true;
        input.server_kem_public_key = None;
        let result = save_profile_to_state(&state, input);
        assert!(result.is_err());
    }

    #[test]
    fn test_save_profile_rejects_invalid_id_format() {
        let state = fresh_state();
        let input = valid_input("BadId", Some("../etc/passwd"));
        let result = save_profile_to_state(&state, input);
        assert!(result.is_err());
    }

    #[test]
    fn test_delete_profile_rejects_missing_id() {
        let state = fresh_state();
        let result = delete_profile_from_state(&state, "does-not-exist");
        assert!(result.is_err());
    }

    #[test]
    fn test_delete_profile_rejects_invalid_id_format() {
        let state = fresh_state();
        let result = delete_profile_from_state(&state, "../etc/passwd");
        assert!(result.is_err());
    }

    #[test]
    fn test_save_then_delete_profile_idempotent() {
        // Even if the disk write fails on save, in-memory state must
        // be consistent: saving + deleting should leave the in-memory
        // profile list empty either way.
        let state = fresh_state();
        let input = valid_input("RoundTrip", Some("rt-1"));
        let _ = save_profile_to_state(&state, input);
        // We don't assert on save's success — disk may not be
        // writable in CI sandbox. Either way deleting "rt-1" should
        // not leave a stale entry.
        let _ = delete_profile_from_state(&state, "rt-1");
        assert!(
            state.read().profiles.iter().all(|p| p.id != "rt-1"),
            "delete should remove the profile if it was inserted"
        );
    }
}
