//! User authentication store using SQLite.
//!
//! Provides secure storage and verification of user credentials for VPN authentication.
//! Passwords are hashed using Argon2id (memory-hard, resistant to GPU attacks).

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use rusqlite::{Connection, params};
use tracing::{debug, info, warn};

use crate::error::ServerError;

/// Information about a user (without password hash).
#[derive(Debug, Clone)]
pub struct UserInfo {
    /// Unique user ID.
    pub id: i64,
    /// Username (unique).
    pub username: String,
    /// When the user was created (Unix timestamp).
    pub created_at: i64,
    /// When the user was last updated (Unix timestamp).
    pub updated_at: i64,
    /// Whether the user is enabled.
    pub enabled: bool,
    /// Last successful login — always None (no-log: not persisted to disk).
    pub last_login: Option<i64>,
    /// Number of consecutive failed login attempts.
    pub failed_attempts: i32,
    /// Lockout expiry timestamp (Unix seconds) if account is temporarily locked.
    pub locked_until: Option<i64>,
}

/// User authentication store backed by SQLite.
///
/// NOTE: Connection is not thread-safe for concurrent writes.
/// The server uses UserStore from a single async context.
/// SQLite WAL mode provides read concurrency.
pub struct UserStore {
    conn: Connection,
    /// On-disk path of the SQLite file (None for in-memory test stores).
    /// Used by the background hash-upgrade thread (`spawn_hash_upgrade`)
    /// to open its own connection so the upgrade does not contend with
    /// the request-handling connection and so the upgrade does not show
    /// up in the request's timing profile.
    db_path: Option<std::path::PathBuf>,
}

impl UserStore {
    const MAX_FAILED_ATTEMPTS: i32 = 10;
    const LOCKOUT_BASE_SECS: i64 = 30;
    const LOCKOUT_MAX_SECS: i64 = 3600;

    #[cfg(unix)]
    fn set_owner_only_permissions(path: &Path, mode: u32) -> Result<(), ServerError> {
        let permissions = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(path, permissions).map_err(|e| {
            ServerError::Config(format!(
                "failed to set permissions on {}: {}",
                path.display(),
                e
            ))
        })
    }

    /// Open or create a user store at the given path.
    ///
    /// Creates the database and tables if they don't exist.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ServerError> {
        let path = path.as_ref();

        // Create parent directory if it doesn't exist
        if let Some(parent) = path.parent()
            && !parent.exists()
        {
            std::fs::create_dir_all(parent).map_err(|e| {
                ServerError::Config(format!(
                    "failed to create user database directory {}: {}",
                    parent.display(),
                    e
                ))
            })?;
        }

        #[cfg(unix)]
        if let Some(parent) = path.parent() {
            Self::set_owner_only_permissions(parent, 0o700)?;
        }

        let conn = Connection::open(path).map_err(|e| {
            ServerError::Config(format!(
                "failed to open user database {}: {}",
                path.display(),
                e
            ))
        })?;

        #[cfg(unix)]
        if path.exists() {
            Self::set_owner_only_permissions(path, 0o600)?;
        }

        // Enable WAL mode for better concurrency
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .map_err(|e| ServerError::Config(format!("failed to set SQLite pragmas: {}", e)))?;

        let store = Self {
            conn,
            db_path: Some(path.to_path_buf()),
        };
        store.initialize_schema()?;

        info!("User store opened: {:?}", path);
        Ok(store)
    }

    /// Open an in-memory database (for testing).
    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self, ServerError> {
        let conn = Connection::open_in_memory().map_err(|e| {
            ServerError::Config(format!("failed to open in-memory database: {}", e))
        })?;
        let store = Self {
            conn,
            db_path: None,
        };
        store.initialize_schema()?;
        Ok(store)
    }

    /// Initialize the database schema.
    fn initialize_schema(&self) -> Result<(), ServerError> {
        self.conn
            .execute_batch(
                r"
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                    password_hash TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    last_login INTEGER,
                    failed_attempts INTEGER NOT NULL DEFAULT 0,
                    locked_until INTEGER
                );
                
                CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
                CREATE INDEX IF NOT EXISTS idx_users_enabled ON users(enabled);
                ",
            )
            .map_err(|e| ServerError::Config(format!("failed to initialize user schema: {}", e)))?;

        self.ensure_schema_compatibility()?;

        debug!("User store schema initialized");
        Ok(())
    }

    fn ensure_schema_compatibility(&self) -> Result<(), ServerError> {
        if !self.table_has_column("users", "locked_until")? {
            self.conn
                .execute("ALTER TABLE users ADD COLUMN locked_until INTEGER", [])
                .map_err(|e| {
                    ServerError::Config(format!("failed to add users.locked_until column: {}", e))
                })?;
        }
        Ok(())
    }

    fn table_has_column(&self, table: &str, column: &str) -> Result<bool, ServerError> {
        let pragma = format!("PRAGMA table_info({})", table);
        let mut stmt = self
            .conn
            .prepare(&pragma)
            .map_err(|e| ServerError::Config(format!("failed to inspect schema: {}", e)))?;

        let mut rows = stmt
            .query([])
            .map_err(|e| ServerError::Config(format!("failed to query schema: {}", e)))?;

        while let Some(row) = rows
            .next()
            .map_err(|e| ServerError::Config(format!("failed to iterate schema rows: {}", e)))?
        {
            let name: String = row
                .get(1)
                .map_err(|e| ServerError::Config(format!("failed to read schema row: {}", e)))?;
            if name == column {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Get the current Unix timestamp.
    fn now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    /// Build the Argon2id instance with hardened parameters.
    ///
    /// Memory: 64 MiB  Iterations: 3  Parallelism: 4 lanes.
    /// These exceed OWASP's 2023 minimum (19 MiB, t=2, p=1) and target a
    /// per-hash cost of ~150 ms on modern server CPUs — a reasonable balance
    /// between login latency and offline brute-force resistance for a server
    /// that holds a SQLite users database whose theft is our main threat model.
    fn argon2() -> Argon2<'static> {
        // The builder only fails for out-of-range values; our constants are in range.
        let params = Params::new(65536, 3, 4, None)
            .expect("Argon2 params (64 MiB, t=3, p=4) are within valid range");
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
    }

    /// Hash a password using Argon2id with hardened parameters.
    fn hash_password(password: &str) -> Result<String, ServerError> {
        let salt = SaltString::generate(&mut OsRng);
        Self::argon2()
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| ServerError::Config(format!("failed to hash password: {}", e)))
    }

    /// Verify a password against a hash.
    ///
    /// Uses the stored PHC string's parameters, not our own; this ensures
    /// backward compatibility with hashes computed under previous (weaker)
    /// parameter sets. The verifier reads m/t/p from the hash itself.
    fn verify_password_hash(password: &str, hash: &str) -> bool {
        let Ok(parsed_hash) = PasswordHash::new(hash) else {
            return false;
        };

        Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok()
    }

    /// Return `true` if the stored PHC hash should be re-computed with the
    /// current (stronger) Argon2id parameters.
    ///
    /// We compare only memory cost (`m`) and iteration count (`t`). If either
    /// is below our current target, we upgrade. Parallelism (`p`) differences
    /// alone don't force an upgrade to avoid churn on minor tuning changes.
    fn hash_needs_upgrade(hash: &str) -> bool {
        let Ok(parsed) = PasswordHash::new(hash) else {
            return false;
        };
        let target = Params::new(65536, 3, 4, None).expect("target params are valid");
        // Extract current params; if parsing fails, err on the safe side and
        // request upgrade on next login.
        let Ok(current) = Params::try_from(&parsed) else {
            return true;
        };
        current.m_cost() < target.m_cost() || current.t_cost() < target.t_cost()
    }

    /// Consume comparable CPU work on negative auth paths to reduce timing
    /// side channels.
    ///
    /// FIX-029: when a hash is available (locked / disabled paths where we
    /// already fetched the row), REPLAY the verify against that hash. This
    /// matches the legacy hash's Argon2 parameters exactly, so an attacker
    /// timing a "locked" response cannot distinguish it from a "wrong
    /// password" response even when the stored hash still uses pre-2024
    /// parameters that hash significantly faster than today's target.
    ///
    /// When no hash is known (user-not-found path), fall back to hashing
    /// with the modern target parameters. This leaves a residual timing
    /// gap between "user exists with weak legacy hash" and "user does
    /// not exist" until every stored hash is migrated by
    /// `hash_needs_upgrade` — bounded but real.
    fn apply_auth_delay_against_hash(password: &str, hash: Option<&str>) {
        match hash {
            Some(stored) => {
                let _ = Self::verify_password_hash(password, stored);
            }
            None => {
                let _ = Self::hash_password(password);
            }
        }
    }

    /// Back-compat shim — equivalent to `apply_auth_delay_against_hash(password, None)`.
    fn apply_auth_delay(password: &str) {
        Self::apply_auth_delay_against_hash(password, None);
    }

    /// Public hook to consume Argon2id-equivalent CPU work on negative auth paths.
    ///
    /// Used by callers that decide to short-circuit authentication (for
    /// example after [`AuthLockoutTracker::check_lockout`](crate::auth_lockout::AuthLockoutTracker::check_lockout)
    /// fires) but want the rejection to be observationally indistinguishable
    /// from a genuine "wrong password" outcome. Without this padding a
    /// remote attacker can fingerprint "lockout active" vs. "wrong
    /// password" by measuring the response time and use that signal to map
    /// out which (username, ip) tuples are throttled.
    ///
    /// The work performed is identical to what `verify_password` runs on a
    /// failed attempt: a fresh Argon2id hash with the production
    /// parameters. Discards its output.
    pub fn apply_auth_delay_public(password: &str) {
        Self::apply_auth_delay(password);
    }

    /// Run an Argon2id rehash + DB update on a detached background thread.
    ///
    /// Used to upgrade weak password hashes opportunistically on login
    /// without contributing to the request's timing signature (see
    /// AUTH-2). The thread opens its own SQLite connection so it does
    /// not contend with the request-handling connection. Errors are
    /// logged at `warn!` and never propagated — the user stays logged
    /// in with the old hash and we will retry on the next login.
    ///
    /// `password` is taken by value so the caller can hand off ownership
    /// of a freshly-allocated copy; it lives only until the rehash
    /// finishes inside the spawned thread.
    fn spawn_hash_upgrade(db_path: std::path::PathBuf, user_id: i64, password: String) {
        let spawn_result = std::thread::Builder::new()
            .name(format!("hpn-hash-upgrade-{}", user_id))
            .spawn(move || {
                let new_hash = match Self::hash_password(&password) {
                    Ok(h) => h,
                    Err(e) => {
                        warn!("Background rehash failed for user_id {}: {}", user_id, e);
                        return;
                    }
                };
                let conn = match Connection::open(&db_path) {
                    Ok(c) => c,
                    Err(e) => {
                        warn!(
                            "Background rehash: failed to open user DB for user_id {}: {}",
                            user_id, e
                        );
                        return;
                    }
                };
                if let Err(e) = conn.execute(
                    "UPDATE users SET password_hash = ?1, updated_at = ?2 WHERE id = ?3",
                    params![new_hash, Self::now(), user_id],
                ) {
                    warn!(
                        "Background rehash: UPDATE failed for user_id {}: {}",
                        user_id, e
                    );
                } else {
                    debug!("Background rehash committed for user_id {}", user_id);
                }
            });
        if let Err(e) = spawn_result {
            // OS refused to spawn (FD/PID exhaustion). The user is still
            // logged in correctly with the old hash; the upgrade simply
            // does not happen this time and will retry on the next login.
            warn!(
                "Could not spawn background rehash thread for user_id {}: {}",
                user_id, e
            );
        }
    }

    /// Add a new user.
    ///
    /// Returns an error if the username already exists.
    pub fn add_user(&self, username: &str, password: &str) -> Result<(), ServerError> {
        // Validate username
        if username.is_empty() || username.len() > 64 {
            return Err(ServerError::Config(
                "username must be 1-64 characters".into(),
            ));
        }

        if !username
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
        {
            return Err(ServerError::Config(
                "username can only contain alphanumeric characters, underscores, hyphens, and dots"
                    .into(),
            ));
        }

        // Validate password
        if password.len() < 8 {
            return Err(ServerError::Config(
                "password must be at least 8 characters".into(),
            ));
        }

        let password_hash = Self::hash_password(password)?;
        let now = Self::now();

        self.conn
            .execute(
                "INSERT INTO users (username, password_hash, created_at, updated_at) VALUES (?1, ?2, ?3, ?4)",
                params![username, password_hash, now, now],
            )
            .map_err(|e| {
                if e.to_string().contains("UNIQUE constraint failed") {
                    ServerError::Config(format!("user '{}' already exists", username))
                } else {
                    ServerError::Config(format!("failed to add user: {}", e))
                }
            })?;

        info!("User '{}' added", username);
        Ok(())
    }

    /// Remove a user by username.
    ///
    /// Returns true if the user was removed, false if not found.
    pub fn remove_user(&self, username: &str) -> Result<bool, ServerError> {
        let rows = self
            .conn
            .execute("DELETE FROM users WHERE username = ?1", params![username])
            .map_err(|e| ServerError::Config(format!("failed to remove user: {}", e)))?;

        if rows > 0 {
            info!("User '{}' removed", username);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// List all users.
    pub fn list_users(&self) -> Result<Vec<UserInfo>, ServerError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, username, created_at, updated_at, enabled, last_login, failed_attempts, locked_until FROM users ORDER BY username",
            )
            .map_err(|e| ServerError::Config(format!("failed to prepare query: {}", e)))?;

        let users = stmt
            .query_map([], |row| {
                Ok(UserInfo {
                    id: row.get(0)?,
                    username: row.get(1)?,
                    created_at: row.get(2)?,
                    updated_at: row.get(3)?,
                    enabled: row.get::<_, i32>(4)? != 0,
                    last_login: None, // Never expose (privacy)
                    failed_attempts: row.get(6)?,
                    locked_until: row.get(7)?,
                })
            })
            .map_err(|e| ServerError::Config(format!("failed to list users: {}", e)))?;

        users
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| ServerError::Config(format!("failed to collect users: {}", e)))
    }

    /// Get a user by username.
    pub fn get_user(&self, username: &str) -> Result<Option<UserInfo>, ServerError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, username, created_at, updated_at, enabled, last_login, failed_attempts, locked_until FROM users WHERE username = ?1",
            )
            .map_err(|e| ServerError::Config(format!("failed to prepare query: {}", e)))?;

        let mut rows = stmt
            .query(params![username])
            .map_err(|e| ServerError::Config(format!("failed to query user: {}", e)))?;

        if let Some(row) = rows
            .next()
            .map_err(|e| ServerError::Config(format!("failed to fetch row: {}", e)))?
        {
            Ok(Some(UserInfo {
                id: row
                    .get(0)
                    .map_err(|e| ServerError::Config(format!("failed to get id: {}", e)))?,
                username: row
                    .get(1)
                    .map_err(|e| ServerError::Config(format!("failed to get username: {}", e)))?,
                created_at: row
                    .get(2)
                    .map_err(|e| ServerError::Config(format!("failed to get created_at: {}", e)))?,
                updated_at: row
                    .get(3)
                    .map_err(|e| ServerError::Config(format!("failed to get updated_at: {}", e)))?,
                enabled: row
                    .get::<_, i32>(4)
                    .map_err(|e| ServerError::Config(format!("failed to get enabled: {}", e)))?
                    != 0,
                last_login: None, // Never expose (privacy)
                failed_attempts: row.get(6).map_err(|e| {
                    ServerError::Config(format!("failed to get failed_attempts: {}", e))
                })?,
                locked_until: row.get(7).map_err(|e| {
                    ServerError::Config(format!("failed to get locked_until: {}", e))
                })?,
            }))
        } else {
            Ok(None)
        }
    }

    /// Verify a user's password.
    ///
    /// Returns true if the username exists, is enabled, and the password is correct.
    /// Updates last_login on success, increments failed_attempts on failure.
    pub fn verify_password(&self, username: &str, password: &str) -> Result<bool, ServerError> {
        // Get user info and password hash
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, password_hash, enabled, failed_attempts, locked_until FROM users WHERE username = ?1",
            )
            .map_err(|e| ServerError::Config(format!("failed to prepare query: {}", e)))?;

        let mut rows = stmt
            .query(params![username])
            .map_err(|e| ServerError::Config(format!("failed to query user: {}", e)))?;

        let row = match rows
            .next()
            .map_err(|e| ServerError::Config(format!("failed to fetch row: {}", e)))?
        {
            Some(r) => r,
            None => {
                Self::apply_auth_delay(password);
                debug!("Authentication failed: user not found");
                return Ok(false);
            }
        };

        let user_id: i64 = row
            .get(0)
            .map_err(|e| ServerError::Config(format!("failed to get id: {}", e)))?;
        let password_hash: String = row
            .get(1)
            .map_err(|e| ServerError::Config(format!("failed to get password_hash: {}", e)))?;
        let enabled: bool = row
            .get::<_, i32>(2)
            .map_err(|e| ServerError::Config(format!("failed to get enabled: {}", e)))?
            != 0;
        let failed_attempts: i32 = row
            .get(3)
            .map_err(|e| ServerError::Config(format!("failed to get failed_attempts: {}", e)))?;
        let locked_until: Option<i64> = row
            .get(4)
            .map_err(|e| ServerError::Config(format!("failed to get locked_until: {}", e)))?;

        let now = Self::now();
        // Enforce the time-bounded lockout computed on the last failure.
        // `locked_until` is set by the failure path below whenever
        // `failed_attempts` crosses `MAX_FAILED_ATTEMPTS`, with an
        // exponentially-backed-off expiry capped at `LOCKOUT_MAX_SECS`.
        //
        // SECURITY NOTE: we do NOT additionally reject on
        // `failed_attempts >= MAX_FAILED_ATTEMPTS` alone. Doing so makes
        // the lockout permanent (the counter is only reset by a
        // successful login, which is exactly what a locked-out user
        // cannot reach) and turns the brute-force protection into a
        // reliable account-DoS primitive: an attacker who knows any
        // username needs only 10 failed handshakes to lock that user
        // out for the lifetime of the deployment. The `locked_until`
        // check below is the sole gatekeeper — once the backoff window
        // has elapsed, the user gets ONE attempt; if that attempt also
        // fails, the backoff recomputes with a longer window.
        if let Some(until) = locked_until
            && until > now
        {
            // FIX-029: replay against the real stored hash so the lockout
            // path has the same Argon2 timing as a verify-fail path.
            Self::apply_auth_delay_against_hash(password, Some(&password_hash));
            warn!(
                "Authentication failed: account temporarily locked ({}s remaining)",
                (until - now).max(0)
            );
            return Ok(false);
        }

        // Check if user is enabled
        if !enabled {
            // FIX-029: same as above — replay against the user's real hash
            // so an attacker cannot distinguish disabled-account from
            // wrong-password by timing.
            Self::apply_auth_delay_against_hash(password, Some(&password_hash));
            debug!("Authentication failed: user disabled");
            return Ok(false);
        }

        // Verify password
        if Self::verify_password_hash(password, &password_hash) {
            // Success - reset failed_attempts (no last_login stored for privacy)
            self.conn
                .execute(
                    "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?1",
                    params![user_id],
                )
                .map_err(|e| {
                    ServerError::Config(format!("failed to reset login attempts: {}", e))
                })?;

            // Transparently upgrade legacy hashes to the current Argon2id
            // parameters. SECURITY (AUTH-2 mitigation): the upgrade is
            // dispatched to a detached OS thread so it does NOT show up
            // in this request's latency. Doing the rehash inline made the
            // first-login-after-upgrade observably slower than ordinary
            // logins (one extra ~150 ms Argon2id), giving a remote
            // attacker a timing oracle for "this account just had its
            // hash params raised" and, more usefully, "this username is
            // valid AND was authenticated recently". The detached path
            // closes that channel: the response goes back at the same
            // moment whether or not an upgrade fires, and the rehash
            // happens lazily on a background connection.
            //
            // In-memory test stores skip the upgrade (no `db_path`); the
            // existing tests do not exercise this path.
            if Self::hash_needs_upgrade(&password_hash)
                && let Some(path) = self.db_path.clone()
            {
                Self::spawn_hash_upgrade(path, user_id, password.to_string());
            }

            debug!("Authentication successful");
            Ok(true)
        } else {
            // Failure - increment failed_attempts
            let new_failed_attempts = failed_attempts.saturating_add(1);
            let lockout_until = if new_failed_attempts >= Self::MAX_FAILED_ATTEMPTS {
                let exponent = (new_failed_attempts - Self::MAX_FAILED_ATTEMPTS).clamp(0, 10);
                let backoff_secs = (Self::LOCKOUT_BASE_SECS.saturating_mul(1_i64 << exponent))
                    .min(Self::LOCKOUT_MAX_SECS);
                Some(now.saturating_add(backoff_secs))
            } else {
                None
            };

            self.conn
                .execute(
                    "UPDATE users SET failed_attempts = ?1, locked_until = ?2, updated_at = ?3 WHERE id = ?4",
                    params![new_failed_attempts, lockout_until, now, user_id],
                )
                .map_err(|e| ServerError::Config(format!("failed to update failed_attempts: {}", e)))?;

            debug!("Authentication failed: incorrect password");
            Ok(false)
        }
    }

    /// Enable or disable a user.
    pub fn set_enabled(&self, username: &str, enabled: bool) -> Result<bool, ServerError> {
        let rows = self
            .conn
            .execute(
                "UPDATE users SET enabled = ?1, updated_at = ?2 WHERE username = ?3",
                params![enabled as i32, Self::now(), username],
            )
            .map_err(|e| ServerError::Config(format!("failed to update user: {}", e)))?;

        if rows > 0 {
            info!(
                "User '{}' {}",
                username,
                if enabled { "enabled" } else { "disabled" }
            );
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Change a user's password.
    pub fn change_password(&self, username: &str, new_password: &str) -> Result<bool, ServerError> {
        // Validate password
        if new_password.len() < 8 {
            return Err(ServerError::Config(
                "password must be at least 8 characters".into(),
            ));
        }

        let password_hash = Self::hash_password(new_password)?;
        let now = Self::now();

        let rows = self
            .conn
            .execute(
                "UPDATE users SET password_hash = ?1, updated_at = ?2, failed_attempts = 0, locked_until = NULL WHERE username = ?3",
                params![password_hash, now, username],
            )
            .map_err(|e| ServerError::Config(format!("failed to update password: {}", e)))?;

        if rows > 0 {
            info!("Password changed for user '{}'", username);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Reset failed login attempts for a user (unlock).
    pub fn reset_failed_attempts(&self, username: &str) -> Result<bool, ServerError> {
        let rows = self
            .conn
            .execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL, updated_at = ?1 WHERE username = ?2",
                params![Self::now(), username],
            )
            .map_err(|e| ServerError::Config(format!("failed to reset failed_attempts: {}", e)))?;

        if rows > 0 {
            info!("Failed attempts reset for user '{}'", username);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Get the number of users.
    pub fn count_users(&self) -> Result<usize, ServerError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
            .map_err(|e| ServerError::Config(format!("failed to count users: {}", e)))?;

        Ok(count as usize)
    }

    /// Check if authentication is required (i.e., there are users in the database).
    pub fn has_users(&self) -> Result<bool, ServerError> {
        self.count_users().map(|c| c > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_verify_user() {
        let store = UserStore::open_in_memory().unwrap();

        // Add user
        store.add_user("alice", "password123").unwrap();

        // Verify correct password
        assert!(store.verify_password("alice", "password123").unwrap());

        // Verify incorrect password
        assert!(!store.verify_password("alice", "wrongpassword").unwrap());

        // Verify non-existent user
        assert!(!store.verify_password("bob", "password123").unwrap());
    }

    #[test]
    fn test_duplicate_user() {
        let store = UserStore::open_in_memory().unwrap();

        store.add_user("alice", "password123").unwrap();
        let result = store.add_user("alice", "differentpassword");
        assert!(result.is_err());
    }

    #[test]
    fn test_username_case_insensitive() {
        let store = UserStore::open_in_memory().unwrap();

        store.add_user("Alice", "password123").unwrap();

        // Should find user regardless of case
        assert!(store.get_user("alice").unwrap().is_some());
        assert!(store.get_user("ALICE").unwrap().is_some());
        assert!(store.get_user("Alice").unwrap().is_some());

        // Password verification should also work
        assert!(store.verify_password("alice", "password123").unwrap());
        assert!(store.verify_password("ALICE", "password123").unwrap());
    }

    #[test]
    fn test_disable_user() {
        let store = UserStore::open_in_memory().unwrap();

        store.add_user("alice", "password123").unwrap();
        assert!(store.verify_password("alice", "password123").unwrap());

        // Disable user
        store.set_enabled("alice", false).unwrap();

        // Verification should fail for disabled user
        assert!(!store.verify_password("alice", "password123").unwrap());

        // Re-enable user
        store.set_enabled("alice", true).unwrap();
        assert!(store.verify_password("alice", "password123").unwrap());
    }

    #[test]
    fn test_change_password() {
        let store = UserStore::open_in_memory().unwrap();

        store.add_user("alice", "password123").unwrap();
        assert!(store.verify_password("alice", "password123").unwrap());

        // Change password
        store.change_password("alice", "newpassword456").unwrap();

        // Old password should fail
        assert!(!store.verify_password("alice", "password123").unwrap());

        // New password should work
        assert!(store.verify_password("alice", "newpassword456").unwrap());
    }

    #[test]
    fn test_list_users() {
        let store = UserStore::open_in_memory().unwrap();

        store.add_user("alice", "password123").unwrap();
        store.add_user("bob", "password456").unwrap();
        store.add_user("charlie", "password789").unwrap();

        let users = store.list_users().unwrap();
        assert_eq!(users.len(), 3);

        // Should be sorted by username
        assert_eq!(users[0].username, "alice");
        assert_eq!(users[1].username, "bob");
        assert_eq!(users[2].username, "charlie");
    }

    #[test]
    fn test_remove_user() {
        let store = UserStore::open_in_memory().unwrap();

        store.add_user("alice", "password123").unwrap();
        assert!(store.get_user("alice").unwrap().is_some());

        // Remove user
        assert!(store.remove_user("alice").unwrap());
        assert!(store.get_user("alice").unwrap().is_none());

        // Removing non-existent user returns false
        assert!(!store.remove_user("alice").unwrap());
    }

    #[test]
    fn test_failed_attempts_lockout() {
        let store = UserStore::open_in_memory().unwrap();

        store.add_user("alice", "password123").unwrap();

        // Fail 10 times
        for _ in 0..10 {
            assert!(!store.verify_password("alice", "wrongpassword").unwrap());
        }

        // Should be locked out even with correct password
        assert!(!store.verify_password("alice", "password123").unwrap());

        // Reset failed attempts
        store.reset_failed_attempts("alice").unwrap();

        // Should work again
        assert!(store.verify_password("alice", "password123").unwrap());
    }

    #[test]
    fn test_lockout_is_time_bounded_not_permanent() {
        // REGRESSION GUARD (AUTH-1): `verify_password` used to reject on
        // `failed_attempts >= MAX_FAILED_ATTEMPTS` in addition to the
        // `locked_until` check, which turned the brute-force protection
        // into a permanent account-DoS (the counter is only reset by a
        // successful login, which the locked-out user cannot reach).
        //
        // This test asserts that after the `locked_until` window has
        // elapsed, the correct password is accepted even when the
        // `failed_attempts` counter is still at or above
        // MAX_FAILED_ATTEMPTS. It simulates elapsed time by writing a
        // past `locked_until` value directly into the database.
        let store = UserStore::open_in_memory().unwrap();
        store.add_user("alice", "password123").unwrap();

        // Trigger the lockout: 10 failures sets failed_attempts = 10 and
        // locked_until = now + LOCKOUT_BASE_SECS (30s).
        for _ in 0..10 {
            assert!(!store.verify_password("alice", "wrongpassword").unwrap());
        }

        // Sanity: correct password is rejected right now (lockout active).
        assert!(
            !store.verify_password("alice", "password123").unwrap(),
            "correct password must be rejected while lockout is still active"
        );

        // Simulate time passing: rewind `locked_until` to one hour ago.
        // `failed_attempts` intentionally stays at 10 so we verify that
        // the stale counter alone no longer permanently rejects.
        let past = UserStore::now() - 3600;
        store
            .conn
            .execute(
                "UPDATE users SET locked_until = ?1 WHERE username = 'alice'",
                params![past],
            )
            .unwrap();

        // With the lockout window expired, the correct password must
        // now be accepted. If this fails, `verify_password` has
        // regressed to the permanent-lockout behaviour that AUTH-1
        // called out.
        assert!(
            store.verify_password("alice", "password123").unwrap(),
            "once locked_until has elapsed, the correct password must \
             succeed regardless of the stale failed_attempts counter \
             (AUTH-1 regression guard)"
        );

        // And on success, the counter was reset to 0.
        let info = store.get_user("alice").unwrap().unwrap();
        assert_eq!(info.failed_attempts, 0);
        assert_eq!(info.locked_until, None);
    }

    #[test]
    fn test_password_validation() {
        let store = UserStore::open_in_memory().unwrap();

        // Too short password
        let result = store.add_user("alice", "short");
        assert!(result.is_err());

        // Valid password
        let result = store.add_user("alice", "longpassword");
        assert!(result.is_ok());
    }

    #[test]
    fn test_username_validation() {
        let store = UserStore::open_in_memory().unwrap();

        // Empty username
        let result = store.add_user("", "password123");
        assert!(result.is_err());

        // Invalid characters
        let result = store.add_user("user@domain", "password123");
        assert!(result.is_err());

        // Valid usernames
        assert!(store.add_user("alice", "password123").is_ok());
        assert!(store.add_user("bob_smith", "password123").is_ok());
        assert!(store.add_user("user-1", "password123").is_ok());
        assert!(store.add_user("john.doe", "password123").is_ok());
    }

    #[test]
    fn test_has_users() {
        let store = UserStore::open_in_memory().unwrap();

        assert!(!store.has_users().unwrap());

        store.add_user("alice", "password123").unwrap();
        assert!(store.has_users().unwrap());
    }
}
