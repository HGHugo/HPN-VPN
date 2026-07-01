//! Privilege dropping for security hardening.
//!
//! After binding to privileged ports (< 1024) and creating TUN devices,
//! the server should drop root privileges to minimize attack surface.
//!
//! # Security Best Practices
//!
//! 1. Run as root only to bind sockets and create TUN device
//! 2. Drop to unprivileged user immediately after
//! 3. Use a dedicated system user (e.g., "hpn" or "nobody")
//! 4. Ensure the user has minimal permissions
//!
//! # Example Configuration
//!
//! ```toml
//! [server]
//! run_as_user = "hpn"
//! run_as_group = "hpn"
//! ```

// Allow unsafe code in this module - required for libc syscalls (setuid, setgid, etc.)
// These are security-critical operations that cannot be done safely in Rust.
// SAFETY: All unsafe blocks have documented safety requirements and proper error handling.
#![allow(unsafe_code)]

use tracing::{debug, error, info, warn};

use crate::error::{ServerError, ServerResult};

/// Check if the current process is running as root (UID 0).
#[cfg(unix)]
pub fn is_root() -> bool {
    // SAFETY: getuid() is always safe and has no side effects
    unsafe { libc::getuid() == 0 }
}

#[cfg(not(unix))]
pub fn is_root() -> bool {
    false
}

/// Get the current effective user ID.
#[cfg(unix)]
pub fn current_uid() -> u32 {
    // SAFETY: getuid() is always safe
    unsafe { libc::getuid() }
}

#[cfg(not(unix))]
pub fn current_uid() -> u32 {
    0
}

/// Get the current effective group ID.
#[cfg(unix)]
pub fn current_gid() -> u32 {
    // SAFETY: getgid() is always safe
    unsafe { libc::getgid() }
}

#[cfg(not(unix))]
pub fn current_gid() -> u32 {
    0
}

/// Privilege dropper that handles switching from root to an unprivileged user.
///
/// This struct captures the target user/group at creation time and performs
/// the actual privilege drop when `drop_privileges()` is called.
pub struct PrivilegeDropper {
    target_uid: Option<u32>,
    target_gid: Option<u32>,
    username: Option<String>,
    groupname: Option<String>,
}

impl PrivilegeDropper {
    /// Create a new privilege dropper from configuration.
    ///
    /// # Arguments
    ///
    /// * `username` - Target username to switch to (e.g., "nobody", "hpn")
    /// * `groupname` - Target group (optional, uses user's primary group if None)
    ///
    /// # Errors
    ///
    /// Returns an error if the user doesn't exist or can't be looked up.
    #[cfg(unix)]
    pub fn new(username: Option<&str>, groupname: Option<&str>) -> ServerResult<Self> {
        let (target_uid, target_gid, resolved_username, resolved_groupname) =
            match (username, groupname) {
                (None, None) => {
                    // No privilege dropping configured
                    (None, None, None, None)
                }
                (Some(user), group) => {
                    // Look up user
                    let (uid, primary_gid) = lookup_user(user)?;

                    // Use specified group or user's primary group
                    let (gid, gname) = if let Some(g) = group {
                        let gid = lookup_group(g)?;
                        (gid, g.to_string())
                    } else {
                        // Get group name for the primary GID
                        let gname = lookup_group_name(primary_gid)
                            .unwrap_or_else(|| format!("{}", primary_gid));
                        (primary_gid, gname)
                    };

                    (Some(uid), Some(gid), Some(user.to_string()), Some(gname))
                }
                (None, Some(group)) => {
                    // Group specified without user - this is unusual but valid
                    let gid = lookup_group(group)?;
                    warn!(
                        "Group '{}' specified without user - will only change group",
                        group
                    );
                    (None, Some(gid), None, Some(group.to_string()))
                }
            };

        Ok(Self {
            target_uid,
            target_gid,
            username: resolved_username,
            groupname: resolved_groupname,
        })
    }

    #[cfg(not(unix))]
    pub fn new(_username: Option<&str>, _groupname: Option<&str>) -> ServerResult<Self> {
        Ok(Self {
            target_uid: None,
            target_gid: None,
            username: None,
            groupname: None,
        })
    }

    /// Check if privilege dropping is configured.
    pub fn is_configured(&self) -> bool {
        self.target_uid.is_some() || self.target_gid.is_some()
    }

    /// Drop privileges to the configured user/group.
    ///
    /// This should be called AFTER:
    /// - Binding to privileged ports
    /// - Creating TUN devices
    /// - Setting up NAT/iptables rules
    /// - Any other operations requiring root
    ///
    /// # Security
    ///
    /// Once privileges are dropped, they cannot be regained. This is intentional
    /// to prevent privilege escalation attacks.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Not running as root (nothing to drop)
    /// - setgid() fails
    /// - setuid() fails
    #[cfg(unix)]
    pub fn drop_privileges(&self) -> ServerResult<()> {
        if !self.is_configured() {
            debug!("Privilege dropping not configured, continuing as current user");
            return Ok(());
        }

        // Check if we're root
        if !is_root() {
            if self.is_configured() {
                warn!(
                    "Privilege dropping configured but not running as root (UID {})",
                    current_uid()
                );
            }
            return Ok(());
        }

        info!(
            "Dropping privileges: root -> {}:{}",
            self.username.as_deref().unwrap_or("(same)"),
            self.groupname.as_deref().unwrap_or("(same)")
        );

        // Drop supplementary groups first (before we lose root)
        // SAFETY: setgroups(0, NULL) removes all supplementary groups
        let ret = unsafe { libc::setgroups(0, std::ptr::null()) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            error!("Failed to clear supplementary groups: {}", err);
            return Err(ServerError::Config(format!("setgroups(0) failed: {}", err)));
        }
        debug!("Cleared supplementary groups");

        // Change group first (must be done before dropping UID)
        if let Some(gid) = self.target_gid {
            // SAFETY: setgid() is safe with a valid GID
            let ret = unsafe { libc::setgid(gid) };
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                error!("Failed to setgid({}): {}", gid, err);
                return Err(ServerError::Config(format!(
                    "setgid({}) failed: {}",
                    gid, err
                )));
            }

            // Also set effective and saved GIDs
            let ret = unsafe { libc::setegid(gid) };
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                error!("Failed to setegid({}): {}", gid, err);
                return Err(ServerError::Config(format!(
                    "setegid({}) failed: {}",
                    gid, err
                )));
            }

            debug!("Changed group to GID {}", gid);
        }

        // Change user (this is the point of no return)
        if let Some(uid) = self.target_uid {
            // SAFETY: setuid() is safe with a valid UID
            let ret = unsafe { libc::setuid(uid) };
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                error!("Failed to setuid({}): {}", uid, err);
                return Err(ServerError::Config(format!(
                    "setuid({}) failed: {}",
                    uid, err
                )));
            }

            // Also set effective and saved UIDs (belt and suspenders)
            let ret = unsafe { libc::seteuid(uid) };
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                error!("Failed to seteuid({}): {}", uid, err);
                return Err(ServerError::Config(format!(
                    "seteuid({}) failed: {}",
                    uid, err
                )));
            }

            debug!("Changed user to UID {}", uid);
        }

        // Verify we're no longer root
        if is_root() {
            error!("CRITICAL: Still running as root after privilege drop!");
            return Err(ServerError::Config(
                "Failed to drop privileges: still root".into(),
            ));
        }

        // Verify we can't regain root privileges
        // SAFETY: setuid(0) should fail if privileges were properly dropped
        let ret = unsafe { libc::setuid(0) };
        if ret == 0 {
            error!("CRITICAL: Was able to regain root privileges!");
            return Err(ServerError::Config(
                "Privilege drop incomplete: can still setuid(0)".into(),
            ));
        }

        // FIX-031: post-drop hardening on Linux.
        //
        // PR_SET_NO_NEW_PRIVS (since 3.5) makes any subsequent execve()
        // ignore set-uid / set-gid / file-capabilities bits. Once set,
        // the flag is inherited across forks and execs and CANNOT be
        // cleared — even an attacker who gains code execution as our
        // dropped user cannot regain elevated privileges by execing a
        // setuid helper like /bin/su or a vulnerable suid binary on the
        // host. Best-effort: log and continue if the kernel rejects it
        // (very old kernels predate the prctl).
        //
        // PR_SET_DUMPABLE=0 stops the kernel from producing a core dump
        // of this process. Core dumps after the drop would otherwise be
        // owned by root in /var/lib/systemd/coredump/ (or similar) and
        // could leak session keys / handshake state via the post-mortem
        // analysis path on a compromised host. We set it explicitly
        // because the kernel's auto-clear-on-setuid behaviour only
        // applies when crossing a uid boundary in a single syscall;
        // libc::setuid + setgid sequences sometimes leave dumpable=1.
        #[cfg(target_os = "linux")]
        {
            // SAFETY: prctl with PR_SET_NO_NEW_PRIVS takes 5 args of which
            // only arg2 is read for this option; the rest are ignored.
            let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                warn!(
                    "prctl(PR_SET_NO_NEW_PRIVS) failed: {} — running without it",
                    err
                );
            } else {
                debug!("prctl(PR_SET_NO_NEW_PRIVS) set");
            }

            // SAFETY: prctl with PR_SET_DUMPABLE takes one effective arg2.
            let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                warn!(
                    "prctl(PR_SET_DUMPABLE, 0) failed: {} — core dumps may leak secrets",
                    err
                );
            } else {
                debug!("prctl(PR_SET_DUMPABLE, 0) set — core dumps disabled");
            }
        }

        info!(
            "Successfully dropped privileges to UID {} GID {}",
            current_uid(),
            current_gid()
        );

        Ok(())
    }

    #[cfg(not(unix))]
    pub fn drop_privileges(&self) -> ServerResult<()> {
        if self.is_configured() {
            warn!("Privilege dropping is only supported on Unix systems");
        }
        Ok(())
    }

    /// Get the target username (if configured).
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    /// Get the target group name (if configured).
    pub fn groupname(&self) -> Option<&str> {
        self.groupname.as_deref()
    }
}

/// Look up a user by name and return (UID, primary GID).
#[cfg(unix)]
fn lookup_user(username: &str) -> ServerResult<(u32, u32)> {
    use std::ffi::CString;

    let c_username = CString::new(username).map_err(|_| {
        ServerError::Config(format!(
            "Invalid username (contains null byte): {}",
            username
        ))
    })?;

    // SAFETY: getpwnam() is safe with a valid C string, returns pointer to static data
    let pwd = unsafe { libc::getpwnam(c_username.as_ptr()) };

    if pwd.is_null() {
        return Err(ServerError::Config(format!(
            "User '{}' not found. Create it with: useradd -r -s /usr/sbin/nologin {}",
            username, username
        )));
    }

    // SAFETY: We verified pwd is not null
    let uid = unsafe { (*pwd).pw_uid };
    let gid = unsafe { (*pwd).pw_gid };

    debug!("Resolved user '{}' to UID {} GID {}", username, uid, gid);

    Ok((uid, gid))
}

/// Look up a group by name and return the GID.
#[cfg(unix)]
fn lookup_group(groupname: &str) -> ServerResult<u32> {
    use std::ffi::CString;

    let c_groupname = CString::new(groupname).map_err(|_| {
        ServerError::Config(format!(
            "Invalid group name (contains null byte): {}",
            groupname
        ))
    })?;

    // SAFETY: getgrnam() is safe with a valid C string
    let grp = unsafe { libc::getgrnam(c_groupname.as_ptr()) };

    if grp.is_null() {
        return Err(ServerError::Config(format!(
            "Group '{}' not found. Create it with: groupadd -r {}",
            groupname, groupname
        )));
    }

    // SAFETY: We verified grp is not null
    let gid = unsafe { (*grp).gr_gid };

    debug!("Resolved group '{}' to GID {}", groupname, gid);

    Ok(gid)
}

/// Look up a group name by GID.
#[cfg(unix)]
fn lookup_group_name(gid: u32) -> Option<String> {
    // SAFETY: getgrgid() is safe with any GID
    let grp = unsafe { libc::getgrgid(gid) };

    if grp.is_null() {
        return None;
    }

    // SAFETY: We verified grp is not null, gr_name is a valid C string
    let name_ptr = unsafe { (*grp).gr_name };
    if name_ptr.is_null() {
        return None;
    }

    // SAFETY: gr_name is a valid C string
    let c_str = unsafe { std::ffi::CStr::from_ptr(name_ptr) };
    c_str.to_str().ok().map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_root() {
        // This test just verifies the function doesn't panic
        let _ = is_root();
    }

    #[test]
    fn test_current_uid_gid() {
        let uid = current_uid();
        let gid = current_gid();
        // Just verify they return reasonable values
        // In tests, we're usually not root (UID 0)
        // But we can't make strong assertions about the values
        assert!(uid < u32::MAX);
        assert!(gid < u32::MAX);
    }

    #[test]
    fn test_privilege_dropper_not_configured() {
        let dropper = PrivilegeDropper::new(None, None).unwrap();
        assert!(!dropper.is_configured());
        assert!(dropper.username().is_none());
        assert!(dropper.groupname().is_none());
    }

    #[test]
    #[cfg(unix)]
    fn test_privilege_dropper_invalid_user() {
        // Try to create dropper with non-existent user
        let result = PrivilegeDropper::new(Some("__nonexistent_user_12345__"), None);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(unix)]
    fn test_privilege_dropper_valid_user() {
        // "root" or "nobody" should exist on most Unix systems
        // Try root first (always exists), then nobody
        let result = PrivilegeDropper::new(Some("root"), None);
        if let Ok(dropper) = result {
            assert!(dropper.is_configured());
            assert_eq!(dropper.username(), Some("root"));
        }
    }

    #[test]
    fn test_drop_privileges_not_configured() {
        let dropper = PrivilegeDropper::new(None, None).unwrap();
        // Should succeed even when not configured
        assert!(dropper.drop_privileges().is_ok());
    }
}
