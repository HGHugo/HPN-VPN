//! Size-based rolling file appender for production logging.
//!
//! Writes log output to a file with automatic rotation when the file
//! exceeds `max_size_bytes`. Old files are renamed with `.1`, `.2`, etc.
//! suffixes and the oldest are deleted when `max_files` is exceeded.
//!
//! Thread-safe via `parking_lot::Mutex`. The mutex is only held during
//! the actual `write()` call — no contention with the tracing subscriber.

use parking_lot::Mutex;
use std::fs;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// File mode used for log files on Unix targets.
///
/// `0o640` = owner rw, group r, others none. Server logs contain
/// invalid-packet traces, rate-limit events, error messages and
/// session lifecycle events; even with `no_log = true` the metadata
/// can aid an attacker performing reconnaissance, so the file is not
/// world-readable on multi-user hosts. Group read is preserved so a
/// dedicated logging group (e.g. `adm` on Debian) can ship logs to
/// the SIEM without elevation.
#[cfg(unix)]
const LOG_FILE_MODE: u32 = 0o640;

/// Apply restrictive permissions to a freshly-created log file.
///
/// Best-effort: a permission error is logged via `eprintln!` (the
/// tracing subscriber is not yet initialised when this runs from
/// `tracing-subscriber::fmt::Layer::with_writer` setup) and not
/// propagated, so a slightly-too-permissive log file does not block
/// server startup.
#[cfg(unix)]
fn restrict_log_permissions(path: &Path) {
    if let Err(e) = fs::set_permissions(path, fs::Permissions::from_mode(LOG_FILE_MODE)) {
        eprintln!(
            "Could not set restrictive permissions ({:o}) on log file {}: {}",
            LOG_FILE_MODE,
            path.display(),
            e
        );
    }
}

#[cfg(not(unix))]
fn restrict_log_permissions(_path: &Path) {
    // Windows ACLs are inherited from the parent directory; we rely on
    // the operator placing the log directory under an appropriately
    // restricted path (e.g. ProgramData with the SYSTEM-and-Admins
    // ACL) rather than touching ACLs from Rust.
}

/// A size-based rolling file writer.
///
/// Implements `io::Write` for use with `tracing_subscriber::fmt::MakeWriter`.
pub struct RollingFileWriter {
    inner: Arc<Mutex<RollingFileInner>>,
}

struct RollingFileInner {
    path: PathBuf,
    file: fs::File,
    current_size: u64,
    max_size: u64,
    max_files: u32,
}

impl RollingFileWriter {
    /// Create a new rolling file writer.
    ///
    /// # Arguments
    /// * `path` — Log file path (e.g., `/var/log/hpn/server.log`)
    /// * `max_size_mb` — Rotate when file exceeds this size in MB
    /// * `max_files` — Keep at most this many rotated files (e.g., 5 → .1 .2 .3 .4 .5)
    pub fn new(path: &str, max_size_mb: u64, max_files: u32) -> io::Result<Self> {
        let path = PathBuf::from(path);

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Open file in append mode
        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;

        // Tighten permissions immediately after creation so the world-
        // readable default (mode 0644 on most Linux distros) does not
        // outlive even the first write. Soft-fail: see helper docstring.
        restrict_log_permissions(&path);

        let current_size = file.metadata().map(|m| m.len()).unwrap_or(0);

        Ok(Self {
            inner: Arc::new(Mutex::new(RollingFileInner {
                path,
                file,
                current_size,
                max_size: max_size_mb * 1024 * 1024,
                max_files,
            })),
        })
    }
}

impl Clone for RollingFileWriter {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl io::Write for RollingFileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut inner = self.inner.lock();
        let written = inner.file.write(buf)?;
        inner.current_size += written as u64;

        // Check if rotation is needed
        if inner.current_size >= inner.max_size {
            inner.rotate();
        }

        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.lock().file.flush()
    }
}

impl RollingFileInner {
    /// Rotate log files: server.log → server.log.1 → server.log.2 → ... → delete oldest.
    ///
    /// Safety: we first probe that we can create a new primary file. If we
    /// cannot (disk full, permission denied), we abandon the rotation and
    /// keep writing to the current fd unchanged — no data loss, no ring
    /// cascade. Only when the new-file create succeeds do we perform the
    /// rename cascade and swap fds. This is atomic on POSIX filesystems.
    fn rotate(&mut self) {
        // Flush current file before renaming.
        let _ = self.file.flush();

        // Probe: create the replacement file at a temp path first. If this
        // fails, abort rotation entirely to avoid the ring-cascade data-loss
        // bug where a failed open would still delete `.max_files` and shift
        // all rotated files, but leave the fd pointing at an orphaned file.
        let tmp_path = format!("{}.rotate-tmp", self.path.display());
        let new_file = match fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&tmp_path)
        {
            Ok(f) => f,
            Err(e) => {
                eprintln!(
                    "Log rotation skipped (cannot create {}: {}); continuing on current file",
                    tmp_path, e
                );
                // Reset size so we don't re-enter rotate() on every write —
                // this gives transient failures a chance to clear and also
                // simply lets the current file grow past max until next check.
                self.current_size = 0;
                return;
            }
        };

        // Tighten permissions on the replacement file before it gets
        // installed as the primary slot, so a brief race window
        // between rename and the next `restrict_log_permissions`
        // cannot leave the world-readable default in place.
        restrict_log_permissions(std::path::Path::new(&tmp_path));

        // Delete the oldest file if it exists.
        let oldest = format!("{}.{}", self.path.display(), self.max_files);
        let _ = fs::remove_file(&oldest);

        // Shift existing rotated files: .4 → .5, .3 → .4, .2 → .3, .1 → .2.
        for i in (1..self.max_files).rev() {
            let from_path = format!("{}.{}", self.path.display(), i);
            let to_path = format!("{}.{}", self.path.display(), i + 1);
            let _ = fs::rename(&from_path, &to_path);
        }

        // Rename current → .1.
        let rotated = format!("{}.1", self.path.display());
        let _ = fs::rename(&self.path, &rotated);

        // Move the pre-opened replacement into the primary slot.
        if let Err(e) = fs::rename(&tmp_path, &self.path) {
            eprintln!(
                "Log rotation: failed to install new primary ({}); logs saved to {}",
                e, rotated
            );
            let _ = fs::remove_file(&tmp_path);
            self.current_size = 0;
            return;
        }

        self.file = new_file;
        self.current_size = 0;
    }
}

/// A `MakeWriter` implementation for tracing that writes to the rolling file.
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for RollingFileWriter {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}
