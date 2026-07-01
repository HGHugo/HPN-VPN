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
use std::path::PathBuf;
use std::sync::Arc;

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
    /// Rotate log files. See `hpn-server/src/log_file.rs::rotate` for the full
    /// design notes. Key invariant: probe the new-file create BEFORE renaming
    /// so a failure leaves all existing files intact.
    fn rotate(&mut self) {
        let _ = self.file.flush();

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
                self.current_size = 0;
                return;
            }
        };

        let oldest = format!("{}.{}", self.path.display(), self.max_files);
        let _ = fs::remove_file(&oldest);

        for i in (1..self.max_files).rev() {
            let from_path = format!("{}.{}", self.path.display(), i);
            let to_path = format!("{}.{}", self.path.display(), i + 1);
            let _ = fs::rename(&from_path, &to_path);
        }

        let rotated = format!("{}.1", self.path.display());
        let _ = fs::rename(&self.path, &rotated);

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
