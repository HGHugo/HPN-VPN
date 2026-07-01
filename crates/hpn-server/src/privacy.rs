//! Privacy / no-log mode.
//!
//! When `no_log` mode is enabled, IP addresses are redacted from
//! log output using the `Redact<T>` wrapper. Use `privacy::addr()`
//! to wrap a SocketAddr before logging.

use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};

/// Global no-log flag. Set once at startup from config.
static NO_LOG: AtomicBool = AtomicBool::new(true);

/// Initialize the global no-log flag from the server config.
pub fn init(no_log: bool) {
    NO_LOG.store(no_log, Ordering::SeqCst);
}

/// Returns true if no-log mode is active.
pub fn is_enabled() -> bool {
    NO_LOG.load(Ordering::Relaxed)
}

/// A wrapper that redacts the inner value when displayed in no-log mode.
pub struct Redact<T: fmt::Display>(pub T);

impl<T: fmt::Display> fmt::Display for Redact<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if NO_LOG.load(Ordering::Relaxed) {
            write!(f, "[redacted]")
        } else {
            write!(f, "{}", self.0)
        }
    }
}

impl<T: fmt::Display + fmt::Debug> fmt::Debug for Redact<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if NO_LOG.load(Ordering::Relaxed) {
            write!(f, "[redacted]")
        } else {
            write!(f, "{:?}", self.0)
        }
    }
}

/// Convenience: wrap a SocketAddr for redacted display.
#[inline]
pub fn addr(a: SocketAddr) -> Redact<SocketAddr> {
    Redact(a)
}
