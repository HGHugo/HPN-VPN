//! Privacy / no-log mode for relay.

use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};

static NO_LOG: AtomicBool = AtomicBool::new(true);

pub fn init(no_log: bool) {
    NO_LOG.store(no_log, Ordering::SeqCst);
}

pub fn is_enabled() -> bool {
    NO_LOG.load(Ordering::Relaxed)
}

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

#[inline]
pub fn addr(a: SocketAddr) -> Redact<SocketAddr> {
    Redact(a)
}
