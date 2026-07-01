//! HPN Relay - Multi-hop routing relay server.
//!
//! A relay server that forwards encrypted HPN packets between clients and
//! upstream servers, enabling multi-hop routing for enhanced privacy and
//! censorship resistance.
//!
//! # Architecture
//!
//! ```text
//! Client <-> Relay 1 <-> Relay 2 <-> ... <-> Server
//! ```
//!
//! The relay operates at the UDP layer, forwarding encrypted packets without
//! decrypting them. It maintains session state to route packets correctly
//! and provides NAT traversal support.

// Pedantic lint policy: these are intentional suppressions, not tech debt.
// Structural (would require significant refactoring):
#![allow(clippy::too_many_lines)]
#![allow(clippy::cognitive_complexity)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::cast_possible_truncation)]
// Style preferences (consistent across HPN crates):
#![allow(clippy::similar_names)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::struct_field_names)]
#![allow(clippy::single_match_else)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

pub mod config;
pub mod error;
pub mod log_file;
pub mod metrics;
pub mod privacy;
pub mod relay;
pub mod session;

/// Batch I/O using recvmmsg/sendmmsg for high-throughput forwarding.
///
/// **Experimental** — gated behind the `batch-io` Cargo feature, off by
/// default. The shipping `RelayServer::run` does NOT call into this
/// path: a complete integration (and the integration tests called for
/// in audit item M-8) is required before flipping the default. The
/// module compiles when the feature is enabled so operators can opt in
/// from a custom main, and so its compile-time correctness is checked
/// in CI without forcing it on every install.
///
/// Linux-only because `recvmmsg`/`sendmmsg` are Linux extensions.
#[cfg(all(target_os = "linux", feature = "batch-io"))]
pub mod batch_io;

pub use config::RelayConfig;
pub use error::{RelayError, RelayResult};
pub use metrics::RelayMetrics;
pub use relay::RelayServer;
pub use session::RelaySession;
