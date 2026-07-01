//! HPN Core Library
//!
//! This crate provides the core cryptographic primitives and protocol
//! implementation for the HPN VPN.
//!
//! # Modules
//!
//! - [`crypto`]: Cryptographic primitives (hybrid KEM, signatures, AEAD, KDF)
//! - [`protocol`]: Protocol messages, header, handshake, and session management
//! - [`types`]: Common types used throughout the library
//! - [`error`]: Error types

// Pedantic lint policy: intentional suppressions.
// Structural (numeric casts, complex functions, lock patterns):
#![allow(clippy::too_many_lines)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::struct_excessive_bools)]
// Style (consistent across HPN crates):
#![allow(clippy::similar_names)]
#![allow(clippy::struct_field_names)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::missing_fields_in_debug)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::unnecessary_wraps)]
// Pervasive in crypto code (155 occurrences):
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::doc_markdown)]

pub mod crypto;
pub mod error;
pub mod perf;
pub mod protocol;
pub mod provider_envelope;
pub mod types;

pub use error::{Error, Result};
pub use perf::{
    AlignedBuffer, BatchProcessor, BufferPool, LockFreeBufferPool, SlabAllocator, ThroughputTracker,
};
pub use types::*;
