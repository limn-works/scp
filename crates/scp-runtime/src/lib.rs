#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
//! Async runtime orchestration for SCP (Shared Context Protocol).
//!
//! `scp-runtime` contains the async orchestration and stateful logic that all
//! SCP clients share:
//!
//! - [`crypto::mls`] — MLS (Messaging Layer Security) group encryption wrapper.
//!   Every SCP context maps to one MLS group. Provides create, add member,
//!   remove member, and destroy operations. See ADR-001.
//!
//! # Architecture
//!
//! `scp-runtime` depends on `scp-protocol` for pure sync types and
//! `scp-platform` for platform abstraction traits (key custody, storage).
//! It does not depend on any transport layer — the runtime is purely about
//! identity, crypto, and protocol logic.
//!
//! See `.docs/architecture.md` for the full crate layout and build phases.

#![forbid(unsafe_code)]

// scp-runtime test targets require the `testing` feature: numerous `#[cfg(test)]`
// modules call `#[cfg(feature = "testing")]`-gated helpers. `testing` is normally
// enabled transitively via the `scp-testing` dev-dependency; this tripwire turns a
// severed back-edge into a clear message instead of a cryptic E0599 (or silent vanish).
#[cfg(all(test, not(feature = "testing")))]
compile_error!(
    "scp-runtime test targets require the `testing` feature \
     (enabled transitively via the scp-testing dev-dependency, or pass \
     `--features scp-runtime/testing` explicitly)."
);

pub mod bridge;
pub mod context;
pub mod crypto;
pub mod discovery;
pub mod economy;
pub mod envelope;
pub mod event_log;
pub mod identity;
pub mod metrics;
pub mod provenance;
pub mod store;
pub mod sync;
pub mod trust;
pub mod well_known;

// Re-export the MLS module's primary types at the crate level for convenience.
pub use crypto::mls;
