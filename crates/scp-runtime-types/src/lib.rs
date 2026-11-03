//! Types, codecs and stateless services of the SCP runtime (ADR-070 §2).
//!
//! These modules depend on no runtime state: configuration and policy types,
//! access-key, sender-key and UCAN codecs, the MLS backend, discovery,
//! economy, identity and well-known records. `scp-runtime-core` and every
//! domain crate build on them.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

// Test targets require the `testing` feature: `#[cfg(test)]` modules call
// `#[cfg(feature = "testing")]`-gated helpers of the scp dependencies. This
// tripwire turns a missing `--features` into a clear message instead of a
// cryptic E0599.
#[cfg(all(test, not(feature = "testing")))]
compile_error!(
    "scp-runtime-types test targets require the `testing` feature: pass \
     `--features testing` (or `--features scp-runtime-types/testing` in a multi-package command)."
);

pub mod context;
pub mod crypto;
pub mod discovery;
pub mod economy;
pub mod envelope;
pub mod identity;
pub mod metrics;
pub mod provenance;
pub mod sync;
pub mod trust;
pub mod well_known;
