//! The SCP runtime's per-context actor, supervisor, stores and transports (ADR-070 §2).
//!
//! `scp-runtime-core` holds every runtime module that is neither a types module
//! (`scp-runtime-types`) nor one of the 13 domains: the per-context actor and its
//! dispatch hub, the [`Supervisor`](context::supervisor::Supervisor), persistence,
//! the stores, sync, trust and push. The hub reaches each domain only through the
//! [`DomainHandlers`](context::domains::DomainHandlers) trait objects that the
//! assembly crate `scp-runtime` builds, so no core module names a domain crate.
//!
//! See `.docs/architecture.md` for the full crate layout and build phases.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

// Test targets require the `testing` feature: numerous `#[cfg(test)]` modules call
// `#[cfg(feature = "testing")]`-gated helpers. No dev-dependency edge turns it on,
// so every test command names the feature. This tripwire turns a missing
// `--features` into a clear message instead of a cryptic E0599.
#[cfg(all(test, not(feature = "testing")))]
compile_error!(
    "scp-runtime-core test targets require the `testing` feature: pass \
     `--features testing` (or `--features scp-runtime-core/testing` in a multi-package command)."
);

pub mod context;
pub mod crypto;
pub mod envelope;
pub mod identity;
pub mod push;
pub mod store;
pub mod sync;
pub mod trust;

// Re-export the MLS module's primary types at the crate level for convenience.
pub use crypto::mls;
