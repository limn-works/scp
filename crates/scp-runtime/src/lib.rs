#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
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
// modules call `#[cfg(feature = "testing")]`-gated helpers. No dev-dependency edge
// turns it on, because any edge back to this crate makes its lib test wait for its lib
// (see the note above the `[[example]]` entries in Cargo.toml), so every test command
// names the feature. This tripwire turns a missing `--features` into a clear message
// instead of a cryptic E0599.
#[cfg(all(test, not(feature = "testing")))]
compile_error!(
    "scp-runtime test targets require the `testing` feature: pass \
     `--features testing` (or `--features scp-runtime/testing` in a multi-package command)."
);

pub mod context;
pub mod crypto;
pub mod discovery;
pub mod economy;
pub mod envelope;
pub mod identity;
pub mod metrics;
pub mod provenance;
pub mod push;
pub mod store;
pub mod sync;
pub mod trust;
pub mod well_known;

// Re-export the MLS module's primary types at the crate level for convenience.
pub use crypto::mls;

/// Builds the 13 domain handlers every [`Supervisor`] takes as its last
/// constructor argument (ADR-070 §3).
///
/// This is the one production constructor of
/// [`DomainHandlers`](context::domains::DomainHandlers): each field holds the
/// field-less struct that forwards to its domain's functions.
///
/// [`Supervisor`]: context::supervisor::Supervisor
#[must_use]
pub fn domain_handlers() -> context::domains::DomainHandlers {
    use context::actor::handlers;
    use std::sync::Arc;
    context::domains::DomainHandlers {
        messaging: Arc::new(handlers::messaging::Messaging),
        lifecycle: Arc::new(handlers::lifecycle::Lifecycle),
        governance: Arc::new(handlers::governance::Governance),
        broadcast: Arc::new(handlers::broadcast::Broadcast),
        economy: Arc::new(handlers::economy::Economy),
        trust_recovery: Arc::new(handlers::trust_recovery::TrustRecovery),
        standing: Arc::new(handlers::standing::Standing),
        ttl_close: Arc::new(handlers::ttl_close::TtlClose),
        outlets: Arc::new(handlers::outlets::Outlets),
        push: Arc::new(handlers::push::Push),
        queries: Arc::new(handlers::queries::Queries),
        saga: Arc::new(handlers::saga::Saga),
        lifecycle_control: Arc::new(handlers::lifecycle_control::LifecycleControl),
    }
}
