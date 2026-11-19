//! The ttl close domain of the SCP runtime (ADR-070 §2): context time-to-live, expiry and close.
//!
//! The crate exports [`TtlClose`], the
//! [`TtlCloseDomain`](scp_runtime_core::context::domains::TtlCloseDomain) implementation
//! that the assembly crate `scp-runtime` installs in
//! [`DomainHandlers`](scp_runtime_core::context::domains::DomainHandlers). Every other item is
//! private to the crate, except the `testing`-gated `testing_access` module.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

// Test targets require the `testing` feature: the `#[cfg(test)]` modules call
// `#[cfg(feature = "testing")]`-gated helpers of `scp-runtime-core`, and the
// command variants core gates on `testing` need this crate's match arms. No
// dev-dependency edge turns it on, so every test command names the feature. This
// tripwire turns a missing `--features` into a clear message instead of a cryptic E0599.
#[cfg(all(test, not(feature = "testing")))]
compile_error!(
    "scp-runtime-ttl-close test targets require the `testing` feature: pass \
     `--features testing` (or `--features scp-runtime-ttl-close/testing` in a multi-package command)."
);

mod handler;
mod helpers;
#[cfg(test)]
mod test_support;

/// The items sibling domain crates' tests call directly (`testing` only).
///
/// A domain's tests stay beside its code (ADR-070 plan §6.1), and a few of them
/// drive another domain's functions to set up or observe state. A sibling reaches
/// a domain only as a dev-dependency, so these items are exported here and
/// nowhere else; no production build compiles this module.
#[cfg(feature = "testing")]
pub mod testing_access {
    pub use crate::helpers::reset_ttl_timer;
}

/// The ttl-close domain's [`TtlCloseDomain`](scp_runtime_core::context::domains::TtlCloseDomain)
/// implementation, which the assembly's `domain_handlers()` installs.
pub struct TtlClose;

#[async_trait::async_trait]
impl scp_runtime_core::context::domains::TtlCloseDomain for TtlClose {
    async fn dispatch(
        &self,
        cell: &mut scp_runtime_core::context::actor::class_s::ClassSCell,
        deps: &scp_runtime_core::context::actor::deps::ActorDeps,
        cmd: scp_runtime_core::context::actor::commands::TtlCloseCommand,
    ) -> scp_runtime_core::context::actor::outcome::Outcome<()> {
        handler::dispatch(cell, deps, cmd).await
    }

    async fn extend_ttl_deadline_and_record(
        &self,
        cell: &mut scp_runtime_core::context::actor::class_s::ClassSCell,
        event_log: &dyn scp_runtime_core::context::builder::ContextEventLogProvider,
        context_id_bytes: &[u8; 32],
        actor_did: &str,
        additional_secs: u64,
        leaf: scp_runtime_core::context::shared::ttl_close::ExtensionLeaf,
    ) -> Result<(), scp_protocol::context::ContextError> {
        crate::helpers::extend_ttl_deadline_and_record(
            cell,
            event_log,
            context_id_bytes,
            actor_did,
            additional_secs,
            leaf,
        )
        .await
    }

    async fn handle_ttl_expiry(
        &self,
        cell: &mut scp_runtime_core::context::actor::class_s::ClassSCell,
        deps: &scp_runtime_core::context::actor::deps::ActorDeps,
        handle: &scp_runtime_core::context::ContextHandle,
        prior_completed: u8,
    ) -> scp_runtime_core::context::shared::ttl_close::TtlExpiryOutcome {
        crate::helpers::handle_ttl_expiry(cell, deps, handle, prior_completed).await
    }
}
