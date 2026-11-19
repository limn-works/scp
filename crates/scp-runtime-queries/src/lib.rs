//! The queries domain of the SCP runtime (ADR-070 §2): read-only context queries and checkpoint comparison.
//!
//! The crate exports [`Queries`], the
//! [`QueriesDomain`](scp_runtime_core::context::domains::QueriesDomain) implementation
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
    "scp-runtime-queries test targets require the `testing` feature: pass \
     `--features testing` (or `--features scp-runtime-queries/testing` in a multi-package command)."
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
    pub use crate::helpers::capability_requirements;
}

/// The queries domain's [`QueriesDomain`](scp_runtime_core::context::domains::QueriesDomain)
/// implementation, which the assembly's `domain_handlers()` installs.
pub struct Queries;

#[async_trait::async_trait]
impl scp_runtime_core::context::domains::QueriesDomain for Queries {
    async fn dispatch(
        &self,
        cell: &mut scp_runtime_core::context::actor::class_s::ClassSCell,
        deps: &scp_runtime_core::context::actor::deps::ActorDeps,
        cmd: scp_runtime_core::context::actor::commands::QueriesCommand,
    ) -> scp_runtime_core::context::actor::outcome::Outcome<()> {
        handler::dispatch(cell, deps, cmd).await
    }

    fn compare_remote_checkpoint(
        &self,
        view: &mut scp_runtime_core::context::actor::class_s::ClassCMut<'_>,
        deps: &scp_runtime_core::context::actor::deps::ActorDeps,
        context_id: &str,
        remote: &scp_event_log::checkpoint::ConsistencyCheckpoint,
    ) -> Result<scp_event_log::checkpoint::CheckpointComparison, scp_protocol::context::ContextError>
    {
        crate::helpers::compare_remote_checkpoint(view, deps, context_id, remote)
    }
}
