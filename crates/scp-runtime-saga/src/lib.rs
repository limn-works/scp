//! The saga domain of the SCP runtime (ADR-070 §2): the cross-context saga phases.
//!
//! The crate exports [`Saga`], the
//! [`SagaDomain`](scp_runtime_core::context::domains::SagaDomain) implementation
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
    "scp-runtime-saga test targets require the `testing` feature: pass \
     `--features testing` (or `--features scp-runtime-saga/testing` in a multi-package command)."
);

mod handler;
#[cfg(test)]
mod test_support;

/// The saga domain's [`SagaDomain`](scp_runtime_core::context::domains::SagaDomain)
/// implementation, which the assembly's `domain_handlers()` installs.
pub struct Saga;

#[async_trait::async_trait]
impl scp_runtime_core::context::domains::SagaDomain for Saga {
    async fn dispatch(
        &self,
        cell: &mut scp_runtime_core::context::actor::class_s::ClassSCell,
        deps: &scp_runtime_core::context::actor::deps::ActorDeps,
        cmd: scp_runtime_core::context::actor::commands::SagaPhaseMessage,
    ) -> scp_runtime_core::context::actor::outcome::Outcome<()> {
        handler::dispatch(cell, deps, cmd).await
    }
}
