//! The standing domain of the SCP runtime (ADR-070 §2): standing (bilateral) contexts between two participants.
//!
//! The crate exports [`Standing`], the
//! [`StandingDomain`](scp_runtime_core::context::domains::StandingDomain) implementation
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
    "scp-runtime-standing test targets require the `testing` feature: pass \
     `--features testing` (or `--features scp-runtime-standing/testing` in a multi-package command)."
);

mod handler;
mod helpers;
#[cfg(test)]
mod test_support;

/// The standing domain's [`StandingDomain`](scp_runtime_core::context::domains::StandingDomain)
/// implementation, which the assembly's `domain_handlers()` installs.
pub struct Standing;

#[async_trait::async_trait]
impl scp_runtime_core::context::domains::StandingDomain for Standing {
    async fn dispatch(
        &self,
        deps: &scp_runtime_core::context::actor::deps::ActorDeps,
        cmd: scp_runtime_core::context::actor::commands::StandingCommand,
    ) -> scp_runtime_core::context::actor::outcome::Outcome<()> {
        handler::dispatch(deps, cmd).await
    }
}
