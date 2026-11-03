//! The push domain of the SCP runtime (ADR-070 §2): push-notification registration commands.
//!
//! The crate exports [`Push`], the
//! [`PushDomain`](scp_runtime_core::context::domains::PushDomain) implementation
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
    "scp-runtime-push test targets require the `testing` feature: pass \
     `--features testing` (or `--features scp-runtime-push/testing` in a multi-package command)."
);

mod handler;
mod helpers;

/// The push domain's [`PushDomain`](scp_runtime_core::context::domains::PushDomain)
/// implementation, which the assembly's `domain_handlers()` installs.
pub struct Push;

impl scp_runtime_core::context::domains::PushDomain for Push {
    fn dispatch(
        &self,
        state: &scp_runtime_core::context::actor::state::PerContextState,
        cmd: scp_runtime_core::context::actor::commands::PushCommand,
    ) -> scp_runtime_core::context::actor::outcome::Outcome<()> {
        handler::dispatch(state, cmd)
    }
}
