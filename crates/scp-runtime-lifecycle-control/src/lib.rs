//! The lifecycle control domain of the SCP runtime (ADR-070 §2): actor lifecycle control commands.
//!
//! The crate exports [`LifecycleControl`], the
//! [`LifecycleControlDomain`](scp_runtime_core::context::domains::LifecycleControlDomain) implementation
//! that the assembly crate `scp-runtime` installs in
//! [`DomainHandlers`](scp_runtime_core::context::domains::DomainHandlers). Every other item is
//! private to the crate.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

// Test targets require the `testing` feature: the `#[cfg(test)]` modules call
// `#[cfg(feature = "testing")]`-gated helpers of `scp-runtime-core`, and the
// command variants core gates on `testing` need this crate's match arms. No
// dev-dependency edge turns it on, so every test command names the feature. This
// tripwire turns a missing `--features` into a clear message instead of a cryptic E0599.
#[cfg(all(test, not(feature = "testing")))]
compile_error!(
    "scp-runtime-lifecycle-control test targets require the `testing` feature: pass \
     `--features testing` (or `--features scp-runtime-lifecycle-control/testing` in a multi-package command)."
);

mod handler;

/// The lifecycle-control domain's [`LifecycleControlDomain`](scp_runtime_core::context::domains::LifecycleControlDomain)
/// implementation, which the assembly's `domain_handlers()` installs.
pub struct LifecycleControl;

#[async_trait::async_trait]
impl scp_runtime_core::context::domains::LifecycleControlDomain for LifecycleControl {
    async fn dispatch(
        &self,
        cell: &mut scp_runtime_core::context::actor::class_s::ClassSCell,
        deps: &scp_runtime_core::context::actor::deps::ActorDeps,
        cmd: scp_runtime_core::context::actor::commands::LifecycleControlCommand,
    ) -> scp_runtime_core::context::actor::outcome::Outcome<()> {
        handler::dispatch(cell, deps, cmd).await
    }
}
