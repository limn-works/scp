//! The broadcast domain of the SCP runtime (ADR-070 §2): broadcast-context subscription, publication and subscriber blocking.
//!
//! The crate exports [`Broadcast`], the
//! [`BroadcastDomain`](scp_runtime_core::context::domains::BroadcastDomain) implementation
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
    "scp-runtime-broadcast test targets require the `testing` feature: pass \
     `--features testing` (or `--features scp-runtime-broadcast/testing` in a multi-package command)."
);

mod handler;
mod helpers;
#[cfg(test)]
mod test_support;

/// The broadcast domain's [`BroadcastDomain`](scp_runtime_core::context::domains::BroadcastDomain)
/// implementation, which the assembly's `domain_handlers()` installs.
pub struct Broadcast;

#[async_trait::async_trait]
impl scp_runtime_core::context::domains::BroadcastDomain for Broadcast {
    async fn dispatch(
        &self,
        cell: &mut scp_runtime_core::context::actor::class_s::ClassSCell,
        deps: &scp_runtime_core::context::actor::deps::ActorDeps,
        cmd: scp_runtime_core::context::actor::commands::BroadcastCommand,
    ) -> scp_runtime_core::context::actor::outcome::Outcome<()> {
        handler::dispatch(cell, deps, cmd).await
    }

    async fn block_broadcast_subscriber(
        &self,
        cell: &mut scp_runtime_core::context::actor::class_s::ClassSCell,
        deps: &scp_runtime_core::context::actor::deps::ActorDeps,
        context_id: &str,
        author_did: &scp_did::DID,
        subscriber_did: &scp_did::DID,
    ) -> Result<scp_protocol::context::broadcast::BlockResult, scp_protocol::context::ContextError>
    {
        crate::helpers::block_broadcast_subscriber(
            cell,
            deps,
            context_id,
            author_did,
            subscriber_did,
        )
        .await
    }

    async fn unblock_broadcast_subscriber(
        &self,
        cell: &mut scp_runtime_core::context::actor::class_s::ClassSCell,
        deps: &scp_runtime_core::context::actor::deps::ActorDeps,
        context_id: &str,
        author_did: &scp_did::DID,
        subscriber_did: &scp_did::DID,
    ) -> Result<(), scp_protocol::context::ContextError> {
        crate::helpers::unblock_broadcast_subscriber(
            cell,
            deps,
            context_id,
            author_did,
            subscriber_did,
        )
        .await
    }
}
