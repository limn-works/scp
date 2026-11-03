//! The lifecycle domain of the SCP runtime (ADR-070 §2): creating, importing, restoring, joining, leaving and closing contexts.
//!
//! The crate exports [`Lifecycle`], the
//! [`LifecycleDomain`](scp_runtime_core::context::domains::LifecycleDomain) implementation
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
    "scp-runtime-lifecycle test targets require the `testing` feature: pass \
     `--features testing` (or `--features scp-runtime-lifecycle/testing` in a multi-package command)."
);

mod handler;
mod helpers;
mod logic;
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
    pub use crate::helpers::{drain_and_deliver_sender_keys, leave_context};
}

/// The lifecycle domain's [`LifecycleDomain`](scp_runtime_core::context::domains::LifecycleDomain)
/// implementation, which the assembly's `domain_handlers()` installs.
pub struct Lifecycle;

#[async_trait::async_trait]
impl scp_runtime_core::context::domains::LifecycleDomain for Lifecycle {
    async fn dispatch(
        &self,
        cell: &mut scp_runtime_core::context::actor::class_s::ClassSCell,
        deps: &scp_runtime_core::context::actor::deps::ActorDeps,
        cmd: scp_runtime_core::context::actor::commands::LifecycleCommand,
    ) -> scp_runtime_core::context::actor::outcome::Outcome<()> {
        handler::dispatch(cell, deps, cmd).await
    }

    async fn close_context(
        &self,
        cell: &mut scp_runtime_core::context::actor::class_s::ClassSCell,
        deps: &scp_runtime_core::context::actor::deps::ActorDeps,
        handle: &scp_runtime_core::context::ContextHandle,
        initiator_did: &scp_did::DID,
    ) -> Result<scp_runtime_core::context::ttl::CloseResult, scp_protocol::context::ContextError>
    {
        crate::helpers::close_context(cell, deps, handle, initiator_did).await
    }

    async fn create_context(
        &self,
        deps: &scp_runtime_core::context::actor::deps::ActorDeps,
        create: scp_runtime_core::context::domains::CreateContextRequest<'_>,
    ) -> Result<
        scp_runtime_core::context::shared::lifecycle::SpawnedContext,
        scp_protocol::context::builder::ContextCreationError,
    > {
        Box::pin(crate::helpers::create_context(
            deps,
            create.context_id,
            create.params,
            create.creator_did,
            create.local_pseudonym,
            create.relay_urls,
            create.first_state,
        ))
        .await
    }

    async fn drain_and_deliver_sender_keys(
        &self,
        deps: &scp_runtime_core::context::actor::deps::ActorDeps,
        view: &mut scp_runtime_core::context::actor::class_s::ClassCMut<'_>,
        context_id: &str,
        scope: scp_runtime_core::context::shared::lifecycle::DistributionScope,
    ) -> scp_runtime_core::context::actor::state::DistributionReport {
        crate::helpers::drain_and_deliver_sender_keys(deps, view, context_id, scope).await
    }

    async fn import_context_from_export(
        &self,
        deps: &scp_runtime_core::context::actor::deps::ActorDeps,
        export: scp_runtime_core::context::export_import::ContextExport,
        verifying_key: &ed25519_dalek::VerifyingKey,
        local_pseudonym: Option<[u8; 32]>,
        first_state: &scp_runtime_core::context::shared::lifecycle::FirstStateRollback,
    ) -> Result<
        scp_runtime_core::context::shared::lifecycle::SpawnedContext,
        scp_protocol::context::ContextError,
    > {
        Box::pin(crate::helpers::import_context(
            deps,
            export,
            verifying_key,
            local_pseudonym,
            first_state,
        ))
        .await
    }

    async fn restore_all_contexts(
        &self,
        supervisor: &std::sync::Arc<scp_runtime_core::context::supervisor::Supervisor>,
    ) -> Result<Vec<String>, scp_protocol::context::ContextError> {
        crate::helpers::restore_all_contexts(supervisor).await
    }

    async fn restore_context(
        &self,
        deps: &scp_runtime_core::context::actor::deps::ActorDeps,
        context_id: &str,
        handle: &scp_runtime_core::context::ContextHandle,
        preloaded_snapshot: Option<scp_runtime_core::context::state::ContextSnapshot>,
    ) -> Result<(), scp_protocol::context::ContextError> {
        Box::pin(crate::helpers::restore_context(
            deps,
            context_id,
            handle,
            preloaded_snapshot,
        ))
        .await
    }

    async fn retry_pending_sender_key_rotation(
        &self,
        cell: &mut scp_runtime_core::context::actor::class_s::ClassSCell,
        deps: &scp_runtime_core::context::actor::deps::ActorDeps,
        context_id: &str,
    ) {
        crate::helpers::retry_pending_sender_key_rotation(cell, deps, context_id).await;
    }

    async fn rotate_sender_key_and_distribute(
        &self,
        cell: &mut scp_runtime_core::context::actor::class_s::ClassSCell,
        deps: &scp_runtime_core::context::actor::deps::ActorDeps,
        context_id: &str,
    ) {
        crate::helpers::rotate_sender_key_and_distribute(cell, deps, context_id).await;
    }

    async fn shutdown_all_contexts(
        &self,
        supervisor: &scp_runtime_core::context::supervisor::Supervisor,
    ) {
        crate::helpers::shutdown_all_contexts(supervisor).await;
    }
}
