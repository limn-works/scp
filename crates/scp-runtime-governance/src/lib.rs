//! The governance domain of the SCP runtime (ADR-070 §2): proposals, votes, governance actions and their consequences.
//!
//! The crate exports [`Governance`], the
//! [`GovernanceDomain`](scp_runtime_core::context::domains::GovernanceDomain) implementation
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
    "scp-runtime-governance test targets require the `testing` feature: pass \
     `--features testing` (or `--features scp-runtime-governance/testing` in a multi-package command)."
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
    pub use crate::handler::evaluate_governance_timeouts;
    pub use crate::helpers::{
        ExecutedProposal, detect_and_handle_conflicts, execute_extend_ttl,
        execute_governance_action, execute_propose_context_migration, execute_reset_member,
        execute_restore_access, execute_revoke, execute_rotate_content_keys, list_proposals,
        propose_governance_action_inner,
    };
}

/// The governance domain's [`GovernanceDomain`](scp_runtime_core::context::domains::GovernanceDomain)
/// implementation, which the assembly's `domain_handlers()` installs.
pub struct Governance;

#[async_trait::async_trait]
impl scp_runtime_core::context::domains::GovernanceDomain for Governance {
    async fn dispatch(
        &self,
        cell: &mut scp_runtime_core::context::actor::class_s::ClassSCell,
        deps: &scp_runtime_core::context::actor::deps::ActorDeps,
        cmd: scp_runtime_core::context::actor::commands::GovernanceCommand,
    ) -> scp_runtime_core::context::actor::outcome::Outcome<()> {
        handler::dispatch(cell, deps, cmd).await
    }

    async fn evaluate_governance_timeouts(
        &self,
        cell: &mut scp_runtime_core::context::actor::class_s::ClassSCell,
        deps: &scp_runtime_core::context::actor::deps::ActorDeps,
    ) -> scp_runtime_core::context::actor::outcome::Outcome<bool> {
        handler::evaluate_governance_timeouts(cell, deps).await
    }

    async fn enforce_triggered_consequences(
        &self,
        state: &mut scp_runtime_core::context::actor::class_s::ConsequenceStateSplit<'_>,
        args: &scp_runtime_core::context::shared::governance::EnforceConsequencesCtx<'_>,
        obligation: &mut Option<scp_runtime_core::context::actor::class_s::ClassSCommitToken>,
    ) -> bool {
        crate::logic::enforce_triggered_consequences(state, args, obligation).await
    }

    fn event_log_entries_for_consequences(
        &self,
        receive_buffer: &scp_protocol::context::membership::ReceiveBuffer,
        context_id: &str,
        now: u64,
        event_log: &dyn scp_runtime_core::context::builder::ContextEventLogProvider,
    ) -> Result<(Vec<scp_event_log::Event>, u64), scp_protocol::context::ContextError> {
        crate::logic::event_log_entries_for_consequences(receive_buffer, context_id, now, event_log)
    }

    fn event_log_entries_for_consequences_after_side_effect(
        &self,
        receive_buffer: &scp_protocol::context::membership::ReceiveBuffer,
        context_id: &str,
        now: u64,
        event_log: &dyn scp_runtime_core::context::builder::ContextEventLogProvider,
    ) -> (Vec<scp_event_log::Event>, u64) {
        crate::logic::event_log_entries_for_consequences_after_side_effect(
            receive_buffer,
            context_id,
            now,
            event_log,
        )
    }

    async fn keep_broadcast_failure(
        &self,
        cell: &mut scp_runtime_core::context::actor::class_s::ClassSCell,
        deps: &scp_runtime_core::context::actor::deps::ActorDeps,
        context_id: &str,
        failure: scp_runtime_core::context::shared::governance::BroadcastFailure,
    ) -> Result<(), scp_protocol::context::ContextError> {
        crate::helpers::keep_broadcast_failure(cell, deps, context_id, failure).await
    }

    async fn try_broadcast_commit(
        &self,
        deps: &scp_runtime_core::context::actor::deps::ActorDeps,
        context_id: &str,
        commit_bytes: Vec<u8>,
        operation: &scp_runtime_core::context::state::CommitOperation,
    ) -> Option<scp_runtime_core::context::shared::governance::BroadcastFailure> {
        crate::helpers::try_broadcast_commit(deps, context_id, commit_bytes, operation).await
    }
}
