//! Governance handlers — see
//! [`GovernanceCommand`](crate::context::actor::commands::GovernanceCommand)
//! and plan row 10 of the commit ladder.
//!
//! # Commit 10 scope
//!
//! Migrates the dispatch shape: the handler takes
//! `&Arc<ContextManager>` + [`ActorDeps`] + [`GovernanceCommand`], returns
//! `Outcome<()>`.
//!
//! The underlying byte-identical implementation still lives on
//! [`ContextManager`](crate::context::manager::ContextManager): each
//! handler delegates to
//! [`ContextManager::propose_governance_action`](crate::context::manager::ContextManager::propose_governance_action),
//! [`ContextManager::propose_governance_action_checked`](crate::context::manager::ContextManager::propose_governance_action_checked),
//! [`ContextManager::vote_on_proposal`](crate::context::manager::ContextManager::vote_on_proposal),
//! [`ContextManager::approve_governance_proposal`](crate::context::manager::ContextManager::approve_governance_proposal),
//! [`ContextManager::reject_governance_proposal`](crate::context::manager::ContextManager::reject_governance_proposal),
//! [`ContextManager::withdraw_governance_vote`](crate::context::manager::ContextManager::withdraw_governance_vote),
//! [`ContextManager::execute_governance_action`](crate::context::manager::ContextManager::execute_governance_action),
//! [`ContextManager::get_proposal`](crate::context::manager::ContextManager::get_proposal),
//! [`ContextManager::list_proposals`](crate::context::manager::ContextManager::list_proposals),
//! [`ContextManager::apply_pending_ceiling_modification`](crate::context::manager::ContextManager::apply_pending_ceiling_modification),
//! [`ContextManager::apply_pending_economic_policy_change`](crate::context::manager::ContextManager::apply_pending_economic_policy_change),
//! [`ContextManager::tombstone_migrated_context`](crate::context::manager::ContextManager::tombstone_migrated_context),
//! [`ContextManager::migration_state`](crate::context::manager::ContextManager::migration_state),
//! or
//! [`ContextManager::acknowledge_commit_fault`](crate::context::manager::ContextManager::acknowledge_commit_fault).
//! The shim's job is:
//!
//! 1. Wrap the delegated call in [`tokio::time::timeout`] with a 30s
//!    budget per ADR-049 §7 / plan §"Transport timeouts inside actor
//!    handlers". Timeout maps to
//!    [`ContextError::TransportTimeout`](scp_protocol::context::ContextError::TransportTimeout).
//! 2. Preserve byte-identical on-the-wire behaviour — proposal IDs,
//!    signature sets, event emission, and MLS epoch coordination are
//!    produced by the legacy methods unchanged.
//!
//! # Transport-timeout budget
//!
//! [`HANDLER_TIMEOUT`] is the handler-level budget. The legacy
//! `ContextManager` methods do not carry their own deadline — this is
//! the new behaviour introduced by ADR-049 §7. 30 seconds matches the
//! plan's "every transport and storage call inside a handler wraps
//! `tokio::time::timeout(30s, ...)`" contract.
//!
//! # Read vs. mutate classification
//!
//! Only `GetProposal`, `ListProposals`, and `MigrationState` are read-
//! only — the handler uses [`Outcome::ok(())`](crate::context::actor::outcome::Outcome::ok).
//! Every other variant mutates per-context state (proposal lifecycle,
//! vote tallies, executed-proposals replay set, ceiling / economic-
//! policy slots, migration flags) and uses
//! [`Outcome::ok_mutated(())`](crate::context::actor::outcome::Outcome::ok_mutated).
//! `AcknowledgeCommitFault` takes the fault marker out of the context
//! — that is a mutation regardless of whether any observable state
//! changes beyond the marker slot.

use std::sync::Arc;
use std::time::Duration;

use scp_protocol::context::ContextError;
use tokio::sync::oneshot;

use crate::context::actor::commands::{
    ExecuteGovernanceActionPayload, GovernanceCommand, ProposeGovernanceActionCheckedReply,
    ProposeGovernanceActionPayload, ProposeGovernanceActionReply, VoteOnProposalPayload,
    VoteOnProposalReply,
};
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;
use crate::context::manager::ContextManager;

/// Per-call transport budget for governance handlers. Plan
/// §"Transport timeouts inside actor handlers": 30 seconds.
pub const HANDLER_TIMEOUT: Duration = Duration::from_secs(30);

/// Dispatch a [`GovernanceCommand`] against an attached manager + deps
/// bundle.
///
/// Plan-conforming dispatch signature: matches the post-refactor actor
/// `run()` loop's call shape
/// (`handlers::governance::dispatch(&mgr, &self.deps, cmd).await`).
/// `deps` is accepted for symmetry — the governance handler does not
/// yet touch deps during the shim period. Commit 12 rewires these paths
/// once the manager surface is deleted.
pub async fn dispatch(
    mgr: &Arc<ContextManager>,
    _deps: &ActorDeps,
    cmd: GovernanceCommand,
) -> Outcome<()> {
    // `Box::pin` the dispatch future — the combined per-variant locals
    // (GovernanceProposal ~1KB, ContextParams ~1KB, and the 30s-timeout
    // future each variant wraps) cross clippy's 16-KB stack budget for
    // async futures. Boxing here moves the per-variant state onto the
    // heap once per dispatch.
    Box::pin(dispatch_inner(mgr, cmd)).await
}

/// Shim-callable dispatch. Used by
/// [`Supervisor::dispatch_governance_command`](crate::context::supervisor::supervisor::Supervisor::dispatch_governance_command)
/// during the commits-10-to-11 migration window — deleted in commit 12
/// when the shim dissolves and the actor's `run()` loop is the only
/// caller of [`dispatch`].
///
/// Governance commands do not yet touch [`ActorDeps`] during the shim
/// period. This entry point exists so callers can route governance
/// operations through the shim without synthesizing an [`ActorDeps`] —
/// matching the pattern established for queries (commit 7), messaging
/// (commit 8), and lifecycle + ttl_close (commit 9).
pub(crate) async fn dispatch_from_shim(
    mgr: &Arc<ContextManager>,
    cmd: GovernanceCommand,
) -> Outcome<()> {
    Box::pin(dispatch_inner(mgr, cmd)).await
}

async fn dispatch_inner(mgr: &Arc<ContextManager>, cmd: GovernanceCommand) -> Outcome<()> {
    match cmd {
        GovernanceCommand::Placeholder { reply } => reply_not_implemented(reply),
        GovernanceCommand::ProposeGovernanceAction { payload, reply } => {
            Box::pin(handle_propose_governance_action(
                mgr, *payload, reply, false,
            ))
            .await
        }
        GovernanceCommand::ProposeGovernanceActionChecked { payload, reply } => {
            Box::pin(handle_propose_governance_action_checked(
                mgr, *payload, reply,
            ))
            .await
        }
        GovernanceCommand::VoteOnProposal {
            payload,
            approve,
            reply,
        } => Box::pin(handle_vote_on_proposal(mgr, *payload, approve, reply)).await,
        GovernanceCommand::ApproveGovernanceProposal { payload, reply } => {
            Box::pin(handle_approve_governance_proposal(mgr, *payload, reply)).await
        }
        GovernanceCommand::RejectGovernanceProposal { payload, reply } => {
            Box::pin(handle_reject_governance_proposal(mgr, *payload, reply)).await
        }
        GovernanceCommand::WithdrawGovernanceVote {
            context_id,
            proposal_id,
            voter_did,
            reply,
        } => {
            handle_withdraw_governance_vote(mgr, &context_id, &proposal_id, &voter_did, reply).await
        }
        GovernanceCommand::ExecuteGovernanceAction { payload, reply } => {
            Box::pin(handle_execute_governance_action(mgr, *payload, reply)).await
        }
        GovernanceCommand::GetProposal {
            context_id,
            proposal_id,
            reply,
        } => handle_get_proposal(mgr, &context_id, &proposal_id, reply).await,
        GovernanceCommand::ListProposals { context_id, reply } => {
            handle_list_proposals(mgr, &context_id, reply).await
        }
        GovernanceCommand::ApplyPendingCeilingModification {
            context_id,
            current_timestamp,
            reply,
        } => {
            handle_apply_pending_ceiling_modification(mgr, &context_id, current_timestamp, reply)
                .await
        }
        GovernanceCommand::ApplyPendingEconomicPolicyChange {
            context_id,
            current_timestamp,
            reply,
        } => {
            handle_apply_pending_economic_policy_change(mgr, &context_id, current_timestamp, reply)
                .await
        }
        GovernanceCommand::TombstoneMigratedContext { context_id, reply } => {
            handle_tombstone_migrated_context(mgr, &context_id, reply).await
        }
        GovernanceCommand::MigrationState { context_id, reply } => {
            handle_migration_state(mgr, &context_id, reply).await
        }
        GovernanceCommand::AcknowledgeCommitFault { context_id, reply } => {
            handle_acknowledge_commit_fault(mgr, &context_id, reply).await
        }
    }
}

/// Handle [`GovernanceCommand::ProposeGovernanceAction`] — delegates to
/// [`ContextManager::propose_governance_action`](crate::context::manager::ContextManager::propose_governance_action)
/// under a 30s timeout. `_checked` is a sibling flag the dispatch
/// function uses to pick between the two manager entry points; this
/// helper handles only the unchecked variant (checked has its own
/// helper because the reply type differs).
async fn handle_propose_governance_action(
    mgr: &Arc<ContextManager>,
    p: ProposeGovernanceActionPayload,
    reply: ProposeGovernanceActionReply,
    _checked: bool,
) -> Outcome<()> {
    let manager = Arc::clone(mgr);
    let context_id = p.context_id.clone();
    let signing_key = p.signing_key.to_signing_key();

    // Box::pin the propose future — the underlying governance path's
    // 16 KB+ locals crosses clippy's stack budget for async futures
    // (ADR-049 commit 12c.2 observed this after the lifecycle / ttl_close
    // hoist tightened some call-graph futures adjacent to the governance
    // path). Boxing moves the state onto the heap.
    let propose_fut = async move {
        Box::pin(
            crate::context::governance_helpers::propose_governance_action(
                &manager,
                &p.context_id,
                &p.proposer_did,
                p.action,
                &signing_key,
            ),
        )
        .await
    };

    let (outcome, reply_result) = match Box::pin(tokio::time::timeout(HANDLER_TIMEOUT, propose_fut))
        .await
    {
        Ok(Ok(tuple)) => (Outcome::ok_mutated(()), Ok(tuple)),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "propose_governance_action exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`GovernanceCommand::ProposeGovernanceActionChecked`] —
/// delegates to
/// [`ContextManager::propose_governance_action_checked`](crate::context::manager::ContextManager::propose_governance_action_checked)
/// under a 30s timeout.
async fn handle_propose_governance_action_checked(
    mgr: &Arc<ContextManager>,
    p: ProposeGovernanceActionPayload,
    reply: ProposeGovernanceActionCheckedReply,
) -> Outcome<()> {
    let manager = Arc::clone(mgr);
    let context_id = p.context_id.clone();
    let signing_key = p.signing_key.to_signing_key();

    // Box::pin — see the rationale on the sibling
    // `handle_propose_governance_action`.
    let propose_fut = async move {
        Box::pin(
            crate::context::governance_helpers::propose_governance_action_checked(
                &manager,
                &p.context_id,
                &p.proposer_did,
                p.action,
                &signing_key,
            ),
        )
        .await
    };

    let (outcome, reply_result) = match Box::pin(tokio::time::timeout(HANDLER_TIMEOUT, propose_fut))
        .await
    {
        Ok(Ok(outcome_val)) => (Outcome::ok_mutated(()), Ok(outcome_val)),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "propose_governance_action_checked exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`GovernanceCommand::VoteOnProposal`] — delegates to
/// [`ContextManager::vote_on_proposal`](crate::context::manager::ContextManager::vote_on_proposal)
/// under a 30s timeout.
async fn handle_vote_on_proposal(
    mgr: &Arc<ContextManager>,
    p: VoteOnProposalPayload,
    approve: bool,
    reply: VoteOnProposalReply,
) -> Outcome<()> {
    let manager = Arc::clone(mgr);
    let context_id = p.context_id.clone();
    let signing_key = p.signing_key.to_signing_key();

    // Box::pin — see sibling `handle_propose_governance_action`. The
    // governance-path future crosses clippy's 16 KB stack budget after
    // the 12c.3b hoist; boxing inside the `async move` keeps the
    // heap allocation per-call rather than per-handler.
    let vote_fut = async move {
        Box::pin(crate::context::governance_helpers::vote_on_proposal(
            &manager,
            &p.context_id,
            &p.proposal_id,
            &p.voter_did,
            approve,
            &signing_key,
        ))
        .await
    };

    // Box::pin — governance futures cross clippy's 16 KB stack budget
    // (ADR-049 commit 12c.2). See sibling `handle_propose_governance_action`.
    let (outcome, reply_result) =
        match Box::pin(tokio::time::timeout(HANDLER_TIMEOUT, vote_fut)).await {
            Ok(Ok(tuple)) => (Outcome::ok_mutated(()), Ok(tuple)),
            Ok(Err(e)) => {
                let sketch = outcome_error_sketch(&e);
                (Outcome::err_mutated(sketch), Err(e))
            }
            Err(_elapsed) => {
                let err = ContextError::TransportTimeout(format!(
                    "vote_on_proposal exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
                ));
                let sketch = outcome_error_sketch(&err);
                (Outcome::err_mutated(sketch), Err(err))
            }
        };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`GovernanceCommand::ApproveGovernanceProposal`] — delegates
/// to
/// [`ContextManager::approve_governance_proposal`](crate::context::manager::ContextManager::approve_governance_proposal)
/// under a 30s timeout.
async fn handle_approve_governance_proposal(
    mgr: &Arc<ContextManager>,
    p: VoteOnProposalPayload,
    reply: oneshot::Sender<Result<scp_protocol::context::governance::ProposalStatus, ContextError>>,
) -> Outcome<()> {
    let manager = Arc::clone(mgr);
    let context_id = p.context_id.clone();
    let signing_key = p.signing_key.to_signing_key();

    // Box::pin — see sibling `handle_propose_governance_action`.
    let approve_fut = async move {
        Box::pin(
            crate::context::governance_helpers::approve_governance_proposal(
                &manager,
                &p.context_id,
                &p.proposal_id,
                &p.voter_did,
                &signing_key,
            ),
        )
        .await
    };

    // Box::pin — see sibling `handle_propose_governance_action`.
    let (outcome, reply_result) = match Box::pin(tokio::time::timeout(HANDLER_TIMEOUT, approve_fut))
        .await
    {
        Ok(Ok(status)) => (Outcome::ok_mutated(()), Ok(status)),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "approve_governance_proposal exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`GovernanceCommand::RejectGovernanceProposal`] — delegates
/// to
/// [`ContextManager::reject_governance_proposal`](crate::context::manager::ContextManager::reject_governance_proposal)
/// under a 30s timeout.
async fn handle_reject_governance_proposal(
    mgr: &Arc<ContextManager>,
    p: VoteOnProposalPayload,
    reply: oneshot::Sender<Result<scp_protocol::context::governance::ProposalStatus, ContextError>>,
) -> Outcome<()> {
    let manager = Arc::clone(mgr);
    let context_id = p.context_id.clone();
    let signing_key = p.signing_key.to_signing_key();

    // Box::pin — see sibling `handle_propose_governance_action`.
    let reject_fut = async move {
        Box::pin(
            crate::context::governance_helpers::reject_governance_proposal(
                &manager,
                &p.context_id,
                &p.proposal_id,
                &p.voter_did,
                &signing_key,
            ),
        )
        .await
    };

    // Box::pin — see sibling `handle_propose_governance_action`.
    let (outcome, reply_result) = match Box::pin(tokio::time::timeout(HANDLER_TIMEOUT, reject_fut))
        .await
    {
        Ok(Ok(status)) => (Outcome::ok_mutated(()), Ok(status)),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "reject_governance_proposal exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`GovernanceCommand::WithdrawGovernanceVote`] — delegates to
/// [`ContextManager::withdraw_governance_vote`](crate::context::manager::ContextManager::withdraw_governance_vote)
/// under a 30s timeout.
async fn handle_withdraw_governance_vote(
    mgr: &Arc<ContextManager>,
    context_id: &str,
    proposal_id: &scp_protocol::context::governance::ProposalId,
    voter_did: &scp_identity::DID,
    reply: oneshot::Sender<Result<scp_protocol::context::governance::ProposalStatus, ContextError>>,
) -> Outcome<()> {
    let manager = Arc::clone(mgr);
    let withdraw_fut = crate::context::governance_helpers::withdraw_governance_vote(
        &manager,
        context_id,
        proposal_id,
        voter_did,
    );

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, withdraw_fut).await {
        Ok(Ok(status)) => (Outcome::ok_mutated(()), Ok(status)),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "withdraw_governance_vote exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`GovernanceCommand::ExecuteGovernanceAction`] — delegates to
/// [`ContextManager::execute_governance_action`](crate::context::manager::ContextManager::execute_governance_action)
/// under a 30s timeout.
async fn handle_execute_governance_action(
    mgr: &Arc<ContextManager>,
    p: ExecuteGovernanceActionPayload,
    reply: oneshot::Sender<Result<crate::context::manager::GovernanceActionResult, ContextError>>,
) -> Outcome<()> {
    let manager = Arc::clone(mgr);
    let context_id = p.context_id.clone();
    let proposal = p.proposal;

    let execute_fut = async move {
        crate::context::governance_helpers::execute_governance_action(
            &manager,
            &p.context_id,
            &proposal,
        )
        .await
    };

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, execute_fut).await {
        Ok(Ok(result)) => (Outcome::ok_mutated(()), Ok(result)),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "execute_governance_action exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`GovernanceCommand::GetProposal`] — read-only, delegates to
/// [`ContextManager::get_proposal`](crate::context::manager::ContextManager::get_proposal)
/// under a 30s timeout.
async fn handle_get_proposal(
    mgr: &Arc<ContextManager>,
    context_id: &str,
    proposal_id: &scp_protocol::context::governance::ProposalId,
    reply: oneshot::Sender<
        Result<scp_protocol::context::governance::GovernanceProposal, ContextError>,
    >,
) -> Outcome<()> {
    let manager = Arc::clone(mgr);
    let get_fut =
        crate::context::governance_helpers::get_proposal(&manager, context_id, proposal_id);

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, get_fut).await {
        Ok(Ok(proposal)) => (Outcome::ok(()), Ok(proposal)),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "get_proposal exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`GovernanceCommand::ListProposals`] — read-only, delegates
/// to
/// [`ContextManager::list_proposals`](crate::context::manager::ContextManager::list_proposals)
/// under a 30s timeout.
async fn handle_list_proposals(
    mgr: &Arc<ContextManager>,
    context_id: &str,
    reply: oneshot::Sender<
        Result<Vec<scp_protocol::context::governance::GovernanceProposal>, ContextError>,
    >,
) -> Outcome<()> {
    let manager = Arc::clone(mgr);
    let list_fut = crate::context::governance_helpers::list_proposals(&manager, context_id);

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, list_fut).await {
        Ok(Ok(proposals)) => (Outcome::ok(()), Ok(proposals)),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "list_proposals exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`GovernanceCommand::ApplyPendingCeilingModification`] —
/// delegates to
/// [`ContextManager::apply_pending_ceiling_modification`](crate::context::manager::ContextManager::apply_pending_ceiling_modification)
/// under a 30s timeout.
async fn handle_apply_pending_ceiling_modification(
    mgr: &Arc<ContextManager>,
    context_id: &str,
    current_timestamp: u64,
    reply: oneshot::Sender<Result<bool, ContextError>>,
) -> Outcome<()> {
    let manager = Arc::clone(mgr);
    let apply_fut = crate::context::governance_helpers::apply_pending_ceiling_modification(
        &manager,
        context_id,
        current_timestamp,
    );

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, apply_fut).await {
        Ok(Ok(applied)) => {
            // Only mark mutated when the call actually applied a change.
            let outcome = if applied {
                Outcome::ok_mutated(())
            } else {
                Outcome::ok(())
            };
            (outcome, Ok(applied))
        }
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "apply_pending_ceiling_modification exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`GovernanceCommand::ApplyPendingEconomicPolicyChange`] —
/// delegates to
/// [`ContextManager::apply_pending_economic_policy_change`](crate::context::manager::ContextManager::apply_pending_economic_policy_change)
/// under a 30s timeout.
async fn handle_apply_pending_economic_policy_change(
    mgr: &Arc<ContextManager>,
    context_id: &str,
    current_timestamp: u64,
    reply: oneshot::Sender<Result<bool, ContextError>>,
) -> Outcome<()> {
    let manager = Arc::clone(mgr);
    let apply_fut = crate::context::governance_helpers::apply_pending_economic_policy_change(
        &manager,
        context_id,
        current_timestamp,
    );

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, apply_fut).await {
        Ok(Ok(applied)) => {
            let outcome = if applied {
                Outcome::ok_mutated(())
            } else {
                Outcome::ok(())
            };
            (outcome, Ok(applied))
        }
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "apply_pending_economic_policy_change exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`GovernanceCommand::TombstoneMigratedContext`] — delegates
/// to
/// [`ContextManager::tombstone_migrated_context`](crate::context::manager::ContextManager::tombstone_migrated_context)
/// under a 30s timeout.
async fn handle_tombstone_migrated_context(
    mgr: &Arc<ContextManager>,
    context_id: &str,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let manager = Arc::clone(mgr);
    let tombstone_fut =
        crate::context::governance_helpers::tombstone_migrated_context(&manager, context_id);

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, tombstone_fut).await {
        Ok(Ok(())) => (Outcome::ok_mutated(()), Ok(())),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "tombstone_migrated_context exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`GovernanceCommand::MigrationState`] — read-only, delegates
/// to
/// [`ContextManager::migration_state`](crate::context::manager::ContextManager::migration_state)
/// under a 30s timeout. The legacy method returns an `Option`
/// (no error) — timeout is mapped to `TransportTimeout` on the reply
/// side, consistent with other read handlers.
async fn handle_migration_state(
    mgr: &Arc<ContextManager>,
    context_id: &str,
    reply: oneshot::Sender<Result<Option<crate::context::manager::MigrationState>, ContextError>>,
) -> Outcome<()> {
    let manager = Arc::clone(mgr);
    let migration_fut = crate::context::governance_helpers::migration_state(&manager, context_id);

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, migration_fut).await {
        Ok(state) => (Outcome::ok(()), Ok(state)),
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "migration_state exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`GovernanceCommand::AcknowledgeCommitFault`] — delegates to
/// [`ContextManager::acknowledge_commit_fault`](crate::context::manager::ContextManager::acknowledge_commit_fault)
/// under a 30s timeout.
async fn handle_acknowledge_commit_fault(
    mgr: &Arc<ContextManager>,
    context_id: &str,
    reply: oneshot::Sender<Result<crate::context::manager::CommitFaultMarker, ContextError>>,
) -> Outcome<()> {
    let manager = Arc::clone(mgr);
    let ack_fut =
        crate::context::governance_helpers::acknowledge_commit_fault(&manager, context_id);

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, ack_fut).await {
        Ok(Ok(marker)) => (Outcome::ok_mutated(()), Ok(marker)),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "acknowledge_commit_fault exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Produce a best-effort clone-equivalent `ContextError` for the
/// handler's [`Outcome`] sink given a borrowed error that cannot be
/// cloned. Mirrors the pattern used in
/// [`handlers::messaging`](crate::context::actor::handlers::messaging)
/// and [`handlers::lifecycle`](crate::context::actor::handlers::lifecycle).
fn outcome_error_sketch(err: &ContextError) -> ContextError {
    match err {
        ContextError::TransportTimeout(msg) => ContextError::TransportTimeout(msg.clone()),
        ContextError::TransportFailed(msg) => ContextError::TransportFailed(msg.clone()),
        ContextError::CryptoFailed(msg) => ContextError::CryptoFailed(msg.clone()),
        ContextError::PermissionDenied(msg) => ContextError::PermissionDenied(msg.clone()),
        ContextError::MemberNotFound(msg) => ContextError::MemberNotFound(msg.clone()),
        ContextError::ContextNotRegistered(msg) => ContextError::ContextNotRegistered(msg.clone()),
        ContextError::ContextNotActive => ContextError::ContextNotActive,
        ContextError::MembershipFailed(msg) => ContextError::MembershipFailed(msg.clone()),
        ContextError::EventLogFailed(msg) => ContextError::EventLogFailed(msg.clone()),
        ContextError::GovernanceFailed(msg) => ContextError::GovernanceFailed(msg.clone()),
        ContextError::InvalidState(msg) => ContextError::InvalidState(msg.clone()),
        other => ContextError::CryptoFailed(format!("{other}")),
    }
}

fn reply_not_implemented(reply: oneshot::Sender<Result<(), ContextError>>) -> Outcome<()> {
    const MSG: &str = "GovernanceCommand::Placeholder — real variants migrate in commit 10 of \
                       ADR-049; Placeholder retained for commit-6 compile stability and \
                       deleted in commit 12 with the shim";
    let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
    Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
}
