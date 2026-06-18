//! Governance handlers — see
//! [`GovernanceCommand`](crate::context::actor::commands::GovernanceCommand)
//! and plan row 10 of the commit ladder.
//!
//! # Dispatch shape
//!
//! The actor's `run()` loop invokes [`dispatch`] with `(&mut
//! PerContextState, &ActorDeps, GovernanceCommand)`. Every governance
//! variant has an actor-shape handler (`handle_*_actor`) that reads
//! and mutates `state.governance` directly through the actor-shape
//! helpers in
//! [`crate::context::governance_helpers`](crate::context::governance_helpers).
//! The migration-window shim — `dispatch_from_shim` and the
//! supervisor-shape `handle_*` helpers — has been deleted at Phase 2A
//! finalization. The `Placeholder` variant remains as the mailbox-test
//! handshake target.
//!
//! # Transport-timeout budget
//!
//! [`HANDLER_TIMEOUT`] is the handler-level budget. Per ADR-049 §7,
//! every transport and storage call inside a handler wraps
//! [`tokio::time::timeout`] with a 30-second budget; a timeout maps to
//! [`ContextError::TransportTimeout`](scp_protocol::context::ContextError::TransportTimeout).
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

/// Per-call transport budget for governance handlers. Plan
/// §"Transport timeouts inside actor handlers": 30 seconds.
pub const HANDLER_TIMEOUT: Duration = Duration::from_secs(30);

/// Dispatch a [`GovernanceCommand`] against actor-owned state and deps.
///
/// Plan-conforming dispatch signature: matches the post-refactor actor
/// `run()` loop's call shape
/// (`handlers::governance::dispatch(state, deps, cmd).await`).
///
/// Every variant routes through an actor-shape `handle_*_actor` helper
/// that reads or mutates `state.governance` directly through
/// [`crate::context::governance_helpers`](crate::context::governance_helpers).
/// The migration-window shim — `dispatch_from_shim`, the
/// supervisor-shape `handle_*` helpers, and the `*_legacy` bodies they
/// delegated to — was removed at Phase 2A finalization.
pub async fn dispatch(
    state: &mut crate::context::actor::state::PerContextState,
    deps: &ActorDeps,
    cmd: GovernanceCommand,
) -> Outcome<()> {
    // `Box::pin` the dispatch future — the combined per-variant locals
    // (GovernanceProposal ~1KB, ContextParams ~1KB, and the 30s-timeout
    // future each variant wraps) cross clippy's 16-KB stack budget for
    // async futures. Boxing here moves the per-variant state onto the
    // heap once per dispatch.
    Box::pin(dispatch_state(state, deps, cmd)).await
}

/// Actor-shape variant dispatch. Every governance variant now takes
/// state + deps directly. Only the no-op `Placeholder` variant
/// (commit-6 mailbox-test handshake) returns `NotImplemented`
/// synchronously; deleted with the `Placeholder` itself at Phase 2A
/// finalization.
#[allow(
    clippy::too_many_lines,
    reason = "exhaustive GovernanceCommand match — splitting loses the \
              unified dispatch surface that pipeline-wiring tests assert"
)]
async fn dispatch_state(
    state: &mut crate::context::actor::state::PerContextState,
    deps: &ActorDeps,
    cmd: GovernanceCommand,
) -> Outcome<()> {
    match cmd {
        // ---------- migrated variants (actor-shape) ----------
        GovernanceCommand::GetProposal {
            context_id: _,
            proposal_id,
            reply,
        } => handle_get_proposal_actor(state, &proposal_id, reply),
        GovernanceCommand::ListProposals {
            context_id: _,
            reply,
        } => handle_list_proposals_actor(state, reply),
        GovernanceCommand::MigrationState {
            context_id: _,
            reply,
        } => handle_migration_state_actor(state, reply),
        GovernanceCommand::TombstoneMigratedContext { context_id, reply } => {
            handle_tombstone_migrated_context_actor(state, deps, &context_id, reply).await
        }
        GovernanceCommand::AcknowledgeCommitFault { context_id, reply } => {
            handle_acknowledge_commit_fault_actor(state, &context_id, reply)
        }
        GovernanceCommand::WithdrawGovernanceVote {
            context_id,
            proposal_id,
            voter_did,
            reply,
        } => {
            handle_withdraw_governance_vote_actor(
                state,
                deps,
                &context_id,
                &proposal_id,
                &voter_did,
                reply,
            )
            .await
        }
        GovernanceCommand::ApplyPendingCeilingModification {
            context_id,
            current_timestamp,
            reply,
        } => {
            handle_apply_pending_ceiling_modification_actor(
                state,
                deps,
                &context_id,
                current_timestamp,
                reply,
            )
            .await
        }
        GovernanceCommand::ApplyPendingEconomicPolicyChange {
            context_id,
            current_timestamp,
            reply,
        } => {
            handle_apply_pending_economic_policy_change_actor(
                state,
                deps,
                &context_id,
                current_timestamp,
                reply,
            )
            .await
        }
        GovernanceCommand::ExecuteGovernanceAction { payload, reply } => {
            Box::pin(handle_execute_governance_action_actor(
                state, deps, *payload, reply,
            ))
            .await
        }
        GovernanceCommand::ProposeGovernanceAction { payload, reply } => {
            Box::pin(handle_propose_governance_action_actor(
                state, deps, *payload, reply, false,
            ))
            .await
        }
        GovernanceCommand::ProposeGovernanceActionChecked { payload, reply } => {
            Box::pin(handle_propose_governance_action_checked_actor(
                state, deps, *payload, reply,
            ))
            .await
        }
        GovernanceCommand::VoteOnProposal {
            payload,
            approve,
            reply,
        } => {
            Box::pin(handle_vote_on_proposal_actor(
                state, deps, *payload, approve, reply,
            ))
            .await
        }
        GovernanceCommand::ApproveGovernanceProposal { payload, reply } => {
            Box::pin(handle_approve_governance_proposal_actor(
                state, deps, *payload, reply,
            ))
            .await
        }
        GovernanceCommand::RejectGovernanceProposal { payload, reply } => {
            Box::pin(handle_reject_governance_proposal_actor(
                state, deps, *payload, reply,
            ))
            .await
        }
        GovernanceCommand::EvaluatePeriodicConsequences { reply } => {
            handle_evaluate_periodic_consequences_actor(state, deps, reply)
        }
        GovernanceCommand::ProcessPendingCommits { reply } => {
            Box::pin(handle_process_pending_commits_actor(state, deps, reply)).await
        }
        GovernanceCommand::EvaluateTimeouts { reply } => {
            Box::pin(handle_evaluate_timeouts_actor(state, deps, reply)).await
        }
        GovernanceCommand::StartTimeoutTask { reply } => {
            handle_start_timeout_task_actor(state, deps, reply).await
        }
        // Placeholder is a no-op handshake target reserved for mailbox
        // tests. Returns NotImplemented synchronously; no state mutation.
        GovernanceCommand::Placeholder { reply } => reply_not_implemented(reply),
    }
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

// ---------------------------------------------------------------------------
// Actor-shape handlers (Phase 2A.8 ladder; one per migrated entry point)
// ---------------------------------------------------------------------------

/// Handle [`GovernanceCommand::GetProposal`] (actor-shape, read-only).
///
/// Delegates to
/// [`get_proposal`](crate::context::governance_helpers::get_proposal),
/// which reads directly off `state.governance.engine`. Sync — no
/// transport-timeout wrapping needed because there are no awaits.
fn handle_get_proposal_actor(
    state: &crate::context::actor::state::PerContextState,
    proposal_id: &scp_protocol::context::governance::ProposalId,
    reply: oneshot::Sender<
        Result<scp_protocol::context::governance::GovernanceProposal, ContextError>,
    >,
) -> Outcome<()> {
    let result = crate::context::governance_helpers::get_proposal(state, proposal_id);
    let outcome = match &result {
        Ok(_) => Outcome::ok(()),
        Err(e) => Outcome::err(outcome_error_sketch(e)),
    };
    let _ = reply.send(result);
    outcome
}

/// Handle [`GovernanceCommand::ListProposals`] (actor-shape, read-only).
fn handle_list_proposals_actor(
    state: &crate::context::actor::state::PerContextState,
    reply: oneshot::Sender<
        Result<Vec<scp_protocol::context::governance::GovernanceProposal>, ContextError>,
    >,
) -> Outcome<()> {
    let proposals = crate::context::governance_helpers::list_proposals(state);
    let _ = reply.send(Ok(proposals));
    Outcome::ok(())
}

/// Handle [`GovernanceCommand::MigrationState`] (actor-shape, read-only).
fn handle_migration_state_actor(
    state: &crate::context::actor::state::PerContextState,
    reply: oneshot::Sender<Result<Option<crate::context::state::MigrationState>, ContextError>>,
) -> Outcome<()> {
    let migration = crate::context::governance_helpers::migration_state(state);
    let _ = reply.send(Ok(migration));
    Outcome::ok(())
}

/// Handle [`GovernanceCommand::TombstoneMigratedContext`] (actor-shape).
async fn handle_tombstone_migrated_context_actor(
    state: &mut crate::context::actor::state::PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let tombstone_fut =
        crate::context::governance_helpers::tombstone_migrated_context(state, deps, context_id);
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

/// Handle [`GovernanceCommand::AcknowledgeCommitFault`] (actor-shape).
fn handle_acknowledge_commit_fault_actor(
    state: &mut crate::context::actor::state::PerContextState,
    context_id: &str,
    reply: oneshot::Sender<Result<crate::context::state::CommitFaultMarker, ContextError>>,
) -> Outcome<()> {
    let result = crate::context::governance_helpers::acknowledge_commit_fault(state, context_id);
    let outcome = match &result {
        Ok(_) => Outcome::ok_mutated(()),
        Err(e) => Outcome::err_mutated(outcome_error_sketch(e)),
    };
    let _ = reply.send(result);
    outcome
}

/// Handle [`GovernanceCommand::WithdrawGovernanceVote`] (actor-shape).
async fn handle_withdraw_governance_vote_actor(
    state: &mut crate::context::actor::state::PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    proposal_id: &scp_protocol::context::governance::ProposalId,
    voter_did: &scp_identity::DID,
    reply: oneshot::Sender<Result<scp_protocol::context::governance::ProposalStatus, ContextError>>,
) -> Outcome<()> {
    let withdraw_fut = crate::context::governance_helpers::withdraw_governance_vote(
        state,
        deps,
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

/// Handle [`GovernanceCommand::ApplyPendingCeilingModification`] (actor-shape).
async fn handle_apply_pending_ceiling_modification_actor(
    state: &mut crate::context::actor::state::PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    current_timestamp: u64,
    reply: oneshot::Sender<Result<bool, ContextError>>,
) -> Outcome<()> {
    let apply_fut = crate::context::governance_helpers::apply_pending_ceiling_modification(
        state,
        deps,
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
                "apply_pending_ceiling_modification exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err(sketch), Err(err))
        }
    };
    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`GovernanceCommand::ProposeGovernanceAction`] (actor-shape).
async fn handle_propose_governance_action_actor(
    state: &mut crate::context::actor::state::PerContextState,
    deps: &ActorDeps,
    p: ProposeGovernanceActionPayload,
    reply: ProposeGovernanceActionReply,
    _checked: bool,
) -> Outcome<()> {
    let context_id = p.context_id.clone();
    let signing_key = p.signing_key.to_signing_key();
    let proposer_did = p.proposer_did.clone();
    let action = p.action;

    // Actor-shape twin of the legacy unchecked
    // `Supervisor::propose_governance_action` entry point: `check=false`.
    // Role-based eligibility (admin status, the threshold/majority signer
    // set) is enforced by the governance engine, which returns
    // `GovernanceFailed` for ineligible proposers. The suspension overlay
    // inside `propose_governance_action_inner` still applies unconditionally.
    // The checked `GovernancePropose` capability path is reached through the
    // dedicated `ProposeGovernanceActionChecked` command.
    let propose_fut = async move {
        Box::pin(
            crate::context::governance_helpers::propose_governance_action_inner(
                state,
                deps,
                &p.context_id,
                &proposer_did,
                action,
                &signing_key,
                false,
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

/// Handle [`GovernanceCommand::ProposeGovernanceActionChecked`] (actor-shape).
async fn handle_propose_governance_action_checked_actor(
    state: &mut crate::context::actor::state::PerContextState,
    deps: &ActorDeps,
    p: ProposeGovernanceActionPayload,
    reply: ProposeGovernanceActionCheckedReply,
) -> Outcome<()> {
    let context_id = p.context_id.clone();
    let signing_key = p.signing_key.to_signing_key();
    let proposer_did = p.proposer_did.clone();
    let action = p.action;

    let propose_fut = async move {
        Box::pin(
            crate::context::governance_helpers::propose_governance_action_checked(
                state,
                deps,
                &p.context_id,
                &proposer_did,
                action,
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

/// Handle [`GovernanceCommand::VoteOnProposal`] (actor-shape).
///
/// This is the actor-shape twin of the legacy unchecked
/// `Supervisor::vote_on_proposal` entry point, so `check_vote_capability`
/// is `false`: role-based eligibility (the threshold/majority signer set,
/// admin status) is enforced by the governance engine itself, which returns
/// `GovernanceFailed` for non-eligible voters. The suspension overlay inside
/// `vote_on_proposal_inner` still applies unconditionally. The checked
/// `GovernanceVote` capability path is reached through the dedicated
/// `ApproveGovernanceProposal` / `RejectGovernanceProposal` commands.
async fn handle_vote_on_proposal_actor(
    state: &mut crate::context::actor::state::PerContextState,
    deps: &ActorDeps,
    p: VoteOnProposalPayload,
    approve: bool,
    reply: VoteOnProposalReply,
) -> Outcome<()> {
    let context_id = p.context_id.clone();
    let signing_key = p.signing_key.to_signing_key();
    let voter_did = p.voter_did.clone();
    let proposal_id = p.proposal_id;

    let vote_fut = async move {
        Box::pin(crate::context::governance_helpers::vote_on_proposal_inner(
            state,
            deps,
            &p.context_id,
            &proposal_id,
            &voter_did,
            approve,
            &signing_key,
            false,
        ))
        .await
    };

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

/// Handle [`GovernanceCommand::ApproveGovernanceProposal`] (actor-shape).
async fn handle_approve_governance_proposal_actor(
    state: &mut crate::context::actor::state::PerContextState,
    deps: &ActorDeps,
    p: VoteOnProposalPayload,
    reply: oneshot::Sender<Result<scp_protocol::context::governance::ProposalStatus, ContextError>>,
) -> Outcome<()> {
    let context_id = p.context_id.clone();
    let signing_key = p.signing_key.to_signing_key();
    let voter_did = p.voter_did.clone();
    let proposal_id = p.proposal_id;

    let approve_fut = async move {
        Box::pin(
            crate::context::governance_helpers::approve_governance_proposal(
                state,
                deps,
                &p.context_id,
                &proposal_id,
                &voter_did,
                &signing_key,
            ),
        )
        .await
    };

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

/// Handle [`GovernanceCommand::RejectGovernanceProposal`] (actor-shape).
async fn handle_reject_governance_proposal_actor(
    state: &mut crate::context::actor::state::PerContextState,
    deps: &ActorDeps,
    p: VoteOnProposalPayload,
    reply: oneshot::Sender<Result<scp_protocol::context::governance::ProposalStatus, ContextError>>,
) -> Outcome<()> {
    let context_id = p.context_id.clone();
    let signing_key = p.signing_key.to_signing_key();
    let voter_did = p.voter_did.clone();
    let proposal_id = p.proposal_id;

    let reject_fut = async move {
        Box::pin(
            crate::context::governance_helpers::reject_governance_proposal(
                state,
                deps,
                &p.context_id,
                &proposal_id,
                &voter_did,
                &signing_key,
            ),
        )
        .await
    };

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

/// Handle [`GovernanceCommand::ExecuteGovernanceAction`] (actor-shape).
async fn handle_execute_governance_action_actor(
    state: &mut crate::context::actor::state::PerContextState,
    deps: &ActorDeps,
    payload: ExecuteGovernanceActionPayload,
    reply: oneshot::Sender<Result<crate::context::state::GovernanceActionResult, ContextError>>,
) -> Outcome<()> {
    let context_id = payload.context_id.clone();
    let proposal = payload.proposal;

    let execute_fut = async move {
        Box::pin(
            crate::context::governance_helpers::execute_governance_action(
                state,
                deps,
                &payload.context_id,
                &proposal,
            ),
        )
        .await
    };

    let (outcome, reply_result) = match Box::pin(tokio::time::timeout(HANDLER_TIMEOUT, execute_fut))
        .await
    {
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

/// Handle [`GovernanceCommand::ApplyPendingEconomicPolicyChange`] (actor-shape).
async fn handle_apply_pending_economic_policy_change_actor(
    state: &mut crate::context::actor::state::PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    current_timestamp: u64,
    reply: oneshot::Sender<Result<bool, ContextError>>,
) -> Outcome<()> {
    let apply_fut = crate::context::governance_helpers::apply_pending_economic_policy_change(
        state,
        deps,
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

fn reply_not_implemented(reply: oneshot::Sender<Result<(), ContextError>>) -> Outcome<()> {
    const MSG: &str = "GovernanceCommand::Placeholder — real variants migrate in commit 10 of \
                       ADR-049; Placeholder retained for commit-6 compile stability and \
                       deleted in commit 12 with the shim";
    let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
    Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
}

// ---------------------------------------------------------------------------
// Sweep handlers (Phase 2A finalization — sweep helper relocation)
// ---------------------------------------------------------------------------

/// Handle [`GovernanceCommand::EvaluatePeriodicConsequences`] (actor-shape).
///
/// Per-actor body of the relocated sweep. Evaluates consequence rules
/// against the actor's own `state` and applies any triggered actions
/// (suspend / revoke / etc.) to `state.membership` /
/// `state.role_state`. Mirrors the per-context body of
/// `evaluate_periodic_consequences_legacy` (which read
/// `Supervisor::contexts` DashMap directly); the actor-shape variant
/// operates on `&mut state` and never touches the supervisor's DashMap.
fn handle_evaluate_periodic_consequences_actor(
    state: &mut crate::context::actor::state::PerContextState,
    deps: &ActorDeps,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    use scp_protocol::trust::consequence::{TriggeredConsequence, evaluate_consequence_rules};

    use crate::context::governance_logic::{
        ConsequenceStateSplit, EnforceConsequencesCtx, enforce_triggered_consequences,
        event_log_entries_for_consequences,
    };

    let rules = state.governance.consequence_rules.clone();
    if rules.is_empty() {
        let _ = reply.send(Ok(()));
        return Outcome::ok(());
    }
    let now = deps.clock.now_secs();
    let context_id = state.handle.context_id().to_owned();
    let member_dids: Vec<scp_identity::DID> =
        state.membership.members().map(|m| m.did.clone()).collect();
    let events = event_log_entries_for_consequences(
        &state.receive_buffer,
        &context_id,
        now,
        deps.event_log.as_ref(),
    );

    let mut results: Vec<(scp_identity::DID, Vec<TriggeredConsequence>)> = Vec::new();
    for member_did in member_dids {
        let triggered = evaluate_consequence_rules(&rules, &events, member_did.as_ref(), now);
        if !triggered.is_empty() {
            results.push((member_did, triggered));
        }
    }
    if results.is_empty() {
        let _ = reply.send(Ok(()));
        return Outcome::ok(());
    }
    let mut split = ConsequenceStateSplit::from_state(state);
    for (member_did, triggered) in &results {
        enforce_triggered_consequences(
            &mut split,
            &EnforceConsequencesCtx {
                context_id: &context_id,
                member_did,
                now,
                triggered,
                rules: &rules,
                clock: deps.clock.as_ref(),
                event_log: deps.event_log.as_ref(),
                event_tx: deps.event_tx.as_ref(),
            },
        );
    }
    let _ = reply.send(Ok(()));
    Outcome::ok_mutated(())
}

/// Outcome of attempting to retry a single pending MLS commit
/// (PR #1606 C6). Phase A of [`handle_process_pending_commits_actor`]
/// produces one of these per pending entry whose backoff has elapsed;
/// Phase B applies the outcomes to the actor's pending-commits queue.
enum CommitRetryOutcomeKind {
    Success {
        attempts: u32,
        operation: crate::context::state::CommitOperation,
    },
    Retry {
        error: String,
        next_attempt_at: u64,
        new_retry_count: u32,
        operation: crate::context::state::CommitOperation,
    },
    Failed {
        reason: String,
        attempts: u32,
        operation: crate::context::state::CommitOperation,
    },
}
struct CommitRetryOutcome {
    index: usize,
    kind: CommitRetryOutcomeKind,
}

/// Phase A of [`handle_process_pending_commits_actor`]. Classifies each
/// pending commit whose backoff has elapsed as `Success`, `Retry`, or
/// `Failed`. Returns one outcome per processed entry (entries whose
/// `next_attempt_at` is still in the future are skipped).
///
/// Operates on a snapshot, not `&state`, so the transport sends happen
/// with no `&state` borrow held. The actor's `dispatch_state` arm owns
/// the `&mut state` borrow exclusively for the command's lifetime so
/// no other command can interleave between Phase A and Phase B.
fn compute_commit_retry_outcomes(
    snapshot: &[crate::context::state::PendingCommit],
    now: u64,
    transport: &dyn crate::context::builder::ContextTransportProvider,
) -> Vec<CommitRetryOutcome> {
    use crate::context::state::{MAX_COMMIT_AGE_SECS, MAX_COMMIT_RETRIES, commit_retry_backoff};

    let mut outcomes: Vec<CommitRetryOutcome> = Vec::new();
    for (idx, pending) in snapshot.iter().enumerate() {
        if now < pending.next_attempt_at {
            continue;
        }
        let age = now.saturating_sub(pending.first_attempt_at);
        if age >= MAX_COMMIT_AGE_SECS {
            outcomes.push(CommitRetryOutcome {
                index: idx,
                kind: CommitRetryOutcomeKind::Failed {
                    reason: format!("max age exceeded ({age}s >= {MAX_COMMIT_AGE_SECS}s)"),
                    attempts: pending.retry_count,
                    operation: pending.operation.clone(),
                },
            });
            continue;
        }
        match transport.send_message(&pending.routing_id, &pending.commit_bytes) {
            Ok(()) => {
                outcomes.push(CommitRetryOutcome {
                    index: idx,
                    kind: CommitRetryOutcomeKind::Success {
                        attempts: pending.retry_count,
                        operation: pending.operation.clone(),
                    },
                });
            }
            Err(e) => {
                let new_retry_count = pending.retry_count.saturating_add(1);
                if new_retry_count > MAX_COMMIT_RETRIES {
                    outcomes.push(CommitRetryOutcome {
                        index: idx,
                        kind: CommitRetryOutcomeKind::Failed {
                            reason: e.to_string(),
                            attempts: new_retry_count,
                            operation: pending.operation.clone(),
                        },
                    });
                } else {
                    let backoff = commit_retry_backoff(new_retry_count);
                    outcomes.push(CommitRetryOutcome {
                        index: idx,
                        kind: CommitRetryOutcomeKind::Retry {
                            error: e.to_string(),
                            next_attempt_at: now.saturating_add(backoff),
                            new_retry_count,
                            operation: pending.operation.clone(),
                        },
                    });
                }
            }
        }
    }
    outcomes
}

/// Phase B of [`handle_process_pending_commits_actor`]. Applies the
/// outcomes to `state.pending_commits` under the actor's exclusive
/// `&mut state` borrow. Pushes receive-buffer events and returns the
/// labels that should be appended to the durable event log (Phase C).
fn apply_commit_retry_outcomes(
    state: &mut crate::context::actor::state::PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    outcomes: Vec<CommitRetryOutcome>,
) -> Vec<scp_event_log::EventType> {
    use scp_protocol::context::membership::ContextEvent;

    use crate::context::state::CommitFaultMarker;

    let mut event_log_writes: Vec<scp_event_log::EventType> = Vec::new();
    let queue_len = state.pending_commits.len();
    let mut to_remove: Vec<usize> = Vec::new();
    for outcome in outcomes {
        if outcome.index >= queue_len {
            continue;
        }
        match outcome.kind {
            CommitRetryOutcomeKind::Success {
                attempts,
                operation,
            } => {
                state.emit_event(
                    ContextEvent::CommitBroadcastSucceeded {
                        operation: operation.label(),
                        attempts,
                    },
                    context_id,
                    deps.event_tx.as_ref(),
                );
                event_log_writes.push(scp_event_log::EventType::CommitBroadcastSucceeded);
                to_remove.push(outcome.index);
            }
            CommitRetryOutcomeKind::Retry {
                error,
                next_attempt_at,
                new_retry_count,
                operation,
            } => {
                if let Some(entry) = state.pending_commits.get_mut(outcome.index) {
                    entry.retry_count = new_retry_count;
                    entry.next_attempt_at = next_attempt_at;
                    entry.last_error = Some(error.clone());
                }
                state.emit_event(
                    ContextEvent::CommitBroadcastPending {
                        operation: operation.label(),
                        error,
                        attempt: new_retry_count,
                    },
                    context_id,
                    deps.event_tx.as_ref(),
                );
                event_log_writes.push(scp_event_log::EventType::CommitBroadcastPending);
            }
            CommitRetryOutcomeKind::Failed {
                reason,
                attempts,
                operation,
            } => {
                let now_failed = deps.clock.now_secs();
                state.commit_fault = Some(CommitFaultMarker {
                    operation: operation.clone(),
                    reason: reason.clone(),
                    failed_at: now_failed,
                    retry_count: attempts,
                });
                state.emit_event(
                    ContextEvent::CommitBroadcastFailed {
                        operation: operation.label(),
                        reason,
                        attempts,
                    },
                    context_id,
                    deps.event_tx.as_ref(),
                );
                event_log_writes.push(scp_event_log::EventType::CommitBroadcastFailed);
                to_remove.push(outcome.index);
            }
        }
    }
    to_remove.sort_unstable_by(|a, b| b.cmp(a));
    for idx in to_remove {
        state.pending_commits.remove(idx);
    }
    event_log_writes
}

/// Handle [`GovernanceCommand::ProcessPendingCommits`] (actor-shape).
///
/// Per-actor body of the relocated sweep (PR #1606 C6). Walks
/// `state.pending_commits`, retries any commits whose `next_attempt_at
/// <= now`, and either dequeues on success, updates retry count on
/// transient failure, or marks the context fail-closed once the retry
/// budget is exhausted.
///
/// Mirrors the per-context body of `process_pending_commits_legacy`.
/// The legacy body executed transport sends with the contexts lock
/// RELEASED; the actor-shape body keeps the same property by
/// snapshotting the queue, performing Phase A with no `&state`
/// borrow on the transport call, then re-using the actor's exclusive
/// `&mut state` borrow for Phase B. The actor's own dispatch loop
/// owns the borrow exclusively, so other commands cannot interleave
/// between phases — this preserves the legacy "queue is only mutated
/// by this task between phases" invariant.
async fn handle_process_pending_commits_actor(
    state: &mut crate::context::actor::state::PerContextState,
    deps: &ActorDeps,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    use crate::context::state::{PendingCommit, context_id_to_bytes};

    if state.commit_fault.is_some() {
        let _ = reply.send(Ok(()));
        return Outcome::ok(());
    }
    let snapshot: Vec<PendingCommit> = state.pending_commits.iter().cloned().collect();
    if snapshot.is_empty() {
        let _ = reply.send(Ok(()));
        return Outcome::ok(());
    }
    let now = deps.clock.now_secs();
    let context_id = state.handle.context_id().to_owned();
    let context_id_bytes = context_id_to_bytes(&context_id);

    let outcomes = compute_commit_retry_outcomes(&snapshot, now, deps.transport.as_ref());
    if outcomes.is_empty() {
        let _ = reply.send(Ok(()));
        return Outcome::ok(());
    }

    let event_log_writes = apply_commit_retry_outcomes(state, deps, &context_id, outcomes);

    // Phase C: append durable event log entries (event_log adapter is
    // `Arc<dyn ...>`, takes no `&state` so the actor's borrow is not
    // contended).
    let mut retry_event_count: u64 = 0;
    for label in event_log_writes {
        if let Err(e) = deps
            .event_log
            .append_context_event(&context_id_bytes, label, "system")
        {
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "failed to append commit retry event to durable log"
            );
        }
        retry_event_count += 1;
    }
    if retry_event_count > 0 {
        state.checkpoint_events_since += retry_event_count;
    }
    let _ = reply.send(Ok(()));
    Outcome::ok_mutated(())
}

/// Handle [`GovernanceCommand::EvaluateTimeouts`] (actor-shape).
///
/// Per-actor body of the relocated sweep. Runs one tick of the
/// governance timeout / consequence pipeline for THIS actor's context.
/// Mirrors the per-context body of `start_governance_timeout_task_legacy`
/// — phases 1 through 5.
///
/// Replies `Ok(true)` to continue the supervisor's timer loop, `Ok(false)`
/// to stop (context closing or removed; matches the legacy timer
/// closure's `bool` return). The supervisor-side timer-spawn entry point
/// in [`governance_helpers::start_governance_timeout_task`](crate::context::governance_helpers::start_governance_timeout_task)
/// drives the cadence; per-actor governance-timeout actors land in Phase
/// 2B per ADR-049.
async fn handle_evaluate_timeouts_actor(
    state: &mut crate::context::actor::state::PerContextState,
    deps: &ActorDeps,
    reply: oneshot::Sender<Result<bool, ContextError>>,
) -> Outcome<()> {
    use std::collections::HashSet;

    use scp_identity::DID;

    use crate::context::governance::timeout::{
        collect_active_voters, process_pending_proposals, update_detection_state,
    };
    use crate::context::governance_helpers::build_governance_context;

    let context_id = state.handle.context_id().to_owned();

    // Phase 1: read state, process proposals, detect deadlock.
    let current_state = state.handle.try_read_state();
    if !matches!(
        current_state,
        Some(scp_protocol::context::ContextState::Active)
    ) {
        // None = write-contended, continue next tick.
        // Not Active = context closing, stop the loop.
        let continue_loop = current_state.is_none();
        let _ = reply.send(Ok(continue_loop));
        return Outcome::ok(());
    }

    let gov_ctx = build_governance_context(state, deps.clock.as_ref());

    let current_members: HashSet<DID> = state.membership.members().map(|m| m.did.clone()).collect();
    let departed: Vec<DID> = state
        .governance
        .last_known_members
        .difference(&current_members)
        .cloned()
        .collect();
    state.governance.last_known_members = current_members;

    state.governance.evict_stale_entries(deps.clock.now_secs());

    let epoch_resets: Vec<DID> = std::mem::take(&mut state.governance.pending_epoch_resets);

    let mls_epoch = state.epoch.mls_epoch;
    let recovery_in_progress = state.governance.deadlock.recovery_in_progress;

    let active_voters = collect_active_voters(state.governance.engine.as_ref());

    let result = process_pending_proposals(
        state.governance.engine.as_mut(),
        &gov_ctx,
        &departed,
        &epoch_resets,
    );

    update_detection_state(
        &mut state.governance.deadlock,
        state.governance.engine.as_ref(),
        &gov_ctx,
        &active_voters,
    );

    let conditions = crate::context::governance::timeout::detect_deadlock(
        state.governance.engine.as_ref(),
        &gov_ctx,
        &state.governance.deadlock,
    );

    // Phase 2: translate timeout events.
    let ctx_events = crate::context::governance_helpers::translate_timeout_events(
        &result.events,
        mls_epoch,
        &conditions,
        recovery_in_progress,
    );

    // Phase 3: write results back, update recovery state.
    let needs_write = !ctx_events.is_empty()
        || (conditions.is_empty() && recovery_in_progress)
        || (!conditions.is_empty() && !recovery_in_progress);
    if needs_write {
        for ctx_event in ctx_events {
            state.emit_event(ctx_event, &context_id, deps.event_tx.as_ref());
        }
        if conditions.is_empty() && recovery_in_progress {
            state.governance.deadlock.recovery_in_progress = false;
        } else if !conditions.is_empty() && !recovery_in_progress {
            state.governance.deadlock.recovery_in_progress = true;
        }
    }

    // Phase 4: periodic consequence evaluation (#1531). Reuses the
    // actor-shape sweep body via direct call rather than a nested
    // mailbox dispatch — both operate on `&mut state` already owned by
    // this handler.
    let (consequence_reply_tx, _consequence_reply_rx) = oneshot::channel();
    let _ = handle_evaluate_periodic_consequences_actor(state, deps, consequence_reply_tx);

    // Phase 5 (PR #1606 C6): drain MLS commit retry queue. Same pattern
    // as Phase 4 — direct in-handler call.
    let (commits_reply_tx, _commits_reply_rx) = oneshot::channel();
    let _ = Box::pin(handle_process_pending_commits_actor(
        state,
        deps,
        commits_reply_tx,
    ))
    .await;

    let _ = reply.send(Ok(true));
    Outcome::ok_mutated(())
}

/// Handle [`GovernanceCommand::StartTimeoutTask`] (actor-shape).
///
/// Installs the per-context governance-timeout interval task on
/// actor-owned `state.governance.timeout_task` via the actor-shape
/// [`governance_helpers::spawn_governance_timeout_task`](crate::context::governance_helpers::spawn_governance_timeout_task).
/// The spawned loop mailboxes [`GovernanceCommand::EvaluateTimeouts`]
/// back to THIS actor each tick — no DashMap reach, no generation gate.
///
/// Awaits the `tracked_spawn` task_set push so the abort handle is
/// installed on `state.governance.timeout_task` before replying.
async fn handle_start_timeout_task_actor(
    state: &mut crate::context::actor::state::PerContextState,
    deps: &ActorDeps,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    crate::context::governance_helpers::spawn_governance_timeout_task(state, deps).await;
    let _ = reply.send(Ok(()));
    Outcome::ok_mutated(())
}
