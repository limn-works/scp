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
//! finalization.
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
pub(crate) async fn dispatch(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    cmd: GovernanceCommand,
) -> Outcome<()> {
    // `Box::pin` the dispatch future — the combined per-variant locals
    // (GovernanceProposal ~1KB, ContextParams ~1KB, and the 30s-timeout
    // future each variant wraps) cross clippy's 16-KB stack budget for
    // async futures. Boxing here moves the per-variant state onto the
    // heap once per dispatch.
    Box::pin(dispatch_state(cell, deps, cmd)).await
}

/// Actor-shape variant dispatch. Every governance variant takes
/// state + deps directly.
#[allow(
    clippy::too_many_lines,
    reason = "exhaustive GovernanceCommand match — splitting loses the \
              unified dispatch surface that pipeline-wiring tests assert"
)]
async fn dispatch_state(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    cmd: GovernanceCommand,
) -> Outcome<()> {
    match cmd {
        // ---------- migrated variants (actor-shape) ----------
        GovernanceCommand::GetProposal {
            context_id: _,
            proposal_id,
            reply,
        } => handle_get_proposal_actor(cell, &proposal_id, reply),
        GovernanceCommand::ListProposals {
            context_id: _,
            reply,
        } => handle_list_proposals_actor(cell, reply),
        GovernanceCommand::MigrationState {
            context_id: _,
            reply,
        } => handle_migration_state_actor(cell, reply),
        GovernanceCommand::TombstoneMigratedContext { context_id, reply } => {
            handle_tombstone_migrated_context_actor(cell, deps, &context_id, reply).await
        }
        GovernanceCommand::AcknowledgeCommitFault { context_id, reply } => {
            handle_acknowledge_commit_fault_actor(cell, &context_id, reply)
        }
        GovernanceCommand::WithdrawGovernanceVote {
            context_id,
            proposal_id,
            voter_did,
            reply,
        } => {
            handle_withdraw_governance_vote_actor(
                cell,
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
                cell,
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
                cell,
                deps,
                &context_id,
                current_timestamp,
                reply,
            )
            .await
        }
        GovernanceCommand::ExecuteGovernanceAction { payload, reply } => {
            // The Class-S cell is threaded into the execute-governance path so the
            // downstream `execute_*` leaves it reaches can later migrate onto the
            // fail-closed combinator.
            Box::pin(handle_execute_governance_action_actor(
                cell, deps, *payload, reply,
            ))
            .await
        }
        GovernanceCommand::ProposeGovernanceAction { payload, reply } => {
            // Threaded as the cell: the auto-execute path inside reaches the
            // governance leaves via `execute_governance_action`.
            Box::pin(handle_propose_governance_action_actor(
                cell, deps, *payload, reply, false,
            ))
            .await
        }
        GovernanceCommand::ProposeGovernanceActionChecked { payload, reply } => {
            Box::pin(handle_propose_governance_action_checked_actor(
                cell, deps, *payload, reply,
            ))
            .await
        }
        GovernanceCommand::VoteOnProposal {
            payload,
            approve,
            reply,
        } => {
            Box::pin(handle_vote_on_proposal_actor(
                cell, deps, *payload, approve, reply,
            ))
            .await
        }
        GovernanceCommand::ApproveGovernanceProposal { payload, reply } => {
            Box::pin(handle_approve_governance_proposal_actor(
                cell, deps, *payload, reply,
            ))
            .await
        }
        GovernanceCommand::RejectGovernanceProposal { payload, reply } => {
            Box::pin(handle_reject_governance_proposal_actor(
                cell, deps, *payload, reply,
            ))
            .await
        }
        GovernanceCommand::EvaluatePeriodicConsequences { reply } => {
            handle_evaluate_periodic_consequences_actor(cell, deps, reply).await
        }
        GovernanceCommand::ProcessPendingCommits { reply } => {
            Box::pin(handle_process_pending_commits_actor(cell, deps, reply)).await
        }
        GovernanceCommand::EvaluateTimeouts { reply } => {
            Box::pin(handle_evaluate_timeouts_actor(cell, deps, reply)).await
        }
        GovernanceCommand::StartTimeoutTask { reply } => {
            handle_start_timeout_task_actor(cell, deps, reply).await
        }
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
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let tombstone_fut =
        crate::context::governance_helpers::tombstone_migrated_context(cell, deps, context_id);
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
    cell: &mut crate::context::actor::class_s::ClassSCell,
    context_id: &str,
    reply: oneshot::Sender<Result<crate::context::state::CommitFaultMarker, ContextError>>,
) -> Outcome<()> {
    let result = crate::context::governance_helpers::acknowledge_commit_fault(cell, context_id);
    let outcome = match &result {
        Ok(_) => Outcome::ok_mutated(()),
        Err(e) => Outcome::err_mutated(outcome_error_sketch(e)),
    };
    let _ = reply.send(result);
    outcome
}

/// Handle [`GovernanceCommand::WithdrawGovernanceVote`] (actor-shape).
async fn handle_withdraw_governance_vote_actor(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    proposal_id: &scp_protocol::context::governance::ProposalId,
    voter_did: &scp_did::DID,
    reply: oneshot::Sender<Result<scp_protocol::context::governance::ProposalStatus, ContextError>>,
) -> Outcome<()> {
    let withdraw_fut = crate::context::governance_helpers::withdraw_governance_vote(
        cell,
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
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    current_timestamp: u64,
    reply: oneshot::Sender<Result<bool, ContextError>>,
) -> Outcome<()> {
    let apply_fut = crate::context::governance_helpers::apply_pending_ceiling_modification(
        cell,
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
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    p: ProposeGovernanceActionPayload,
    reply: ProposeGovernanceActionReply,
    _checked: bool,
) -> Outcome<()> {
    let context_id = p.context_id.clone();
    let signing_key = p.signing_key.to_signing_key();
    let proposer_did = p.proposer_did.clone();
    let action = p.action;
    let key_package = p.key_package;

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
                cell,
                deps,
                &p.context_id,
                &proposer_did,
                action,
                &signing_key,
                false,
                key_package.as_deref(),
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
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    p: ProposeGovernanceActionPayload,
    reply: ProposeGovernanceActionCheckedReply,
) -> Outcome<()> {
    let context_id = p.context_id.clone();
    let signing_key = p.signing_key.to_signing_key();
    let proposer_did = p.proposer_did.clone();
    let action = p.action;
    let key_package = p.key_package;

    let propose_fut = async move {
        Box::pin(
            crate::context::governance_helpers::propose_governance_action_checked(
                cell,
                deps,
                &p.context_id,
                &proposer_did,
                action,
                &signing_key,
                key_package.as_deref(),
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
    cell: &mut crate::context::actor::class_s::ClassSCell,
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
            cell,
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
    cell: &mut crate::context::actor::class_s::ClassSCell,
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
                cell,
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
    cell: &mut crate::context::actor::class_s::ClassSCell,
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
                cell,
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
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    payload: ExecuteGovernanceActionPayload,
    reply: oneshot::Sender<Result<crate::context::state::GovernanceActionResult, ContextError>>,
) -> Outcome<()> {
    let context_id = payload.context_id.clone();

    let execute_fut = async move {
        // Direct-execute command. The payload carries ONLY the proposal id —
        // never a proposal, action, status, or caller DID.
        // `execute_governance_action` resolves the authoritative proposal from
        // the actor's own quorum-validated engine by id; a caller cannot
        // fabricate an `Approved` proposal or substitute an action.
        //
        // There is NO executor capability check here: the proposal is already
        // engine-`Approved` (quorum-verified at approve time), so execution is
        // an unprivileged finalization step. Both the executor (the
        // `GovernanceActionExecuted` leaf actor_did) and the consequence
        // subject are resolved INSIDE `execute_governance_action` from the
        // TRACKED proposal's proposer — never a caller-supplied DID (ADR-031 §8
        // "executor DID" / spec §7.3.1).
        Box::pin(
            crate::context::governance_helpers::execute_governance_action(
                cell,
                deps,
                &payload.context_id,
                &payload.proposal_id,
                // Direct-execute: no quorum-crossing voter. The executor (and
                // the `GovernanceActionExecuted` leaf actor_did) is resolved
                // inside `execute_governance_action` from the TRACKED proposal's
                // proposer — never a caller-supplied DID.
                None,
                // Direct-execute never carries an invitee KeyPackage (deferred
                // governed invite is issue #2027).
                None,
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
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    current_timestamp: u64,
    reply: oneshot::Sender<Result<bool, ContextError>>,
) -> Outcome<()> {
    let apply_fut = crate::context::governance_helpers::apply_pending_economic_policy_change(
        cell,
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
async fn handle_evaluate_periodic_consequences_actor(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    use scp_protocol::trust::consequence::{TriggeredConsequence, evaluate_consequence_rules};

    use crate::context::governance_logic::{
        EnforceConsequencesCtx, enforce_triggered_consequences, event_log_entries_for_consequences,
    };

    // Reads of the Class-C consequence config / membership go through the
    // cell's `Deref` (`&PerContextState`); no whole-state `&mut` is taken until
    // the enforcement loop, which routes through the Class-C view.
    let rules = cell.governance.consequence_rules.clone();
    if rules.is_empty() {
        let _ = reply.send(Ok(()));
        return Outcome::ok(());
    }
    let now = deps.clock.now_secs();
    let context_id = cell.handle.context_id().to_owned();
    let member_dids: Vec<scp_did::DID> = cell.membership.members().map(|m| m.did.clone()).collect();
    // Periodic sweep: one convergent window anchor shared across all members
    // so every honest member's durable consequence leaf converges (§9.9.3).
    let (events, convergent_now) = event_log_entries_for_consequences(
        &cell.receive_buffer,
        &context_id,
        now,
        deps.event_log.as_ref(),
    );

    let mut results: Vec<(scp_did::DID, Vec<TriggeredConsequence>)> = Vec::new();
    for member_did in member_dids {
        let triggered =
            evaluate_consequence_rules(&rules, &events, member_did.as_ref(), now, convergent_now);
        if !triggered.is_empty() {
            results.push((member_did, triggered));
        }
    }
    if results.is_empty() {
        let _ = reply.send(Ok(()));
        return Outcome::ok(());
    }
    // Consequence EVALUATION rides the run loop's coalesced persist — the
    // non-persisting Class-C view supplies the disjoint `consequence_split()`
    // borrows `ConsequenceStateSplit` needs (its `role_state` is the
    // consequence-only GROW view). The downward-auth outcomes it can produce — a
    // capability suspension (a `suspended_capabilities` GROW) or an `AssignRole`
    // demotion (a `member_capabilities` replacement) — are OR-accumulated here and
    // persisted fail-closed below (ADR-049 §9, RED-CS3): a coalesce-window crash
    // must not silently re-grant a member's removed authority.
    // ADR-049 §9 (RED-CS3): a fail-closed-persist obligation, owned HERE as a
    // token sink at the cell boundary and populated when a swept consequence
    // applies a downward-auth GROW (idempotent across the sweep — one owed
    // persist). The token carrier (vs. a `bool`) makes a populated-but-undischarged
    // obligation a Drop-guard PANIC in debug/CI.
    let mut downward_auth_obligation: Option<crate::context::actor::class_s::ClassSCommitToken> =
        None;
    {
        let mut view = cell.class_c_view();
        let mut split = view.consequence_split();
        for (member_did, triggered) in &results {
            // The GROW arms `downward_auth_obligation` directly (idempotent across
            // the sweep — one owed persist; no separate `note_downward_auth` call to
            // forget — GAP-A closed).
            let _ = enforce_triggered_consequences(
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
                &mut downward_auth_obligation,
            )
            .await;
        }
        // `split` / `view` drop here, releasing the `&mut cell` borrow.
    }

    // Fail-closed persist of an applied downward-auth mutation (keep-direction):
    // the mutation (suspension or `AssignRole` demotion) is already in memory;
    // committing the obligation's token makes it durable before acking (`take()`
    // discharges the Drop guard). On persist failure the mutation STAYS and the
    // error is surfaced to the caller; the handler still reports `mutated` so the
    // run loop also persists.
    let reply_result = match downward_auth_obligation.take() {
        Some(token) => token.commit(cell, deps, &context_id).await,
        None => Ok(()),
    };
    let _ = reply.send(reply_result);
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
async fn compute_commit_retry_outcomes(
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
        match transport
            .send_message(&pending.routing_id, &pending.commit_bytes)
            .await
        {
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
/// `&mut state` borrow. Pushes the per-committer broadcast-retry
/// lifecycle events as local `ContextEvent`s only.
///
/// Per the phase-2.md ADR-011-amendment exclusion taxonomy (per-committer
/// broadcast-retry bookkeeping), the `CommitBroadcastSucceeded` /
/// `CommitBroadcastPending` / `CommitBroadcastFailed` lifecycle events are
/// NOT durably appended to the canonical Merkle log: only the broadcasting
/// member holds the notion, so two honest members would diverge at equal
/// event count (§9.9.3). No durable consumer reads them.
fn apply_commit_retry_outcomes(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    outcomes: Vec<CommitRetryOutcome>,
) {
    use scp_protocol::context::membership::ContextEvent;

    use crate::context::state::CommitFaultMarker;

    // Coalesced: all mutations are Class-C / structural (the pending-commit
    // queue, the fault marker, and the local-only broadcast-retry lifecycle
    // events) and ride the run loop's coalesced persist — the non-persisting
    // Class-C view holds the disjoint field references without injecting a
    // per-site persist.
    let mut view = cell.class_c_view();
    let queue_len = view.pending_commits_mut().len();
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
                view.emit_event(
                    ContextEvent::CommitBroadcastSucceeded {
                        operation: operation.label(),
                        attempts,
                    },
                    context_id,
                    deps.event_tx.as_ref(),
                );
                to_remove.push(outcome.index);
            }
            CommitRetryOutcomeKind::Retry {
                error,
                next_attempt_at,
                new_retry_count,
                operation,
            } => {
                if let Some(entry) = view.pending_commits_mut().get_mut(outcome.index) {
                    entry.retry_count = new_retry_count;
                    entry.next_attempt_at = next_attempt_at;
                    entry.last_error = Some(error.clone());
                }
                view.emit_event(
                    ContextEvent::CommitBroadcastPending {
                        operation: operation.label(),
                        error,
                        attempt: new_retry_count,
                    },
                    context_id,
                    deps.event_tx.as_ref(),
                );
            }
            CommitRetryOutcomeKind::Failed {
                reason,
                attempts,
                operation,
            } => {
                let now_failed = deps.clock.now_secs();
                *view.commit_fault_mut() = Some(CommitFaultMarker {
                    operation: operation.clone(),
                    reason: reason.clone(),
                    failed_at: now_failed,
                    retry_count: attempts,
                });
                view.emit_event(
                    ContextEvent::CommitBroadcastFailed {
                        operation: operation.label(),
                        reason,
                        attempts,
                    },
                    context_id,
                    deps.event_tx.as_ref(),
                );
                to_remove.push(outcome.index);
            }
        }
    }
    to_remove.sort_unstable_by(|a, b| b.cmp(a));
    for idx in to_remove {
        view.pending_commits_mut().remove(idx);
    }
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
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    use crate::context::state::PendingCommit;

    // Reads go through the cell's `Deref` (`&PerContextState`).
    if cell.commit_fault.is_some() {
        let _ = reply.send(Ok(()));
        return Outcome::ok(());
    }
    let snapshot: Vec<PendingCommit> = cell.pending_commits.iter().cloned().collect();
    if snapshot.is_empty() {
        let _ = reply.send(Ok(()));
        return Outcome::ok(());
    }
    let now = deps.clock.now_secs();
    let context_id = cell.handle.context_id().to_owned();

    let outcomes = compute_commit_retry_outcomes(&snapshot, now, deps.transport.as_ref()).await;
    if outcomes.is_empty() {
        let _ = reply.send(Ok(()));
        return Outcome::ok(());
    }

    // Apply outcomes to the pending-commit queue and surface the per-committer
    // broadcast-retry lifecycle as local `ContextEvent`s. Per the phase-2.md
    // ADR-011-amendment exclusion taxonomy, these events are NOT durably
    // appended to the canonical Merkle log (they are per-committer; only the
    // broadcasting member holds the notion, so honest members would diverge at
    // equal event count — §9.9.3).
    apply_commit_retry_outcomes(cell, deps, &context_id, outcomes);

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
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    reply: oneshot::Sender<Result<bool, ContextError>>,
) -> Outcome<()> {
    use std::collections::HashSet;

    use scp_did::DID;

    use crate::context::governance::timeout::{
        collect_active_voters, process_pending_proposals, update_detection_state,
    };
    use crate::context::governance_helpers::build_governance_context;

    let context_id = cell.handle.context_id().to_owned();

    // Phase 1: read state, process proposals, detect deadlock. Reads go through
    // the cell's `Deref` (`&PerContextState`); every Class-C mutation routes
    // through a short-lived non-persisting Class-C view whose borrow is dropped
    // before the next call — coalesced (no per-site persist; the run loop
    // flushes after the handler reports `mutated`).
    let current_state = cell.handle.state();
    if current_state != scp_protocol::context::ContextState::Active {
        // Not Active = context closing, stop the loop. (The former
        // write-contended `None` branch is gone: the lock-free `ArcSwap`
        // read can never fail, so there is no "retry next tick" case.)
        let _ = reply.send(Ok(false));
        return Outcome::ok(());
    }

    let gov_ctx = build_governance_context(&*cell, deps.clock.as_ref());

    let current_members: HashSet<DID> = cell.membership.members().map(|m| m.did.clone()).collect();
    let departed: Vec<DID> = cell
        .governance
        .last_known_members
        .difference(&current_members)
        .cloned()
        .collect();

    let mls_epoch = cell.epoch.mls_epoch;
    let recovery_in_progress = cell.governance.deadlock.recovery_in_progress;
    let active_voters = collect_active_voters(cell.governance.engine.as_ref());

    // Class-C writes: refresh the last-known-member set, evict stale liveness
    // entries, drain the epoch-reset queue. Each is a short-lived view borrow.
    let epoch_resets: Vec<DID> = {
        let mut view = cell.class_c_view();
        let gov = view.governance_class_c_mut();
        *gov.last_known_members_mut() = current_members;
        gov.evict_stale_entries(deps.clock.now_secs());
        std::mem::take(gov.pending_epoch_resets_mut())
    };

    // `process_pending_proposals` mutates the engine; `update_detection_state`
    // needs `&mut deadlock` AND `&engine` simultaneously (disjoint fields, via
    // `detection_borrows`); `detect_deadlock` reads both. All three run inside a
    // single view borrow that drops before the translate / emit steps.
    let result;
    let conditions;
    {
        let mut view = cell.class_c_view();
        let gov = view.governance_class_c_mut();
        result = process_pending_proposals(
            gov.engine_mut().as_mut(),
            &gov_ctx,
            &departed,
            &epoch_resets,
        );
        let (deadlock, engine) = gov.detection_borrows();
        update_detection_state(&mut *deadlock, engine, &gov_ctx, &active_voters);
        // `detect_deadlock` reads both engine and deadlock; the same disjoint
        // borrows (now reborrowed shared) serve it.
        conditions =
            crate::context::governance::timeout::detect_deadlock(engine, &gov_ctx, deadlock);
    }

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
        let mut view = cell.class_c_view();
        for ctx_event in ctx_events {
            view.emit_event(ctx_event, &context_id, deps.event_tx.as_ref());
        }
        if conditions.is_empty() && recovery_in_progress {
            view.governance_class_c_mut()
                .deadlock_mut()
                .recovery_in_progress = false;
        } else if !conditions.is_empty() && !recovery_in_progress {
            view.governance_class_c_mut()
                .deadlock_mut()
                .recovery_in_progress = true;
        }
    }

    // Phase 4: periodic consequence evaluation (#1531). Reuses the
    // actor-shape sweep body via direct call rather than a nested
    // mailbox dispatch — both operate on the `cell` already owned by
    // this handler. No view borrow is live here.
    let (consequence_reply_tx, _consequence_reply_rx) = oneshot::channel();
    let _ = handle_evaluate_periodic_consequences_actor(cell, deps, consequence_reply_tx).await;

    // Phase 5 (PR #1606 C6): drain MLS commit retry queue. Same pattern
    // as Phase 4 — direct in-handler call.
    let (commits_reply_tx, _commits_reply_rx) = oneshot::channel();
    let _ = Box::pin(handle_process_pending_commits_actor(
        cell,
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
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    crate::context::governance_helpers::spawn_governance_timeout_task(cell, deps).await;
    let _ = reply.send(Ok(()));
    Outcome::ok_mutated(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod consequence_fail_closed_tests {
    //! ADR-049 §9 (RED-CS3): when the consequence ENGINE auto-suspends a member,
    //! the suspension OUTCOME must persist FAIL-CLOSED — a coalesce-window crash
    //! must not silently re-grant the denied capability. This drives the periodic
    //! consequence sweep against a member who trips a `MessageVelocity`
    //! `SuspendAccess` rule, with a persistence provider whose every write FAILS,
    //! and asserts (a) the handler reply surfaces `PersistenceFailed` rather than
    //! `Ok`, and (b) the suspension is RETAINED in memory (keep-direction), not
    //! lost.

    use std::sync::Arc;
    use std::time::Duration;

    use scp_did::DID;
    use scp_protocol::context::membership::ContextEvent;
    use scp_protocol::context::params::Capability;
    use scp_protocol::trust::consequence::{
        ConsequenceAction, ConsequenceRule, ConsequenceTrigger, EnforcementSeverity,
    };
    use tokio::sync::oneshot;

    use crate::context::ContextError;
    use crate::context::actor::class_s::ClassSCell;
    use crate::context::actor::deps::ActorDeps;
    use crate::context::actor::state::PerContextState;
    use crate::context::builder::ContextEventLogProvider;
    use crate::context::persistence::ContextPersistence;
    use crate::context::providers::MerkleEventLogProvider;

    const ADMIN: &str = "did:dht:z6MkAdminFailClosed";
    const SUBJECT: &str = "did:dht:z6MkSubjectFailClosed";
    const CTX_BYTE: u8 = 0x5c;

    /// Persistence whose `persist_context` ALWAYS fails — the fail-closed path.
    struct FailPersistence;
    #[async_trait::async_trait]
    impl ContextPersistence for FailPersistence {
        async fn persist_context(
            &self,
            _: &str,
            _: &crate::context::state::ContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Err("induced persist failure".into())
        }
        async fn load_context(
            &self,
            _: &str,
        ) -> Result<
            Option<crate::context::state::ContextSnapshot>,
            Box<dyn std::error::Error + Send + Sync>,
        > {
            Ok(None)
        }
        async fn delete_context(
            &self,
            _: &str,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        async fn list_persisted_contexts(
            &self,
        ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(Vec::new())
        }
    }

    /// Builds `ActorDeps` wired with the always-failing persistence and a fresh
    /// in-memory Merkle event log (the sweep reads the receive buffer for the
    /// non-convergent `MessageVelocity` evidence; the durable log stays empty).
    async fn build_fail_closed_deps() -> ActorDeps {
        use crate::context::supervisor::supervisor::Supervisor;
        use scp_platform::testing::InMemoryStorage;

        let crypto = Arc::new(crate::crypto::mls::provider::MlsCryptoProvider::new(
            ADMIN.to_owned(),
            std::sync::Arc::new(scp_clock::SystemClock),
        ));
        let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
            Box::new(crate::context::builder::NotConfiguredTransportProvider);
        let event_log: Box<dyn ContextEventLogProvider> = Box::new(MerkleEventLogProvider::new());
        let key_resolver: scp_protocol::context::governance::KeyResolver = Arc::new(|_, _| None);
        let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
            Arc::new(
                crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
                    InMemoryStorage::new(),
                )),
            );
        let clock: Arc<dyn scp_clock::Clock> = Arc::new(scp_clock::TestClock::new(1_700_000_000));
        let supervisor = Supervisor::with_providers(
            crypto,
            transport,
            event_log,
            key_resolver,
            Some(Box::new(FailPersistence)),
            None,
            None,
            Some(clock),
            mls_storage,
        );
        supervisor
            .build_actor_deps(&DID(ADMIN.to_owned()))
            .await
            .expect("build_actor_deps")
    }

    /// Seeds a `PerContextState` where SUBJECT is a member holding
    /// `MessagesWrite`, has buffered enough `MessageSent` events to trip a
    /// `MessageVelocity` threshold of 1, and the context carries a
    /// `MessageVelocity` → `SuspendAccess` consequence rule.
    fn seed_state() -> PerContextState {
        let mut state = PerContextState::new_for_test_encrypted(
            [CTX_BYTE; 32],
            1_700_000_000,
            DID(ADMIN.to_owned()),
        );
        // SUBJECT must be a present member with at least one derived capability,
        // so `suspend_all` (SuspendAccess) actually populates the suspended set.
        state
            .membership
            .add_member(DID(SUBJECT.to_owned()), "member".to_owned(), Vec::new());
        state.role_state.members.insert(SUBJECT.to_owned());
        state.role_state.member_capabilities.insert(
            SUBJECT.to_owned(),
            std::iter::once(Capability::MessagesWrite).collect(),
        );
        // Buffer per-author MessageSent events so a MessageVelocity rule with
        // threshold 1 fires for SUBJECT on the next sweep.
        for seq in 0..5u64 {
            state.receive_buffer.push(ContextEvent::MessageSent {
                sender_did: DID(SUBJECT.to_owned()),
                sequence_number: seq,
                payload: Vec::new(),
            });
        }
        // The consequence rule: a non-convergent MessageVelocity trigger whose
        // action is SuspendAccess (suspend every held capability).
        state.governance.consequence_rules.push(ConsequenceRule {
            trigger: ConsequenceTrigger::MessageVelocity,
            action: ConsequenceAction::Enforcement(EnforcementSeverity::SuspendAccess),
            threshold: 1,
            window: Duration::from_hours(1),
        });
        state
    }

    /// The consequence-engine auto-suspension persists FAIL-CLOSED: with a
    /// failing persistence provider, the periodic sweep handler surfaces the
    /// persist error AND retains the in-memory suspension (keep-direction).
    #[tokio::test]
    async fn periodic_sweep_suspension_persists_fail_closed() {
        let deps = build_fail_closed_deps().await;
        let mut cell = ClassSCell::new(seed_state());

        let (reply_tx, reply_rx) = oneshot::channel();
        let outcome =
            super::handle_evaluate_periodic_consequences_actor(&mut cell, &deps, reply_tx).await;

        // The reply surfaces the fail-closed persist error — the suspension
        // OUTCOME was NOT acknowledged as durable while the write failed.
        let reply = reply_rx.await.expect("handler replies");
        assert!(
            matches!(reply, Err(ContextError::PersistenceFailed(_))),
            "a consequence suspension whose fail-closed persist fails must surface \
             PersistenceFailed, not Ok; got {reply:?}"
        );

        // Keep-direction: the suspension STAYS in memory even though the persist
        // failed (it must not be silently un-applied — that would re-open the
        // re-grant window on the next coalesced write).
        let suspended = cell
            .role_state
            .suspended_for(SUBJECT)
            .expect("SUBJECT must have been suspended by the sweep");
        assert!(
            suspended.contains(&Capability::MessagesWrite),
            "the suspended capability is retained in memory (keep-direction) after \
             the fail-closed persist failure"
        );

        // The handler still reports a mutation so the actor's coalesced persist
        // also re-attempts the write.
        assert!(
            outcome.mutated,
            "the sweep mutated state (the suspension), so the outcome is `mutated`"
        );
    }

    /// SEND path: when a `send` trips a consequence that suspends the sender,
    /// the free (non-paid) send persists the suspension FAIL-CLOSED before
    /// acking — `finalize_send` surfaces the persist error and retains the
    /// suspension (keep-direction). Guards the `persist_finalized_send`
    /// free-path upgrade (ADR-049 §9, RED-CS3).
    #[tokio::test]
    async fn send_suspension_persists_fail_closed() {
        let deps = build_fail_closed_deps().await;
        // Seed SUBJECT as a member who will trip a MessageVelocity SuspendAccess
        // rule on the next send (the send itself emits the MessageSent that, with
        // the pre-seeded buffer, crosses the threshold-1 window).
        let state = seed_state();
        // The send path requires an Active context handle.
        state
            .handle
            .transition_to(&crate::context::ContextState::Active)
            .expect("transition to Active");
        let mut cell = ClassSCell::new(state);
        let ctx_str = hex::encode([CTX_BYTE; 32]);
        // ADR-056: `ctx_str` is a real 64-hex id, so the code under test keys
        // under its DECODED digest. Resolve the explicit arg the same way the
        // internal keying does, not via the raw `SHA-256(ctx_str)` primitive.
        let ctx_bytes = crate::context::state::context_id_to_bytes(&ctx_str);

        // Free (non-paid) send: no token, no signing key, not broadcast.
        let result = crate::context::messaging_helpers::finalize_send(
            &mut cell,
            &deps,
            &ctx_str,
            &ctx_bytes,
            &DID(SUBJECT.to_owned()),
            0,
            b"payload",
            None,
            None,
            false,
        )
        .await;

        assert!(
            matches!(result, Err(ContextError::PersistenceFailed(_))),
            "a send that applies a consequence suspension must persist fail-closed; \
             a failing persist must surface PersistenceFailed, not Ok; got {result:?}"
        );
        let suspended = cell
            .role_state
            .suspended_for(SUBJECT)
            .expect("SUBJECT must have been suspended by the send-path consequence");
        assert!(
            suspended.contains(&Capability::MessagesWrite),
            "the suspended capability is retained in memory (keep-direction) after \
             the send-path fail-closed persist failure"
        );
    }

    /// RECEIVE path: when a received message trips a consequence that suspends
    /// the sender, the receive cascade OR-sets the caller-owned suspension sink
    /// so the cell-holding receive handler persists fail-closed. This drives the
    /// cascade at `deliver_message_and_drain_buffered` (the lowest boundary that
    /// runs receive-side consequence enforcement) and asserts the sink is set,
    /// proving the downward-auth signal reaches the cell boundary (ADR-049 §9,
    /// RED-CS3). The fail-closed persist mechanism itself is proven by the
    /// periodic- and send-path tests above.
    #[tokio::test]
    async fn receive_suspension_sets_fail_closed_sink() {
        let deps = build_fail_closed_deps().await;
        let state = seed_state();
        // The receive cascade requires an Active context handle.
        state
            .handle
            .transition_to(&crate::context::ContextState::Active)
            .expect("transition to Active");
        let mut cell = ClassSCell::new(state);
        let ctx_str = hex::encode([CTX_BYTE; 32]);
        // ADR-056: `ctx_str` is a real 64-hex id, so the code under test keys
        // under its DECODED digest. Resolve the explicit arg the same way the
        // internal keying does, not via the raw `SHA-256(ctx_str)` primitive.
        let ctx_bytes = crate::context::state::context_id_to_bytes(&ctx_str);

        let inner = scp_protocol::envelope::inner::InnerEnvelope {
            version: scp_protocol::envelope::inner::SCP_INNER_ENVELOPE_VERSION,
            context_id: ctx_str.clone(),
            sender_did: SUBJECT.to_owned(),
            epoch: 0,
            generation: 0,
            sequence: 1,
            timestamp: 1_700_000_000,
            message_type: scp_protocol::envelope::inner::MessageType::Content,
            payload_hash: [0u8; 32],
            payload: Vec::new(),
            provenance: None,
            provenance_hash: [0u8; 32],
            signing_key_id: scp_did::SigningKeyId::Active,
            signature: [0u8; 64],
            extensions: std::collections::HashMap::new(),
        };

        let mut downward_auth_sink: Option<crate::context::actor::class_s::ClassSCommitToken> =
            None;
        let mut view = cell.class_c_view();
        let _ = crate::context::messaging_helpers::deliver_message_and_drain_buffered(
            &mut view,
            &deps,
            &ctx_str,
            &ctx_bytes,
            SUBJECT,
            &inner,
            b"hello",
            false,
            &mut downward_auth_sink,
        )
        .await
        .expect("delivery of an in-order application message succeeds");

        assert!(
            downward_auth_sink.is_some(),
            "a received message that trips a suspension consequence must POPULATE the \
             caller-owned token sink so the cell holder commits the suspension fail-closed"
        );
        // Discharge the obligation so the token's Drop guard does not trip. This
        // test runs under a FAILING persistence backend (it proves the SIGNAL
        // reaches the cell boundary; the actual fail-closed persist is proven by
        // the send/periodic tests), so `commit` returns the expected §9 durability
        // error — the keep-direction `commit` consumes the token regardless, which
        // is all that is needed to satisfy the Drop guard.
        if let Some(token) = downward_auth_sink.take() {
            let persist = token.commit(&cell, &deps, &ctx_str).await;
            assert!(
                matches!(persist, Err(ContextError::PersistenceFailed(_))),
                "the failing backend surfaces the §9 durability error on commit; got \
                 {persist:?}"
            );
        }
        // The `view` borrow of `cell` ends here (NLL) so the assertions below can
        // read the cell directly.
        // The suspension landed in memory through the cascade (the cell holder
        // would then persist it fail-closed via the now-set sink).
        let suspended = cell
            .role_state
            .suspended_for(SUBJECT)
            .expect("SUBJECT must have been suspended by the receive-path consequence");
        assert!(suspended.contains(&Capability::MessagesWrite));
    }
}
