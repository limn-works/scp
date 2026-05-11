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
//! supervisor-shape `handle_*` helpers that delegated to
//! `crate::context::governance_helpers_legacy::*_legacy` — has been
//! deleted at Phase 2A finalization. The `Placeholder` variant remains
//! as the mailbox-test handshake target.
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

    // Phase 1 fix-up of ADR-049 (post-review-round-1): the propose path
    // MUST run the suspension-aware capability check (check=true) because
    // engine-side enforcement does not see suspension overlays.
    let propose_fut = async move {
        Box::pin(
            crate::context::governance_helpers::propose_governance_action_inner(
                state,
                deps,
                &p.context_id,
                &proposer_did,
                action,
                &signing_key,
                true,
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
            true,
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
