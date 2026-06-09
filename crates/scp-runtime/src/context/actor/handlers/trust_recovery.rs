//! Trust-recovery handlers — see
//! [`TrustRecoveryCommand`](crate::context::actor::commands::TrustRecoveryCommand)
//! and spec §9.12 / §23.17.
//!
//! # Phase 2A.1 — actor-shape dispatch
//!
//! The handler's primary entry point [`dispatch`] takes
//! `(&mut PerContextState, &ActorDeps, TrustRecoveryCommand)` and routes
//! per-context variants to the migrated state-owning helpers in
//! [`crate::context::trust_recovery_helpers`]. The cross-context
//! `RecoveryNotifyContact` variant cannot be handled inside one actor's
//! mailbox turn because it scans every context for shared membership;
//! that variant is rejected here with a `NotImplemented` reply (the
//! supervisor's [`dispatch_trust_recovery_command`] routes it through
//! [`Supervisor::dispatch_trust_recovery_direct`] before the
//! per-context mailbox lookup).
//!
//! The handler-side shim (`dispatch_from_shim`) was deleted in Phase 2A
//! finalization. The no-mailbox-context fallback now lives on
//! [`Supervisor::dispatch_trust_recovery_direct`](crate::context::supervisor::Supervisor::dispatch_trust_recovery_direct).
//!
//! Each per-call invocation is wrapped in a 30-second
//! [`tokio::time::timeout`] budget per ADR-049 §7.

use std::time::Duration;

use scp_protocol::context::ContextError;
use tokio::sync::oneshot;

use crate::context::actor::commands::{
    CreateGovernanceCheckpointPayload, RecoveryNotifyContactPayload,
    RecoverySendNotificationPayload, TrustRecoveryCommand,
};
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;
use crate::context::actor::state::PerContextState;

/// Per-call transport budget for trust-recovery handlers. Plan
/// §"Transport timeouts inside actor handlers": 30 seconds.
pub const HANDLER_TIMEOUT: Duration = Duration::from_secs(30);

/// Dispatch a [`TrustRecoveryCommand`] against actor-owned state.
///
/// # `RecoveryNotifyContact` and `Placeholder`
///
/// `RecoveryNotifyContact` requires cross-context fan-out and is not
/// handled inside an actor's mailbox turn — it is intercepted by
/// [`Supervisor::dispatch_trust_recovery_command`](crate::context::supervisor::Supervisor::dispatch_trust_recovery_command)
/// and routed through the cross-context direct path before any
/// per-context actor lookup. If a caller mistakenly routes it here,
/// the handler replies [`ContextError::NotImplemented`].
///
/// `Placeholder` exists for mailbox-pipe smoke tests and replies
/// `NotImplemented` by design.
pub async fn dispatch(
    state: &mut PerContextState,
    deps: &ActorDeps,
    cmd: TrustRecoveryCommand,
) -> Outcome<()> {
    Box::pin(dispatch_inner(state, deps, cmd)).await
}

async fn dispatch_inner(
    state: &mut PerContextState,
    deps: &ActorDeps,
    cmd: TrustRecoveryCommand,
) -> Outcome<()> {
    match cmd {
        TrustRecoveryCommand::Placeholder { reply } => reply_not_implemented(reply),
        TrustRecoveryCommand::CreateGovernanceCheckpoint { payload, reply } => {
            handle_create_governance_checkpoint(state, deps, *payload, reply).await
        }
        TrustRecoveryCommand::AddCheckpointCosignature {
            context_id,
            checkpoint,
            cosignature,
            reply,
        } => {
            handle_add_checkpoint_cosignature(
                state,
                deps,
                &context_id,
                *checkpoint,
                *cosignature,
                reply,
            )
            .await
        }
        TrustRecoveryCommand::RecoveryAdvanceEpoch { context_id, reply } => {
            handle_recovery_advance_epoch(state, deps, &context_id, reply).await
        }
        TrustRecoveryCommand::RecoverySendNotification { payload, reply } => {
            handle_recovery_send_notification(state, deps, *payload, reply).await
        }
        TrustRecoveryCommand::RecoveryNotifyContact { payload, reply } => {
            handle_recovery_notify_contact(state, deps, *payload, reply).await
        }
    }
}

/// Handle [`TrustRecoveryCommand::CreateGovernanceCheckpoint`] —
/// state-owning shape. Wraps the migrated helper in a 30s timeout and
/// reports the `Outcome` to the actor's run loop.
async fn handle_create_governance_checkpoint(
    state: &mut PerContextState,
    deps: &ActorDeps,
    p: CreateGovernanceCheckpointPayload,
    reply: oneshot::Sender<
        Result<scp_protocol::context::governance::ContextCheckpoint, ContextError>,
    >,
) -> Outcome<()> {
    let context_id = p.context_id.clone();

    // Helper is synchronous — no await inside its body. Wrap in
    // `async {}` so the 30s timeout still applies (event log pruning
    // could in principle do disk I/O via the provider).
    let create_fut = async {
        crate::context::trust_recovery_helpers::create_governance_checkpoint(
            state,
            deps,
            &p.context_id,
            p.checkpoint_seq,
            p.merkle_root,
            p.event_count,
            p.last_event_hash,
            p.state_snapshot_hash,
            &p.creator_did,
            p.creator_signature,
        )
    };

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, create_fut).await {
        Ok(Ok(checkpoint)) => (Outcome::ok_mutated(()), Ok(checkpoint)),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "create_governance_checkpoint exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`TrustRecoveryCommand::AddCheckpointCosignature`] —
/// state-owning shape. The validation candidate-vector pattern in the
/// helper means the checkpoint mutation only persists on success.
async fn handle_add_checkpoint_cosignature(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    mut checkpoint: scp_protocol::context::governance::ContextCheckpoint,
    cosignature: scp_protocol::context::governance::CosignedCheckpoint,
    reply: oneshot::Sender<
        Result<
            (
                scp_protocol::context::governance::ContextCheckpoint,
                scp_protocol::context::governance::CheckpointAttestationStatus,
            ),
            ContextError,
        >,
    >,
) -> Outcome<()> {
    let add_fut = async {
        crate::context::trust_recovery_helpers::add_checkpoint_cosignature(
            state,
            deps,
            &mut checkpoint,
            cosignature,
        )
    };

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, add_fut).await {
        Ok(Ok(status)) => (Outcome::ok_mutated(()), Ok((checkpoint, status))),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            // On validation failure the helper does NOT apply the
            // cosignature (candidate-vector pattern). Mark the outcome
            // as non-mutated.
            (Outcome::err(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "add_checkpoint_cosignature exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`TrustRecoveryCommand::RecoveryAdvanceEpoch`] — state-owning shape.
async fn handle_recovery_advance_epoch(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    reply: oneshot::Sender<Result<u64, ContextError>>,
) -> Outcome<()> {
    let advance_fut = async {
        crate::context::trust_recovery_helpers::recovery_advance_epoch(state, deps, context_id)
    };

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, advance_fut).await {
        Ok(Ok(epoch)) => (Outcome::ok_mutated(()), Ok(epoch)),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            // `recovery_advance_epoch` may have mutated MLS state
            // before returning an error (the epoch advance precedes
            // the counter increment inside the helper). Report
            // `err_mutated` to be safe.
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "recovery_advance_epoch exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`TrustRecoveryCommand::RecoverySendNotification`] —
/// state-owning shape. Reads `state.epoch.mls_epoch` and uses
/// `deps.crypto.seal` + `deps.transport.send_message`. No persistent
/// state mutation; reports `Outcome::ok(())` on success.
async fn handle_recovery_send_notification(
    state: &mut PerContextState,
    deps: &ActorDeps,
    p: RecoverySendNotificationPayload,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let context_id = p.context_id.clone();
    let signing_key = p.signing_key.to_signing_key();

    let send_fut = async {
        crate::context::trust_recovery_helpers::recovery_send_notification(
            state,
            deps,
            &p.context_id,
            &p.sender_did,
            &p.payload,
            p.sequence,
            &signing_key,
        )
    };

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, send_fut).await {
        Ok(Ok(())) => (Outcome::ok(()), Ok(())),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "recovery_send_notification exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`TrustRecoveryCommand::RecoveryNotifyContact`] — actor-
/// shape entry. Cross-context fan-out: looks up the shared context
/// via [`SupervisorHandle::find_shared_context`](crate::context::supervisor::handle::SupervisorHandle::find_shared_context)
/// and dispatches a `RecoverySendNotification` through the
/// supervisor's mailbox-routing path. The actor that handles this
/// command does not need to be a member of the shared context — any
/// actor with an `ActorDeps` bundle can drive the cross-context
/// lookup. Reports `Outcome::ok(())` on success (no per-context state
/// mutation in this actor).
async fn handle_recovery_notify_contact(
    state: &mut PerContextState,
    deps: &ActorDeps,
    p: RecoveryNotifyContactPayload,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let recovering_did = p.recovering_did.clone();
    let signing_key = p.signing_key.to_signing_key();

    let notify_fut = crate::context::trust_recovery_helpers::recovery_notify_contact(
        state,
        deps,
        &p.recovering_did,
        &p.contact_did,
        &p.payload,
        &signing_key,
    );

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, notify_fut).await {
        Ok(Ok(())) => (Outcome::ok(()), Ok(())),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "recovery_notify_contact exceeded {HANDLER_TIMEOUT:?} budget for recovering_did {recovering_did}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Produce a best-effort clone-equivalent `ContextError` for the
/// handler's [`Outcome`] sink. Mirrors the pattern used in peer
/// handlers.
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
        ContextError::NotImplemented(msg) => ContextError::NotImplemented(msg.clone()),
        other => ContextError::CryptoFailed(format!("{other}")),
    }
}

fn reply_not_implemented(reply: oneshot::Sender<Result<(), ContextError>>) -> Outcome<()> {
    const MSG: &str = "TrustRecoveryCommand::Placeholder — mailbox-pipe smoke target; \
                       no real work performed";
    let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
    Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
}
