//! Trust-recovery handlers — see
//! [`TrustRecoveryCommand`](crate::context::actor::commands::TrustRecoveryCommand)
//! and spec §9.12 / §23.17 / plan row 10 of the commit ladder.
//!
//! # Commit 10 scope
//!
//! Migrates the dispatch shape: the handler takes
//! `&Arc<ContextManager>` + [`ActorDeps`] + [`TrustRecoveryCommand`],
//! returns `Outcome<()>`.
//!
//! The underlying byte-identical implementation still lives on
//! [`ContextManager`](crate::context::manager::ContextManager): each
//! handler delegates to
//! [`ContextManager::create_governance_checkpoint`](crate::context::manager::ContextManager::create_governance_checkpoint),
//! [`ContextManager::add_checkpoint_cosignature`](crate::context::manager::ContextManager::add_checkpoint_cosignature),
//! [`ContextManager::recovery_advance_epoch`](crate::context::manager::ContextManager::recovery_advance_epoch),
//! [`ContextManager::recovery_send_notification`](crate::context::manager::ContextManager::recovery_send_notification),
//! or
//! [`ContextManager::recovery_notify_contact`](crate::context::manager::ContextManager::recovery_notify_contact).
//! The shim wraps each delegated call in [`tokio::time::timeout`] with
//! a 30s budget per ADR-049 §7.
//!
//! # ADR-049 commit 12c.7 — direct dispatch
//!
//! Prior to 12c.7 the handler took a `MutationStateView<'_>` borrow
//! adapter that bundled an `Arc<ContextManager>` reference plus a
//! mutable scratch send-sequence tracker (the trust-recovery path never
//! read the tracker, but the adapter was uniform across handlers).
//! 12c.7 deletes the adapter: the supervisor passes the
//! `&Arc<ContextManager>` directly and no scratch tracker is allocated.
//!
//! Trust-recovery's synchronous methods on `ContextManager`
//! (`verify_attestation`, `create_challenge`, `verify_challenge_response`)
//! are pure-CPU operations with no state mutation; they are not
//! migrated as actor commands because the post-refactor architecture
//! moves them off `ContextManager` entirely (they only need a DID
//! resolver + clock). Migration paths to non-actor helper types land
//! in commit 12 alongside the manager deletion.

use std::time::Duration;

use scp_protocol::context::ContextError;
use tokio::sync::oneshot;

use crate::context::actor::commands::{
    CreateGovernanceCheckpointPayload, RecoveryNotifyContactPayload,
    RecoverySendNotificationPayload, TrustRecoveryCommand,
};
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;
use crate::context::supervisor::Supervisor;

/// Per-call transport budget for trust-recovery handlers. Plan
/// §"Transport timeouts inside actor handlers": 30 seconds.
pub const HANDLER_TIMEOUT: Duration = Duration::from_secs(30);

/// Dispatch a [`TrustRecoveryCommand`] against an attached manager
/// + deps bundle.
///
/// Plan-conforming dispatch signature: matches the post-refactor actor
/// `run()` loop's call shape
/// (`handlers::trust_recovery::dispatch(&mgr, &self.deps, cmd).await`).
/// `deps` is accepted for symmetry — the trust-recovery handler does
/// not yet touch deps during the shim period. Commit 12 rewires these
/// paths.
pub async fn dispatch(
    supervisor: &Supervisor,
    _deps: &ActorDeps,
    cmd: TrustRecoveryCommand,
) -> Outcome<()> {
    Box::pin(dispatch_inner(supervisor, cmd)).await
}

/// Shim-callable dispatch. Used by
/// [`Supervisor::dispatch_trust_recovery_command`](crate::context::supervisor::supervisor::Supervisor::dispatch_trust_recovery_command)
/// during the commits-10-to-11 migration window — deleted in commit 12
/// when the shim dissolves.
///
/// # Supervisor receiver (ADR-049 commit 12c.9d)
pub(crate) async fn dispatch_from_shim(
    supervisor: &Supervisor,
    cmd: TrustRecoveryCommand,
) -> Outcome<()> {
    Box::pin(dispatch_inner(supervisor, cmd)).await
}

async fn dispatch_inner(supervisor: &Supervisor, cmd: TrustRecoveryCommand) -> Outcome<()> {
    match cmd {
        TrustRecoveryCommand::Placeholder { reply } => reply_not_implemented(reply),
        TrustRecoveryCommand::CreateGovernanceCheckpoint { payload, reply } => {
            handle_create_governance_checkpoint(supervisor, *payload, reply).await
        }
        TrustRecoveryCommand::AddCheckpointCosignature {
            context_id,
            checkpoint,
            cosignature,
            reply,
        } => {
            handle_add_checkpoint_cosignature(
                supervisor,
                &context_id,
                *checkpoint,
                *cosignature,
                reply,
            )
            .await
        }
        TrustRecoveryCommand::RecoveryAdvanceEpoch { context_id, reply } => {
            handle_recovery_advance_epoch(supervisor, &context_id, reply).await
        }
        TrustRecoveryCommand::RecoverySendNotification { payload, reply } => {
            handle_recovery_send_notification(supervisor, *payload, reply).await
        }
        TrustRecoveryCommand::RecoveryNotifyContact { payload, reply } => {
            handle_recovery_notify_contact(supervisor, *payload, reply).await
        }
    }
}

/// Handle [`TrustRecoveryCommand::CreateGovernanceCheckpoint`] —
/// delegates to
/// [`ContextManager::create_governance_checkpoint`](crate::context::manager::ContextManager::create_governance_checkpoint)
/// under a 30s timeout. The legacy method prunes the event log as a
/// side effect when a pruning policy is configured — that is a
/// mutation, so the handler reports `mutated: true` on success.
async fn handle_create_governance_checkpoint(
    supervisor: &Supervisor,
    p: CreateGovernanceCheckpointPayload,
    reply: oneshot::Sender<
        Result<scp_protocol::context::governance::ContextCheckpoint, ContextError>,
    >,
) -> Outcome<()> {
    let context_id = p.context_id.clone();

    let create_fut = async {
        crate::context::trust_recovery_helpers::create_governance_checkpoint(
            supervisor,
            &p.context_id,
            p.checkpoint_seq,
            p.merkle_root,
            p.event_count,
            p.last_event_hash,
            p.state_snapshot_hash,
            &p.creator_did,
            p.creator_signature,
        )
        .await
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
/// delegates to
/// [`ContextManager::add_checkpoint_cosignature`](crate::context::manager::ContextManager::add_checkpoint_cosignature)
/// under a 30s timeout. The legacy method takes `&mut ContextCheckpoint`;
/// the handler owns the checkpoint by value and returns the mutated
/// copy alongside the attestation status.
async fn handle_add_checkpoint_cosignature(
    supervisor: &Supervisor,
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
    let add_fut = crate::context::trust_recovery_helpers::add_checkpoint_cosignature(
        supervisor,
        context_id,
        &mut checkpoint,
        cosignature,
    );

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, add_fut).await {
        Ok(Ok(status)) => (Outcome::ok_mutated(()), Ok((checkpoint, status))),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            // On validation failure the legacy method does NOT apply
            // the cosignature (it mutates the candidate vector first).
            // Mark the outcome as non-mutated in that case — but also
            // send back the unchanged checkpoint is not needed, the
            // error carries all the caller needs.
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

/// Handle [`TrustRecoveryCommand::RecoveryAdvanceEpoch`] — delegates
/// to
/// [`ContextManager::recovery_advance_epoch`](crate::context::manager::ContextManager::recovery_advance_epoch)
/// under a 30s timeout.
async fn handle_recovery_advance_epoch(
    supervisor: &Supervisor,
    context_id: &str,
    reply: oneshot::Sender<Result<u64, ContextError>>,
) -> Outcome<()> {
    let advance_fut =
        crate::context::trust_recovery_helpers::recovery_advance_epoch(supervisor, context_id);

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, advance_fut).await {
        Ok(Ok(epoch)) => (Outcome::ok_mutated(()), Ok(epoch)),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            // `recovery_advance_epoch` may have mutated MLS state
            // before returning an error (the epoch advance precedes
            // the counter increment inside the manager). Report
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
/// delegates to
/// [`ContextManager::recovery_send_notification`](crate::context::manager::ContextManager::recovery_send_notification)
/// under a 30s timeout. The legacy method transmits a bypass-encrypted
/// recovery envelope but does not persist per-context state
/// modifications — `Outcome::ok(())` on the success path.
async fn handle_recovery_send_notification(
    supervisor: &Supervisor,
    p: RecoverySendNotificationPayload,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let context_id = p.context_id.clone();
    let signing_key = p.signing_key.to_signing_key();

    let send_fut = async {
        crate::context::trust_recovery_helpers::recovery_send_notification(
            supervisor,
            &p.context_id,
            &p.sender_did,
            &p.payload,
            p.sequence,
            &signing_key,
        )
        .await
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

/// Handle [`TrustRecoveryCommand::RecoveryNotifyContact`] — delegates
/// to
/// [`ContextManager::recovery_notify_contact`](crate::context::manager::ContextManager::recovery_notify_contact)
/// under a 30s timeout. Read-only with respect to per-context state;
/// the legacy method only transmits an envelope through the first
/// shared context it finds.
async fn handle_recovery_notify_contact(
    supervisor: &Supervisor,
    p: RecoveryNotifyContactPayload,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let recovering_did = p.recovering_did.clone();
    let signing_key = p.signing_key.to_signing_key();

    let notify_fut = async {
        crate::context::trust_recovery_helpers::recovery_notify_contact(
            supervisor,
            &p.recovering_did,
            &p.contact_did,
            &p.payload,
            &signing_key,
        )
        .await
    };

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
        other => ContextError::CryptoFailed(format!("{other}")),
    }
}

fn reply_not_implemented(reply: oneshot::Sender<Result<(), ContextError>>) -> Outcome<()> {
    const MSG: &str = "TrustRecoveryCommand::Placeholder — real variants migrate in commit 10 \
                       of ADR-049; Placeholder retained for commit-6 compile stability and \
                       deleted in commit 12 with the shim";
    let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
    Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
}
