//! Standing-pair handlers — see
//! [`StandingCommand`](crate::context::actor::commands::StandingCommand)
//! and spec §5.15.7.
//!
//! # Phase 2A.2 — actor-shape dispatch
//!
//! The handler's entry point [`dispatch`] takes
//! `(&ActorDeps, StandingCommand)` and routes variants to migrated
//! actor-shape helpers in [`crate::context::standing_helpers`]. Phase
//! 2A finalization deleted the supervisor-receiver shim
//! (`dispatch_from_shim`); supervisor-scoped variants (count / has /
//! register / reconnect-all) now route directly through
//! `Supervisor::dispatch_standing_direct` in
//! [`crate::context::supervisor::supervisor`].
//!
//! # SAGA WIRING DEFERRED — see
//! `.docs/adrs/DEFERRED-commit-11-saga-use-cases.md`.
//!
//! The `InitiateStandingPairCreate` saga-initiator variant returns
//! [`ContextError::NotImplemented`](scp_protocol::context::ContextError::NotImplemented)
//! because the 2-phase Prepare+Commit decomposition of
//! [`ContextManager::standing_context`](crate::context::standing_helpers::standing_context)
//! is spec-gapped — the spec does not yet define:
//!   - which fields of the `CreationReceipt` are covered by the
//!     Prepare-side commitment (public fields vs. committed-to-bytes),
//!   - how PrepareB rolls back if the remote side's key package fetch
//!     fails after a local MLS group was created,
//!   - whether the TOCTOU re-check in the legacy implementation should
//!     be driven by Commit-side idempotence or by a Prepare-side lock.
//!
//! Until those land, the saga-initiator path returns
//! `ContextError::NotImplemented`. Non-saga standing commands are fully
//! migrated in this commit (ADR-049 commit 11). The
//! `StandingContext` get-or-create variant still routes through the
//! legacy path, which is idempotent by construction.

use std::time::Duration;

use scp_protocol::context::ContextError;
use tokio::sync::oneshot;

use crate::context::actor::commands::StandingCommand;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;

/// Per-call transport budget for standing handlers. Plan §"Transport
/// timeouts inside actor handlers": 30 seconds.
pub const HANDLER_TIMEOUT: Duration = Duration::from_secs(30);

/// Dispatch a [`StandingCommand`] against actor-owned state and
/// capability-reduced dependencies.
pub async fn dispatch(deps: &ActorDeps, cmd: StandingCommand) -> Outcome<()> {
    Box::pin(dispatch_inner(deps, cmd)).await
}

async fn dispatch_inner(deps: &ActorDeps, cmd: StandingCommand) -> Outcome<()> {
    match cmd {
        StandingCommand::Placeholder { reply } => reply_not_implemented(reply),
        StandingCommand::StandingContext {
            local_did,
            peer_did,
            reply,
        } => handle_standing_context(deps, local_did, peer_did, reply).await,
        StandingCommand::StandingContextCount { reply } => {
            handle_standing_context_count(deps, reply).await
        }
        StandingCommand::HasStandingContext { peer_did, reply } => {
            handle_has_standing_context(deps, peer_did, reply).await
        }
        StandingCommand::RegisterStandingContext { peer_did, reply } => {
            handle_register_standing_context(deps, peer_did, reply).await
        }
        StandingCommand::ReconnectAllStanding { reply } => {
            handle_reconnect_all_standing(deps, reply).await
        }
        StandingCommand::InitiateStandingPairCreate { reply, .. } => reply_saga_deferred(reply),
    }
}

/// Handle [`StandingCommand::StandingContext`] — delegates to
/// [`ContextManager::standing_context`](crate::context::standing_helpers::standing_context)
/// under a 30s timeout.
async fn handle_standing_context(
    deps: &ActorDeps,
    local_did: scp_identity::DID,
    peer_did: scp_identity::DID,
    reply: oneshot::Sender<Result<String, ContextError>>,
) -> Outcome<()> {
    let standing_fut = async {
        crate::context::standing_helpers::standing_context(deps, &local_did, &peer_did).await
    };

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, standing_fut).await {
        Ok(Ok(ctx_id)) => (Outcome::ok_mutated(()), Ok(ctx_id)),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "standing_context exceeded {HANDLER_TIMEOUT:?} budget"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`StandingCommand::StandingContextCount`] — read-only.
async fn handle_standing_context_count(
    deps: &ActorDeps,
    reply: oneshot::Sender<Result<usize, ContextError>>,
) -> Outcome<()> {
    let count_fut = async { crate::context::standing_helpers::standing_context_count(deps) };

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, count_fut).await {
        Ok(count) => (Outcome::ok(()), Ok(count)),
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "standing_context_count exceeded {HANDLER_TIMEOUT:?} budget"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`StandingCommand::HasStandingContext`] — read-only.
async fn handle_has_standing_context(
    deps: &ActorDeps,
    peer_did: scp_identity::DID,
    reply: oneshot::Sender<Result<bool, ContextError>>,
) -> Outcome<()> {
    let has_fut = async { crate::context::standing_helpers::has_standing_context(deps, &peer_did) };

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, has_fut).await {
        Ok(has) => (Outcome::ok(()), Ok(has)),
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "has_standing_context exceeded {HANDLER_TIMEOUT:?} budget"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`StandingCommand::RegisterStandingContext`] — delegates to
/// [`ContextManager::register_standing_context`](crate::context::standing_helpers::register_standing_context)
/// under a 30s timeout. Always mutating.
async fn handle_register_standing_context(
    deps: &ActorDeps,
    peer_did: scp_identity::DID,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let register_fut =
        async { crate::context::standing_helpers::register_standing_context(deps, peer_did).await };

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, register_fut).await {
        Ok(Ok(())) => (Outcome::ok_mutated(()), Ok(())),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "register_standing_context exceeded {HANDLER_TIMEOUT:?} budget"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`StandingCommand::ReconnectAllStanding`] — delegates to
/// [`ContextManager::reconnect_all_standing`](crate::context::standing_helpers::reconnect_all_standing)
/// under a 30s timeout. Always mutating.
async fn handle_reconnect_all_standing(
    deps: &ActorDeps,
    reply: oneshot::Sender<Result<usize, ContextError>>,
) -> Outcome<()> {
    let reconnect_fut = crate::context::standing_helpers::reconnect_all_standing(deps);

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, reconnect_fut).await {
        Ok(Ok(count)) => (Outcome::ok_mutated(()), Ok(count)),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "reconnect_all_standing exceeded {HANDLER_TIMEOUT:?} budget"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Produce a best-effort clone-equivalent `ContextError` for the
/// handler's [`Outcome`] sink. Mirrors the pattern used in the other
/// migrated handler modules (messaging, lifecycle, governance).
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
    const MSG: &str = "StandingCommand::Placeholder — real variants migrate in commit 11 of \
                       ADR-049; Placeholder retained for commit-6 compile stability and \
                       deleted in commit 12 with the shim";
    let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
    Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
}

fn reply_saga_deferred(
    reply: oneshot::Sender<Result<crate::context::supervisor::saga_journal::SagaId, ContextError>>,
) -> Outcome<()> {
    const MSG: &str = "standing::initiate_standing_pair_create — saga wiring deferred to \
                       commit 11.5 per 5 enumerated spec gaps; see \
                       .docs/adrs/DEFERRED-commit-11-saga-use-cases.md (gap 1: standing-pair \
                       2-phase decomposition)";
    let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
    Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
}
