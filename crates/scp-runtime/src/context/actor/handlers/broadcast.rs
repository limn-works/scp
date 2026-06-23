//! Broadcast handlers — see
//! [`BroadcastCommand`](crate::context::actor::commands::BroadcastCommand)
//! and plan §"Broadcast contexts".
//!
//! # Phase 2A.5 -- actor-shape dispatch
//!
//! The handler's primary entry point [`dispatch`] takes
//! `(&mut PerContextState, &ActorDeps, BroadcastCommand)` and routes
//! non-publish variants through [`crate::context::broadcast_helpers`].
//! Every valid context has a registered per-context actor, so a command
//! that finds no actor is replied to with a typed
//! [`ContextError::ContextNotRegistered`](scp_protocol::context::ContextError::ContextNotRegistered)
//! by the supervisor's no-actor fallback.
//!
//! # Publish + key-custody plumbing (two-phase reservation)
//!
//! The publish entry points on `ContextManager` take
//! `custody: &impl KeyCustody`. Because
//! [`KeyCustody`](scp_platform::KeyCustody) uses RPITIT (not
//! `dyn`-safe), the actor mailbox cannot carry a custody reference
//! directly — and the actor must not hold `&mut PerContextState` across
//! an arbitrary-duration host-language `custody.sign().await`. Publish is
//! therefore split into two custody-free mailbox commands plus a release:
//! [`BroadcastCommand::ReserveBroadcastPublish`] reserves the sequence and
//! returns the signing-payload digest; the supervisor signs OUTSIDE the
//! actor with the caller's custody (see
//! [`Supervisor::dispatch_broadcast_command_with_custody`](crate::context::supervisor::supervisor::Supervisor::dispatch_broadcast_command_with_custody));
//! [`BroadcastCommand::ApplyBroadcastPublish`] seals the reserved
//! sequence. A reservation that is never applied is rolled back via
//! [`BroadcastCommand::ReleaseBroadcastReservation`]. Each mailbox phase
//! holds `&mut PerContextState` only briefly, and concurrent publishes
//! each reserve a distinct sequence.
//!
//! # SAGA WIRING DEFERRED — see
//! `.docs/adrs/DEFERRED-commit-11-saga-use-cases.md`.
//!
//! The `InitiateBroadcastHostingHandshake` saga-initiator variant
//! returns [`ContextError::NotImplemented`](scp_protocol::context::ContextError::NotImplemented)
//! because broadcast hosting handshake protocol is spec-gapped — the
//! spec does not yet define the subscriber→host key-exchange frames,
//! host-config negotiation, or §5.14.2 step-4 transport. Until those
//! land, the saga-initiator path returns
//! `ContextError::NotImplemented`.

use std::time::Duration;

use scp_protocol::context::ContextError;
use tokio::sync::oneshot;

use crate::context::actor::class_s::ClassSCell;
use crate::context::actor::commands::{
    ApplyBroadcastPublishPayload, BlockBroadcastSubscriberReply, BroadcastAdmissionReply,
    BroadcastBlockPayload, BroadcastCommand, HandleBroadcastKeyRequestReply, PublishBroadcastReply,
    ReleaseBroadcastReservationPayload, ReserveBroadcastPublishPayload,
    ReserveBroadcastPublishReply, SubscribeBroadcastPayload, SubscribeBroadcastReply,
    UnsubscribeBroadcastPayload, UnsubscribeBroadcastReply,
};
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;

/// Per-call transport budget for broadcast handlers.
pub const HANDLER_TIMEOUT: Duration = Duration::from_secs(30);

/// Dispatch a [`BroadcastCommand`] against actor-owned cell and deps.
///
/// The single-shot `PublishBroadcast` / `PublishBroadcastContent`
/// variants require a key custody reference which cannot cross the actor
/// mailbox; this entry point rejects them with a typed error directing
/// the caller to the two-phase reserve/apply path. The custody-free
/// `ReserveBroadcastPublish` / `ApplyBroadcastPublish` /
/// `ReleaseBroadcastReservation` variants ARE handled here against
/// actor-owned cell.
pub(crate) async fn dispatch(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    cmd: BroadcastCommand,
) -> Outcome<()> {
    Box::pin(dispatch_inner(cell, deps, cmd)).await
}

async fn dispatch_inner(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    cmd: BroadcastCommand,
) -> Outcome<()> {
    match cmd {
        BroadcastCommand::Placeholder { reply } => reply_not_implemented(reply),
        BroadcastCommand::SubscribeBroadcast { payload, reply } => {
            handle_subscribe_broadcast(cell, deps, *payload, reply).await
        }
        BroadcastCommand::UnsubscribeBroadcast { payload, reply } => {
            handle_unsubscribe_broadcast(cell, deps, *payload, reply).await
        }
        BroadcastCommand::BlockBroadcastSubscriber { payload, reply } => {
            handle_block_broadcast_subscriber(cell, deps, *payload, reply).await
        }
        BroadcastCommand::UnblockBroadcastSubscriber { payload, reply } => {
            handle_unblock_broadcast_subscriber(cell, deps, *payload, reply).await
        }
        BroadcastCommand::HandleBroadcastKeyRequest {
            context_id,
            author_did,
            requester_did,
            wrapping_pubkey,
            reply,
        } => {
            handle_handle_broadcast_key_request(
                cell,
                deps,
                &context_id,
                &author_did,
                &requester_did,
                wrapping_pubkey,
                reply,
            )
            .await
        }
        BroadcastCommand::BroadcastSubscriberCount { context_id, reply } => {
            handle_broadcast_subscriber_count(cell, &context_id, reply).await
        }
        BroadcastCommand::IsBroadcastSubscriber {
            context_id,
            did,
            reply,
        } => handle_is_broadcast_subscriber(cell, &context_id, &did, reply).await,
        BroadcastCommand::BroadcastAdmission { context_id, reply } => {
            handle_broadcast_admission(cell, &context_id, reply).await
        }
        BroadcastCommand::PublishBroadcast { reply, .. } => {
            const MSG: &str = "BroadcastCommand::PublishBroadcast requires a KeyCustody reference; \
                 route through Supervisor::dispatch_broadcast_command_with_custody (generic over custody)";
            let _ = reply.send(Err(ContextError::InvalidState(MSG.to_owned())));
            Outcome::err(ContextError::InvalidState(MSG.to_owned()))
        }
        BroadcastCommand::PublishBroadcastContent { reply, .. } => {
            const MSG: &str = "BroadcastCommand::PublishBroadcastContent requires a KeyCustody reference; \
                 route through Supervisor::dispatch_broadcast_command_with_custody (generic over custody)";
            let _ = reply.send(Err(ContextError::InvalidState(MSG.to_owned())));
            Outcome::err(ContextError::InvalidState(MSG.to_owned()))
        }
        BroadcastCommand::ReserveBroadcastPublish { payload, reply } => {
            handle_reserve_broadcast_publish(cell, deps, *payload, reply).await
        }
        BroadcastCommand::ApplyBroadcastPublish { payload, reply } => {
            handle_apply_broadcast_publish(cell, deps, *payload, reply).await
        }
        BroadcastCommand::ReleaseBroadcastReservation { payload, reply } => {
            handle_release_broadcast_reservation(cell, *payload, reply)
        }
        BroadcastCommand::InitiateBroadcastHostingHandshake { reply, .. } => {
            reply_saga_deferred(reply)
        }
    }
}

async fn handle_subscribe_broadcast(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    p: SubscribeBroadcastPayload,
    reply: SubscribeBroadcastReply,
) -> Outcome<()> {
    let context_id = p.context_id.clone();

    let subscribe_fut = async {
        crate::context::broadcast_helpers::subscribe_broadcast::<
            NoopDidResolver,
            NoopNonceTracker,
            NoopRevocationChecker,
            NoopProofResolver,
            std::collections::hash_map::RandomState,
        >(
            cell,
            deps,
            &p.context_id,
            &p.subscriber_did,
            p.ucan.as_ref(),
            p.timestamp,
            None,
        )
    };

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, subscribe_fut).await {
        Ok(Ok(result)) => (Outcome::ok_mutated(()), Ok(result)),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "subscribe_broadcast exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

async fn handle_unsubscribe_broadcast(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    p: UnsubscribeBroadcastPayload,
    reply: UnsubscribeBroadcastReply,
) -> Outcome<()> {
    let context_id = p.context_id.clone();

    let unsub_fut = async {
        crate::context::broadcast_helpers::unsubscribe_broadcast(
            cell,
            deps,
            &p.context_id,
            &p.subscriber_did,
            p.rotate_keys,
        )
    };

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, unsub_fut).await {
        Ok(Ok(result)) => (Outcome::ok_mutated(()), Ok(result)),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "unsubscribe_broadcast exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

async fn handle_block_broadcast_subscriber(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    p: BroadcastBlockPayload,
    reply: BlockBroadcastSubscriberReply,
) -> Outcome<()> {
    let context_id = p.context_id.clone();

    let block_fut = async {
        crate::context::broadcast_helpers::block_broadcast_subscriber(
            cell,
            deps,
            &p.context_id,
            &p.author_did,
            &p.subscriber_did,
        )
    };

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, block_fut).await {
        Ok(Ok(result)) => (Outcome::ok_mutated(()), Ok(result)),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "block_broadcast_subscriber exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

async fn handle_unblock_broadcast_subscriber(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    p: BroadcastBlockPayload,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let context_id = p.context_id.clone();

    let unblock_fut = async {
        crate::context::broadcast_helpers::unblock_broadcast_subscriber(
            cell,
            deps,
            &p.context_id,
            &p.author_did,
            &p.subscriber_did,
        )
    };

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, unblock_fut).await {
        Ok(Ok(())) => (Outcome::ok_mutated(()), Ok(())),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "unblock_broadcast_subscriber exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

async fn handle_handle_broadcast_key_request(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    author_did: &scp_identity::DID,
    requester_did: &scp_identity::DID,
    wrapping_pubkey: [u8; 32],
    reply: HandleBroadcastKeyRequestReply,
) -> Outcome<()> {
    let key_req_fut = async {
        crate::context::broadcast_helpers::handle_broadcast_key_request(
            cell,
            deps,
            author_did,
            requester_did,
            &wrapping_pubkey,
        )
    };

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, key_req_fut).await {
        Ok(Ok(decision)) => (Outcome::ok(()), Ok(decision)),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "handle_broadcast_key_request exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

async fn handle_broadcast_subscriber_count(
    cell: &mut ClassSCell,
    context_id: &str,
    reply: oneshot::Sender<Result<Option<usize>, ContextError>>,
) -> Outcome<()> {
    let count_fut = async { crate::context::broadcast_helpers::broadcast_subscriber_count(cell) };

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, count_fut).await {
        Ok(count) => (Outcome::ok(()), Ok(count)),
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "broadcast_subscriber_count exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

async fn handle_is_broadcast_subscriber(
    cell: &mut ClassSCell,
    context_id: &str,
    did: &str,
    reply: oneshot::Sender<Result<bool, ContextError>>,
) -> Outcome<()> {
    let is_fut = async { crate::context::broadcast_helpers::is_broadcast_subscriber(cell, did) };

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, is_fut).await {
        Ok(is) => (Outcome::ok(()), Ok(is)),
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "is_broadcast_subscriber exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

async fn handle_broadcast_admission(
    cell: &mut ClassSCell,
    context_id: &str,
    reply: BroadcastAdmissionReply,
) -> Outcome<()> {
    let admission_fut = async { crate::context::broadcast_helpers::broadcast_admission(cell) };

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, admission_fut).await {
        Ok(admission) => (Outcome::ok(()), Ok(admission)),
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "broadcast_admission exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

async fn handle_reserve_broadcast_publish(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    p: ReserveBroadcastPublishPayload,
    reply: ReserveBroadcastPublishReply,
) -> Outcome<()> {
    let context_id = p.context_id.clone();

    let reserve_fut = async {
        crate::context::broadcast_helpers::reserve_broadcast_publish(cell, deps, &p.author_did)
    };

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, reserve_fut).await {
        // Reservation mutates actor cell (consumes the sequence), so the
        // outcome is `mutated` even on the happy path — the apply or a
        // later release reconciles it.
        Ok(Ok(out)) => (Outcome::ok_mutated(()), Ok(out)),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "reserve_broadcast_publish exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

async fn handle_apply_broadcast_publish(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    p: ApplyBroadcastPublishPayload,
    reply: PublishBroadcastReply,
) -> Outcome<()> {
    let context_id = p.context_id.clone();

    let apply_fut = async {
        crate::context::broadcast_helpers::apply_broadcast_publish(
            cell,
            deps,
            &p.context_id,
            &p.reservation_id,
            &p.signature,
            &p.payload,
        )
    };

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, apply_fut).await {
        Ok(Ok(env)) => (Outcome::ok_mutated(()), Ok(env)),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "apply_broadcast_publish exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

fn handle_release_broadcast_reservation(
    cell: &mut ClassSCell,
    p: ReleaseBroadcastReservationPayload,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let ReleaseBroadcastReservationPayload { reservation_id, .. } = p;
    crate::context::broadcast_helpers::release_broadcast_reservation(cell, &reservation_id);
    let _ = reply.send(Ok(()));
    // Releasing rolls the reserved sequence back — that is a mutation.
    Outcome::ok_mutated(())
}

// ---------------------------------------------------------------------------
// No-op UCAN validation trait impls — satisfy the generic bounds on
// [`crate::context::broadcast_helpers::subscribe_broadcast`]
// when the caller passes `None` for `validation_ctx`. No method is
// actually invoked; the types exist only as compile-time witnesses so
// the turbofish has something to bind to. Mirrors the
// `NoOpDidResolver` / `NoOpNonceTracker` / ... stubs in the PyO3
// bridge's `context.rs` (public-open broadcast path does not touch
// UCAN validation at all).
// ---------------------------------------------------------------------------

struct NoopDidResolver;
impl scp_protocol::crypto::ucan::validate::DidResolver for NoopDidResolver {
    fn resolve_public_key(
        &self,
        _did: &str,
    ) -> Result<[u8; 32], scp_protocol::crypto::ucan::UcanError> {
        Err(scp_protocol::crypto::ucan::UcanError::MalformedToken(
            "NoopDidResolver (actor broadcast handler) — no resolution available".into(),
        ))
    }
}

struct NoopNonceTracker;
impl scp_protocol::crypto::ucan::validate::NonceTracker for NoopNonceTracker {
    fn check_replay(
        &self,
        _nonce: &str,
        _token_expiry: u64,
    ) -> Result<(), scp_protocol::crypto::ucan::UcanError> {
        Ok(())
    }

    fn record(
        &mut self,
        _nonce: &str,
        _token_expiry: u64,
    ) -> Result<(), scp_protocol::crypto::ucan::UcanError> {
        Ok(())
    }
}

struct NoopRevocationChecker;
impl scp_protocol::crypto::ucan::validate::RevocationChecker for NoopRevocationChecker {
    fn is_revoked(&self, _token_cid: &str) -> bool {
        false
    }
}

struct NoopProofResolver;
impl scp_protocol::crypto::ucan::validate::ProofResolver for NoopProofResolver {
    fn resolve_proof(
        &self,
        _proof_cid: &str,
    ) -> Result<scp_protocol::crypto::ucan::UcanToken, scp_protocol::crypto::ucan::UcanError> {
        Err(scp_protocol::crypto::ucan::UcanError::MalformedToken(
            "NoopProofResolver (actor broadcast handler) — no proof resolution".into(),
        ))
    }
}

/// Produce a best-effort clone-equivalent `ContextError` for the
/// handler's [`Outcome`] sink.
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
    const MSG: &str = "BroadcastCommand::Placeholder — real variants migrate in commit 11 of \
                       ADR-049; Placeholder retained for commit-6 compile stability and \
                       deleted in commit 12 with the shim";
    let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
    Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
}

fn reply_saga_deferred(
    reply: oneshot::Sender<Result<crate::context::supervisor::saga_journal::SagaId, ContextError>>,
) -> Outcome<()> {
    const MSG: &str = "broadcast::initiate_broadcast_hosting_handshake — saga wiring deferred \
                       to commit 11.5 per 5 enumerated spec gaps; see \
                       .docs/adrs/DEFERRED-commit-11-saga-use-cases.md (gap 3: broadcast \
                       hosting handshake protocol)";
    let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
    Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
}
