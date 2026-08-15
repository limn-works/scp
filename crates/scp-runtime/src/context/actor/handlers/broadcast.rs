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
//! The publish entry points in `broadcast_helpers` take
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

use std::time::Duration;

use scp_protocol::context::ContextError;
use scp_protocol::crypto::ucan::validate::{
    DEFAULT_CLOCK_SKEW_TOLERANCE_SECS, InMemoryProofResolver, NoCaveatResolver, ValidationContext,
};
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
use crate::context::economy_logic::{ContextRevocationChecker, KeyResolverDidResolver};

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
    }
}

async fn handle_subscribe_broadcast(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    p: SubscribeBroadcastPayload,
    reply: SubscribeBroadcastReply,
) -> Outcome<()> {
    let context_id = p.context_id.clone();

    // Build the real UCAN [`ValidationContext`] the gated-admission arm of
    // [`BroadcastContext::subscribe`] requires (spec §5.14.4: a gated
    // `messages:read` grant MUST be verified with the full validation pipeline,
    // §07:70). This mirrors `saga::validate_ucan_rebind` — the sole other
    // in-actor `ValidationContext` builder — reusing the SAME VM-aware DID→key
    // and per-context revocation adapters so the answer never diverges from the
    // rest of the runtime.
    //
    // Every input is CLONED out of actor-owned state HERE, before the
    // `&mut cell` borrow that `subscribe_broadcast` takes. `ClassSCell` exposes
    // state only through `Deref` to `&PerContextState`; a live shared borrow
    // into `cell` would conflict with the helper's `&mut cell`, so the ceiling /
    // creator / revocation set are all materialised as owned values first.
    let ceiling = cell.role_state.ceiling().to_ucan_string_set();
    let creator_did = cell.role_state.creator_did.clone();
    let revoked = cell.governance.revoked_spending_ucan_cids.clone();
    // Proof resolver: EMPTY, by design. Per spec §5.14.4 a gated `messages:read`
    // grant is issued DIRECTLY by the context admin/creator — a ROOT token
    // (`prf = []`) whose root issuer IS `context_creator_did`. Intra-context
    // DELEGATION of `messages:read` is not a supported path (the subscribe API
    // carries a single token, not a proof bundle, so a subscriber cannot even
    // supply parent proofs), and there is NO intra-context `messages:read`
    // delegation proof store — the only runtime proof store, `xctx_ucan_proofs`,
    // is the CROSS-context outlet-invocation saga store (empty outside an active
    // saga) and holds `outlet_invoke` proofs, NOT read grants. So we deliberately
    // do NOT clone `xctx_ucan_proofs` here (that would risk cross-contaminating a
    // read-grant validation with unrelated outlet proofs). `verify_delegation_chain`
    // no-ops on a root token's empty `prf`, so this empty resolver is never
    // consulted on the supported path; an out-of-spec DELEGATED grant instead
    // fails closed (`DelegationChainBroken`) — the correct rejection.
    let proof_resolver = InMemoryProofResolver::new();
    let did_resolver = KeyResolverDidResolver::new(&deps.key_resolver);
    let revocation_checker = ContextRevocationChecker {
        revoked_cids: &revoked,
    };
    // Per-call fresh (no-op) nonce tracker — the RESOLVED nonce-tracker decision
    // for gated subscribe. A gated `messages:read` grant is issued once by an
    // admin/creator and presented on every (re)subscribe, so its `nnc` timestamp
    // is legitimately stale relative to the §9.14 ±5-minute freshness window a
    // stateful tracker enforces; a freshness/replay tracker would wrongly reject
    // a valid long-lived READ grant (exactly the failure
    // `saga::validate_ucan_rebind` documents for a re-presented delegation proof).
    // The full pipeline (signature, root-issuer, audience, ceiling, revocation,
    // expiry) still runs on the presented token. Replay of a READ grant is
    // defended in DEPTH, not by the nonce tracker:
    //   - a replay by a NON-audience DID is rejected by audience binding (step 5);
    //   - a replay by the audience DID while STILL subscribed is rejected by the
    //     duplicate-subscriber check ("subscriber already registered");
    //   - a replay by a governance-BANNED audience DID (which the duplicate check
    //     can no longer catch, because the ban removed it from the roster) is
    //     rejected by the DURABLE `banned_subscribers` record on the broadcast
    //     context — checked both at the runtime `subscribe_broadcast` admission
    //     gate and structurally inside `BroadcastContext::subscribe`. That record
    //     is authority-only-clearable (`RestoreAccess`) and survives the banned
    //     subject's own self-leave AND a subsequent admin `RemoveMember`, so the
    //     ban cannot be laundered by leaving to clear `read_exclusion_list` and
    //     replaying the retained UCAN (#2088).
    // Note: a read-access ban is enforced via the durable `banned_subscribers`
    // record (and, for a still-present read-revoked member, `read_exclusion_list`
    // as defense-in-depth) — NOT via `revoked_spending_ucan_cids`, which drives
    // the separate spending-UCAN revocation path and is inert for read grants.
    // Spec is silent on subscribe-nonce dedup; a fresh no-op tracker is the sound,
    // documented choice.
    let mut nonce_tracker = NoOpNonceTracker;

    let mut validation_ctx = ValidationContext {
        did_resolver: &did_resolver,
        nonce_tracker: &mut nonce_tracker,
        revocation_checker: &revocation_checker,
        proof_resolver: &proof_resolver,
        ceiling: &ceiling,
        context_creator_did: &creator_did,
        // The `messages:read` grant is issued TO the subscriber, so the
        // subscriber's DID is the audience the pipeline's step-5 check binds
        // against.
        presenting_agent_did: p.subscriber_did.as_ref(),
        clock_skew_tolerance_secs: DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
        clock: deps.clock.as_ref(),
        caveat_resolver: &NoCaveatResolver,
    };

    let subscribe_fut = async {
        crate::context::broadcast_helpers::subscribe_broadcast(
            cell,
            deps,
            &p.context_id,
            &p.subscriber_did,
            p.ucan.as_ref(),
            p.timestamp,
            Some(&mut validation_ctx),
        )
        .await
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
        .await
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
        .await
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
        .await
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
    author_did: &scp_did::DID,
    requester_did: &scp_did::DID,
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
        .await
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
// Per-call no-op nonce tracker for the gated broadcast-subscribe validation
// pipeline.
//
// The DID resolver and revocation checker slots of the gated-subscribe
// [`ValidationContext`] are the REAL runtime adapters (`KeyResolverDidResolver`,
// `ContextRevocationChecker`); the proof resolver is an empty
// `InMemoryProofResolver` because gated `messages:read` grants are admin/creator
// ROOT tokens with no intra-context delegation (see `handle_subscribe_broadcast`).
// Only the nonce-tracker slot is deliberately a no-op: a gated `messages:read`
// grant is a long-lived, admin/creator-issued token whose `nnc` is minted once
// at issuance and re-presented on every (re)subscribe, so a stateful
// freshness/replay tracker would wrongly reject it (`NonceTooOld`). Replay of a
// READ grant is defended in DEPTH elsewhere, NOT by the nonce tracker: a
// non-audience replay by audience binding, an audience replay while still
// subscribed by the duplicate-subscriber reject, and a replay by a
// governance-BANNED audience DID by the durable `banned_subscribers` record
// (authority-only-clearable, survives self-leave and admin-remove; enforced at
// the `subscribe_broadcast` gate and structurally in `BroadcastContext::subscribe`
// — #2088). This is the SAME accepted production pattern
// `saga::validate_ucan_rebind` uses for a re-presented delegation proof (and
// which its comment cross-references by this name).
// ---------------------------------------------------------------------------

struct NoOpNonceTracker;
impl scp_protocol::crypto::ucan::validate::NonceTracker for NoOpNonceTracker {
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

// ---------------------------------------------------------------------------
// Gated broadcast-subscribe validation tests (spec §5.14.4, §07:70).
//
// These drive the REAL actor handler `handle_subscribe_broadcast` against a
// gated broadcast context, exercising `validate_messages_read_ucan` through the
// full runtime UCAN validation pipeline for the first time (previously the
// handler passed `None` for the validation context, so the protocol rejected
// every gated subscribe on the missing-UCAN check before validation ran — the
// capability was unreachable). A valid admin-issued `messages:read` UCAN must
// let the subscribe succeed; an absent, wrong-signer, or wrong-audience token
// must be rejected.
// ---------------------------------------------------------------------------
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::{Signer, SigningKey};
    use scp_did::{DID, SigningKeyId};
    use scp_protocol::context::broadcast::{BroadcastAdmission, BroadcastContext};
    use scp_protocol::context::params::ContextMode;
    use scp_protocol::context::roles::{Capability, CapabilityCeiling, ContextRoleState};
    use scp_protocol::crypto::ucan::{Attenuation, UcanHeader, UcanPayload, UcanToken};
    use tokio::sync::oneshot;

    use super::*;
    use crate::context::ContextState;
    use crate::context::actor::commands::SubscribeBroadcastPayload;
    use crate::context::actor::state::PerContextState;

    const CREATOR_DID: &str = "did:example:broadcast-creator";
    const SUBSCRIBER_DID: &str = "did:example:broadcast-subscriber";
    /// A context MEMBER who holds a valid `messages:read` grant but never called
    /// subscribe (e.g. the creator, or a member added via join) — the #2088
    /// Finding-1 target.
    const LURKER_DID: &str = "did:example:broadcast-lurker";

    /// Deterministic creator (context admin / UCAN issuer) signing key.
    fn creator_key() -> SigningKey {
        SigningKey::from_bytes(&[0x11; 32])
    }

    /// A different key an attacker might sign a forged token with.
    fn attacker_key() -> SigningKey {
        SigningKey::from_bytes(&[0x99; 32])
    }

    // Recording event log — counts every appended leaf so a test can assert
    // that a REJECTED subscribe appends NO `MemberJoined` leaf. The membership
    // leaf append routes through the trait default
    // `append_membership_change_leaf` → `append_context_event_with_payload` →
    // `append_event`, so counting `append_event` counts the leaf. The other
    // methods just need to succeed; the rest of the trait uses its default impls.
    struct TestEventLog {
        appended: Arc<AtomicUsize>,
    }
    #[async_trait::async_trait]
    impl crate::context::builder::ContextEventLogProvider for TestEventLog {
        async fn init_event_log(
            &self,
            _id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
        async fn append_event(
            &self,
            _id: &[u8; 32],
            _event: scp_event_log::EventType,
            _actor: &str,
            _payload: scp_event_log::EventPayload,
            _timestamp_secs: u64,
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            self.appended.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn destroy_event_log(
            &self,
            _id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
    }

    struct TestPersistence;
    #[async_trait::async_trait]
    impl crate::context::persistence::ContextPersistence for TestPersistence {
        async fn persist_context(
            &self,
            _: &str,
            _: &crate::context::state::ContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
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

    /// Build an `ActorDeps` whose `key_resolver` resolves the creator DID's
    /// `#active` verification key — so a UCAN issued by the creator passes
    /// signature + root-issuer verification, and anything else fails. Returns the
    /// deps plus the shared event-log append counter (number of leaves appended),
    /// so a test can assert that a rejected subscribe appends none.
    async fn build_deps() -> (ActorDeps, Arc<AtomicUsize>) {
        use crate::context::supervisor::supervisor::Supervisor;
        use scp_platform::in_memory::InMemoryStorage;

        let creator_vk = creator_key().verifying_key();
        let key_resolver: scp_protocol::context::governance::KeyResolver =
            Arc::new(move |did: &DID, kid: SigningKeyId| {
                if did.as_ref() == CREATOR_DID && kid == SigningKeyId::Active {
                    Some(creator_vk)
                } else {
                    None
                }
            });

        let crypto = Arc::new(crate::crypto::mls::provider::NodeMlsFactory::new(
            "did:example:broadcast-actor".to_owned(),
            Arc::new(scp_clock::SystemClock),
        ));
        let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
            Box::new(crate::context::builder::NotConfiguredTransportProvider);
        let appended = Arc::new(AtomicUsize::new(0));
        let event_log: Box<dyn crate::context::builder::ContextEventLogProvider> =
            Box::new(TestEventLog {
                appended: Arc::clone(&appended),
            });
        let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
            Arc::new(
                crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
                    InMemoryStorage::new(),
                )),
            );

        let supervisor = Supervisor::with_providers(
            crypto,
            transport,
            event_log,
            key_resolver,
            Some(Box::new(TestPersistence)),
            None,
            None,
            None,
            mls_storage,
        );
        let deps = supervisor
            .build_actor_deps(&DID("did:example:broadcast-actor".to_owned()))
            .await
            .expect("build_actor_deps");
        (deps, appended)
    }

    /// Build an ACTIVE broadcast `ClassSCell` with the given admission policy,
    /// creator [`CREATOR_DID`], and a ceiling admitting `messages:read` +
    /// `member:ban`. Returns the cell and the hex context id (used to scope the
    /// UCAN capability).
    fn build_broadcast_cell(admission: BroadcastAdmission) -> (ClassSCell, String) {
        build_broadcast_cell_with_authors(admission, &[])
    }

    /// Like [`build_broadcast_cell`] but also registers `authors` in the broadcast
    /// context (matching production, where the creator is always an author) — used
    /// by the serve-path BLACK-303 tests.
    fn build_broadcast_cell_with_authors(
        admission: BroadcastAdmission,
        authors: &[&str],
    ) -> (ClassSCell, String) {
        let ctx_bytes = [0x5b; 32];
        let mut state = PerContextState::new_for_test_broadcast(
            ctx_bytes,
            1_700_000_000_000,
            DID(CREATOR_DID.to_owned()),
        );
        let ctx_hex = state.handle.context_id().to_owned();

        // `MemberBan` is in the ceiling so `execute_revoke` (which requires it)
        // can drive the durable-ban attack tests (#2088).
        let ceiling = CapabilityCeiling::new([
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::MemberBan,
        ]);
        state.role_state = ContextRoleState::new(
            ctx_hex.clone(),
            CREATOR_DID,
            ceiling,
            vec![],
            &scp_clock::SystemClock,
        )
        .expect("role state");
        let mut bc = BroadcastContext::new(ctx_hex.clone(), &ContextMode::Broadcast, admission)
            .expect("broadcast context");
        for author in authors {
            bc.add_author(author).expect("add_author");
        }
        state.broadcast_context = Some(bc);
        // Seed the admin (creator) as a member so the context does not auto-close
        // when the single test subscriber/member later self-leaves (the last
        // member leaving closes the context — an artifact that would mask the ban
        // gate).
        state
            .membership
            .add_member(DID(CREATOR_DID.to_owned()), "admin".to_owned(), vec![]);
        state
            .handle
            .transition_to(&ContextState::Active)
            .expect("activate");

        (ClassSCell::new(state), ctx_hex)
    }

    /// Convenience: an ACTIVE, GATED broadcast cell.
    fn build_gated_cell() -> (ClassSCell, String) {
        build_broadcast_cell(BroadcastAdmission::Gated)
    }

    /// Mint a `messages:read` UCAN scoped to `ctx_hex`, issued by `issuer_did`
    /// to audience `aud_did`, signed by `signing_key`.
    fn mint_read_ucan(
        ctx_hex: &str,
        issuer_did: &str,
        aud_did: &str,
        signing_key: &SigningKey,
    ) -> UcanToken {
        let now_secs = scp_clock::Clock::now_secs(&scp_clock::SystemClock);
        let now_millis = scp_clock::Clock::now_millis(&scp_clock::SystemClock);

        let header = UcanHeader::new();
        let payload = UcanPayload {
            iss: issuer_did.to_owned(),
            aud: aud_did.to_owned(),
            exp: now_secs + 3600,
            nbf: Some(now_secs - 60),
            nnc: format!("{now_millis}-aabbccdd11223344aabbccdd11223344"),
            att: vec![Attenuation {
                with: format!("scp:ctx:{ctx_hex}/messages:read"),
                can: "read".to_owned(),
            }],
            prf: vec![],
            fct: None,
            nb: None,
        };

        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = signing_key.sign(signing_input.as_bytes());
        let sig_bytes = signature.to_bytes().to_vec();
        let encoded = format!(
            "{header_b64}.{payload_b64}.{}",
            URL_SAFE_NO_PAD.encode(&sig_bytes)
        );

        UcanToken {
            header,
            payload,
            signature: sig_bytes,
            encoded,
        }
    }

    async fn dispatch_subscribe(
        cell: &mut ClassSCell,
        deps: &ActorDeps,
        ctx_hex: &str,
        ucan: Option<UcanToken>,
    ) -> Result<(), ContextError> {
        dispatch_subscribe_as(cell, deps, ctx_hex, SUBSCRIBER_DID, ucan).await
    }

    /// Drive `handle_subscribe_broadcast` for an arbitrary subscriber DID.
    async fn dispatch_subscribe_as(
        cell: &mut ClassSCell,
        deps: &ActorDeps,
        ctx_hex: &str,
        subscriber_did: &str,
        ucan: Option<UcanToken>,
    ) -> Result<(), ContextError> {
        let (tx, rx) = oneshot::channel();
        let payload = SubscribeBroadcastPayload {
            context_id: ctx_hex.to_owned(),
            subscriber_did: DID(subscriber_did.to_owned()),
            ucan,
            timestamp: 1_700_000_000,
        };
        let _outcome = handle_subscribe_broadcast(cell, deps, payload, tx).await;
        rx.await.expect("reply delivered").map(|_| ())
    }

    #[tokio::test]
    async fn gated_subscribe_with_valid_ucan_succeeds() {
        let (deps, _appends) = build_deps().await;
        let (mut cell, ctx_hex) = build_gated_cell();
        let ucan = mint_read_ucan(&ctx_hex, CREATOR_DID, SUBSCRIBER_DID, &creator_key());

        let result = dispatch_subscribe(&mut cell, &deps, &ctx_hex, Some(ucan)).await;

        assert!(
            result.is_ok(),
            "gated subscribe with a valid admin-issued messages:read UCAN must \
             succeed, got: {result:?}"
        );
        assert!(
            crate::context::broadcast_helpers::is_broadcast_subscriber(&mut cell, SUBSCRIBER_DID),
            "the subscriber must be registered on the roster after a successful \
             gated subscribe"
        );
    }

    #[tokio::test]
    async fn gated_subscribe_without_ucan_is_rejected() {
        let (deps, _appends) = build_deps().await;
        let (mut cell, ctx_hex) = build_gated_cell();

        let result = dispatch_subscribe(&mut cell, &deps, &ctx_hex, None).await;

        assert!(
            matches!(result, Err(ContextError::PermissionDenied(_))),
            "gated subscribe without a UCAN must be PermissionDenied, got: {result:?}"
        );
        assert!(
            !crate::context::broadcast_helpers::is_broadcast_subscriber(&mut cell, SUBSCRIBER_DID),
            "a rejected gated subscribe must NOT register the subscriber"
        );
    }

    #[tokio::test]
    async fn gated_subscribe_with_wrong_signer_is_rejected() {
        let (deps, _appends) = build_deps().await;
        let (mut cell, ctx_hex) = build_gated_cell();
        // Token claims the creator as issuer but is signed by the attacker key;
        // signature verification against the resolved creator key fails.
        let forged = mint_read_ucan(&ctx_hex, CREATOR_DID, SUBSCRIBER_DID, &attacker_key());

        let result = dispatch_subscribe(&mut cell, &deps, &ctx_hex, Some(forged)).await;

        assert!(
            result.is_err(),
            "a messages:read UCAN not signed by the context creator must be \
             rejected, got: {result:?}"
        );
        assert!(
            !crate::context::broadcast_helpers::is_broadcast_subscriber(&mut cell, SUBSCRIBER_DID),
            "a rejected gated subscribe must NOT register the subscriber"
        );
    }

    #[tokio::test]
    async fn gated_subscribe_with_wrong_audience_is_rejected() {
        let (deps, _appends) = build_deps().await;
        let (mut cell, ctx_hex) = build_gated_cell();
        // Validly signed by the creator, but issued to a DIFFERENT audience —
        // the presenting subscriber is not the token's audience, so step-5
        // audience binding rejects it (a confused-deputy defense).
        let misaudienced = mint_read_ucan(
            &ctx_hex,
            CREATOR_DID,
            "did:example:someone-else",
            &creator_key(),
        );

        let result = dispatch_subscribe(&mut cell, &deps, &ctx_hex, Some(misaudienced)).await;

        assert!(
            result.is_err(),
            "a messages:read UCAN whose audience is not the presenting subscriber \
             must be rejected, got: {result:?}"
        );
        assert!(
            !crate::context::broadcast_helpers::is_broadcast_subscriber(&mut cell, SUBSCRIBER_DID),
            "a rejected gated subscribe must NOT register the subscriber"
        );
    }

    /// B2 primary security fix: a governance-banned / read-revoked subscriber
    /// must NOT be able to replay its still-valid `messages:read` grant to
    /// re-appear on the roster (spec §5.14.4). The ban removes the DID from the
    /// subscriber roster and inserts it into `read_exclusion_list` (but does NOT
    /// touch `revoked_spending_ucan_cids`), so without the admission gate the
    /// replay would sail through: the duplicate-subscriber reject can't fire (the
    /// ban removed it) and the UCAN still passes every crypto step. The
    /// `read_exclusion_list` gate in `subscribe_broadcast` closes this.
    #[tokio::test]
    async fn banned_subscriber_cannot_replay_valid_ucan() {
        let (deps, appends) = build_deps().await;
        let (mut cell, ctx_hex) = build_gated_cell();

        // (1) M subscribes with a valid admin-issued grant → succeeds, on roster,
        //     one MemberJoined leaf appended.
        let grant = mint_read_ucan(&ctx_hex, CREATOR_DID, SUBSCRIBER_DID, &creator_key());
        let first = dispatch_subscribe(&mut cell, &deps, &ctx_hex, Some(grant)).await;
        assert!(
            first.is_ok(),
            "initial gated subscribe must succeed: {first:?}"
        );
        assert!(
            crate::context::broadcast_helpers::is_broadcast_subscriber(&mut cell, SUBSCRIBER_DID),
            "M must be on the roster after the initial subscribe"
        );
        let appends_after_join = appends.load(Ordering::SeqCst);
        assert_eq!(
            appends_after_join, 1,
            "the successful subscribe must append exactly one MemberJoined leaf"
        );

        // (2) Governance bans M's read access: the authoritative effect is
        //     inserting M into `read_exclusion_list` AND removing M from the
        //     roster (so the duplicate-subscriber check can no longer catch a
        //     replay). Reproduce both here.
        let m_did = DID(SUBSCRIBER_DID.to_owned());
        cell.class_c_view()
            .access_mut()
            .read_exclusion_list
            .insert(m_did.clone());
        crate::context::broadcast_helpers::unsubscribe_broadcast(
            &mut cell, &deps, &ctx_hex, &m_did, true,
        )
        .await
        .expect("ban removes M from the roster");
        assert!(
            !crate::context::broadcast_helpers::is_broadcast_subscriber(&mut cell, SUBSCRIBER_DID),
            "the ban must remove M from the roster"
        );
        let appends_after_ban = appends.load(Ordering::SeqCst);

        // (3) M replays the SAME still-valid grant → REJECTED at admission with
        //     the uniform reason, NO roster entry, NO new MemberJoined leaf.
        let replay = mint_read_ucan(&ctx_hex, CREATOR_DID, SUBSCRIBER_DID, &creator_key());
        let result = dispatch_subscribe(&mut cell, &deps, &ctx_hex, Some(replay)).await;
        match result {
            Err(ContextError::PermissionDenied(msg)) => {
                assert_eq!(
                    msg,
                    scp_protocol::context::broadcast::SUBSCRIBE_DENY_REASON,
                    "the banned-replay rejection must use the uniform deny reason"
                );
            }
            other => panic!("banned replay must be PermissionDenied, got: {other:?}"),
        }
        assert!(
            !crate::context::broadcast_helpers::is_broadcast_subscriber(&mut cell, SUBSCRIBER_DID),
            "a banned DID must NOT re-appear on the roster after replaying its grant"
        );
        assert_eq!(
            appends.load(Ordering::SeqCst),
            appends_after_ban,
            "a rejected banned replay must append NO new MemberJoined leaf"
        );
    }

    /// Uniform deny-reason constant for the ban admission rejection.
    fn subscribe_deny_reason() -> &'static str {
        scp_protocol::context::broadcast::SUBSCRIBE_DENY_REASON
    }

    fn commit_meta(pid_byte: u8) -> crate::context::governance_helpers::CommitMeta<'static> {
        crate::context::governance_helpers::CommitMeta {
            pid: [pid_byte; 32],
            actor_did: CREATOR_DID,
            timestamp_secs: 1_700_000_000,
        }
    }

    /// #1 EXACT ATTACK (the regression test): a read-banned member cannot launder
    /// the ban by self-leaving (which clears the membership-scoped
    /// `read_exclusion_list`) and replaying a retained `messages:read` UCAN. The
    /// durable `banned_subscribers` record survives the self-leave, so the replay
    /// is rejected at admission — no roster entry, no `MemberJoined` leaf, and M
    /// is not a member (#2088).
    #[tokio::test]
    async fn banned_member_cannot_launder_ban_via_self_leave() {
        use scp_protocol::context::governance::AccessScope;

        let (deps, appends) = build_deps().await;
        let (mut cell, ctx_hex) = build_gated_cell();
        let m = DID(SUBSCRIBER_DID.to_owned());

        // (a) M subscribes with a valid admin-issued grant → roster + membership.
        let grant = mint_read_ucan(&ctx_hex, CREATOR_DID, SUBSCRIBER_DID, &creator_key());
        dispatch_subscribe(&mut cell, &deps, &ctx_hex, Some(grant))
            .await
            .expect("initial subscribe must succeed");
        assert!(cell.membership.contains(SUBSCRIBER_DID));

        // (b) Governance RevokeAccess{M, Read}: durably bans M and writes
        // read_exclusion_list.
        crate::context::governance_helpers::execute_revoke(
            &mut cell,
            &deps,
            &ctx_hex,
            &m,
            AccessScope::Read,
            commit_meta(0x91),
        )
        .await
        .expect("revoke read access");
        assert!(
            cell.broadcast_context
                .as_ref()
                .is_some_and(|bc| bc.is_banned(SUBSCRIBER_DID)),
            "RevokeAccess{{Read}} must record a durable ban"
        );

        // (c) M self-leaves (needs no capability) — clears the membership-scoped
        // read_exclusion_list, the laundering vector.
        let handle = cell.handle.clone();
        crate::context::lifecycle_helpers::leave_context(&mut cell, &deps, &handle, &m, &m)
            .await
            .expect("self-leave");
        assert!(
            !cell.access.read_exclusion_list.contains(&m),
            "self-leave must clear read_exclusion_list (the laundering vector)"
        );
        assert!(
            cell.broadcast_context
                .as_ref()
                .is_some_and(|bc| bc.is_banned(SUBSCRIBER_DID)),
            "the durable ban MUST survive the banned subject's own self-leave"
        );
        assert!(
            !cell.membership.contains(SUBSCRIBER_DID),
            "M is no longer a member after leaving"
        );

        let count_before_replay =
            crate::context::broadcast_helpers::broadcast_subscriber_count(&mut cell);
        let appends_before_replay = appends.load(Ordering::SeqCst);

        // (d) M replays the SAME still-valid grant → REJECTED at admission.
        let replay = mint_read_ucan(&ctx_hex, CREATOR_DID, SUBSCRIBER_DID, &creator_key());
        let result = dispatch_subscribe(&mut cell, &deps, &ctx_hex, Some(replay)).await;
        match result {
            Err(ContextError::PermissionDenied(msg)) => {
                assert_eq!(msg, subscribe_deny_reason());
            }
            other => panic!("banned-replay-after-leave must be PermissionDenied, got: {other:?}"),
        }
        assert!(
            !crate::context::broadcast_helpers::is_broadcast_subscriber(&mut cell, SUBSCRIBER_DID),
            "a laundered replay must NOT re-add M to the roster"
        );
        assert!(
            !cell.membership.contains(SUBSCRIBER_DID),
            "a laundered replay must NOT re-add M to membership"
        );
        assert_eq!(
            crate::context::broadcast_helpers::broadcast_subscriber_count(&mut cell),
            count_before_replay,
            "subscriber_count must be unchanged by the rejected replay"
        );
        assert_eq!(
            appends.load(Ordering::SeqCst),
            appends_before_replay,
            "the rejected replay must append NO MemberJoined leaf for M"
        );
    }

    /// #6 NO OVER-EVICTION (§5.9): `RevokeAccess{Read}` on a member suspends ONLY
    /// `messages:read` and leaves the member in the context — it does not strip
    /// membership or suspend any other capability (a read-revoked member stays a
    /// member; stripping would over-evict).
    #[tokio::test]
    async fn read_revoke_does_not_over_evict_member() {
        use scp_protocol::context::governance::AccessScope;

        let (deps, _appends) = build_deps().await;
        let (mut cell, ctx_hex) = build_gated_cell();
        let m = DID(SUBSCRIBER_DID.to_owned());

        let grant = mint_read_ucan(&ctx_hex, CREATOR_DID, SUBSCRIBER_DID, &creator_key());
        dispatch_subscribe(&mut cell, &deps, &ctx_hex, Some(grant))
            .await
            .expect("subscribe");

        crate::context::governance_helpers::execute_revoke(
            &mut cell,
            &deps,
            &ctx_hex,
            &m,
            AccessScope::Read,
            commit_meta(0x92),
        )
        .await
        .expect("revoke read access");

        assert!(
            cell.membership.contains(SUBSCRIBER_DID),
            "a read-revoked member MUST remain a member (§5.9 — no over-eviction)"
        );
        let suspended = cell.role_state.suspended_for(SUBSCRIBER_DID);
        assert!(
            suspended.is_some_and(|s| s.contains(&Capability::MessagesRead)),
            "messages:read must be suspended after RevokeAccess{{Read}}"
        );
        assert!(
            suspended.is_some_and(|s| s.len() == 1),
            "ONLY messages:read may be suspended — any other held capability \
             (e.g. governance:vote) MUST be untouched (§5.9)"
        );
    }

    /// #2 DURABLE BAN IS THE SOLE DEFENSE AFTER TEARDOWN HYGIENE. Both membership
    /// teardown paths — self-leave (`leave_context`, test #1) and admin-remove
    /// (`execute_remove_member`) — clear the membership-scoped `read_exclusion_list`
    /// for §5.6.1/§5.9 hygiene but do NOT touch `banned_subscribers`. This test
    /// ISOLATES the durable ban as the sole remaining defense: it bans M, then
    /// clears `read_exclusion_list` (the exact effect that teardown has on the
    /// ban-relevant state — reproduced directly because `execute_remove_member`
    /// unconditionally does an MLS-group removal that a broadcast context, whose
    /// subscribers are not MLS members, does not support), and asserts the replay
    /// is STILL rejected purely by the durable `banned_subscribers` record (#2088).
    #[tokio::test]
    async fn durable_ban_alone_rejects_replay_after_read_exclusion_cleared() {
        use scp_protocol::context::governance::AccessScope;

        let (deps, _appends) = build_deps().await;
        let (mut cell, ctx_hex) = build_gated_cell();
        let m = DID(SUBSCRIBER_DID.to_owned());

        let grant = mint_read_ucan(&ctx_hex, CREATOR_DID, SUBSCRIBER_DID, &creator_key());
        dispatch_subscribe(&mut cell, &deps, &ctx_hex, Some(grant))
            .await
            .expect("subscribe");

        // Ban via RevokeAccess{Read}.
        crate::context::governance_helpers::execute_revoke(
            &mut cell,
            &deps,
            &ctx_hex,
            &m,
            AccessScope::Read,
            commit_meta(0x93),
        )
        .await
        .expect("revoke read access");

        // Reproduce the membership-teardown hygiene that BOTH self-leave and
        // admin-remove apply: drop the DID from `read_exclusion_list`. The durable
        // ban is deliberately left untouched (no teardown path clears it).
        cell.class_c_view()
            .access_mut()
            .read_exclusion_list
            .remove(&m);
        assert!(
            !cell.access.read_exclusion_list.contains(&m),
            "the read_exclusion_list defense-in-depth is now cleared"
        );
        assert!(
            cell.broadcast_context
                .as_ref()
                .is_some_and(|bc| bc.is_banned(SUBSCRIBER_DID)),
            "the durable ban MUST survive the teardown that clears read_exclusion_list"
        );

        // Replay with read_exclusion_list cleared → STILL rejected, purely by the
        // durable ban record.
        let replay = mint_read_ucan(&ctx_hex, CREATOR_DID, SUBSCRIBER_DID, &creator_key());
        let result = dispatch_subscribe(&mut cell, &deps, &ctx_hex, Some(replay)).await;
        match result {
            Err(ContextError::PermissionDenied(msg)) => {
                assert_eq!(msg, subscribe_deny_reason());
            }
            other => panic!(
                "durable ban alone must reject the replay after read_exclusion_list \
                 is cleared, got: {other:?}"
            ),
        }
        assert!(
            !crate::context::broadcast_helpers::is_broadcast_subscriber(&mut cell, SUBSCRIBER_DID),
            "a banned DID must NOT re-appear on the roster via the durable-ban gate alone"
        );
    }

    /// #2088 Finding 1: a read-revoked MEMBER who never subscribed (holds a valid
    /// retained `messages:read` grant) must ALSO be durably banned — the ban is
    /// recorded by `RevokeAccess{Read}` despite non-subscription, survives the
    /// member's self-leave, and rejects the replay. Without the fix the member
    /// gets only the self-clearable `read_exclusion_list` and launders the ban.
    #[tokio::test]
    async fn member_not_subscriber_cannot_launder_ban() {
        use scp_protocol::context::governance::AccessScope;

        let (deps, appends) = build_deps().await;
        let (mut cell, ctx_hex) = build_gated_cell();
        let lurker = DID(LURKER_DID.to_owned());

        // Lurker is a MEMBER but NOT a broadcast subscriber.
        cell.class_c_view().membership_class_c_mut().add_member(
            lurker.clone(),
            "member".to_owned(),
            vec![],
        );
        assert!(cell.membership.contains(LURKER_DID));
        assert!(
            !crate::context::broadcast_helpers::is_broadcast_subscriber(&mut cell, LURKER_DID),
            "precondition: lurker never subscribed"
        );

        // RevokeAccess{Read} MUST record the durable ban despite non-subscription.
        crate::context::governance_helpers::execute_revoke(
            &mut cell,
            &deps,
            &ctx_hex,
            &lurker,
            AccessScope::Read,
            commit_meta(0x95),
        )
        .await
        .expect("revoke read access on a member-not-subscriber");
        assert!(
            cell.broadcast_context
                .as_ref()
                .is_some_and(|bc| bc.is_banned(LURKER_DID)),
            "the durable ban MUST be recorded even though the DID was never a subscriber (#2088 Finding 1)"
        );

        // Self-leave clears read_exclusion_list; the durable ban survives.
        let handle = cell.handle.clone();
        crate::context::lifecycle_helpers::leave_context(
            &mut cell, &deps, &handle, &lurker, &lurker,
        )
        .await
        .expect("self-leave");
        assert!(
            !cell.access.read_exclusion_list.contains(&lurker),
            "self-leave clears the membership-scoped read_exclusion_list"
        );
        assert!(
            cell.broadcast_context
                .as_ref()
                .is_some_and(|bc| bc.is_banned(LURKER_DID)),
            "the durable ban MUST survive the member's self-leave"
        );

        let appends_before = appends.load(Ordering::SeqCst);

        // Replay the retained grant → REJECTED at admission by the durable ban.
        let grant = mint_read_ucan(&ctx_hex, CREATOR_DID, LURKER_DID, &creator_key());
        let result =
            dispatch_subscribe_as(&mut cell, &deps, &ctx_hex, LURKER_DID, Some(grant)).await;
        match result {
            Err(ContextError::PermissionDenied(msg)) => assert_eq!(msg, subscribe_deny_reason()),
            other => panic!(
                "member-not-subscriber replay-after-leave must be PermissionDenied, got: {other:?}"
            ),
        }
        assert!(
            !crate::context::broadcast_helpers::is_broadcast_subscriber(&mut cell, LURKER_DID),
            "no roster entry for the rejected replay"
        );
        assert_eq!(
            appends.load(Ordering::SeqCst),
            appends_before,
            "no MemberJoined leaf for the rejected replay"
        );
    }

    /// #2088 Finding 1 (OPEN variant): on an OPEN broadcast no UCAN is required to
    /// subscribe — so the durable ban is the SOLE gate. A read-revoked
    /// member-not-subscriber who self-leaves still cannot subscribe (even with no
    /// UCAN) because the durable ban rejects them.
    #[tokio::test]
    async fn open_broadcast_banned_member_cannot_subscribe_without_ucan() {
        use scp_protocol::context::governance::AccessScope;

        let (deps, _appends) = build_deps().await;
        let (mut cell, ctx_hex) = build_broadcast_cell(BroadcastAdmission::Open);
        let lurker = DID(LURKER_DID.to_owned());

        cell.class_c_view().membership_class_c_mut().add_member(
            lurker.clone(),
            "member".to_owned(),
            vec![],
        );

        crate::context::governance_helpers::execute_revoke(
            &mut cell,
            &deps,
            &ctx_hex,
            &lurker,
            AccessScope::Read,
            commit_meta(0x96),
        )
        .await
        .expect("revoke read access");
        assert!(
            cell.broadcast_context
                .as_ref()
                .is_some_and(|bc| bc.is_banned(LURKER_DID))
        );

        let handle = cell.handle.clone();
        crate::context::lifecycle_helpers::leave_context(
            &mut cell, &deps, &handle, &lurker, &lurker,
        )
        .await
        .expect("self-leave");

        // Open broadcast: subscribe with NO UCAN — still rejected because banned.
        let result = dispatch_subscribe_as(&mut cell, &deps, &ctx_hex, LURKER_DID, None).await;
        match result {
            Err(ContextError::PermissionDenied(msg)) => assert_eq!(msg, subscribe_deny_reason()),
            other => {
                panic!("open-broadcast banned subscribe (no UCAN) must be rejected, got: {other:?}")
            }
        }
        assert!(!crate::context::broadcast_helpers::is_broadcast_subscriber(
            &mut cell, LURKER_DID
        ));
    }

    /// #2088 Finding 2: the durable ban is truly AUTHORITY-CLEARABLE, not
    /// permanent. After a banned subscriber self-leaves (which wipes both role
    /// suspension AND `read_exclusion_list` — the two signals the restore guard
    /// checked), an authority `RestoreAccess{[MessagesRead]}` MUST still reach
    /// `governance_unban_subscriber`, clear the durable ban, and let the DID
    /// re-subscribe. Without the fix the restore short-circuits `NothingToRestore`
    /// and the ban is permanent with no recovery.
    #[tokio::test]
    async fn authority_restore_access_clears_ban_after_leave() {
        use scp_protocol::context::governance::AccessScope;
        use scp_protocol::context::roles::Capability;

        let (deps, appends) = build_deps().await;
        let (mut cell, ctx_hex) = build_gated_cell();
        let m = DID(SUBSCRIBER_DID.to_owned());

        // M subscribes → ban → self-leave (durable ban survives, suspension +
        // read_exclusion cleared).
        let grant = mint_read_ucan(&ctx_hex, CREATOR_DID, SUBSCRIBER_DID, &creator_key());
        dispatch_subscribe(&mut cell, &deps, &ctx_hex, Some(grant))
            .await
            .expect("subscribe");
        crate::context::governance_helpers::execute_revoke(
            &mut cell,
            &deps,
            &ctx_hex,
            &m,
            AccessScope::Read,
            commit_meta(0x97),
        )
        .await
        .expect("revoke");
        let handle = cell.handle.clone();
        crate::context::lifecycle_helpers::leave_context(&mut cell, &deps, &handle, &m, &m)
            .await
            .expect("self-leave");
        assert!(
            cell.broadcast_context
                .as_ref()
                .is_some_and(|bc| bc.is_banned(SUBSCRIBER_DID)),
            "the durable ban survives the leave"
        );

        // Authority RestoreAccess{[MessagesRead]} — must NOT short-circuit
        // NothingToRestore, and must clear the durable ban.
        crate::context::governance_helpers::execute_restore_access(
            &mut cell,
            &deps,
            &ctx_hex,
            &m,
            &[Capability::MessagesRead],
            commit_meta(0x98),
        )
        .await
        .expect(
            "RestoreAccess must succeed after a leave (Finding 2) — the ban is authority-clearable",
        );
        assert!(
            !cell
                .broadcast_context
                .as_ref()
                .unwrap()
                .is_banned(SUBSCRIBER_DID),
            "RestoreAccess MUST clear the durable ban (not permanent)"
        );

        // The un-banned DID can re-subscribe with a fresh grant, emitting a
        // MemberJoined leaf.
        let appends_before = appends.load(Ordering::SeqCst);
        let regrant = mint_read_ucan(&ctx_hex, CREATOR_DID, SUBSCRIBER_DID, &creator_key());
        dispatch_subscribe(&mut cell, &deps, &ctx_hex, Some(regrant))
            .await
            .expect("re-subscribe after RestoreAccess must succeed");
        assert!(
            crate::context::broadcast_helpers::is_broadcast_subscriber(&mut cell, SUBSCRIBER_DID),
            "the un-banned DID is re-subscribed"
        );
        assert_eq!(
            appends.load(Ordering::SeqCst),
            appends_before + 1,
            "the successful re-subscribe emits exactly one MemberJoined leaf"
        );
    }

    /// BLACK-303 (serve-path laundering): a read-banned AUTHOR (the context
    /// creator is always an author) is not on any block list (a non-subscriber
    /// ban writes none) and, after self-leaving, is no longer in
    /// `read_exclusion_list` — yet remains an author. The broadcast KEY-REQUEST
    /// SERVE path must consult the durable ban and DENY, so the banned author
    /// cannot obtain a broadcast key to decrypt content until authority
    /// `RestoreAccess`.
    #[tokio::test]
    async fn banned_author_cannot_launder_ban_via_serve_path() {
        use scp_protocol::context::broadcast::{KEY_REQUEST_DENY_REASON, KeyRequestDecision};
        use scp_protocol::context::governance::AccessScope;

        let (deps, _appends) = build_deps().await;
        // The creator is registered as an author (production: `add_author(creator)`
        // at creation).
        let (mut cell, ctx_hex) =
            build_broadcast_cell_with_authors(BroadcastAdmission::Gated, &[CREATOR_DID]);
        let creator = DID(CREATOR_DID.to_owned());

        // A keeper member so the context does not empty out when the creator leaves.
        cell.class_c_view().membership_class_c_mut().add_member(
            DID("did:example:keeper".to_owned()),
            "member".to_owned(),
            vec![],
        );
        // The local node controls the creator's author DID (serves its key).
        deps.local_dids
            .store(std::sync::Arc::new(std::collections::HashSet::from([
                creator.clone(),
            ])));

        // Baseline: BEFORE the ban, the creator (an author) IS granted a key —
        // proving the ban is what flips the outcome, not some other check.
        let secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let pubkey = x25519_dalek::PublicKey::from(&secret).to_bytes();
        assert!(
            matches!(
                crate::context::broadcast_helpers::handle_broadcast_key_request(
                    &mut cell, &deps, &creator, &creator, &pubkey,
                )
                .expect("serve decision"),
                KeyRequestDecision::Grant { .. }
            ),
            "precondition: an un-banned author is granted a broadcast key"
        );

        // Governance bans the creator (an author, never a subscriber → durable ban
        // recorded, NO block-list entry).
        crate::context::governance_helpers::execute_revoke(
            &mut cell,
            &deps,
            &ctx_hex,
            &creator,
            AccessScope::Read,
            commit_meta(0x9a),
        )
        .await
        .expect("revoke read access on the creator-author");
        assert!(
            cell.broadcast_context
                .as_ref()
                .is_some_and(|bc| bc.is_banned(CREATOR_DID))
        );

        // Creator self-leaves → read_exclusion_list cleared, authorship survives,
        // durable ban survives.
        let handle = cell.handle.clone();
        crate::context::lifecycle_helpers::leave_context(
            &mut cell, &deps, &handle, &creator, &creator,
        )
        .await
        .expect("self-leave");
        assert!(
            !cell.access.read_exclusion_list.contains(&creator),
            "self-leave clears read_exclusion_list (the laundering vector)"
        );
        assert!(
            cell.broadcast_context
                .as_ref()
                .is_some_and(|bc| bc.is_banned(CREATOR_DID)),
            "the durable ban survives the self-leave — is_banned throughout"
        );

        // Serve path: the banned author requests a broadcast key → DENIED.
        let decision = crate::context::broadcast_helpers::handle_broadcast_key_request(
            &mut cell, &deps, &creator, &creator, &pubkey,
        )
        .expect("serve decision");
        match decision {
            KeyRequestDecision::Deny { reason } => assert_eq!(reason, KEY_REQUEST_DENY_REASON),
            KeyRequestDecision::Grant { .. } => {
                panic!(
                    "a banned author MUST be DENIED a broadcast key via the serve path (BLACK-303)"
                )
            }
        }
        assert!(
            cell.broadcast_context
                .as_ref()
                .is_some_and(|bc| bc.is_banned(CREATOR_DID)),
            "still banned after the denied request"
        );
    }

    /// #2088 forward secrecy (runtime propagation): `execute_revoke{Read}` on a
    /// NON-subscriber author must rotate every author's broadcast key through the
    /// runtime path (the rotation rides the Class-S fail-closed persist), so a
    /// cached peer key held by the banned author goes stale. Confirms the protocol
    /// rotation is wired through `execute_revoke` for the non-subscriber case.
    #[tokio::test]
    async fn read_revoke_of_nonsubscriber_author_rotates_keys() {
        use scp_protocol::context::governance::AccessScope;

        let (deps, _appends) = build_deps().await;
        let (mut cell, ctx_hex) =
            build_broadcast_cell_with_authors(BroadcastAdmission::Gated, &[CREATOR_DID]);
        let creator = DID(CREATOR_DID.to_owned());

        // Pre-ban: the creator-author is at epoch 0.
        assert_eq!(
            cell.broadcast_context
                .as_ref()
                .and_then(|bc| bc.get_author(CREATOR_DID))
                .map(scp_protocol::context::broadcast::AuthorState::epoch),
            Some(0)
        );

        crate::context::governance_helpers::execute_revoke(
            &mut cell,
            &deps,
            &ctx_hex,
            &creator,
            AccessScope::Read,
            commit_meta(0x9b),
        )
        .await
        .expect("revoke read access on the creator-author");

        // Forward secrecy: the runtime read-revoke rotated the author key (0 → 1).
        assert_eq!(
            cell.broadcast_context
                .as_ref()
                .and_then(|bc| bc.get_author(CREATOR_DID))
                .map(scp_protocol::context::broadcast::AuthorState::epoch),
            Some(1),
            "read-revoke of a non-subscriber author MUST rotate keys via execute_revoke \
             (forward secrecy) — a cached peer key must go stale"
        );
    }
}
