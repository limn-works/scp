//! Messaging handlers — hot-path send + deliver over per-context state.
//!
//! See [`MessagingCommand`](crate::context::actor::commands::MessagingCommand)
//! and plan §"Submodule organization" / row 8 of the commit ladder.
//!
//! # Phase 2A.7 — actor-shape dispatch
//!
//! The handler's primary entry point [`dispatch`] takes
//! `(&mut PerContextState, &ActorDeps, &mut SendSequenceTracker,
//! MessagingCommand)` and routes every variant through
//! [`crate::context::messaging_helpers`] (the actor-shape messaging
//! helpers). The shim entry point [`dispatch_from_shim`] remains during
//! Phase 2A and routes through [`crate::context::messaging_helpers_legacy`]
//! for callers that arrive via the supervisor mailbox-fallback path
//! before a per-context actor exists.
//!
//! # Send-sequence tracker
//!
//! `send_tracker` is the actor-owned RAII rollback mechanism for
//! sequence reservations
//! ([`SequenceReservation`](crate::context::actor::SequenceReservation)).
//! The wire sequence is still driven by
//! `MembershipState::next_sequence_number` inside the helper body
//! during Phase 2A — `send_tracker` runs in parallel and rolls back
//! on early `?` returns, transport timeouts, and crypto errors.
//! Phase 2A finalization rewires the wire sequence onto `send_tracker`
//! exclusively.
//!
//! # Transport-timeout budget
//!
//! [`HANDLER_TIMEOUT`] is the handler-level budget. The legacy
//! `ContextManager` methods do not carry their own deadline — this is
//! the new behaviour introduced by ADR-049 §7. 30 seconds matches the
//! plan's "every transport and storage call inside a handler wraps
//! `tokio::time::timeout(30s, ...)`" contract.

use std::time::Duration;

use scp_protocol::context::ContextError;
use tokio::sync::oneshot;

use crate::context::ContextHandle;
use crate::context::actor::SendSequenceTracker;
use crate::context::actor::commands::MessagingCommand;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;
use crate::context::actor::sequence::SequenceReservation;
use crate::context::actor::state::PerContextState;

/// Per-call transport budget for mutation handlers. Plan §"Transport
/// timeouts inside actor handlers": 30 seconds.
pub const HANDLER_TIMEOUT: Duration = Duration::from_secs(30);

/// Dispatch a [`MessagingCommand`] against actor-owned state and deps.
///
/// Plan-conforming dispatch signature: matches the post-refactor actor
/// `run()` loop's call shape
/// (`handlers::messaging::dispatch(state, deps, cmd).await`). Each
/// variant routes through [`crate::context::messaging_helpers`] (the
/// actor-shape messaging helpers). The send-sequence tracker
/// (`state.send_tracker`) is reserved internally inside
/// [`handle_send_message`].
pub async fn dispatch(
    state: &mut PerContextState,
    deps: &ActorDeps,
    cmd: MessagingCommand,
) -> Outcome<()> {
    match cmd {
        MessagingCommand::Placeholder { reply } => reply_not_implemented(reply),
        MessagingCommand::SendMessage { payload, reply } => {
            let p = *payload;
            handle_send_message(
                state,
                deps,
                &p.context_id,
                p.params,
                &p.sender_did,
                &p.payload,
                p.signing_key.as_ref(),
                p.signing_key_id,
                p.source_provenance.as_ref(),
                p.spending_ucan.as_ref(),
                reply,
            )
            .await
        }
        MessagingCommand::DeliverIncoming {
            context_id,
            envelope_bytes,
            reply,
        } => handle_deliver_incoming(state, deps, &context_id, &envelope_bytes, reply).await,
        MessagingCommand::DrainEvents { context_id, reply } => {
            handle_drain_events(state, &context_id, reply).await
        }
        MessagingCommand::DrainEquivocationAlerts { context_id, reply } => {
            handle_drain_equivocation_alerts(state, &context_id, reply).await
        }
        MessagingCommand::SendPseudonymAnnouncement { payload, reply } => {
            let p = *payload;
            handle_send_pseudonym_announcement(
                state,
                deps,
                p.context_id,
                p.params,
                &p.sender_did,
                &p.signing_key,
                reply,
            )
            .await
        }
        #[cfg(feature = "testing")]
        MessagingCommand::SeedPeerPseudonym {
            context_id: _,
            member_did,
            pseudonym,
            reply,
        } => handle_seed_peer_pseudonym(state, member_did, pseudonym, reply),
        MessagingCommand::ReportDegradedMode {
            context_id,
            compat,
            unsupported_features,
            reply,
        } => handle_report_degraded_mode(
            state,
            deps,
            &context_id,
            compat,
            unsupported_features,
            reply,
        ),
        MessagingCommand::BuildLocalCheckpoint {
            context_id,
            sender_did,
            signing_key,
            reply,
        } => handle_build_local_checkpoint(
            state,
            deps,
            &context_id,
            &sender_did,
            &signing_key,
            reply,
        ),
        MessagingCommand::CompareRemoteCheckpoint {
            context_id,
            remote,
            reply,
        } => handle_compare_remote_checkpoint(state, deps, &context_id, &remote, reply),
        MessagingCommand::SendHeartbeat {
            context_id,
            sender_did,
            signing_key,
            reply,
        } => handle_send_heartbeat(state, deps, &context_id, &sender_did, &signing_key, reply),
    }
}

/// Handle [`MessagingCommand::SeedPeerPseudonym`] (actor-shape, test-only).
///
/// §9.10.4 test seam: records a peer pseudonym exactly as a delivered
/// `PseudonymAnnouncement` would. Broadcast contexts carry no peer registry —
/// rejects so a mis-targeted test fails loudly. Extracted from the dispatch
/// match so the dispatcher stays a flat one-line-per-arm router.
#[cfg(feature = "testing")]
fn handle_seed_peer_pseudonym(
    state: &mut PerContextState,
    member_did: scp_identity::DID,
    pseudonym: [u8; 32],
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let result = if let Some(reg) = state.routing.peer_registry_mut() {
        reg.insert(member_did, pseudonym);
        Ok(())
    } else {
        Err(ContextError::NotPseudonymousContext {
            context_id: state.handle.context_id().to_owned(),
        })
    };
    let _ = reply.send(result);
    Outcome::ok(())
}

/// Handle [`MessagingCommand::SendMessage`] (actor-shape): reserve a
/// sequence number via RAII on the actor-owned `send_tracker`,
/// delegate to
/// [`messaging_helpers::send_message`](crate::context::messaging_helpers::send_message)
/// under a 30s timeout, commit the reservation on success or let it
/// drop (RAII rollback) on any failure path.
///
/// The reservation is taken first against `state.send_tracker`, then
/// the helper is called with `state`. The reservation is moved
/// (consumed by `commit()` or dropped for rollback) before any other
/// borrow of `state.send_tracker` so the actor-owned RAII tracker
/// stays correct.
#[allow(clippy::too_many_arguments)]
async fn handle_send_message(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    params: scp_protocol::context::params::ContextParams,
    sender_did: &scp_identity::DID,
    payload: &[u8],
    signing_key: Option<&crate::context::actor::commands::SigningKeyBytes>,
    signing_key_id: scp_protocol::identity::SigningKeyId,
    source_provenance: Option<&scp_protocol::provenance::attach::SourceContextInfo>,
    spending_ucan: Option<&scp_protocol::crypto::ucan::UcanToken>,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    // Step 1: reserve + commit a sequence number against the
    // actor-owned tracker. The Phase 2A wire sequence is still driven
    // by `MembershipState::next_sequence_number` inside the helper —
    // `send_tracker` is the actor-shape parallel that becomes
    // authoritative in Phase 2A finalization. We commit the
    // reservation BEFORE the helper call (not after) because the
    // helper takes `&mut state` which would conflict with an active
    // `&mut state.send_tracker` reservation guard. On failure we
    // manually decrement to mirror the RAII rollback semantics; the
    // helper does not read `send_tracker` so the early commit is
    // observationally identical.
    let high_water_before = state.send_tracker.last_issued();
    {
        let reservation = SequenceReservation::reserve(&mut state.send_tracker);
        reservation.commit();
    }

    // Step 2: rebuild an ephemeral `ContextHandle` and transition it to
    // `Active` so the helper observes the same handle state every FFI
    // bridge passes today.
    let handle = ContextHandle::new(context_id.to_owned(), params);
    if let Err(e) = handle
        .transition_to(&scp_protocol::context::ContextState::Active)
        .await
    {
        // Manual rollback — restore the high-water mark prior to
        // reservation. `from_persisted` rebuilds the tracker at the
        // given last-issued value.
        state.send_tracker = SendSequenceTracker::from_persisted(high_water_before);
        let sketch = outcome_error_sketch(&e);
        let _ = reply.send(Err(e));
        return Outcome::err(sketch);
    }

    // Step 3: delegate to the actor-shape helper, wrapped in the
    // per-call transport-timeout budget.
    let sk = signing_key.map(crate::context::actor::commands::SigningKeyBytes::to_signing_key);
    let sk_ref = sk.as_ref();
    let send_fut = crate::context::messaging_helpers::send_message(
        state,
        deps,
        &handle,
        sender_did,
        payload,
        sk_ref,
        signing_key_id,
        source_provenance,
        spending_ucan,
    );

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, send_fut).await {
        Ok(Ok(())) => {
            // Send succeeded — keep the committed high-water mark.
            (Outcome::ok_mutated(()), Ok(()))
        }
        Ok(Err(e)) => {
            // Rollback on failure.
            state.send_tracker = SendSequenceTracker::from_persisted(high_water_before);
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            state.send_tracker = SendSequenceTracker::from_persisted(high_water_before);
            let err = ContextError::TransportTimeout(format!(
                "send_message exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`MessagingCommand::DeliverIncoming`] (actor-shape).
///
/// `deliver_incoming` is sync (no awaits in the actor body), so we
/// wrap it in `async {...}` to keep the per-call transport-timeout
/// budget. Precedent: `handlers::broadcast::handle_broadcast_*` wraps
/// sync helpers the same way.
async fn handle_deliver_incoming(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    envelope_bytes: &[u8],
    reply: crate::context::actor::commands::DeliverIncomingReply,
) -> Outcome<()> {
    let deliver_fut = async {
        crate::context::messaging_helpers::deliver_incoming(state, deps, context_id, envelope_bytes)
    };

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, deliver_fut).await {
        Ok(Ok(opt)) => (Outcome::ok_mutated(()), Ok(opt)),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "deliver_incoming exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`MessagingCommand::DrainEvents`] (actor-shape).
///
/// Drains the actor-owned receive buffer in place. Returns the drained
/// events on the reply channel; never propagates `ContextNotRegistered`
/// because the actor IS the registration.
async fn handle_drain_events(
    state: &mut PerContextState,
    context_id: &str,
    reply: crate::context::actor::commands::DrainEventsReply,
) -> Outcome<()> {
    let drain_fut = async { state.receive_buffer.drain() };

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, drain_fut).await {
        Ok(events) => (Outcome::ok_mutated(()), Ok(events)),
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "drain_events exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`MessagingCommand::DrainEquivocationAlerts`] (actor-shape).
///
/// Extracts only the `EquivocationDetected` alerts from the actor-owned
/// receive buffer, leaving every other buffered event in place and in
/// order for the SDK's normal receive polling. This is the targeted
/// counterpart to [`handle_drain_events`]: the reconnection driver uses
/// it so catch-up does not destroy buffered application traffic
/// (messages, membership changes) that arrived during the sync.
async fn handle_drain_equivocation_alerts(
    state: &mut PerContextState,
    context_id: &str,
    reply: crate::context::actor::commands::DrainEventsReply,
) -> Outcome<()> {
    let drain_fut = async { state.receive_buffer.drain_equivocation_alerts() };

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, drain_fut).await {
        Ok(events) => (Outcome::ok_mutated(()), Ok(events)),
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "drain_equivocation_alerts exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`MessagingCommand::SendPseudonymAnnouncement`] (actor-shape).
async fn handle_send_pseudonym_announcement(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: String,
    params: scp_protocol::context::params::ContextParams,
    sender_did: &scp_identity::DID,
    signing_key: &crate::context::actor::commands::SigningKeyBytes,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let handle = ContextHandle::new(context_id.clone(), params);
    if let Err(e) = handle
        .transition_to(&scp_protocol::context::ContextState::Active)
        .await
    {
        let sketch = outcome_error_sketch(&e);
        let _ = reply.send(Err(e));
        return Outcome::err(sketch);
    }

    let sk = signing_key.to_signing_key();
    let send_fut = crate::context::messaging_helpers::send_pseudonym_announcement(
        state, deps, &handle, sender_did, &sk,
    );

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, send_fut).await {
        Ok(()) => (Outcome::ok_mutated(()), Ok(())),
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "send_pseudonym_announcement exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`MessagingCommand::ReportDegradedMode`] (actor-shape).
///
/// Synchronous pure-emit handler: delegates to the actor-shape
/// [`queries_helpers::report_degraded_mode`](crate::context::queries_helpers::report_degraded_mode)
/// which writes a `DegradedMode` event into `state.receive_buffer` (and
/// the optional broadcast channel on `deps.event_tx`) only when the
/// supplied `compat` is the `DegradedMode` variant. All other
/// `VersionCompatibility` cases are silent no-ops. The handler never
/// awaits transport / storage so no `tokio::time::timeout` wrapper is
/// required. Always replies `Ok(())` and reports
/// [`Outcome::ok_mutated`] because the receive buffer may have grown by
/// one event.
fn handle_report_degraded_mode(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    compat: scp_protocol::envelope::VersionCompatibility,
    unsupported_features: Vec<String>,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    crate::context::queries_helpers::report_degraded_mode(
        state,
        deps,
        context_id,
        compat,
        unsupported_features,
    );
    let _ = reply.send(Ok(()));
    Outcome::ok_mutated(())
}

/// Handle [`MessagingCommand::BuildLocalCheckpoint`] (actor-shape).
///
/// Forces a signed consistency checkpoint from the current event-log
/// state via
/// [`force_create_checkpoint_fields`](crate::context::queries_helpers::force_create_checkpoint_fields),
/// threading disjoint sub-borrows of the actor-owned state exactly as
/// the periodic broadcast path does, then broadcasts it to peers via
/// [`send_checkpoint`](crate::context::messaging_helpers::send_checkpoint)
/// (best-effort — a transport failure is logged but does not fail the
/// command). The send happens inside the actor turn so the FFI-layer
/// reconnection driver never needs `send_checkpoint` (a `pub(crate)`
/// helper) across the crate boundary: Phase 3 (`event_log_sync`) is one
/// mailbox round-trip — build + broadcast — and the reply carries the
/// built checkpoint so the driver can record it.
///
/// Synchronous (the send body has no awaits); no
/// `tokio::time::timeout` wrapper required. Always replies
/// `Ok(checkpoint)`; reports [`Outcome::ok_mutated`] because the
/// checkpoint ring and counters changed.
fn handle_build_local_checkpoint(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    sender_did: &scp_identity::DID,
    signing_key: &crate::context::actor::commands::SigningKeyBytes,
    reply: crate::context::actor::commands::BuildLocalCheckpointReply,
) -> Outcome<()> {
    let sk = signing_key.to_signing_key();
    let now = deps.clock.now_secs();
    let broadcast_context_is_none = state.broadcast_context.is_none();
    let mls_epoch = state.epoch.mls_epoch;
    let checkpoint = crate::context::queries_helpers::force_create_checkpoint_fields(
        context_id,
        broadcast_context_is_none,
        mls_epoch,
        &mut state.checkpoint_events_since,
        &mut state.checkpoint_last_time_secs,
        &mut state.checkpoints,
        sender_did,
        &sk,
        now,
        &*deps.event_log,
    );

    // Broadcast the freshly-built checkpoint to peers over the regular
    // encrypted inner-envelope pipeline (§9.9.3). Best-effort: a transport
    // failure is logged but never fails the build (the reconnection driver
    // still receives + records the local checkpoint). Mirrors the
    // periodic `create_and_broadcast_checkpoint_if_due` contract.
    if let Err(e) = crate::context::messaging_helpers::send_checkpoint(
        deps,
        state,
        context_id,
        sender_did,
        &sk,
        &checkpoint,
    ) {
        tracing::warn!(
            context_id,
            error = %e,
            "failed to broadcast forced consistency checkpoint to peers \
             (best-effort; build not rolled back) (§9.9.3)"
        );
    }

    let _ = reply.send(Ok(checkpoint));
    Outcome::ok_mutated(())
}

/// Handle [`MessagingCommand::CompareRemoteCheckpoint`] (actor-shape).
///
/// Compares a remote checkpoint against local event-log state via
/// [`compare_remote_checkpoint`](crate::context::queries_helpers::compare_remote_checkpoint),
/// which verifies membership + the checkpoint Ed25519 signature, compares
/// Merkle roots, and emits `ContextEvent::EquivocationDetected` on a
/// `Divergent` result (§9.9.3). Synchronous; forwards the typed
/// `Result<CheckpointComparison, ContextError>` verbatim so the caller
/// sees the `Behind` (consistency-proof catch-up seam, specified
/// separately) / `Ahead` / `Consistent` / `Divergent`
/// classification and any `MemberNotFound` / `CryptoFailed` error.
fn handle_compare_remote_checkpoint(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    remote: &scp_event_log::checkpoint::ConsistencyCheckpoint,
    reply: crate::context::actor::commands::CompareRemoteCheckpointReply,
) -> Outcome<()> {
    let result =
        crate::context::queries_helpers::compare_remote_checkpoint(state, deps, context_id, remote);
    let mutated = result.is_ok();
    let _ = reply.send(result);
    if mutated {
        Outcome::ok_mutated(())
    } else {
        Outcome::ok(())
    }
}

/// Handle [`MessagingCommand::SendHeartbeat`] (actor-shape).
///
/// Sends a suppression-detection heartbeat (§9.9.2) to context peers via
/// [`send_heartbeat`](crate::context::messaging_helpers::send_heartbeat),
/// which routes an EMPTY-payload [`MessageType::Heartbeat`](scp_protocol::envelope::inner::MessageType::Heartbeat)
/// envelope through the regular encrypt-and-send path. The caller (the
/// bridge/SDK subscribe-path scheduler) supplies `sender_did` + `signing_key`
/// per-call — the signing key is not actor-owned state. Routing the send
/// through the actor serializes it with the context's other sends.
///
/// Synchronous (the send body has no awaits); no `tokio::time::timeout`
/// wrapper required. Forwards the `send_heartbeat` result verbatim:
/// `Ok(())` on success, or the transport error if every fan-out send fails.
/// The send does not mutate per-context state (it uses sequence `0` and
/// touches no counters), so this reports [`Outcome::ok`] / [`Outcome::err`].
fn handle_send_heartbeat(
    state: &PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    sender_did: &scp_identity::DID,
    signing_key: &crate::context::actor::commands::SigningKeyBytes,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let sk = signing_key.to_signing_key();
    let result =
        crate::context::messaging_helpers::send_heartbeat(deps, state, context_id, sender_did, &sk);
    match result {
        Ok(()) => {
            let _ = reply.send(Ok(()));
            Outcome::ok(())
        }
        Err(e) => {
            let sketch = outcome_error_sketch(&e);
            let _ = reply.send(Err(e));
            Outcome::err(sketch)
        }
    }
}

// ---------------------------------------------------------------------------
// Outcome sink helpers
// ---------------------------------------------------------------------------

/// Produce a best-effort clone-equivalent `ContextError` for the
/// handler's [`Outcome`] sink given a borrowed error that cannot be
/// cloned. The outcome consumer only reads `mutated` (on the actor's
/// dispatch loop) — the `result` field carries a representative
/// variant (preserving the `TransportTimeout` / `TransportFailed` /
/// `CryptoFailed` classification when recoverable from the
/// `Display` string). This is a shim workaround; commit 12 deletes
/// the two-channel pattern by making `Outcome`'s `Err` consumption
/// the sole error path.
fn outcome_error_sketch(err: &ContextError) -> ContextError {
    match err {
        ContextError::TransportTimeout(msg) => ContextError::TransportTimeout(msg.clone()),
        ContextError::TransportFailed(msg) => ContextError::TransportFailed(msg.clone()),
        ContextError::CryptoFailed(msg) => ContextError::CryptoFailed(msg.clone()),
        ContextError::PermissionDenied(msg) => ContextError::PermissionDenied(msg.clone()),
        ContextError::MemberNotFound(msg) => ContextError::MemberNotFound(msg.clone()),
        ContextError::ContextNotRegistered(msg) => ContextError::ContextNotRegistered(msg.clone()),
        ContextError::ContextNotActive => ContextError::ContextNotActive,
        other => ContextError::CryptoFailed(format!("{other}")),
    }
}

fn reply_not_implemented(reply: oneshot::Sender<Result<(), ContextError>>) -> Outcome<()> {
    const MSG: &str = "MessagingCommand::Placeholder — real variants \
                       SendMessage/DeliverIncoming land in commit 8 of ADR-049; \
                       Placeholder retained for commit-6 compile stability and \
                       deleted in commit 12 with the shim";
    let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
    Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
}
