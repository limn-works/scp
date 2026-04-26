//! Messaging handlers — hot-path send + deliver over per-context state.
//!
//! See [`MessagingCommand`](crate::context::actor::commands::MessagingCommand)
//! and plan §"Submodule organization" / row 8 of the commit ladder.
//!
//! # Commit 8 scope
//!
//! Migrates the dispatch shape: the handler takes
//! `&Arc<ContextManager>` + `&mut SendSequenceTracker` + [`ActorDeps`] +
//! [`MessagingCommand`], returns `Outcome<()>`.
//!
//! The underlying byte-identical implementation still lives on
//! [`ContextManager::send_message`](crate::context::supervisor::Supervisor::send_message)
//! and
//! [`ContextManager::deliver_incoming`](crate::context::messaging_helpers::deliver_incoming):
//! the handler delegates to those methods for envelope construction,
//! MLS encryption, transport fan-out, anti-replay, buffered delivery,
//! consequence evaluation, etc. The shim's job is:
//!
//! 1. Wrap the delegated call in [`tokio::time::timeout`] with a 30s
//!    budget per ADR-049 §7 / plan §"Transport timeouts inside actor
//!    handlers". Timeout maps to
//!    [`ContextError::TransportTimeout`](scp_protocol::context::ContextError::TransportTimeout).
//! 2. Use [`SequenceReservation::reserve`](crate::context::actor::SequenceReservation)
//!    on the caller-supplied `send_tracker` for the send path so the RAII
//!    rollback mechanism is exercised on every failure mode (early `?`
//!    return, transport timeout, crypto error). The legacy
//!    `MembershipState::next_sequence_number` tracker remains
//!    authoritative for wire sequence numbers during the shim period;
//!    commit 12 rewires the send path so this tracker alone drives the
//!    wire sequence.
//!
//! # ADR-049 commit 12c.7 — direct dispatch
//!
//! Prior to 12c.7 the handler took a `MutationStateView<'_>` borrow
//! adapter that bundled an `Arc<ContextManager>` reference plus a
//! mutable borrow of the per-context `SendSequenceTracker`. 12c.7
//! deletes the adapter: the supervisor passes the
//! `&Arc<ContextManager>` plus a `&mut SendSequenceTracker` directly.
//! Both remain required — the send path needs the tracker for RAII
//! reservation; the deliver path only reads the manager, so the
//! tracker is threaded through but not consumed on that arm.
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
use crate::context::supervisor::Supervisor;

/// Per-call transport budget for mutation handlers. Plan §"Transport
/// timeouts inside actor handlers": 30 seconds.
pub const HANDLER_TIMEOUT: Duration = Duration::from_secs(30);

/// Dispatch a [`MessagingCommand`] against the attached manager + the
/// per-context send-sequence tracker + a deps bundle. Each real variant
/// wraps the delegated
/// [`Supervisor`](crate::context::supervisor::Supervisor) call in
/// [`tokio::time::timeout`] with the per-call [`HANDLER_TIMEOUT`]
/// budget.
///
/// Plan-conforming dispatch signature: matches the post-refactor actor
/// `run()` loop's call shape
/// (`handlers::messaging::dispatch(&mgr, &self.deps, &mut state.send_tracker, cmd).await`).
/// `deps` is accepted for symmetry — the messaging handler does not yet
/// touch deps during the shim period (the transport, event log, etc.
/// live on the legacy [`Supervisor`](crate::context::supervisor::Supervisor)).
/// Commit 12 rewires these paths to use `deps` directly once the
/// manager surface is deleted.
///
/// Deleted / heavily refactored in commit 12 (the shim-driven
/// delegation pattern goes away with `ContextManager`; the handler
/// body reads state and encrypts in-place against the actor's owned
/// backends).
pub async fn dispatch(
    supervisor: &Supervisor,
    _deps: &ActorDeps,
    send_tracker: &mut SendSequenceTracker,
    cmd: MessagingCommand,
) -> Outcome<()> {
    dispatch_inner(supervisor, send_tracker, cmd).await
}

/// Shim-callable dispatch. Used by
/// [`Supervisor::dispatch_command`](crate::context::supervisor::supervisor::Supervisor::dispatch_command)
/// during the commits-8-to-11 migration window — deleted in commit 12
/// when the shim dissolves and the actor's `run()` loop is the only
/// caller of [`dispatch`].
///
/// Messaging commands do not yet touch [`ActorDeps`] during the shim
/// period (the transport, MLS/HPKE backends, and key-package store
/// live on the legacy [`Supervisor`](crate::context::supervisor::Supervisor)).
/// Requiring callers to synthesize an `ActorDeps` instance just to route
/// a send / deliver through the shim would force every bridge into a
/// placeholder-deps dance before commits 9-11 land the real dep wiring.
/// This entry point exists to avoid that churn — it takes only the
/// supervisor, the send tracker, and the command.
///
/// # Supervisor receiver (ADR-049 commit 12)
///
/// Takes `&Supervisor` so the hoisted
/// [`messaging_helpers`](crate::context::messaging_helpers) free
/// functions can read the lifted provider slots directly. Each
/// delegated call either reads `supervisor.X_ref()` for lifted
/// providers or derives `&ContextManager` via
/// `supervisor.crypto_ref().expect(...)` etc. for the
/// remaining manager-only surface.
pub(crate) async fn dispatch_from_shim(
    supervisor: &Supervisor,
    send_tracker: &mut SendSequenceTracker,
    cmd: MessagingCommand,
) -> Outcome<()> {
    dispatch_inner(supervisor, send_tracker, cmd).await
}

async fn dispatch_inner(
    supervisor: &Supervisor,
    send_tracker: &mut SendSequenceTracker,
    cmd: MessagingCommand,
) -> Outcome<()> {
    match cmd {
        MessagingCommand::Placeholder { reply } => reply_not_implemented(reply),
        MessagingCommand::SendMessage { payload, reply } => {
            // Unbox the payload on the handler side. The boxed shape
            // on the variant exists to keep variant sizes uniform
            // across the outer `ContextCommand` enum; the handler does
            // not need to preserve the Box.
            let p = *payload;
            handle_send_message(
                supervisor,
                send_tracker,
                &p.context_id,
                p.params,
                &p.sender_did,
                &p.payload,
                p.signing_key.as_ref(),
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
        } => handle_deliver_incoming(supervisor, &context_id, &envelope_bytes, reply).await,
        MessagingCommand::DrainEvents { context_id, reply } => {
            handle_drain_events(supervisor, &context_id, reply).await
        }
        MessagingCommand::SendPseudonymAnnouncement { payload, reply } => {
            let p = *payload;
            handle_send_pseudonym_announcement(
                supervisor,
                p.context_id,
                p.params,
                &p.sender_did,
                &p.signing_key,
                reply,
            )
            .await
        }
    }
}

/// Handle [`MessagingCommand::SendMessage`]: reserve a sequence number
/// via RAII, delegate to
/// [`messaging_helpers::send_message`](crate::context::messaging_helpers::send_message)
/// under a 30s timeout, commit the reservation on success or let it
/// drop (RAII rollback) on any failure path.
///
/// Phase 1 fix-up of ADR-049 (post-review-round-1): the helper now
/// reads `clock` / `key_resolver` directly from the supervisor's
/// provider slots, so the handler no longer fishes them out before the
/// call.
#[allow(
    clippy::too_many_arguments,
    reason = "matches messaging_helpers::send_message signature \
              after the clock/key_resolver parameter drop"
)]
async fn handle_send_message(
    supervisor: &Supervisor,
    send_tracker: &mut SendSequenceTracker,
    context_id: &str,
    params: scp_protocol::context::params::ContextParams,
    sender_did: &scp_identity::DID,
    payload: &[u8],
    signing_key: Option<&crate::context::actor::commands::SigningKeyBytes>,
    source_provenance: Option<&scp_protocol::provenance::attach::SourceContextInfo>,
    spending_ucan: Option<&scp_protocol::crypto::ucan::UcanToken>,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    // Step 1: reserve the next actor-shape sequence number. The RAII
    // guard rolls back on any early `?` return below, on transport
    // timeout, or on crypto failure. Wire sequence numbers
    // (`MembershipState::next_sequence_number`) are assigned inside
    // `messaging_helpers::send_message`.
    let reservation = SequenceReservation::reserve(send_tracker);
    let _reserved = reservation.number();

    // Step 2: rebuild an ephemeral `ContextHandle` on the receive side
    // and transition it to `Active` — matches the pattern every FFI
    // bridge uses today when calling `send_message` on an owned handle.
    let handle = ContextHandle::new(context_id.to_owned(), params);
    if let Err(e) = handle
        .transition_to(&scp_protocol::context::ContextState::Active)
        .await
    {
        // Transition failed — reservation drops, rolling back the
        // tracker. This path is safety-net only; the bridges guarantee
        // the underlying context is registered and active before
        // dispatching the command. `ContextError` is `!Clone`; stage a
        // sketch for the Outcome sink before forwarding the authoritative
        // error on the reply channel.
        let sketch = outcome_error_sketch(&e);
        let _ = reply.send(Err(e));
        drop(reservation);
        return Outcome::err(sketch);
    }

    // Step 3: delegate to the hoisted byte-identical implementation,
    // wrapped in the per-call transport-timeout budget. The closure
    // rebuilds the signing key from the zeroizing bytes held in the
    // command.
    let sk = signing_key.map(crate::context::actor::commands::SigningKeyBytes::to_signing_key);
    let sk_ref = sk.as_ref();
    let send_fut = crate::context::messaging_helpers::send_message(
        supervisor,
        &handle,
        sender_did,
        payload,
        sk_ref,
        source_provenance,
        spending_ucan,
    );

    // `ContextError` is `!Clone`. To surface the outcome through both
    // the oneshot reply AND the handler's typed `Outcome`, route the
    // reply first and then stage a message-only second copy for the
    // outcome via `outcome_error_sketch` below. The legacy method's
    // error type carries no `Copy`/`Clone`-sensitive payload that the
    // Outcome sink actually inspects — callers observe the typed
    // result through the oneshot reply; the `Outcome` is consumed by
    // the actor's `dirty` machinery which only looks at `mutated`.
    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, send_fut).await {
        Ok(Ok(())) => {
            // Step 4a: send succeeded — commit the reservation so the
            // actor-shape tracker advances. Wire sequence numbers were
            // advanced inside the legacy path (`MembershipState`).
            reservation.commit();
            (Outcome::ok_mutated(()), Ok(()))
        }
        Ok(Err(e)) => {
            // Step 4b: legacy send returned a typed error. Reservation
            // drops (RAII) and rolls back the actor-shape tracker.
            // Keep the typed error on the reply channel; the Outcome
            // carries the same message text via
            // `ContextError::CryptoFailed`-shaped stand-in so the
            // actor's dirty-tracking consumer still sees a typed error
            // variant. See the comment above for the !Clone rationale.
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            // Step 4c: transport hung past the budget. Drop the
            // reservation to roll back, surface the typed timeout
            // error. The in-flight `send_fut` is cancelled when the
            // timeout future's polled result is `Err(Elapsed)` — the
            // future is dropped immediately as we fall out of this
            // match arm.
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
    // Preserve the variant's *category* so downstream code that
    // matches on `ContextError` (e.g. retry logic) still classifies
    // correctly. Fall back to `CryptoFailed(msg)` for variants whose
    // payload cannot be easily reconstructed (rate-limited, etc.).
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

/// Handle [`MessagingCommand::DeliverIncoming`]: delegate to
/// [`ContextManager::deliver_incoming`](crate::context::messaging_helpers::deliver_incoming)
/// under the same 30s timeout contract.
///
/// Takes the manager by shared reference — deliver does not reserve a
/// send-sequence, so no access to the `send_tracker` is needed during
/// the shim period. The handler signature will flip to take the full
/// actor state (including the `recv_tracker`) in commit 12 when the
/// receive-sequence tracker moves onto the actor state.
async fn handle_deliver_incoming(
    supervisor: &Supervisor,
    context_id: &str,
    envelope_bytes: &[u8],
    reply: crate::context::actor::commands::DeliverIncomingReply,
) -> Outcome<()> {
    // Phase 1 fix-up of ADR-049 (post-review-round-1): the helper reads
    // `clock` / `key_resolver` from the supervisor directly.
    let deliver_fut = crate::context::messaging_helpers::deliver_incoming(
        supervisor,
        context_id,
        envelope_bytes,
    );

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

/// Handle [`MessagingCommand::DrainEvents`]: delegate to the hoisted
/// [`queries_helpers::drain_events`](crate::context::queries_helpers::drain_events)
/// under a 30s timeout.
///
/// The legacy method returns an empty `Vec` on unknown context (no
/// error). The dispatch shim preserves that contract: the reply
/// channel always carries `Ok(events)` — never
/// `Err(ContextNotRegistered)`. `mutated: true` because draining the
/// receive buffer empties it.
async fn handle_drain_events(
    supervisor: &Supervisor,
    context_id: &str,
    reply: crate::context::actor::commands::DrainEventsReply,
) -> Outcome<()> {
    // ADR-049 commit 12c.9d — `queries_helpers::drain_events` now takes
    // `&Supervisor`. Drain returns `Vec<_>` (no error channel); the
    // helper degrades to empty-vec on detached supervisor, matching
    // the legacy "unknown context" semantics.
    let drain_fut = crate::context::queries_helpers::drain_events(supervisor, context_id);

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

/// Handle [`MessagingCommand::SendPseudonymAnnouncement`]: delegate to
/// [`ContextManager::send_pseudonym_announcement`](crate::context::messaging_helpers::send_pseudonym_announcement)
/// under a 30s timeout.
///
/// Best-effort — the legacy method returns `()` and silently logs
/// transport / serialization failures internally. The dispatch shim
/// preserves that contract: the reply channel always carries `Ok(())`
/// unless the timeout fires (in which case `TransportTimeout` is
/// surfaced for observability). `mutated: true` because the
/// announcement, if successfully sent, advances the wire-sequence
/// counter on the underlying `send_message` path.
///
/// Calls
/// [`messaging_helpers::send_pseudonym_announcement`](crate::context::messaging_helpers::send_pseudonym_announcement)
/// directly on the supervisor reference. The 30s timeout is the same
/// budget every handler uses for transport-touching operations.
async fn handle_send_pseudonym_announcement(
    supervisor: &Supervisor,
    context_id: String,
    params: scp_protocol::context::params::ContextParams,
    sender_did: &scp_identity::DID,
    signing_key: &crate::context::actor::commands::SigningKeyBytes,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    // Rebuild the ephemeral handle the legacy method takes by
    // reference; transition it to `Active` so the underlying
    // `send_message` path (called inside `send_pseudonym_announcement`)
    // observes the same handle state every FFI bridge passes today.
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
        supervisor, &handle, sender_did, &sk,
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

fn reply_not_implemented(reply: oneshot::Sender<Result<(), ContextError>>) -> Outcome<()> {
    const MSG: &str = "MessagingCommand::Placeholder — real variants \
                       SendMessage/DeliverIncoming land in commit 8 of ADR-049; \
                       Placeholder retained for commit-6 compile stability and \
                       deleted in commit 12 with the shim";
    // Two copies of the string to construct two non-cloneable `ContextError`
    // values — one for the oneshot reply, one for the `Outcome` sink.
    // Drop-tolerant: if the caller's receiver is gone, send returns Err.
    // That is the intentional cancellation path; we ignore the result.
    let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
    Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
}
