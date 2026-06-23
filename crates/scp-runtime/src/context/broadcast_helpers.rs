// Read-only actor helpers still take `&mut PerContextState` so their
// handler futures capture `&mut T` (`T: Send`) rather than `&T`
// (`T: Sync` required). `PerContextState` is intentionally Send + !Sync.
#![allow(clippy::needless_pass_by_ref_mut)]

//! Broadcast helpers -- actor-shape signatures
//! (ADR-049 Phase 2A.5, `broadcast` domain migration).
//!
//! # Purpose
//!
//! This module hosts broadcast-domain helpers that operate on actor-owned
//! [`PerContextState`](crate::context::actor::state::PerContextState) and
//! capability-reduced [`ActorDeps`](crate::context::actor::deps::ActorDeps).
//! The legacy `&Supervisor` lock-and-call bodies live in
//! [`crate::context::broadcast_helpers_legacy`] until Phase 2A finalization
//! removes the shim fallback.
//!
//! Publish helpers are actor-shaped here for parity with the domain surface,
//! but the actor mailbox still rejects publish commands: `KeyCustody` uses
//! RPITIT and cannot cross the mailbox as a trait object. During the migration
//! window publish dispatch stays on the generic supervisor shim.

use std::hash::BuildHasher;

use scp_identity::DID;
use scp_protocol::context::ContextError;
use scp_protocol::context::broadcast::{
    BlockResult, BroadcastAdmission, BroadcastContext, KeyRequestDecision, SubscriptionResult,
    UnsubscribeResult,
};
use scp_protocol::context::membership::ContextEvent;
use scp_protocol::context::roles::Capability;
use scp_protocol::crypto::sender_keys::BroadcastEnvelope;
use scp_protocol::crypto::ucan::UcanToken;
use scp_protocol::crypto::ucan::validate::{
    DidResolver, NonceTracker, ProofResolver, RevocationChecker, ValidationContext,
};

use crate::context::actor::class_s::ClassSCell;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::state::{
    BroadcastReservationId, PendingBroadcastPublish, PerContextState,
};
use crate::context::state::{context_id_to_bytes, require_active, strip_event_payload};

// ---------------------------------------------------------------------------
// subscribe_broadcast
// ---------------------------------------------------------------------------

/// Subscribes a DID to a broadcast context using actor-owned state.
///
/// # Errors
///
/// - [`ContextError::ContextNotActive`] if the context is not `Active`.
/// - [`ContextError::MembershipFailed`] if the actor is not a broadcast
///   context or the subscriber is already registered.
/// - [`ContextError::PermissionDenied`] if the context is gated and no valid
///   `messagesRead` UCAN is supplied.
pub fn subscribe_broadcast<D, N, R, P, S>(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    subscriber_did: &DID,
    ucan: Option<&UcanToken>,
    timestamp: u64,
    validation_ctx: Option<&mut ValidationContext<'_, D, N, R, P, S>>,
) -> Result<SubscriptionResult, ContextError>
where
    D: DidResolver + Send + Sync,
    N: NonceTracker + Send + Sync,
    R: RevocationChecker + Send + Sync,
    P: ProofResolver + Send + Sync,
    S: BuildHasher + Send + Sync,
{
    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&cell.handle)?;
    cell.handle
        .params()
        .check_version_compatibility(scp_protocol::envelope::SCP_PROTOCOL_VERSION)?;

    // All in-state mutations below are Class-C (broadcast subscriber roster
    // ADD, broadcast metadata, receive buffer, checkpoint counter) with the
    // best-effort persist below — routed through the non-persisting Class-C
    // view (ADR-049 §9). Member ADD is a structural Class-C op (the restricted
    // `MembershipClassCMut` exposes it; member REMOVAL is the downward-auth
    // Class-S op it withholds — see `unsubscribe_broadcast`).
    let (result, snapshot) = {
        let mut view = cell.class_c_view();
        let bc = view
            .broadcast_context_mut()
            .as_mut()
            .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;

        let result = bc.subscribe(subscriber_did, ucan, timestamp, validation_ctx)?;
        let snapshot = bc.to_snapshot();
        (result, snapshot)
    };

    {
        let mut view = cell.class_c_view();
        view.membership_class_c_mut().add_member(
            subscriber_did.clone(),
            "subscriber".into(),
            vec![],
        );
    }
    emit_event(
        cell.class_c_view().receive_buffer_mut(),
        result.event.clone(),
        context_id,
        deps.event_tx.as_ref(),
    );

    persist_broadcast_snapshot(deps, context_id, &snapshot);
    persist_state_best_effort(cell, deps, context_id);

    deps.event_log.append_context_event(
        &context_id_bytes,
        scp_event_log::EventType::MemberJoined,
        subscriber_did.as_ref(),
        // Committer-assigned: the subscriber's signed subscribe-request
        // timestamp, copied by every member (§7.3.1, §9.9.3).
        timestamp,
    )?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;

    Ok(result)
}

// ---------------------------------------------------------------------------
// unsubscribe_broadcast
// ---------------------------------------------------------------------------

/// Unsubscribes a DID from a broadcast context.
///
/// # Errors
///
/// - [`ContextError::ContextNotActive`] if the context is not `Active`.
/// - [`ContextError::MembershipFailed`] if the actor is not a broadcast
///   context.
pub fn unsubscribe_broadcast(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    subscriber_did: &DID,
    rotate_keys: bool,
) -> Result<UnsubscribeResult, ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&cell.handle)?;

    let (result, snapshot) = {
        let mut view = cell.class_c_view();
        let bc = view
            .broadcast_context_mut()
            .as_mut()
            .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;

        let result = bc.unsubscribe(subscriber_did, rotate_keys)?;
        let snapshot = bc.to_snapshot();
        (result, snapshot)
    };

    // SECURITY CARVE-OUT (ADR-049 §9): a broadcast UNSUBSCRIBE removes a
    // SUBSCRIBER from the roster best-effort, NOT a regular member. A broadcast
    // context's subscriber roster carries NO key secrecy — content is public,
    // per-author broadcast keys (not MLS group keys) protect publication, and
    // the unsubscribe is not an MLS-gated authorization boundary — so a
    // coalesce-window rollback at most re-lists a public-content subscriber for
    // the window, with no membership-secrecy consequence. The restricted
    // `MembershipClassCMut::remove_subscriber` (scoped by name + contract to the
    // broadcast roster) expresses exactly this best-effort removal; the general
    // `remove_member` (a fail-closed downward-auth Class-S op) is deliberately
    // NOT exposed on the view. Behaviour is unchanged (best-effort, coalesced).
    cell.class_c_view()
        .membership_class_c_mut()
        .remove_subscriber(subscriber_did);
    emit_event(
        cell.class_c_view().receive_buffer_mut(),
        ContextEvent::MemberLeft {
            member_did: subscriber_did.clone(),
        },
        context_id,
        deps.event_tx.as_ref(),
    );

    persist_broadcast_snapshot(deps, context_id, &snapshot);
    persist_state_best_effort(cell, deps, context_id);

    deps.event_log.append_context_event(
        &context_id_bytes,
        scp_event_log::EventType::MemberLeft,
        subscriber_did.as_ref(),
        // Committer-assigned: the unsubscribing author's clock — the source of
        // the `created_at` on its outgoing leave message, copied by every
        // member (§7.3.1, §9.9.3).
        deps.clock.now_secs(),
    )?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;

    Ok(result)
}

// ---------------------------------------------------------------------------
// Two-phase broadcast publish (reserve + apply)
// ---------------------------------------------------------------------------
//
// `KeyCustody` is an RPITIT trait and is not `dyn`-safe, so the signer
// cannot cross the actor mailbox; and the actor must not hold `&mut
// PerContextState` across an arbitrary-duration host-language
// `custody.sign().await`. The publish is therefore split into two
// mailbox commands, each holding `&mut state` only briefly:
//
//   1. `reserve_broadcast_publish` (phase 1) reserves the broadcast
//      sequence, builds the signing payload, and stores a
//      `PendingBroadcastPublish`. Returns the signing payload + the
//      reservation id.
//   2. The caller signs the payload with its own custody, OUTSIDE the
//      actor.
//   3. `apply_broadcast_publish` (phase 2) validates the reservation,
//      seals with the RESERVED sequence, emits the event, sends on the
//      transport, appends to the event log, and removes the reservation.
//
// A reservation that is never applied (signing failed, caller dropped)
// is released by `release_broadcast_reservation` so the sequence is not
// burned — matching the legacy single-phase path, where a signing
// failure occurred before any sequence increment. Concurrent publishes
// each reserve a distinct sequence, closing the double-sequence /
// signature-mismatch hazard the single-phase shim had under
// decomposition.

/// Outcome of [`reserve_broadcast_publish`] (phase 1). Carries the
/// reservation id (echoed back at apply) and the exact bytes the caller
/// must sign with its key custody.
#[derive(Debug, Clone)]
pub struct BroadcastPublishReservationOutcome {
    /// Identifier of the stored reservation. Pass back to
    /// [`apply_broadcast_publish`] to seal the reserved sequence.
    pub reservation_id: BroadcastReservationId,
    /// Canonical broadcast signing-payload digest (32-byte hash) to hand
    /// to `KeyCustody::sign`. Matches the legacy single-phase signer
    /// input exactly.
    pub signing_payload: [u8; 32],
}

/// Phase 1 of the two-phase broadcast publish: reserve the sequence and
/// build the signing payload. Holds `&mut state` only for this call —
/// never across the caller's async sign.
///
/// # Errors
///
/// - [`ContextError::ContextNotActive`] if the context is not `Active`.
/// - [`ContextError::MembershipFailed`] if the actor is not a broadcast
///   context.
/// - [`ContextError::PermissionDenied`] if the sender is not an author or
///   write access is suspended.
pub fn reserve_broadcast_publish(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    author_did: &DID,
) -> Result<BroadcastPublishReservationOutcome, ContextError> {
    require_active(&cell.handle)?;

    // Suspension-aware capability check (§9.17, ADR-038). In broadcast
    // contexts, authors may be registered with the BroadcastContext
    // without being members of the role_state, so we check the
    // suspension overlay directly: only members whose MessagesWrite
    // capability has been explicitly suspended via governance Revoke are
    // blocked here. The downstream `bc.reserve_publish` enforces author
    // registration. READ of the downward-auth `suspended_capabilities`
    // overlay via Deref (a read cannot violate the §9 invariant).
    if cell
        .role_state
        .suspended_capabilities
        .get(author_did.as_ref())
        .is_some_and(|s| s.contains(&Capability::MessagesWrite))
    {
        return Err(ContextError::PermissionDenied(format!(
            "write access has been suspended for {author_did}"
        )));
    }

    let timestamp = deps.clock.now_millis();
    let nonce = scp_protocol::crypto::sender_keys::generate_broadcast_nonce();

    // Reserve the broadcast sequence + build the signing payload. Both the
    // broadcast metadata reservation and the pending-publish insert are
    // Class-C (the handler reports `mutated`; the run loop coalesce-persists)
    // — routed through the non-persisting Class-C view (ADR-049 §9).
    let mut view = cell.class_c_view();
    let bc = view
        .broadcast_context_mut()
        .as_mut()
        .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;

    // Reserve the broadcast sequence atomically. A concurrent publish on
    // the same author gets the next number, never this one.
    let reservation = bc.reserve_publish(author_did.as_ref())?;

    let provenance_hash = scp_protocol::crypto::sender_keys::compute_provenance_hash(None)
        .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;
    let signing_payload = scp_protocol::crypto::sender_keys::build_broadcast_signing_payload(
        &scp_protocol::crypto::sender_keys::SigningPayloadFields {
            version: scp_protocol::envelope::SCP_PROTOCOL_VERSION,
            context_id: bc.context_id(),
            author_did: author_did.as_ref(),
            sequence: reservation.reserved_sequence,
            key_epoch: reservation.key_epoch,
            timestamp,
            nonce: &nonce,
            provenance_hash: &provenance_hash,
        },
    )
    .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

    let reservation_id = BroadcastReservationId::new_random();
    view.pending_broadcast_publishes_mut().insert(
        reservation_id.clone(),
        PendingBroadcastPublish {
            author_did: author_did.clone(),
            reserved_sequence: reservation.reserved_sequence,
            key_epoch: reservation.key_epoch,
            timestamp,
            nonce,
        },
    );

    Ok(BroadcastPublishReservationOutcome {
        reservation_id,
        signing_payload,
    })
}

/// Phase 2 of the two-phase broadcast publish: seal the reserved
/// sequence with the caller-produced `signature`, emit the event, send
/// on the transport, and append to the event log. Holds `&mut state`
/// only for this call.
///
/// On any failure before the seal succeeds the reservation is released
/// (sequence returned to the author's counter if still the head) so the
/// sequence is not burned. After the seal succeeds the sequence is
/// permanently consumed even if transport delivery fails — matching the
/// legacy path, which also burned the broadcast sequence on a
/// post-seal transport failure.
///
/// # Errors
///
/// - [`ContextError::ContextNotActive`] if the context is not `Active`.
/// - [`ContextError::InvalidState`] if `reservation_id` does not match a
///   live reservation (already applied, expired, or never issued).
/// - [`ContextError::MembershipFailed`] if the actor is not a broadcast
///   context.
/// - [`ContextError::CryptoFailed`] on a signature-length mismatch, an
///   epoch change between phases, or a seal failure.
pub fn apply_broadcast_publish(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    reservation_id: &BroadcastReservationId,
    signature: &[u8],
    payload: &[u8],
) -> Result<BroadcastEnvelope, ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    // Resolve the reservation first so a stale/duplicate apply is a
    // clean typed error and never touches sequence state. Class-C
    // pending-publish map (coalesced persist) — non-persisting Class-C view.
    let pending = cell
        .class_c_view()
        .pending_broadcast_publishes_mut()
        .remove(reservation_id)
        .ok_or_else(|| {
            ContextError::InvalidState(format!(
                "no live broadcast-publish reservation for id {}",
                reservation_id.0
            ))
        })?;

    // From here on, any early return must release the reserved sequence
    // (it was consumed at phase 1 but never sealed). `apply_guarded`
    // owns that rollback discipline.
    apply_guarded(
        cell,
        deps,
        context_id,
        &context_id_bytes,
        &pending,
        signature,
        payload,
    )
}

/// Inner apply body. Separated so the caller-facing
/// [`apply_broadcast_publish`] can guarantee the reserved sequence is
/// released on every error path.
fn apply_guarded(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    context_id_bytes: &[u8; 32],
    pending: &PendingBroadcastPublish,
    signature: &[u8],
    payload: &[u8],
) -> Result<BroadcastEnvelope, ContextError> {
    // Seal under the reserved sequence. On any failure before the seal
    // succeeds, release the reserved sequence so it is not burned.
    let envelope = match seal_reserved(cell, pending, signature, payload) {
        Ok(env) => env,
        Err(e) => {
            release_reserved(cell, pending);
            return Err(e);
        }
    };

    // Seal succeeded — the broadcast sequence is now permanently consumed
    // (matches legacy: a post-seal transport failure burns it too). The
    // per-sender sequence bump is Class-C structural bookkeeping (exposed on
    // the restricted `MembershipClassCMut`) — non-persisting Class-C view.
    let seq = cell
        .class_c_view()
        .membership_class_c_mut()
        .next_sequence_number(pending.author_did.as_ref())
        .ok_or_else(|| ContextError::MemberNotFound(pending.author_did.to_string()))?;
    emit_event(
        cell.class_c_view().receive_buffer_mut(),
        ContextEvent::MessageSent {
            sender_did: pending.author_did.clone(),
            sequence_number: seq,
            payload: payload.to_vec(),
        },
        context_id,
        deps.event_tx.as_ref(),
    );

    let envelope_bytes = rmp_serde::to_vec_named(&envelope)
        .map_err(|e| ContextError::CryptoFailed(format!("envelope serialization: {e}")))?;
    deps.transport
        .send_message(context_id_bytes, &envelope_bytes)?;

    // `MessageSent` is no longer a durable Merkle leaf — per ADR-051 §6 / the
    // phase-2.md ADR-011 amendment exclusion taxonomy §2 it is a per-author,
    // non-convergent event surfaced only as the local `ContextEvent::MessageSent`
    // emitted above. The former durable append (and its `checkpoint_events_since`
    // increment) is removed so two honest members derive the same
    // `event_log_merkle_root` (§9.9.3).

    Ok(envelope)
}

/// Validate the context and seal the reserved-sequence broadcast. Pure
/// up to the seal — performs no event emission or transport. Returns the
/// sealed envelope without mutating membership / checkpoint counters.
fn seal_reserved(
    cell: &mut ClassSCell,
    pending: &PendingBroadcastPublish,
    signature: &[u8],
    payload: &[u8],
) -> Result<BroadcastEnvelope, ContextError> {
    require_active(&cell.handle)?;

    let sig_bytes: [u8; 64] = signature.try_into().map_err(|_| {
        ContextError::CryptoFailed(format!(
            "custody signature has wrong length: expected 64, got {}",
            signature.len()
        ))
    })?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    // Broadcast metadata seal is Class-C (coalesced persist) — non-persisting
    // Class-C view (ADR-049 §9).
    let mut view = cell.class_c_view();
    let bc = view
        .broadcast_context_mut()
        .as_mut()
        .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;

    // Detect a key rotation between reserve and apply — sealing under a
    // rotated key would produce a ciphertext whose epoch the signed
    // payload no longer matches.
    let current_epoch = bc.publish_metadata(pending.author_did.as_ref())?.key_epoch;
    if current_epoch != pending.key_epoch {
        return Err(ContextError::CryptoFailed(format!(
            "broadcast key epoch changed between reserve and apply for {} \
             (reserved at {}, now {})",
            pending.author_did, pending.key_epoch, current_epoch
        )));
    }

    bc.apply_reserved_publish(
        pending.author_did.as_ref(),
        payload,
        &pending.nonce,
        scp_protocol::context::broadcast::ReservedPublishApply {
            sequence: pending.reserved_sequence,
            timestamp: pending.timestamp,
            signature,
            provenance: None,
        },
    )
}

/// Roll back the reserved sequence for a pending publish that will not be
/// applied. No-op if the context is no longer a broadcast context.
fn release_reserved(cell: &mut ClassSCell, pending: &PendingBroadcastPublish) {
    // Broadcast metadata rollback is Class-C (coalesced persist) — view.
    if let Some(bc) = cell.class_c_view().broadcast_context_mut().as_mut() {
        bc.rollback_reserved_publish(pending.author_did.as_ref(), pending.reserved_sequence);
    }
}

/// Release a broadcast-publish reservation that will never be applied
/// (the caller's signing failed, or the caller is aborting). Removes the
/// stored reservation and rolls the reserved sequence back if it is still
/// the head. No-op if the reservation id is unknown.
pub fn release_broadcast_reservation(
    cell: &mut ClassSCell,
    reservation_id: &BroadcastReservationId,
) {
    // Both the pending-publish map and the broadcast metadata are Class-C
    // (coalesced persist) — route through the non-persisting Class-C view.
    // Separate the two `&mut` reaches (remove the reservation, then roll the
    // sequence back) so each view borrow is short-lived (ADR-049 §9).
    let Some(pending) = cell
        .class_c_view()
        .pending_broadcast_publishes_mut()
        .remove(reservation_id)
    else {
        return;
    };
    if let Some(bc) = cell.class_c_view().broadcast_context_mut().as_mut() {
        bc.rollback_reserved_publish(pending.author_did.as_ref(), pending.reserved_sequence);
    }
}

// ---------------------------------------------------------------------------
// block_broadcast_subscriber
// ---------------------------------------------------------------------------

/// Blocks a subscriber from receiving future broadcast keys from an author.
///
/// # Errors
///
/// - [`ContextError::ContextNotActive`] if the context is not `Active`.
/// - [`ContextError::MembershipFailed`] if the actor is not a broadcast
///   context.
/// - [`ContextError::MemberNotFound`] if the author is not registered.
pub fn block_broadcast_subscriber(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    author_did: &DID,
    subscriber_did: &DID,
) -> Result<BlockResult, ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&cell.handle)?;

    // Class-C broadcast metadata + receive buffer + checkpoint counter
    // (best-effort/coalesced persist) — non-persisting Class-C view (ADR-049 §9).
    let (result, snapshot) = {
        let mut view = cell.class_c_view();
        let bc = view
            .broadcast_context_mut()
            .as_mut()
            .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;

        let result = bc.block_subscriber(author_did, subscriber_did)?;
        let snapshot = bc.to_snapshot();
        (result, snapshot)
    };

    emit_event(
        cell.class_c_view().receive_buffer_mut(),
        ContextEvent::MemberBlocked {
            blocked_did: subscriber_did.clone(),
            author_did: author_did.clone(),
        },
        context_id,
        deps.event_tx.as_ref(),
    );

    persist_broadcast_snapshot(deps, context_id, &snapshot);

    deps.event_log.append_context_event(
        &context_id_bytes,
        scp_event_log::EventType::MemberBlocked,
        author_did.as_ref(),
        // Committer-assigned: the blocking author's clock — the source of the
        // `created_at` on its outgoing block message, copied by every member
        // (§7.3.1, §9.9.3).
        deps.clock.now_secs(),
    )?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;

    Ok(result)
}

// ---------------------------------------------------------------------------
// unblock_broadcast_subscriber
// ---------------------------------------------------------------------------

/// Unblocks a previously blocked subscriber in a broadcast context.
///
/// # Errors
///
/// - [`ContextError::ContextNotActive`] if the context is not `Active`.
/// - [`ContextError::MembershipFailed`] if the actor is not a broadcast
///   context.
/// - [`ContextError::MemberNotFound`] if the author is not registered.
/// - [`ContextError::InvalidState`] if the subscriber is not blocked.
pub fn unblock_broadcast_subscriber(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    author_did: &DID,
    subscriber_did: &DID,
) -> Result<(), ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&cell.handle)?;

    // Class-C broadcast metadata + receive buffer + checkpoint counter
    // (best-effort/coalesced persist) — non-persisting Class-C view (ADR-049 §9).
    let snapshot = {
        let mut view = cell.class_c_view();
        let bc = view
            .broadcast_context_mut()
            .as_mut()
            .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;

        let _result = bc.unblock_subscriber(author_did, subscriber_did)?;
        bc.to_snapshot()
    };

    emit_event(
        cell.class_c_view().receive_buffer_mut(),
        ContextEvent::MemberUnblocked {
            unblocked_did: subscriber_did.clone(),
            author_did: author_did.clone(),
        },
        context_id,
        deps.event_tx.as_ref(),
    );

    persist_broadcast_snapshot(deps, context_id, &snapshot);

    deps.event_log.append_context_event(
        &context_id_bytes,
        scp_event_log::EventType::MemberUnblocked,
        author_did.as_ref(),
        // Committer-assigned: the unblocking author's clock — the source of the
        // `created_at` on its outgoing unblock message, copied by every member
        // (§7.3.1, §9.9.3).
        deps.clock.now_secs(),
    )?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;

    Ok(())
}

// ---------------------------------------------------------------------------
// handle_broadcast_key_request
// ---------------------------------------------------------------------------

/// Evaluates whether a subscriber's broadcast key request should be granted.
///
/// # Errors
///
/// Returns [`ContextError::PermissionDenied`] if `author_did` is not a locally
/// controlled DID, and [`ContextError::MembershipFailed`] if the actor is not a
/// broadcast context.
pub fn handle_broadcast_key_request(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    author_did: &DID,
    requester_did: &DID,
    wrapping_pubkey: &[u8; 32],
) -> Result<KeyRequestDecision, ContextError> {
    if !deps.local_dids.load().contains(author_did) {
        return Err(ContextError::PermissionDenied(format!(
            "author DID is not controlled by the local node: {author_did}"
        )));
    }

    let bc = cell
        .broadcast_context
        .as_ref()
        .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;

    Ok(bc.handle_key_request(author_did, requester_did, wrapping_pubkey))
}

// ---------------------------------------------------------------------------
// broadcast_subscriber_count
// ---------------------------------------------------------------------------

/// Returns the number of subscribers in a broadcast context.
#[must_use]
pub fn broadcast_subscriber_count(cell: &mut ClassSCell) -> Option<usize> {
    cell.broadcast_context
        .as_ref()
        .map(BroadcastContext::subscriber_count)
}

// ---------------------------------------------------------------------------
// is_broadcast_subscriber
// ---------------------------------------------------------------------------

/// Returns `true` if the given DID is a subscriber in a broadcast context.
#[must_use]
pub fn is_broadcast_subscriber(cell: &mut ClassSCell, did: &str) -> bool {
    cell.broadcast_context
        .as_ref()
        .is_some_and(|bc| bc.is_subscriber(did))
}

// ---------------------------------------------------------------------------
// broadcast_admission
// ---------------------------------------------------------------------------

/// Returns the admission policy for a broadcast context.
#[must_use]
pub fn broadcast_admission(cell: &mut ClassSCell) -> Option<BroadcastAdmission> {
    cell.broadcast_context
        .as_ref()
        .map(BroadcastContext::admission)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn emit_event(
    receive_buffer: &mut scp_protocol::context::membership::ReceiveBuffer,
    event: ContextEvent,
    context_id: &str,
    tx: Option<&tokio::sync::broadcast::Sender<(String, ContextEvent)>>,
) {
    if matches!(event, ContextEvent::WelcomeGenerated { .. }) {
        let _ = receive_buffer.push(event);
        return;
    }

    let _ = receive_buffer.push(event.clone());
    if let Some(tx) = tx {
        let sanitized = strip_event_payload(&event);
        let _ = tx.send((context_id.to_owned(), sanitized));
    }
}

fn persist_broadcast_snapshot(
    deps: &ActorDeps,
    context_id: &str,
    snapshot: &scp_protocol::context::broadcast::BroadcastContextSnapshot,
) {
    if let Err(e) = deps.persistence.persist_broadcast(context_id, snapshot) {
        tracing::warn!(
            context_id = %context_id,
            error = %e,
            "failed to persist broadcast snapshot"
        );
    }
}

/// Best-effort persist of the current actor state. Mirrors
/// the legacy context-snapshot persistence path, but reads fields from actor
/// state rather than the old lock-shaped state.
fn persist_state_best_effort(state: &PerContextState, deps: &ActorDeps, context_id: &str) {
    let mut snapshot = build_snapshot_from_state(state);

    let ctx_id_bytes = context_id_to_bytes(context_id);
    match deps.crypto.export_crypto_state(&ctx_id_bytes) {
        Ok(crypto_state) => snapshot.mls_crypto_state = crypto_state,
        Err(e) => {
            snapshot.needs_reconnect = true;
            snapshot.mls_crypto_state = Vec::new();
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "failed to export MLS crypto state for persistence; \
                 snapshot marked needs_reconnect=true so restore \
                 fires the §23.11 reconnection pipeline"
            );
        }
    }

    if let Err(e) = deps.persistence.persist_context(context_id, &snapshot) {
        crate::metrics::record_persistence_failure();
        tracing::warn!(
            context_id = %context_id,
            error = %e,
            "failed to persist context snapshot"
        );
    }
}

fn build_snapshot_from_state(state: &PerContextState) -> crate::context::state::ContextSnapshot {
    use crate::context::state::VelocityTrackerSnapshot;
    use scp_protocol::context::ContextState;

    let context_state_value = state
        .handle
        .try_read_state()
        .unwrap_or(ContextState::Active);
    let ttl_remaining_secs = state.ttl.timer.remaining_secs();
    let grace_entries = state.epoch.grace_store.to_grace_entries();

    crate::context::state::ContextSnapshot {
        context_id: state.handle.context_id().to_owned(),
        creation_timestamp_secs: state.creation_timestamp_secs,
        state: context_state_value,
        context_params: state.handle.params().clone(),
        membership: state.membership.clone(),
        role_state: state.role_state.clone(),
        event_log_merkle_root: [0u8; 32],
        executed_proposals: state
            .governance
            .class_s
            .executed_proposals
            .keys()
            .copied()
            .collect(),
        ttl_remaining_secs,
        registered_tools: state.governance.registered_tools.clone(),
        read_exclusion_list: state.access.read_exclusion_list.clone(),
        tool_interfaces: state.governance.tool_interfaces.clone(),
        threshold_signers: state.governance.class_s.threshold_signers.clone(),
        threshold_value: state.governance.class_s.threshold_value,
        pruning_policy: state.governance.pruning_policy.clone(),
        governance_model_config: Some(state.governance.engine.model_config()),
        economic_policy: state.governance.economic_policy.clone(),
        budget_tracker: state.governance.budget_tracker.clone(),
        approved_proposals: state.governance.approved_proposals.clone(),
        next_proposal_seq: state.governance.next_proposal_seq,
        governance_freeze: state.governance.freeze,
        pending_ceiling_modification: state.governance.pending_ceiling_modification.clone(),
        pending_economic_policy_change: state.governance.pending_economic_policy_change.clone(),
        mls_epoch: state.epoch.mls_epoch,
        epoch_coordination_records: state.epoch.coordinator.records().to_vec(),
        grace_entries,
        needs_reconnect: state.epoch.needs_reconnect,
        mls_crypto_state: Vec::new(),
        migration_state: state.migration_state.clone(),
        access_key_store: state.access.access_key_store.clone(),
        consequence_rules: state.governance.consequence_rules.clone(),
        participation_cache: state.governance.participation_cache.clone(),
        velocity_tracker: Some(state.governance.velocity_tracker.window_secs()),
        velocity_tracker_state: Some(VelocityTrackerSnapshot {
            window_secs: state.governance.velocity_tracker.window_secs(),
            entries: state.governance.velocity_tracker.snapshot_entries(),
        }),
        cooldown_until: state.governance.cooldown_until.clone(),
        proposal_timestamps: state.governance.proposal_timestamps.clone(),
        message_pricing: state.governance.message_pricing.clone(),
        hard_rate_limit_config: Some(state.governance.hard_rate_limit.config().clone()),
        hard_rate_limit_state: state.governance.hard_rate_limit.snapshot_entries(),
        spending_nonce_tracker_state: state
            .governance
            .class_s
            .spending_nonce_tracker
            .snapshot_entries(),
        revoked_spending_ucan_cids: state.governance.revoked_spending_ucan_cids.clone(),
        pending_commits: state.pending_commits.clone(),
        commit_fault: state.commit_fault.clone(),
        checkpoint_events_since: state.checkpoint_events_since,
        checkpoint_last_time_secs: state.checkpoint_last_time_secs,
        generation: state.generation,
        routing: state.routing.clone(),
        // ADR-049 §9 Class S (line 144): persist the staged saga slot
        // through its sanctioned mirror via the shared helper.
        saga_pending: crate::context::messaging_helpers::saga_pending_snapshot(state),
        xctx_committed_outputs: crate::context::messaging_helpers::xctx_committed_outputs_snapshot(
            state,
        ),
        xctx_committed_invocations:
            crate::context::messaging_helpers::xctx_committed_invocations_snapshot(state),
        xctx_caller_reservations:
            crate::context::messaging_helpers::xctx_caller_reservations_snapshot(state),
        xctx_nonce_dedup: crate::context::messaging_helpers::xctx_nonce_dedup_snapshot(state),
    }
}
