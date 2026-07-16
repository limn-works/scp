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
//! The pre-migration `&Supervisor` lock-and-call bodies have been removed
//! (Phase 2A finalization); this module is the sole home for these helpers.
//!
//! Publish helpers are actor-shaped here for parity with the domain surface,
//! but the actor mailbox still rejects publish commands: `KeyCustody` uses
//! RPITIT and cannot cross the mailbox as a trait object. During the migration
//! window publish dispatch stays on the generic supervisor shim.

use std::hash::BuildHasher;

use scp_did::DID;
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
pub async fn subscribe_broadcast<D, N, R, P, S>(
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

    // Governance-ban admission gate (spec §5.14.4 / §5.14.8, #2088), fail-closed
    // BEFORE any roster mutation or `MemberJoined` leaf.
    //
    // AUTHORITATIVE check: the durable `banned_subscribers` record on the
    // broadcast context. A governance ban (`execute_revoke{Read}` →
    // `governance_ban_subscriber`) removes the DID from the roster AND records it
    // here; this record is INDEPENDENT of the subscriber registry and of
    // `read_exclusion_list`, and is cleared ONLY by an authority via
    // `RestoreAccess` — so it survives the banned subject's OWN self-leave and a
    // subsequent admin `RemoveMember` (both of which clear `read_exclusion_list`
    // for §5.6.1/§5.9 hygiene). This closes the replay-after-leave laundering the
    // review found: a banned DID that self-leaves to clear its exclusion still
    // cannot re-subscribe by replaying a retained `messages:read` UCAN. (The
    // protocol `subscribe` also enforces this by construction; this is the early,
    // uniform-reason gate.)
    //
    // DEFENSE-IN-DEPTH: `read_exclusion_list` still catches a STILL-PRESENT
    // read-revoked member (§5.9 keeps them a member; they are excluded from CEK
    // wrapping but not yet in `banned_subscribers` if never a broadcast
    // subscriber). Both return the uniform
    // [`SUBSCRIBE_DENY_REASON`](scp_protocol::context::broadcast::SUBSCRIBE_DENY_REASON)
    // so the rejection does not disclose ban status.
    if cell
        .broadcast_context
        .as_ref()
        .is_some_and(|bc| bc.is_banned(subscriber_did.as_ref()))
    {
        return Err(ContextError::PermissionDenied(
            scp_protocol::context::broadcast::SUBSCRIBE_DENY_REASON.to_owned(),
        ));
    }
    if cell.access.read_exclusion_list.contains(subscriber_did) {
        return Err(ContextError::PermissionDenied(
            scp_protocol::context::broadcast::SUBSCRIBE_DENY_REASON.to_owned(),
        ));
    }

    // All in-state mutations below are Class-C (broadcast subscriber roster
    // ADD, broadcast metadata, receive buffer, checkpoint counter) with the
    // best-effort persist below — routed through the non-persisting Class-C
    // view (ADR-049 §9). Member ADD is a structural Class-C op (the restricted
    // `MembershipClassCMut` exposes it; member REMOVAL is the downward-auth
    // Class-S op it withholds — see `unsubscribe_broadcast`).
    let result = {
        let mut view = cell.class_c_view();
        let mut bc = view
            .broadcast_class_c_mut()
            .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;

        bc.subscribe(subscriber_did, ucan, timestamp, validation_ctx)?
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

    // Broadcast roster state now rides the Class-S `ContextSnapshot`; the
    // whole-snapshot best-effort persist below covers it. Subscribe/unsubscribe
    // are roster ADD/REMOVE with no key secrecy, best-effort by design (§9 carve).
    persist_state_best_effort(cell, deps, context_id).await;

    // Subject-bearing leaf (ADR-011 amendment): carry the subscriber
    // (`subscriber_did`, which on a self-subscribe already equals `actor_did`)
    // and the "subscriber" role, so the leaf shape is uniform with member
    // joins and the SDK reads `subject_did` consistently. The participation
    // record (§7.3.2) attributes the join interval to this subject.
    //
    // Committer-assigned: the subscriber's signed subscribe-request timestamp,
    // copied by every member (§7.3.1, §9.9.3).
    deps.event_log
        .append_membership_change_leaf(
            &context_id_bytes,
            scp_event_log::EventType::MemberJoined,
            subscriber_did.as_ref(),
            subscriber_did.as_ref(),
            "subscriber",
            timestamp,
        )
        .await?;
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
pub async fn unsubscribe_broadcast(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    subscriber_did: &DID,
    rotate_keys: bool,
) -> Result<UnsubscribeResult, ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&cell.handle)?;

    let result = {
        let mut view = cell.class_c_view();
        let mut bc = view
            .broadcast_class_c_mut()
            .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;

        bc.unsubscribe(subscriber_did, rotate_keys)?
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

    // Broadcast roster state now rides the Class-S `ContextSnapshot`; the
    // whole-snapshot best-effort persist below covers it. Subscribe/unsubscribe
    // are roster ADD/REMOVE with no key secrecy, best-effort by design (§9 carve).
    persist_state_best_effort(cell, deps, context_id).await;

    // Subject-bearing leaf (ADR-011 amendment): carry the unsubscribing
    // subscriber (`subscriber_did`, which already equals `actor_did` on this
    // self-unsubscribe path) and the "subscriber" role, so the leaf shape is
    // uniform with member leaves and the SDK reads `subject_did` consistently.
    //
    // Committer-assigned: the unsubscribing author's clock — the source of the
    // `created_at` on its outgoing leave message, copied by every member
    // (§7.3.1, §9.9.3).
    deps.event_log
        .append_membership_change_leaf(
            &context_id_bytes,
            scp_event_log::EventType::MemberLeft,
            subscriber_did.as_ref(),
            subscriber_did.as_ref(),
            "subscriber",
            deps.clock.now_secs(),
        )
        .await?;
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
        .suspended_for(author_did.as_ref())
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
    let mut bc = view
        .broadcast_class_c_mut()
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
pub async fn apply_broadcast_publish(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    reservation_id: &BroadcastReservationId,
    signature: &[u8],
    payload: &[u8],
) -> Result<BroadcastEnvelope, ContextError> {
    let routing_id = broadcast_publish_routing_id(context_id);

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
        &routing_id,
        &pending,
        signature,
        payload,
    )
    .await
}

/// Relay routing id under which a sealed broadcast envelope is published.
///
/// Broadcast routing is `SHA-256(context_id)` (no domain separator) per spec
/// §5.14.6 — the identical value the read side computes
/// (`scp_node::projection::compute_routing_id`,
/// `BroadcastRoutingId`/`ProjectedContext::routing_id`). It is deliberately
/// **NOT** `context_id_to_bytes` (the ADR-056 keying chokepoint, which DECODES
/// a real 64-hex id to its digest): for a real context id those two values
/// diverge (`SHA-256(hex(digest)) != digest`), so routing a publish through the
/// keying digest would store the blob at a relay slot no subscriber or
/// projection ever reads — the deploy then commits zero assets
/// (`scp-node` `host_site` `CommitCountMismatch { committed: 0, expected: N }`).
/// Routing through the canonical broadcast-routing primitive keeps publish and
/// projection addressing the SAME slot by construction.
fn broadcast_publish_routing_id(context_id: &str) -> [u8; 32] {
    scp_protocol::context::broadcast_routing_id(context_id)
}

/// Inner apply body. Separated so the caller-facing
/// [`apply_broadcast_publish`] can guarantee the reserved sequence is
/// released on every error path.
async fn apply_guarded(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    routing_id: &[u8; 32],
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
        .send_message(routing_id, &envelope_bytes)
        .await?;

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
    let mut bc = view
        .broadcast_class_c_mut()
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
    if let Some(mut bc) = cell.class_c_view().broadcast_class_c_mut() {
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
    if let Some(mut bc) = cell.class_c_view().broadcast_class_c_mut() {
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
pub async fn block_broadcast_subscriber(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    author_did: &DID,
    subscriber_did: &DID,
) -> Result<BlockResult, ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&cell.handle)?;

    // Fail-closed (ADR-049 §9, §5.14.8 block-before-serve). The block ADVANCES
    // the author key epoch and ADDS the subscriber to the author's block list — a
    // downward-authorization revocation. It MUST be durable BEFORE the block is
    // acked: an actor crash in the coalesce window after a best-effort ack would
    // roll the epoch advance + block-list insert back and silently RE-GRANT the
    // revoked subscriber post-block key access (encryption-as-access-control
    // violation). Route the mutation through the fail-closed KEEP combinator: on a
    // persist failure the in-memory block is RETAINED (un-blocking is the unsafe
    // direction) and the error propagates so the caller never observes a
    // non-durable block — BEFORE any MemberBlocked event-log append or ack. The
    // broadcast state now rides the Class-S `ContextSnapshot`, so this persist is
    // atomic with `read_exclusion_list` in one row.
    let result = cell
        .commit_class_s_keep(deps, context_id, |mut view| {
            let bc =
                view.rest_mut().broadcast_context.as_mut().ok_or_else(|| {
                    ContextError::MembershipFailed("not a broadcast context".into())
                })?;
            bc.block_subscriber(author_did, subscriber_did)
        })
        .await?;

    // Durable — now emit the MemberBlocked receive-buffer event + Merkle leaf.
    emit_event(
        cell.class_c_view().receive_buffer_mut(),
        ContextEvent::MemberBlocked {
            blocked_did: subscriber_did.clone(),
            author_did: author_did.clone(),
        },
        context_id,
        deps.event_tx.as_ref(),
    );

    let block_ts = deps.clock.now_secs();
    deps.event_log
        .append_context_event(
            &context_id_bytes,
            scp_event_log::EventType::MemberBlocked,
            author_did.as_ref(),
            // Committer-assigned: the blocking author's clock — the source of the
            // `created_at` on its outgoing block message, copied by every member
            // (§7.3.1, §9.9.3).
            block_ts,
        )
        .await?;

    // ADR-007 §5: blocking a subscriber rotates the author's sender-key epoch.
    // Append the KeyEpochAdvance leaf immediately after MemberBlocked so the
    // two leaves are always co-located in the Merkle log. rotate_sender_key_for_block
    // always increments by exactly 1, so old = new.saturating_sub(1) is exact.
    let old_epoch = result.new_epoch.saturating_sub(1);
    match scp_event_log::payload::encode_payload(&scp_event_log::payload::KeyEpochAdvancedPayload {
        old_epoch,
        new_epoch: result.new_epoch,
    }) {
        Ok(payload) => {
            if let Err(e) = deps
                .event_log
                .append_context_event_with_payload(
                    &context_id_bytes,
                    scp_event_log::EventType::KeyEpochAdvance,
                    author_did.as_ref(),
                    payload,
                    block_ts,
                )
                .await
            {
                tracing::warn!(
                    context_id = %context_id,
                    error = %e,
                    "KeyEpochAdvance event-log append failed (best-effort)"
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "KeyEpochAdvance payload encode failed (best-effort)"
            );
        }
    }
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
pub async fn unblock_broadcast_subscriber(
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
    // Unblock is an UPWARD authorization change (block-list REMOVE, re-grants
    // access) and does NOT rotate keys (§9.16.8), so best-effort persistence is
    // correct: a coalesce-window rollback re-instates the block (the safe
    // direction), never a spurious grant. Deliberately NOT tightened to
    // fail-closed — see the block-before-serve asymmetry (§5.14.8).
    {
        let mut view = cell.class_c_view();
        let mut bc = view
            .broadcast_class_c_mut()
            .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;

        let _result = bc.unblock_subscriber(author_did, subscriber_did)?;
    }

    emit_event(
        cell.class_c_view().receive_buffer_mut(),
        ContextEvent::MemberUnblocked {
            unblocked_did: subscriber_did.clone(),
            author_did: author_did.clone(),
        },
        context_id,
        deps.event_tx.as_ref(),
    );

    // Broadcast roster/block state rides the Class-S `ContextSnapshot`; the
    // whole-snapshot best-effort persist covers the block-list REMOVE.
    persist_state_best_effort(cell, deps, context_id).await;

    deps.event_log
        .append_context_event(
            &context_id_bytes,
            scp_event_log::EventType::MemberUnblocked,
            author_did.as_ref(),
            // Committer-assigned: the unblocking author's clock — the source of the
            // `created_at` on its outgoing unblock message, copied by every member
            // (§7.3.1, §9.9.3).
            deps.clock.now_secs(),
        )
        .await?;
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

    // Durable-ban serve-path gate (§5.14.8, #2088 / BLACK-303), fail-closed before
    // any grant. AUTHORITATIVE: the durable `banned_subscribers` record — the same
    // authority-only-clearable signal the subscribe-admission gate uses. This
    // catches a banned DID whom NEITHER other signal covers: a banned AUTHOR (the
    // context creator is always an author) is never on any block list (a
    // non-subscriber ban writes no block-list entry) and, once they self-leave,
    // is no longer in `read_exclusion_list`. `BroadcastContext::handle_key_request`
    // enforces this by construction for all callers; this early check keeps the
    // runtime serve path symmetric with subscribe. Uses the uniform reason
    // (non-leakage).
    if bc.is_banned(requester_did.as_ref()) {
        return Ok(KeyRequestDecision::Deny {
            reason: scp_protocol::context::broadcast::KEY_REQUEST_DENY_REASON.to_owned(),
        });
    }

    // Serve-path exclusion consult (defense-in-depth, §5.14.8 block-before-serve)
    // for a STILL-PRESENT read-revoked member: `read_exclusion_list` is written
    // fail-closed on `RevokeAccess{Read}` and consulted here before the per-author
    // block-list check. Unlike the durable ban above, this entry is CLEARED when
    // the subject self-leaves, so it is a defense-in-depth complement — NOT the
    // authoritative durable signal. Uses the SAME uniform deny reason (non-leakage).
    // Disjoint shared borrow of `cell.access` (a different field than
    // `broadcast_context`), so `bc` stays valid for the delegation below.
    if cell.access.read_exclusion_list.contains(requester_did) {
        return Ok(KeyRequestDecision::Deny {
            reason: scp_protocol::context::broadcast::KEY_REQUEST_DENY_REASON.to_owned(),
        });
    }

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

/// Best-effort persist of the current actor state. Mirrors
/// the legacy context-snapshot persistence path, but reads fields from actor
/// state rather than the old lock-shaped state.
fn persist_state_best_effort<'d, 'c>(
    state: &PerContextState,
    deps: &'d ActorDeps,
    context_id: &'c str,
) -> impl std::future::Future<Output = ()> + Send + use<'d, 'c> {
    let mut snapshot = build_snapshot_from_state(state);

    let ctx_id_bytes = context_id_to_bytes(context_id);
    // ADR-049 PR-6 (read-authority switch): the per-sender epoch + recv-sequence
    // floors are sourced from the AUTHORITATIVE Supervisor-owned Class-M registry
    // (`deps.supervisor.export_*`) and threaded into `export_crypto_state` as the
    // durable-blob params. ADR-049 PR-7 (SCP-CRYPTOMOVE-001): the export now runs
    // on the actor's `state` (was the provider); the X25519 wrapping keypair enters
    // as params from the retained `deps.crypto.wrapping_keypair()`, and the send
    // sequence is read from `state.send_tracker` inside the twin.
    let (wrapping_public_key, wrapping_secret_key) = deps.crypto.wrapping_keypair();
    match state.export_crypto_state(
        deps.supervisor.export_sender_key_epochs(&ctx_id_bytes),
        deps.supervisor.export_recv_sequence_floors(&ctx_id_bytes),
        wrapping_public_key,
        &*wrapping_secret_key,
    ) {
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

    async move {
        if let Err(e) = deps
            .persistence
            .persist_context(context_id, &snapshot)
            .await
        {
            crate::metrics::record_persistence_failure();
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "failed to persist context snapshot"
            );
        }
    }
}

fn build_snapshot_from_state(state: &PerContextState) -> crate::context::state::ContextSnapshot {
    // Single source of truth (ADR-049 §9): delegate to the canonical builder so
    // the broadcast Class-S fold and the field-round-trip tripwire cover every
    // persist path. This copy was value-identical to the canonical one.
    crate::context::messaging_helpers::build_snapshot_from_state(state)
}

#[cfg(test)]
mod broadcast_routing_tests {
    use super::broadcast_publish_routing_id;
    use crate::context::state::context_id_to_bytes;

    /// Regression guard (ADR-056 / spec §5.14.6): the broadcast publish path
    /// MUST address the relay under the broadcast ROUTING id
    /// (`SHA-256(context_id)`), NOT the canonical context-identity digest that
    /// `context_id_to_bytes` decodes for a real 64-hex id. Before this guard,
    /// `apply_broadcast_publish` routed the `send_message` slot through
    /// `context_id_to_bytes`. On `main` that incidentally equalled
    /// `SHA-256(id)`; ADR-056 broke the equality, so publish stored a blob at a
    /// slot the projection (`compute_routing_id` = `SHA-256(id)`) never reads —
    /// the self-host deploy then committed zero assets (`host_site`
    /// `CommitCountMismatch`). This test pins the routing primitive so a future
    /// edit that swaps it back to the keying digest fails fast, without a full
    /// HTTP/relay round-trip.
    #[test]
    fn broadcast_publish_routes_under_sha256_routing_id_not_keying_digest() {
        // A canonical id: lowercase-hex of a known 32-byte digest — exactly the
        // shape `generate_context_id` emits (`hex(32 random bytes)`).
        let digest: [u8; 32] = [
            0x05, 0xf9, 0x1c, 0x9f, 0x77, 0x21, 0x9f, 0xd7, 0x6e, 0xee, 0x2b, 0x7e, 0x07, 0x16,
            0x24, 0xf9, 0x1d, 0xf4, 0xc2, 0x11, 0x50, 0x71, 0xb4, 0xa6, 0x5b, 0x6b, 0xd8, 0x03,
            0x5c, 0xf4, 0x6b, 0xbe,
        ];
        let id = hex::encode(digest);
        assert_eq!(id.len(), 64, "fixture id must be a real 64-hex context id");

        // The keying chokepoint DECODES a real 64-hex id to its digest. For
        // such an id that decoded digest IS the id's own bytes — and is NOT
        // `SHA-256(id)`. This precondition is what makes the two slots diverge.
        assert_eq!(
            context_id_to_bytes(&id),
            digest,
            "a real 64-hex id resolves to its decoded digest (ADR-056 keying)"
        );
        let sha256_of_id = scp_protocol::context::context_id_bytes(&id);
        assert_ne!(
            sha256_of_id, digest,
            "test precondition: SHA-256(hex(digest)) must differ from the digest, \
             else publish-slot vs read-slot could not diverge"
        );

        // The publish path's routing slot MUST be the SHA-256 broadcast routing
        // id, matching the projection read side …
        let routing = broadcast_publish_routing_id(&id);
        assert_eq!(
            routing,
            scp_protocol::context::broadcast_routing_id(&id),
            "broadcast publish must route under the canonical broadcast routing id"
        );
        assert_eq!(
            routing, sha256_of_id,
            "broadcast routing id is SHA-256(context_id) per §5.14.6"
        );

        // … and MUST NOT be the ADR-056 keying digest (the bug this fixes).
        assert_ne!(
            routing,
            context_id_to_bytes(&id),
            "broadcast publish MUST NOT route under the keying digest — that stores \
             the blob at a slot no subscriber/projection reads (host_site CommitCountMismatch)"
        );
    }
}
