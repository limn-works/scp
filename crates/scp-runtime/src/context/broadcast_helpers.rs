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
use scp_protocol::context::broadcast_content::{BroadcastContent, serialize_broadcast_content};
use scp_protocol::context::membership::ContextEvent;
use scp_protocol::context::roles::Capability;
use scp_protocol::crypto::sender_keys::BroadcastEnvelope;
use scp_protocol::crypto::ucan::UcanToken;
use scp_protocol::crypto::ucan::validate::{
    DidResolver, NonceTracker, ProofResolver, RevocationChecker, ValidationContext,
};

use crate::context::actor::deps::ActorDeps;
use crate::context::actor::state::PerContextState;
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
    state: &mut PerContextState,
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

    require_active(&state.handle)?;
    state
        .handle
        .params()
        .check_version_compatibility(scp_protocol::envelope::SCP_PROTOCOL_VERSION)?;

    let (result, snapshot) = {
        let bc = state
            .broadcast_context
            .as_mut()
            .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;

        let result = bc.subscribe(subscriber_did, ucan, timestamp, validation_ctx)?;
        let snapshot = bc.to_snapshot();
        (result, snapshot)
    };

    state
        .membership
        .add_member(subscriber_did.clone(), "subscriber".into(), vec![]);
    emit_event(
        state,
        result.event.clone(),
        context_id,
        deps.event_tx.as_ref(),
    );

    persist_broadcast_snapshot(deps, context_id, &snapshot);
    persist_state_best_effort(state, deps, context_id);

    deps.event_log.append_context_event(
        &context_id_bytes,
        "MemberJoined",
        subscriber_did.as_ref(),
    )?;
    state.checkpoint_events_since += 1;

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
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    subscriber_did: &DID,
    rotate_keys: bool,
) -> Result<UnsubscribeResult, ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&state.handle)?;

    let (result, snapshot) = {
        let bc = state
            .broadcast_context
            .as_mut()
            .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;

        let result = bc.unsubscribe(subscriber_did, rotate_keys)?;
        let snapshot = bc.to_snapshot();
        (result, snapshot)
    };

    state.membership.remove_member(subscriber_did);
    emit_event(
        state,
        ContextEvent::MemberLeft {
            member_did: subscriber_did.clone(),
        },
        context_id,
        deps.event_tx.as_ref(),
    );

    persist_broadcast_snapshot(deps, context_id, &snapshot);
    persist_state_best_effort(state, deps, context_id);

    deps.event_log.append_context_event(
        &context_id_bytes,
        "MemberLeft",
        subscriber_did.as_ref(),
    )?;
    state.checkpoint_events_since += 1;

    Ok(result)
}

// ---------------------------------------------------------------------------
// publish_broadcast
// ---------------------------------------------------------------------------

/// Publishes a message to a broadcast context using actor-owned state.
///
/// This helper is actor-shaped, but the Phase 2A mailbox path cannot call it
/// because `KeyCustody` is not `dyn`-safe. The supervisor shim continues to
/// use [`crate::context::broadcast_helpers_legacy::publish_broadcast_legacy`].
///
/// # Errors
///
/// - [`ContextError::ContextNotActive`] if the context is not `Active`.
/// - [`ContextError::MembershipFailed`] if the actor is not a broadcast
///   context.
/// - [`ContextError::PermissionDenied`] if the sender is not an author or
///   write access is suspended.
#[allow(
    dead_code,
    reason = "Actor-shaped publish helper is reserved until custody becomes mailbox-addressable; Phase 2A routes publish through the generic shim."
)]
pub async fn publish_broadcast(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    author_did: &DID,
    payload: &[u8],
    custody: &impl scp_platform::KeyCustody,
    signing_key_handle: &scp_platform::KeyHandle,
) -> Result<BroadcastEnvelope, ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&state.handle)?;

    if state
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
    let (_meta, nonce, signing_payload) = {
        let bc = state
            .broadcast_context
            .as_ref()
            .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;

        let meta = bc.publish_metadata(author_did)?;
        let nonce = scp_protocol::crypto::sender_keys::generate_broadcast_nonce();
        let provenance_hash = scp_protocol::crypto::sender_keys::compute_provenance_hash(None)
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;
        let signing_payload = scp_protocol::crypto::sender_keys::build_broadcast_signing_payload(
            &scp_protocol::crypto::sender_keys::SigningPayloadFields {
                version: scp_protocol::envelope::SCP_PROTOCOL_VERSION,
                context_id: meta.context_id,
                author_did: meta.author_did,
                sequence: meta.next_sequence,
                key_epoch: meta.key_epoch,
                timestamp,
                nonce: &nonce,
                provenance_hash: &provenance_hash,
            },
        )
        .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;
        (meta, nonce, signing_payload)
    };

    let platform_sig = custody
        .sign(signing_key_handle, &signing_payload)
        .await
        .map_err(|e| ContextError::CryptoFailed(format!("custody signing failed: {e}")))?;
    let sig_bytes: [u8; 64] = platform_sig.as_bytes().try_into().map_err(|_| {
        ContextError::CryptoFailed(format!(
            "custody signature has wrong length: expected 64, got {}",
            platform_sig.as_bytes().len()
        ))
    })?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    require_active(&state.handle)?;

    let envelope = {
        let bc = state
            .broadcast_context
            .as_mut()
            .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;
        let envelope = bc.publish(author_did, payload, timestamp, signature, &nonce, None)?;

        let seq = state
            .membership
            .next_sequence_number(author_did)
            .ok_or_else(|| ContextError::MemberNotFound(author_did.to_string()))?;
        emit_event(
            state,
            ContextEvent::MessageSent {
                sender_did: author_did.clone(),
                sequence_number: seq,
                payload: payload.to_vec(),
            },
            context_id,
            deps.event_tx.as_ref(),
        );

        envelope
    };

    let envelope_bytes = rmp_serde::to_vec_named(&envelope)
        .map_err(|e| ContextError::CryptoFailed(format!("envelope serialization: {e}")))?;
    deps.transport
        .send_message(&context_id_bytes, &envelope_bytes)?;

    deps.event_log
        .append_context_event(&context_id_bytes, "MessageSent", author_did.as_ref())?;
    state.checkpoint_events_since += 1;

    Ok(envelope)
}

// ---------------------------------------------------------------------------
// publish_broadcast_content
// ---------------------------------------------------------------------------

/// Publishes a [`BroadcastContent`] to a broadcast context.
///
/// See [`publish_broadcast`] for the custody migration note.
///
/// # Errors
///
/// Returns [`ContextError::CryptoFailed`] if content serialization fails, or
/// any error returned by [`publish_broadcast`].
#[allow(
    dead_code,
    reason = "Actor-shaped publish helper is reserved until custody becomes mailbox-addressable; Phase 2A routes publish through the generic shim."
)]
pub async fn publish_broadcast_content(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    author_did: &DID,
    content: BroadcastContent,
    custody: &impl scp_platform::KeyCustody,
    signing_key_handle: &scp_platform::KeyHandle,
) -> Result<BroadcastEnvelope, ContextError> {
    let payload = serialize_broadcast_content(&content)
        .map_err(|e| ContextError::CryptoFailed(format!("content serialization failed: {e}")))?;
    publish_broadcast(
        state,
        deps,
        context_id,
        author_did,
        &payload,
        custody,
        signing_key_handle,
    )
    .await
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
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    author_did: &DID,
    subscriber_did: &DID,
) -> Result<BlockResult, ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&state.handle)?;

    let (result, snapshot) = {
        let bc = state
            .broadcast_context
            .as_mut()
            .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;

        let result = bc.block_subscriber(author_did, subscriber_did)?;
        let snapshot = bc.to_snapshot();
        (result, snapshot)
    };

    emit_event(
        state,
        ContextEvent::MemberBlocked {
            blocked_did: subscriber_did.clone(),
            author_did: author_did.clone(),
        },
        context_id,
        deps.event_tx.as_ref(),
    );

    persist_broadcast_snapshot(deps, context_id, &snapshot);

    deps.event_log
        .append_context_event(&context_id_bytes, "MemberBlocked", author_did.as_ref())?;
    state.checkpoint_events_since += 1;

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
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    author_did: &DID,
    subscriber_did: &DID,
) -> Result<(), ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&state.handle)?;

    let snapshot = {
        let bc = state
            .broadcast_context
            .as_mut()
            .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;

        let _result = bc.unblock_subscriber(author_did, subscriber_did)?;
        bc.to_snapshot()
    };

    emit_event(
        state,
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
        "MemberUnblocked",
        author_did.as_ref(),
    )?;
    state.checkpoint_events_since += 1;

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
    state: &mut PerContextState,
    deps: &ActorDeps,
    author_did: &DID,
    requester_did: &DID,
) -> Result<KeyRequestDecision, ContextError> {
    if !deps.local_dids.load().contains(author_did) {
        return Err(ContextError::PermissionDenied(format!(
            "author DID is not controlled by the local node: {author_did}"
        )));
    }

    let bc = state
        .broadcast_context
        .as_ref()
        .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;

    Ok(bc.handle_key_request(author_did, requester_did))
}

// ---------------------------------------------------------------------------
// broadcast_subscriber_count
// ---------------------------------------------------------------------------

/// Returns the number of subscribers in a broadcast context.
#[must_use]
pub fn broadcast_subscriber_count(state: &mut PerContextState) -> Option<usize> {
    state
        .broadcast_context
        .as_ref()
        .map(BroadcastContext::subscriber_count)
}

// ---------------------------------------------------------------------------
// is_broadcast_subscriber
// ---------------------------------------------------------------------------

/// Returns `true` if the given DID is a subscriber in a broadcast context.
#[must_use]
pub fn is_broadcast_subscriber(state: &mut PerContextState, did: &str) -> bool {
    state
        .broadcast_context
        .as_ref()
        .is_some_and(|bc| bc.is_subscriber(did))
}

// ---------------------------------------------------------------------------
// broadcast_admission
// ---------------------------------------------------------------------------

/// Returns the admission policy for a broadcast context.
#[must_use]
pub fn broadcast_admission(state: &mut PerContextState) -> Option<BroadcastAdmission> {
    state
        .broadcast_context
        .as_ref()
        .map(BroadcastContext::admission)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn emit_event(
    state: &mut PerContextState,
    event: ContextEvent,
    context_id: &str,
    tx: Option<&tokio::sync::broadcast::Sender<(String, ContextEvent)>>,
) {
    if matches!(event, ContextEvent::WelcomeGenerated { .. }) {
        let _ = state.receive_buffer.push(event);
        return;
    }

    let _ = state.receive_buffer.push(event.clone());
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
        state: context_state_value,
        context_params: state.handle.params().clone(),
        membership: state.membership.clone(),
        role_state: state.role_state.clone(),
        executed_proposals: state
            .governance
            .executed_proposals
            .keys()
            .copied()
            .collect(),
        ttl_remaining_secs,
        registered_tools: state.governance.registered_tools.clone(),
        read_exclusion_list: state.access.read_exclusion_list.clone(),
        tool_interfaces: state.governance.tool_interfaces.clone(),
        threshold_signers: state.governance.threshold_signers.clone(),
        threshold_value: state.governance.threshold_value,
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
        spending_nonce_tracker_state: state.governance.spending_nonce_tracker.snapshot_entries(),
        pending_commits: state.pending_commits.clone(),
        commit_fault: state.commit_fault.clone(),
        checkpoint_events_since: state.checkpoint_events_since,
        checkpoint_last_time_secs: state.checkpoint_last_time_secs,
        generation: state.generation,
        local_pseudonym: state.local_pseudonym,
        pseudonym_registry: state
            .pseudonym_registry
            .iter()
            .map(|(did, p)| (did.to_string(), *p))
            .collect(),
    }
}
