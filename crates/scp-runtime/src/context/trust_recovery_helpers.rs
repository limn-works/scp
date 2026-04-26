//! Trust-recovery helpers — actor-shape signatures
//! (ADR-049 Phase 2A.1, trust_recovery domain migration).
//!
//! # Purpose
//!
//! This module hosts the trust-recovery-domain helpers that the actor
//! handlers in [`crate::context::actor::handlers::trust_recovery`] call
//! to implement [`TrustRecoveryCommand`](crate::context::actor::commands::TrustRecoveryCommand).
//!
//! # Phase 2A.1 migration
//!
//! Helpers that mutate per-context state take
//! `(state: &mut PerContextState, deps: &ActorDeps, ...)`. Provider
//! access (clock, transport, event log, persistence, MLS crypto) flows
//! through `deps`; per-context state mutation flows through `state`.
//! Cross-context fan-out remains on the supervisor — see
//! [`recovery_notify_contact`] for the one helper that retains an
//! `&Supervisor` parameter for that reason.
//!
//! # Top-level helpers
//!
//! Per-context (state-owning):
//! [`create_governance_checkpoint`], [`add_checkpoint_cosignature`],
//! [`recovery_advance_epoch`], [`recovery_send_notification`].
//!
//! Cross-context (supervisor-shaped):
//! [`recovery_notify_contact`].
//!
//! # Not migrated as commands
//!
//! `verify_attestation`, `create_challenge`, `verify_challenge_response`
//! are pure-CPU helpers with no state mutation; they live elsewhere in
//! the runtime (DID resolver + clock only) and are not exercised through
//! the actor mailbox.

// Module-level allow — the legacy lock-shim helpers below preserve the
// hold-lock-across-await pattern from the pre-migration body verbatim,
// so narrowing changes lock-ordering semantics. Allowing the lint
// crate-locally on this module keeps the legacy hoist byte-identical.
#![allow(clippy::significant_drop_tightening)]

use std::sync::Arc;

use scp_identity::DID;
use scp_protocol::context::ContextError;
use scp_protocol::context::governance::{
    CheckpointAttestationStatus, ContextCheckpoint, CosignedCheckpoint,
};

use crate::context::actor::deps::ActorDeps;
use crate::context::actor::state::PerContextState;
use crate::context::manager_methods;
use crate::context::manager_methods::PROVIDER_NOT_INITIALIZED as ATTACHED_EXPECT;
use crate::context::state::{context_id_to_bytes, require_active};
use crate::context::supervisor::Supervisor;

// ---------------------------------------------------------------------------
// 1. create_governance_checkpoint
// ---------------------------------------------------------------------------

/// Creates a governance-aware checkpoint for a context. State-owning
/// signature: `state` carries the per-context governance/pruning policy
/// and lifecycle handle; `deps.clock` produces `created_at`;
/// `deps.event_log` performs best-effort log pruning when a pruning
/// policy is configured (#1474).
///
/// Mutation surface: this helper does NOT mutate `state` — the
/// checkpoint object is returned by value and any pruning is delegated
/// to the event-log provider (which owns its own storage). The handler
/// flags this as `mutated: true` only because pruning has external side
/// effects worth coalescing into the actor's persist tick.
#[allow(clippy::too_many_arguments)]
pub async fn create_governance_checkpoint(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    checkpoint_seq: u64,
    merkle_root: [u8; 32],
    event_count: u64,
    last_event_hash: [u8; 32],
    state_snapshot_hash: [u8; 32],
    creator_did: &DID,
    creator_signature: Vec<u8>,
) -> Result<ContextCheckpoint, ContextError> {
    require_active(&state.handle)?;

    let (_, min_count) = state.governance.engine.checkpoint_cosignature_requirements();
    let attestation_status = if min_count == 0 {
        CheckpointAttestationStatus::FullyAttested
    } else {
        CheckpointAttestationStatus::PartiallyAttested
    };

    // Capture pruning policy snapshot for the optional pruning step.
    let pruning_policy = state.governance.pruning_policy.clone();

    let created_at = deps.clock.now_secs();

    let checkpoint = ContextCheckpoint {
        checkpoint_seq,
        merkle_root,
        event_count,
        last_event_hash,
        state_snapshot_hash,
        created_at,
        creator_did: creator_did.clone(),
        creator_signature,
        cosignatures: Vec::new(),
        attestation_status,
    };

    // Trigger event log pruning if a pruning policy is configured on the
    // context (#1474). Best-effort: log but do not fail the checkpoint
    // creation if pruning encounters an error.
    if let Some(ref policy) = pruning_policy {
        let context_id_bytes = context_id_to_bytes(context_id);
        if deps
            .event_log
            .prune_before_checkpoint(&context_id_bytes, event_count, policy)
            .is_some_and(|pruned| pruned > 0)
        {
            tracing::info!(
                context_id = %context_id,
                checkpoint_seq = checkpoint_seq,
                "pruned event log entries after governance checkpoint"
            );
        }
    }

    Ok(checkpoint)
}

// ---------------------------------------------------------------------------
// 2. add_checkpoint_cosignature
// ---------------------------------------------------------------------------

/// Adds a cosignature to an existing checkpoint and re-evaluates
/// attestation status.
///
/// State-owning signature: reads the per-context governance engine
/// from `state.governance.engine` to call
/// `validate_checkpoint_cosignatures`. Does NOT mutate `state` — only
/// the caller-owned `checkpoint` argument is mutated, and only after
/// validation succeeds (the candidate-vector pattern preserves
/// transactional integrity).
pub async fn add_checkpoint_cosignature(
    state: &mut PerContextState,
    _deps: &ActorDeps,
    checkpoint: &mut ContextCheckpoint,
    cosignature: CosignedCheckpoint,
) -> Result<CheckpointAttestationStatus, ContextError> {
    use sha2::Digest as _;

    // Validate with a candidate vector first — only mutate checkpoint
    // after validation passes to avoid leaving corrupt state on error.
    let mut candidate = checkpoint.cosignatures.clone();
    candidate.push(cosignature);

    // Compute checkpoint hash for verification.
    let mut hasher = sha2::Sha256::new();
    hasher.update(checkpoint.merkle_root);
    hasher.update(checkpoint.checkpoint_seq.to_be_bytes());
    hasher.update(checkpoint.event_count.to_be_bytes());
    let checkpoint_hash: [u8; 32] = hasher.finalize().into();

    let status = state
        .governance
        .engine
        .validate_checkpoint_cosignatures(&candidate, &checkpoint_hash)
        .map_err(|e| ContextError::GovernanceFailed(e.to_string()))?;

    // Validation passed — commit the mutation.
    checkpoint.cosignatures = candidate;
    checkpoint.attestation_status = status.clone();
    Ok(status)
}

// ---------------------------------------------------------------------------
// 3. recovery_advance_epoch
// ---------------------------------------------------------------------------

/// Advances the MLS epoch for a context as part of compromise recovery
/// (spec §9.12 step 2).
///
/// State-owning signature: increments `state.epoch.mls_epoch` and
/// pushes the old epoch into `state.epoch.grace_store`; bumps
/// `state.checkpoint_events_since`. The MLS Commit is broadcast via
/// `deps.transport`; the epoch-advancement event is appended via
/// `deps.event_log`.
///
/// # No relock / generation gate
///
/// The legacy version dropped the per-context lock around the MLS
/// epoch advance and reacquired it with a generation check. The actor
/// owns `state` for the entire dispatch turn, so the generation check
/// is unnecessary — there is no concurrent close-and-recreate window
/// to defend against. The `require_active` check is preserved across
/// the await because a saga-driven Pause/Closing transition could land
/// on the actor's mailbox between awaits, but the ordering of mailbox
/// commands means a `LifecycleControl::Pause` would have already
/// completed by the time we resume here. Re-checking is defense-in-depth.
pub async fn recovery_advance_epoch(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
) -> Result<u64, ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    // 1. Validate the context is active.
    require_active(&state.handle)?;

    // 2. Perform the MLS epoch advance (Update + self-Commit). Operates
    //    on the supervisor-scoped `MlsCryptoProvider` contexts map; this
    //    will move onto `state.mode` directly when the MLS provider
    //    dissolves (plan §"MlsCryptoProvider dissolution"). If this
    //    fails the bookkeeping counter is NOT incremented.
    let epoch_output = deps.crypto.advance_epoch(&context_id_bytes)?;

    // 2b. Broadcast the MLS Commit to all members so they can advance
    //     their group epoch and ratchet key material.
    if !epoch_output.commit_bytes.is_empty() {
        let routing_id = scp_protocol::context::context_routing_id(context_id);
        if let Err(e) = deps.transport.send_message(&routing_id, &epoch_output.commit_bytes) {
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "failed to broadcast recovery epoch advance MLS Commit"
            );
        }
    }

    // 3. Re-validate after the crypto op to close the TOCTOU window
    //    between the active check in step 1 and the counter increment
    //    here. The actor owns `state`, but a `LifecycleControl::Pause`
    //    delivered between awaits would have flipped the lifecycle —
    //    however the mailbox ordering serializes commands, so this is
    //    defense-in-depth.
    require_active(&state.handle)?;

    // 4. Increment bookkeeping counter and manage grace store.
    let old_epoch = state.epoch.mls_epoch;
    state.epoch.mls_epoch = old_epoch.saturating_add(1);
    let _expired = state.epoch.grace_store.add_epoch(old_epoch);
    let new_epoch = state.epoch.mls_epoch;

    // 5. Emit epoch advancement event to event log. Event log failures
    //    are non-fatal — recovery must not be blocked by logging issues.
    if let Err(e) = deps.event_log.append_context_event(
        &context_id_bytes,
        "recovery/epoch_advanced",
        "system:recovery",
    ) {
        tracing::warn!(
            context_id = %context_id,
            error = %e,
            "failed to append recovery epoch advancement event to event log"
        );
    }
    state.checkpoint_events_since += 1;

    // 6. Persist if configured (best-effort). The actor's coalesced
    //    persist arm of the `tokio::select!` loop will catch this on
    //    the next 50ms tick anyway, but the legacy path persisted
    //    inline — preserve that timing for behaviour parity.
    persist_state_best_effort(state, deps, context_id);

    Ok(new_epoch)
}

// ---------------------------------------------------------------------------
// 4. recovery_send_notification
// ---------------------------------------------------------------------------

/// Sends an encrypted message to a context for recovery notification
/// purposes (spec §9.12 step 5).
///
/// State-owning signature: reads `state.epoch.mls_epoch` for envelope
/// construction and `deps.clock` for the timestamp. Sealing routes
/// through `deps.crypto` (still supervisor-scoped during the migration
/// window); transport delivery via `deps.transport`. Does NOT mutate
/// `state`.
pub async fn recovery_send_notification(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    sender_did: &str,
    payload: &[u8],
    sequence: u64,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<(), ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    // Look up the current MLS epoch from owned state. Receivers validate
    // the message against their local epoch state.
    let current_epoch = state.epoch.mls_epoch;

    // Construct a minimal inner envelope for the recovery notification.
    // Recovery notifications bypass the full send_message pipeline but
    // still go through the envelope crypto layer (seal).
    let timestamp = deps.clock.now_millis();
    let params = scp_protocol::envelope::inner::InnerEnvelopeParams {
        version: scp_protocol::envelope::SCP_PROTOCOL_VERSION,
        context_id,
        sender_did,
        epoch: current_epoch,
        generation: 0,
        sequence,
        timestamp,
        message_type: scp_protocol::envelope::inner::MessageType::Recovery,
        payload,
        provenance: None,
        signing_key_id: scp_protocol::identity::SigningKeyId::Active,
    };

    let inner = crate::envelope::inner::sign::create_inner_envelope_raw(&params, signing_key)
        .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

    // Use domain-separated routing ID for relay routing, distinct from
    // the raw context_id_bytes used for MLS crypto keying.
    let routing_id = scp_protocol::context::context_routing_id(context_id);
    let encrypted = deps.crypto.seal(
        &context_id_bytes,
        &inner,
        &routing_id,
        300, // 5 minute blob TTL
    )?;

    // Send via transport using the domain-separated routing ID.
    deps.transport.send_message(&routing_id, &encrypted)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// 5. recovery_notify_contact (cross-context — supervisor-shaped)
// ---------------------------------------------------------------------------

/// Sends a recovery notification to a contact DID by finding shared
/// contexts between the recovering DID and the contact DID
/// (spec §9.12 step 5 — context not yet known).
///
/// # Cross-context fan-out
///
/// This helper is intrinsically cross-context: it scans every context
/// the supervisor manages to find the first one where both the
/// recovering DID and the contact DID are members. The actor model
/// forbids one actor reaching another's state directly — but this
/// scan is a read-only enumeration that legitimately belongs to the
/// supervisor. It therefore retains the `&Supervisor` parameter.
///
/// Once the shared context is found, the notification is dispatched
/// through the supervisor's `dispatch_trust_recovery_command` mailbox
/// path, which routes a `RecoverySendNotification` command to the
/// target context's actor. This preserves the per-actor mailbox
/// discipline for the actual mutation (envelope creation + transport
/// send), while the cross-context lookup remains supervisor-scoped.
///
/// # Migration trajectory
///
/// Phase 2A keeps the supervisor-side scan over the `contexts: Arc<DashMap<...>>`
/// map (the per-context `Mutex<PerContextState>`s still exist during
/// the helper-migration window). Once Phase 2A finalization deletes
/// the `Mutex<PerContextState>` map and replaces it with one
/// `ContextActor` per context, this scan becomes a fan-out over the
/// actor map asking each actor's mailbox for membership state. That
/// rewrite lands with Phase 2A finalization (after all 10 helper
/// domains migrate); the structural shape here remains correct
/// across the transition.
pub async fn recovery_notify_contact(
    supervisor: &Supervisor,
    recovering_did: &str,
    contact_did: &str,
    payload: &[u8],
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<(), ContextError> {
    let contexts = supervisor.contexts_arc();
    // Find a context where both the recovering DID and the contact DID
    // are members. The first matching context is used for delivery.
    // Collect (key, Arc) pairs first to release DashMap shard locks
    // before awaiting per-context Mutexes. Holding a DashMap Ref across
    // .await would deadlock any concurrent shard access.
    let shared_context_id = {
        let entries: Vec<(String, Arc<tokio::sync::Mutex<crate::context::state::PerContextState>>)> =
            contexts
                .iter()
                .map(|entry| (entry.key().clone(), Arc::clone(entry.value())))
                .collect();
        let mut found = None;
        for (context_id, arc) in entries {
            let ctx = arc.lock().await;
            if ctx.membership.contains(recovering_did) && ctx.membership.contains(contact_did) {
                found = Some(context_id);
                break;
            }
        }
        found
    };

    match shared_context_id {
        Some(context_id) => {
            // Dispatch a `RecoverySendNotification` command through the
            // supervisor's mailbox routing. When an actor exists for the
            // target context, the command crosses the actor mailbox and
            // the per-context state-owning helper above runs inside the
            // actor's dispatch turn. When no actor is registered (legacy
            // shim window), the supervisor's fallback path will pick up
            // the per-context Arc directly.
            //
            // Contact notifications use sequence=4 (step 5 in recovery).
            use crate::context::actor::commands::{
                RecoverySendNotificationPayload, SigningKeyBytes, TrustRecoveryCommand,
            };
            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
            let payload_box = Box::new(RecoverySendNotificationPayload {
                context_id,
                sender_did: recovering_did.to_owned(),
                payload: payload.to_vec(),
                sequence: 4,
                signing_key: SigningKeyBytes::from_signing_key(signing_key),
            });
            let cmd = TrustRecoveryCommand::RecoverySendNotification {
                payload: payload_box,
                reply: reply_tx,
            };
            supervisor.dispatch_trust_recovery_command(cmd).await?;
            reply_rx
                .await
                .map_err(|_| {
                    ContextError::TransportFailed(
                        "recovery_notify_contact: oneshot reply channel closed".to_owned(),
                    )
                })?
        }
        None => Err(ContextError::TransportFailed(format!(
            "no shared context found between {recovering_did} and {contact_did}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Legacy lock-shaped helpers (Phase 2A.1 fallback path)
// ---------------------------------------------------------------------------
//
// These helpers preserve the pre-migration body shape — they take
// `&Supervisor`, lock the per-context `Mutex<PerContextState>` from the
// supervisor's `contexts: Arc<DashMap<...>>` map, and operate on the
// legacy lock-shaped `state::PerContextState` type. They exist as a
// fallback for [`Supervisor::dispatch_trust_recovery_command`] when no
// `ContextActor` is registered for a context — the common case during
// the helper-migration window before every context's actor is wired.
//
// Once Phase 2A finalization deletes the
// `Mutex<PerContextState>` map and every context has a `ContextActor`,
// these legacy helpers are deleted and the supervisor's dispatcher
// returns `ContextNotRegistered` for any per-context command without a
// registered actor.

/// Legacy lock-shaped variant of [`create_governance_checkpoint`].
/// Operates on the supervisor's per-context `Mutex<PerContextState>`
/// rather than actor-owned state.
#[allow(clippy::too_many_arguments)]
pub async fn create_governance_checkpoint_legacy(
    supervisor: &Supervisor,
    context_id: &str,
    checkpoint_seq: u64,
    merkle_root: [u8; 32],
    event_count: u64,
    last_event_hash: [u8; 32],
    state_snapshot_hash: [u8; 32],
    creator_did: &DID,
    creator_signature: Vec<u8>,
) -> Result<ContextCheckpoint, ContextError> {
    let clock = supervisor
        .clock_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let event_log = supervisor
        .event_log_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let ctx_arc = manager_methods::get_context_arc(supervisor, context_id)
        .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
    let guard = ctx_arc.lock().await;
    let ctx = &*guard;
    require_active(&ctx.handle)?;

    let (_, min_count) = ctx.governance.engine.checkpoint_cosignature_requirements();
    let attestation_status = if min_count == 0 {
        CheckpointAttestationStatus::FullyAttested
    } else {
        CheckpointAttestationStatus::PartiallyAttested
    };

    // Capture pruning policy before dropping the lock.
    let pruning_policy = ctx.governance.pruning_policy.clone();

    let created_at = clock.now_secs();

    let checkpoint = ContextCheckpoint {
        checkpoint_seq,
        merkle_root,
        event_count,
        last_event_hash,
        state_snapshot_hash,
        created_at,
        creator_did: creator_did.clone(),
        creator_signature,
        cosignatures: Vec::new(),
        attestation_status,
    };

    if let Some(ref policy) = pruning_policy {
        let context_id_bytes = context_id_to_bytes(context_id);
        if event_log
            .prune_before_checkpoint(&context_id_bytes, event_count, policy)
            .is_some_and(|pruned| pruned > 0)
        {
            tracing::info!(
                context_id = %context_id,
                checkpoint_seq = checkpoint_seq,
                "pruned event log entries after governance checkpoint"
            );
        }
    }

    Ok(checkpoint)
}

/// Legacy lock-shaped variant of [`add_checkpoint_cosignature`].
pub async fn add_checkpoint_cosignature_legacy(
    supervisor: &Supervisor,
    context_id: &str,
    checkpoint: &mut ContextCheckpoint,
    cosignature: CosignedCheckpoint,
) -> Result<CheckpointAttestationStatus, ContextError> {
    use sha2::Digest as _;

    let ctx_arc = manager_methods::get_context_arc(supervisor, context_id)
        .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
    let guard = ctx_arc.lock().await;
    let ctx = &*guard;

    let mut candidate = checkpoint.cosignatures.clone();
    candidate.push(cosignature);

    let mut hasher = sha2::Sha256::new();
    hasher.update(checkpoint.merkle_root);
    hasher.update(checkpoint.checkpoint_seq.to_be_bytes());
    hasher.update(checkpoint.event_count.to_be_bytes());
    let checkpoint_hash: [u8; 32] = hasher.finalize().into();

    let status = ctx
        .governance
        .engine
        .validate_checkpoint_cosignatures(&candidate, &checkpoint_hash)
        .map_err(|e| ContextError::GovernanceFailed(e.to_string()))?;

    checkpoint.cosignatures = candidate;
    checkpoint.attestation_status = status.clone();
    Ok(status)
}

/// Legacy lock-shaped variant of [`recovery_advance_epoch`].
pub async fn recovery_advance_epoch_legacy(
    supervisor: &Supervisor,
    context_id: &str,
) -> Result<u64, ContextError> {
    let crypto = supervisor
        .crypto_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let transport = supervisor
        .transport_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let event_log = supervisor
        .event_log_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let context_id_bytes = context_id_to_bytes(context_id);

    // 1. Validate the context exists and is active (lock scoped).
    //    Capture generation for confused-deputy detection on reacquire.
    let ctx_gen = {
        let (guard, generation) = manager_methods::lock_context(supervisor, context_id).await?;
        let ctx = &*guard;
        require_active(&ctx.handle)?;
        generation
    };

    // 2. Perform the MLS epoch advance (Update + self-Commit).
    let epoch_output = crypto.advance_epoch(&context_id_bytes)?;

    // 2b. Broadcast the MLS Commit.
    if !epoch_output.commit_bytes.is_empty() {
        let routing_id = scp_protocol::context::context_routing_id(context_id);
        if let Err(e) = transport.send_message(&routing_id, &epoch_output.commit_bytes) {
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "failed to broadcast recovery epoch advance MLS Commit"
            );
        }
    }

    // 3. Increment bookkeeping counter and manage grace store.
    let new_epoch = {
        let mut guard = manager_methods::relock_context(supervisor, &ctx_gen).await?;
        let ctx = &mut *guard;
        require_active(&ctx.handle)?;
        let old_epoch = ctx.epoch.mls_epoch;
        ctx.epoch.mls_epoch = old_epoch.saturating_add(1);
        let _expired = ctx.epoch.grace_store.add_epoch(old_epoch);
        ctx.epoch.mls_epoch
    };

    // 4. Emit epoch advancement event to event log.
    if let Err(e) = event_log.append_context_event(
        &context_id_bytes,
        "recovery/epoch_advanced",
        "system:recovery",
    ) {
        tracing::warn!(
            context_id = %context_id,
            error = %e,
            "failed to append recovery epoch advancement event to event log"
        );
    }
    {
        if let Ok(mut guard) = manager_methods::relock_context(supervisor, &ctx_gen).await {
            let ctx = &mut *guard;
            ctx.checkpoint_events_since += 1;
        }
    }

    // 5. Persist if configured (best-effort).
    if manager_methods::has_persistence(supervisor)
        && let Ok(guard) = manager_methods::relock_context(supervisor, &ctx_gen).await
    {
        let ctx = &*guard;
        let snapshot = manager_methods::snapshot_context(ctx);
        manager_methods::persist_context_snapshot(supervisor, context_id, snapshot);
    }

    Ok(new_epoch)
}

/// Legacy lock-shaped variant of [`recovery_send_notification`].
pub async fn recovery_send_notification_legacy(
    supervisor: &Supervisor,
    context_id: &str,
    sender_did: &str,
    payload: &[u8],
    sequence: u64,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<(), ContextError> {
    let crypto = supervisor
        .crypto_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let transport = supervisor
        .transport_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let clock = supervisor
        .clock_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let context_id_bytes = context_id_to_bytes(context_id);

    let current_epoch = {
        if let Ok(arc) = manager_methods::get_context_arc(supervisor, context_id) {
            let ctx = arc.lock().await;
            ctx.epoch.mls_epoch
        } else {
            0
        }
    };

    let timestamp = clock.now_millis();
    let params = scp_protocol::envelope::inner::InnerEnvelopeParams {
        version: scp_protocol::envelope::SCP_PROTOCOL_VERSION,
        context_id,
        sender_did,
        epoch: current_epoch,
        generation: 0,
        sequence,
        timestamp,
        message_type: scp_protocol::envelope::inner::MessageType::Recovery,
        payload,
        provenance: None,
        signing_key_id: scp_protocol::identity::SigningKeyId::Active,
    };

    let inner = crate::envelope::inner::sign::create_inner_envelope_raw(&params, signing_key)
        .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

    let routing_id = scp_protocol::context::context_routing_id(context_id);
    let encrypted = crypto.seal(&context_id_bytes, &inner, &routing_id, 300)?;

    transport.send_message(&routing_id, &encrypted)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Best-effort persist of the current actor state. Called inline by
/// helpers whose legacy bodies persisted on every mutating operation;
/// the actor's coalesced persist arm catches non-inline mutations on
/// its 50ms tick.
///
/// Operates on an `ActorDeps`-shaped state. Mirrors the structure of
/// `manager_methods::persist_context_snapshot` but reads fields off
/// the actor's `PerContextState` rather than the legacy lock-shaped
/// type. The MLS crypto state export still goes through the
/// supervisor-scoped `MlsCryptoProvider` (matches the legacy path);
/// this collapses into `state.mode` after the MLS provider dissolution
/// in a later Phase 2 sub-chunk.
fn persist_state_best_effort(state: &PerContextState, deps: &ActorDeps, context_id: &str) {
    let mut snapshot = build_snapshot_from_state(state);

    // Export MLS crypto state alongside the context snapshot (#645).
    // AC3 bug 2: on export failure, mark the snapshot
    // `needs_reconnect = true` and persist an empty crypto blob.
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
        // Best-effort persistence: log but don't fail the operation.
        // In-memory state remains authoritative.
        crate::metrics::record_persistence_failure();
        tracing::warn!(
            context_id = %context_id,
            error = %e,
            "failed to persist context snapshot"
        );
    }
}

/// Builds a [`ContextSnapshot`](crate::context::state::ContextSnapshot)
/// from the actor's [`PerContextState`]. Field-for-field parallel to
/// [`crate::context::manager_methods::snapshot_context`]; consumes the
/// actor-owned `PerContextState` rather than the legacy lock-shaped
/// type.
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
        executed_proposals: state.governance.executed_proposals.keys().copied().collect(),
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
        // MLS crypto state is populated in `persist_state_best_effort`
        // where the crypto provider is available. Initialized empty here.
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
