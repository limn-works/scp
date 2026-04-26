//! Legacy lock-shaped trust-recovery helpers — Phase 2A.1 fallback path.
//!
//! These helpers preserve the pre-migration body shape: they take
//! `&Supervisor`, lock the per-context `Mutex<PerContextState>` from
//! the supervisor's `contexts: Arc<DashMap<...>>` map, and operate on
//! the legacy lock-shaped [`crate::context::state::PerContextState`]
//! type. They exist as a fallback for
//! [`crate::context::supervisor::Supervisor::dispatch_trust_recovery_command`]
//! when no [`ContextActor`](crate::context::actor::ContextActor) is
//! registered for a context — the common case during the helper-
//! migration window before every context's actor is wired.
//!
//! # Lifetime
//!
//! Once Phase 2A finalization deletes the `Mutex<PerContextState>` map
//! and every context has a `ContextActor`, this entire module is
//! deleted and the supervisor's dispatcher returns
//! [`ContextError::ContextNotRegistered`] for any per-context command
//! without a registered actor.
//!
//! # Behaviour parity
//!
//! Each helper here is a byte-identical hoist of the pre-migration
//! body in [`crate::context::trust_recovery_helpers`] (now refactored
//! to actor-shape `(state, deps)` signatures). The hold-lock-across-
//! await pattern is preserved verbatim — narrowing changes lock-
//! ordering semantics and is intentionally avoided in the fallback
//! path.

#![allow(clippy::significant_drop_tightening)]

use scp_identity::DID;
use scp_protocol::context::ContextError;
use scp_protocol::context::governance::{
    CheckpointAttestationStatus, ContextCheckpoint, CosignedCheckpoint,
};

use crate::context::manager_methods;
use crate::context::manager_methods::PROVIDER_NOT_INITIALIZED as ATTACHED_EXPECT;
use crate::context::state::{context_id_to_bytes, require_active};
use crate::context::supervisor::Supervisor;

/// Legacy lock-shaped variant of
/// [`crate::context::trust_recovery_helpers::create_governance_checkpoint`].
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

/// Legacy lock-shaped variant of
/// [`crate::context::trust_recovery_helpers::add_checkpoint_cosignature`].
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

/// Legacy lock-shaped variant of
/// [`crate::context::trust_recovery_helpers::recovery_advance_epoch`].
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

/// Legacy lock-shaped variant of
/// [`crate::context::trust_recovery_helpers::recovery_send_notification`].
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

/// Legacy variant of
/// [`crate::context::trust_recovery_helpers::recovery_notify_contact`]
/// — same shape as the actor-side helper but routes the
/// `RecoverySendNotification` directly through the supervisor's
/// dispatcher (rather than through `SupervisorHandle`). Used by
/// `identity::recovery::ProductionRecoveryBackend` which holds a
/// supervisor `Arc` directly rather than an `ActorDeps` bundle.
pub async fn recovery_notify_contact_legacy(
    supervisor: &Supervisor,
    recovering_did: &str,
    contact_did: &str,
    payload: &[u8],
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<(), ContextError> {
    use crate::context::actor::commands::{
        RecoverySendNotificationPayload, SigningKeyBytes, TrustRecoveryCommand,
    };
    use std::sync::Arc;

    // Find a context where both the recovering DID and the contact DID
    // are members. Collect (key, Arc) pairs first to release DashMap
    // shard locks before awaiting per-context Mutexes.
    let shared_context_id = {
        let entries: Vec<(String, Arc<tokio::sync::Mutex<crate::context::state::PerContextState>>)> =
            supervisor
                .contexts_arc()
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
            // Contact notifications use sequence=4 (step 5 in recovery).
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
            reply_rx.await.map_err(|_| {
                ContextError::TransportFailed(
                    "recovery_notify_contact_legacy: oneshot reply channel closed".to_owned(),
                )
            })?
        }
        None => Err(ContextError::TransportFailed(format!(
            "no shared context found between {recovering_did} and {contact_did}"
        ))),
    }
}
