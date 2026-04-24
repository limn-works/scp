// Module-level allow — the legacy inherent-impl form in
// `manager/trust_recovery.rs` carried `#[allow(clippy::significant_drop_tightening)]`
// on its impl block. The hoisted bodies preserve the same lock-hold-across-await
// patterns deliberately (narrowing changes lock-ordering semantics); allowing
// the lint crate-locally keeps the hoist byte-identical to the legacy behavior.
#![allow(clippy::significant_drop_tightening)]

//! Trust-recovery helpers with explicit-collaborator signatures
//! (ADR-049 §12c.3).
//!
//! # Purpose
//!
//! This module hoists the trust-recovery-domain methods that the actor
//! handlers in [`crate::context::actor::handlers::trust_recovery`] currently
//! reach via `view.manager().X(...)`. The hoist is a **pre-work** commit for
//! the actor handler body migration (later ADR-049 commits): handler bodies
//! cannot take `&ContextManager` — they take `&ActorDeps` and
//! `&mut PerContextState` — so the methods they call must accept explicit
//! collaborators rather than reaching through `self`.
//!
//! This file is the trust-recovery counterpart to
//! [`crate::context::messaging_helpers`] (12b.1, 12c.1, 12c.1b) and
//! [`crate::context::lifecycle_helpers`] (12c.2).
//!
//! # Behavior preservation
//!
//! Every hoisted free function is **behavior-preserving by construction**.
//! Its body is a verbatim copy of the legacy inherent method's body with
//! `self.X` replaced by either:
//!
//! - `mgr.X(...)` for remaining inherent methods on
//!   [`ContextManager`](crate::context::manager::ContextManager), or
//! - `mgr.X_ref()` / explicit collaborator parameters for fields.
//!
//! The legacy inherent methods on
//! [`ContextManager`](crate::context::manager::ContextManager) remain as
//! one-line forwarders; they are deleted alongside the outer shim in a
//! later ADR-049 commit when the actor handler bodies own the trust-
//! recovery path directly.
//!
//! # Top-level methods hoisted (actor-handler entry points)
//!
//! [`create_governance_checkpoint`], [`add_checkpoint_cosignature`],
//! [`recovery_advance_epoch`], [`recovery_send_notification`],
//! [`recovery_notify_contact`].
//!
//! # Not hoisted
//!
//! `verify_attestation`, `create_challenge`, `verify_challenge_response`
//! remain as inherent methods on [`ContextManager`]. They are pure-CPU
//! operations with no state mutation and are not migrated as actor
//! commands; the post-refactor architecture moves them off
//! `ContextManager` entirely (they only need a DID resolver + clock).

use std::sync::Arc;

use scp_identity::DID;
use scp_protocol::context::ContextError;
use scp_protocol::context::governance::{
    CheckpointAttestationStatus, ContextCheckpoint, CosignedCheckpoint,
};

use crate::context::manager::{
    ContextManager, PerContextState, context_id_to_bytes, require_active,
};
use crate::context::supervisor::Supervisor;

/// Shared expectation message for `Supervisor::attached_context_manager()`
/// inside helpers (ADR-049 commit 12c.9d).
const ATTACHED_EXPECT: &str = "trust_recovery_helpers: Supervisor must be fully attached before helper invocation \
     (set by Supervisor::attach_context_manager during bridge construction)";

// ---------------------------------------------------------------------------
// 1. create_governance_checkpoint
// ---------------------------------------------------------------------------

/// Creates a governance-aware checkpoint for a context (hoisted body of
/// the legacy
/// [`ContextManager::create_governance_checkpoint`](crate::context::manager::ContextManager::create_governance_checkpoint)).
///
/// See the legacy method's doc comment for the full semantics.
/// Byte-identical behavior.
#[allow(clippy::too_many_arguments)]
pub async fn create_governance_checkpoint(
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
    let mgr = supervisor
        .attached_context_manager()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let ctx_arc = mgr
        .get_context_arc(context_id)
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

    let created_at = mgr.clock_ref().now_secs();

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

    // Drop the contexts lock before pruning to avoid holding it during
    // potentially expensive I/O (persistence writes).

    // Trigger event log pruning if a pruning policy is configured on the
    // context (#1474). Best-effort: log but do not fail the checkpoint
    // creation if pruning encounters an error.
    if let Some(ref policy) = pruning_policy {
        let context_id_bytes = context_id_to_bytes(context_id);
        if mgr
            .event_log_ref()
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
/// attestation status (hoisted body of
/// [`ContextManager::add_checkpoint_cosignature`](crate::context::manager::ContextManager::add_checkpoint_cosignature)).
///
/// See the legacy method's doc comment for the full semantics.
/// Byte-identical behavior.
pub async fn add_checkpoint_cosignature(
    supervisor: &Supervisor,
    context_id: &str,
    checkpoint: &mut ContextCheckpoint,
    cosignature: CosignedCheckpoint,
) -> Result<CheckpointAttestationStatus, ContextError> {
    use sha2::Digest as _;

    let mgr = supervisor
        .attached_context_manager()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let ctx_arc = mgr
        .get_context_arc(context_id)
        .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
    let guard = ctx_arc.lock().await;
    let ctx = &*guard;

    // Validate with a candidate vector first — only mutate checkpoint
    // after validation passes to avoid leaving corrupt state on error.
    let mut candidate = checkpoint.cosignatures.clone();
    candidate.push(cosignature);

    // Compute checkpoint hash for verification
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

    // Validation passed — commit the mutation.
    checkpoint.cosignatures = candidate;
    checkpoint.attestation_status = status.clone();
    Ok(status)
}

// ---------------------------------------------------------------------------
// 3. recovery_advance_epoch
// ---------------------------------------------------------------------------

/// Advances the MLS epoch for a context as part of compromise recovery
/// (hoisted body of
/// [`ContextManager::recovery_advance_epoch`](crate::context::manager::ContextManager::recovery_advance_epoch)).
///
/// See the legacy method's doc comment for the full semantics.
/// Byte-identical behavior.
pub async fn recovery_advance_epoch(
    supervisor: &Supervisor,
    context_id: &str,
) -> Result<u64, ContextError> {
    let mgr = supervisor
        .attached_context_manager()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let context_id_bytes = context_id_to_bytes(context_id);

    // 1. Validate the context exists and is active (lock scoped).
    //    Capture generation for confused-deputy detection on reacquire.
    let ctx_gen = {
        let (guard, generation) = mgr.lock_context(context_id).await?;
        let ctx = &*guard;
        require_active(&ctx.handle)?;
        generation
    };

    // 2. Perform the MLS epoch advance (Update + self-Commit).
    //    If this fails the counter is NOT incremented.
    let epoch_output = mgr.crypto_ref().advance_epoch(&context_id_bytes)?;

    // 2b. Broadcast the MLS Commit to all members so they can advance
    //     their group epoch and ratchet key material.
    if !epoch_output.commit_bytes.is_empty() {
        let routing_id = scp_protocol::context::context_routing_id(context_id);
        if let Err(e) = mgr
            .transport_ref()
            .send_message(&routing_id, &epoch_output.commit_bytes)
        {
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "failed to broadcast recovery epoch advance MLS Commit"
            );
        }
    }

    // 3. Increment bookkeeping counter and manage grace store.
    //    Verify generation to detect confused-deputy (context removed
    //    and recreated while we awaited the MLS commit).
    let new_epoch = {
        let mut guard = mgr.relock_context(&ctx_gen).await?;
        let ctx = &mut *guard;
        // Re-validate after the crypto op to close the TOCTOU window between
        // the active check in step 1 and the counter increment here. A
        // concurrent close_context could have transitioned the handle while
        // we awaited the MLS commit.
        require_active(&ctx.handle)?;
        let old_epoch = ctx.epoch.mls_epoch;
        ctx.epoch.mls_epoch = old_epoch.saturating_add(1);
        let _expired = ctx.epoch.grace_store.add_epoch(old_epoch);
        ctx.epoch.mls_epoch
    };

    // 4. Emit epoch advancement event to event log. Event log failures
    //    are non-fatal — recovery must not be blocked by logging issues.
    if let Err(e) = mgr.event_log_ref().append_context_event(
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
        if let Ok(mut guard) = mgr.relock_context(&ctx_gen).await {
            let ctx = &mut *guard;
            ctx.checkpoint_events_since += 1;
        }
    }

    // 5. Persist if configured (best-effort).
    if mgr.has_persistence()
        && let Ok(guard) = mgr.relock_context(&ctx_gen).await
    {
        let ctx = &*guard;
        let snapshot = ContextManager::snapshot_context(ctx);
        mgr.persist_context_snapshot(context_id, snapshot);
    }

    Ok(new_epoch)
}

// ---------------------------------------------------------------------------
// 4. recovery_send_notification
// ---------------------------------------------------------------------------

/// Sends an encrypted message to a context for recovery notification
/// purposes (hoisted body of
/// [`ContextManager::recovery_send_notification`](crate::context::manager::ContextManager::recovery_send_notification)).
///
/// See the legacy method's doc comment for the full semantics.
/// Byte-identical behavior.
pub async fn recovery_send_notification(
    supervisor: &Supervisor,
    context_id: &str,
    sender_did: &str,
    payload: &[u8],
    sequence: u64,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<(), ContextError> {
    let mgr = supervisor
        .attached_context_manager()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let context_id_bytes = context_id_to_bytes(context_id);

    // Look up the current MLS epoch for this context. After an epoch
    // advance in step 2, the epoch is > 0 — using the real value ensures
    // receivers can validate the message against their local epoch state.
    let current_epoch = {
        if let Ok(arc) = mgr.get_context_arc(context_id) {
            let ctx = arc.lock().await;
            ctx.epoch.mls_epoch
        } else {
            0
        }
    };

    // Construct a minimal inner envelope for the recovery notification.
    // Recovery notifications bypass the full send_message pipeline but
    // still go through the envelope crypto layer (seal).
    let timestamp = mgr.clock_ref().now_millis();
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
    let encrypted = mgr.crypto_ref().seal(
        &context_id_bytes,
        &inner,
        &routing_id,
        300, // 5 minute blob TTL
    )?;

    // Send via transport using the domain-separated routing ID.
    mgr.transport_ref().send_message(&routing_id, &encrypted)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// 5. recovery_notify_contact
// ---------------------------------------------------------------------------

/// Sends a recovery notification to a contact DID by finding shared
/// contexts (hoisted body of
/// [`ContextManager::recovery_notify_contact`](crate::context::manager::ContextManager::recovery_notify_contact)).
///
/// See the legacy method's doc comment for the full semantics.
/// Byte-identical behavior.
pub async fn recovery_notify_contact(
    supervisor: &Supervisor,
    recovering_did: &str,
    contact_did: &str,
    payload: &[u8],
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<(), ContextError> {
    let mgr = supervisor
        .attached_context_manager()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    // Find a context where both the recovering DID and the contact DID
    // are members. The first matching context is used for delivery.
    // Collect (key, Arc) pairs first to release DashMap shard locks before
    // awaiting per-context Mutexes. Holding a DashMap Ref across .await
    // would deadlock any concurrent shard access.
    let shared_context_id = {
        let contexts = mgr.contexts_arc();
        let entries: Vec<(String, Arc<tokio::sync::Mutex<PerContextState>>)> = contexts
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
            recovery_send_notification(
                supervisor,
                &context_id,
                recovering_did,
                payload,
                4,
                signing_key,
            )
            .await
        }
        None => Err(ContextError::TransportFailed(format!(
            "no shared context found between {recovering_did} and {contact_did}"
        ))),
    }
}
