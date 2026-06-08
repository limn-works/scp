// Module-level allow — the legacy inherent-impl forms in
// `manager/mod.rs` carried `#[allow(clippy::significant_drop_tightening)]`
// on impl blocks for the per-context lock infrastructure helpers. The
// hoisted bodies preserve the same lock-hold-across-await patterns
// deliberately (narrowing changes lock-ordering semantics across the
// per-context mutex); allowing the lint crate-locally keeps the hoist
// byte-identical to the legacy behavior.
#![allow(clippy::significant_drop_tightening)]

//! Cross-domain `ContextManager` infrastructure helpers with explicit-
//! collaborator signatures (ADR-049 commit 12).
//!
//! # Purpose
//!
//! This module hoists the cross-domain infrastructure methods that the
//! existing per-domain `*_helpers.rs` files reach via `mgr.X(...)`. The
//! per-domain helpers (lifecycle, messaging, broadcast, governance,
//! economy, queries, standing, tools, `trust_recovery`) all need access to
//! the same per-context lock primitives, persistence shortcuts, broadcast
//! initialization, payment-failure event recording, and operational gauge
//! updates — methods that don't fit into a single domain's helper file.
//!
//! Co-locating them here keeps each domain's helper module focused while
//! preserving the "one canonical free-function form per legacy method"
//! invariant the rest of the 12c hoist series established.
//!
//! # Behavior preservation
//!
//! Every hoisted free function is **behavior-preserving by construction**.
//! Its body is a verbatim copy of the legacy inherent method's body with
//! `self.X` replaced by either:
//!
//! - `mgr.X_ref()` accessor calls for fields still owned by
//!   [`Supervisor`](crate::context::supervisor::Supervisor), or
//! - `supervisor.X_ref()` accessor calls for the provider slots already
//!   lifted to [`Supervisor`](crate::context::supervisor::Supervisor) in
//!   ADR-049 commit 12c.9a/9b.
//!
//! The legacy inherent methods on
//! [`Supervisor`](crate::context::supervisor::Supervisor) remain as
//! one-line forwarders that thread `self.supervisor()` into each helper
//! through the `Weak<Supervisor>` back-pointer installed by
//! [`Supervisor::with_providers`](crate::context::supervisor::Supervisor::with_providers)
//! during bridge construction. The forwarders are deleted alongside the
//! outer shim in commit 12c.9g.4.
//!
//! # Hoisted methods
//!
//! Per-context lock primitives:
//! - [`lock_context`] — lock + capture generation token.
//! - [`relock_context`] — reacquire under generation guard.
//! - [`get_context_arc`] — clone the per-context `Arc<Mutex<...>>`.
//! - [`get_context_arc_pub`] — `pub(crate)` variant for the query shim.
//!
//! Per-context map mutations:
//! - [`remove_context`] — drop a context from the map.
//!
//! Persistence shortcuts:
//! - [`has_persistence`] — predicate for skipping snapshot work.
//! - [`persist_context_snapshot`] — best-effort persist + crypto export.
//! - [`persist_broadcast_snapshot`] — best-effort persist of broadcast state.
//! - [`persist_context_and_broadcast`] — atomic snapshot of both pairs.
//!
//! Broadcast bootstrapping:
//! - [`init_broadcast_context`] — create + persist initial broadcast state.
//!
//! Operational metrics:
//! - [`update_context_gauges`] — refresh active-contexts + buffer-occupancy gauges.

use std::sync::Arc;

use scp_identity::DID;
use scp_protocol::context::ContextError;
use scp_protocol::context::ContextParams;
use scp_protocol::context::ContextState;
use scp_protocol::context::broadcast::{
    BroadcastAdmission, BroadcastContext, BroadcastContextSnapshot,
};
use scp_protocol::context::builder::ContextCreationError;
use scp_protocol::context::params::{ContextMode, TemplateId};
use tokio::sync::Mutex;

use crate::context::state::{
    ContextGeneration, ContextSnapshot, PerContextState, VelocityTrackerSnapshot,
    context_id_to_bytes,
};
use crate::context::supervisor::Supervisor;

// ---------------------------------------------------------------------------
// Shared "provider not initialized" diagnostic
// ---------------------------------------------------------------------------

/// Canonical diagnostic message for the
/// [`ContextError::NotInitialized`] error variant returned when a
/// helper consults a provider slot that has not been populated by
/// [`Supervisor::with_providers`](crate::context::supervisor::Supervisor::with_providers).
///
/// Phase 1 fix-up of ADR-049 (post-review-round-1): replaces the prior
/// per-helper `ATTACHED_EXPECT` constants. One canonical string keeps
/// the diagnostic stable across the helper graph; future audit
/// tooling can grep for the single identifier.
pub const PROVIDER_NOT_INITIALIZED: &str =
    "Supervisor providers not initialized — call Supervisor::with_providers";

// ---------------------------------------------------------------------------
// 1. lock_context
// ---------------------------------------------------------------------------

/// Locks the per-context `Mutex` and returns an owned guard plus a
/// generation token for confused-deputy detection on later reacquire.
///
/// Hoisted body of the legacy `ContextManager::lock_context` method
/// (deleted in commit 12 of the ADR-049 ladder). Byte-identical
/// behavior.
///
/// # Errors
///
/// Returns [`ContextError::ContextNotRegistered`] if `context_id` is not
/// in the map.
pub async fn lock_context(
    supervisor: &Supervisor,
    context_id: &str,
) -> Result<
    (
        tokio::sync::OwnedMutexGuard<PerContextState>,
        ContextGeneration,
    ),
    ContextError,
> {
    let arc = get_context_arc(supervisor, context_id)?;
    let guard = arc.lock_owned().await;
    let token = ContextGeneration {
        context_id: context_id.to_owned(),
        generation: guard.generation,
    };
    Ok((guard, token))
}

// ---------------------------------------------------------------------------
// 2. relock_context
// ---------------------------------------------------------------------------

/// Reacquires the per-context `Mutex` and verifies the generation counter
/// matches `token`. Detects the confused-deputy scenario where the context
/// was removed and recreated between lock release and reacquire.
///
/// Hoisted body of the legacy `ContextManager::relock_context` method
/// (deleted in commit 12 of the ADR-049 ladder). Byte-identical
/// behavior.
///
/// # Errors
///
/// - [`ContextError::ContextNotRegistered`] if the context is gone.
/// - [`ContextError::PermissionDenied`] if the generation changed.
pub async fn relock_context(
    supervisor: &Supervisor,
    token: &ContextGeneration,
) -> Result<tokio::sync::OwnedMutexGuard<PerContextState>, ContextError> {
    let arc = get_context_arc(supervisor, &token.context_id)?;
    let guard = arc.lock_owned().await;
    if guard.generation != token.generation {
        return Err(ContextError::PermissionDenied(format!(
            "context {} was removed and recreated (generation {} != {})",
            token.context_id, guard.generation, token.generation,
        )));
    }
    Ok(guard)
}

// ---------------------------------------------------------------------------
// 3. get_context_arc
// ---------------------------------------------------------------------------

/// Clones the `Arc<Mutex<PerContextState>>` for a context without locking
/// the per-context mutex. Used when the caller needs the `Arc` but will
/// lock it later.
///
/// Hoisted body of the legacy
/// [`ContextManager::get_context_arc`](crate::context::supervisor::Supervisor::get_context_arc)
/// (ADR-049 commit 12). Byte-identical behavior.
///
/// # Errors
///
/// Returns [`ContextError::ContextNotRegistered`] if the context is not
/// in the map, OR [`ContextError::NotInitialized`] if the supervisor's
/// per-context map slot has not been populated by
/// `Supervisor::with_providers`.
pub fn get_context_arc(
    supervisor: &Supervisor,
    context_id: &str,
) -> Result<Arc<Mutex<PerContextState>>, ContextError> {
    supervisor
        .contexts_ref()
        .get(context_id)
        .map(|entry| Arc::clone(entry.value()))
        .ok_or_else(|| ContextError::ContextNotRegistered(context_id.to_owned()))
}

// ---------------------------------------------------------------------------
// 6. has_persistence
// ---------------------------------------------------------------------------

/// Returns `true` if a persistence provider is configured.
///
/// Hoisted body of the legacy
/// [`ContextManager::has_persistence`](crate::context::supervisor::Supervisor::has_persistence)
/// (ADR-049 commit 12). Byte-identical behavior — uses the
/// supervisor's lifted persistence slot
/// (`Supervisor::persistence_ref`) which already collapses the
/// "not attached" + "attached but no persistence" cases to a single
/// `None`.
///
/// Use this to guard snapshot creation so that expensive deep-clones of
/// `PerContextState` are skipped when no persistence provider exists
/// (the common case for most bridges).
#[inline]
#[must_use]
pub fn has_persistence(supervisor: &Supervisor) -> bool {
    supervisor.persistence_ref().is_some()
}

// ---------------------------------------------------------------------------
// 8. update_context_gauges
// ---------------------------------------------------------------------------

/// Updates operational gauge metrics (active contexts, buffer occupancy).
///
/// ADR-049 Phase 2A finalization (`DashMap` removal): the gauge sweep now
/// reads the per-context actor registry instead of the legacy `contexts`
/// `DashMap`. `active_contexts` is the registered actor count
/// ([`Supervisor::actor_ids`](crate::context::supervisor::Supervisor::actor_ids));
/// `buffer_occupancy` is the sum of each actor's receive-buffer length,
/// gathered by mailboxing
/// [`LifecycleCommand::ReportBufferLen`](crate::context::actor::commands::LifecycleCommand::ReportBufferLen)
/// to each actor (the handler reads `state.receive_buffer.len()` from
/// owned state — no cross-actor lock).
///
/// Called after mutations that change context count or buffer state.
/// Best-effort: if no metrics recorder is installed, these are no-ops
/// (#1467); actors that fail to reply within the send timeout are skipped
/// (metrics are approximate, exactly as the legacy `try_lock` skip was).
pub async fn update_context_gauges(supervisor: &Supervisor) {
    use crate::context::actor::commands::{ContextCommand, LifecycleCommand};

    let actor_ids = supervisor.actor_ids();
    crate::metrics::set_active_contexts(actor_ids.len());

    let mut total_buffered: usize = 0;
    for ctx_id in actor_ids {
        let Some(actor) = supervisor.lookup(&ctx_id) else {
            continue;
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = ContextCommand::Lifecycle(LifecycleCommand::ReportBufferLen { reply: tx });
        // Skip actors that cannot accept the command (closed mailbox /
        // timeout) — approximate metrics, same as the legacy try_lock
        // skip-on-contention behaviour.
        if actor
            .send_with_timeout(cmd, crate::context::actor::SEND_TIMEOUT)
            .await
            .is_err()
        {
            continue;
        }
        if let Ok(len) = rx.await {
            total_buffered += len;
        }
    }
    crate::metrics::set_buffer_occupancy(total_buffered);
}

// ---------------------------------------------------------------------------
// 9. persist_context_snapshot
// ---------------------------------------------------------------------------

/// Persists a context snapshot if a persistence provider is configured.
///
/// Hoisted body of the legacy
/// [`ContextManager::persist_context_snapshot`](crate::context::supervisor::Supervisor::persist_context_snapshot)
/// (ADR-049 commit 12). Byte-identical behavior.
///
/// Best-effort: logs errors but does not propagate them to callers. On a
/// detached supervisor the call is a no-op (no provider to persist to).
pub fn persist_context_snapshot(
    supervisor: &Supervisor,
    context_id: &str,
    mut snapshot: ContextSnapshot,
) {
    let Some(persistence) = supervisor.persistence_ref() else {
        return;
    };
    let Some(crypto) = supervisor.crypto_ref() else {
        return;
    };
    // Export MLS crypto state alongside the context snapshot (#645).
    // Populate `mls_crypto_state` in-place on the owned snapshot (#711).
    //
    // AC3 bug 2 fix: on export failure, mark the snapshot
    // `needs_reconnect = true` and persist an empty crypto blob.
    // Previously the error branch silently persisted a snapshot with
    // a default (empty) `mls_crypto_state` and no reconnect signal
    // — the restore path would then load the context, attempt to
    // resume MLS encryption against an empty state, and fail in a
    // way that required manual operator intervention. With the
    // flag set, the restore path fires the §23.11 reconnection
    // pipeline exactly as it would for any other unrecoverable
    // crypto state, so the context heals automatically.
    let ctx_id_bytes = context_id_to_bytes(context_id);
    match crypto.export_crypto_state(&ctx_id_bytes) {
        Ok(state) => snapshot.mls_crypto_state = state,
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
    if let Err(e) = persistence.persist_context(context_id, &snapshot) {
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

// ---------------------------------------------------------------------------
// 10. persist_broadcast_snapshot
// ---------------------------------------------------------------------------

/// Persists a broadcast context snapshot if a persistence provider is
/// configured. Best-effort: logs errors but does not propagate.
///
/// Hoisted body of the legacy
/// [`ContextManager::persist_broadcast_snapshot`](crate::context::supervisor::Supervisor::persist_broadcast_snapshot)
/// (ADR-049 commit 12). Byte-identical behavior.
pub fn persist_broadcast_snapshot(
    supervisor: &Supervisor,
    context_id: &str,
    snapshot: &BroadcastContextSnapshot,
) {
    if let Some(persistence) = supervisor.persistence_ref()
        && let Err(e) = persistence.persist_broadcast(context_id, snapshot)
    {
        tracing::warn!(
            context_id = %context_id,
            error = %e,
            "failed to persist broadcast snapshot"
        );
    }
}

// ---------------------------------------------------------------------------
// 11. init_broadcast_context
// ---------------------------------------------------------------------------

/// Initializes a `BroadcastContext` if the context is in Broadcast mode
/// (SCP-227). Derives admission policy from `template_id` and registers
/// the creator as the first author. Persists the initial broadcast state
/// for crash recovery.
///
/// Hoisted body of the legacy
/// [`ContextManager::init_broadcast_context`](crate::context::supervisor::Supervisor::init_broadcast_context)
/// (ADR-049 commit 12). Byte-identical behavior.
pub fn init_broadcast_context(
    supervisor: &Supervisor,
    context_id: &str,
    params: &ContextParams,
    creator_did: &DID,
) -> Result<Option<BroadcastContext>, ContextCreationError> {
    if params.mode != ContextMode::Broadcast {
        return Ok(None);
    }
    // The `Some(PublicBroadcast | PaidBroadcast)` arm and the wildcard
    // arm both resolve to `BroadcastAdmission::Open` — the explicit arm
    // is preserved verbatim from the legacy
    // `ContextManager::init_broadcast_context` body so the hoisted
    // function reads identically. `match_same_arms` is silenced
    // crate-locally; merging would lose the documentation that
    // `Public`/`Paid` broadcasts are deliberately Open.
    #[allow(clippy::match_same_arms)]
    let admission = match params.template_id {
        Some(TemplateId::GatedBroadcast) => BroadcastAdmission::Gated,
        Some(TemplateId::PublicBroadcast | TemplateId::PaidBroadcast) => BroadcastAdmission::Open,
        _ => BroadcastAdmission::Open,
    };
    let mut bc = BroadcastContext::new(context_id.to_owned(), &params.mode, admission)
        .map_err(|e| ContextCreationError::CreationFailed(e.to_string()))?;
    // Register the creator as the first author (messagesWrite).
    bc.add_author(creator_did)
        .map_err(|e| ContextCreationError::CreationFailed(e.to_string()))?;
    // Persist initial broadcast state for crash recovery.
    if has_persistence(supervisor) {
        persist_broadcast_snapshot(supervisor, context_id, &bc.to_snapshot());
    }
    Ok(Some(bc))
}

// ---------------------------------------------------------------------------
// 12. persist_context_and_broadcast
// ---------------------------------------------------------------------------

/// Persists context and broadcast state if a persistence provider is
/// configured.
///
/// Hoisted body of the legacy
/// [`ContextManager::persist_context_and_broadcast`](crate::context::supervisor::Supervisor::persist_context_and_broadcast)
/// (ADR-049 commit 12). Byte-identical behavior.
pub async fn persist_context_and_broadcast(supervisor: &Supervisor, context_id: &str) {
    if has_persistence(supervisor)
        && let Ok(arc) = get_context_arc(supervisor, context_id)
    {
        let ctx = arc.lock().await;
        let snapshot = snapshot_context(&ctx);
        let bc_snapshot = ctx
            .broadcast_context
            .as_ref()
            .map(BroadcastContext::to_snapshot);
        drop(ctx);
        persist_context_snapshot(supervisor, context_id, snapshot);
        if let Some(ref bcs) = bc_snapshot {
            persist_broadcast_snapshot(supervisor, context_id, bcs);
        }
    }
}

// ---------------------------------------------------------------------------
// 14. snapshot_context
// ---------------------------------------------------------------------------

/// Takes a [`ContextSnapshot`] from the current [`PerContextState`].
///
/// Hoisted body of the legacy
/// [`ContextManager::snapshot_context`](crate::context::supervisor::Supervisor::snapshot_context)
/// (ADR-049 commit 12). Byte-identical behavior.
///
/// Must be called while the contexts mutex is held (snapshot under lock).
pub fn snapshot_context(ctx: &PerContextState) -> ContextSnapshot {
    let state = ctx.handle.try_read_state().unwrap_or(ContextState::Active);
    let ttl_remaining_secs = ctx.ttl.timer.remaining_secs();
    // Capture grace entries for transactional persistence (§23.11).
    // On clock error, persist an empty vec — the recovery path will
    // treat the missing entries as expired (conservative: forward secrecy
    // prioritized over message recovery, per §23.11 inconsistent state
    // fallback).
    let grace_entries = ctx.epoch.grace_store.to_grace_entries();
    ContextSnapshot {
        context_id: ctx.handle.context_id().to_owned(),
        state,
        context_params: ctx.handle.params().clone(),
        membership: ctx.membership.clone(),
        role_state: ctx.role_state.clone(),
        executed_proposals: ctx.governance.executed_proposals.keys().copied().collect(),
        ttl_remaining_secs,
        registered_tools: ctx.governance.registered_tools.clone(),
        read_exclusion_list: ctx.access.read_exclusion_list.clone(),
        tool_interfaces: ctx.governance.tool_interfaces.clone(),
        threshold_signers: ctx.governance.threshold_signers.clone(),
        threshold_value: ctx.governance.threshold_value,
        pruning_policy: ctx.governance.pruning_policy.clone(),
        governance_model_config: Some(ctx.governance.engine.model_config()),
        economic_policy: ctx.governance.economic_policy.clone(),
        budget_tracker: ctx.governance.budget_tracker.clone(),
        approved_proposals: ctx.governance.approved_proposals.clone(),
        next_proposal_seq: ctx.governance.next_proposal_seq,
        governance_freeze: ctx.governance.freeze,
        pending_ceiling_modification: ctx.governance.pending_ceiling_modification.clone(),
        pending_economic_policy_change: ctx.governance.pending_economic_policy_change.clone(),
        mls_epoch: ctx.epoch.mls_epoch,
        epoch_coordination_records: ctx.epoch.coordinator.records().to_vec(),
        grace_entries,
        needs_reconnect: ctx.epoch.needs_reconnect,
        // MLS crypto state is populated in `persist_context_snapshot`
        // where the crypto provider is available. Initialized empty here.
        mls_crypto_state: Vec::new(),
        migration_state: ctx.migration_state.clone(),
        access_key_store: ctx.access.access_key_store.clone(),
        consequence_rules: ctx.governance.consequence_rules.clone(),
        participation_cache: ctx.governance.participation_cache.clone(),
        velocity_tracker: Some(ctx.governance.velocity_tracker.window_secs()),
        velocity_tracker_state: Some(VelocityTrackerSnapshot {
            window_secs: ctx.governance.velocity_tracker.window_secs(),
            entries: ctx.governance.velocity_tracker.snapshot_entries(),
        }),
        cooldown_until: ctx.governance.cooldown_until.clone(),
        proposal_timestamps: ctx.governance.proposal_timestamps.clone(),
        message_pricing: ctx.governance.message_pricing.clone(),
        hard_rate_limit_config: Some(ctx.governance.hard_rate_limit.config().clone()),
        hard_rate_limit_state: ctx.governance.hard_rate_limit.snapshot_entries(),
        spending_nonce_tracker_state: ctx.governance.spending_nonce_tracker.snapshot_entries(),
        pending_commits: ctx.pending_commits.clone(),
        commit_fault: ctx.commit_fault.clone(),
        checkpoint_events_since: ctx.checkpoint_events_since,
        checkpoint_last_time_secs: ctx.checkpoint_last_time_secs,
        generation: ctx.generation,
        local_pseudonym: ctx.local_pseudonym,
        pseudonym_registry: ctx
            .pseudonym_registry
            .iter()
            .map(|(did, p)| (did.to_string(), *p))
            .collect(),
    }
}
