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
//! The per-context lock primitives and the `contexts` `DashMap` they read
//! were deleted in the ADR-049 Phase 2A finalization once the last
//! `&Supervisor` caller (the legacy tools economy wrapper) moved to the
//! actor-split economy reserve/settle path. Per-context state now lives
//! only inside the per-context actor; the helpers below remain because
//! they mailbox the actors or touch supervisor-scoped provider slots.
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

use scp_identity::DID;
use scp_protocol::context::ContextParams;
use scp_protocol::context::ContextState;
use scp_protocol::context::broadcast::{
    BroadcastAdmission, BroadcastContext, BroadcastContextSnapshot,
};
use scp_protocol::context::builder::ContextCreationError;
use scp_protocol::context::params::{ContextMode, TemplateId};

use crate::context::state::{ContextSnapshot, PerContextState, VelocityTrackerSnapshot};
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
// has_persistence
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
// persist_broadcast_snapshot
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

/// Persists context and broadcast state for a single context if a
/// persistence provider is configured.
///
/// ADR-049 Phase 2A finalization (`DashMap` removal): the snapshot is no
/// longer read from the legacy `contexts` `DashMap`. Instead this mailboxes
/// [`LifecycleCommand::FlushSnapshot`](crate::context::actor::commands::LifecycleCommand::FlushSnapshot)
/// to the single target context's actor — the actor builds the snapshot
/// (context + crypto export + broadcast) from its owned
/// [`PerContextState`] and persists it via `deps.persistence`. The
/// per-context body is identical to the per-actor slice
/// [`flush_all_contexts`](crate::context::lifecycle_helpers::flush_all_contexts)
/// fans out to.
///
/// Best-effort: a missing actor, a closed mailbox, or a send timeout is a
/// silent skip (the actor persists on its own lifecycle paths too).
pub async fn persist_context_and_broadcast(supervisor: &Supervisor, context_id: &str) {
    use crate::context::actor::commands::{ContextCommand, LifecycleCommand};

    if !has_persistence(supervisor) {
        return;
    }
    let Some(actor) = supervisor.lookup(context_id) else {
        return;
    };
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = ContextCommand::Lifecycle(LifecycleCommand::FlushSnapshot { reply: tx });
    if actor
        .send_with_timeout(cmd, crate::context::actor::SEND_TIMEOUT)
        .await
        .is_err()
    {
        return;
    }
    let _ = rx.await;
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
        event_log_merkle_root: [0u8; 32],
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
        revoked_spending_ucan_cids: ctx.governance.revoked_spending_ucan_cids.clone(),
        pending_commits: ctx.pending_commits.clone(),
        commit_fault: ctx.commit_fault.clone(),
        checkpoint_events_since: ctx.checkpoint_events_since,
        checkpoint_last_time_secs: ctx.checkpoint_last_time_secs,
        generation: ctx.generation,
        routing: ctx.routing.clone(),
        // ADR-049 §9 Class S (line 144): persist the staged saga slot through
        // its sanctioned mirror via the shared helper.
        saga_pending: crate::context::messaging_helpers::saga_pending_snapshot(ctx),
    }
}
