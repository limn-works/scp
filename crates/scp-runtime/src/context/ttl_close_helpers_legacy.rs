// Module-level allow — the legacy inherent-impl form in
// `manager/lifecycle.rs` (which housed the TTL/close path) carried
// `#[allow(clippy::significant_drop_tightening)]` on its impl block.
// The hoisted bodies preserve the same lock-hold-across-await patterns
// deliberately (narrowing changes lock-ordering semantics across the
// per-context mutex); allowing the lint crate-locally keeps the hoist
// byte-identical to the legacy behavior.
#![allow(clippy::significant_drop_tightening)]

//! Legacy TTL-close helpers
//! (ADR-049 Phase 2A.6, TTL-domain shim-fallback path).
//!
//! # Purpose
//!
//! This module preserves the pre-migration `&Supervisor` lock-and-call
//! TTL-close helper bodies for the Phase 2A shim fallback. The live
//! actor path now calls [`crate::context::ttl_close_helpers`], which
//! owns per-context state directly; the shim path keeps these legacy
//! twins until Phase 2A finalization removes all `*_helpers_legacy.rs`
//! modules.
//!
//! # Behavior preservation
//!
//! Every hoisted free function is **behavior-preserving by construction**.
//! The bodies are verbatim copies of the legacy `lifecycle_helpers`
//! TTL-close functions (commits 12c.2 and earlier); the only delta vs
//! the original is the [`spawn_ttl_timer_legacy`] rename to disambiguate
//! the legacy entry point from the actor-shape
//! [`crate::context::ttl_close_helpers::start_ttl_timer`] /
//! [`crate::context::ttl_close_helpers::reset_ttl_timer`] helpers and
//! to make the shim-fallback intent legible at the call site.
//!
//! # Legacy twins
//!
//! [`finalize_close`], [`handle_ttl_expiry`], [`propose_ttl_extension`],
//! [`reset_ttl_timer`], [`start_ttl_timer`], [`spawn_ttl_timer_legacy`].
//!
//! # `spawn_ttl_timer_legacy` — out-of-domain callers
//!
//! `spawn_ttl_timer_legacy` is also reached by lifecycle restore /
//! finalize-create / import paths
//! (`lifecycle_helpers_legacy::restore_context_legacy`,
//! `lifecycle_helpers_legacy::finalize_create_legacy`,
//! `lifecycle_helpers_legacy::import_context_legacy`) and by the
//! governance TTL extension proposal handler
//! (`governance_helpers::handle_ttl_extension_proposal`). Phase 2A.9
//! migrated the lifecycle outer entry points to actor-shape; the bodies
//! still spawn the TTL timer through this legacy path until per-actor
//! TTL ownership lands in a follow-on Phase 2 chunk.

use std::sync::Arc;

use scp_identity::DID;
use scp_protocol::context::ContextError;
use scp_protocol::context::membership::ContextEvent;

use crate::context::ContextHandle;
use crate::context::manager_methods;
use crate::context::supervisor::Supervisor;
use crate::context::ttl::{self, TtlExtension};

// Phase 1 fix-up of ADR-049 (post-review-round-1): per-helper
// `ATTACHED_EXPECT` constants consolidated to the single
// `PROVIDER_NOT_INITIALIZED` definition in `manager_methods`.
use crate::context::manager_methods::PROVIDER_NOT_INITIALIZED as ATTACHED_EXPECT;

// ---------------------------------------------------------------------------
// 1. finalize_close (top-level)
// ---------------------------------------------------------------------------

/// Completes context closure (hoisted body of the legacy
/// `ContextManager::finalize_close`).
///
/// Destroys MLS group state and sender keys, issues relay deletion
/// requests for ephemeral/summary scopes, transitions from `Closing`
/// to `Closed`, and appends the final `ContextClosed` event.
pub async fn finalize_close(
    supervisor: &Supervisor,
    handle: &ContextHandle,
) -> Result<(), ContextError> {
    let crypto = supervisor
        .crypto_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let transport = supervisor
        .transport_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let event_log = supervisor
        .event_log_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let context_id = handle.context_id().to_owned();

    ttl::finalize_close(
        handle,
        crypto.as_ref(),
        transport.as_ref(),
        event_log.as_ref(),
    )
    .await?;

    // Delete persisted state after finalize (best-effort).
    if let Some(persistence) = supervisor.persistence_ref() {
        let _ = persistence.delete_context(&context_id);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 2. handle_ttl_expiry (top-level)
// ---------------------------------------------------------------------------

/// Handles automatic TTL expiry (hoisted body of the legacy
/// `ContextManager::handle_ttl_expiry`).
///
/// Transitions from `Active` to `Expired`, destroys keys per memory
/// scope, issues relay deletion requests for ephemeral/summary scopes,
/// and appends `ContextExpired` to the event log.
pub async fn handle_ttl_expiry(
    supervisor: &Supervisor,
    handle: &ContextHandle,
) -> Result<(), ContextError> {
    let crypto = supervisor
        .crypto_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let transport = supervisor
        .transport_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let event_log = supervisor
        .event_log_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let context_id = handle.context_id().to_owned();

    // Capture generation before async expiry work for confused-deputy
    // detection on reacquire.
    let ctx_gen = {
        let (_guard, generation) = manager_methods::lock_context(supervisor, &context_id)
            .await
            .map_err(|_| ContextError::ContextNotRegistered(context_id.clone()))?;
        generation
    };

    // Async TTL expiry logic -- no lock held. Pass transport for
    // best-effort relay ciphertext deletion (§5.11).
    let result = ttl::try_ttl_expiry_cleanup(
        handle,
        crypto.as_ref(),
        Some(transport.as_ref()),
        event_log.as_ref(),
        0,
    )
    .await;

    // Cancel governance timeout task, decay participation, and emit
    // appropriate event (lock acquired, then dropped, with generation check).
    {
        if let Ok(mut guard) = manager_methods::relock_context(supervisor, &ctx_gen).await {
            let ctx = &mut *guard;
            ctx.governance.timeout_task.cancel();
            // Participation decay on TTL expiry (#1530): clear
            // participation cache and cooldown state so stale data does
            // not carry over if the context is later restored.
            ctx.governance.decay_participation();
            if result.is_complete() {
                let event = ContextEvent::Expired;
                ctx.emit_event(event, &context_id, supervisor.event_tx_ref());
            } else {
                let event = ContextEvent::ExpiryFailed {
                    reason: result.to_string(),
                    state_transitioned: result.state_transitioned(),
                    mls_destroyed: result.mls_destroyed(),
                    sender_key_destroyed: result.sender_key_destroyed(),
                    event_logged: result.event_logged(),
                };
                ctx.emit_event(event, &context_id, supervisor.event_tx_ref());
            }
        } else {
            tracing::warn!(
                context_id = %context_id,
                "handle_ttl_expiry: generation mismatch — skipping state mutation"
            );
        }
    }

    // Persist context state after TTL expiry (best-effort).
    if manager_methods::has_persistence(supervisor)
        && let Ok(guard) = manager_methods::relock_context(supervisor, &ctx_gen).await
    {
        let ctx = &*guard;
        let snapshot = manager_methods::snapshot_context(ctx);
        manager_methods::persist_context_snapshot(supervisor, &context_id, snapshot);
    }

    if result.has_failures() {
        let msg = result.errors().join("; ");
        return Err(
            if !result.mls_destroyed() || !result.sender_key_destroyed() {
                ContextError::CryptoFailed(msg)
            } else {
                ContextError::EventLogFailed(msg)
            },
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 3. propose_ttl_extension (top-level)
// ---------------------------------------------------------------------------

/// Proposes a TTL extension (hoisted body of the legacy
/// `ContextManager::propose_ttl_extension`).
///
/// Records consent from the given member. Returns `true` iff every
/// member has now consented (unanimous); the caller should then call
/// [`reset_ttl_timer`] with the new duration.
pub async fn propose_ttl_extension(
    supervisor: &Supervisor,
    context_id: &str,
    member_did: &DID,
    proposed_duration: std::time::Duration,
) -> Result<bool, ContextError> {
    // All checks and mutation within a single lock acquisition.
    let ctx_arc = manager_methods::get_context_arc(supervisor, context_id)
        .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
    let mut guard = ctx_arc.lock().await;
    let ctx = &mut *guard;

    if !ctx.membership.contains(member_did) {
        return Err(ContextError::MemberNotFound(member_did.to_string()));
    }

    let member_count = ctx.membership.count();

    // Initialize extension proposal if not already in progress.
    let extension = ctx
        .ttl
        .extension
        .get_or_insert_with(|| TtlExtension::new(proposed_duration, member_count));

    extension.add_consent(member_did.clone());
    let unanimous = extension.is_unanimous();

    // Persist context state after proposal consent (best-effort).
    if manager_methods::has_persistence(supervisor) {
        let ctx_snapshot = manager_methods::snapshot_context(ctx);
        manager_methods::persist_context_snapshot(supervisor, context_id, ctx_snapshot);
    }

    Ok(unanimous)
}

// ---------------------------------------------------------------------------
// 4. reset_ttl_timer (top-level)
// ---------------------------------------------------------------------------

/// Resets the TTL timer after a successful unanimous extension (hoisted
/// body of the legacy `ContextManager::reset_ttl_timer`).
///
/// Cancels the old timer and spawns a new one with the given duration.
/// Clears the extension proposal state.
pub async fn reset_ttl_timer(
    supervisor: &Supervisor,
    context_id: &str,
    new_duration: std::time::Duration,
    handle: ContextHandle,
) {
    // Cancel old timer and clear extension state (lock, then drop).
    {
        if let Ok(ctx_arc) = manager_methods::get_context_arc(supervisor, context_id) {
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            ctx.ttl.timer.cancel();
            ctx.ttl.extension = None;
        }
    }

    spawn_ttl_timer_legacy(supervisor, context_id, new_duration, handle).await;

    // Persist context state after TTL reset (best-effort).
    if manager_methods::has_persistence(supervisor)
        && let Ok(ctx_arc) = manager_methods::get_context_arc(supervisor, context_id)
    {
        let guard = ctx_arc.lock().await;
        let ctx = &*guard;
        let snapshot = manager_methods::snapshot_context(ctx);
        manager_methods::persist_context_snapshot(supervisor, context_id, snapshot);
    }
}

// ---------------------------------------------------------------------------
// 5. start_ttl_timer (top-level shim, forwarder into spawn_ttl_timer_legacy)
// ---------------------------------------------------------------------------

/// Installs a TTL timer for the given context (hoisted body of the
/// legacy `ContextManager::start_ttl_timer`).
///
/// Thin shim that delegates to [`spawn_ttl_timer_legacy`] — the
/// shim-callable
/// [`TtlCloseCommand::StartTtlTimer`](crate::context::actor::commands::TtlCloseCommand::StartTtlTimer)
/// fallback uses this wrapper so it doesn't need to depend on the
/// supervisor-internal spawn helper directly.
pub async fn start_ttl_timer(
    supervisor: &Supervisor,
    context_id: &str,
    duration: std::time::Duration,
    handle: ContextHandle,
) {
    spawn_ttl_timer_legacy(supervisor, context_id, duration, handle).await;
}

// ---------------------------------------------------------------------------
// 6. spawn_ttl_timer_legacy (transitive — shared by reset_ttl_timer,
//    start_ttl_timer, import_context, finalize_create, restore_context,
//    governance_helpers::handle_ttl_extension_proposal)
// ---------------------------------------------------------------------------

/// Spawns a TTL timer for the given context (hoisted body of the legacy
/// `ContextManager::spawn_ttl_timer`).
///
/// See the legacy method's doc comment for the full timer-fired /
/// cancelled select-arm semantics, generation-check handling, and
/// `ContextEvent::Expired` / `ContextEvent::ExpiryFailed` emission
/// policy. Byte-identical to the legacy method.
///
/// # Rename
///
/// Renamed from `spawn_ttl_timer` (legacy `lifecycle_helpers`) to
/// `spawn_ttl_timer_legacy` so the shim-fallback intent is legible at
/// the call site and to avoid future namespace clashes with any
/// actor-shape `spawn_ttl_timer` that might land in
/// [`crate::context::ttl_close_helpers`] during Phase 2A.9.
#[allow(clippy::too_many_lines)] // 12c.9g.2 widens the prelude (5 supervisor accessor probes vs 1 provider readiness check) by 14 lines so the spawn_blocking closure body fits within the previous 90-line budget — see commit message.
pub async fn spawn_ttl_timer_legacy(
    supervisor: &Supervisor,
    context_id: &str,
    duration: std::time::Duration,
    handle: ContextHandle,
) {
    let Some(crypto_ref) = supervisor.crypto_ref() else {
        tracing::error!(
            context_id,
            "spawn_ttl_timer: Supervisor is not attached — skipping"
        );
        return;
    };
    let Some(transport_ref) = supervisor.transport_ref() else {
        tracing::error!(
            context_id,
            "spawn_ttl_timer: Supervisor transport not initialized — skipping"
        );
        return;
    };
    let Some(event_log_ref) = supervisor.event_log_ref() else {
        tracing::error!(
            context_id,
            "spawn_ttl_timer: Supervisor event log not initialized — skipping"
        );
        return;
    };
    let contexts_ref_arc = supervisor.contexts_arc();
    let Some(task_set_arc) = supervisor.task_set_ref() else {
        tracing::error!(
            context_id,
            "spawn_ttl_timer: Supervisor task set not initialized — skipping"
        );
        return;
    };
    // Extract the cancel Notify and generation under lock, then drop.
    let (cancel, spawn_generation) = {
        let Ok(arc) = manager_methods::get_context_arc(supervisor, context_id) else {
            return;
        };
        let ctx = arc.lock().await;
        (ctx.ttl.timer.cancel.clone(), ctx.generation)
    };

    // Clone Arc-wrapped providers so the spawned task can perform
    // key destruction, relay deletion, and event logging on TTL expiry.
    let crypto = Arc::clone(crypto_ref);
    let transport = Arc::clone(transport_ref);
    let event_log = Arc::clone(event_log_ref);
    let event_tx = supervisor.event_tx_ref().cloned();
    let contexts_ref = contexts_ref_arc;
    let context_id_owned = context_id.to_owned();

    let abort_handle = {
        let mut task_set = task_set_arc.lock().await;
        task_set.spawn(async move {
            tokio::select! {
                () = tokio::time::sleep(duration) => {
                    // Timer fired. Run cleanup with exponential backoff
                    // retries (SCP-169, #612). Pass transport so relay
                    // ciphertext deletion happens on timer-initiated expiry
                    // (§5.11, #612 finding 2).
                    let result = ttl::run_ttl_expiry_with_retries(
                        &handle,
                        crypto.as_ref(),
                        Some(transport.as_ref()),
                        event_log.as_ref(),
                        &cancel,
                    ).await;

                    // Emit event to the receive buffer and decay governance
                    // state under a single lock acquisition (matches the
                    // synchronous handle_ttl_expiry path; H8 fix).
                    if let Some(entry) = contexts_ref.get(&context_id_owned) {
                        let ctx_arc = entry.value().clone();
                        drop(entry);
                        let mut guard = ctx_arc.lock().await;
                        let ctx = &mut *guard;
                        // Generation check: if the context was removed
                        // and recreated since this timer was spawned,
                        // the timer belongs to the old context — skip.
                        if ctx.generation != spawn_generation {
                            tracing::warn!(
                                context_id = %context_id_owned,
                                spawn_generation,
                                current_generation = ctx.generation,
                                "TTL timer fired for stale context generation; skipping"
                            );
                        } else if result.is_complete() {
                            let event = ContextEvent::Expired;
                            ctx.emit_event(event, &context_id_owned, event_tx.as_ref());
                            ctx.governance.timeout_task.cancel();
                            ctx.governance.decay_participation();
                        } else {
                            let event = ContextEvent::ExpiryFailed {
                                reason: result.to_string(),
                                state_transitioned: result.state_transitioned(),
                                mls_destroyed: result.mls_destroyed(),
                                sender_key_destroyed: result.sender_key_destroyed(),
                                event_logged: result.event_logged(),
                            };
                            ctx.emit_event(event, &context_id_owned, event_tx.as_ref());
                            ctx.governance.timeout_task.cancel();
                            ctx.governance.decay_participation();
                        }
                    }
                }
                () = cancel.notified() => {
                    // Timer was cancelled.
                }
            }
        })
    };

    // Store the abort handle for cancel/is_active checks (lock, then drop).
    let context_id_for_store = context_id.to_owned();
    if let Ok(ctx_arc) = manager_methods::get_context_arc(supervisor, &context_id_for_store) {
        let mut guard = ctx_arc.lock().await;
        let ctx = &mut *guard;
        ctx.ttl.timer.task = Some(abort_handle);
    }
}
