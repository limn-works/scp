// Module-level allow — the legacy inherent-impl form in
// `manager/lifecycle.rs` (which housed the TTL/close path) carried
// `#[allow(clippy::significant_drop_tightening)]` on its impl block.
// The hoisted bodies preserve the same lock-hold-across-await patterns
// deliberately (narrowing changes lock-ordering semantics across the
// per-context mutex); allowing the lint crate-locally keeps the hoist
// byte-identical to the legacy behavior.
#![allow(clippy::significant_drop_tightening)]

//! Legacy TTL-close timer-spawn entry point
//! (ADR-049 Phase 2A.6, post-finalization residual).
//!
//! # Purpose
//!
//! Phase 2A finalization eliminated the supervisor-receiver shim for
//! TTL-close commands — every [`TtlCloseCommand`] now routes through the
//! per-context actor mailbox via
//! [`Supervisor::dispatch_ttl_close_command`].
//! The bulk of the legacy `&Supervisor` lock-and-call TTL helpers
//! (`finalize_close`, `handle_ttl_expiry`, `propose_ttl_extension`,
//! `reset_ttl_timer`, `start_ttl_timer`) were deleted with that shim.
//!
//! [`spawn_ttl_timer_legacy`] survives because non-domain callers
//! (lifecycle restore / finalize-create / import paths in
//! `lifecycle_helpers`, the governance TTL-extension proposal handler in
//! `governance_helpers`, and the actor-shape
//! `ttl_close_helpers::{start_ttl_timer,reset_ttl_timer}` escape) still
//! need a single shared spawn-timer entry point that owns the supervisor's
//! `task_set` and contexts map. Phase 2A.9 (lifecycle migration) revisits
//! timer ownership end-to-end and removes this last residual.
//!
//! # `_legacy` suffix
//!
//! The `_legacy` suffix is retained to make the shim-fallback intent
//! legible at every call site and to avoid future namespace clashes with
//! any actor-shape `spawn_ttl_timer` that might land in
//! [`crate::context::ttl_close_helpers`] during Phase 2A.9.

use std::sync::Arc;

use scp_protocol::context::membership::ContextEvent;

use crate::context::ContextHandle;
use crate::context::manager_methods;
use crate::context::supervisor::Supervisor;
use crate::context::ttl;

// ---------------------------------------------------------------------------
// spawn_ttl_timer_legacy (sole survivor of Phase 2A finalization)
//
// Called from production lifecycle paths
// (`lifecycle_helpers::{restore_context,finalize_create,import_context}`,
// `governance_helpers::handle_ttl_extension_proposal`) and the actor-shape
// `ttl_close_helpers::{start_ttl_timer,reset_ttl_timer}` escape until
// Phase 2A.9 (lifecycle migration) revisits timer ownership end-to-end.
// All other legacy helpers (`finalize_close`, `handle_ttl_expiry`,
// `propose_ttl_extension`, `reset_ttl_timer`, `start_ttl_timer`) were
// deleted with the supervisor-receiver shim in Phase 2A finalization.
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
