// Module-level allow — the legacy inherent-impl form in
// `manager/standing.rs` carried `#[allow(clippy::significant_drop_tightening)]`
// on its impl block. The hoisted bodies preserve the same lock-hold-across-await
// patterns deliberately (narrowing changes lock-ordering semantics); allowing
// the lint crate-locally keeps the hoist byte-identical to the legacy behavior.
#![allow(clippy::significant_drop_tightening)]

//! Standing-context legacy survivors
//! (ADR-049 Phase 2A finalization).
//!
//! # Purpose
//!
//! Phase 2A finalization eliminated the supervisor-receiver shim for
//! standing commands — every [`StandingCommand`] now routes through the
//! per-context actor mailbox (variants carrying `(local_did, peer_did)`)
//! or directly through `Supervisor::dispatch_standing_direct` (the
//! supervisor-scoped variants). The bulk of the legacy `&Supervisor`
//! lock-and-call standing helpers (`standing_context_count_legacy`,
//! `has_standing_context_legacy`, `register_standing_context_legacy`)
//! were deleted with that shim.
//!
//! Two functions survive:
//!
//! - [`standing_context_legacy`] — get-or-create standing context, called
//!   from [`crate::context::supervisor::handle::SupervisorHandle::standing_context`]
//!   (which is what the actor-shape `standing_helpers::standing_context`
//!   delegates to) and from `Supervisor::dispatch_standing_direct`. The
//!   creation path still routes through
//!   [`crate::context::lifecycle_helpers_legacy::create_context_legacy`]
//!   until standing-pair sagas land (deferred per
//!   `.docs/adrs/DEFERRED-commit-11-saga-use-cases.md`).
//! - [`reconnect_all_standing_legacy`] — fan-out reconnect across the
//!   supervisor's standing index, called from
//!   [`crate::context::supervisor::handle::SupervisorHandle::reconnect_all_standing`]
//!   and from `Supervisor::dispatch_standing_direct`.

use scp_identity::DID;
use scp_protocol::context::templates::template_params;
use scp_protocol::context::{ContextError, ContextState, TemplateId};

use crate::context::ContextHandle;
use crate::context::supervisor::Supervisor;
use crate::context::{lifecycle_helpers_legacy, manager_methods};

// Phase 1 fix-up of ADR-049 (post-review-round-1): per-helper
// `ATTACHED_EXPECT` constants consolidated to the single
// `PROVIDER_NOT_INITIALIZED` definition in `manager_methods`.
use crate::context::manager_methods::PROVIDER_NOT_INITIALIZED as ATTACHED_EXPECT;

// ---------------------------------------------------------------------------
// standing_context_legacy (top-level, production survivor)
// ---------------------------------------------------------------------------

/// Returns an existing standing context or creates a new one (contact graph).
///
/// Hoisted body of the legacy
/// [`ContextManager::standing_context`](crate::context::standing_helpers::standing_context).
/// See the legacy method's doc comment for the full semantics.
/// Byte-identical behavior.
///
/// # Errors
///
/// Returns [`ContextError`] if context creation fails.
pub async fn standing_context_legacy(
    supervisor: &Supervisor,
    local_did: &DID,
    peer_did: &DID,
) -> Result<String, ContextError> {
    let context_id =
        crate::context::standing_helpers::generate_standing_context_id(local_did, peer_did);

    // Step 1: Check if the context exists and is Active/Creating.
    //
    // Lock ordering: `contexts` -> `standing_contexts` (see module docs).
    //
    // The handle's interior `RwLock` is read via the synchronous
    // `try_read_state()` to avoid awaiting on it while holding the
    // `contexts` mutex. Awaiting `state()` here would form a deadlock
    // cycle with any task that holds the handle's `RwLock` as writer
    // (e.g. `transition_to`) and is waiting on `contexts.lock()`.
    //
    // If `try_read_state()` returns `None` (writer currently holds the
    // lock), we treat the context as transient/terminal and fall through
    // to the create-new-context path; the TOCTOU re-check below will
    // resolve any race idempotently.
    {
        if let Ok(arc) = manager_methods::get_context_arc(supervisor, &context_id) {
            let ctx = arc.lock().await;
            let state = ctx.handle.try_read_state();
            match state {
                // Step 2: Active or still being set up -- return immediately.
                Some(ContextState::Active | ContextState::Creating) => {
                    drop(ctx);
                    // ArcSwap+write_lock pattern (ADR-049 §Decision 12).
                    let _guard = supervisor.write_lock.lock().await;
                    let snapshot = supervisor.standing_contexts_ref().load_full();
                    let mut updated: std::collections::HashMap<String, DID> = (*snapshot).clone();
                    updated.insert(peer_did.to_string(), peer_did.clone());
                    supervisor
                        .standing_contexts_ref()
                        .store(std::sync::Arc::new(updated));
                    return Ok(context_id);
                }
                // Step 4: Peer has left, context ended, or the handle's
                // state lock is currently contended -- fall through to
                // create a new one. The post-create TOCTOU re-check
                // handles any race with concurrent callers.
                Some(
                    ContextState::Closed
                    | ContextState::Expired
                    | ContextState::Closing
                    | ContextState::MigratingOut
                    | ContextState::Tombstoned,
                )
                | None => {
                    // Will create a new context below.
                }
            }
        }
    }

    // Step 3/4: Create a new bilateral-persistent context via the full
    // create_context flow (membership, roles, governance).
    let params = template_params(&TemplateId::BilateralPersistent);
    match lifecycle_helpers_legacy::create_context_legacy(
        supervisor,
        context_id.clone(),
        params,
        local_did.clone(),
        None,
    )
    .await
    {
        Ok(_) => {}
        Err(e) => {
            // TOCTOU: a concurrent call may have created the context
            // between our check and this create attempt. If the context
            // now exists and is Active/Creating, use it idempotently.
            // Otherwise propagate the original error.
            //
            // Use `try_read_state()` (sync) to avoid awaiting on the
            // handle's `RwLock` while holding `contexts.lock()`. A
            // contended state lock is treated as "not idempotent" and
            // surfaces the original create error rather than masking it.
            if let Ok(arc) = manager_methods::get_context_arc(supervisor, &context_id) {
                let ctx = arc.lock().await;
                if matches!(
                    ctx.handle.try_read_state(),
                    Some(ContextState::Active | ContextState::Creating)
                ) {
                    drop(ctx);
                    // Concurrent creation succeeded — fall through.
                } else {
                    return Err(ContextError::TransportFailed(e.to_string()));
                }
            } else {
                return Err(ContextError::TransportFailed(e.to_string()));
            }
        }
    }

    // Track the standing context (ArcSwap+write_lock, ADR-049 §Decision 12).
    {
        let _guard = supervisor.write_lock.lock().await;
        let snapshot = supervisor.standing_contexts_ref().load_full();
        let mut updated: std::collections::HashMap<String, DID> = (*snapshot).clone();
        updated.insert(peer_did.to_string(), peer_did.clone());
        supervisor
            .standing_contexts_ref()
            .store(std::sync::Arc::new(updated));
    }

    Ok(context_id)
}

// ---------------------------------------------------------------------------
// reconnect_all_standing (top-level, production survivor)
// ---------------------------------------------------------------------------

/// Reconnects transport for all active standing contexts.
///
/// Called during SDK initialization. Iterates all tracked standing contexts
/// and reconnects transport for those in the `Active` state. Contexts in
/// terminal states (`Closed`, `Expired`) are skipped.
///
/// Hoisted body of the legacy
/// [`ContextManager::reconnect_all_standing`](crate::context::standing_helpers::reconnect_all_standing).
/// See the legacy method's doc comment for the full semantics.
/// Byte-identical behavior.
///
/// # Returns
///
/// The number of contexts successfully reconnected.
///
/// # Errors
///
/// Returns [`ContextError::TransportFailed`] if any reconnection fails.
/// Partial reconnection results are still applied — contexts that
/// succeeded remain connected.
pub async fn reconnect_all_standing_legacy(supervisor: &Supervisor) -> Result<usize, ContextError> {
    // Phase 1: Collect standing context info and local DIDs under their
    // respective locks, then release BOTH before acquiring per-context
    // Mutexes. This prevents the lock ordering inversion that would
    // otherwise occur: standing_context() acquires per-context Mutex
    // then standing_contexts, so reconnect_all_standing must NOT hold
    // standing_contexts while acquiring per-context Mutexes.
    // Lock-free reads (ADR-049 §Decision 12).
    let standing_entries: Vec<(String, scp_identity::DID)> = supervisor
        .standing_contexts_ref()
        .load()
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    let local_did_list: Vec<scp_identity::DID> =
        supervisor.local_dids_ref().load().iter().cloned().collect();

    // Phase 1b: Resolve context IDs and clone handles under individual
    // per-context Mutexes only (no standing_contexts or local_dids held).
    let mut handles: Vec<(String, ContextHandle)> = Vec::new();
    for (_key, peer_did) in &standing_entries {
        for local_did in &local_did_list {
            let context_id =
                crate::context::standing_helpers::generate_standing_context_id(local_did, peer_did);
            if let Ok(arc) = manager_methods::get_context_arc(supervisor, &context_id) {
                let ctx = arc.lock().await;
                handles.push((context_id, ctx.handle.clone()));
                break;
            }
        }
    }

    // Phase 2: Iterate collected handles without any locks held.
    // Track terminal context IDs for eviction in Phase 3.
    let mut reconnected = 0;
    let mut terminal_context_ids = Vec::new();
    for (context_id, handle) in &handles {
        let state = handle.state().await;
        match state {
            ContextState::Active => {
                let context_id_bytes = scp_protocol::context::context_id_bytes(context_id);
                supervisor
                    .transport_ref()
                    .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?
                    .publish_context(&context_id_bytes, handle.params())
                    .map_err(|e| {
                        ContextError::TransportFailed(format!(
                            "reconnection failed for context {context_id}: {e}"
                        ))
                    })?;
                reconnected += 1;
            }
            // Standing contexts in terminal states are candidates for
            // eviction to prevent unbounded map growth.
            ContextState::Closed | ContextState::Expired | ContextState::Tombstoned => {
                terminal_context_ids.push(context_id.clone());
            }
            _ => {} // Creating, Closing, MigratingOut -- transient, keep
        }
    }

    // Phase 3: Evict standing contexts in terminal states.
    // Since generate_standing_context_id hashes the DIDs, we check each
    // standing entry by regenerating its context ID and comparing.
    // Lock ordering fix: acquire local_dids BEFORE standing_contexts
    // to match the canonical order (per-context first, then standing).
    // Collecting into a HashSet avoids holding the RwLock across the
    // standing_contexts lock acquisition.
    if !terminal_context_ids.is_empty() {
        // Lock-free read of local_dids (ADR-049 §Decision 12).
        let local_did_set: std::collections::HashSet<DID> =
            supervisor.local_dids_ref().load().iter().cloned().collect();
        // ArcSwap+write_lock for the standing_contexts mutation.
        let _guard = supervisor.write_lock.lock().await;
        let snapshot = supervisor.standing_contexts_ref().load_full();
        let to_remove: Vec<String> = snapshot
            .iter()
            .filter(|(_key, peer_did)| {
                local_did_set.iter().any(|local_did| {
                    let cid = crate::context::standing_helpers::generate_standing_context_id(
                        local_did, peer_did,
                    );
                    terminal_context_ids.contains(&cid)
                })
            })
            .map(|(key, _)| key.clone())
            .collect();
        if !to_remove.is_empty() {
            let mut updated: std::collections::HashMap<String, DID> = (*snapshot).clone();
            for key in &to_remove {
                updated.remove(key);
            }
            supervisor
                .standing_contexts_ref()
                .store(std::sync::Arc::new(updated));
        }
    }

    Ok(reconnected)
}
