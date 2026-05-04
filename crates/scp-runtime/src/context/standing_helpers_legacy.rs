// Module-level allow — the legacy inherent-impl form in
// `manager/standing.rs` carried `#[allow(clippy::significant_drop_tightening)]`
// on its impl block. The hoisted bodies preserve the same lock-hold-across-await
// patterns deliberately (narrowing changes lock-ordering semantics); allowing
// the lint crate-locally keeps the hoist byte-identical to the legacy behavior.
#![allow(clippy::significant_drop_tightening)]

//! Standing-context helpers with explicit-collaborator signatures
//! (ADR-049 commit 12).
//!
//! # Purpose
//!
//! This module hoists the standing-domain methods that the actor handler
//! in [`crate::context::actor::handlers::standing`] currently reaches via
//! `view.manager().X(...)`. After ADR-049 commit 12 (`ContextManager`
//! deletion) every helper takes `&Supervisor`; Phase 2 of the
//! post-review-round-1 plan will retarget the handler-side helpers to
//! `&mut PerContextState + &ActorDeps`.
//!
//! This file is the standing counterpart to
//! [`crate::context::messaging_helpers`] (12b.1, 12c.1, 12c.1b),
//! [`crate::context::lifecycle_helpers`] (12c.2),
//! [`crate::context::governance_helpers`] (12c.3b),
//! [`crate::context::economy_helpers`] (12c.3a), and
//! [`crate::context::trust_recovery_helpers`] (12c.3a).
//!
//! # Behavior preservation
//!
//! Every hoisted free function is **behavior-preserving by construction**.
//! Its body is a verbatim copy of the legacy inherent method's body with
//! `self.X` replaced by either:
//!
//! - `manager_methods::X(supervisor, ...)` /
//!   `<domain>_helpers::X(supervisor, ...)` for the cross-domain and
//!   per-domain free-function helpers hoisted from `ContextManager` in
//!   ADR-049 commit 12c.9g.1 (helper bodies migrated to direct calls in
//!   commit 12c.9g.2; no `mgr` derivation), or
//! - `supervisor.X_ref().ok_or(NotInitialized)?` for provider slots
//!   lifted to the supervisor in ADR-049 commit 12c.9a-9b.
//!
//! The legacy inherent methods on
//! [`Supervisor`](crate::context::supervisor::Supervisor) remain as
//! one-line forwarders; they are deleted alongside the outer shim in a
//! later ADR-049 commit when the actor handler body owns the standing
//! path directly.
//!
//! # Top-level methods hoisted (actor-handler entry points)
//!
//! [`standing_context`], [`standing_context_count`],
//! [`has_standing_context`], [`register_standing_context`],
//! [`reconnect_all_standing`].
//!
//! # Pure helpers (no `mgr` parameter)
//!
//! [`generate_standing_context_id`] is a pure function. It is re-exported
//! from `manager/standing.rs` as well to preserve the legacy public path
//! for test code that imports it directly.

use scp_identity::DID;
use scp_protocol::context::templates::template_params;
use scp_protocol::context::{ContextError, ContextState, TemplateId};
use sha2::{Digest, Sha256};

use crate::context::ContextHandle;
use crate::context::manager_methods;
use crate::context::supervisor::Supervisor;

// Phase 1 fix-up of ADR-049 (post-review-round-1): per-helper
// `ATTACHED_EXPECT` constants consolidated to the single
// `PROVIDER_NOT_INITIALIZED` definition in `manager_methods`.
use crate::context::manager_methods::PROVIDER_NOT_INITIALIZED as ATTACHED_EXPECT;

// ---------------------------------------------------------------------------
// generate_standing_context_id (pure helper, no mgr parameter)
// ---------------------------------------------------------------------------

/// Generates a deterministic context ID for a standing context between two DIDs.
///
/// The ID is derived from both DIDs sorted lexicographically, ensuring the same
/// context ID is generated regardless of which peer initiates. Uses a
/// `standing:` prefix for namespace isolation and a truncated SHA-256 hash of
/// the sorted DID pair for the unique portion.
///
/// Hoisted body of the legacy
/// [`crate::context::standing_helpers::generate_standing_context_id`]
/// free function (ADR-049 commit 12). The legacy free function remains
/// as a thin re-export so test code importing the legacy path keeps
/// working through the shim window.
pub fn generate_standing_context_id(local_did: &DID, peer_did: &DID) -> String {
    // Sort to ensure determinism regardless of direction.
    let (a, b) = if local_did.as_ref() <= peer_did.as_ref() {
        (local_did.as_ref(), peer_did.as_ref())
    } else {
        (peer_did.as_ref(), local_did.as_ref())
    };
    // Hash the sorted DIDs with the standing prefix for a stable, deterministic ID.
    let mut hasher = Sha256::new();
    hasher.update(b"standing:");
    hasher.update(a.as_bytes());
    hasher.update(b":");
    hasher.update(b.as_bytes());
    let hash = hasher.finalize();
    // Use the full 32-byte hash to avoid birthday-bound collisions.
    // Truncating to 8 bytes (64 bits) has a ~50% collision probability
    // at ~5 billion standing contexts (birthday paradox).
    format!("standing-{}", hex::encode(hash))
}

// ---------------------------------------------------------------------------
// 1. standing_context (top-level, actor-handler entry point)
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
    let context_id = generate_standing_context_id(local_did, peer_did);

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
    match crate::context::lifecycle_helpers_legacy::create_context_legacy(
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
// 2. standing_context_count (top-level, actor-handler entry point)
// ---------------------------------------------------------------------------

/// Returns the number of tracked standing contexts.
///
/// Hoisted body of the legacy `ContextManager::standing_context_count`
/// method. `async` is preserved (despite no `await` after the lock-free
/// migration) to keep the signature symmetric with the rest of the
/// standing-domain helpers and the legacy actor-handler entry point.
#[allow(clippy::unused_async)]
pub async fn standing_context_count_legacy(supervisor: &Supervisor) -> usize {
    // Lock-free read (ADR-049 §Decision 12).
    supervisor.standing_contexts_ref().load().len()
}

// ---------------------------------------------------------------------------
// 3. has_standing_context (top-level, actor-handler entry point)
// ---------------------------------------------------------------------------

/// Returns `true` if a standing context exists for the given peer DID.
///
/// Hoisted body of the legacy `ContextManager::has_standing_context`
/// method. `async` is preserved (despite no `await` after the
/// lock-free migration) to match the rest of the standing-domain
/// helper signatures.
#[allow(clippy::unused_async)]
pub async fn has_standing_context_legacy(supervisor: &Supervisor, peer_did: &DID) -> bool {
    // Lock-free read (ADR-049 §Decision 12).
    supervisor
        .standing_contexts_ref()
        .load()
        .contains_key(peer_did.as_ref())
}

// ---------------------------------------------------------------------------
// 4. register_standing_context (top-level, actor-handler entry point)
// ---------------------------------------------------------------------------

/// Registers an existing context as a standing context.
///
/// Used during startup to restore standing contexts from persisted state.
/// The context must be a `bilateral-persistent` context already registered
/// in the manager's `contexts` map.
///
/// Hoisted body of the legacy
/// [`ContextManager::register_standing_context`](crate::context::standing_helpers::register_standing_context).
pub async fn register_standing_context_legacy(supervisor: &Supervisor, peer_did: DID) {
    // ArcSwap+write_lock pattern (ADR-049 §Decision 12).
    let _guard = supervisor.write_lock.lock().await;
    let snapshot = supervisor.standing_contexts_ref().load_full();
    let mut updated: std::collections::HashMap<String, DID> = (*snapshot).clone();
    updated.insert(peer_did.to_string(), peer_did);
    supervisor
        .standing_contexts_ref()
        .store(std::sync::Arc::new(updated));
}

// ---------------------------------------------------------------------------
// 5. reconnect_all_standing (top-level, actor-handler entry point)
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
            let context_id = generate_standing_context_id(local_did, peer_did);
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
                    let cid = generate_standing_context_id(local_did, peer_did);
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
