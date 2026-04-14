//! Standing contexts (contact graph) folded into [`ContextManager`].
//!
//! Standing bilateral contexts serve as the real-time communication primitive
//! (spec section 5.12.4). `standing_context(local_did, peer_did)` is a
//! get-or-create operation that returns an existing `bilateral-persistent`
//! context or creates one. Idempotent.
//!
//! On SDK initialization, [`ContextManager::reconnect_all_standing`]
//! reconnects transport for all standing contexts. Standing contexts are
//! available immediately after `sdk.init()` returns.
//!
//! See `.docs/standards/sdk-common.md` section "Standing contexts (contact
//! graph)" for the authoritative specification.
//!
//! # Lock ordering
//!
//! When acquiring multiple `ContextManager` mutexes inside this module the
//! canonical order is **per-context `Mutex` first, then `standing_contexts`**
//! (most frequently contended lock acquired innermost). All call sites in
//! this file follow this order; any new code touching both mutexes must do
//! the same to preserve a global lock-order graph free of cycles.
//!
//! `reconnect_all_standing` collects data from `standing_contexts` and
//! `local_dids` first, **drops both locks**, then acquires per-context
//! Mutexes individually. This prevents a lock ordering inversion with
//! `standing_context`, which acquires per-context Mutex then
//! `standing_contexts`.
//!
//! Additionally, [`ContextHandle`] interior `RwLock` reads MUST use
//! [`ContextHandle::try_read_state`] (sync, fail-fast) when performed inside
//! a held `Mutex` guard. The async [`ContextHandle::state`] would await on
//! the handle's `RwLock` while holding `contexts.lock()`, which deadlocks
//! against any concurrent path that already holds the handle's `RwLock` as
//! writer and is waiting on `contexts.lock()`. See [`super::lifecycle`] and
//! [`super::mod`]'s `require_active` for the same pattern.
//!
//! # SCP-138

use scp_identity::DID;
use scp_protocol::context::templates::template_params;
use scp_protocol::context::{ContextError, ContextState, TemplateId};
use sha2::{Digest, Sha256};

use super::ContextManager;

// ---------------------------------------------------------------------------
// Deterministic context ID generation
// ---------------------------------------------------------------------------

/// Generates a deterministic context ID for a standing context between two DIDs.
///
/// The ID is derived from both DIDs sorted lexicographically, ensuring the same
/// context ID is generated regardless of which peer initiates. Uses a
/// `standing:` prefix for namespace isolation and a truncated SHA-256 hash of
/// the sorted DID pair for the unique portion.
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
// ContextManager standing context methods
// ---------------------------------------------------------------------------

#[allow(clippy::significant_drop_tightening)]
impl ContextManager {
    /// Returns an existing standing context or creates a new one (contact graph).
    ///
    /// This is the primary API for the contact graph. It follows four steps:
    ///
    /// 1. Check local state for an existing `bilateral-persistent` context
    ///    with this peer DID.
    /// 2. If found and `Active`, return it. Zero network cost -- instant.
    /// 3. If not found, create one (`bilateral-persistent` template), send
    ///    invitation, return the context ID. First message queues until the
    ///    peer joins.
    /// 4. If found but peer has left (context is `Closed`, `Expired`, or
    ///    `Closing`), create a new one (re-invitation).
    ///
    /// # Arguments
    ///
    /// * `local_did` -- The local identity DID (creator of standing contexts).
    /// * `peer_did` -- The peer DID to establish a standing context with.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] if context creation fails.
    pub async fn standing_context(
        &self,
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
            if let Ok(arc) = self.get_context_arc(&context_id) {
                let ctx = arc.lock().await;
                let state = ctx.handle.try_read_state();
                match state {
                    // Step 2: Active or still being set up -- return immediately.
                    Some(ContextState::Active | ContextState::Creating) => {
                        drop(ctx);
                        let mut standing = self.standing_contexts.lock().await;
                        standing.insert(peer_did.to_string(), peer_did.clone());
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
        // ContextManager::create_context flow (membership, roles, governance).
        let params = template_params(&TemplateId::BilateralPersistent);
        match self
            .create_context(context_id.clone(), params, local_did.clone())
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
                if let Ok(arc) = self.get_context_arc(&context_id) {
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

        // Re-acquire lock to track the standing context.
        let mut standing = self.standing_contexts.lock().await;
        standing.insert(peer_did.to_string(), peer_did.clone());

        Ok(context_id)
    }

    /// Returns the number of tracked standing contexts.
    pub async fn standing_context_count(&self) -> usize {
        self.standing_contexts.lock().await.len()
    }

    /// Returns `true` if a standing context exists for the given peer DID.
    pub async fn has_standing_context(&self, peer_did: &DID) -> bool {
        self.standing_contexts
            .lock()
            .await
            .contains_key(peer_did.as_ref())
    }

    /// Registers an existing context as a standing context.
    ///
    /// Used during startup to restore standing contexts from persisted state.
    /// The context must be a `bilateral-persistent` context already registered
    /// in `self.contexts`.
    pub async fn register_standing_context(&self, peer_did: DID) {
        self.standing_contexts
            .lock()
            .await
            .insert(peer_did.to_string(), peer_did);
    }

    /// Reconnects transport for all active standing contexts.
    ///
    /// Called during SDK initialization. Iterates all tracked standing contexts
    /// and reconnects transport for those in the `Active` state. Contexts in
    /// terminal states (`Closed`, `Expired`) are skipped.
    ///
    /// This is background work -- standing contexts are available immediately
    /// after this method returns.
    ///
    /// # Returns
    ///
    /// The number of contexts successfully reconnected.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::TransportFailed`] if any reconnection fails.
    /// Partial reconnection results are still applied -- contexts that
    /// succeeded remain connected.
    pub async fn reconnect_all_standing(&self) -> Result<usize, ContextError> {
        // Phase 1: Collect standing context info and local DIDs under their
        // respective locks, then release BOTH before acquiring per-context
        // Mutexes. This prevents the lock ordering inversion that would
        // otherwise occur: standing_context() acquires per-context Mutex
        // then standing_contexts, so reconnect_all_standing must NOT hold
        // standing_contexts while acquiring per-context Mutexes.
        let standing_entries: Vec<(String, scp_identity::DID)> = {
            let standing = self.standing_contexts.lock().await;
            standing
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        };
        // standing_contexts lock DROPPED.

        let local_did_list: Vec<scp_identity::DID> = {
            let local_dids = self.local_dids.read().await;
            local_dids.iter().cloned().collect()
        };
        // local_dids lock DROPPED.

        // Phase 1b: Resolve context IDs and clone handles under individual
        // per-context Mutexes only (no standing_contexts or local_dids held).
        let mut handles: Vec<(String, super::super::ContextHandle)> = Vec::new();
        for (_key, peer_did) in &standing_entries {
            for local_did in &local_did_list {
                let context_id = generate_standing_context_id(local_did, peer_did);
                if let Ok(arc) = self.get_context_arc(&context_id) {
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
                    self.transport
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
            let local_did_set: std::collections::HashSet<DID> =
                self.local_dids.read().await.iter().cloned().collect();
            let mut standing = self.standing_contexts.lock().await;
            let to_remove: Vec<String> = standing
                .iter()
                .filter(|(_key, peer_did)| {
                    local_did_set.iter().any(|local_did| {
                        let cid = generate_standing_context_id(local_did, peer_did);
                        terminal_context_ids.contains(&cid)
                    })
                })
                .map(|(key, _)| key.clone())
                .collect();
            for key in &to_remove {
                standing.remove(key);
            }
        }

        Ok(reconnected)
    }
}
