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
        // Hold the standing_contexts lock only for the check, then drop
        // before the async create_context call to avoid holding the lock
        // across an await point.
        {
            let mut standing = self.standing_contexts.lock().await;
            let contexts = self.contexts.lock().await;
            if let Some(ctx) = contexts.get(&context_id) {
                let state = ctx.handle.state().await;
                match state {
                    // Step 2: Active or still being set up -- return immediately.
                    ContextState::Active | ContextState::Creating => {
                        standing.insert(peer_did.to_string(), peer_did.clone());
                        return Ok(context_id);
                    }
                    // Step 4: Peer has left or context ended -- fall through to
                    // create a new one.
                    ContextState::Closed
                    | ContextState::Expired
                    | ContextState::Closing
                    | ContextState::MigratingOut
                    | ContextState::Tombstoned => {
                        // Will create a new context below.
                    }
                }
            }
            // Drop both locks before async creation.
            drop(contexts);
            drop(standing);
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
                let contexts = self.contexts.lock().await;
                if let Some(ctx) = contexts.get(&context_id) {
                    let state = ctx.handle.state().await;
                    if matches!(state, ContextState::Active | ContextState::Creating) {
                        drop(contexts);
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
        // Phase 1: Collect (context_id, handle) pairs under locks, then release.
        // This avoids holding any locks across await points.
        let handles: Vec<(String, super::super::ContextHandle)> = {
            let standing = self.standing_contexts.lock().await;
            let local_dids = self.local_dids.read().await;
            let contexts = self.contexts.lock().await;

            let mut out = Vec::new();
            for peer_did in standing.values() {
                for local_did in local_dids.iter() {
                    let context_id = generate_standing_context_id(local_did, peer_did);
                    if let Some(ctx) = contexts.get(&context_id) {
                        out.push((context_id, ctx.handle.clone()));
                        break;
                    }
                }
            }
            out
        };

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
        if !terminal_context_ids.is_empty() {
            let mut standing = self.standing_contexts.lock().await;
            let local_dids = self.local_dids.read().await;
            let to_remove: Vec<String> = standing
                .iter()
                .filter(|(_key, peer_did)| {
                    local_dids.iter().any(|local_did| {
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
