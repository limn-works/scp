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
//! # Hoist (ADR-049 commit 12c.4)
//!
//! The five `ContextManager` methods reached by the standing actor handler
//! (`standing_context`, `standing_context_count`, `has_standing_context`,
//! `register_standing_context`, `reconnect_all_standing`) now forward to
//! hoisted `pub async fn` free functions in
//! [`crate::context::standing_helpers`]. See the helper module for the
//! authoritative bodies; the methods here are one-line forwarders that
//! preserve the legacy `mgr.X(...)` call shape during the
//! commits-10-to-12 shim window.
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
//! Additionally, [`ContextHandle`](crate::context::ContextHandle) interior
//! `RwLock` reads MUST use
//! [`ContextHandle::try_read_state`](crate::context::ContextHandle::try_read_state)
//! (sync, fail-fast) when performed inside a held `Mutex` guard. The async
//! [`ContextHandle::state`](crate::context::ContextHandle::state) would
//! await on the handle's `RwLock` while holding `contexts.lock()`, which
//! deadlocks against any concurrent path that already holds the handle's
//! `RwLock` as writer and is waiting on `contexts.lock()`. See
//! [`super::lifecycle`] and [`super::mod`]'s `require_active` for the
//! same pattern.
//!
//! # SCP-138

use scp_identity::DID;
use scp_protocol::context::ContextError;

use super::ContextManager;

// ---------------------------------------------------------------------------
// Deterministic context ID generation (legacy re-export)
// ---------------------------------------------------------------------------

/// Generates a deterministic context ID for a standing context between two DIDs.
///
/// Legacy thin re-export to the hoisted
/// [`crate::context::standing_helpers::generate_standing_context_id`]
/// pure helper (ADR-049 commit 12c.4). Test code that imports the legacy
/// path keeps working through the shim window — `manager/tests/lifecycle.rs`
/// references it via `super::super::standing::generate_standing_context_id`.
/// `dead_code` allow because the only callers are inside `#[cfg(test)]`
/// modules; deleted alongside the wider standing surface in commit 12f.
#[allow(dead_code)]
pub fn generate_standing_context_id(local_did: &DID, peer_did: &DID) -> String {
    crate::context::standing_helpers::generate_standing_context_id(local_did, peer_did)
}

// ---------------------------------------------------------------------------
// ContextManager standing context methods (forwarders)
// ---------------------------------------------------------------------------

impl ContextManager {
    /// Returns an existing standing context or creates a new one (contact graph).
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::standing_helpers::standing_context`] free
    /// function (ADR-049 commit 12c.4). Deleted in a later commit
    /// alongside every other `ContextManager` standing surface.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] if context creation fails.
    pub async fn standing_context(
        &self,
        local_did: &DID,
        peer_did: &DID,
    ) -> Result<String, ContextError> {
        crate::context::standing_helpers::standing_context(self, local_did, peer_did).await
    }

    /// Returns the number of tracked standing contexts.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::standing_helpers::standing_context_count`] free
    /// function (ADR-049 commit 12c.4).
    pub async fn standing_context_count(&self) -> usize {
        crate::context::standing_helpers::standing_context_count(self).await
    }

    /// Returns `true` if a standing context exists for the given peer DID.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::standing_helpers::has_standing_context`] free
    /// function (ADR-049 commit 12c.4).
    pub async fn has_standing_context(&self, peer_did: &DID) -> bool {
        crate::context::standing_helpers::has_standing_context(self, peer_did).await
    }

    /// Registers an existing context as a standing context.
    ///
    /// Used during startup to restore standing contexts from persisted state.
    /// The context must be a `bilateral-persistent` context already registered
    /// in `self.contexts`.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::standing_helpers::register_standing_context`]
    /// free function (ADR-049 commit 12c.4).
    pub async fn register_standing_context(&self, peer_did: DID) {
        crate::context::standing_helpers::register_standing_context(self, peer_did).await;
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
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::standing_helpers::reconnect_all_standing`] free
    /// function (ADR-049 commit 12c.4).
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
        crate::context::standing_helpers::reconnect_all_standing(self).await
    }
}
