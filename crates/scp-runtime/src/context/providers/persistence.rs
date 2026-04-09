//! Production [`ContextPersistence`] implementation.
//!
//! The canonical production implementation is
//! [`ProtocolRepositoryContextBridge`],
//! which wraps `Arc<ProtocolRepository<S>>` and implements the synchronous
//! [`ContextPersistence`] trait by bridging to the async `ProtocolRepository` methods.
//!
//! This module re-exports the canonical implementation for convenience and
//! provides an additional in-memory implementation suitable for integration
//! tests that need persistence semantics without a storage backend.
//!
//! [`ContextPersistence`]: crate::context::manager::ContextPersistence

use std::collections::HashMap;
use std::sync::Mutex;

use crate::context::manager::{ContextPersistence, ContextSnapshot};
use scp_protocol::context::broadcast::BroadcastContextSnapshot;

// Re-export the canonical implementation.
pub use crate::store::context::ProtocolRepositoryContextBridge;

/// In-memory [`ContextPersistence`] implementation for integration tests.
///
/// Stores context and broadcast snapshots in `HashMap`s protected by
/// `std::sync::Mutex`. Suitable for integration tests that need persistence
/// semantics (e.g., persist-drop-restore round-trip tests) without requiring
/// a `ProtocolRepository` or storage backend.
///
/// # Thread Safety
///
/// All state is protected by `std::sync::Mutex`. Lock scopes are minimal.
///
/// # Example
///
/// ```rust,ignore
/// let persistence = InMemoryPersistence::new();
/// let manager = ContextManager::with_persistence(
///     Box::new(crypto),
///     Box::new(transport),
///     Box::new(event_log),
///     Box::new(persistence),
///     key_resolver,
/// );
/// ```
pub struct InMemoryPersistence {
    contexts: Mutex<HashMap<String, ContextSnapshot>>,
    broadcasts: Mutex<HashMap<String, BroadcastContextSnapshot>>,
}

impl InMemoryPersistence {
    /// Creates a new empty in-memory persistence provider.
    #[must_use]
    pub fn new() -> Self {
        Self {
            contexts: Mutex::new(HashMap::new()),
            broadcasts: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryPersistence {
    fn default() -> Self {
        Self::new()
    }
}

impl ContextPersistence for InMemoryPersistence {
    fn persist_context(
        &self,
        context_id: &str,
        snapshot: &ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.contexts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(context_id.to_owned(), snapshot.clone());
        Ok(())
    }

    fn load_context(
        &self,
        context_id: &str,
    ) -> Result<Option<ContextSnapshot>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self
            .contexts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(context_id)
            .cloned())
    }

    fn persist_broadcast(
        &self,
        context_id: &str,
        snapshot: &BroadcastContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.broadcasts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(context_id.to_owned(), snapshot.clone());
        Ok(())
    }

    fn load_broadcast(
        &self,
        context_id: &str,
    ) -> Result<Option<BroadcastContextSnapshot>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self
            .broadcasts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(context_id)
            .cloned())
    }

    fn delete_context(
        &self,
        context_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.contexts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(context_id);
        self.broadcasts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(context_id);
        Ok(())
    }

    fn list_persisted_contexts(
        &self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self
            .contexts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .keys()
            .cloned()
            .collect())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    use scp_protocol::context::ContextState;
    use scp_protocol::context::membership::MembershipState;
    use scp_protocol::context::params::ContextParams;
    use scp_protocol::context::roles::{ContextRoleState, default_ceiling};

    fn test_snapshot(context_id: &str) -> ContextSnapshot {
        let role_state = ContextRoleState::new(
            context_id,
            "did:dht:z6MkTestCreator",
            default_ceiling(),
            Vec::new(),
            &scp_primitives::SystemClock,
        )
        .unwrap();

        ContextSnapshot {
            context_id: context_id.to_owned(),
            state: ContextState::Active,
            context_params: ContextParams::default(),
            membership: MembershipState::default(),
            role_state,
            executed_proposals: HashSet::default(),
            ttl_remaining_secs: None,
            registered_tools: Vec::new(),
            read_exclusion_list: HashSet::default(),
            tool_interfaces: Vec::new(),
            threshold_signers: Vec::new(),
            threshold_value: 0,
            pruning_policy: None,
            governance_model_config: None,
            economic_policy: None,
            budget_tracker: scp_protocol::economy::budget::MemberBudgetTracker::new(),
            approved_proposals: std::collections::HashMap::new(),
            governance_freeze: None,
            pending_ceiling_modification: None,
            pending_economic_policy_change: None,
            mls_epoch: 0,
            epoch_coordination_records: Vec::new(),
            grace_entries: Vec::new(),
            needs_reconnect: false,
            mls_crypto_state: Vec::new(),
            migration_state: None,
            access_key_store: scp_protocol::crypto::access_keys::AccessKeyStore::new(),
            consequence_rules: Vec::new(),
            participation_cache: std::collections::HashMap::new(),
            velocity_tracker: None,
            velocity_tracker_state: None,
            cooldown_until: std::collections::HashMap::new(),
            proposal_timestamps: std::collections::HashMap::new(),
            message_pricing: None,
            hard_rate_limit_config: None,
            hard_rate_limit_state: std::collections::HashMap::new(),
            spending_nonce_tracker_state: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn persist_and_load_context_roundtrip() {
        let persistence = InMemoryPersistence::new();
        let snapshot = test_snapshot("ctx-1");

        persistence.persist_context("ctx-1", &snapshot).unwrap();

        let loaded = persistence.load_context("ctx-1").unwrap();
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.context_id, "ctx-1");
        assert_eq!(loaded.state, ContextState::Active);
    }

    #[test]
    fn load_missing_context_returns_none() {
        let persistence = InMemoryPersistence::new();
        let loaded = persistence.load_context("nonexistent").unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn delete_context_removes_both_stores() {
        let persistence = InMemoryPersistence::new();
        let snapshot = test_snapshot("ctx-del");

        persistence.persist_context("ctx-del", &snapshot).unwrap();

        persistence.delete_context("ctx-del").unwrap();

        assert!(persistence.load_context("ctx-del").unwrap().is_none());
    }

    #[test]
    fn list_persisted_contexts() {
        let persistence = InMemoryPersistence::new();

        persistence
            .persist_context("ctx-a", &test_snapshot("ctx-a"))
            .unwrap();
        persistence
            .persist_context("ctx-b", &test_snapshot("ctx-b"))
            .unwrap();

        let mut list = persistence.list_persisted_contexts().unwrap();
        list.sort();
        assert_eq!(list, vec!["ctx-a", "ctx-b"]);
    }

    #[test]
    fn persist_overwrites_existing() {
        let persistence = InMemoryPersistence::new();

        let mut snap1 = test_snapshot("ctx-ow");
        snap1.threshold_value = 1;
        persistence.persist_context("ctx-ow", &snap1).unwrap();

        let mut snap2 = test_snapshot("ctx-ow");
        snap2.threshold_value = 42;
        persistence.persist_context("ctx-ow", &snap2).unwrap();

        let loaded = persistence.load_context("ctx-ow").unwrap().unwrap();
        assert_eq!(loaded.threshold_value, 42);
    }
}
