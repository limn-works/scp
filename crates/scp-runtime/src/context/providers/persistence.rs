//! Production [`ContextPersistence`] implementation.
//!
//! The canonical production implementation is
//! [`ProtocolRepositoryContextBridge`],
//! which wraps `Arc<ProtocolRepository<S>>` and implements the async
//! [`ContextPersistence`] trait by `.await`-ing the async `ProtocolRepository`
//! methods directly (ADR-049 Decision 7).
//!
//! This module re-exports the canonical implementation for convenience and,
//! under `#[cfg(any(test, feature = "testing"))]`, an in-memory implementation
//! for integration tests that need persistence semantics without a storage
//! backend.
//!
//! [`ContextPersistence`]: crate::context::persistence::ContextPersistence

// Every import below serves `InMemoryPersistence` alone, so each carries the
// same gate the type does; a shipped build of this module holds only the
// `ProtocolRepositoryContextBridge` re-export.
#[cfg(any(test, feature = "testing"))]
use std::collections::HashMap;
#[cfg(any(test, feature = "testing"))]
#[allow(
    clippy::disallowed_types,
    reason = "`ContextPersistence` is async (ADR-049 Decision 7), but this in-memory map's critical section is a synchronous lock→mutate→drop with NO await held across the guard, so `std::sync::Mutex` is correct — a `tokio::sync::Mutex` would add a needless async lock where none is required."
)]
use std::sync::Mutex;

#[cfg(any(test, feature = "testing"))]
use async_trait::async_trait;

#[cfg(any(test, feature = "testing"))]
use crate::context::persistence::ContextPersistence;
#[cfg(any(test, feature = "testing"))]
use crate::context::state::ContextSnapshot;

// Re-export the canonical implementation.
pub use crate::store::context::ProtocolRepositoryContextBridge;

/// In-memory [`ContextPersistence`] implementation for integration tests.
///
/// Stores context snapshots in a `HashMap` protected by
/// `std::sync::Mutex`. Suitable for integration tests that need persistence
/// semantics (e.g., persist-drop-restore round-trip tests) without requiring
/// a `ProtocolRepository` or storage backend.
///
/// Gated behind `#[cfg(any(test, feature = "testing"))]`, so dead-code
/// elimination removes it from every shipped artifact and the ADR-062
/// §Decision 6 feature-graph gate can prove its absence. The production
/// implementation of the trait is [`ProtocolRepositoryContextBridge`].
///
/// # Thread Safety
///
/// All state is protected by `std::sync::Mutex`. Lock scopes are minimal.
///
/// # Example
///
/// ```rust,ignore
/// let persistence: Box<dyn ContextPersistence> = Box::new(InMemoryPersistence::new());
/// let supervisor = Supervisor::with_providers(
///     crypto,
///     transport,
///     event_log,
///     key_resolver,
///     Some(persistence),
///     payment_adapter,
///     event_tx,
///     clock,
///     mls_storage,
/// );
/// ```
#[cfg(any(test, feature = "testing"))]
pub struct InMemoryPersistence {
    #[allow(
        clippy::disallowed_types,
        reason = "`ContextPersistence` is async (ADR-049 Decision 7), but this map's critical section is a synchronous lock→mutate→drop with NO await held across the guard, so `std::sync::Mutex` is correct — a `tokio::sync::Mutex` would add a needless async lock where none is required."
    )]
    contexts: Mutex<HashMap<String, ContextSnapshot>>,
}

#[cfg(any(test, feature = "testing"))]
#[allow(
    clippy::disallowed_types,
    reason = "`ContextPersistence` is async (ADR-049 Decision 7), but this map's critical section is a synchronous lock→mutate→drop with NO await held across the guard, so `std::sync::Mutex` is correct — a `tokio::sync::Mutex` would add a needless async lock where none is required."
)]
impl InMemoryPersistence {
    /// Creates a new empty in-memory persistence provider.
    #[must_use]
    pub fn new() -> Self {
        Self {
            contexts: Mutex::new(HashMap::new()),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl Default for InMemoryPersistence {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "testing"))]
#[async_trait]
impl ContextPersistence for InMemoryPersistence {
    async fn persist_context(
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

    async fn load_context(
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

    async fn delete_context(
        &self,
        context_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.contexts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(context_id);
        Ok(())
    }

    async fn list_persisted_contexts(
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
            &scp_clock::SystemClock,
        )
        .unwrap();

        ContextSnapshot {
            context_id: context_id.to_owned(),
            creation_timestamp_secs: 1_700_000_000,
            state: ContextState::Active,
            context_params: ContextParams::default(),
            membership: MembershipState::default(),
            role_state,
            event_log_merkle_root: [0u8; 32],
            executed_proposals: HashSet::default(),
            ttl_deadline_secs: None,
            registered_outlets: Vec::new(),
            read_exclusion_list: HashSet::default(),
            outlet_interfaces: Vec::new(),
            threshold_signers: Vec::new(),
            threshold_value: 0,
            pruning_policy: None,
            governance_model_config: None,
            economic_policy: None,
            budget_tracker: scp_protocol::economy::budget::MemberBudgetTracker::new(),
            approved_proposals: std::collections::HashMap::new(),
            next_proposal_seq: 0,
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
            revoked_spending_ucan_cids: std::collections::HashSet::new(),
            pending_commits: std::collections::VecDeque::new(),
            commit_fault: None,
            checkpoint_events_since: 0,
            checkpoint_last_time_secs: 0,
            generation: 0,
            routing: crate::context::actor::state::ContextRouting::Broadcast,
            saga_pending: std::collections::HashMap::new(),
            xctx_committed_outputs: std::collections::HashMap::new(),
            xctx_committed_stream_outputs: std::collections::HashMap::new(),
            xctx_committed_invocations: std::collections::HashSet::new(),
            xctx_caller_reservations: std::collections::HashMap::new(),
            xctx_nonce_dedup: std::collections::HashMap::new(),
            caveat_counters: std::collections::HashMap::new(),
            stream_reservations: std::collections::HashMap::new(),
            broadcast: None,
        }
    }

    #[tokio::test]
    async fn persist_and_load_context_roundtrip() {
        let persistence = InMemoryPersistence::new();
        let snapshot = test_snapshot("ctx-1");

        persistence
            .persist_context("ctx-1", &snapshot)
            .await
            .unwrap();

        let loaded = persistence.load_context("ctx-1").await.unwrap();
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.context_id, "ctx-1");
        assert_eq!(loaded.state, ContextState::Active);
    }

    #[tokio::test]
    async fn load_missing_context_returns_none() {
        let persistence = InMemoryPersistence::new();
        let loaded = persistence.load_context("nonexistent").await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn delete_context_removes_both_stores() {
        let persistence = InMemoryPersistence::new();
        let snapshot = test_snapshot("ctx-del");

        persistence
            .persist_context("ctx-del", &snapshot)
            .await
            .unwrap();

        persistence.delete_context("ctx-del").await.unwrap();

        assert!(persistence.load_context("ctx-del").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn list_persisted_contexts() {
        let persistence = InMemoryPersistence::new();

        persistence
            .persist_context("ctx-a", &test_snapshot("ctx-a"))
            .await
            .unwrap();
        persistence
            .persist_context("ctx-b", &test_snapshot("ctx-b"))
            .await
            .unwrap();

        let mut list = persistence.list_persisted_contexts().await.unwrap();
        list.sort();
        assert_eq!(list, vec!["ctx-a", "ctx-b"]);
    }

    #[tokio::test]
    async fn persist_preserves_creation_timestamp_secs() {
        let persistence = InMemoryPersistence::new();
        let mut snapshot = test_snapshot("ctx-creation-ts");
        snapshot.creation_timestamp_secs = 1_711_000_555;

        persistence
            .persist_context("ctx-creation-ts", &snapshot)
            .await
            .unwrap();

        let loaded = persistence
            .load_context("ctx-creation-ts")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            loaded.creation_timestamp_secs, 1_711_000_555,
            "the convergent creation time must survive persist → load so restore re-arms a \
             convergent TTL deadline"
        );
    }

    #[tokio::test]
    async fn persist_overwrites_existing() {
        let persistence = InMemoryPersistence::new();

        let mut snap1 = test_snapshot("ctx-ow");
        snap1.threshold_value = 1;
        persistence.persist_context("ctx-ow", &snap1).await.unwrap();

        let mut snap2 = test_snapshot("ctx-ow");
        snap2.threshold_value = 42;
        persistence.persist_context("ctx-ow", &snap2).await.unwrap();

        let loaded = persistence.load_context("ctx-ow").await.unwrap().unwrap();
        assert_eq!(loaded.threshold_value, 42);
    }
}
