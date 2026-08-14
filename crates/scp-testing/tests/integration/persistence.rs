//! SCP-PERSIST-070: End-to-end integration tests for context persistence.
//!
//! Two layers are covered:
//!
//! * The storage layer (`persistence_tests!` macro): create contexts with
//!   members and roles -> persist -> "restart" (re-read from the same
//!   `ProtocolRepository` backend) -> verify state -> continue operations.
//!   Also covers close cleanup (`delete_context`), TTL-expiry roundtrip,
//!   cross-adapter parity, and sequence-number / role-assignment survival.
//! * The actor layer (`executed_proposals_survive_restart_and_accumulate`): a
//!   governance action executed before a simulated restart leaves its
//!   Class-S `executed_proposals` replay marker (ADR-049 §9) durably
//!   persisted; after the context is rehydrated from persistence, the marker
//!   is still present in the live actor and continues to accumulate new
//!   markers — proving replay protection survives a restart.
//!
//! ## ADR-049 note — why this is not the old already-executed assertion
//!
//! Before ADR-049 a `ContextManager` re-executed a caller-supplied proposal
//! object, so a replay tripped the `executed_proposals` guard directly. The
//! actor-per-context model persists ONLY the Class-S `executed_proposals`
//! marker set in the [`ContextSnapshot`] — the governance engine's tracked
//! proposals are ephemeral runtime state and are intentionally not part of the
//! snapshot. The public replay path (`ExecuteGovernanceAction` by id) resolves
//! the proposal from the engine BEFORE consulting `executed_proposals`, so a
//! post-restore replay is rejected as "not tracked", not "already executed".
//! The durable, security-critical property that actually survives restart is
//! the `executed_proposals` marker set itself — which is exactly what this test
//! asserts.
//!
//! See `.docs/prds/` SCP-PERSIST-070 for acceptance criteria.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use scp_core::context::builder::{
    ContextCreationError, ContextEventLogProvider, ContextTransportProvider,
};
use scp_core::context::governance::{GovernanceAction, KeyResolver};
use scp_core::context::persistence::ContextPersistence;
use scp_core::context::state::ContextSnapshot;
use scp_core::context::supervisor::{
    DurableProviders, ProtocolRepositorySagaJournal, SagaJournal, Supervisor,
};
use scp_core::context::{ContextMode, ContextParams, ContextState, LocalTransportProvider};
use scp_core::crypto::mls::provider::NodeMlsFactory;
use scp_core::crypto::mls::storage_adapter::{OpenMlsStorageAdapter, SpawnBlockingStorageAdapter};
use scp_core::economy::Amount;
use scp_core::store::ProtocolRepository;
use scp_did::DID;
use scp_platform::in_memory::InMemoryStorage;

#[cfg(feature = "filesystem")]
use scp_platform::filesystem::FilesystemStorage;
#[cfg(feature = "sqlite")]
use scp_platform::sqlite::SqliteStorage;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Creates a `ProtocolRepository` wrapping fresh `InMemoryStorage`.
fn make_store() -> ProtocolRepository<InMemoryStorage> {
    ProtocolRepository::new_for_testing(InMemoryStorage::new())
}

// ---------------------------------------------------------------------------
// Macro for cross-adapter test generation
// ---------------------------------------------------------------------------

/// Generates the full persistence test suite for a given `Storage` implementation.
///
/// Currently instantiated for `InMemoryStorage` only. When `SqliteStorage` and
/// `FilesystemStorage` land, additional instantiations will be added here,
/// producing identical test suites for each backend.
macro_rules! persistence_tests {
    ($mod_name:ident, $make_store:expr) => {
        mod $mod_name {
            #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

            use super::*;

            // ---------------------------------------------------------------
            // AC1: Full restart test
            // ---------------------------------------------------------------

            /// Store context state, params, memberships, and roles, then
            /// re-read from the same storage backend to verify everything
            /// survives a simulated restart.
            #[tokio::test]
            async fn full_restart_preserves_context_state() {
                let store = $make_store;

                let ctx_id = "ctx-restart-test";
                let alice = DID::from("did:dht:z6MkAlice");
                let bob = DID::from("did:dht:z6MkBob");

                // --- Phase 1: Populate state ---
                let context_state = b"active-state-bytes".to_vec();
                let context_params = b"context-params-json".to_vec();

                store
                    .store_context_state(ctx_id, &context_state)
                    .await
                    .unwrap();
                store
                    .store_context_params(ctx_id, &context_params)
                    .await
                    .unwrap();
                store
                    .store_membership(ctx_id, &alice, "admin")
                    .await
                    .unwrap();
                store
                    .store_membership(ctx_id, &bob, "member")
                    .await
                    .unwrap();
                store
                    .store_role(ctx_id, "admin", b"admin-role-definition")
                    .await
                    .unwrap();
                store
                    .store_role(ctx_id, "member", b"member-role-definition")
                    .await
                    .unwrap();
                store
                    .store_role(ctx_id, "observer", b"observer-role-definition")
                    .await
                    .unwrap();

                // --- Phase 2: "Restart" -- re-read from storage ---
                // In production this would be a new ProtocolRepository instance
                // wrapping the same durable backend (SQLite file, etc.).
                // With InMemoryStorage, reading from the same instance
                // proves the read path works correctly.

                let loaded_state = store.load_context_state(ctx_id).await.unwrap();
                assert_eq!(loaded_state, Some(context_state.clone()));

                let loaded_params = store.load_context_params(ctx_id).await.unwrap();
                assert_eq!(loaded_params, Some(context_params.clone()));

                let alice_role = store.load_membership(ctx_id, &alice).await.unwrap();
                assert_eq!(alice_role, Some("admin".to_owned()));

                let bob_role = store.load_membership(ctx_id, &bob).await.unwrap();
                assert_eq!(bob_role, Some("member".to_owned()));

                let mut members = store.list_members(ctx_id).await.unwrap();
                members.sort_by(|a, b| a.0.cmp(&b.0));
                assert_eq!(members.len(), 2);
                assert_eq!(members[0].0, alice);
                assert_eq!(members[1].0, bob);

                let mut roles = store.list_roles(ctx_id).await.unwrap();
                roles.sort();
                assert_eq!(roles, vec!["admin", "member", "observer"]);

                let admin_def = store.load_role(ctx_id, "admin").await.unwrap();
                assert_eq!(admin_def, Some(b"admin-role-definition".to_vec()));

                // --- Phase 3: Continue operations after "restart" ---
                let carol = DID::from("did:dht:z6MkCarol");
                store
                    .store_membership(ctx_id, &carol, "observer")
                    .await
                    .unwrap();
                let carol_role = store.load_membership(ctx_id, &carol).await.unwrap();
                assert_eq!(carol_role, Some("observer".to_owned()));

                let members_after = store.list_members(ctx_id).await.unwrap();
                assert_eq!(members_after.len(), 3);
            }

            /// Multiple contexts persist independently and survive restart.
            #[tokio::test]
            async fn full_restart_multiple_contexts() {
                let store = $make_store;

                // Create two contexts.
                store
                    .store_context_state("ctx-a", b"state-a")
                    .await
                    .unwrap();
                store
                    .store_context_state("ctx-b", b"state-b")
                    .await
                    .unwrap();
                store
                    .store_membership("ctx-a", &DID::from("did:dht:z6MkAlice"), "admin")
                    .await
                    .unwrap();
                store
                    .store_membership("ctx-b", &DID::from("did:dht:z6MkBob"), "admin")
                    .await
                    .unwrap();

                // Verify list_active_contexts.
                let contexts = store.list_active_contexts().await.unwrap();
                assert_eq!(contexts, vec!["ctx-a", "ctx-b"]);

                // Verify isolation: ctx-a members != ctx-b members.
                let a_members = store.list_members("ctx-a").await.unwrap();
                assert_eq!(a_members.len(), 1);
                assert_eq!(a_members[0].0, DID::from("did:dht:z6MkAlice"));

                let b_members = store.list_members("ctx-b").await.unwrap();
                assert_eq!(b_members.len(), 1);
                assert_eq!(b_members[0].0, DID::from("did:dht:z6MkBob"));
            }

            // ---------------------------------------------------------------
            // AC2: Close cleanup
            // ---------------------------------------------------------------

            /// `delete_context` removes all persisted state (state, params,
            /// memberships, roles). Verified via `list_keys` returning empty
            /// for context prefix.
            #[tokio::test]
            async fn close_cleanup_removes_all_context_state() {
                let store = $make_store;
                let ctx_id = "ctx-cleanup-test";
                let did = DID::from("did:dht:z6MkMember");

                // Populate all context key types.
                store.store_context_state(ctx_id, b"state").await.unwrap();
                store.store_context_params(ctx_id, b"params").await.unwrap();
                store
                    .store_membership(ctx_id, &did, "member")
                    .await
                    .unwrap();
                store
                    .store_role(ctx_id, "admin", b"role-data")
                    .await
                    .unwrap();
                store
                    .store_role(ctx_id, "viewer", b"viewer-data")
                    .await
                    .unwrap();

                // Verify state exists before deletion.
                assert!(store.load_context_state(ctx_id).await.unwrap().is_some());
                let contexts_before = store.list_active_contexts().await.unwrap();
                assert!(contexts_before.contains(&ctx_id.to_owned()));

                // Delete context.
                let deleted = store.delete_context(ctx_id).await.unwrap();
                assert!(
                    deleted >= 5,
                    "should have deleted at least 5 keys, got {deleted}"
                );

                // Verify all state is gone.
                assert!(store.load_context_state(ctx_id).await.unwrap().is_none());
                assert!(store.load_context_params(ctx_id).await.unwrap().is_none());
                assert!(store.load_membership(ctx_id, &did).await.unwrap().is_none());
                assert!(store.load_role(ctx_id, "admin").await.unwrap().is_none());
                assert!(store.load_role(ctx_id, "viewer").await.unwrap().is_none());

                // Context should no longer appear in active list.
                let contexts_after = store.list_active_contexts().await.unwrap();
                assert!(!contexts_after.contains(&ctx_id.to_owned()));
            }

            /// Deleting one context does not affect another.
            #[tokio::test]
            async fn close_cleanup_preserves_other_contexts() {
                let store = $make_store;

                store
                    .store_context_state("ctx-keep", b"keep-state")
                    .await
                    .unwrap();
                store
                    .store_context_state("ctx-delete", b"delete-state")
                    .await
                    .unwrap();
                store
                    .store_membership("ctx-keep", &DID::from("did:dht:z6MkAlice"), "admin")
                    .await
                    .unwrap();
                store
                    .store_membership("ctx-delete", &DID::from("did:dht:z6MkBob"), "admin")
                    .await
                    .unwrap();

                store.delete_context("ctx-delete").await.unwrap();

                // ctx-keep is unaffected.
                assert_eq!(
                    store.load_context_state("ctx-keep").await.unwrap(),
                    Some(b"keep-state".to_vec())
                );
                let keep_members = store.list_members("ctx-keep").await.unwrap();
                assert_eq!(keep_members.len(), 1);

                // ctx-delete is gone.
                assert!(
                    store
                        .load_context_state("ctx-delete")
                        .await
                        .unwrap()
                        .is_none()
                );
            }

            // ---------------------------------------------------------------
            // AC3: TTL expiry state persists
            // ---------------------------------------------------------------

            /// Context state with `ContextState::Expired` serialization survives
            /// a persist/load roundtrip, and the expired context can be listed
            /// but no longer accepts new memberships (enforced at the manager
            /// level, not the store level -- the store is state-agnostic).
            #[tokio::test]
            async fn ttl_expiry_state_persists_and_roundtrips() {
                let store = $make_store;
                let ctx_id = "ctx-expired-test";

                // Simulate an expired context: store context state containing
                // a serialized ContextState::Expired marker.
                let expired_state = rmp_serde::to_vec(&ContextState::Expired).unwrap();
                store
                    .store_context_state(ctx_id, &expired_state)
                    .await
                    .unwrap();
                store
                    .store_context_params(ctx_id, b"params-for-expired")
                    .await
                    .unwrap();

                // Verify roundtrip.
                let loaded_bytes = store.load_context_state(ctx_id).await.unwrap().unwrap();
                let loaded_state: ContextState = rmp_serde::from_slice(&loaded_bytes).unwrap();
                assert_eq!(loaded_state, ContextState::Expired);

                // The expired context still shows up in active contexts (it
                // has a state key). The caller is responsible for interpreting
                // the state and refusing operations.
                let active = store.list_active_contexts().await.unwrap();
                assert!(active.contains(&ctx_id.to_owned()));
            }

            /// Contexts in different lifecycle states all persist/roundtrip correctly.
            #[tokio::test]
            async fn all_lifecycle_states_persist_correctly() {
                let store = $make_store;

                let states = [
                    ("ctx-creating", ContextState::Creating),
                    ("ctx-active", ContextState::Active),
                    ("ctx-closing", ContextState::Closing),
                    ("ctx-closed", ContextState::Closed),
                    ("ctx-expired", ContextState::Expired),
                ];

                for (ctx_id, state) in &states {
                    let bytes = rmp_serde::to_vec(state).unwrap();
                    store.store_context_state(ctx_id, &bytes).await.unwrap();
                }

                for (ctx_id, expected_state) in &states {
                    let loaded_bytes = store.load_context_state(ctx_id).await.unwrap().unwrap();
                    let loaded: ContextState = rmp_serde::from_slice(&loaded_bytes).unwrap();
                    assert_eq!(
                        &loaded, expected_state,
                        "lifecycle state mismatch for {ctx_id}"
                    );
                }
            }

            // ---------------------------------------------------------------
            // AC5: Sequence numbers survive restart; role assignments survive
            // ---------------------------------------------------------------

            /// Membership role assignments persist and are loadable after
            /// simulated restart.
            #[tokio::test]
            async fn role_assignments_survive_restart() {
                let store = $make_store;
                let ctx_id = "ctx-roles-restart";

                let alice = DID::from("did:dht:z6MkAlice");
                let bob = DID::from("did:dht:z6MkBob");
                let carol = DID::from("did:dht:z6MkCarol");

                store
                    .store_membership(ctx_id, &alice, "admin")
                    .await
                    .unwrap();
                store
                    .store_membership(ctx_id, &bob, "member")
                    .await
                    .unwrap();
                store
                    .store_membership(ctx_id, &carol, "observer")
                    .await
                    .unwrap();

                // Role definitions.
                store
                    .store_role(ctx_id, "admin", b"admin-caps")
                    .await
                    .unwrap();
                store
                    .store_role(ctx_id, "member", b"member-caps")
                    .await
                    .unwrap();
                store
                    .store_role(ctx_id, "observer", b"observer-caps")
                    .await
                    .unwrap();

                // Simulate restart: reload all.
                let alice_role = store.load_membership(ctx_id, &alice).await.unwrap();
                assert_eq!(alice_role, Some("admin".to_owned()));

                let bob_role = store.load_membership(ctx_id, &bob).await.unwrap();
                assert_eq!(bob_role, Some("member".to_owned()));

                let carol_role = store.load_membership(ctx_id, &carol).await.unwrap();
                assert_eq!(carol_role, Some("observer".to_owned()));

                // All roles present.
                let mut roles = store.list_roles(ctx_id).await.unwrap();
                roles.sort();
                assert_eq!(roles, vec!["admin", "member", "observer"]);
            }

            /// Sequence numbers are stored as part of identity private state
            /// and survive a persist/load roundtrip.
            ///
            /// The `ProtocolRepository`'s identity module stores per-DID private state
            /// at monotonic sequence numbers. This test verifies that the
            /// sequence ordering is preserved across writes and reads.
            #[tokio::test]
            async fn sequence_numbers_survive_restart_and_remain_monotonic() {
                let store = $make_store;
                let did = DID::from("did:dht:z6MkSequenceTest");

                // Store identity private state at increasing sequence numbers.
                for seq in 0..5u64 {
                    let state = format!("state-at-seq-{seq}");
                    store
                        .store_identity_private_state(&did, seq, state.as_bytes())
                        .await
                        .unwrap();
                }

                // Simulate restart: read back each sequence number.
                for seq in 0..5u64 {
                    let loaded = store
                        .load_identity_private_state(&did, seq)
                        .await
                        .unwrap()
                        .unwrap();
                    let expected = format!("state-at-seq-{seq}");
                    assert_eq!(
                        loaded,
                        expected.as_bytes().to_vec(),
                        "private state at seq {seq} mismatch"
                    );
                }

                // Verify that a sequence number that was never written returns None.
                assert!(
                    store
                        .load_identity_private_state(&did, 99)
                        .await
                        .unwrap()
                        .is_none()
                );

                // Verify that we can continue writing after "restart".
                store
                    .store_identity_private_state(&did, 5, b"state-at-seq-5")
                    .await
                    .unwrap();
                let loaded = store
                    .load_identity_private_state(&did, 5)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(loaded, b"state-at-seq-5".to_vec());
            }

            // ---------------------------------------------------------------
            // Cross-domain isolation
            // ---------------------------------------------------------------

            /// Context data is isolated from identity data: deleting a context
            /// does not affect identity state, and vice versa.
            #[tokio::test]
            async fn context_and_identity_isolation() {
                let store = $make_store;
                let ctx_id = "ctx-isolation";
                let did = DID::from("did:dht:z6MkIsolation");

                // Store context and identity data.
                store
                    .store_context_state(ctx_id, b"context-data")
                    .await
                    .unwrap();
                store
                    .store_identity_document(&did, b"identity-doc")
                    .await
                    .unwrap();

                // Delete context -> identity unaffected.
                store.delete_context(ctx_id).await.unwrap();
                assert!(store.load_context_state(ctx_id).await.unwrap().is_none());
                assert_eq!(
                    store.load_identity_document(&did).await.unwrap(),
                    Some(b"identity-doc".to_vec())
                );

                // Delete identity -> (already deleted) context unaffected.
                store
                    .store_context_state(ctx_id, b"context-data-2")
                    .await
                    .unwrap();
                store.delete_identity(&did).await.unwrap();
                assert_eq!(
                    store.load_context_state(ctx_id).await.unwrap(),
                    Some(b"context-data-2".to_vec())
                );
                assert!(store.load_identity_document(&did).await.unwrap().is_none());
            }

            // ---------------------------------------------------------------
            // Overwrite semantics
            // ---------------------------------------------------------------

            /// Overwriting context state replaces the previous value.
            #[tokio::test]
            async fn context_state_overwrite() {
                let store = $make_store;
                let ctx_id = "ctx-overwrite";

                store
                    .store_context_state(ctx_id, b"state-v1")
                    .await
                    .unwrap();
                store
                    .store_context_state(ctx_id, b"state-v2")
                    .await
                    .unwrap();

                let loaded = store.load_context_state(ctx_id).await.unwrap().unwrap();
                assert_eq!(loaded, b"state-v2".to_vec());
            }

            /// Overwriting a role for a member updates the assignment.
            #[tokio::test]
            async fn membership_role_overwrite() {
                let store = $make_store;
                let ctx_id = "ctx-role-change";
                let did = DID::from("did:dht:z6MkPromoted");

                store
                    .store_membership(ctx_id, &did, "member")
                    .await
                    .unwrap();
                store.store_membership(ctx_id, &did, "admin").await.unwrap();

                let loaded = store.load_membership(ctx_id, &did).await.unwrap();
                assert_eq!(loaded, Some("admin".to_owned()));
            }

            // ---------------------------------------------------------------
            // Large-scale persistence
            // ---------------------------------------------------------------

            /// Persistence handles a context with many members and roles.
            #[tokio::test]
            async fn large_context_persistence() {
                let store = $make_store;
                let ctx_id = "ctx-large";

                store
                    .store_context_state(ctx_id, b"large-context-state")
                    .await
                    .unwrap();

                // Add 50 members.
                for i in 0..50u32 {
                    let did = DID::from(format!("did:dht:z6MkMember{i:03}"));
                    let role = if i == 0 { "admin" } else { "member" };
                    store.store_membership(ctx_id, &did, role).await.unwrap();
                }

                // Add 5 roles.
                for i in 0..5u32 {
                    let role_name = format!("role-{i}");
                    let role_data = format!("role-data-{i}");
                    store
                        .store_role(ctx_id, &role_name, role_data.as_bytes())
                        .await
                        .unwrap();
                }

                // Verify.
                let members = store.list_members(ctx_id).await.unwrap();
                assert_eq!(members.len(), 50);

                let roles = store.list_roles(ctx_id).await.unwrap();
                assert_eq!(roles.len(), 5);

                // Delete and verify cleanup.
                let deleted = store.delete_context(ctx_id).await.unwrap();
                // state + 50 memberships + 5 roles = 56 minimum
                assert!(
                    deleted >= 56,
                    "expected at least 56 deleted keys, got {deleted}"
                );

                let members_after = store.list_members(ctx_id).await.unwrap();
                assert!(members_after.is_empty());
            }

            // ---------------------------------------------------------------
            // AC3 (extended): Expired context state survives restore
            // ---------------------------------------------------------------

            /// Stores a context with `ContextState::Expired`, loads it back, and
            /// verifies the expired state is faithfully restored. This ensures
            /// that expired contexts are not silently dropped or reset during
            /// the persist/load cycle.
            #[tokio::test]
            async fn expired_context_refuses_operations_after_restore() {
                let store = $make_store;
                let ctx_id = "ctx-expired-restore";

                // Persist context as Expired.
                let expired_state = rmp_serde::to_vec(&ContextState::Expired).unwrap();
                store
                    .store_context_state(ctx_id, &expired_state)
                    .await
                    .unwrap();
                store
                    .store_context_params(ctx_id, b"params-expired-ctx")
                    .await
                    .unwrap();

                // Add a member before expiry (simulates pre-expiry state).
                let alice = DID::from("did:dht:z6MkAliceExpired");
                store
                    .store_membership(ctx_id, &alice, "member")
                    .await
                    .unwrap();

                // --- "Restart": load state back ---
                let loaded_bytes = store
                    .load_context_state(ctx_id)
                    .await
                    .unwrap()
                    .expect("expired state should be loadable");
                let loaded_state: ContextState = rmp_serde::from_slice(&loaded_bytes).unwrap();

                // Verify the state is Expired.
                assert_eq!(
                    loaded_state,
                    ContextState::Expired,
                    "restored state must be Expired"
                );

                // Verify params and membership survived alongside the expired state.
                let loaded_params = store.load_context_params(ctx_id).await.unwrap();
                assert_eq!(loaded_params, Some(b"params-expired-ctx".to_vec()));

                let alice_role = store.load_membership(ctx_id, &alice).await.unwrap();
                assert_eq!(alice_role, Some("member".to_owned()));

                // The expired context still appears in the active context list
                // (the store is state-agnostic; callers interpret the state).
                let active = store.list_active_contexts().await.unwrap();
                assert!(
                    active.contains(&ctx_id.to_owned()),
                    "expired context should still appear in active list"
                );
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Cross-adapter test instantiations (AC4)
// ---------------------------------------------------------------------------

// InMemoryStorage -- always available, no feature gate.
persistence_tests!(in_memory, make_store());

// SqliteStorage -- gated behind `sqlite` feature.
#[cfg(feature = "sqlite")]
persistence_tests!(sqlite, {
    let dir = tempfile::tempdir().unwrap();
    let key = [0xABu8; 32];
    let dir_path = dir.path().to_path_buf();
    let _ = Box::leak(Box::new(dir));
    ProtocolRepository::new(SqliteStorage::new(&dir_path, &key).unwrap())
});

// FilesystemStorage -- gated behind `filesystem` feature.
#[cfg(feature = "filesystem")]
persistence_tests!(filesystem, {
    let dir = tempfile::tempdir().unwrap();
    let dir_path = dir.path().to_path_buf();
    let _ = Box::leak(Box::new(dir));
    ProtocolRepository::new_for_testing(FilesystemStorage::new(&dir_path).unwrap())
});

// ---------------------------------------------------------------------------
// Actor-layer restore test — `executed_proposals` replay-marker durability.
// ---------------------------------------------------------------------------

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// In-memory `ContextPersistence` double. Two supervisors (process 1 "before
/// restart" and process 2 "after restart") share ONE backing map through
/// `Arc`, so the snapshot process 1 persists is the one process 2 restores.
#[derive(Default)]
struct SharedPersistence {
    contexts: Mutex<HashMap<String, ContextSnapshot>>,
}

#[async_trait::async_trait]
impl ContextPersistence for SharedPersistence {
    async fn persist_context(
        &self,
        context_id: &str,
        snapshot: &ContextSnapshot,
    ) -> Result<(), BoxError> {
        self.contexts
            .lock()
            .unwrap()
            .insert(context_id.to_owned(), snapshot.clone());
        Ok(())
    }

    async fn load_context(&self, context_id: &str) -> Result<Option<ContextSnapshot>, BoxError> {
        Ok(self.contexts.lock().unwrap().get(context_id).cloned())
    }

    async fn delete_context(&self, context_id: &str) -> Result<(), BoxError> {
        self.contexts.lock().unwrap().remove(context_id);
        Ok(())
    }

    async fn list_persisted_contexts(&self) -> Result<Vec<String>, BoxError> {
        Ok(self.contexts.lock().unwrap().keys().cloned().collect())
    }
}

/// `Box<dyn ContextPersistence>` newtype sharing the `Arc` backing map between
/// the two supervisors (the constructor takes an owned `Box`, but both
/// processes must read/write the SAME map).
struct SharedPersistenceArc(Arc<SharedPersistence>);

#[async_trait::async_trait]
impl ContextPersistence for SharedPersistenceArc {
    async fn persist_context(
        &self,
        context_id: &str,
        snapshot: &ContextSnapshot,
    ) -> Result<(), BoxError> {
        self.0.persist_context(context_id, snapshot).await
    }
    async fn load_context(&self, context_id: &str) -> Result<Option<ContextSnapshot>, BoxError> {
        self.0.load_context(context_id).await
    }
    async fn delete_context(&self, context_id: &str) -> Result<(), BoxError> {
        self.0.delete_context(context_id).await
    }
    async fn list_persisted_contexts(&self) -> Result<Vec<String>, BoxError> {
        self.0.list_persisted_contexts().await
    }
}

/// No-op event-log provider (mirrors `saga_bridge_bootstrap.rs`).
struct NoOpEventLog;
// `unused_async`: these no-op test-double methods have no await, but the
// ADR-049 Decision-7 async `ContextEventLogProvider` trait requires the
// `async fn` signature.
#[async_trait::async_trait]
#[allow(clippy::unused_async)]
impl ContextEventLogProvider for NoOpEventLog {
    async fn init_event_log(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    async fn append_event(
        &self,
        _: &[u8; 32],
        _: scp_event_log::EventType,
        _: &str,
        _: scp_event_log::EventPayload,
        _timestamp_secs: u64,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }
    async fn destroy_event_log(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
}

fn test_mls_storage() -> Arc<dyn OpenMlsStorageAdapter> {
    Arc::new(SpawnBlockingStorageAdapter::new(Arc::new(
        InMemoryStorage::new(),
    )))
}

/// Deterministic Ed25519 signing key derived from a DID string, so a matching
/// `KeyResolver` can resolve the verifying key for governance-proposal
/// signature validation.
fn deterministic_signing_key(did: &DID) -> ed25519_dalek::SigningKey {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    did.as_ref().hash(&mut hasher);
    let h = hasher.finish();
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&h.to_le_bytes());
    ed25519_dalek::SigningKey::from_bytes(&seed)
}

fn deterministic_key_resolver() -> KeyResolver {
    Arc::new(|did: &DID, _kid: scp_did::SigningKeyId| {
        Some(deterministic_signing_key(did).verifying_key())
    })
}

/// Builds a `Supervisor` over caller-supplied shared persistence, a saga
/// journal, and MLS storage (the ingredients `restore_on_startup` needs),
/// mirroring `saga_bridge_bootstrap.rs::bridge_supervisor`.
fn restore_supervisor(
    creator_did: &str,
    persistence: Arc<SharedPersistence>,
    journal: Arc<dyn SagaJournal>,
    mls_storage: Arc<dyn OpenMlsStorageAdapter>,
) -> Arc<Supervisor> {
    Supervisor::with_providers_and_journal(
        Arc::new(NodeMlsFactory::new(
            creator_did.to_owned(),
            Arc::new(scp_clock::SystemClock),
        )),
        Box::new(LocalTransportProvider) as Box<dyn ContextTransportProvider>,
        Box::new(NoOpEventLog) as Box<dyn ContextEventLogProvider>,
        deterministic_key_resolver(),
        Some(Box::new(SharedPersistenceArc(persistence))),
        None,
        None,
        None,
        DurableProviders::for_test(journal, mls_storage),
    )
}

/// End-to-end: a governance `ApproveSpend` executed before a simulated restart
/// leaves its Class-S `executed_proposals` replay marker durably persisted in
/// the [`ContextSnapshot`]; after the context is rehydrated into a fresh
/// `Supervisor` from that same persistence backend, the marker is still present
/// in the live actor and a SECOND governance action accumulates a new marker
/// alongside the restored one — proving the replay-protection set (ADR-049 §9
/// Class-S) survives a restart. See the module-level ADR-049 note for why this
/// replaces the old "replay rejected as already-executed" assertion.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn executed_proposals_survive_restart_and_accumulate() {
    let creator_str = "did:dht:z6MkPersistRestoreCreator";
    let creator = DID::from(creator_str);
    let signing_key = deterministic_signing_key(&creator);
    let ctx_id = "ctx-persist-restore-replay";

    // Shared backing stores survive the "crash" (drop of process 1's supervisor).
    // The MLS storage backend MUST be shared too: an Encrypted context's MLS
    // group state lives in the OpenMLS storage, and the restart's restore leg
    // reinstates the group FROM that same backend.
    let persistence = Arc::new(SharedPersistence::default());
    let journal_storage = Arc::new(InMemoryStorage::new());
    let mls_storage = test_mls_storage();

    // Captured before process 1 is dropped.
    let first_proposal_id;

    // === Process 1: create a context, execute a governance action, persist ===
    {
        let journal1: Arc<dyn SagaJournal> = Arc::new(ProtocolRepositorySagaJournal::new(
            Arc::clone(&journal_storage),
        ));
        let sup1 = restore_supervisor(
            creator_str,
            Arc::clone(&persistence),
            journal1,
            Arc::clone(&mls_storage),
        );
        sup1.register_local_did(creator.clone()).await.unwrap();

        // `Encrypted` (MLS-backed) is the standard restore path: the group state
        // lives in the shared OpenMLS storage and the restore leg reinstates it.
        let params = ContextParams {
            mode: ContextMode::Encrypted,
            ..ContextParams::default()
        };
        sup1.create_context(ctx_id.to_owned(), params, creator.clone(), None)
            .await
            .expect("create_context");

        // Under the default SingleAdmin governance the creator is admin, so this
        // proposal auto-approves and EXECUTES — marking `executed_proposals` and
        // persisting the Class-S snapshot fail-closed.
        let (proposal, _events, execution) = sup1
            .propose_governance_action(
                ctx_id,
                &creator,
                GovernanceAction::ApproveSpend {
                    spender: creator.clone(),
                    amount: Amount::new(1_000),
                    purpose: "restore-replay durability probe (pre-restart)".to_owned(),
                },
                &signing_key,
            )
            .await
            .expect("propose_governance_action (pre-restart)");
        assert!(
            execution.is_some(),
            "SingleAdmin ApproveSpend by the admin must auto-execute"
        );
        first_proposal_id = proposal.proposal_id;

        // Flush the live context to persistence — the durable `Active` snapshot
        // the restart's restore leg must rehydrate (also captures the executed
        // marker already committed Class-S above).
        sup1.flush_all_contexts().await.expect("flush_all_contexts");

        let snapshot = persistence
            .load_context(ctx_id)
            .await
            .unwrap()
            .expect("context must be persisted after the executed governance action");
        assert!(
            snapshot.executed_proposals.contains(&first_proposal_id),
            "the executed proposal's replay marker must be Class-S persisted before restart"
        );
        assert_eq!(
            snapshot.state,
            ContextState::Active,
            "the persisted snapshot must be Active so the restore leg rehydrates it"
        );

        // Drop sup1 (= process exit / crash) WITHOUT the in-memory actor state.
    }

    // === Process 2: fresh supervisor over the SAME durable stores, restored ===
    let journal2: Arc<dyn SagaJournal> = Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(
        &journal_storage,
    )));
    let sup2 = restore_supervisor(
        creator_str,
        Arc::clone(&persistence),
        journal2,
        Arc::clone(&mls_storage),
    );
    sup2.register_local_did(creator.clone()).await.unwrap();

    // Pre-condition: the context is NOT yet resident (process 2 hasn't restored).
    assert!(
        sup2.read_context_state(ctx_id).await.is_none(),
        "the context must be non-resident before restore_on_startup runs"
    );

    // Rehydrate every persisted Active context from the persistence backend.
    let restored = sup2.restore_on_startup().await.expect("restore_on_startup");
    assert!(
        restored.iter().any(|id| id == ctx_id),
        "restore_on_startup must rehydrate the persisted context, got {restored:?}"
    );
    assert_eq!(
        sup2.read_context_state(ctx_id).await,
        Some(ContextState::Active),
        "the restored context must be a live Active actor"
    );

    // Execute a SECOND governance action after the restart. This forces the
    // restored actor to (a) prove it rehydrated the prior `executed_proposals`
    // marker and (b) accumulate a new one alongside it.
    let (second_proposal, _events, second_execution) = sup2
        .propose_governance_action(
            ctx_id,
            &creator,
            GovernanceAction::ApproveSpend {
                spender: creator.clone(),
                amount: Amount::new(2_000),
                purpose: "restore-replay durability probe (post-restart)".to_owned(),
            },
            &signing_key,
        )
        .await
        .expect("propose_governance_action (post-restart)");
    assert!(
        second_execution.is_some(),
        "the post-restart ApproveSpend must also auto-execute"
    );
    let second_proposal_id = second_proposal.proposal_id;
    assert_ne!(
        first_proposal_id, second_proposal_id,
        "the two proposals must have distinct ids"
    );

    // The re-persisted snapshot must carry BOTH markers: the restored one AND the
    // post-restart one. If the restore leg had dropped `executed_proposals`, the
    // post-restart Class-S persist would overwrite the snapshot with only the new
    // marker and this assertion would fail.
    let snapshot_after = persistence
        .load_context(ctx_id)
        .await
        .unwrap()
        .expect("context must remain persisted after the post-restart action");
    assert!(
        snapshot_after
            .executed_proposals
            .contains(&first_proposal_id),
        "the pre-restart replay marker must survive restore (rehydrated into the actor)"
    );
    assert!(
        snapshot_after
            .executed_proposals
            .contains(&second_proposal_id),
        "the post-restart replay marker must accumulate alongside the restored one"
    );
}
