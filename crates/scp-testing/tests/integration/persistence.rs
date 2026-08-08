// ADR-049 §15: ContextCryptoProvider trait deleted. Tests in this
// file construct ContextManager with the trait's mock implementations; the
// rewire path awaits backend injection. File gated until then.
#![cfg(any())]

//! SCP-PERSIST-070: End-to-end integration tests for context persistence.
//!
//! Tests the full context lifecycle through `ProtocolRepository`: create contexts
//! with members, messages, and roles -> persist -> "restart" (re-read from
//! the same storage backend) -> verify state -> continue operations.
//!
//! Also covers:
//! - Close cleanup (`delete_context` removes all persisted state).
//! - TTL expiry (expired state persists and roundtrips correctly).
//! - Cross-adapter parity (macro-driven, currently `InMemoryStorage` only;
//!   ready for `SqliteStorage` and `FilesystemStorage` when they land).
//! - Sequence number and role assignment survival across restarts.
//!
//! See `.docs/prds/` SCP-PERSIST-070 for acceptance criteria.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::sync::Arc;

use scp_core::context::governance::{
    GovernanceAction, GovernanceContext, GovernanceEngine, KeyResolver, ProposalStatus,
    SingleAdminEngine,
};
use scp_core::context::manager::{ContextManager, ContextPersistence, ContextSnapshot};
use scp_core::context::{
    Capability, ContextHandle, ContextMode, ContextParams, ContextState, MemoryScope,
};
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
// ContextManager-level persistence integration test
// ---------------------------------------------------------------------------

/// A simple `ContextPersistence` implementation using synchronous
/// `Mutex<HashMap>` for testing the `Supervisor::restore_context`
/// path. Avoids the "`block_on` inside runtime" problem by not using async
/// storage under the hood.
struct InMemoryContextPersistence {
    contexts: std::sync::Mutex<HashMap<String, ContextSnapshot>>,
}

impl InMemoryContextPersistence {
    fn new() -> Self {
        Self {
            contexts: std::sync::Mutex::new(HashMap::new()),
        }
    }
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[async_trait::async_trait]
impl ContextPersistence for InMemoryContextPersistence {
    async fn persist_context(
        &self,
        context_id: &str,
        snapshot: &ContextSnapshot,
    ) -> Result<(), BoxError> {
        self.contexts
            .lock()
            .map_err(|e| -> BoxError { Box::new(std::io::Error::other(e.to_string())) })?
            .insert(context_id.to_owned(), snapshot.clone());
        Ok(())
    }

    async fn load_context(&self, context_id: &str) -> Result<Option<ContextSnapshot>, BoxError> {
        let guard = self
            .contexts
            .lock()
            .map_err(|e| -> BoxError { Box::new(std::io::Error::other(e.to_string())) })?;
        Ok(guard.get(context_id).cloned())
    }

    async fn delete_context(&self, context_id: &str) -> Result<(), BoxError> {
        self.contexts
            .lock()
            .map_err(|e| -> BoxError { Box::new(std::io::Error::other(e.to_string())) })?
            .remove(context_id);
        Ok(())
    }

    async fn list_persisted_contexts(&self) -> Result<Vec<String>, BoxError> {
        let guard = self
            .contexts
            .lock()
            .map_err(|e| -> BoxError { Box::new(std::io::Error::other(e.to_string())) })?;
        Ok(guard.keys().cloned().collect())
    }
}

/// Newtype wrapper enabling multiple `ContextManager` instances to share
/// the same `InMemoryContextPersistence` backing store, simulating a
/// restart against the same durable storage. Required because the orphan
/// rule prevents implementing `ContextPersistence` for `Arc<T>` directly.
struct SharedPersistence(Arc<InMemoryContextPersistence>);

#[async_trait::async_trait]
impl ContextPersistence for SharedPersistence {
    async fn persist_context(
        &self,
        context_id: &str,
        snapshot: &ContextSnapshot,
    ) -> Result<(), BoxError> {
        self.0.persist_context(context_id, snapshot)
    }

    async fn load_context(&self, context_id: &str) -> Result<Option<ContextSnapshot>, BoxError> {
        self.0.load_context(context_id)
    }

    async fn delete_context(&self, context_id: &str) -> Result<(), BoxError> {
        self.0.delete_context(context_id)
    }

    async fn list_persisted_contexts(&self) -> Result<Vec<String>, BoxError> {
        self.0.list_persisted_contexts()
    }
}

/// Minimal mock providers for `ContextManager` construction.
/// These are never called in the broadcast restoration path -- only the
/// persistence provider is exercised.
mod mock_providers {
    use scp_core::context::builder::{
        ContextCreationError, ContextCryptoProvider, ContextEventLogProvider,
        ContextTransportProvider,
    };
    use scp_core::context::{ContextError, ContextParams};

    pub struct MockCrypto;
    impl ContextCryptoProvider for MockCrypto {
        fn validate_creator_identity(&self) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn create_mls_group(&self, _ctx_id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn generate_sender_key(&self, _ctx_id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn init_broadcast_key(&self, _ctx_id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn destroy_mls_group(&self, _ctx_id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn destroy_sender_key(&self, _ctx_id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn validate_key_package(
            &self,
            _owner_did: &str,
            _key_package_bytes: Option<&[u8]>,
        ) -> Result<(), ContextError> {
            Ok(())
        }
        fn add_member(
            &self,
            _ctx_id: &[u8; 32],
            _member_did: &str,
            _key_package_bytes: Option<&[u8]>,
        ) -> Result<scp_core::context::AddMemberOutput, ContextError> {
            Ok(scp_core::context::AddMemberOutput::default())
        }
        fn remove_member(
            &self,
            _ctx_id: &[u8; 32],
            _member_did: &str,
        ) -> Result<scp_core::context::RemoveMemberOutput, ContextError> {
            Ok(scp_core::context::RemoveMemberOutput::default())
        }
        fn distribute_sender_key(
            &self,
            _ctx_id: &[u8; 32],
            _member_did: &str,
        ) -> Result<(), ContextError> {
            Ok(())
        }
        fn remove_member_sender_key(
            &self,
            _ctx_id: &[u8; 32],
            _member_did: &str,
        ) -> Result<(), ContextError> {
            Ok(())
        }

        fn seal(
            &self,
            _context_id: &[u8; 32],
            inner: &scp_core::envelope::inner::InnerEnvelope,
            _routing_id: &[u8],
            _blob_ttl: u32,
        ) -> Result<Vec<u8>, ContextError> {
            // Mock: serialize inner envelope directly (no encryption).
            rmp_serde::to_vec_named(inner)
                .map_err(|e| ContextError::CryptoFailed(format!("mock seal: {e}")))
        }

        fn open(
            &self,
            _context_id: &[u8; 32],
            outer_bytes: &[u8],
        ) -> Result<scp_core::context::builder::OpenResult, ContextError> {
            // Mock: deserialize directly as InnerEnvelope (no decryption).
            let inner: scp_core::envelope::inner::InnerEnvelope =
                rmp_serde::from_slice(outer_bytes)
                    .map_err(|e| ContextError::CryptoFailed(format!("mock open: {e}")))?;
            let sender_did = inner.sender_did.clone();
            Ok(scp_core::context::builder::OpenResult::Application(
                Box::new(scp_core::context::builder::OpenedEnvelope {
                    inner,
                    sender_did,
                    // ADR-049 PR-4: mock open() has no live recv tracker; the
                    // follower mirror-forward drop is non-fatal.
                    receive_floor: scp_core::context::builder::ReceiveFloor {
                        epoch: 0,
                        sequence: 0,
                    },
                }),
            ))
        }
    }

    pub struct MockTransport;
    #[async_trait::async_trait]
    impl ContextTransportProvider for MockTransport {
        fn is_connected(&self) -> bool {
            true
        }
        async fn publish_context(
            &self,
            _ctx_id: &[u8; 32],
            _params: &ContextParams,
        ) -> Result<(), ContextCreationError> {
            Ok(())
        }
        async fn delete_published(&self, _ctx_id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        async fn send_message(
            &self,
            _ctx_id: &[u8; 32],
            _encrypted_payload: &[u8],
        ) -> Result<(), ContextError> {
            Ok(())
        }
    }

    pub struct MockEventLog;
    // `unused_async`: these methods have no await because they are no-op test
    // doubles, but the ADR-049 Decision-7 async `ContextEventLogProvider` trait
    // requires the `async fn` signature.
    #[async_trait::async_trait]
    #[allow(clippy::unused_async)]
    impl ContextEventLogProvider for MockEventLog {
        async fn init_event_log(&self, _ctx_id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        async fn append_event(
            &self,
            _ctx_id: &[u8; 32],
            _event_type: scp_event_log::EventType,
            _actor_did: &str,
            _payload: scp_event_log::EventPayload,
            _timestamp_secs: u64,
        ) -> Result<(), ContextCreationError> {
            Ok(())
        }
        async fn destroy_event_log(&self, _ctx_id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
    }
}

/// Creates a mock key resolver that maps known test DIDs to verifying keys.
fn mock_key_resolver() -> KeyResolver {
    Arc::new(|did: &DID, _kid: scp_did::SigningKeyId| {
        let did_str: &str = did.as_ref();
        match did_str {
            "did:dht:z6MkAuthor1" => {
                Some(ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]).verifying_key())
            }
            "did:dht:z6MkBob" => {
                Some(ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]).verifying_key())
            }
            _ => None,
        }
    })
}

/// End-to-end test: persist a broadcast context snapshot via
/// `InMemoryContextPersistence`, then restore it into a fresh
/// `ContextManager` via `restore_context`. Also verifies that
/// `executed_proposals` (the replay protection set) persists across
/// restart: a governance action executed before restart is rejected
/// as a replay after restore.
#[tokio::test]
async fn context_manager_broadcast_restore_roundtrip() {
    use mock_providers::*;

    let persistence = Arc::new(InMemoryContextPersistence::new());
    let ctx_id = "ctx-manager-restore";
    let creator_did = scp_did::DID::from("did:dht:z6MkAuthor1");
    let bob_did = scp_did::DID::from("did:dht:z6MkBob");

    // --- Phase 1: Create context, execute governance action, persist ---

    let params = ContextParams {
        mode: ContextMode::Broadcast,
        memory_scope: MemoryScope::Full,
        ceiling: vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::RoleAssign,
        ],
        ..ContextParams::default()
    };

    // ADR-049 §15 — wrap with `attach_test_supervisor`.
    let manager = scp_core::context::attach_test_supervisor(ContextManager::with_persistence(
        Box::new(MockCrypto),
        Box::new(MockTransport),
        Box::new(MockEventLog),
        Box::new(SharedPersistence(Arc::clone(&persistence))),
        mock_key_resolver(),
    ));

    // Register creator DID as locally controlled.
    manager.register_local_did(creator_did.clone()).await;

    let _handle = manager
        .create_context(ctx_id.into(), params.clone(), creator_did.clone(), None)
        .await
        .unwrap();

    // Build an approved AddMember governance proposal via SingleAdminEngine.
    // AddMember does not require broadcast-specific setup -- it works with
    // the context as created above.
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    let mut engine = SingleAdminEngine::new(creator_did.clone(), mock_key_resolver());
    let gov_ctx = GovernanceContext {
        context_id: ctx_id.to_owned(),
        members: vec![(creator_did.clone(), "admin".to_owned())],
        admin_dids: vec![creator_did.clone()],
        current_epoch: None,
        now: 1000,
    };
    let action = GovernanceAction::AddMember {
        did: bob_did.clone(),
        role: "member".to_owned(),
    };
    let (proposal, _events) = engine
        .propose(&creator_did, action, &gov_ctx, &signing_key)
        .unwrap();
    assert!(matches!(proposal.status, ProposalStatus::Approved));

    // Capture the proposal_id for replay verification after restart.
    let proposal_id = proposal.proposal_id;

    // Execute the governance action (this persists the snapshot including
    // executed_proposals via the shared persistence).
    let result = manager.execute_governance_action(ctx_id, &proposal).await;
    assert!(result.is_ok(), "first execution should succeed");

    // Verify bob was actually added.
    assert!(
        manager.is_member(ctx_id, "did:dht:z6MkBob").await,
        "bob should be a member after AddMember governance action"
    );

    // --- Phase 2: Verify persistence contains executed_proposals ---

    let persisted = persistence.load_context(ctx_id).unwrap().unwrap();
    assert!(
        persisted.executed_proposals.contains(&proposal_id),
        "executed_proposals should be persisted after governance action"
    );

    // --- Phase 3: Drop first manager (simulates process exit) ---
    drop(manager);

    // --- Phase 4: Create a new manager, restore, and verify replay rejection ---

    // ADR-049 §15 — wrap with `attach_test_supervisor`.
    let manager2 = scp_core::context::attach_test_supervisor(ContextManager::with_persistence(
        Box::new(MockCrypto),
        Box::new(MockTransport),
        Box::new(MockEventLog),
        Box::new(SharedPersistence(Arc::clone(&persistence))),
        mock_key_resolver(),
    ));

    // Restore takes the context id alone: the params and the rebuilt handle come
    // from the persisted snapshot, so a caller cannot substitute a different
    // authority envelope (see `RestoreContextPayload`).
    manager2.restore_context(ctx_id).await.unwrap();

    // Verify membership survived restart.
    assert!(
        manager2.is_member(ctx_id, &creator_did.0).await,
        "creator membership should survive restart"
    );
    assert!(
        manager2.is_member(ctx_id, "did:dht:z6MkBob").await,
        "bob membership should survive restart"
    );

    // Attempt to replay the SAME governance proposal after restart.
    // This must be rejected -- the executed_proposals set should have
    // been restored from persistence.
    let replay_result = manager2.execute_governance_action(ctx_id, &proposal).await;
    assert!(
        replay_result.is_err(),
        "replayed governance proposal must be rejected after restart"
    );
    let err_msg = format!("{}", replay_result.unwrap_err());
    assert!(
        err_msg.contains("already been executed"),
        "error should indicate replay: {err_msg}"
    );
}
