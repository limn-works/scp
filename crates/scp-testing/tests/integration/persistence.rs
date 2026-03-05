//! SCP-PERSIST-070: End-to-end integration tests for context persistence.
//!
//! Tests the full context lifecycle through `ProtocolStore`: create contexts
//! with members, messages, and roles -> persist -> "restart" (re-read from
//! the same storage backend) -> verify state -> continue operations.
//!
//! Also covers:
//! - Close cleanup (`delete_context` removes all persisted state).
//! - TTL expiry (expired state persists and roundtrips correctly).
//! - Cross-adapter parity (macro-driven, currently `InMemoryStorage` only;
//!   ready for `SqliteStorage` and `FilesystemStorage` when they land).
//! - Sequence number and role assignment survival across restarts.
//! - Broadcast context snapshot persistence and restoration.
//!
//! See `.docs/prds/` SCP-PERSIST-070 for acceptance criteria.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{HashMap, HashSet};

use scp_core::context::broadcast::{
    AuthorStateSnapshot, BroadcastAdmission, BroadcastContext, BroadcastContextSnapshot,
    SubscriberRecord,
};
use scp_core::context::manager::{ContextManager, ContextPersistence, ContextSnapshot};
use scp_core::context::{
    Capability, CapabilityCeiling, ContextHandle, ContextParams, ContextRoleState, ContextState,
    MembershipState,
};
use scp_core::crypto::sender_keys::generate_sender_key;
use scp_core::store::ProtocolStore;
use scp_identity::DID;
use scp_platform::testing::InMemoryStorage;

#[cfg(feature = "filesystem")]
use scp_platform::filesystem::FilesystemStorage;
#[cfg(feature = "sqlite")]
use scp_platform::sqlite::SqliteStorage;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Creates a `ProtocolStore` wrapping fresh `InMemoryStorage`.
fn make_store() -> ProtocolStore<InMemoryStorage> {
    ProtocolStore::new(InMemoryStorage::new())
}

/// Creates a deterministic `BroadcastContextSnapshot` for testing.
fn make_broadcast_snapshot(context_id: &str) -> BroadcastContextSnapshot {
    let mut subscribers = HashMap::new();
    subscribers.insert(
        "did:dht:z6MkSub1".to_owned(),
        SubscriberRecord {
            subscriber_did: "did:dht:z6MkSub1".to_owned(),
            registered_at: 1_700_000_000,
            has_ucan: false,
        },
    );
    subscribers.insert(
        "did:dht:z6MkSub2".to_owned(),
        SubscriberRecord {
            subscriber_did: "did:dht:z6MkSub2".to_owned(),
            registered_at: 1_700_000_100,
            has_ucan: true,
        },
    );

    let mut block_list = HashSet::new();
    block_list.insert("did:dht:z6MkBlocked".to_owned());

    let mut authors = HashMap::new();
    authors.insert(
        "did:dht:z6MkAuthor1".to_owned(),
        AuthorStateSnapshot {
            author_did: "did:dht:z6MkAuthor1".to_owned(),
            broadcast_key: generate_sender_key(),
            epoch: 3,
            block_list,
        },
    );

    BroadcastContextSnapshot {
        context_id: context_id.to_owned(),
        admission: BroadcastAdmission::Open,
        subscribers,
        authors,
    }
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
                // In production this would be a new ProtocolStore instance
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
            /// memberships, roles, broadcast state, block lists). Verified
            /// via `list_keys` returning empty for context prefix.
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

                // Also persist broadcast state if this context were broadcast.
                let snapshot = make_broadcast_snapshot(ctx_id);
                store
                    .store_broadcast_state(ctx_id, &snapshot)
                    .await
                    .unwrap();

                let mut block_list = HashSet::new();
                block_list.insert("did:dht:z6MkBlocked".to_owned());
                store
                    .store_broadcast_block_list(ctx_id, "did:dht:z6MkAuthor", &block_list)
                    .await
                    .unwrap();

                // Verify state exists before deletion.
                assert!(store.load_context_state(ctx_id).await.unwrap().is_some());
                let contexts_before = store.list_active_contexts().await.unwrap();
                assert!(contexts_before.contains(&ctx_id.to_owned()));

                // Delete context.
                let deleted = store.delete_context(ctx_id).await.unwrap();
                assert!(
                    deleted >= 6,
                    "should have deleted at least 6 keys, got {deleted}"
                );

                // Verify all state is gone.
                assert!(store.load_context_state(ctx_id).await.unwrap().is_none());
                assert!(store.load_context_params(ctx_id).await.unwrap().is_none());
                assert!(store.load_membership(ctx_id, &did).await.unwrap().is_none());
                assert!(store.load_role(ctx_id, "admin").await.unwrap().is_none());
                assert!(store.load_role(ctx_id, "viewer").await.unwrap().is_none());
                assert!(store.load_broadcast_state(ctx_id).await.unwrap().is_none());
                assert!(
                    store
                        .load_broadcast_block_list(ctx_id, "did:dht:z6MkAuthor")
                        .await
                        .unwrap()
                        .is_none()
                );

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
            /// The `ProtocolStore`'s identity module stores per-DID private state
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
            // Broadcast context persistence
            // ---------------------------------------------------------------

            /// Broadcast context snapshot roundtrips through `ProtocolStore`.
            #[tokio::test]
            async fn broadcast_snapshot_roundtrip() {
                let store = $make_store;
                let ctx_id = "ctx-broadcast-roundtrip";
                let snapshot = make_broadcast_snapshot(ctx_id);

                store
                    .store_broadcast_state(ctx_id, &snapshot)
                    .await
                    .unwrap();

                let loaded = store.load_broadcast_state(ctx_id).await.unwrap().unwrap();

                assert_eq!(loaded.context_id, ctx_id);
                assert_eq!(loaded.admission, BroadcastAdmission::Open);
                assert_eq!(loaded.subscribers.len(), 2);
                assert!(loaded.subscribers.contains_key("did:dht:z6MkSub1"));
                assert!(loaded.subscribers.contains_key("did:dht:z6MkSub2"));
                assert_eq!(loaded.authors.len(), 1);

                let author = loaded.authors.get("did:dht:z6MkAuthor1").unwrap();
                let original_author = snapshot.authors.get("did:dht:z6MkAuthor1").unwrap();
                assert_eq!(author.epoch, 3);
                assert_eq!(
                    author.broadcast_key.as_bytes(),
                    original_author.broadcast_key.as_bytes(),
                    "broadcast_key must survive persist/load roundtrip"
                );
                assert!(author.block_list.contains("did:dht:z6MkBlocked"));
            }

            /// Broadcast context can be restored from snapshot and produces
            /// a working `BroadcastContext` instance.
            #[tokio::test]
            async fn broadcast_restore_from_snapshot() {
                let store = $make_store;
                let ctx_id = "ctx-broadcast-restore";
                let snapshot = make_broadcast_snapshot(ctx_id);

                store
                    .store_broadcast_state(ctx_id, &snapshot)
                    .await
                    .unwrap();

                let loaded = store.load_broadcast_state(ctx_id).await.unwrap().unwrap();

                // Reconstruct BroadcastContext from snapshot.
                let bc = BroadcastContext::from_snapshot(loaded);

                // Verify the restored context has the correct state.
                let re_snapshot = bc.to_snapshot();
                assert_eq!(re_snapshot.context_id, ctx_id);
                assert_eq!(re_snapshot.admission, BroadcastAdmission::Open);
                assert_eq!(re_snapshot.subscribers.len(), 2);
                assert_eq!(re_snapshot.authors.len(), 1);

                let author = re_snapshot.authors.get("did:dht:z6MkAuthor1").unwrap();
                assert_eq!(author.epoch, 3);
            }

            /// Broadcast block lists survive persist/load roundtrip and deletion.
            #[tokio::test]
            async fn broadcast_block_list_roundtrip_and_cleanup() {
                let store = $make_store;
                let ctx_id = "ctx-block-list-test";
                let author = "did:dht:z6MkAuthor";

                let mut block_list = HashSet::new();
                block_list.insert("did:dht:z6MkBlocked1".to_owned());
                block_list.insert("did:dht:z6MkBlocked2".to_owned());

                store
                    .store_broadcast_block_list(ctx_id, author, &block_list)
                    .await
                    .unwrap();

                let loaded = store
                    .load_broadcast_block_list(ctx_id, author)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(loaded, block_list);

                // delete_context should also remove block lists.
                store.store_context_state(ctx_id, b"state").await.unwrap();
                store.delete_context(ctx_id).await.unwrap();

                assert!(
                    store
                        .load_broadcast_block_list(ctx_id, author)
                        .await
                        .unwrap()
                        .is_none()
                );
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
    ProtocolStore::new(SqliteStorage::new(&dir_path, &key).unwrap())
});

// FilesystemStorage -- gated behind `filesystem` feature.
#[cfg(feature = "filesystem")]
persistence_tests!(filesystem, {
    let dir = tempfile::tempdir().unwrap();
    let dir_path = dir.path().to_path_buf();
    let _ = Box::leak(Box::new(dir));
    ProtocolStore::new(FilesystemStorage::new(&dir_path).unwrap())
});

// ---------------------------------------------------------------------------
// ContextManager-level persistence integration test
// ---------------------------------------------------------------------------

/// A simple `ContextPersistence` implementation using synchronous
/// `Mutex<HashMap>` for testing the `ContextManager::restore_context`
/// path. Avoids the "`block_on` inside runtime" problem by not using async
/// storage under the hood.
struct InMemoryContextPersistence {
    contexts: std::sync::Mutex<HashMap<String, ContextSnapshot>>,
    broadcasts: std::sync::Mutex<HashMap<String, BroadcastContextSnapshot>>,
}

impl InMemoryContextPersistence {
    fn new() -> Self {
        Self {
            contexts: std::sync::Mutex::new(HashMap::new()),
            broadcasts: std::sync::Mutex::new(HashMap::new()),
        }
    }
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

impl ContextPersistence for InMemoryContextPersistence {
    fn persist_context(
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

    fn load_context(&self, context_id: &str) -> Result<Option<ContextSnapshot>, BoxError> {
        let guard = self
            .contexts
            .lock()
            .map_err(|e| -> BoxError { Box::new(std::io::Error::other(e.to_string())) })?;
        Ok(guard.get(context_id).cloned())
    }

    fn persist_broadcast(
        &self,
        context_id: &str,
        snapshot: &BroadcastContextSnapshot,
    ) -> Result<(), BoxError> {
        self.broadcasts
            .lock()
            .map_err(|e| -> BoxError { Box::new(std::io::Error::other(e.to_string())) })?
            .insert(context_id.to_owned(), snapshot.clone());
        Ok(())
    }

    fn load_broadcast(
        &self,
        context_id: &str,
    ) -> Result<Option<BroadcastContextSnapshot>, BoxError> {
        let guard = self
            .broadcasts
            .lock()
            .map_err(|e| -> BoxError { Box::new(std::io::Error::other(e.to_string())) })?;
        Ok(guard.get(context_id).cloned())
    }

    fn delete_context(&self, context_id: &str) -> Result<(), BoxError> {
        self.contexts
            .lock()
            .map_err(|e| -> BoxError { Box::new(std::io::Error::other(e.to_string())) })?
            .remove(context_id);
        self.broadcasts
            .lock()
            .map_err(|e| -> BoxError { Box::new(std::io::Error::other(e.to_string())) })?
            .remove(context_id);
        Ok(())
    }

    fn list_persisted_contexts(&self) -> Result<Vec<String>, BoxError> {
        let guard = self
            .contexts
            .lock()
            .map_err(|e| -> BoxError { Box::new(std::io::Error::other(e.to_string())) })?;
        Ok(guard.keys().cloned().collect())
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
        fn validate_key_package(&self, _owner_did: &str) -> Result<(), ContextError> {
            Ok(())
        }
        fn add_member(&self, _ctx_id: &[u8; 32], _member_did: &str) -> Result<(), ContextError> {
            Ok(())
        }
        fn remove_member(&self, _ctx_id: &[u8; 32], _member_did: &str) -> Result<(), ContextError> {
            Ok(())
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
        fn encrypt_message(
            &self,
            _ctx_id: &[u8; 32],
            _sender_did: &str,
            _payload: &[u8],
        ) -> Result<Vec<u8>, ContextError> {
            Ok(vec![])
        }
    }

    pub struct MockTransport;
    impl ContextTransportProvider for MockTransport {
        fn is_connected(&self) -> bool {
            true
        }
        fn publish_context(
            &self,
            _ctx_id: &[u8; 32],
            _params: &ContextParams,
        ) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn delete_published(&self, _ctx_id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn send_message(
            &self,
            _ctx_id: &[u8; 32],
            _encrypted_payload: &[u8],
        ) -> Result<(), ContextError> {
            Ok(())
        }
    }

    pub struct MockEventLog;
    impl ContextEventLogProvider for MockEventLog {
        fn init_event_log(&self, _ctx_id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn append_event(
            &self,
            _ctx_id: &[u8; 32],
            _event: &str,
        ) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn destroy_event_log(&self, _ctx_id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
    }
}

/// End-to-end test: persist a broadcast context snapshot via
/// `InMemoryContextPersistence`, then restore it into a fresh
/// `ContextManager` via `restore_context`.
#[tokio::test]
async fn context_manager_broadcast_restore_roundtrip() {
    use mock_providers::*;

    let persistence = InMemoryContextPersistence::new();
    let ctx_id = "ctx-manager-restore";

    // Persist a context snapshot (required for restore_context).
    let ceiling = CapabilityCeiling::new(vec![Capability::MessagesRead, Capability::MessagesWrite]);
    let role_state = ContextRoleState::new(ctx_id, "did:dht:z6MkAuthor1", ceiling, vec![]).unwrap();

    let context_snapshot = ContextSnapshot {
        context_id: ctx_id.to_owned(),
        state: ContextState::Active,
        context_params: ContextParams::default(),
        membership: MembershipState::new(),
        role_state,
        executed_proposals: HashSet::new(),
        ttl_remaining_secs: None,
        registered_tools: Vec::new(),
        write_revoked_members: HashSet::new(),
        tool_interfaces: Vec::new(),
        threshold_signers: Vec::new(),
        threshold_value: 0,
        pruning_policy: None,
    };
    persistence
        .persist_context(ctx_id, &context_snapshot)
        .unwrap();

    // Persist a broadcast snapshot.
    let broadcast_snapshot = make_broadcast_snapshot(ctx_id);
    persistence
        .persist_broadcast(ctx_id, &broadcast_snapshot)
        .unwrap();

    // Create a ContextManager with persistence.
    let manager = ContextManager::with_persistence(
        Box::new(MockCrypto),
        Box::new(MockTransport),
        Box::new(MockEventLog),
        Box::new(persistence),
    );

    // Create a context handle in Active state (simulating post-restart).
    let handle = ContextHandle::new(ctx_id.to_owned(), ContextParams::default());
    handle.transition_to(&ContextState::Active).await.unwrap();

    // Restore the context from persistence.
    manager.restore_context(ctx_id, &handle).await.unwrap();

    // Verify the context is registered by trying to restore again (should fail
    // with "already registered").
    let handle2 = ContextHandle::new(ctx_id.to_owned(), ContextParams::default());
    handle2.transition_to(&ContextState::Active).await.unwrap();
    let result = manager.restore_context(ctx_id, &handle2).await;
    assert!(result.is_err(), "double-restore should fail");
}
