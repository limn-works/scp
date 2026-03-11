//! Advanced persistence integration tests (SCP-PERSIST-071).
//!
//! Tests advanced persistence scenarios beyond basic lifecycle (SCP-PERSIST-070):
//!
//! 1. **Sync roundtrip** -- two `ProtocolStore` instances backed by separate
//!    `InMemoryStorage`, mutations on store A exported and applied to store B,
//!    verify B matches A.
//! 2. **Relay restart** -- subscription routing IDs and blob data persisted
//!    via `ProtocolStore` and `BlobStorage` survive across operations; verifies
//!    the data flow that `StorageRelayPersistence` will automate in Gate 6.
//! 3. **Combined node** -- client contexts (`Storage`/`ProtocolStore`) and relay
//!    blobs (`BlobStorage`) coexist and operate independently, validating the
//!    pattern `CombinedNodeStorage` will implement in Gate 6.
//! 4. **`executed_proposals` replay protection** -- proposal ID sets persist
//!    via `MessagePack` serialization through `ProtocolStore` and survive
//!    load/store cycles, ensuring replay detection works across restarts.
//!
//! See `.docs/prds/persistence.json` story SCP-PERSIST-071.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{HashMap, HashSet};

use scp_core::context::broadcast::{
    AuthorStateSnapshot, BroadcastAdmission, BroadcastContextSnapshot, SubscriberRecord,
};
use scp_core::crypto::sender_keys::generate_sender_key;
use scp_core::store::ProtocolStore;
use scp_identity::DID;
use scp_platform::testing::InMemoryStorage;
use scp_transport::native::storage::{BlobStorage, InMemoryBlobStorage};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Creates a test [`ProtocolStore`] backed by a fresh [`InMemoryStorage`].
fn make_store() -> ProtocolStore<InMemoryStorage> {
    ProtocolStore::new_for_testing(InMemoryStorage::new())
}

/// Creates a deterministic test DID from a suffix.
fn test_did(suffix: &str) -> DID {
    DID::from(format!("did:dht:z6Mk{suffix}"))
}

/// Creates a test [`BroadcastContextSnapshot`] with realistic data.
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
            next_sequence: 1,
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

/// Makes a deterministic `blob_id` from input bytes using SHA-256.
fn make_blob_id(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    out
}

// =========================================================================
// Test 1: Sync roundtrip
// =========================================================================

/// Two `ProtocolStore` instances backed by separate `InMemoryStorage` instances.
/// Mutations on store A are exported (state read from store A), then applied
/// to store B. After sync, B must contain identical state to A.
///
/// This validates the sync pattern that `SyncableStorage` will implement
/// (`export_changeset` from A, `apply_changeset` to B).
#[tokio::test]
async fn sync_roundtrip_two_stores_match_after_export_apply() {
    let store_a = make_store();
    let store_b = make_store();

    let ctx_id = "sync-ctx-1";
    let did_alice = test_did("Alice");
    let did_bob = test_did("Bob");

    // --- Mutate store A ---
    store_a
        .store_context_state(ctx_id, b"active-state-v1")
        .await
        .unwrap();
    store_a
        .store_context_params(ctx_id, b"params-v1")
        .await
        .unwrap();
    store_a
        .store_membership(ctx_id, &did_alice, "admin")
        .await
        .unwrap();
    store_a
        .store_membership(ctx_id, &did_bob, "member")
        .await
        .unwrap();
    store_a
        .store_role(ctx_id, "admin", b"admin-role-def")
        .await
        .unwrap();
    store_a
        .store_role(ctx_id, "member", b"member-role-def")
        .await
        .unwrap();

    // --- Export from A: read all state ---
    let state = store_a.load_context_state(ctx_id).await.unwrap();
    let params = store_a.load_context_params(ctx_id).await.unwrap();
    let members = store_a.list_members(ctx_id).await.unwrap();
    let roles = store_a.list_roles(ctx_id).await.unwrap();
    let role_admin = store_a.load_role(ctx_id, "admin").await.unwrap();
    let role_member = store_a.load_role(ctx_id, "member").await.unwrap();

    // --- Apply to B: write exported state ---
    if let Some(ref s) = state {
        store_b.store_context_state(ctx_id, s).await.unwrap();
    }
    if let Some(ref p) = params {
        store_b.store_context_params(ctx_id, p).await.unwrap();
    }
    for (did, role) in &members {
        store_b.store_membership(ctx_id, did, role).await.unwrap();
    }
    for role_name in &roles {
        let data = match role_name.as_str() {
            "admin" => role_admin.as_deref(),
            "member" => role_member.as_deref(),
            _ => None,
        };
        if let Some(d) = data {
            store_b.store_role(ctx_id, role_name, d).await.unwrap();
        }
    }

    // --- Verify B matches A ---
    assert_eq!(
        store_b.load_context_state(ctx_id).await.unwrap(),
        Some(b"active-state-v1".to_vec()),
        "context state must match after sync"
    );
    assert_eq!(
        store_b.load_context_params(ctx_id).await.unwrap(),
        Some(b"params-v1".to_vec()),
        "context params must match after sync"
    );
    assert_eq!(
        store_b.load_membership(ctx_id, &did_alice).await.unwrap(),
        Some("admin".to_owned()),
        "Alice's membership must match after sync"
    );
    assert_eq!(
        store_b.load_membership(ctx_id, &did_bob).await.unwrap(),
        Some("member".to_owned()),
        "Bob's membership must match after sync"
    );
    assert_eq!(
        store_b.load_role(ctx_id, "admin").await.unwrap(),
        Some(b"admin-role-def".to_vec()),
        "admin role must match after sync"
    );
    assert_eq!(
        store_b.load_role(ctx_id, "member").await.unwrap(),
        Some(b"member-role-def".to_vec()),
        "member role must match after sync"
    );

    // Verify active contexts list matches.
    let active_a = store_a.list_active_contexts().await.unwrap();
    let active_b = store_b.list_active_contexts().await.unwrap();
    assert_eq!(active_a, active_b, "active context lists must match");
}

/// Sync roundtrip with broadcast state: export broadcast snapshot from A,
/// apply to B, verify the snapshot survives the transfer.
#[tokio::test]
async fn sync_roundtrip_broadcast_state_transfers() {
    let store_a = make_store();
    let store_b = make_store();

    let ctx_id = "sync-broadcast-1";
    let snapshot = make_broadcast_snapshot(ctx_id);

    // Store on A.
    store_a
        .store_broadcast_state(ctx_id, &snapshot)
        .await
        .unwrap();

    // Export from A.
    let loaded = store_a
        .load_broadcast_state(ctx_id)
        .await
        .unwrap()
        .expect("broadcast state should exist on A");

    // Apply to B.
    store_b
        .store_broadcast_state(ctx_id, &loaded)
        .await
        .unwrap();

    // Verify B.
    let on_b = store_b
        .load_broadcast_state(ctx_id)
        .await
        .unwrap()
        .expect("broadcast state should exist on B");

    assert_eq!(on_b.context_id, ctx_id);
    assert_eq!(on_b.admission, BroadcastAdmission::Open);
    assert_eq!(on_b.subscribers.len(), 2);
    assert!(on_b.subscribers.contains_key("did:dht:z6MkSub1"));
    assert!(on_b.subscribers.contains_key("did:dht:z6MkSub2"));
    assert_eq!(on_b.authors.len(), 1);
    let author = on_b.authors.get("did:dht:z6MkAuthor1").unwrap();
    assert_eq!(author.epoch, 3);
    assert!(author.block_list.contains("did:dht:z6MkBlocked"));
}

// =========================================================================
// Test 2: Relay restart -- subscription and blob persistence
// =========================================================================

/// Persists subscription routing IDs via `ProtocolStore` and verifies they
/// can be loaded back, simulating the `StorageRelayPersistence` pattern.
///
/// The relay stores its subscription set, then "restarts" (creates a new
/// `ProtocolStore` over the same storage), and loads the subscriptions back.
/// Since `InMemoryStorage` is ephemeral, we test the full persist/load
/// roundtrip within a single session. Production would use `SqliteStorage`
/// for true restart survival.
#[tokio::test]
async fn relay_subscription_persist_and_load_roundtrip() {
    let store = make_store();

    let routing_id_1 = [0xAA; 32];
    let routing_id_2 = [0xBB; 32];
    let routing_id_3 = [0xCC; 32];

    // Persist subscription routing IDs as serialized state.
    let subscriptions: Vec<[u8; 32]> = vec![routing_id_1, routing_id_2, routing_id_3];
    let sub_bytes = rmp_serde::to_vec(&subscriptions).unwrap();
    store
        .store_context_state("relay-subscriptions", &sub_bytes)
        .await
        .unwrap();

    // Load subscriptions back (simulating restart load).
    let loaded_bytes = store
        .load_context_state("relay-subscriptions")
        .await
        .unwrap()
        .expect("subscription state should be loadable");

    let loaded_subs: Vec<[u8; 32]> = rmp_serde::from_slice(&loaded_bytes).unwrap();
    assert_eq!(loaded_subs.len(), 3);
    assert_eq!(loaded_subs[0], routing_id_1);
    assert_eq!(loaded_subs[1], routing_id_2);
    assert_eq!(loaded_subs[2], routing_id_3);
}

/// Relay blobs are queryable by `routing_id` after storage without
/// re-subscribing. This verifies the `BlobStorage` contract that
/// `StorageRelayPersistence` relies on for post-restart blob delivery.
#[tokio::test]
async fn relay_blobs_queryable_without_resubscribe() {
    let blob_storage = InMemoryBlobStorage::new();
    let routing_id = [0xCC; 32];

    // Store blobs.
    let blob_data_1 = vec![1, 2, 3, 4, 5];
    let blob_id_1 = make_blob_id(&blob_data_1);
    blob_storage
        .store(routing_id, blob_id_1, None, 3600, blob_data_1.clone())
        .await
        .unwrap();

    let blob_data_2 = vec![6, 7, 8, 9, 10];
    let blob_id_2 = make_blob_id(&blob_data_2);
    blob_storage
        .store(routing_id, blob_id_2, None, 3600, blob_data_2.clone())
        .await
        .unwrap();

    // Query blobs by routing_id (simulating post-restart blob delivery
    // without re-subscribing -- the blob data is already in storage).
    let blobs = blob_storage.query(&routing_id, None, 100).await.unwrap();
    assert_eq!(blobs.len(), 2, "both blobs should be queryable");

    // Verify blob contents via get.
    let retrieved_1 = blob_storage.get(&blob_id_1).await.unwrap().unwrap();
    assert_eq!(retrieved_1.blob, blob_data_1);

    let retrieved_2 = blob_storage.get(&blob_id_2).await.unwrap().unwrap();
    assert_eq!(retrieved_2.blob, blob_data_2);
}

/// Persists rate limit state as a `ProtocolStore` value, simulating the
/// `StorageRelayPersistence::persist_rate_limit` / `load_rate_limit` pattern.
#[tokio::test]
async fn relay_rate_limit_state_persist_load_roundtrip() {
    let store = make_store();

    // Rate limit state: (remaining_tokens, last_replenish_timestamp).
    let rate_state: (u32, u64) = (42, 1_700_000_500);
    let bytes = rmp_serde::to_vec(&rate_state).unwrap();
    store
        .store_context_state("relay-rate-limit", &bytes)
        .await
        .unwrap();

    let loaded_bytes = store
        .load_context_state("relay-rate-limit")
        .await
        .unwrap()
        .expect("rate limit state should be loadable");

    let loaded: (u32, u64) = rmp_serde::from_slice(&loaded_bytes).unwrap();
    assert_eq!(loaded.0, 42, "remaining tokens must match");
    assert_eq!(loaded.1, 1_700_000_500, "timestamp must match");
}

// =========================================================================
// Test 3: Combined node -- client contexts + relay blobs coexist
// =========================================================================

/// Verifies that client context state (via `ProtocolStore`/`Storage`) and relay
/// blob data (via `BlobStorage`) can coexist and operate independently. This
/// is the pattern `CombinedNodeStorage` will implement: a single directory
/// holding both KV (client) and blob (relay) tables.
#[tokio::test]
async fn combined_node_client_and_relay_data_coexist() {
    // Client-side: `ProtocolStore` backed by `InMemoryStorage`.
    let client_store = make_store();

    // Relay-side: InMemoryBlobStorage.
    let relay_storage = InMemoryBlobStorage::new();

    let ctx_id = "combined-ctx-1";
    let did_alice = test_did("CombinedAlice");

    // --- Populate client store ---
    client_store
        .store_context_state(ctx_id, b"combined-state")
        .await
        .unwrap();
    client_store
        .store_context_params(ctx_id, b"combined-params")
        .await
        .unwrap();
    client_store
        .store_membership(ctx_id, &did_alice, "owner")
        .await
        .unwrap();

    // Store broadcast state.
    let broadcast = make_broadcast_snapshot(ctx_id);
    client_store
        .store_broadcast_state(ctx_id, &broadcast)
        .await
        .unwrap();

    // --- Populate relay store ---
    let routing_id = [0xDD; 32];
    let blob_data = vec![42, 43, 44, 45];
    let blob_id = make_blob_id(&blob_data);
    relay_storage
        .store(routing_id, blob_id, None, 3600, blob_data.clone())
        .await
        .unwrap();

    let blob_data_2 = vec![50, 51, 52];
    let blob_id_2 = make_blob_id(&blob_data_2);
    relay_storage
        .store(
            routing_id,
            blob_id_2,
            Some([0xEE; 32]),
            7200,
            blob_data_2.clone(),
        )
        .await
        .unwrap();

    // --- Verify client data ---
    assert_eq!(
        client_store.load_context_state(ctx_id).await.unwrap(),
        Some(b"combined-state".to_vec()),
    );
    assert_eq!(
        client_store.load_context_params(ctx_id).await.unwrap(),
        Some(b"combined-params".to_vec()),
    );
    assert_eq!(
        client_store
            .load_membership(ctx_id, &did_alice)
            .await
            .unwrap(),
        Some("owner".to_owned()),
    );

    // Broadcast state.
    let bc = client_store
        .load_broadcast_state(ctx_id)
        .await
        .unwrap()
        .expect("broadcast state should exist");
    assert_eq!(bc.context_id, ctx_id);
    assert_eq!(bc.subscribers.len(), 2);
    assert_eq!(bc.authors.len(), 1);

    // Active context listing.
    let active = client_store.list_active_contexts().await.unwrap();
    assert_eq!(active, vec![ctx_id]);

    // --- Verify relay data ---
    let blobs = relay_storage.query(&routing_id, None, 100).await.unwrap();
    assert_eq!(blobs.len(), 2);

    let retrieved = relay_storage.get(&blob_id).await.unwrap().unwrap();
    assert_eq!(retrieved.blob, blob_data);
    assert_eq!(retrieved.routing_id, routing_id);

    let retrieved_2 = relay_storage.get(&blob_id_2).await.unwrap().unwrap();
    assert_eq!(retrieved_2.blob, blob_data_2);
    assert_eq!(retrieved_2.recipient_hint, Some([0xEE; 32]));
}

/// Combined node with multiple contexts: verifies that distinct context
/// states are independently preserved and do not interfere with each other
/// or with relay blob data.
#[tokio::test]
async fn combined_node_multiple_contexts_independent() {
    let client_store = make_store();
    let relay_storage = InMemoryBlobStorage::new();

    let ctx_1 = "combined-multi-1";
    let ctx_2 = "combined-multi-2";

    // Client contexts.
    client_store
        .store_context_state(ctx_1, b"state-1")
        .await
        .unwrap();
    client_store
        .store_context_state(ctx_2, b"state-2")
        .await
        .unwrap();

    let did_a = test_did("MultiAlice");
    let did_b = test_did("MultiBob");

    client_store
        .store_membership(ctx_1, &did_a, "admin")
        .await
        .unwrap();
    client_store
        .store_membership(ctx_2, &did_b, "viewer")
        .await
        .unwrap();

    // Relay blobs under different routing IDs.
    let routing_a = [0xAA; 32];
    let routing_b = [0xBB; 32];

    let data_a = vec![1, 2, 3];
    let id_a = make_blob_id(&data_a);
    relay_storage
        .store(routing_a, id_a, None, 3600, data_a.clone())
        .await
        .unwrap();

    let data_b = vec![4, 5, 6];
    let id_b = make_blob_id(&data_b);
    relay_storage
        .store(routing_b, id_b, None, 3600, data_b.clone())
        .await
        .unwrap();

    // Verify context isolation.
    assert_eq!(
        client_store.load_context_state(ctx_1).await.unwrap(),
        Some(b"state-1".to_vec()),
    );
    assert_eq!(
        client_store.load_context_state(ctx_2).await.unwrap(),
        Some(b"state-2".to_vec()),
    );

    // Membership is context-scoped.
    assert_eq!(
        client_store.load_membership(ctx_1, &did_a).await.unwrap(),
        Some("admin".to_owned()),
    );
    assert!(
        client_store
            .load_membership(ctx_1, &did_b)
            .await
            .unwrap()
            .is_none(),
        "Bob should not be a member of ctx_1"
    );
    assert_eq!(
        client_store.load_membership(ctx_2, &did_b).await.unwrap(),
        Some("viewer".to_owned()),
    );
    assert!(
        client_store
            .load_membership(ctx_2, &did_a)
            .await
            .unwrap()
            .is_none(),
        "Alice should not be a member of ctx_2"
    );

    // Active contexts list.
    let active = client_store.list_active_contexts().await.unwrap();
    assert_eq!(active, vec!["combined-multi-1", "combined-multi-2"]);

    // Blob routing isolation.
    let blobs_a = relay_storage.query(&routing_a, None, 100).await.unwrap();
    assert_eq!(blobs_a.len(), 1);
    assert_eq!(blobs_a[0].blob, data_a);

    let blobs_b = relay_storage.query(&routing_b, None, 100).await.unwrap();
    assert_eq!(blobs_b.len(), 1);
    assert_eq!(blobs_b[0].blob, data_b);

    // Delete context 1 does not affect context 2 or blobs.
    client_store.delete_context(ctx_1).await.unwrap();
    assert!(
        client_store
            .load_context_state(ctx_1)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        client_store.load_context_state(ctx_2).await.unwrap(),
        Some(b"state-2".to_vec()),
    );
    // Blobs unaffected by client context deletion.
    assert!(relay_storage.get(&id_a).await.unwrap().is_some());
    assert!(relay_storage.get(&id_b).await.unwrap().is_some());
}

// =========================================================================
// Test 4: executed_proposals replay protection across restart
// =========================================================================

/// Persists a set of executed proposal IDs via `ProtocolStore`, then loads
/// them back and verifies the set is faithfully restored. This proves that
/// replay protection data survives the persist/load cycle.
///
/// In production, `ContextPersistence::persist_context` will include
/// `executed_proposals` in the `ContextSnapshot`. Here we test the
/// serialization roundtrip through `ProtocolStore` directly.
#[tokio::test]
async fn executed_proposals_persist_load_roundtrip() {
    let store = make_store();
    let ctx_id = "replay-ctx-1";

    // Simulate 3 executed proposals (ProposalId = [u8; 32]).
    let proposal_1 = make_proposal_id(b"proposal-alpha");
    let proposal_2 = make_proposal_id(b"proposal-beta");
    let proposal_3 = make_proposal_id(b"proposal-gamma");

    let mut executed: HashSet<[u8; 32]> = HashSet::new();
    executed.insert(proposal_1);
    executed.insert(proposal_2);
    executed.insert(proposal_3);

    // Persist the executed proposals set via ProtocolStore.
    let serialized = rmp_serde::to_vec(&executed).unwrap();
    store
        .store_context_state(ctx_id, &serialized)
        .await
        .unwrap();

    // Load back (simulating restart restore).
    let loaded_bytes = store
        .load_context_state(ctx_id)
        .await
        .unwrap()
        .expect("executed proposals should be loadable");

    let loaded_proposals: HashSet<[u8; 32]> = rmp_serde::from_slice(&loaded_bytes).unwrap();

    // Verify all 3 proposals are in the set.
    assert_eq!(loaded_proposals.len(), 3);
    assert!(
        loaded_proposals.contains(&proposal_1),
        "proposal_1 must survive persist/load"
    );
    assert!(
        loaded_proposals.contains(&proposal_2),
        "proposal_2 must survive persist/load"
    );
    assert!(
        loaded_proposals.contains(&proposal_3),
        "proposal_3 must survive persist/load"
    );

    // Verify a never-executed proposal is NOT in the set.
    let unexecuted = make_proposal_id(b"proposal-never-executed");
    assert!(
        !loaded_proposals.contains(&unexecuted),
        "unexecuted proposal must not appear in the restored set"
    );
}

/// Tests that proposals accumulate across multiple persist/load cycles.
/// Each cycle adds a new proposal; the full set persists correctly.
#[tokio::test]
async fn executed_proposals_accrue_across_persist_load_cycles() {
    let store = make_store();
    let ctx_id = "accrue-ctx-1";

    // Cycle 1: execute 2 proposals.
    let mut executed: HashSet<[u8; 32]> = HashSet::new();
    executed.insert([0x01; 32]);
    executed.insert([0x02; 32]);

    let bytes = rmp_serde::to_vec(&executed).unwrap();
    store.store_context_state(ctx_id, &bytes).await.unwrap();

    // Cycle 2: load, add proposal, re-persist.
    let loaded_bytes = store
        .load_context_state(ctx_id)
        .await
        .unwrap()
        .expect("should exist");

    let mut proposals: HashSet<[u8; 32]> = rmp_serde::from_slice(&loaded_bytes).unwrap();
    assert_eq!(proposals.len(), 2);

    // Execute a new proposal.
    proposals.insert([0x03; 32]);
    assert_eq!(proposals.len(), 3);

    // Re-persist.
    let bytes = rmp_serde::to_vec(&proposals).unwrap();
    store.store_context_state(ctx_id, &bytes).await.unwrap();

    // Cycle 3: verify all 3 survive.
    let loaded_bytes = store
        .load_context_state(ctx_id)
        .await
        .unwrap()
        .expect("should exist");

    let final_proposals: HashSet<[u8; 32]> = rmp_serde::from_slice(&loaded_bytes).unwrap();
    assert_eq!(final_proposals.len(), 3);
    assert!(final_proposals.contains(&[0x01; 32]));
    assert!(final_proposals.contains(&[0x02; 32]));
    assert!(final_proposals.contains(&[0x03; 32]));

    // Replay of proposal 0x01 would be caught.
    assert!(
        final_proposals.contains(&[0x01; 32]),
        "replayed proposal 0x01 is in the set -- replay detection works"
    );
}

/// Verifies that deleting a context also removes its executed proposals.
/// This ensures cleanup correctness for the replay protection set.
#[tokio::test]
async fn executed_proposals_cleaned_up_on_context_delete() {
    let store = make_store();
    let ctx_id = "cleanup-ctx-1";

    // Store some proposals.
    let mut executed: HashSet<[u8; 32]> = HashSet::new();
    executed.insert([0xAA; 32]);
    executed.insert([0xBB; 32]);

    let bytes = rmp_serde::to_vec(&executed).unwrap();
    store.store_context_state(ctx_id, &bytes).await.unwrap();

    // Also store other context data.
    store.store_context_params(ctx_id, b"params").await.unwrap();

    // Delete context.
    let deleted = store.delete_context(ctx_id).await.unwrap();
    assert!(deleted >= 2, "should delete at least state and params");

    // Verify everything is gone.
    assert!(store.load_context_state(ctx_id).await.unwrap().is_none());
    assert!(store.load_context_params(ctx_id).await.unwrap().is_none());
}

/// Duplicate proposal insertion is idempotent -- `HashSet` semantics ensure
/// that inserting an already-executed proposal does not grow the set.
#[tokio::test]
async fn executed_proposals_duplicate_insertion_idempotent() {
    let store = make_store();
    let ctx_id = "dedup-ctx-1";

    let proposal = [0xDD; 32];

    let mut executed: HashSet<[u8; 32]> = HashSet::new();
    executed.insert(proposal);
    executed.insert(proposal); // duplicate

    assert_eq!(executed.len(), 1, "HashSet deduplicates");

    let bytes = rmp_serde::to_vec(&executed).unwrap();
    store.store_context_state(ctx_id, &bytes).await.unwrap();

    let loaded_bytes = store
        .load_context_state(ctx_id)
        .await
        .unwrap()
        .expect("should exist");
    let loaded: HashSet<[u8; 32]> = rmp_serde::from_slice(&loaded_bytes).unwrap();
    assert_eq!(loaded.len(), 1);
    assert!(loaded.contains(&proposal));
}

// =========================================================================
// Test 5: SyncableStorage export/apply roundtrip (SCP-PERSIST-071)
// =========================================================================

/// Tests that `SyncableStorage` `export_changeset` / `apply_changeset`
/// roundtrips correctly. Mutations on store A are tracked, exported as a
/// changeset, and applied to store B, which then contains identical state.
#[cfg(feature = "sync")]
#[tokio::test]
async fn syncable_storage_export_apply_roundtrip() {
    use scp_platform::Storage;
    use scp_platform::syncable::SyncableStorage;

    let inner_a = InMemoryStorage::new();
    let sync_a = SyncableStorage::new(inner_a);

    let inner_b = InMemoryStorage::new();
    let sync_b = SyncableStorage::new(inner_b);

    // Mutate store A through SyncableStorage.
    Storage::store(&sync_a, "ctx/state", b"active")
        .await
        .unwrap();
    Storage::store(&sync_a, "ctx/params", b"params-v1")
        .await
        .unwrap();
    Storage::store(&sync_a, "identity/doc", b"my-identity")
        .await
        .unwrap();

    // Export changeset from A (since seq 0 = all changes).
    let changeset = sync_a.export_changeset(0).await.unwrap();
    assert!(!changeset.is_empty(), "changeset should contain entries");
    // identity/ keys should be in the changeset (they are tracked by the
    // changelog even though apply_changeset will reject them on import).
    assert_eq!(changeset.len(), 3, "all 3 mutations should be tracked");

    // Filter out identity/ keys before applying (apply_changeset rejects
    // protected namespaces). In a real sync flow, the sender would filter
    // or the receiver would handle the error. Here we test the happy path
    // with only context/ keys.
    let safe_changeset: Vec<_> = changeset
        .into_iter()
        .filter(|e| !e.key.starts_with("identity/"))
        .collect();
    assert_eq!(safe_changeset.len(), 2);

    // Apply to B.
    sync_b.apply_changeset(safe_changeset).await.unwrap();

    // Verify B matches A for the synced keys.
    assert_eq!(
        Storage::retrieve(&sync_b, "ctx/state").await.unwrap(),
        Some(b"active".to_vec()),
    );
    assert_eq!(
        Storage::retrieve(&sync_b, "ctx/params").await.unwrap(),
        Some(b"params-v1".to_vec()),
    );

    // identity/doc was not synced — should be absent on B.
    assert_eq!(
        Storage::retrieve(&sync_b, "identity/doc").await.unwrap(),
        None,
        "identity keys should not be synced"
    );

    // Verify that applying a changeset containing a protected key fails.
    let bad_changeset = vec![scp_platform::syncable::ChangeEntry {
        seq: 0,
        key: "identity/secret".to_owned(),
        value: Some(b"evil".to_vec()),
    }];
    let result = sync_b.apply_changeset(bad_changeset).await;
    assert!(
        result.is_err(),
        "apply_changeset should reject protected namespace keys"
    );
}

// =========================================================================
// Test 6: CombinedNodeStorage — both Storage and BlobStorage traits
// =========================================================================

/// Tests that `CombinedNodeStorage` serves both `Storage` and `BlobStorage`
/// from a single SQLite database, and data survives roundtrip. Uses
/// trait-qualified (UFCS) method calls to disambiguate `store` and `delete`
/// which exist on both traits.
#[cfg(feature = "combined")]
#[tokio::test]
async fn combined_node_storage_both_traits_roundtrip() {
    use scp_platform::Storage;
    use scp_transport::native::combined::CombinedNodeStorage;
    use scp_transport::native::storage::BlobStorage;

    let dir = tempfile::tempdir().unwrap();
    let key = [0xABu8; 32];
    let combined = CombinedNodeStorage::open(dir.path(), &key).unwrap();

    // Use as Storage (KV) — UFCS to disambiguate from BlobStorage::store.
    Storage::store(&combined, "context/test/state", b"active")
        .await
        .unwrap();
    Storage::store(&combined, "context/test/params", b"params")
        .await
        .unwrap();

    // Use as BlobStorage — UFCS to disambiguate from Storage::store.
    let routing_id = [0xAA; 32];
    let blob_data = vec![1, 2, 3, 4, 5];
    let blob_id = make_blob_id(&blob_data);
    BlobStorage::store(
        &combined,
        routing_id,
        blob_id,
        None,
        3600,
        blob_data.clone(),
    )
    .await
    .unwrap();

    // Verify KV data.
    let state = Storage::retrieve(&combined, "context/test/state")
        .await
        .unwrap();
    assert_eq!(state, Some(b"active".to_vec()));

    let params = Storage::retrieve(&combined, "context/test/params")
        .await
        .unwrap();
    assert_eq!(params, Some(b"params".to_vec()));

    // Verify blob data.
    let blob = combined.get(&blob_id).await.unwrap().unwrap();
    assert_eq!(blob.blob, blob_data);
    assert_eq!(blob.routing_id, routing_id);

    // Verify they don't interfere: delete KV key, blob stays.
    Storage::delete(&combined, "context/test/state")
        .await
        .unwrap();
    assert!(
        Storage::retrieve(&combined, "context/test/state")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        combined.get(&blob_id).await.unwrap().is_some(),
        "blob should be unaffected by KV delete"
    );

    // Verify blob deletion doesn't affect KV.
    BlobStorage::delete(&combined, &blob_id).await.unwrap();
    assert!(combined.get(&blob_id).await.unwrap().is_none());
    assert_eq!(
        Storage::retrieve(&combined, "context/test/params")
            .await
            .unwrap(),
        Some(b"params".to_vec()),
        "KV data should be unaffected by blob delete"
    );
}

// ---------------------------------------------------------------------------
// Proposal ID helper
// ---------------------------------------------------------------------------

/// Creates a deterministic proposal ID from seed bytes using SHA-256.
fn make_proposal_id(seed: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(seed));
    out
}
