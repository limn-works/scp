//! `ProtocolRepository` module integration tests (SCP-PERSIST-072).
//!
//! Tests each `ProtocolRepository` domain module through the full
//! `ProtocolRepository -> Storage -> Backend` path using `InMemoryStorage`.
//!
//! Coverage:
//! - **Context**: membership store/load/list/remove roundtrip; role CRUD;
//!   context state and params; broadcast state and block lists; `delete_context`
//!   cascades; active context listing.
//! - **Identity**: DID document roundtrip; signing key roundtrip; private state
//!   sequence ordering; `delete_identity` cascades.
//! - **UCAN / Nonce**: token CRUD; revocation; nonce replay rejection after
//!   `check_and_record_nonce`; `prune_expired_nonces` removes only expired.
//! - **Economy**: adapter credential store/load/list/remove; identity isolation.
//! - **Tools**: tool and tool-session CRUD; context scoping; delete cascades.
//! - **Event Log**: append/load/range query, Merkle root and tree node roundtrip.
//! - **Sender Keys**: store/load/list/remove roundtrip; context isolation.
//! - **DID Cache**: cache with expiry; TOFU record roundtrip.
//! - **Transport**: relay score store/load/list roundtrip.
//! - **MLS**: group state roundtrip via `MlsStorageBridge`; context isolation.
//!
//! See spec sections 17.3 and 17.4.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashSet;
use std::sync::Arc;

use scp_core::crypto::mls::MlsStorageBridge;
use scp_core::store::ProtocolRepository;
use scp_identity::DID;
use scp_platform::testing::InMemoryStorage;

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

/// Creates a fresh `ProtocolRepository<InMemoryStorage>` for each test.
fn make_store() -> ProtocolRepository<InMemoryStorage> {
    ProtocolRepository::new_for_testing(InMemoryStorage::new())
}

// =========================================================================
// Context module — membership
// =========================================================================

#[tokio::test]
async fn membership_store_load_list_remove_roundtrip() {
    let store = make_store();
    let ctx = "ctx-membership-test";
    let alice = DID::from("did:dht:z6MkAlice");
    let bob = DID::from("did:dht:z6MkBob");

    // Store memberships.
    store.store_membership(ctx, &alice, "admin").await.unwrap();
    store.store_membership(ctx, &bob, "member").await.unwrap();

    // Load individual memberships.
    assert_eq!(
        store.load_membership(ctx, &alice).await.unwrap(),
        Some("admin".to_owned())
    );
    assert_eq!(
        store.load_membership(ctx, &bob).await.unwrap(),
        Some("member".to_owned())
    );

    // List all members.
    let mut members = store.list_members(ctx).await.unwrap();
    members.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(members.len(), 2);
    assert_eq!(members[0].0, alice);
    assert_eq!(members[0].1, "admin");
    assert_eq!(members[1].0, bob);
    assert_eq!(members[1].1, "member");

    // Remove one member.
    store.remove_membership(ctx, &alice).await.unwrap();
    assert!(store.load_membership(ctx, &alice).await.unwrap().is_none());

    // Remaining member still present.
    assert_eq!(
        store.load_membership(ctx, &bob).await.unwrap(),
        Some("member".to_owned())
    );

    // List reflects removal.
    let remaining = store.list_members(ctx).await.unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].0, bob);
}

#[tokio::test]
async fn membership_is_context_scoped() {
    let store = make_store();
    let did = DID::from("did:dht:z6MkShared");

    store
        .store_membership("ctx-a", &did, "admin")
        .await
        .unwrap();
    store
        .store_membership("ctx-b", &did, "viewer")
        .await
        .unwrap();

    assert_eq!(
        store.load_membership("ctx-a", &did).await.unwrap(),
        Some("admin".to_owned())
    );
    assert_eq!(
        store.load_membership("ctx-b", &did).await.unwrap(),
        Some("viewer".to_owned())
    );
}

// =========================================================================
// Context module — roles
// =========================================================================

#[tokio::test]
async fn role_store_load_list_roundtrip() {
    let store = make_store();
    let ctx = "ctx-role-test";

    store.store_role(ctx, "admin", b"admin-caps").await.unwrap();
    store
        .store_role(ctx, "member", b"member-caps")
        .await
        .unwrap();
    store
        .store_role(ctx, "viewer", b"viewer-caps")
        .await
        .unwrap();

    assert_eq!(
        store.load_role(ctx, "admin").await.unwrap(),
        Some(b"admin-caps".to_vec())
    );
    assert_eq!(
        store.load_role(ctx, "member").await.unwrap(),
        Some(b"member-caps".to_vec())
    );

    let mut roles = store.list_roles(ctx).await.unwrap();
    roles.sort();
    assert_eq!(roles, vec!["admin", "member", "viewer"]);
}

// =========================================================================
// Context module — state and params
// =========================================================================

#[tokio::test]
async fn context_state_and_params_roundtrip() {
    let store = make_store();
    let ctx = "ctx-state-test";

    store
        .store_context_state(ctx, b"serialized-state")
        .await
        .unwrap();
    store
        .store_context_params(ctx, b"serialized-params")
        .await
        .unwrap();

    assert_eq!(
        store.load_context_state(ctx).await.unwrap(),
        Some(b"serialized-state".to_vec())
    );
    assert_eq!(
        store.load_context_params(ctx).await.unwrap(),
        Some(b"serialized-params".to_vec())
    );
}

#[tokio::test]
async fn context_state_returns_none_for_missing() {
    let store = make_store();
    assert!(
        store
            .load_context_state("nonexistent")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .load_context_params("nonexistent")
            .await
            .unwrap()
            .is_none()
    );
}

// =========================================================================
// Context module — delete cascades
// =========================================================================

#[tokio::test]
async fn delete_context_removes_all_associated_state() {
    let store = make_store();
    let ctx = "ctx-delete-test";
    let did = DID::from("did:dht:z6MkMember");

    // Populate context with state, params, membership, role, outlet, session.
    store.store_context_state(ctx, b"state").await.unwrap();
    store.store_context_params(ctx, b"params").await.unwrap();
    store.store_membership(ctx, &did, "member").await.unwrap();
    store.store_role(ctx, "admin", b"role-data").await.unwrap();
    store
        .store_outlet(ctx, "outlet-1", b"outlet-reg")
        .await
        .unwrap();
    store
        .store_outlet_session(ctx, "sess-1", b"sess-data")
        .await
        .unwrap();
    store
        .store_ucan_token(ctx, "tok-1", b"token-data")
        .await
        .unwrap();

    // Delete the entire context.
    let deleted = store.delete_context(ctx).await.unwrap();
    assert!(
        deleted >= 7,
        "expected at least 7 keys deleted, got {deleted}"
    );

    // Verify all state is gone.
    assert!(store.load_context_state(ctx).await.unwrap().is_none());
    assert!(store.load_context_params(ctx).await.unwrap().is_none());
    assert!(store.load_membership(ctx, &did).await.unwrap().is_none());
    assert!(store.load_role(ctx, "admin").await.unwrap().is_none());
    assert!(
        store
            .load_outlet(ctx, "outlet-1")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .load_outlet_session(ctx, "sess-1")
            .await
            .unwrap()
            .is_none()
    );
    assert!(store.load_ucan_token(ctx, "tok-1").await.unwrap().is_none());
}

// =========================================================================
// Context module — active context listing
// =========================================================================

#[tokio::test]
async fn list_active_contexts_returns_contexts_with_state() {
    let store = make_store();

    store
        .store_context_state("ctx-alpha", b"state-a")
        .await
        .unwrap();
    store
        .store_context_state("ctx-beta", b"state-b")
        .await
        .unwrap();
    // ctx-gamma has only params, no state — should NOT appear.
    store
        .store_context_params("ctx-gamma", b"params-only")
        .await
        .unwrap();

    let contexts = store.list_active_contexts().await.unwrap();
    assert_eq!(contexts, vec!["ctx-alpha", "ctx-beta"]);
}

// =========================================================================
// Context module — broadcast block list persistence
// =========================================================================

#[tokio::test]
async fn broadcast_block_list_store_load_roundtrip() {
    let store = make_store();
    let ctx = "ctx-broadcast-blocks";
    let author_did = "did:dht:z6MkAuthor";

    let mut block_list = HashSet::new();
    block_list.insert("did:dht:z6MkBlocked1".to_owned());
    block_list.insert("did:dht:z6MkBlocked2".to_owned());

    store
        .store_broadcast_block_list(ctx, author_did, &block_list)
        .await
        .unwrap();

    let loaded = store
        .load_broadcast_block_list(ctx, author_did)
        .await
        .unwrap();
    assert_eq!(loaded, Some(block_list));
}

#[tokio::test]
async fn broadcast_block_list_returns_none_for_missing() {
    let store = make_store();
    let loaded = store
        .load_broadcast_block_list("ctx-missing", "did:dht:z6MkUnknown")
        .await
        .unwrap();
    assert!(loaded.is_none());
}

#[tokio::test]
async fn broadcast_block_list_overwrite() {
    let store = make_store();
    let ctx = "ctx-block-overwrite";
    let author = "did:dht:z6MkAuthor";

    let mut v1 = HashSet::new();
    v1.insert("did:dht:z6MkA".to_owned());
    store
        .store_broadcast_block_list(ctx, author, &v1)
        .await
        .unwrap();

    let mut v2 = HashSet::new();
    v2.insert("did:dht:z6MkA".to_owned());
    v2.insert("did:dht:z6MkB".to_owned());
    store
        .store_broadcast_block_list(ctx, author, &v2)
        .await
        .unwrap();

    let loaded = store.load_broadcast_block_list(ctx, author).await.unwrap();
    assert_eq!(loaded, Some(v2));
}

#[tokio::test]
async fn delete_context_removes_broadcast_block_lists() {
    let store = make_store();
    let ctx = "ctx-block-delete";
    let author = "did:dht:z6MkAuthor";

    let mut block_list = HashSet::new();
    block_list.insert("did:dht:z6MkBlocked".to_owned());
    store
        .store_broadcast_block_list(ctx, author, &block_list)
        .await
        .unwrap();

    store.delete_context(ctx).await.unwrap();

    let loaded = store.load_broadcast_block_list(ctx, author).await.unwrap();
    assert!(loaded.is_none());
}

// =========================================================================
// Context module — broadcast state persistence
// =========================================================================

#[tokio::test]
async fn broadcast_state_store_load_roundtrip() {
    use scp_core::context::broadcast::{
        AuthorStateSnapshot, BroadcastAdmission, BroadcastContextSnapshot, SubscriberRecord,
    };
    use scp_core::crypto::sender_keys::generate_sender_key;
    use std::collections::HashMap;

    let store = make_store();
    let ctx = "ctx-broadcast-state";

    let mut subscribers = HashMap::new();
    subscribers.insert(
        "did:dht:z6MkSub1".to_owned(),
        SubscriberRecord {
            subscriber_did: "did:dht:z6MkSub1".to_owned(),
            registered_at: 1_700_000_000,
            has_ucan: false,
        },
    );

    let mut block_list = HashSet::new();
    block_list.insert("did:dht:z6MkBlocked".to_owned());

    let mut authors = HashMap::new();
    authors.insert(
        "did:dht:z6MkAuthor".to_owned(),
        AuthorStateSnapshot {
            author_did: "did:dht:z6MkAuthor".to_owned(),
            broadcast_key: generate_sender_key(),
            epoch: 5,
            next_sequence: 1,
            block_list,
        },
    );

    let snapshot = BroadcastContextSnapshot {
        context_id: ctx.to_owned(),
        admission: BroadcastAdmission::Open,
        subscribers,
        authors,
    };

    store.store_broadcast_state(ctx, &snapshot).await.unwrap();

    let loaded = store.load_broadcast_state(ctx).await.unwrap();
    assert!(loaded.is_some());
    let loaded = loaded.unwrap();
    assert_eq!(loaded.context_id, ctx);
    assert_eq!(loaded.admission, BroadcastAdmission::Open);
    assert_eq!(loaded.subscribers.len(), 1);
    assert!(loaded.subscribers.contains_key("did:dht:z6MkSub1"));
    assert_eq!(loaded.authors.len(), 1);
    let author = loaded.authors.get("did:dht:z6MkAuthor").unwrap();
    assert_eq!(author.epoch, 5);
    assert!(author.block_list.contains("did:dht:z6MkBlocked"));
}

#[tokio::test]
async fn broadcast_state_returns_none_for_missing() {
    let store = make_store();
    assert!(
        store
            .load_broadcast_state("nonexistent")
            .await
            .unwrap()
            .is_none()
    );
}

// =========================================================================
// Identity module — DID document and signing key
// =========================================================================

#[tokio::test]
async fn identity_document_roundtrip() {
    let store = make_store();
    let did = DID::from("did:dht:z6MkIdentTest");
    let doc = b"mock-did-document-bytes".to_vec();

    store.store_identity_document(&did, &doc).await.unwrap();
    let loaded = store.load_identity_document(&did).await.unwrap();
    assert_eq!(loaded, Some(doc));
}

#[tokio::test]
async fn identity_document_returns_none_for_missing() {
    let store = make_store();
    let did = DID::from("did:dht:z6MkUnknown");
    assert!(store.load_identity_document(&did).await.unwrap().is_none());
}

#[tokio::test]
async fn identity_signing_key_roundtrip() {
    let store = make_store();
    let did = DID::from("did:dht:z6MkIdentKey");
    let key_data = vec![0xAB, 0xCD, 0xEF, 0x01];

    store
        .store_active_signing_key(&did, &key_data)
        .await
        .unwrap();
    let loaded = store.load_active_signing_key(&did).await.unwrap();
    assert_eq!(loaded, Some(key_data));
}

// =========================================================================
// Identity module — private state with sequence ordering
// =========================================================================

#[tokio::test]
async fn identity_private_state_sequence_ordering() {
    let store = make_store();
    let did = DID::from("did:dht:z6MkSeqTest");

    // Store private state at three sequence numbers.
    store
        .store_identity_private_state(&did, 0, b"state-0")
        .await
        .unwrap();
    store
        .store_identity_private_state(&did, 1, b"state-1")
        .await
        .unwrap();
    store
        .store_identity_private_state(&did, 42, b"state-42")
        .await
        .unwrap();

    // Load by specific sequence — each returns its own data.
    assert_eq!(
        store.load_identity_private_state(&did, 0).await.unwrap(),
        Some(b"state-0".to_vec())
    );
    assert_eq!(
        store.load_identity_private_state(&did, 1).await.unwrap(),
        Some(b"state-1".to_vec())
    );
    assert_eq!(
        store.load_identity_private_state(&did, 42).await.unwrap(),
        Some(b"state-42".to_vec())
    );

    // Non-existent sequence returns None.
    assert!(
        store
            .load_identity_private_state(&did, 99)
            .await
            .unwrap()
            .is_none()
    );
}

// =========================================================================
// Identity module — delete cascades
// =========================================================================

#[tokio::test]
async fn delete_identity_removes_all_state() {
    let store = make_store();
    let did = DID::from("did:dht:z6MkDeleteIdent");

    store.store_identity_document(&did, b"doc").await.unwrap();
    store.store_active_signing_key(&did, b"key").await.unwrap();
    store
        .store_identity_private_state(&did, 0, b"state")
        .await
        .unwrap();
    // Also store adapter credentials (economy module, same identity prefix).
    store
        .store_adapter_credentials(&did, "x402", b"cred")
        .await
        .unwrap();

    let deleted = store.delete_identity(&did).await.unwrap();
    assert!(
        deleted >= 4,
        "expected at least 4 keys deleted, got {deleted}"
    );

    assert!(store.load_identity_document(&did).await.unwrap().is_none());
    assert!(store.load_active_signing_key(&did).await.unwrap().is_none());
    assert!(
        store
            .load_identity_private_state(&did, 0)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .load_adapter_credentials(&did, "x402")
            .await
            .unwrap()
            .is_none()
    );
}

// =========================================================================
// UCAN module — nonce replay prevention
// =========================================================================

#[tokio::test]
async fn nonce_replay_rejected_after_check_and_record() {
    let store = make_store();
    let nonce = {
        let mut h = [0u8; 32];
        h[0] = 0xDE;
        h[1] = 0xAD;
        h[31] = 0xFF;
        h
    };

    // First use: accepted.
    let first = store
        .check_and_record_nonce("ctx-nonce", &nonce, 1000, 2000)
        .await
        .unwrap();
    assert!(first, "first nonce use should succeed");

    // Replay: rejected.
    let replay = store
        .check_and_record_nonce("ctx-nonce", &nonce, 1001, 2000)
        .await
        .unwrap();
    assert!(!replay, "nonce replay should be rejected");
}

#[tokio::test]
async fn nonce_is_context_scoped() {
    let store = make_store();
    let nonce = {
        let mut h = [0u8; 32];
        h[0] = 0xAA;
        h
    };

    // Record in context A.
    let first = store
        .check_and_record_nonce("ctx-a", &nonce, 1000, 2000)
        .await
        .unwrap();
    assert!(first);

    // Same nonce in context B: should be accepted (context-scoped).
    let second = store
        .check_and_record_nonce("ctx-b", &nonce, 1000, 2000)
        .await
        .unwrap();
    assert!(second, "nonce should be independent across contexts");
}

// =========================================================================
// UCAN module — prune_expired_nonces
// =========================================================================

#[tokio::test]
async fn prune_expired_nonces_removes_only_expired() {
    let store = make_store();
    let ctx = "ctx-prune";

    // Nonce A: expires at 500.
    let nonce_a = {
        let mut h = [0u8; 32];
        h[0] = 0xAA;
        h
    };
    // Nonce B: expires at 2000.
    let nonce_b = {
        let mut h = [0u8; 32];
        h[0] = 0xBB;
        h
    };
    // Nonce C: expires at 600 (boundary).
    let nonce_c = {
        let mut h = [0u8; 32];
        h[0] = 0xCC;
        h
    };

    store
        .check_and_record_nonce(ctx, &nonce_a, 100, 500)
        .await
        .unwrap();
    store
        .check_and_record_nonce(ctx, &nonce_b, 200, 2000)
        .await
        .unwrap();
    store
        .check_and_record_nonce(ctx, &nonce_c, 300, 600)
        .await
        .unwrap();

    // Prune at now=600: nonces with expiry <= 600 are removed (A and C).
    let pruned = store.prune_expired_nonces(ctx, 600).await.unwrap();
    assert_eq!(pruned, 2, "expected 2 nonces pruned");

    // Nonce A can be re-used (was pruned).
    let reuse_a = store
        .check_and_record_nonce(ctx, &nonce_a, 700, 3000)
        .await
        .unwrap();
    assert!(reuse_a, "pruned nonce should be re-usable");

    // Nonce C can be re-used (was pruned).
    let reuse_c = store
        .check_and_record_nonce(ctx, &nonce_c, 700, 3000)
        .await
        .unwrap();
    assert!(reuse_c, "pruned nonce should be re-usable");

    // Nonce B still rejected (not expired).
    let replay_b = store
        .check_and_record_nonce(ctx, &nonce_b, 700, 3000)
        .await
        .unwrap();
    assert!(!replay_b, "un-pruned nonce should still reject replays");
}

#[tokio::test]
async fn prune_expired_nonces_returns_zero_when_none_expired() {
    let store = make_store();
    let nonce = {
        let mut h = [0u8; 32];
        h[0] = 0xFF;
        h
    };

    store
        .check_and_record_nonce("ctx-noprune", &nonce, 100, 9999)
        .await
        .unwrap();

    let pruned = store
        .prune_expired_nonces("ctx-noprune", 500)
        .await
        .unwrap();
    assert_eq!(pruned, 0);
}

// =========================================================================
// UCAN module — token CRUD
// =========================================================================

#[tokio::test]
async fn ucan_token_store_load_list_delete_roundtrip() {
    let store = make_store();
    let ctx = "ctx-ucan";

    store
        .store_ucan_token(ctx, "tok-1", b"token-body-1")
        .await
        .unwrap();
    store
        .store_ucan_token(ctx, "tok-2", b"token-body-2")
        .await
        .unwrap();

    // Load individual.
    assert_eq!(
        store.load_ucan_token(ctx, "tok-1").await.unwrap(),
        Some(b"token-body-1".to_vec())
    );

    // List.
    let tokens = store.list_ucan_tokens(ctx).await.unwrap();
    assert_eq!(tokens, vec!["tok-1", "tok-2"]);

    // Delete one.
    store.delete_ucan_token(ctx, "tok-1").await.unwrap();
    assert!(store.load_ucan_token(ctx, "tok-1").await.unwrap().is_none());

    // Other still present.
    assert!(store.load_ucan_token(ctx, "tok-2").await.unwrap().is_some());
}

#[tokio::test]
async fn ucan_tokens_are_context_scoped() {
    let store = make_store();

    store
        .store_ucan_token("ctx-x", "tok-shared", b"data-x")
        .await
        .unwrap();
    store
        .store_ucan_token("ctx-y", "tok-shared", b"data-y")
        .await
        .unwrap();

    assert_eq!(
        store.load_ucan_token("ctx-x", "tok-shared").await.unwrap(),
        Some(b"data-x".to_vec())
    );
    assert_eq!(
        store.load_ucan_token("ctx-y", "tok-shared").await.unwrap(),
        Some(b"data-y".to_vec())
    );
}

// =========================================================================
// UCAN module — revocation
// =========================================================================

#[tokio::test]
async fn revocation_roundtrip() {
    let store = make_store();
    let ctx = "ctx-revoke";

    // Not revoked initially.
    assert!(!store.is_revoked(ctx, "tok-abc").await.unwrap());

    // Revoke.
    store.store_revocation(ctx, "tok-abc").await.unwrap();
    assert!(store.is_revoked(ctx, "tok-abc").await.unwrap());

    // Other token not affected.
    assert!(!store.is_revoked(ctx, "tok-other").await.unwrap());
}

#[tokio::test]
async fn revocation_is_context_scoped() {
    let store = make_store();

    store.store_revocation("ctx-1", "tok-xyz").await.unwrap();
    assert!(store.is_revoked("ctx-1", "tok-xyz").await.unwrap());
    assert!(
        !store.is_revoked("ctx-2", "tok-xyz").await.unwrap(),
        "revocation should not leak across contexts"
    );
}

// =========================================================================
// Economy module — adapter credentials
// =========================================================================

#[tokio::test]
async fn adapter_credentials_store_load_list_remove_roundtrip() {
    let store = make_store();
    let did = DID::from("did:dht:z6MkEconUser");

    store
        .store_adapter_credentials(&did, "lightning", b"cred-ln")
        .await
        .unwrap();
    store
        .store_adapter_credentials(&did, "x402", b"cred-x402")
        .await
        .unwrap();

    // Load.
    assert_eq!(
        store
            .load_adapter_credentials(&did, "lightning")
            .await
            .unwrap(),
        Some(b"cred-ln".to_vec())
    );
    assert_eq!(
        store.load_adapter_credentials(&did, "x402").await.unwrap(),
        Some(b"cred-x402".to_vec())
    );

    // List.
    let mut ids = store.list_adapter_credentials(&did).await.unwrap();
    ids.sort();
    assert_eq!(ids, vec!["lightning", "x402"]);

    // Remove.
    store
        .remove_adapter_credentials(&did, "lightning")
        .await
        .unwrap();
    assert!(
        store
            .load_adapter_credentials(&did, "lightning")
            .await
            .unwrap()
            .is_none()
    );

    // Other still present.
    assert!(
        store
            .load_adapter_credentials(&did, "x402")
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn adapter_credentials_isolated_between_identities() {
    let store = make_store();
    let alice = DID::from("did:dht:z6MkAliceEcon");
    let bob = DID::from("did:dht:z6MkBobEcon");

    store
        .store_adapter_credentials(&alice, "x402", b"alice-cred")
        .await
        .unwrap();
    store
        .store_adapter_credentials(&bob, "x402", b"bob-cred")
        .await
        .unwrap();

    assert_eq!(
        store
            .load_adapter_credentials(&alice, "x402")
            .await
            .unwrap(),
        Some(b"alice-cred".to_vec())
    );
    assert_eq!(
        store.load_adapter_credentials(&bob, "x402").await.unwrap(),
        Some(b"bob-cred".to_vec())
    );
}

// =========================================================================
// Outlets module — outlet registration and sessions
// =========================================================================

#[tokio::test]
async fn outlet_store_load_list_delete_roundtrip() {
    let store = make_store();
    let ctx = "ctx-outlets";

    store
        .store_outlet(ctx, "calculator", b"calc-reg")
        .await
        .unwrap();
    store
        .store_outlet(ctx, "search", b"search-reg")
        .await
        .unwrap();

    // Load.
    assert_eq!(
        store.load_outlet(ctx, "calculator").await.unwrap(),
        Some(b"calc-reg".to_vec())
    );

    // List.
    let outlets = store.list_outlets(ctx).await.unwrap();
    assert_eq!(outlets, vec!["calculator", "search"]);

    // Delete.
    store.delete_outlet(ctx, "calculator").await.unwrap();
    assert!(
        store
            .load_outlet(ctx, "calculator")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn outlets_are_context_scoped() {
    let store = make_store();

    store
        .store_outlet("ctx-1", "outlet-abc", b"data-1")
        .await
        .unwrap();
    store
        .store_outlet("ctx-2", "outlet-abc", b"data-2")
        .await
        .unwrap();

    assert_eq!(
        store.load_outlet("ctx-1", "outlet-abc").await.unwrap(),
        Some(b"data-1".to_vec())
    );
    assert_eq!(
        store.load_outlet("ctx-2", "outlet-abc").await.unwrap(),
        Some(b"data-2".to_vec())
    );
}

#[tokio::test]
async fn outlet_session_store_load_delete_roundtrip() {
    let store = make_store();
    let ctx = "ctx-sessions";

    store
        .store_outlet_session(ctx, "sess-1", b"session-state")
        .await
        .unwrap();

    assert_eq!(
        store.load_outlet_session(ctx, "sess-1").await.unwrap(),
        Some(b"session-state".to_vec())
    );

    store.delete_outlet_session(ctx, "sess-1").await.unwrap();
    assert!(
        store
            .load_outlet_session(ctx, "sess-1")
            .await
            .unwrap()
            .is_none()
    );
}

// =========================================================================
// Cross-module — context isolation between modules
// =========================================================================

#[tokio::test]
async fn context_isolation_between_modules() {
    let store = make_store();

    // Store data in different modules for different contexts.
    store
        .store_context_state("ctx-1", b"state-1")
        .await
        .unwrap();
    store
        .store_outlet("ctx-2", "outlet-1", b"outlet-data")
        .await
        .unwrap();
    store
        .store_ucan_token("ctx-3", "tok-1", b"token-data")
        .await
        .unwrap();

    // Each context only has its own data.
    assert!(
        store
            .load_outlet("ctx-1", "outlet-1")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .load_ucan_token("ctx-1", "tok-1")
            .await
            .unwrap()
            .is_none()
    );
    assert!(store.load_context_state("ctx-2").await.unwrap().is_none());
    assert!(
        store
            .load_ucan_token("ctx-2", "tok-1")
            .await
            .unwrap()
            .is_none()
    );
    assert!(store.load_context_state("ctx-3").await.unwrap().is_none());
    assert!(
        store
            .load_outlet("ctx-3", "outlet-1")
            .await
            .unwrap()
            .is_none()
    );
}

// =========================================================================
// Cross-module — identity vs context namespace isolation
// =========================================================================

#[tokio::test]
async fn identity_and_context_namespaces_are_isolated() {
    let store = make_store();
    let did = DID::from("did:dht:z6MkIsolation");

    // Store identity data.
    store
        .store_identity_document(&did, b"id-doc")
        .await
        .unwrap();

    // Store context data using a context ID.
    store
        .store_context_state("ctx-iso", b"ctx-state")
        .await
        .unwrap();

    // Deleting the context should not affect identity.
    store.delete_context("ctx-iso").await.unwrap();
    assert_eq!(
        store.load_identity_document(&did).await.unwrap(),
        Some(b"id-doc".to_vec())
    );

    // Deleting the identity should not affect contexts.
    store
        .store_context_state("ctx-iso-2", b"ctx-state-2")
        .await
        .unwrap();
    store.delete_identity(&did).await.unwrap();
    assert_eq!(
        store.load_context_state("ctx-iso-2").await.unwrap(),
        Some(b"ctx-state-2".to_vec())
    );
}

// =========================================================================
// Event Log module — append, load, range, Merkle root & tree nodes
// =========================================================================

#[tokio::test]
async fn event_log_append_load_roundtrip() {
    let store = make_store();
    let hash: [u8; 32] = [0xAA; 32];
    store.append_event("ctx-el", 0, &hash).await.unwrap();

    let loaded = store.load_event("ctx-el", 0).await.unwrap();
    assert_eq!(loaded, Some(hash.to_vec()));

    let count = store.event_count("ctx-el").await.unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn event_log_load_event_range_returns_ordered_subset() {
    let store = make_store();
    for seq in 0u64..5 {
        #[allow(clippy::cast_possible_truncation)]
        let hash = [seq as u8; 32];
        store.append_event("ctx-range", seq, &hash).await.unwrap();
    }

    // Range is [start, end) — so (1, 4) returns events 1, 2, 3.
    let range = store.load_event_range("ctx-range", 1, 4).await.unwrap();
    assert_eq!(range.len(), 3);
    assert_eq!(range[0], [1u8; 32].to_vec());
    assert_eq!(range[1], [2u8; 32].to_vec());
    assert_eq!(range[2], [3u8; 32].to_vec());
}

#[tokio::test]
async fn event_log_missing_sequence_returns_none() {
    let store = make_store();
    let loaded = store.load_event("ctx-miss", 999).await.unwrap();
    assert!(loaded.is_none());
}

#[tokio::test]
async fn event_log_merkle_root_roundtrip() {
    let store = make_store();
    let root: [u8; 32] = [0xBB; 32];
    store.store_event_root("ctx-root", &root).await.unwrap();

    let loaded = store.load_event_root("ctx-root").await.unwrap();
    assert_eq!(loaded, Some(root));
}

#[tokio::test]
async fn event_log_merkle_tree_node_roundtrip() {
    let store = make_store();
    let hash: [u8; 32] = [0xCC; 32];
    store
        .store_event_tree_node("ctx-tree", 2, 5, &hash)
        .await
        .unwrap();

    let loaded = store.load_event_tree_node("ctx-tree", 2, 5).await.unwrap();
    assert_eq!(loaded, Some(hash));

    // Different level/index returns None.
    assert!(
        store
            .load_event_tree_node("ctx-tree", 3, 5)
            .await
            .unwrap()
            .is_none()
    );
}

// =========================================================================
// Sender Keys module — store, load, list, remove
// =========================================================================

#[tokio::test]
async fn sender_key_store_load_roundtrip() {
    let store = make_store();
    let did = DID::from("did:dht:z6MkSenderKey1");
    let key_data = b"sender-key-bytes-32";

    store
        .store_sender_key("ctx-sk", &did, key_data)
        .await
        .unwrap();
    let loaded = store.load_sender_key("ctx-sk", &did).await.unwrap();
    assert_eq!(loaded, Some(key_data.to_vec()));
}

#[tokio::test]
async fn sender_key_list_returns_all_pairs() {
    let store = make_store();
    let did1 = DID::from("did:dht:z6MkSK-a");
    let did2 = DID::from("did:dht:z6MkSK-b");

    store
        .store_sender_key("ctx-skl", &did1, b"key-a")
        .await
        .unwrap();
    store
        .store_sender_key("ctx-skl", &did2, b"key-b")
        .await
        .unwrap();

    let list = store.list_sender_keys("ctx-skl").await.unwrap();
    assert_eq!(list.len(), 2);

    let listed: HashSet<String> = list.iter().map(|(d, _)| d.to_string()).collect();
    assert!(listed.contains(&did1.to_string()));
    assert!(listed.contains(&did2.to_string()));
}

#[tokio::test]
async fn sender_key_remove_deletes_entry() {
    let store = make_store();
    let did = DID::from("did:dht:z6MkSKRemove");

    store
        .store_sender_key("ctx-skr", &did, b"remove-me")
        .await
        .unwrap();
    store.remove_sender_key("ctx-skr", &did).await.unwrap();

    assert!(
        store
            .load_sender_key("ctx-skr", &did)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn sender_key_context_isolation() {
    let store = make_store();
    let did = DID::from("did:dht:z6MkSKIso");

    store
        .store_sender_key("ctx-sk-a", &did, b"key-a")
        .await
        .unwrap();
    store
        .store_sender_key("ctx-sk-b", &did, b"key-b")
        .await
        .unwrap();

    // Different contexts, same DID — keys are independent.
    assert_eq!(
        store.load_sender_key("ctx-sk-a", &did).await.unwrap(),
        Some(b"key-a".to_vec())
    );
    assert_eq!(
        store.load_sender_key("ctx-sk-b", &did).await.unwrap(),
        Some(b"key-b".to_vec())
    );
}

// =========================================================================
// DID Cache — cache with expiry; TOFU record roundtrip
// =========================================================================

#[tokio::test]
async fn did_cache_roundtrip_and_expiry() {
    let store = make_store();
    let did = DID::from("did:dht:z6MkCacheDID");

    store
        .cache_did_document(&did, b"doc-bytes", 1000)
        .await
        .unwrap();

    // Before expiry — returns document.
    let loaded = store.load_cached_did_document(&did, 500).await.unwrap();
    assert_eq!(loaded, Some(b"doc-bytes".to_vec()));

    // At expiry — returns None.
    let expired = store.load_cached_did_document(&did, 1000).await.unwrap();
    assert!(expired.is_none());

    // After expiry — returns None.
    let expired = store.load_cached_did_document(&did, 2000).await.unwrap();
    assert!(expired.is_none());
}

#[tokio::test]
async fn did_cache_overwrite_with_later_expiry() {
    let store = make_store();
    let did = DID::from("did:dht:z6MkCacheOver");

    store.cache_did_document(&did, b"v1", 100).await.unwrap();
    store.cache_did_document(&did, b"v2", 200).await.unwrap();

    // Old expiry passed, but new expiry not yet — should return v2.
    let loaded = store.load_cached_did_document(&did, 150).await.unwrap();
    assert_eq!(loaded, Some(b"v2".to_vec()));
}

#[tokio::test]
async fn tofu_record_roundtrip() {
    let store = make_store();
    let did = DID::from("did:dht:z6MkTOFU");

    store
        .store_tofu_record(&did, b"first-seen-data")
        .await
        .unwrap();
    let loaded = store.load_tofu_record(&did).await.unwrap();
    assert_eq!(loaded, Some(b"first-seen-data".to_vec()));
}

#[tokio::test]
async fn tofu_record_missing_returns_none() {
    let store = make_store();
    let did = DID::from("did:dht:z6MkTOFUMissing");
    assert!(store.load_tofu_record(&did).await.unwrap().is_none());
}

// =========================================================================
// Transport module — relay score store/load/list
// =========================================================================

#[tokio::test]
async fn relay_score_store_load_roundtrip() {
    let store = make_store();
    store
        .store_relay_score("wss://relay1.example.com", b"score-data")
        .await
        .unwrap();

    let loaded = store
        .load_relay_score("wss://relay1.example.com")
        .await
        .unwrap();
    assert_eq!(loaded, Some(b"score-data".to_vec()));
}

#[tokio::test]
async fn relay_score_list_returns_all_stored() {
    let store = make_store();
    store
        .store_relay_score("wss://relay-a.example.com", b"score-a")
        .await
        .unwrap();
    store
        .store_relay_score("wss://relay-b.example.com", b"score-b")
        .await
        .unwrap();

    let list = store.list_relay_scores().await.unwrap();
    assert_eq!(list.len(), 2);

    let urls: HashSet<String> = list.iter().map(|e| e.url.clone()).collect();
    assert!(urls.contains("wss://relay-a.example.com"));
    assert!(urls.contains("wss://relay-b.example.com"));
}

#[tokio::test]
async fn relay_score_missing_returns_none() {
    let store = make_store();
    assert!(
        store
            .load_relay_score("wss://nonexistent.example.com")
            .await
            .unwrap()
            .is_none()
    );
}

// =========================================================================
// MLS module — group state roundtrip via MlsStorageBridge; context isolation
// =========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mls_bridge_group_state_roundtrip() {
    use openmls::group::{GroupId as MlsGroupId, MlsGroupState};
    use openmls_traits::storage::StorageProvider;

    let store = Arc::new(make_store());
    let bridge = MlsStorageBridge::new(store, "ctx-mls-rt".to_owned()).unwrap();

    let group_id = MlsGroupId::from_slice(b"test-group-rt");

    StorageProvider::write_group_state(&bridge, &group_id, &MlsGroupState::Operational).unwrap();

    let loaded: Option<MlsGroupState> = StorageProvider::group_state(&bridge, &group_id).unwrap();
    assert!(loaded.is_some(), "group state should be loaded");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mls_bridge_context_isolation() {
    use openmls::group::{GroupId as MlsGroupId, MlsGroupState};
    use openmls_traits::storage::StorageProvider;

    let store = Arc::new(make_store());

    let bridge_a = MlsStorageBridge::new(Arc::clone(&store), "ctx-mls-a".to_owned()).unwrap();
    let bridge_b = MlsStorageBridge::new(Arc::clone(&store), "ctx-mls-b".to_owned()).unwrap();

    let group_id = MlsGroupId::from_slice(b"shared-group-id");

    StorageProvider::write_group_state(&bridge_a, &group_id, &MlsGroupState::Operational).unwrap();
    StorageProvider::write_group_state(&bridge_b, &group_id, &MlsGroupState::Inactive).unwrap();

    // Same group_id, different contexts — values are independent.
    let a: Option<MlsGroupState> = StorageProvider::group_state(&bridge_a, &group_id).unwrap();
    let b: Option<MlsGroupState> = StorageProvider::group_state(&bridge_b, &group_id).unwrap();
    assert!(a.is_some(), "bridge_a state should exist");
    assert!(b.is_some(), "bridge_b state should exist");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mls_bridge_survives_restart() {
    use openmls::group::{GroupId as MlsGroupId, MlsGroupState};
    use openmls_traits::storage::StorageProvider;

    let store = Arc::new(make_store());
    let group_id = MlsGroupId::from_slice(b"restart-group");

    // Write via one bridge instance.
    {
        let bridge =
            MlsStorageBridge::new(Arc::clone(&store), "ctx-mls-restart".to_owned()).unwrap();
        StorageProvider::write_group_state(&bridge, &group_id, &MlsGroupState::Operational)
            .unwrap();
    }

    // Read via a fresh bridge instance backed by the same store.
    let bridge2 = MlsStorageBridge::new(store, "ctx-mls-restart".to_owned()).unwrap();
    let loaded: Option<MlsGroupState> = StorageProvider::group_state(&bridge2, &group_id).unwrap();
    assert!(loaded.is_some(), "state should survive bridge recreation");
}
