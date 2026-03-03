//! `ProtocolStore` module integration tests (SCP-PERSIST-072).
//!
//! Tests each `ProtocolStore` domain module through the full
//! `ProtocolStore -> Storage -> Backend` path using `InMemoryStorage`.
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
//!
//! See spec sections 17.3 and 17.4.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashSet;

use scp_core::store::ProtocolStore;
use scp_identity::DID;
use scp_platform::testing::InMemoryStorage;

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

/// Creates a fresh `ProtocolStore<InMemoryStorage>` for each test.
fn make_store() -> ProtocolStore<InMemoryStorage> {
    ProtocolStore::new(InMemoryStorage::new())
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
    store
        .store_membership(ctx, &alice, "admin")
        .await
        .unwrap();
    store
        .store_membership(ctx, &bob, "member")
        .await
        .unwrap();

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

    store
        .store_role(ctx, "admin", b"admin-caps")
        .await
        .unwrap();
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

    // Populate context with state, params, membership, role, tool, session.
    store
        .store_context_state(ctx, b"state")
        .await
        .unwrap();
    store
        .store_context_params(ctx, b"params")
        .await
        .unwrap();
    store
        .store_membership(ctx, &did, "member")
        .await
        .unwrap();
    store
        .store_role(ctx, "admin", b"role-data")
        .await
        .unwrap();
    store
        .store_tool(ctx, "tool-1", b"tool-reg")
        .await
        .unwrap();
    store
        .store_tool_session(ctx, "sess-1", b"sess-data")
        .await
        .unwrap();
    store
        .store_ucan_token(ctx, "tok-1", b"token-data")
        .await
        .unwrap();

    // Delete the entire context.
    let deleted = store.delete_context(ctx).await.unwrap();
    assert!(deleted >= 7, "expected at least 7 keys deleted, got {deleted}");

    // Verify all state is gone.
    assert!(store.load_context_state(ctx).await.unwrap().is_none());
    assert!(store.load_context_params(ctx).await.unwrap().is_none());
    assert!(store.load_membership(ctx, &did).await.unwrap().is_none());
    assert!(store.load_role(ctx, "admin").await.unwrap().is_none());
    assert!(store.load_tool(ctx, "tool-1").await.unwrap().is_none());
    assert!(
        store
            .load_tool_session(ctx, "sess-1")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .load_ucan_token(ctx, "tok-1")
            .await
            .unwrap()
            .is_none()
    );
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

    let loaded = store
        .load_broadcast_block_list(ctx, author)
        .await
        .unwrap();
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

    let loaded = store
        .load_broadcast_block_list(ctx, author)
        .await
        .unwrap();
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
    assert!(
        store
            .load_identity_document(&did)
            .await
            .unwrap()
            .is_none()
    );
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
        store
            .load_identity_private_state(&did, 0)
            .await
            .unwrap(),
        Some(b"state-0".to_vec())
    );
    assert_eq!(
        store
            .load_identity_private_state(&did, 1)
            .await
            .unwrap(),
        Some(b"state-1".to_vec())
    );
    assert_eq!(
        store
            .load_identity_private_state(&did, 42)
            .await
            .unwrap(),
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

    store
        .store_identity_document(&did, b"doc")
        .await
        .unwrap();
    store
        .store_active_signing_key(&did, b"key")
        .await
        .unwrap();
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

    assert!(
        store
            .load_identity_document(&did)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .load_active_signing_key(&did)
            .await
            .unwrap()
            .is_none()
    );
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
    assert!(
        store
            .load_ucan_token(ctx, "tok-2")
            .await
            .unwrap()
            .is_some()
    );
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
        store
            .load_adapter_credentials(&did, "x402")
            .await
            .unwrap(),
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
        store
            .load_adapter_credentials(&bob, "x402")
            .await
            .unwrap(),
        Some(b"bob-cred".to_vec())
    );
}

// =========================================================================
// Tools module — tool registration and sessions
// =========================================================================

#[tokio::test]
async fn tool_store_load_list_delete_roundtrip() {
    let store = make_store();
    let ctx = "ctx-tools";

    store
        .store_tool(ctx, "calculator", b"calc-reg")
        .await
        .unwrap();
    store
        .store_tool(ctx, "search", b"search-reg")
        .await
        .unwrap();

    // Load.
    assert_eq!(
        store.load_tool(ctx, "calculator").await.unwrap(),
        Some(b"calc-reg".to_vec())
    );

    // List.
    let tools = store.list_tools(ctx).await.unwrap();
    assert_eq!(tools, vec!["calculator", "search"]);

    // Delete.
    store.delete_tool(ctx, "calculator").await.unwrap();
    assert!(store.load_tool(ctx, "calculator").await.unwrap().is_none());
}

#[tokio::test]
async fn tools_are_context_scoped() {
    let store = make_store();

    store
        .store_tool("ctx-1", "tool-abc", b"data-1")
        .await
        .unwrap();
    store
        .store_tool("ctx-2", "tool-abc", b"data-2")
        .await
        .unwrap();

    assert_eq!(
        store.load_tool("ctx-1", "tool-abc").await.unwrap(),
        Some(b"data-1".to_vec())
    );
    assert_eq!(
        store.load_tool("ctx-2", "tool-abc").await.unwrap(),
        Some(b"data-2".to_vec())
    );
}

#[tokio::test]
async fn tool_session_store_load_delete_roundtrip() {
    let store = make_store();
    let ctx = "ctx-sessions";

    store
        .store_tool_session(ctx, "sess-1", b"session-state")
        .await
        .unwrap();

    assert_eq!(
        store.load_tool_session(ctx, "sess-1").await.unwrap(),
        Some(b"session-state".to_vec())
    );

    store.delete_tool_session(ctx, "sess-1").await.unwrap();
    assert!(
        store
            .load_tool_session(ctx, "sess-1")
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
        .store_tool("ctx-2", "tool-1", b"tool-data")
        .await
        .unwrap();
    store
        .store_ucan_token("ctx-3", "tok-1", b"token-data")
        .await
        .unwrap();

    // Each context only has its own data.
    assert!(store.load_tool("ctx-1", "tool-1").await.unwrap().is_none());
    assert!(
        store
            .load_ucan_token("ctx-1", "tok-1")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .load_context_state("ctx-2")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .load_ucan_token("ctx-2", "tok-1")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .load_context_state("ctx-3")
            .await
            .unwrap()
            .is_none()
    );
    assert!(store.load_tool("ctx-3", "tool-1").await.unwrap().is_none());
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
