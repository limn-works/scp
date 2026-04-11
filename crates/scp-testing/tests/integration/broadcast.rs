#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! B5: Broadcast context integration tests.
//!
//! Exercises `BroadcastContext` creation, subscriber registration (open + gated),
//! `AuthorState`, seal/open roundtrip, blocking, key request handling,
//! unsubscribe, snapshot serialization, and `BroadcastKeyEpochAdvance`.

use std::hash::RandomState;

use ed25519_dalek::Signer;
use scp_core::context::broadcast::SubscriptionResult;
use scp_core::context::{
    AuthorState, BroadcastAdmission, BroadcastContext, BroadcastContextSnapshot, ContextError,
    ContextMode, KeyRequestDecision,
};
use scp_core::crypto::sender_keys::{
    BroadcastKeyEpochAdvance, SealBroadcastParams, SigningPayloadFields,
    build_broadcast_signing_payload, compute_provenance_hash, generate_broadcast_key,
    generate_broadcast_nonce, open_broadcast_trusted, rotate_broadcast_key, seal_broadcast,
};
use scp_core::crypto::ucan::UcanError;
use scp_core::crypto::ucan::validate::{
    InMemoryDidResolver, InMemoryProofResolver, InMemoryRevocationChecker, NonceTracker,
};

// ---------------------------------------------------------------------------
// Stub NonceTracker for integration tests (the in-memory one is cfg(test))
// ---------------------------------------------------------------------------

struct StubNonceTracker;

impl NonceTracker for StubNonceTracker {
    fn check_replay(&self, _nonce: &str, _token_expiry: u64) -> Result<(), UcanError> {
        Ok(())
    }

    fn record(&mut self, _nonce: &str, _token_expiry: u64) -> Result<(), UcanError> {
        Ok(())
    }
}

/// Helper to subscribe on open contexts without a validation context.
fn subscribe_open(
    ctx: &mut BroadcastContext,
    subscriber_did: &str,
    timestamp: u64,
) -> Result<SubscriptionResult, ContextError> {
    ctx.subscribe::<
        InMemoryDidResolver,
        StubNonceTracker,
        InMemoryRevocationChecker,
        InMemoryProofResolver,
        RandomState,
    >(subscriber_did, None, timestamp, None)
}

// ---------------------------------------------------------------------------
// 1. broadcast_context_creation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn broadcast_context_creation() {
    let ctx = BroadcastContext::new(
        "ctx-broadcast-001".to_owned(),
        &ContextMode::Broadcast,
        BroadcastAdmission::Open,
    );
    assert!(ctx.is_ok());

    let ctx = ctx.unwrap();
    assert_eq!(ctx.context_id(), "ctx-broadcast-001");
    assert_eq!(ctx.admission(), BroadcastAdmission::Open);
    assert_eq!(ctx.subscriber_count(), 0);
}

// ---------------------------------------------------------------------------
// 2. broadcast_context_encrypted_mode_fails
// ---------------------------------------------------------------------------

#[tokio::test]
async fn broadcast_context_encrypted_mode_fails() {
    let result = BroadcastContext::new(
        "ctx-encrypted".to_owned(),
        &ContextMode::Encrypted,
        BroadcastAdmission::Open,
    );
    assert!(result.is_err());
    assert!(
        matches!(
            result.unwrap_err(),
            ContextError::InvalidMemoryScopeForBroadcast
        ),
        "creating BroadcastContext with Encrypted mode should fail"
    );
}

// ---------------------------------------------------------------------------
// 3. open_subscribe_without_ucan
// ---------------------------------------------------------------------------

#[tokio::test]
async fn open_subscribe_without_ucan() {
    let mut ctx = BroadcastContext::new(
        "ctx-open-sub".to_owned(),
        &ContextMode::Broadcast,
        BroadcastAdmission::Open,
    )
    .unwrap();

    // Add an author so author_epochs is populated
    ctx.add_author("did:key:author1").unwrap();

    let result = subscribe_open(&mut ctx, "did:key:subscriber1", 1_700_000_000);
    assert!(result.is_ok());

    let sub_result = result.unwrap();
    assert!(sub_result.author_epochs.contains_key("did:key:author1"));
    assert_eq!(ctx.subscriber_count(), 1);
    assert!(ctx.is_subscriber("did:key:subscriber1"));
}

// ---------------------------------------------------------------------------
// 4. gated_subscribe_without_ucan_fails
// ---------------------------------------------------------------------------

#[tokio::test]
async fn gated_subscribe_without_ucan_fails() {
    let mut ctx = BroadcastContext::new(
        "ctx-gated-sub".to_owned(),
        &ContextMode::Broadcast,
        BroadcastAdmission::Gated,
    )
    .unwrap();

    // Subscribing to a gated context without UCAN should fail
    let result = subscribe_open(&mut ctx, "did:key:subscriber1", 1_700_000_000);
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), ContextError::PermissionDenied(_)),
        "gated subscribe without UCAN should be PermissionDenied"
    );
    assert_eq!(ctx.subscriber_count(), 0);
}

// ---------------------------------------------------------------------------
// 5. per_author_broadcast_key
// ---------------------------------------------------------------------------

#[tokio::test]
async fn per_author_broadcast_key() {
    let author = AuthorState::new("did:key:author-test".to_owned());
    assert_eq!(author.author_did, "did:key:author-test");
    assert_eq!(author.epoch, 0);
    assert_eq!(author.next_sequence, 1);
    assert!(author.block_list.is_empty());

    // The broadcast key should be 32 bytes of non-zero randomness
    let key_bytes = author.broadcast_key.as_bytes();
    assert_eq!(key_bytes.len(), 32);
    // Extremely unlikely all zero
    assert!(key_bytes.iter().any(|b| *b != 0));
}

// ---------------------------------------------------------------------------
// 6. seal_open_roundtrip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn seal_open_roundtrip() {
    let author_did = "did:key:author-roundtrip";
    let bk = generate_broadcast_key(author_did);
    let payload = b"Hello, broadcast world!";
    let nonce = generate_broadcast_nonce();

    let provenance_hash = compute_provenance_hash(None).unwrap();
    let signing_payload = build_broadcast_signing_payload(&SigningPayloadFields {
        version: scp_core::envelope::SCP_PROTOCOL_VERSION,
        context_id: "ctx-roundtrip",
        author_did,
        sequence: 1,
        key_epoch: 0,
        timestamp: 1_700_000_000_000,
        nonce: &nonce,
        provenance_hash: &provenance_hash,
    });

    // Sign with a test key
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0xBB; 32]);
    let signature = signing_key.sign(&signing_payload);

    let params = SealBroadcastParams {
        context_id: "ctx-roundtrip",
        sequence: 1,
        timestamp: 1_700_000_000_000,
        provenance: None,
        signature,
    };

    let envelope = seal_broadcast(&bk, payload, &nonce, &params).unwrap();
    assert_eq!(envelope.context_id, "ctx-roundtrip");
    assert_eq!(envelope.author_did, author_did);
    assert_eq!(envelope.sequence, 1);
    assert_eq!(envelope.key_epoch, 0);

    // Decrypt (trusted path -- no signature re-verification)
    let decrypted = open_broadcast_trusted(&bk, &envelope).unwrap();
    assert_eq!(decrypted, payload);
}

// ---------------------------------------------------------------------------
// 7. open_with_wrong_key_fails
// ---------------------------------------------------------------------------

#[tokio::test]
async fn open_with_wrong_key_fails() {
    let author_did = "did:key:author-wrong-key";
    let bk = generate_broadcast_key(author_did);
    let wrong_bk = generate_broadcast_key(author_did); // different random key
    let payload = b"secret data";
    let nonce = generate_broadcast_nonce();

    let provenance_hash = compute_provenance_hash(None).unwrap();
    let signing_payload = build_broadcast_signing_payload(&SigningPayloadFields {
        version: scp_core::envelope::SCP_PROTOCOL_VERSION,
        context_id: "ctx-wrong-key",
        author_did,
        sequence: 1,
        key_epoch: 0,
        timestamp: 1_700_000_000_000,
        nonce: &nonce,
        provenance_hash: &provenance_hash,
    });

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0xCC; 32]);
    let signature = signing_key.sign(&signing_payload);

    let params = SealBroadcastParams {
        context_id: "ctx-wrong-key",
        sequence: 1,
        timestamp: 1_700_000_000_000,
        provenance: None,
        signature,
    };

    let envelope = seal_broadcast(&bk, payload, &nonce, &params).unwrap();

    // Try to decrypt with a different key -- should fail
    let result = open_broadcast_trusted(&wrong_bk, &envelope);
    assert!(result.is_err(), "decrypting with wrong key should fail");
}

// ---------------------------------------------------------------------------
// 8. block_subscriber_rotates_key
// ---------------------------------------------------------------------------

#[tokio::test]
async fn block_subscriber_rotates_key() {
    let mut ctx = BroadcastContext::new(
        "ctx-block-sub".to_owned(),
        &ContextMode::Broadcast,
        BroadcastAdmission::Open,
    )
    .unwrap();

    ctx.add_author("did:key:author1").unwrap();
    subscribe_open(&mut ctx, "did:key:subscriber1", 1000).unwrap();

    // Verify the author starts at epoch 0
    let author_before = ctx.get_author("did:key:author1").unwrap();
    assert_eq!(author_before.epoch, 0);

    // Block subscriber
    let block_result = ctx
        .block_subscriber("did:key:author1", "did:key:subscriber1")
        .unwrap();
    assert_eq!(block_result.new_epoch, 1);
    assert!(block_result.block_list.contains("did:key:subscriber1"));
    assert_eq!(block_result.author_did, "did:key:author1");

    // The author's epoch should now be 1
    let author_after = ctx.get_author("did:key:author1").unwrap();
    assert_eq!(author_after.epoch, 1);
    assert!(author_after.block_list.contains("did:key:subscriber1"));

    // The subscriber is still in the roster (per-author blocking only)
    assert!(ctx.is_subscriber("did:key:subscriber1"));
}

// ---------------------------------------------------------------------------
// 9. handle_key_request_non_blocked
// ---------------------------------------------------------------------------

#[tokio::test]
async fn handle_key_request_non_blocked() {
    let mut ctx = BroadcastContext::new(
        "ctx-key-req".to_owned(),
        &ContextMode::Broadcast,
        BroadcastAdmission::Open,
    )
    .unwrap();

    ctx.add_author("did:key:author1").unwrap();
    subscribe_open(&mut ctx, "did:key:subscriber1", 1000).unwrap();

    let decision = ctx.handle_key_request("did:key:author1", "did:key:subscriber1");
    match decision {
        KeyRequestDecision::Grant { key_bytes, epoch } => {
            assert_eq!(epoch, 0);
            assert_eq!(key_bytes.len(), 32);
        }
        KeyRequestDecision::Deny { reason } => {
            panic!("expected Grant, got Deny: {reason}");
        }
    }
}

// ---------------------------------------------------------------------------
// 10. handle_key_request_blocked
// ---------------------------------------------------------------------------

#[tokio::test]
async fn handle_key_request_blocked() {
    let mut ctx = BroadcastContext::new(
        "ctx-key-req-blocked".to_owned(),
        &ContextMode::Broadcast,
        BroadcastAdmission::Open,
    )
    .unwrap();

    ctx.add_author("did:key:author1").unwrap();
    subscribe_open(&mut ctx, "did:key:subscriber1", 1000).unwrap();

    // Block the subscriber
    ctx.block_subscriber("did:key:author1", "did:key:subscriber1")
        .unwrap();

    let decision = ctx.handle_key_request("did:key:author1", "did:key:subscriber1");
    match decision {
        KeyRequestDecision::Deny { reason } => {
            assert!(!reason.is_empty(), "deny reason should not be empty");
        }
        KeyRequestDecision::Grant { .. } => {
            panic!("expected Deny for blocked subscriber, got Grant");
        }
    }
}

// ---------------------------------------------------------------------------
// 11. unsubscribe
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unsubscribe() {
    let mut ctx = BroadcastContext::new(
        "ctx-unsub".to_owned(),
        &ContextMode::Broadcast,
        BroadcastAdmission::Open,
    )
    .unwrap();

    ctx.add_author("did:key:author1").unwrap();
    subscribe_open(&mut ctx, "did:key:subscriber1", 1000).unwrap();
    assert!(ctx.is_subscriber("did:key:subscriber1"));

    let result = ctx.unsubscribe("did:key:subscriber1", false).unwrap();
    assert_eq!(result.subscriber_did, "did:key:subscriber1");
    assert!(result.key_rotations.is_empty()); // rotate_keys = false
    assert!(!ctx.is_subscriber("did:key:subscriber1"));
    assert_eq!(ctx.subscriber_count(), 0);
}

// ---------------------------------------------------------------------------
// 12. broadcast_context_snapshot_roundtrip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn broadcast_context_snapshot_roundtrip() {
    let mut ctx = BroadcastContext::new(
        "ctx-snapshot".to_owned(),
        &ContextMode::Broadcast,
        BroadcastAdmission::Open,
    )
    .unwrap();

    ctx.add_author("did:key:author1").unwrap();
    subscribe_open(&mut ctx, "did:key:sub1", 1000).unwrap();
    subscribe_open(&mut ctx, "did:key:sub2", 2000).unwrap();

    // Block one subscriber from one author
    ctx.block_subscriber("did:key:author1", "did:key:sub1")
        .unwrap();

    // Take snapshot
    let snapshot = ctx.to_snapshot();
    assert_eq!(snapshot.context_id, "ctx-snapshot");
    assert_eq!(snapshot.admission, BroadcastAdmission::Open);
    assert_eq!(snapshot.subscribers.len(), 2);
    assert_eq!(snapshot.authors.len(), 1);

    // Serialize and deserialize via MessagePack
    let bytes = rmp_serde::to_vec(&snapshot).unwrap();
    let deserialized: BroadcastContextSnapshot = rmp_serde::from_slice(&bytes).unwrap();

    assert_eq!(deserialized.context_id, "ctx-snapshot");
    assert_eq!(deserialized.admission, BroadcastAdmission::Open);
    assert_eq!(deserialized.subscribers.len(), 2);
    assert_eq!(deserialized.authors.len(), 1);

    // Reconstruct context from snapshot
    let restored = BroadcastContext::from_snapshot(deserialized);
    assert_eq!(restored.context_id(), "ctx-snapshot");
    assert_eq!(restored.subscriber_count(), 2);
    assert!(restored.is_subscriber("did:key:sub1"));
    assert!(restored.is_subscriber("did:key:sub2"));
    assert!(restored.is_blocked("did:key:author1", "did:key:sub1"));
    assert!(!restored.is_blocked("did:key:author1", "did:key:sub2"));
}

// ---------------------------------------------------------------------------
// 13. broadcast_key_epoch_advance
// ---------------------------------------------------------------------------

#[tokio::test]
async fn broadcast_key_epoch_advance() {
    let author_did = "did:key:author-epoch";
    let bk = generate_broadcast_key(author_did);
    assert_eq!(bk.epoch(), 0);
    assert_eq!(bk.author_did(), author_did);

    // Rotate the key
    let (new_bk, advance) = rotate_broadcast_key(&bk, 1_700_000_000_000).unwrap();
    assert_eq!(new_bk.epoch(), 1);
    assert_eq!(new_bk.author_did(), author_did);

    // Verify the epoch advance event
    assert_eq!(advance.author_did, author_did);
    assert_eq!(advance.new_epoch, 1);
    assert_eq!(advance.timestamp, 1_700_000_000_000);

    // Verify BroadcastKeyEpochAdvance can be constructed directly
    let manual_advance = BroadcastKeyEpochAdvance {
        author_did: "did:key:manual".to_owned(),
        new_epoch: 5,
        timestamp: 1_800_000_000_000,
    };
    assert_eq!(manual_advance.new_epoch, 5);

    // Second rotation
    let (bk2, advance2) = rotate_broadcast_key(&new_bk, 1_700_000_001_000).unwrap();
    assert_eq!(bk2.epoch(), 2);
    assert_eq!(advance2.new_epoch, 2);
}
