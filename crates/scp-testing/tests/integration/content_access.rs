#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! B16: Content access control integration tests.
//!
//! Tests access key generation, CEK wrap/unwrap, content wrap/unwrap with AAD,
//! `ContentAccessState` forward-only transitions, `BlockListState` from events,
//! `BlockListEvent` variants, broadcast block key request denial, and sender key
//! rotation on block.
//!
//! Exercises public APIs from `scp_core::crypto::access_keys` (wrapping module),
//! `scp_core::crypto::access_keys` (mod — generation, `ContentAccessState`),
//! `scp_core::identity::block_list`, and `scp_core::context::broadcast`.

use std::hash::RandomState;

use scp_core::context::broadcast::{BroadcastAdmission, KeyRequestDecision};
use scp_core::context::{BroadcastContext, ContextMode};
use scp_core::crypto::access_keys::wrapping::{unwrap_cek, unwrap_content, wrap_cek, wrap_content};
use scp_core::crypto::access_keys::{
    ContentAccessState, ContentEncryptionKey, generate_access_key,
};
use scp_core::crypto::ucan::UcanError;
use scp_core::crypto::ucan::validate::{
    InMemoryDidResolver, InMemoryProofResolver, InMemoryRevocationChecker, NonceTracker,
};
use scp_core::identity::block_list::{BlockListEvent, BlockListState};
use scp_identity::DID;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn did(s: &str) -> DID {
    DID::from(s)
}

struct StubNonceTracker;

impl NonceTracker for StubNonceTracker {
    fn check_replay(&self, _nonce: &str, _token_expiry: u64) -> Result<(), UcanError> {
        Ok(())
    }

    fn record(&mut self, _nonce: &str, _token_expiry: u64) -> Result<(), UcanError> {
        Ok(())
    }
}

/// Subscribe to an open broadcast context without a UCAN.
fn subscribe_open(
    ctx: &mut BroadcastContext,
    subscriber_did: &str,
    timestamp: u64,
) -> Result<(), scp_core::context::ContextError> {
    ctx.subscribe::<
        InMemoryDidResolver,
        StubNonceTracker,
        InMemoryRevocationChecker,
        InMemoryProofResolver,
        RandomState,
    >(subscriber_did, None, timestamp, None)?;
    Ok(())
}

// ===========================================================================
// 1. Access key generation
// ===========================================================================

#[test]
fn access_key_generation() {
    let key = generate_access_key("ctx-integration", "did:dht:z6MkAlice");

    // Key material must be 32 bytes and non-zero.
    assert_eq!(key.as_bytes().len(), 32);
    assert_ne!(
        key.as_bytes(),
        &[0u8; 32],
        "access key should not be all-zero"
    );

    // Metadata should be stored correctly.
    assert_eq!(key.context_id(), "ctx-integration");
    assert_eq!(key.member_did(), "did:dht:z6MkAlice");
    assert_eq!(key.epoch(), 0);
}

// ===========================================================================
// 2. CEK wrap/unwrap roundtrip
// ===========================================================================

#[test]
fn cek_wrap_unwrap_roundtrip() {
    let access_key = generate_access_key("ctx-test", "did:dht:z6MkBob");
    let cek = ContentEncryptionKey::generate();
    let original_bytes = *cek.as_bytes();

    let wrapped = wrap_cek(&cek, &access_key).expect("wrap_cek should succeed");
    assert_eq!(wrapped.len(), 40, "wrapped CEK must be 40 bytes (RFC 3394)");

    let unwrapped = unwrap_cek(&wrapped, &access_key).expect("unwrap_cek should succeed");
    assert_eq!(
        unwrapped.as_bytes(),
        &original_bytes,
        "unwrapped CEK must match original"
    );
}

// ===========================================================================
// 3. CEK unwrap with wrong key fails
// ===========================================================================

#[test]
fn cek_unwrap_wrong_key_fails() {
    let key_correct = generate_access_key("ctx-test", "did:dht:z6MkAlice");
    let key_wrong = generate_access_key("ctx-test", "did:dht:z6MkBob");
    let cek = ContentEncryptionKey::generate();

    let wrapped = wrap_cek(&cek, &key_correct).unwrap();
    let result = unwrap_cek(&wrapped, &key_wrong);

    assert!(result.is_err(), "unwrap with wrong access key must fail");
}

// ===========================================================================
// 4. Content wrap/unwrap roundtrip (with AAD)
// ===========================================================================

#[test]
fn content_wrap_unwrap_roundtrip() {
    let access_key = generate_access_key("ctx-aad-test", "did:dht:z6MkAlice");
    let did = "did:dht:z6MkAlice";
    let context_id = "ctx-aad-test";
    let sender_did = "did:dht:z6MkSender";
    let key_epoch = 0u64;
    let sequence = 42u64;
    let plaintext = b"Hello, content access control!";

    let recipients = vec![scp_core::crypto::access_keys::wrapping::Recipient {
        did,
        access_key: &access_key,
    }];

    let wrapped = wrap_content(
        plaintext,
        &recipients,
        context_id,
        sender_did,
        key_epoch,
        sequence,
    )
    .expect("wrap_content should succeed");

    assert_eq!(wrapped.wrapped_ceks.len(), 1);
    assert_eq!(wrapped.nonce.len(), 12);

    let decrypted = unwrap_content(
        &wrapped,
        did,
        &access_key,
        context_id,
        sender_did,
        key_epoch,
        sequence,
    )
    .expect("unwrap_content should succeed");

    assert_eq!(
        decrypted, plaintext,
        "decrypted content must match original"
    );
}

// ===========================================================================
// 5. Content unwrap with wrong AAD (wrong context_id) fails
// ===========================================================================

#[test]
fn content_unwrap_wrong_aad_fails() {
    let access_key = generate_access_key("ctx-original", "did:dht:z6MkAlice");
    let did = "did:dht:z6MkAlice";
    let context_id = "ctx-original";
    let wrong_context_id = "ctx-relocated";
    let sender_did = "did:dht:z6MkSender";
    let key_epoch = 0u64;
    let sequence = 1u64;
    let plaintext = b"Cross-context relocation detection";

    let recipients = vec![scp_core::crypto::access_keys::wrapping::Recipient {
        did,
        access_key: &access_key,
    }];

    let wrapped = wrap_content(
        plaintext,
        &recipients,
        context_id,
        sender_did,
        key_epoch,
        sequence,
    )
    .unwrap();

    // Attempt to unwrap with a different context_id (simulates cross-context
    // ciphertext relocation). The AAD mismatch should cause AES-256-GCM
    // authentication to fail.
    let result = unwrap_content(
        &wrapped,
        did,
        &access_key,
        wrong_context_id,
        sender_did,
        key_epoch,
        sequence,
    );

    assert!(
        result.is_err(),
        "unwrap with wrong context_id should fail (AAD mismatch)"
    );
}

// ===========================================================================
// 6. ContentAccessState transitions — forward-only
// ===========================================================================

#[test]
fn content_access_state_transitions() {
    // Full -> ReadOnly -> PresenceOnly -> NonMember: all valid forward transitions.
    let state = ContentAccessState::Full;
    assert!(state.can_read());
    assert!(state.can_write());

    let state = state
        .transition_to(ContentAccessState::ReadOnly)
        .expect("Full -> ReadOnly should succeed");
    assert!(state.can_read());
    assert!(!state.can_write());

    let state = state
        .transition_to(ContentAccessState::PresenceOnly)
        .expect("ReadOnly -> PresenceOnly should succeed");
    assert!(!state.can_read());
    assert!(!state.can_write());

    let state = state
        .transition_to(ContentAccessState::NonMember)
        .expect("PresenceOnly -> NonMember should succeed");
    assert!(!state.can_read());
    assert!(!state.can_write());

    // Same-state transitions are also valid.
    let state = ContentAccessState::ReadOnly;
    let result = state.transition_to(ContentAccessState::ReadOnly);
    assert_eq!(result, Ok(ContentAccessState::ReadOnly));
}

// ===========================================================================
// 7. ContentAccessState — reverse transitions rejected
// ===========================================================================

#[test]
fn content_access_state_reverse_blocked() {
    // ReadOnly -> Full is forbidden.
    let state = ContentAccessState::ReadOnly;
    assert_eq!(
        state.transition_to(ContentAccessState::Full),
        Err(ContentAccessState::ReadOnly),
        "ReadOnly -> Full should be rejected"
    );

    // PresenceOnly -> ReadOnly is forbidden.
    let state = ContentAccessState::PresenceOnly;
    assert_eq!(
        state.transition_to(ContentAccessState::ReadOnly),
        Err(ContentAccessState::PresenceOnly),
        "PresenceOnly -> ReadOnly should be rejected"
    );

    // NonMember -> Full is forbidden.
    let state = ContentAccessState::NonMember;
    assert_eq!(
        state.transition_to(ContentAccessState::Full),
        Err(ContentAccessState::NonMember),
        "NonMember -> Full should be rejected"
    );

    // PresenceOnly -> Full is forbidden.
    let state = ContentAccessState::PresenceOnly;
    assert_eq!(
        state.transition_to(ContentAccessState::Full),
        Err(ContentAccessState::PresenceOnly),
        "PresenceOnly -> Full should be rejected"
    );

    // NonMember -> PresenceOnly is forbidden.
    let state = ContentAccessState::NonMember;
    assert_eq!(
        state.transition_to(ContentAccessState::PresenceOnly),
        Err(ContentAccessState::NonMember),
        "NonMember -> PresenceOnly should be rejected"
    );

    // But restore_to bypasses the constraint (governance action).
    let restored = ContentAccessState::NonMember.restore_to(ContentAccessState::Full);
    assert_eq!(restored, ContentAccessState::Full);
}

// ===========================================================================
// 8. BlockListState from events
// ===========================================================================

#[test]
fn block_list_state_from_events() {
    let events = vec![
        // Block Dave globally.
        BlockListEvent::BlockDID {
            target_did: did("did:dht:z6MkDave"),
            timestamp: 1000,
        },
        // Block Eve in ctx-1.
        BlockListEvent::BlockDIDInContext {
            target_did: did("did:dht:z6MkEve"),
            context_id: "ctx-1".to_owned(),
            timestamp: 2000,
        },
        // Unblock Dave globally.
        BlockListEvent::UnblockDID {
            target_did: did("did:dht:z6MkDave"),
            timestamp: 3000,
        },
    ];

    let state = BlockListState::from_events(&events);

    // Dave was blocked then unblocked -> not blocked.
    assert!(
        !state.is_globally_blocked(&did("did:dht:z6MkDave")),
        "Dave should be unblocked after UnblockDID"
    );

    // Eve is blocked in ctx-1 only.
    assert!(
        state.is_blocked_in_context(&did("did:dht:z6MkEve"), "ctx-1"),
        "Eve should be blocked in ctx-1"
    );
    assert!(
        !state.is_blocked_in_context(&did("did:dht:z6MkEve"), "ctx-2"),
        "Eve should not be blocked in ctx-2"
    );
    assert!(
        !state.is_globally_blocked(&did("did:dht:z6MkEve")),
        "Eve should not be globally blocked"
    );
}

// ===========================================================================
// 9. BlockListEvent — all 4 variants
// ===========================================================================

#[test]
fn block_list_event_variants() {
    let events = vec![
        BlockListEvent::BlockDID {
            target_did: did("did:dht:z6MkA"),
            timestamp: 100,
        },
        BlockListEvent::UnblockDID {
            target_did: did("did:dht:z6MkA"),
            timestamp: 200,
        },
        BlockListEvent::BlockDIDInContext {
            target_did: did("did:dht:z6MkB"),
            context_id: "ctx-1".to_owned(),
            timestamp: 300,
        },
        BlockListEvent::UnblockDIDInContext {
            target_did: did("did:dht:z6MkB"),
            context_id: "ctx-1".to_owned(),
            timestamp: 400,
        },
    ];

    // All four variants should be constructible and produce correct state.
    let state = BlockListState::from_events(&events);

    // BlockDID followed by UnblockDID -> unblocked.
    assert!(!state.is_globally_blocked(&did("did:dht:z6MkA")));

    // BlockDIDInContext followed by UnblockDIDInContext -> unblocked.
    assert!(!state.is_blocked_in_context(&did("did:dht:z6MkB"), "ctx-1"));

    // Empty state.
    assert!(state.global_block_list().is_empty());
    assert!(state.context_block_list("ctx-1").is_empty());
}

// ===========================================================================
// 10. Broadcast block denies key request
// ===========================================================================

#[test]
fn broadcast_block_denies_key_request() {
    let mut ctx = BroadcastContext::new(
        "ctx-broadcast-block".to_owned(),
        &ContextMode::Broadcast,
        BroadcastAdmission::Open,
    )
    .unwrap();

    let author_did = "did:example:alice";
    let subscriber_did = "did:example:bob";

    // Register author and subscriber.
    ctx.add_author(author_did).unwrap();
    subscribe_open(&mut ctx, subscriber_did, 1000).unwrap();

    // Before blocking: key request should be granted.
    let decision = ctx.handle_key_request(author_did, subscriber_did);
    assert!(
        matches!(decision, KeyRequestDecision::Grant { .. }),
        "subscriber should be granted before block"
    );

    // Block the subscriber for this author.
    ctx.block_subscriber(author_did, subscriber_did).unwrap();

    // After blocking: key request should be denied.
    let decision = ctx.handle_key_request(author_did, subscriber_did);
    assert!(
        matches!(decision, KeyRequestDecision::Deny { .. }),
        "blocked subscriber should be denied"
    );
}

// ===========================================================================
// 11. Sender key rotation on block
// ===========================================================================

#[test]
fn sender_key_rotation_on_block() {
    let mut ctx = BroadcastContext::new(
        "ctx-rotation-test".to_owned(),
        &ContextMode::Broadcast,
        BroadcastAdmission::Open,
    )
    .unwrap();

    let author_did = "did:example:alice";
    let subscriber_a = "did:example:bob";
    let subscriber_b = "did:example:eve";

    // Set up: author + two subscribers.
    ctx.add_author(author_did).unwrap();
    subscribe_open(&mut ctx, subscriber_a, 1000).unwrap();
    subscribe_open(&mut ctx, subscriber_b, 1001).unwrap();

    // Get the initial epoch.
    let initial_decision = ctx.handle_key_request(author_did, subscriber_a);
    let initial_epoch = match &initial_decision {
        KeyRequestDecision::Grant { epoch, .. } => *epoch,
        KeyRequestDecision::Deny { reason } => panic!("expected Grant, got Deny: {reason}"),
    };
    assert_eq!(initial_epoch, 0, "initial epoch should be 0");

    // Block subscriber_b -> triggers key rotation.
    let block_result = ctx.block_subscriber(author_did, subscriber_b).unwrap();
    assert_eq!(
        block_result.new_epoch, 1,
        "epoch should increment after block"
    );
    assert!(
        block_result.block_list.contains(subscriber_b),
        "blocked DID should be in the block list"
    );

    // subscriber_a (not blocked) should still get access at the new epoch.
    let post_block_decision = ctx.handle_key_request(author_did, subscriber_a);
    match &post_block_decision {
        KeyRequestDecision::Grant { epoch, .. } => {
            assert_eq!(*epoch, 1, "non-blocked subscriber should see epoch 1");
        }
        KeyRequestDecision::Deny { reason } => {
            panic!("non-blocked subscriber should be granted, got Deny: {reason}");
        }
    }

    // subscriber_b (blocked) should be denied.
    let denied = ctx.handle_key_request(author_did, subscriber_b);
    assert!(
        matches!(denied, KeyRequestDecision::Deny { .. }),
        "blocked subscriber should be denied after key rotation"
    );
}
