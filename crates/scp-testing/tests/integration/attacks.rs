#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::items_after_statements,
    clippy::too_many_lines,
    clippy::iter_on_single_items
)]

//! B14: Attack scenario integration tests.
//!
//! Negative tests verifying that various attack vectors are properly rejected.
//! Covers relay misbehavior detection, identity attacks, membership attacks,
//! cryptographic attacks, governance attacks, broadcast attacks, privacy
//! unlinkability, content access attacks, participation admission attacks,
//! sender key exchange attacks, and UCAN replay/expiry rejection.

use std::collections::{HashMap, HashSet};
use std::hash::RandomState;
use std::sync::Arc;

use ed25519_dalek::Signer;
use scp_core::context::broadcast::SubscriptionResult;
use scp_core::context::governance::majority::MajorityVoteEngine;
use scp_core::context::governance::multisig::ThresholdEngine;
use scp_core::context::governance::{
    GovernanceAction, GovernanceContext, GovernanceEngine, GovernanceError, KeyResolver,
    ProposalStatus, RejectionReason, VoteType, sign_vote, verify_vote,
};
use scp_core::context::params::Capability;
use scp_core::context::roles::{CapabilityCeiling, RoleDefinition, default_ceiling};
use scp_core::context::{
    BroadcastAdmission, BroadcastContext, ContextError, ContextMode, KeyRequestDecision,
    builtin_observer,
};
use scp_core::crypto::access_keys::wrapping::{unwrap_cek, wrap_cek};
use scp_core::crypto::access_keys::{ContentEncryptionKey, generate_access_key};
use scp_core::crypto::sender_keys::{
    BlockNotification, HandleRequestParams, NonceDedup, SealBroadcastParams, SenderKeyError,
    SenderKeyRequest, SigningPayloadFields, build_broadcast_signing_payload,
    compute_provenance_hash, decrypt_sender_layer, encrypt_sender_layer, generate_broadcast_key,
    generate_broadcast_nonce, generate_sender_key, handle_sender_key_request,
    open_broadcast_trusted, request_sender_key, seal_broadcast,
    validate_block_notification_freshness,
};
use scp_core::crypto::ucan::validate::{
    InMemoryDidResolver, InMemoryProofResolver, InMemoryRevocationChecker, NonceTracker,
};
use scp_core::crypto::ucan::{CapabilityUri, UcanError};
use scp_core::envelope::inner::SCP_INNER_ENVELOPE_VERSION;
use scp_core::envelope::{
    InnerEnvelopeParams, MessageType, SCP_PROTOCOL_VERSION, SequenceTracker, create_inner_envelope,
    derive_pseudonym,
};
use scp_core::identity::SigningKeyId;
use scp_core::trust::custody_violation::{ActionCategory, enforce_category_a};
use scp_core::trust::{
    ParticipationFact, ParticipationInput, ParticipationThreshold, RequireParticipation,
    produce_participation_profile, verify_participation_requirements,
};
use scp_event_log::{Event, EventPayload, EventType};
use scp_identity::IdentityError;
use scp_identity::document::{DidDocument, VerificationMethod};
use scp_platform::testing::InMemoryKeyCustody;
use scp_platform::traits::{KeyCustody, KeyType};
use scp_testing::relay::behavior::{EquivocationConfig, ReplayConfig, SuppressionConfig};
use scp_testing::relay::{BehaviorMode, InMemoryRelay};

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
// Governance helpers
// ---------------------------------------------------------------------------

fn alice_did() -> scp_identity::DID {
    scp_identity::DID::from("did:dht:z6MkAlice")
}

fn bob_did() -> scp_identity::DID {
    scp_identity::DID::from("did:dht:z6MkBob")
}

fn carol_did() -> scp_identity::DID {
    scp_identity::DID::from("did:dht:z6MkCarol")
}

fn sk_for(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

/// Mock key resolver: Alice=1, Bob=2, Carol=3.
fn mock_resolver() -> KeyResolver {
    Arc::new(|did: &scp_identity::DID| {
        let did_str: &str = did.as_ref();
        match did_str {
            "did:dht:z6MkAlice" => Some(sk_for(1).verifying_key()),
            "did:dht:z6MkBob" => Some(sk_for(2).verifying_key()),
            "did:dht:z6MkCarol" => Some(sk_for(3).verifying_key()),
            _ => None,
        }
    })
}

fn governance_context(
    ctx_id: &str,
    members: &[(scp_identity::DID, &str)],
    admin_dids: &[scp_identity::DID],
    now: u64,
) -> GovernanceContext {
    GovernanceContext {
        context_id: ctx_id.to_owned(),
        members: members
            .iter()
            .map(|(d, r)| (d.clone(), (*r).to_owned()))
            .collect(),
        admin_dids: admin_dids.to_vec(),
        current_epoch: Some(1),
        now,
    }
}

// ===========================================================================
// Relay attacks (InMemoryRelay from scp_testing::relay)
// ===========================================================================

// ---------------------------------------------------------------------------
// 1. relay_suppression_detectable
// ---------------------------------------------------------------------------

#[tokio::test]
async fn relay_suppression_detectable() {
    let mut relay =
        InMemoryRelay::with_behavior(BehaviorMode::Suppressing(SuppressionConfig { drop_nth: 2 }));
    let routing_id = [0xAA; 32];
    let (_sub_id, mut rx) = relay.subscribe(routing_id);

    // Store 10 messages
    for i in 0u8..10 {
        relay.store(routing_id, vec![i], None, 1000 + u64::from(i));
    }

    // Collect delivered messages
    let mut delivered = Vec::new();
    while let Ok(msg) = rx.try_recv() {
        delivered.push(msg.data[0]);
    }

    // With drop_nth=2, messages 2,4,6,8,10 (1-indexed msg_num) are dropped.
    // That means messages with payloads 1,3,5,7,9 are dropped (0-indexed i+1 matches msg_num).
    // Delivered: payloads 0,2,4,6,8 (5 messages)
    assert_eq!(
        delivered.len(),
        5,
        "suppression should drop ~half the messages"
    );

    // Gaps are detectable: the sequence has holes
    assert!(
        delivered.len() < 10,
        "subscriber should detect missing messages via sequence gaps"
    );
}

// ---------------------------------------------------------------------------
// 2. relay_equivocation_divergence
// ---------------------------------------------------------------------------

#[tokio::test]
async fn relay_equivocation_divergence() {
    let mut relay = InMemoryRelay::with_behavior(BehaviorMode::Equivocating(EquivocationConfig {
        diverge_after: 2,
    }));
    let routing_id = [0xBB; 32];

    let (_sub_id_0, mut rx0) = relay.subscribe(routing_id);
    let (_sub_id_1, mut rx1) = relay.subscribe(routing_id);

    // Store 5 messages (3 after the divergence threshold of 2)
    for i in 0u8..5 {
        relay.store(routing_id, vec![i, 0xFF], None, 2000 + u64::from(i));
    }

    let mut msgs_0 = Vec::new();
    while let Ok(msg) = rx0.try_recv() {
        msgs_0.push(msg.data);
    }

    let mut msgs_1 = Vec::new();
    while let Ok(msg) = rx1.try_recv() {
        msgs_1.push(msg.data);
    }

    // Both subscribers should get all 5 messages
    assert_eq!(msgs_0.len(), 5);
    assert_eq!(msgs_1.len(), 5);

    // First 2 messages are identical (before divergence)
    assert_eq!(msgs_0[0], msgs_1[0]);
    assert_eq!(msgs_0[1], msgs_1[1]);

    // After divergence, the odd-indexed subscriber (sub_id_1) gets flipped data
    // At least one message after divergence should differ
    let diverged = msgs_0[2..]
        .iter()
        .zip(msgs_1[2..].iter())
        .any(|(a, b)| a != b);
    assert!(
        diverged,
        "subscribers should see divergent data after equivocation threshold"
    );
}

// ---------------------------------------------------------------------------
// 3. relay_replay_dedup
// ---------------------------------------------------------------------------

#[tokio::test]
async fn relay_replay_dedup() {
    let mut relay =
        InMemoryRelay::with_behavior(BehaviorMode::Replaying(ReplayConfig { replay_count: 1 }));
    let routing_id = [0xCC; 32];
    let (_sub_id, mut rx) = relay.subscribe(routing_id);

    // Store one message
    let blob_id = relay.store(routing_id, vec![42], None, 3000);

    // Collect all delivered messages
    let mut delivered = Vec::new();
    while let Ok(msg) = rx.try_recv() {
        delivered.push(msg);
    }

    // With replay_count=1, the message should be delivered twice
    assert_eq!(
        delivered.len(),
        2,
        "replay should deliver message twice (original + 1 replay)"
    );

    // Both deliveries have the same blob_id -- dedup via BlobId shows identical IDs
    assert_eq!(delivered[0].blob_id, blob_id);
    assert_eq!(delivered[1].blob_id, blob_id);
    assert_eq!(
        delivered[0].blob_id, delivered[1].blob_id,
        "replayed messages should have identical blob IDs for dedup detection"
    );
}

// ---------------------------------------------------------------------------
// 4. relay_deletion_noncompliant
// ---------------------------------------------------------------------------

#[tokio::test]
async fn relay_deletion_noncompliant() {
    let mut relay = InMemoryRelay::with_behavior(BehaviorMode::DeletionNonCompliant);
    let routing_id = [0xDD; 32];

    let blob_id = relay.store(routing_id, vec![99], None, 4000);
    assert_eq!(relay.blob_count(), 1);

    // Delete should return false (non-compliant)
    let deleted = relay.delete(&blob_id);
    assert!(
        !deleted,
        "DeletionNonCompliant relay should return false on delete"
    );

    // Blob should still be queryable
    let blob = relay.get(&blob_id);
    assert!(
        blob.is_some(),
        "blob should still be retrievable after non-compliant delete"
    );
    assert_eq!(blob.unwrap().data, vec![99]);
}

// ===========================================================================
// Identity attacks
// ===========================================================================

// ---------------------------------------------------------------------------
// 5. fabricated_did_document_agent_keys
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fabricated_did_document_agent_keys() {
    // Create a DID document with 2 #agent verification methods (invalid)
    let did = "did:dht:zFabricated";
    let identity_pk = [1u8; 32];
    let active_pk = [2u8; 32];
    let agent_pk_1 = [3u8; 32];
    let commitment = [4u8; 32];

    let mut doc = DidDocument::new_with_agent_key(
        did,
        &identity_pk,
        &active_pk,
        &commitment,
        Some(&agent_pk_1),
    );

    // Manually inject a second #agent VM to simulate a fabricated document
    doc.verification_method.push(VerificationMethod {
        id: format!("{did}#agent-duplicate"),
        method_type: "Ed25519VerificationKey2020".to_owned(),
        controller: did.to_owned(),
        public_key_multibase: "z11111111111111111111111111111111111111111111".to_owned(),
    });

    // validate_agent_keys should fail: more than one #agent VM
    // Note: the check filters for VMs ending with "#agent", and our duplicate
    // ends with "#agent-duplicate", so we need to use the exact suffix.
    // Let's use the correct id format.
    doc.verification_method.last_mut().unwrap().id = format!("{did}#agent");

    // Now there are 2 VMs ending with "#agent"
    let result = doc.validate_agent_keys();
    assert!(
        result.is_err(),
        "multiple #agent VMs should fail validation"
    );
    let err = result.unwrap_err();
    assert!(
        matches!(err, IdentityError::MultipleAgentKeys { count: 2 }),
        "expected MultipleAgentKeys with count=2, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// 6. category_a_rejects_agent_key
// ---------------------------------------------------------------------------

#[tokio::test]
async fn category_a_rejects_agent_key() {
    // enforce_category_a should reject agent keys for Category A actions
    let result = enforce_category_a(
        SigningKeyId::Agent,
        ActionCategory::CategoryA,
        "did:dht:zViolator",
        "DID document modification",
        &[0u8; 64],
    );

    assert!(
        result.is_err(),
        "agent key should be rejected for Category A actions"
    );
    let violation = result.unwrap_err();
    assert!(
        violation.error_message.contains("Category A"),
        "error should mention Category A: {}",
        violation.error_message
    );
    assert_eq!(violation.signing_key_id, SigningKeyId::Agent);

    // Active key should pass for the same action
    let active_result = enforce_category_a(
        SigningKeyId::Active,
        ActionCategory::CategoryA,
        "did:dht:zLegitimate",
        "DID document modification",
        &[0u8; 64],
    );
    assert!(
        active_result.is_ok(),
        "active key should be allowed for Category A actions"
    );
}

// ===========================================================================
// Cryptographic attacks
// ===========================================================================

// ---------------------------------------------------------------------------
// 7. tampered_ciphertext_rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tampered_ciphertext_rejected() {
    let key = generate_sender_key();
    let plaintext = b"sensitive protocol data";
    let ctx_id = "ctx-tamper";
    let sender_did = "did:dht:z6MkSender";
    let epoch = 1u64;
    let seq = 0u64;
    let mut ciphertext =
        encrypt_sender_layer(&key, plaintext, ctx_id, sender_did, epoch, seq).unwrap();

    // Flip a bit in the encrypted portion (after the 12-byte nonce)
    let tamper_index = 13;
    ciphertext[tamper_index] ^= 0xFF;

    let result = decrypt_sender_layer(&key, &ciphertext, ctx_id, sender_did, epoch, seq);
    assert!(result.is_err(), "tampered ciphertext should be rejected");
    assert!(
        matches!(result, Err(SenderKeyError::AuthenticationFailed)),
        "expected AuthenticationFailed, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// 8. sender_key_nonce_reuse_rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sender_key_nonce_reuse_rejected() {
    let mut dedup = NonceDedup::new();
    let nonce: [u8; 16] = [42u8; 16];
    let now_secs = 1_700_000_000u64;

    // First use: not a replay
    assert!(
        !dedup.is_replayed(&nonce, now_secs),
        "first occurrence should not be flagged as replay"
    );
    dedup.record(nonce, now_secs);

    // Second use: IS a replay
    assert!(
        dedup.is_replayed(&nonce, now_secs),
        "same nonce within window should be detected as replay"
    );
}

// ---------------------------------------------------------------------------
// 9. block_notification_stale_timestamp
// ---------------------------------------------------------------------------

#[tokio::test]
async fn block_notification_stale_timestamp() {
    // Create a block notification with a stale timestamp (>30s old)
    let custody = InMemoryKeyCustody::new();
    let signing_key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();

    let clock = scp_primitives::SystemClock;
    let msg = scp_core::crypto::sender_keys::send_block_notification(
        &custody,
        &signing_key,
        "ctx-stale",
        "did:dht:alice",
        "did:dht:dave",
        SigningKeyId::Active,
        &clock,
    )
    .await
    .unwrap();

    let notification: BlockNotification = rmp_serde::from_slice(&msg).unwrap();

    // Set "now" to 60 seconds in the future (well past the 30s freshness window)
    let far_future_ms = notification.timestamp + 60_000;
    let result = validate_block_notification_freshness(&notification, far_future_ms);
    assert!(
        matches!(result, Err(SenderKeyError::StaleBlockNotification)),
        "stale block notification should be rejected, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// 10. wrong_sender_key_decryption_fails
// ---------------------------------------------------------------------------

#[tokio::test]
async fn wrong_sender_key_decryption_fails() {
    let correct_key = generate_sender_key();
    let wrong_key = generate_sender_key();
    let plaintext = b"secret message for authorized recipients only";

    let ctx_id = "ctx-wrongkey";
    let sender_did = "did:dht:z6MkSender";
    let epoch = 1u64;
    let seq = 0u64;
    let ciphertext =
        encrypt_sender_layer(&correct_key, plaintext, ctx_id, sender_did, epoch, seq).unwrap();

    let result = decrypt_sender_layer(&wrong_key, &ciphertext, ctx_id, sender_did, epoch, seq);
    assert!(result.is_err(), "decryption with wrong key should fail");
    assert!(
        matches!(result, Err(SenderKeyError::AuthenticationFailed)),
        "expected AuthenticationFailed, got: {result:?}"
    );
}

// ===========================================================================
// Governance attacks
// ===========================================================================

// ---------------------------------------------------------------------------
// 11. vote_wrong_signing_key
// ---------------------------------------------------------------------------

#[tokio::test]
async fn vote_wrong_signing_key() {
    // Sign a vote with Alice's key, then verify with Bob's key -> should fail
    let proposal_id = [0xAA; 32];
    let alice_sk = sk_for(1);
    let bob_vk = sk_for(2).verifying_key();

    let vote = sign_vote(
        &proposal_id,
        &VoteType::Approve,
        "did:dht:z6MkAlice",
        1_700_000_000,
        &alice_sk,
    )
    .unwrap();

    let result = verify_vote(&proposal_id, &vote, &bob_vk);
    assert!(
        result.is_err(),
        "vote signed by Alice should fail verification against Bob's key"
    );
    assert!(
        matches!(result, Err(GovernanceError::VerificationFailed(_))),
        "expected VerificationFailed, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// 12. double_vote_rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn double_vote_rejected() {
    let voters = vec![alice_did(), bob_did(), carol_did()];
    let mut engine = MajorityVoteEngine::new(voters, 86_400, 5000, mock_resolver()).unwrap();

    let now = 1_700_000_000;
    let ctx = governance_context(
        "ctx-double-vote",
        &[
            (alice_did(), "member"),
            (bob_did(), "member"),
            (carol_did(), "member"),
        ],
        &[alice_did()],
        now,
    );

    let (proposal, _) = engine
        .propose(
            &alice_did(),
            GovernanceAction::AddMember {
                did: "did:dht:z6MkNew".into(),
                role: "member".to_owned(),
            },
            &ctx,
            &sk_for(1),
        )
        .unwrap();

    // Alice approves
    engine
        .approve(&proposal.proposal_id, &alice_did(), &ctx, &sk_for(1))
        .unwrap();

    // Alice tries to approve again -> should fail with AlreadyVoted
    let result = engine.approve(&proposal.proposal_id, &alice_did(), &ctx, &sk_for(1));
    assert!(result.is_err(), "double vote should be rejected");
    assert!(
        matches!(result, Err(GovernanceError::AlreadyVoted)),
        "expected AlreadyVoted, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// 13. voting_window_expired
// ---------------------------------------------------------------------------

#[tokio::test]
async fn voting_window_expired() {
    let voters = vec![alice_did(), bob_did(), carol_did()];
    // Voting window of 300 seconds (5 minutes)
    let mut engine = MajorityVoteEngine::new(voters, 300, 5000, mock_resolver()).unwrap();

    let now = 1_700_000_000;
    let ctx = governance_context(
        "ctx-expired-vote",
        &[
            (alice_did(), "member"),
            (bob_did(), "member"),
            (carol_did(), "member"),
        ],
        &[alice_did()],
        now,
    );

    let (proposal, _) = engine
        .propose(
            &alice_did(),
            GovernanceAction::AddMember {
                did: "did:dht:z6MkNew".into(),
                role: "member".to_owned(),
            },
            &ctx,
            &sk_for(1),
        )
        .unwrap();

    // Fast-forward past the voting window
    let expired_ctx = governance_context(
        "ctx-expired-vote",
        &[
            (alice_did(), "member"),
            (bob_did(), "member"),
            (carol_did(), "member"),
        ],
        &[alice_did()],
        now + 301, // 301 seconds later, past the 300s window
    );

    // Bob tries to vote after the window has expired — MajorityVoteEngine auto-resolves
    // the proposal instead of returning an error. With no votes cast and quorum unmet,
    // the proposal is rejected for insufficient participation.
    let (status, _events) = engine
        .approve(&proposal.proposal_id, &bob_did(), &expired_ctx, &sk_for(2))
        .expect("past-deadline approve triggers resolve, not error");
    assert_eq!(
        status,
        ProposalStatus::Rejected {
            reason: RejectionReason::InsufficientParticipation
        },
        "expected InsufficientParticipation after expired window with no votes"
    );
}

// ---------------------------------------------------------------------------
// 14. minority_cannot_block_majority
// ---------------------------------------------------------------------------

#[tokio::test]
async fn minority_cannot_block_majority() {
    let voters = vec![alice_did(), bob_did(), carol_did()];
    let mut engine = MajorityVoteEngine::new(voters, 86_400, 5000, mock_resolver()).unwrap();

    let now = 1_700_000_000;
    let ctx = governance_context(
        "ctx-minority-block",
        &[
            (alice_did(), "member"),
            (bob_did(), "member"),
            (carol_did(), "member"),
        ],
        &[alice_did()],
        now,
    );

    let (proposal, _) = engine
        .propose(
            &alice_did(),
            GovernanceAction::AddMember {
                did: "did:dht:z6MkNew".into(),
                role: "member".to_owned(),
            },
            &ctx,
            &sk_for(1),
        )
        .unwrap();

    // Carol rejects (1 rejection)
    let (status, _) = engine
        .reject(&proposal.proposal_id, &carol_did(), &ctx, &sk_for(3))
        .unwrap();
    assert_eq!(
        status,
        ProposalStatus::Pending,
        "1 reject out of 3 should still be pending"
    );

    // Alice approves
    let (status, _) = engine
        .approve(&proposal.proposal_id, &alice_did(), &ctx, &sk_for(1))
        .unwrap();
    assert_eq!(
        status,
        ProposalStatus::Pending,
        "1 approve + 1 reject should still be pending"
    );

    // Bob approves -> 2 approvals vs 1 rejection = majority approved
    let (status, _) = engine
        .approve(&proposal.proposal_id, &bob_did(), &ctx, &sk_for(2))
        .unwrap();
    assert_eq!(
        status,
        ProposalStatus::Approved,
        "2 approvals out of 3 (majority) should approve despite 1 rejection"
    );
}

// ===========================================================================
// Broadcast attacks
// ===========================================================================

// ---------------------------------------------------------------------------
// 15. gated_broadcast_no_ucan_rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn gated_broadcast_no_ucan_rejected() {
    let mut ctx = BroadcastContext::new(
        "ctx-gated-attack".to_owned(),
        &ContextMode::Broadcast,
        BroadcastAdmission::Gated,
    )
    .unwrap();

    // Subscribing to a gated context without UCAN should fail
    let result = subscribe_open(&mut ctx, "did:key:attacker", 1_700_000_000);
    assert!(result.is_err(), "gated subscribe without UCAN should fail");
    assert!(
        matches!(result.unwrap_err(), ContextError::PermissionDenied(_)),
        "expected PermissionDenied for gated subscribe without UCAN"
    );
    assert_eq!(ctx.subscriber_count(), 0, "no subscribers should be added");
}

// ---------------------------------------------------------------------------
// 16. blocked_subscriber_key_request_denied
// ---------------------------------------------------------------------------

#[tokio::test]
async fn blocked_subscriber_key_request_denied() {
    let mut ctx = BroadcastContext::new(
        "ctx-blocked-key-req".to_owned(),
        &ContextMode::Broadcast,
        BroadcastAdmission::Open,
    )
    .unwrap();

    ctx.add_author("did:key:author1").unwrap();
    subscribe_open(&mut ctx, "did:key:subscriber1", 1000).unwrap();

    // Block the subscriber
    ctx.block_subscriber("did:key:author1", "did:key:subscriber1")
        .unwrap();

    // Key request from blocked subscriber should be denied
    let decision = ctx.handle_key_request("did:key:author1", "did:key:subscriber1");
    match decision {
        KeyRequestDecision::Deny { reason } => {
            assert!(
                !reason.is_empty(),
                "deny reason should explain why the request was rejected"
            );
        }
        KeyRequestDecision::Grant { .. } => {
            panic!("blocked subscriber should be denied key access, got Grant");
        }
    }
}

// ---------------------------------------------------------------------------
// 17. broadcast_wrong_key_decryption_fails
// ---------------------------------------------------------------------------

#[tokio::test]
async fn broadcast_wrong_key_decryption_fails() {
    let author_did = "did:key:author-wrong-bk";
    let correct_bk = generate_broadcast_key(author_did);
    let wrong_bk = generate_broadcast_key(author_did); // different random key
    let payload = b"encrypted broadcast content";
    let nonce = generate_broadcast_nonce();

    let provenance_hash = compute_provenance_hash(None).unwrap();
    let signing_payload = build_broadcast_signing_payload(&SigningPayloadFields {
        version: SCP_PROTOCOL_VERSION,
        context_id: "ctx-wrong-bk",
        author_did,
        sequence: 1,
        key_epoch: 0,
        timestamp: 1_700_000_000_000,
        nonce: &nonce,
        provenance_hash: &provenance_hash,
    })
    .unwrap();

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0xDD; 32]);
    let signature = signing_key.sign(&signing_payload);

    let params = SealBroadcastParams {
        context_id: "ctx-wrong-bk",
        sequence: 1,
        timestamp: 1_700_000_000_000,
        provenance: None,
        signature,
    };

    let envelope = seal_broadcast(&correct_bk, payload, &nonce, &params).unwrap();

    // Decrypt with wrong key -> should fail
    let result = open_broadcast_trusted(&wrong_bk, &envelope);
    assert!(
        result.is_err(),
        "decrypting broadcast with wrong key should fail"
    );
}

// ===========================================================================
// Privacy attacks
// ===========================================================================

// ---------------------------------------------------------------------------
// 18. pseudonym_unlinkability
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pseudonym_unlinkability() {
    let custody = InMemoryKeyCustody::new();
    let key_handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();

    // Same identity, different contexts -> different routing_ids
    let p1 = derive_pseudonym(&custody, &key_handle, b"context-alpha")
        .await
        .unwrap();
    let p2 = derive_pseudonym(&custody, &key_handle, b"context-beta")
        .await
        .unwrap();

    assert_ne!(
        p1.public_key.as_bytes(),
        p2.public_key.as_bytes(),
        "pseudonyms derived for different contexts must be unlinkable"
    );

    // Verify that the routing_ids (public keys) are 32 bytes
    assert_eq!(p1.public_key.as_bytes().len(), 32);
    assert_eq!(p2.public_key.as_bytes().len(), 32);
}

// ===========================================================================
// UCAN attacks
// ===========================================================================

// ---------------------------------------------------------------------------
// 19. ucan_expired_token_rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ucan_expired_token_rejected() {
    use scp_core::crypto::ucan::mint::{MintParams, mint_ucan};
    use scp_core::crypto::ucan::validate::{ValidationContext, validate_ucan};

    let custody = InMemoryKeyCustody::new();
    let issuer_key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
    let issuer_pk: [u8; 32] = custody
        .public_key(&issuer_key)
        .await
        .unwrap()
        .into_bytes()
        .try_into()
        .unwrap();

    let issuer_did = "did:dht:zIssuer";
    let audience_did = "did:dht:zAudience";
    let context_id = "ctx-ucan-expired";

    // Mint a token with very short lifetime (1 second)
    let capabilities = vec!["messages:write".to_owned()];
    let token = mint_ucan(
        &MintParams {
            issuer_did,
            issuer_key: &issuer_key,
            audience_did,
            context_id,
            capabilities: &capabilities,
            lifetime_secs: 1,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        },
        &custody,
        &scp_primitives::SystemClock,
    )
    .await
    .unwrap();

    // Wait for the token to expire
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Set up validation context
    let mut resolver_keys = HashMap::new();
    resolver_keys.insert(issuer_did.to_owned(), issuer_pk);
    let did_resolver = InMemoryDidResolver::from_keys(resolver_keys);
    let mut nonce_tracker = StubNonceTracker;
    let revocation_checker = InMemoryRevocationChecker::new();
    let proof_resolver = InMemoryProofResolver::new();
    let mut ceiling: HashSet<String> = HashSet::new();
    ceiling.insert("messages:write".to_owned());

    let required_cap = CapabilityUri::new(context_id, "messages", "write");
    let mut ctx = ValidationContext {
        did_resolver: &did_resolver,
        nonce_tracker: &mut nonce_tracker,
        revocation_checker: &revocation_checker,
        proof_resolver: &proof_resolver,
        ceiling: &ceiling,
        context_creator_did: issuer_did,
        presenting_agent_did: audience_did,
        clock_skew_tolerance_secs: 0, // No tolerance to ensure expiry is detected
        clock: &scp_primitives::SystemClock,
        caveat_resolver: &scp_protocol::crypto::ucan::validate::NoCaveatResolver,
    };

    let result = validate_ucan(&token, &required_cap, &mut ctx);
    assert!(result.is_err(), "expired token should be rejected");
    assert!(
        matches!(result, Err(UcanError::TokenExpired)),
        "expected TokenExpired, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// 20. ucan_nonce_replay_rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ucan_nonce_replay_rejected() {
    use scp_core::crypto::ucan::mint::{MintParams, mint_ucan};
    use scp_core::crypto::ucan::validate::{ValidationContext, validate_ucan};

    // Define nonce tracker that rejects the second use of the same nonce
    struct ReplayNonceTracker {
        seen: HashSet<String>,
    }
    impl NonceTracker for ReplayNonceTracker {
        fn check_replay(&self, nonce: &str, _token_expiry: u64) -> Result<(), UcanError> {
            if self.seen.contains(nonce) {
                return Err(UcanError::NonceReused(nonce.to_owned()));
            }
            Ok(())
        }

        fn record(&mut self, nonce: &str, token_expiry: u64) -> Result<(), UcanError> {
            self.check_replay(nonce, token_expiry)?;
            self.seen.insert(nonce.to_owned());
            Ok(())
        }
    }

    let custody = InMemoryKeyCustody::new();
    let issuer_key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
    let issuer_pk: [u8; 32] = custody
        .public_key(&issuer_key)
        .await
        .unwrap()
        .into_bytes()
        .try_into()
        .unwrap();

    let issuer_did = "did:dht:zIssuerReplay";
    let audience_did = "did:dht:zAudienceReplay";
    let context_id = "ctx-ucan-nonce-replay";

    let capabilities = vec!["messages:write".to_owned()];
    let token = mint_ucan(
        &MintParams {
            issuer_did,
            issuer_key: &issuer_key,
            audience_did,
            context_id,
            capabilities: &capabilities,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        },
        &custody,
        &scp_primitives::SystemClock,
    )
    .await
    .unwrap();

    // Set up validation context with a real nonce tracker that enforces uniqueness
    let mut resolver_keys = HashMap::new();
    resolver_keys.insert(issuer_did.to_owned(), issuer_pk);
    let did_resolver = InMemoryDidResolver::from_keys(resolver_keys);
    let revocation_checker = InMemoryRevocationChecker::new();
    let proof_resolver = InMemoryProofResolver::new();
    let mut ceiling: HashSet<String> = HashSet::new();
    ceiling.insert("messages:write".to_owned());

    let required_cap = CapabilityUri::new(context_id, "messages", "write");

    let mut nonce_tracker = ReplayNonceTracker {
        seen: HashSet::new(),
    };

    // First validation should succeed
    {
        let mut ctx = ValidationContext {
            did_resolver: &did_resolver,
            nonce_tracker: &mut nonce_tracker,
            revocation_checker: &revocation_checker,
            proof_resolver: &proof_resolver,
            ceiling: &ceiling,
            context_creator_did: issuer_did,
            presenting_agent_did: audience_did,
            clock_skew_tolerance_secs: 300,
            clock: &scp_primitives::SystemClock,
            caveat_resolver: &scp_protocol::crypto::ucan::validate::NoCaveatResolver,
        };
        let result = validate_ucan(&token, &required_cap, &mut ctx);
        assert!(
            result.is_ok(),
            "first validation should succeed: {result:?}"
        );
    }

    // Second validation with same token (same nonce) should fail
    {
        let mut ctx = ValidationContext {
            did_resolver: &did_resolver,
            nonce_tracker: &mut nonce_tracker,
            revocation_checker: &revocation_checker,
            proof_resolver: &proof_resolver,
            ceiling: &ceiling,
            context_creator_did: issuer_did,
            presenting_agent_did: audience_did,
            clock_skew_tolerance_secs: 300,
            clock: &scp_primitives::SystemClock,
            caveat_resolver: &scp_protocol::crypto::ucan::validate::NoCaveatResolver,
        };
        let result = validate_ucan(&token, &required_cap, &mut ctx);
        assert!(result.is_err(), "replayed nonce should be rejected");
        assert!(
            matches!(result, Err(UcanError::NonceReused(_))),
            "expected NonceReused, got: {result:?}"
        );
    }
}

// ===========================================================================
// Membership attacks
// ===========================================================================

// ---------------------------------------------------------------------------
// 21. observer_role_cannot_write
// ---------------------------------------------------------------------------

#[tokio::test]
async fn observer_role_cannot_write() {
    let ceiling = default_ceiling();
    let observer = builtin_observer(&ceiling);

    // Observer should have MessagesRead but NOT MessagesWrite or ToolInvokeAll.
    assert!(
        observer.capabilities.contains(&Capability::MessagesRead),
        "observer should have MessagesRead"
    );
    assert!(
        !observer.capabilities.contains(&Capability::MessagesWrite),
        "observer must NOT have MessagesWrite"
    );
    assert!(
        !observer.capabilities.contains(&Capability::OutletCallAll),
        "observer must NOT have ToolInvokeAll"
    );
    assert!(
        !observer
            .capabilities
            .contains(&Capability::GovernancePropose),
        "observer must NOT have GovernancePropose"
    );
}

// ---------------------------------------------------------------------------
// 22. capability_expansion_outside_ceiling_rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn capability_expansion_outside_ceiling_rejected() {
    // Create a restricted ceiling with only read capability.
    let restricted_ceiling = CapabilityCeiling::new([Capability::MessagesRead]);

    // Attempting to create a role with write capability outside the ceiling
    // should be rejected.
    let result = RoleDefinition::new(
        "attacker-role",
        [Capability::MessagesWrite].into_iter().collect(),
        &restricted_ceiling,
    );

    assert!(
        result.is_err(),
        "role with capability outside ceiling must be rejected"
    );
}

// ===========================================================================
// Cryptographic attacks (additional)
// ===========================================================================

// ---------------------------------------------------------------------------
// 23. sequence_replay_detected (SequenceTracker)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sequence_replay_detected() {
    let mut tracker = SequenceTracker::new();

    let custody = InMemoryKeyCustody::from_seed(230);
    let key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();

    // First envelope at sequence 5.
    let env1 = create_inner_envelope(
        &InnerEnvelopeParams {
            version: SCP_INNER_ENVELOPE_VERSION,
            context_id: "ctx-seq-replay",
            sender_did: "did:dht:z6MkReplaySender",
            epoch: 1,
            generation: 0,
            sequence: 5,
            timestamp: 1_700_000_000_000,
            message_type: MessageType::Content,
            payload: b"msg-1",
            provenance: None,
            signing_key_id: SigningKeyId::Active,
        },
        &custody,
        &key,
    )
    .await
    .unwrap();

    assert!(
        tracker.validate_and_advance(&env1).is_ok(),
        "first message at seq 5 should be accepted"
    );

    // Replay: same sequence number (5) from same sender.
    let custody2 = InMemoryKeyCustody::from_seed(231);
    let key2 = custody2.generate_keypair(KeyType::Ed25519).await.unwrap();
    let env2 = create_inner_envelope(
        &InnerEnvelopeParams {
            version: SCP_INNER_ENVELOPE_VERSION,
            context_id: "ctx-seq-replay",
            sender_did: "did:dht:z6MkReplaySender",
            epoch: 1,
            generation: 0,
            sequence: 5, // same as env1
            timestamp: 1_700_000_001_000,
            message_type: MessageType::Content,
            payload: b"msg-replay",
            provenance: None,
            signing_key_id: SigningKeyId::Active,
        },
        &custody2,
        &key2,
    )
    .await
    .unwrap();

    let result = tracker.validate_and_advance(&env2);
    assert!(result.is_err(), "duplicate sequence should be rejected");
    assert!(
        matches!(
            result.unwrap_err(),
            scp_core::envelope::EnvelopeError::SequenceRegression {
                received_sequence: 5,
                last_seen_sequence: 5,
                ..
            }
        ),
        "expected SequenceRegression"
    );
}

// ===========================================================================
// Content access attacks
// ===========================================================================

// ---------------------------------------------------------------------------
// 24. cek_unwrap_with_wrong_key_fails
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cek_unwrap_with_wrong_key_fails() {
    let correct_key = generate_access_key("ctx-cek-attack", "did:dht:z6MkAlice");
    let wrong_key = generate_access_key("ctx-cek-attack", "did:dht:z6MkAttacker");
    let cek = ContentEncryptionKey::generate();

    let wrapped = wrap_cek(&cek, &correct_key).unwrap();

    // Attempt to unwrap with the wrong access key.
    let result = unwrap_cek(&wrapped, &wrong_key);
    assert!(
        result.is_err(),
        "CEK unwrap with wrong access key must fail"
    );
}

// ===========================================================================
// Participation admission attacks
// ===========================================================================

fn make_test_event(
    event_type: EventType,
    actor_did: &str,
    timestamp: u64,
    sequence: u64,
    payload: Vec<u8>,
) -> Event {
    Event {
        event_type,
        actor_did: actor_did.into(),
        timestamp,
        sequence,
        payload: EventPayload { data: payload },
        prev_hash: [0u8; 32],
        signature: vec![0u8; 64],
    }
}

// ---------------------------------------------------------------------------
// 25. forged_participation_profile_signature_rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn forged_participation_profile_signature_rejected() {
    let alice_did = "did:dht:z6MkAliceAdmission";
    let context_key_material = [42u8; 32];
    let merkle_root = [0u8; 32];

    let events = vec![
        make_test_event(EventType::MessageSent, alice_did, 1000, 0, vec![]),
        make_test_event(EventType::MessageSent, alice_did, 2000, 1, vec![]),
    ];

    let mut profile = produce_participation_profile(
        &context_key_material,
        "ctx-forged",
        alice_did,
        &ParticipationInput {
            events: &events,
            merkle_root,
            is_member: true,
            is_opted_in: true,
            current_time: 3000,
        },
    )
    .unwrap();

    // Verify original signature is valid.
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let vk = VerifyingKey::from_bytes(&profile.signer_public_key).unwrap();
    let sig = Signature::from_bytes(&profile.signature);
    let signable = profile.signable_bytes();
    assert!(
        vk.verify(&signable, &sig).is_ok(),
        "original signature should verify"
    );

    // Forge: tamper with the participation data.
    profile.outlet_invocation_count = 9999;

    // Signature check should fail after tampering.
    let tampered_signable = profile.signable_bytes();
    let tampered_sig = Signature::from_bytes(&profile.signature);
    let tampered_result = vk.verify(&tampered_signable, &tampered_sig);
    assert!(
        tampered_result.is_err(),
        "forged participation profile must fail signature verification"
    );
}

// ---------------------------------------------------------------------------
// 26. stale_participation_profile_rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn stale_participation_profile_rejected() {
    let alice_did = "did:dht:z6MkAliceStale";
    let context_key_material = [55u8; 32];
    let merkle_root = [0u8; 32];

    let events = vec![
        make_test_event(EventType::MessageSent, alice_did, 1000, 0, vec![]),
        make_test_event(EventType::MessageSent, alice_did, 2000, 1, vec![]),
    ];

    let profile = produce_participation_profile(
        &context_key_material,
        "ctx-stale",
        alice_did,
        &ParticipationInput {
            events: &events,
            merkle_root,
            is_member: true,
            is_opted_in: true,
            current_time: 3000, // profile created at time 3000
        },
    )
    .unwrap();

    // Requirement: max_age_secs = 60 (profile must be recent).
    let requirements = vec![RequireParticipation {
        fact: ParticipationFact::ParticipationDuration,
        threshold: ParticipationThreshold::AtLeast(500),
        max_age_secs: 60,
        min_contexts: 1,
    }];

    // Verify at time 4000 (profile is 1000 seconds old, exceeds 60s max_age).
    let result = verify_participation_requirements(4000, &requirements, &[profile]);
    assert!(
        result.is_err(),
        "stale participation profile (1000s old, max 60s) must be rejected"
    );
}

// ===========================================================================
// Sender key exchange attacks
// ===========================================================================

// ---------------------------------------------------------------------------
// 27. sender_key_request_blocked_did_denied
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sender_key_request_blocked_did_denied() {
    let requester_custody = InMemoryKeyCustody::from_seed(270);
    let requester_key = requester_custody
        .generate_keypair(KeyType::Ed25519)
        .await
        .unwrap();
    let requester_pub = requester_custody.public_key(&requester_key).await.unwrap();
    let requester_did = "did:dht:z6MkBlockedRequester";
    let sender_did = "did:dht:z6MkSenderExchange";

    let sender_key = generate_sender_key();

    // Create a request.
    let clock = scp_primitives::SystemClock;
    let request_result = request_sender_key(
        &requester_custody,
        &requester_key,
        requester_did,
        sender_did,
        1,
        &clock,
    )
    .await
    .unwrap();

    let request: SenderKeyRequest = rmp_serde::from_slice(&request_result.request_message).unwrap();

    // Add the requester to the block list.
    let mut block_list: HashSet<String> = HashSet::new();
    block_list.insert(requester_did.to_owned());

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let params = HandleRequestParams {
        sender_key: &sender_key,
        context_id: "ctx-blocked-exchange",
        sender_did,
        epoch: 1,
        block_list: &block_list,
        context_members: None,
        now_secs,
    };
    let mut nonce_dedup = NonceDedup::new();

    let response = handle_sender_key_request(
        &request,
        requester_pub.as_bytes(),
        &params,
        &mut nonce_dedup,
    )
    .await
    .unwrap();

    assert!(
        response.is_none(),
        "blocked requester should get None response (denied)"
    );
}

// ===========================================================================
// Identity attacks (additional: UCAN self-delegation and key scope)
// ===========================================================================

// ---------------------------------------------------------------------------
// 28. self_delegation_without_key_scope_rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn self_delegation_without_key_scope_rejected() {
    use scp_core::crypto::ucan::mint::{MintParams, mint_ucan};

    let custody = InMemoryKeyCustody::from_seed(280);
    let issuer_key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
    let issuer_pk: [u8; 32] = custody
        .public_key(&issuer_key)
        .await
        .unwrap()
        .into_bytes()
        .try_into()
        .unwrap();

    let issuer_did = format!("did:dht:z6Mk{}", hex::encode(&issuer_pk[..8]));
    let capabilities = vec!["messages:write".to_owned()];
    let ceiling: HashSet<String> = std::iter::once("messages:write".to_owned()).collect();

    // Self-delegation: iss == aud, NO key_scope.
    // mint_ucan enforces ADR-039 and rejects this at mint time (defense layer 1).
    let params = MintParams {
        issuer_did: &issuer_did,
        issuer_key: &issuer_key,
        audience_did: &issuer_did,
        context_id: "ctx-self-deleg-atk",
        capabilities: &capabilities,
        lifetime_secs: 3600,
        not_before: None,
        proofs: vec![],
        facts: None,
        key_scope: None,
        signing_key_id: None,
        ceiling: Some(ceiling.clone()),
    };

    let result = mint_ucan(&params, &custody, &scp_primitives::SystemClock).await;
    assert!(
        result.is_err(),
        "self-delegation without key_scope must be rejected at mint time"
    );
    let err = result.unwrap_err();
    assert!(
        matches!(err, UcanError::MalformedToken(ref msg) if msg.contains("self-delegation")),
        "expected MalformedToken mentioning self-delegation, got: {err:?}"
    );

    // Verify that self-delegation WITH key_scope succeeds (positive control).
    let params_with_scope = MintParams {
        issuer_did: &issuer_did,
        issuer_key: &issuer_key,
        audience_did: &issuer_did,
        context_id: "ctx-self-deleg-atk",
        capabilities: &capabilities,
        lifetime_secs: 3600,
        not_before: None,
        proofs: vec![],
        facts: None,
        key_scope: Some("#active".to_owned()),
        signing_key_id: None,
        ceiling: Some(ceiling.clone()),
    };
    let ok_token = mint_ucan(&params_with_scope, &custody, &scp_primitives::SystemClock).await;
    assert!(
        ok_token.is_ok(),
        "self-delegation WITH key_scope should succeed: {:?}",
        ok_token.unwrap_err()
    );
}

// ---------------------------------------------------------------------------
// 29. ucan_kid_scope_mismatch_rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ucan_kid_scope_mismatch_rejected() {
    use scp_core::crypto::ucan::mint::{MintParams, mint_ucan};
    use scp_core::crypto::ucan::validate::{ValidationContext, validate_ucan};

    let custody = InMemoryKeyCustody::from_seed(290);
    let issuer_key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
    let issuer_pk: [u8; 32] = custody
        .public_key(&issuer_key)
        .await
        .unwrap()
        .into_bytes()
        .try_into()
        .unwrap();

    let issuer_did = format!("did:dht:z6Mk{}", hex::encode(&issuer_pk[..8]));
    let capabilities = vec!["messages:write".to_owned()];
    let ceiling: HashSet<String> = std::iter::once("messages:write".to_owned()).collect();

    // Mint with key_scope="#active" (sets both kid and fct.scp_key_scope).
    let params = MintParams {
        issuer_did: &issuer_did,
        issuer_key: &issuer_key,
        audience_did: &issuer_did,
        context_id: "ctx-kid-mismatch-atk",
        capabilities: &capabilities,
        lifetime_secs: 3600,
        not_before: None,
        proofs: vec![],
        facts: None,
        key_scope: Some("#active".to_owned()),
        signing_key_id: None,
        ceiling: Some(ceiling.clone()),
    };

    let mut token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
        .await
        .unwrap();

    // Tamper: set kid to "#agent" while fct still says "#active".
    token.header.kid = Some("#agent".to_owned());

    let mut resolver_keys = HashMap::new();
    resolver_keys.insert(issuer_did.clone(), issuer_pk);
    let did_resolver = InMemoryDidResolver::from_keys(resolver_keys);
    let revocation_checker = InMemoryRevocationChecker::new();
    let proof_resolver = InMemoryProofResolver::new();

    struct KidMismatchNonceTracker(HashSet<String>);
    impl NonceTracker for KidMismatchNonceTracker {
        fn check_replay(&self, nonce: &str, _: u64) -> Result<(), UcanError> {
            if self.0.contains(nonce) {
                return Err(UcanError::NonceReused(nonce.to_owned()));
            }
            Ok(())
        }

        fn record(&mut self, nonce: &str, token_expiry: u64) -> Result<(), UcanError> {
            self.check_replay(nonce, token_expiry)?;
            self.0.insert(nonce.to_owned());
            Ok(())
        }
    }

    let mut nonce_tracker = KidMismatchNonceTracker(HashSet::new());
    let required_cap = CapabilityUri::new("ctx-kid-mismatch-atk", "messages", "write");

    let mut ctx = ValidationContext {
        did_resolver: &did_resolver,
        nonce_tracker: &mut nonce_tracker,
        revocation_checker: &revocation_checker,
        proof_resolver: &proof_resolver,
        ceiling: &ceiling,
        context_creator_did: &issuer_did,
        presenting_agent_did: &issuer_did,
        clock_skew_tolerance_secs: 300,
        clock: &scp_primitives::SystemClock,
        caveat_resolver: &scp_protocol::crypto::ucan::validate::NoCaveatResolver,
    };

    let result = validate_ucan(&token, &required_cap, &mut ctx);
    assert!(result.is_err(), "kid/scope mismatch must be rejected");
    // The tampered kid references a verification method (#agent) that doesn't
    // exist on the fabricated DID. The resolver catches this before signature
    // verification reaches the key scope check. This is correct defense-in-depth:
    // the attack is blocked at the resolver level (MalformedToken) because
    // the tampered VM reference can't be resolved.
    let err = result.unwrap_err();
    assert!(
        matches!(
            err,
            UcanError::KeyScopeMismatch { .. }
                | UcanError::SignatureInvalid
                | UcanError::MalformedToken(_)
        ),
        "expected KeyScopeMismatch, SignatureInvalid, or MalformedToken, got: {err:?}"
    );
    // Also verify the second defense layer: register #agent key so the
    // resolver succeeds, then validate_key_scope catches the kid/scope mismatch.
    let mut resolver_keys_with_agent = HashMap::new();
    resolver_keys_with_agent.insert(issuer_did.clone(), issuer_pk);
    let did_resolver_2 = InMemoryDidResolver {
        keys: resolver_keys_with_agent,
        kid_keys: std::iter::once(((issuer_did.clone(), "#agent".to_owned()), issuer_pk)).collect(),
    };
    let revocation_checker_2 = InMemoryRevocationChecker::new();
    let proof_resolver_2 = InMemoryProofResolver::new();

    struct KidMismatchNonceTracker2(HashSet<String>);
    impl NonceTracker for KidMismatchNonceTracker2 {
        fn check_replay(&self, nonce: &str, _: u64) -> Result<(), UcanError> {
            if self.0.contains(nonce) {
                return Err(UcanError::NonceReused(nonce.to_owned()));
            }
            Ok(())
        }

        fn record(&mut self, nonce: &str, token_expiry: u64) -> Result<(), UcanError> {
            self.check_replay(nonce, token_expiry)?;
            self.0.insert(nonce.to_owned());
            Ok(())
        }
    }

    let mut nonce_tracker_2 = KidMismatchNonceTracker2(HashSet::new());
    let required_cap_2 = CapabilityUri::new("ctx-kid-mismatch-atk", "messages", "write");

    let mut ctx_2 = ValidationContext {
        did_resolver: &did_resolver_2,
        nonce_tracker: &mut nonce_tracker_2,
        revocation_checker: &revocation_checker_2,
        proof_resolver: &proof_resolver_2,
        ceiling: &ceiling,
        context_creator_did: &issuer_did,
        presenting_agent_did: &issuer_did,
        clock_skew_tolerance_secs: 300,
        clock: &scp_primitives::SystemClock,
        caveat_resolver: &scp_protocol::crypto::ucan::validate::NoCaveatResolver,
    };

    let result_2 = validate_ucan(&token, &required_cap_2, &mut ctx_2);
    assert!(
        result_2.is_err(),
        "kid/scope mismatch must be rejected (layer 2)"
    );
    let err_2 = result_2.unwrap_err();
    // With the #agent key registered (same key material), the signature verifies
    // because verify_signature uses the original `encoded` string (not the
    // tampered deserialized header). Then validate_key_scope catches the mismatch:
    // kid="#agent" (from deserialized header) != fct.scp_key_scope="#active".
    assert!(
        matches!(err_2, UcanError::KeyScopeMismatch { .. }),
        "expected KeyScopeMismatch (layer 2), got: {err_2:?}"
    );
}

// ===========================================================================
// Governance attacks (additional: ThresholdEngine voting window)
// ===========================================================================

// ---------------------------------------------------------------------------
// 30. threshold_voting_after_window_expired
// ---------------------------------------------------------------------------

#[tokio::test]
async fn threshold_voting_after_window_expired() {
    let signers = vec![alice_did(), bob_did(), carol_did()];
    let mut engine = ThresholdEngine::new(signers, 2, 300, mock_resolver()).unwrap();

    let now = 1_700_000_000;
    let ctx = governance_context(
        "ctx-threshold-expired",
        &[
            (alice_did(), "admin"),
            (bob_did(), "admin"),
            (carol_did(), "admin"),
        ],
        &[alice_did(), bob_did(), carol_did()],
        now,
    );

    let (proposal, _) = engine
        .propose(
            &alice_did(),
            GovernanceAction::CloseContext { reason: None },
            &ctx,
            &sk_for(1),
        )
        .unwrap();

    // Advance past voting deadline.
    let expired_ctx = governance_context(
        "ctx-threshold-expired",
        &[
            (alice_did(), "admin"),
            (bob_did(), "admin"),
            (carol_did(), "admin"),
        ],
        &[alice_did(), bob_did(), carol_did()],
        now + 301,
    );

    let result = engine.approve(&proposal.proposal_id, &bob_did(), &expired_ctx, &sk_for(2));
    assert!(result.is_err());
    assert!(
        matches!(
            result.unwrap_err(),
            GovernanceError::VotingWindowExpired { .. }
        ),
        "expected VotingWindowExpired"
    );
}

// ---------------------------------------------------------------------------
// 31. delayed_messages_reorderable_by_sequence
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delayed_messages_reorderable_by_sequence() {
    // Store messages with sequence numbers embedded in payload.
    // Even if they arrive out of order, the sequence field allows reconstruction.
    let mut relay = InMemoryRelay::new();
    let routing_id = [0xEE; 32];
    let (_sub_id, mut rx) = relay.subscribe(routing_id);

    // Simulate out-of-order delivery by storing messages in scrambled order.
    let messages: Vec<(u64, &[u8])> = vec![(3, b"msg-3"), (1, b"msg-1"), (2, b"msg-2")];

    for (seq, data) in &messages {
        let mut payload = seq.to_be_bytes().to_vec();
        payload.extend_from_slice(data);
        relay.store(routing_id, payload, None, 4000 + seq);
    }

    // Collect received messages (arrive in store order: 3, 1, 2).
    let mut received: Vec<(u64, Vec<u8>)> = Vec::new();
    while let Ok(msg) = rx.try_recv() {
        let seq = u64::from_be_bytes(msg.data[..8].try_into().unwrap());
        let data = msg.data[8..].to_vec();
        received.push((seq, data));
    }

    // Sort by sequence field to restore original order.
    received.sort_by_key(|(seq, _)| *seq);
    assert_eq!(received[0].0, 1);
    assert_eq!(received[1].0, 2);
    assert_eq!(received[2].0, 3);
    assert_eq!(received[0].1, b"msg-1");
    assert_eq!(received[1].1, b"msg-2");
    assert_eq!(received[2].1, b"msg-3");
}
