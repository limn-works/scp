#![allow(
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::redundant_field_names,
    clippy::cast_possible_truncation
)]
//! Integration tests: behavioral validation with event log Merkle operations.
//!
//! These three tests verify that `compute_behavioral_record` (scp-core trust
//! module) integrates correctly with event log checkpointing and pruning
//! (scp-event-log). They were originally in checkpoint.rs and pruning.rs
//! within the event log module, removed during the scp-event-log extraction
//! (PR #199) because they cross the crate boundary. Restored here as
//! scp-core integration tests per the original extraction plan.
//!
//! Covers SCP-125 AC6: behavioral validation continues to work with
//! checkpointed and pruned event logs.

use sha2::{Digest, Sha256};

use scp_core::trust::compute_behavioral_record;
use scp_event_log::checkpoint::ConsistencyCheckpoint;
use scp_event_log::pruning::{PruningConfig, prune_before_checkpoint};
use scp_event_log::test_helpers::{TestSigner, did_from_pubkey, sign_event, test_keypair};
use scp_event_log::tree::{self, GENESIS_PREV_HASH};
use scp_event_log::{Event, EventLog, EventType};

// ---------------------------------------------------------------------------
// Local test helpers
// ---------------------------------------------------------------------------

/// Computes the RFC 6962 Merkle root from a slice of leaf hashes.
///
/// This is a pure computation that does not require `push_leaf_raw` (which
/// is `pub(crate)` in scp-event-log). The algorithm mirrors
/// `tree::recompute_raw`: leaves are hashed with 0x01 prefix concatenation
/// at each interior level.
fn merkle_root_from_leaves(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut current_layer: Vec<[u8; 32]> = leaves.to_vec();
    while current_layer.len() > 1 {
        let mut next_layer = Vec::new();
        let mut i = 0;
        while i < current_layer.len() {
            if i + 1 < current_layer.len() {
                let mut h = Sha256::new();
                h.update([0x01]);
                h.update(current_layer[i]);
                h.update(current_layer[i + 1]);
                next_layer.push(h.finalize().into());
                i += 2;
            } else {
                // Odd node promoted to next level.
                next_layer.push(current_layer[i]);
                i += 1;
            }
        }
        current_layer = next_layer;
    }
    current_layer[0]
}

/// Builds an event log with `n` events and returns the log, events, and leaf
/// hashes. All events come from a single actor. The first event is
/// `ContextCreated`, every 5th is `GovernanceAction`, and the rest are
/// `MessageSent`.
fn build_log_with_events(n: u64, start_timestamp: u64) -> (EventLog, Vec<Event>, Vec<[u8; 32]>) {
    let (verifying_key, signing_key) = test_keypair();
    let did = did_from_pubkey(&verifying_key);
    let mut log = EventLog::new("ctx-prune-test".to_owned());
    let mut prev_hash = GENESIS_PREV_HASH;
    let mut events = Vec::new();
    let mut leaf_hashes = Vec::new();

    for i in 0..n {
        let event_type = if i == 0 {
            EventType::ContextCreated
        } else if i % 5 == 0 {
            EventType::GovernanceAction
        } else {
            EventType::MessageSent
        };

        let event = sign_event(
            event_type,
            &did,
            start_timestamp + i * 100,
            i,
            format!("event-{i}").into_bytes(),
            prev_hash,
            &signing_key,
        );
        tree::append(&mut log, &event).expect("append should succeed");

        let serialized = rmp_serde::to_vec(&event).expect("serialization should succeed");
        let mut hasher = Sha256::new();
        hasher.update([0x00]);
        hasher.update(&serialized);
        let leaf_hash: [u8; 32] = hasher.finalize().into();

        leaf_hashes.push(leaf_hash);
        events.push(event);
        prev_hash = leaf_hash;
    }

    (log, events, leaf_hashes)
}

/// Creates a mock checkpoint at the given event count by computing the
/// Merkle root from the first `event_count` leaf hashes.
fn make_checkpoint(
    log: &EventLog,
    context_id: &str,
    event_count: u64,
    timestamp: u64,
) -> ConsistencyCheckpoint {
    let leaves = log.leaves();
    let subset: Vec<[u8; 32]> = leaves.iter().take(event_count as usize).copied().collect();
    let merkle_root = merkle_root_from_leaves(&subset);

    ConsistencyCheckpoint {
        context_id: context_id.to_owned(),
        sender_did: "did:key:admin".into(),
        event_count,
        merkle_root,
        epoch: Some(1),
        timestamp,
        signature: vec![0u8; 64],
    }
}

// ---------------------------------------------------------------------------
// Test 1: behavioral validation with checkpointed log
// ---------------------------------------------------------------------------

/// Exercises behavioral record computation against a checkpoint Merkle root
/// with 2 participants and 12 events covering `ContextCreated`, `MemberJoined`,
/// `RoleAssigned`, `MessageSent`, `ToolInvoked`, `GovernanceAction`, `ToolVerified`.
///
/// This is the core assertion of SCP-125 AC6.
#[tokio::test]
async fn behavioral_validation_works_with_checkpointed_log() {
    let (vk_alice, sk_alice) = test_keypair();
    let did_alice = did_from_pubkey(&vk_alice);
    let (vk_bob, sk_bob) = test_keypair();
    let did_bob = did_from_pubkey(&vk_bob);

    let mut log = EventLog::new("ctx-behavioral-checkpoint".to_owned());
    let mut prev_hash = GENESIS_PREV_HASH;
    let mut all_events = Vec::new();

    // Helper closure: append an event and track it.
    let append = |log: &mut EventLog,
                  events: &mut Vec<Event>,
                  event_type: EventType,
                  actor_did: &str,
                  timestamp: u64,
                  seq: u64,
                  payload: Vec<u8>,
                  signing_key: &ed25519_dalek::SigningKey,
                  prev: [u8; 32]|
     -> [u8; 32] {
        let event = sign_event(
            event_type,
            actor_did,
            timestamp,
            seq,
            payload,
            prev,
            signing_key,
        );
        tree::append(log, &event).expect("append should succeed");
        let leaf_hash: [u8; 32] = {
            let mut h = Sha256::new();
            h.update([0x00]);
            h.update(rmp_serde::to_vec(&event).expect("event serialization should succeed"));
            h.finalize().into()
        };
        events.push(event);
        leaf_hash
    };

    // Event 0: Alice creates context.
    prev_hash = append(
        &mut log,
        &mut all_events,
        EventType::ContextCreated,
        &did_alice,
        1_000_000,
        0,
        vec![],
        &sk_alice,
        prev_hash,
    );

    // Event 1: Alice joins.
    prev_hash = append(
        &mut log,
        &mut all_events,
        EventType::MemberJoined,
        &did_alice,
        1_000_001,
        1,
        vec![],
        &sk_alice,
        prev_hash,
    );

    // Event 2: Bob joins.
    prev_hash = append(
        &mut log,
        &mut all_events,
        EventType::MemberJoined,
        &did_bob,
        1_000_002,
        2,
        vec![],
        &sk_bob,
        prev_hash,
    );

    // Event 3: Alice assigns role to Bob.
    prev_hash = append(
        &mut log,
        &mut all_events,
        EventType::RoleAssigned,
        &did_alice,
        1_000_003,
        3,
        did_bob.as_bytes().to_vec(),
        &sk_alice,
        prev_hash,
    );

    // Event 4: Alice sends a message.
    prev_hash = append(
        &mut log,
        &mut all_events,
        EventType::MessageSent,
        &did_alice,
        1_000_004,
        4,
        b"hello from alice".to_vec(),
        &sk_alice,
        prev_hash,
    );

    // Event 5: Bob sends a message.
    prev_hash = append(
        &mut log,
        &mut all_events,
        EventType::MessageSent,
        &did_bob,
        1_000_005,
        5,
        b"hello from bob".to_vec(),
        &sk_bob,
        prev_hash,
    );

    // Event 6: Alice invokes a tool.
    prev_hash = append(
        &mut log,
        &mut all_events,
        EventType::ToolInvoked,
        &did_alice,
        1_000_006,
        6,
        b"search-tool".to_vec(),
        &sk_alice,
        prev_hash,
    );

    // Event 7: Alice invokes the same tool again.
    prev_hash = append(
        &mut log,
        &mut all_events,
        EventType::ToolInvoked,
        &did_alice,
        1_000_007,
        7,
        b"search-tool".to_vec(),
        &sk_alice,
        prev_hash,
    );

    // Event 8: Bob invokes a different tool.
    prev_hash = append(
        &mut log,
        &mut all_events,
        EventType::ToolInvoked,
        &did_bob,
        1_000_008,
        8,
        b"execute-tool".to_vec(),
        &sk_bob,
        prev_hash,
    );

    // Event 9: Alice performs a governance action targeting Bob.
    prev_hash = append(
        &mut log,
        &mut all_events,
        EventType::GovernanceAction,
        &did_alice,
        1_000_009,
        9,
        did_bob.as_bytes().to_vec(),
        &sk_alice,
        prev_hash,
    );

    // Event 10: Alice verifies a tool (attestation-adjacent).
    prev_hash = append(
        &mut log,
        &mut all_events,
        EventType::ToolVerified,
        &did_alice,
        1_000_010,
        10,
        vec![],
        &sk_alice,
        prev_hash,
    );

    // Event 11: Bob sends another message.
    let _ = append(
        &mut log,
        &mut all_events,
        EventType::MessageSent,
        &did_bob,
        1_000_011,
        11,
        b"final message".to_vec(),
        &sk_bob,
        prev_hash,
    );

    assert_eq!(tree::event_count(&log), 12);

    // Create a checkpoint using the TestSigner from scp-event-log.
    let signer = TestSigner::new();
    let checkpoint = scp_event_log::checkpoint::generate_checkpoint(&log, &did_alice, 1, &signer)
        .await
        .expect("checkpoint generation should succeed");

    assert_eq!(checkpoint.event_count, 12);
    assert_eq!(checkpoint.merkle_root, tree::root(&log));

    // Compute behavioral record for Alice using the checkpoint's Merkle root.
    // This is the core assertion of SCP-125 AC6: behavioral validation
    // continues to work with checkpointed logs.
    let record = compute_behavioral_record(
        &all_events,
        &did_alice,
        "ctx-behavioral-checkpoint",
        checkpoint.merkle_root,
        2_000_000,
    )
    .expect("behavioral record computation should succeed");

    // Alice participated in events 0,1,3,4,6,7,9,10 = 8 events.
    assert_eq!(record.participation_count, 8);
    // Duration: 1_000_010 - 1_000_000 = 10 seconds.
    assert_eq!(record.participation_duration_seconds, 10);
    // Tool invocations: search-tool x2.
    assert_eq!(record.tool_invocations.len(), 1);
    assert_eq!(record.tool_invocations.get("search-tool"), Some(&2));
    // Governance actions by Alice: 1 (targeting Bob).
    assert_eq!(record.governance_actions_by.len(), 1);
    // Governance actions against Alice: 0.
    assert_eq!(record.governance_actions_against.len(), 0);
    // Role history for Alice: 0 (Alice assigned Bob, not herself).
    assert_eq!(record.role_history.len(), 0);
    // Attestation history: 1 (ToolVerified event).
    assert_eq!(record.attestation_history.len(), 1);
    // Context creation: 1.
    assert_eq!(record.context_creation_count, 1);
    // Merkle root matches checkpoint.
    assert_eq!(record.event_log_root, checkpoint.merkle_root);

    // Also verify Bob's behavioral record against the same checkpoint.
    let bob_record = compute_behavioral_record(
        &all_events,
        &did_bob,
        "ctx-behavioral-checkpoint",
        checkpoint.merkle_root,
        2_000_000,
    )
    .expect("Bob's behavioral record computation should succeed");

    // Bob participated in events 2,5,8,11 = 4 events.
    assert_eq!(bob_record.participation_count, 4);
    // Duration: 1_000_011 - 1_000_002 = 9 seconds.
    assert_eq!(bob_record.participation_duration_seconds, 9);
    // Bob's tool invocations: execute-tool x1.
    assert_eq!(bob_record.tool_invocations.len(), 1);
    assert_eq!(bob_record.tool_invocations.get("execute-tool"), Some(&1));
    // Bob is the target of Alice's governance action.
    assert_eq!(bob_record.governance_actions_against.len(), 1);
    // Bob was assigned a role.
    assert_eq!(bob_record.role_history.len(), 1);
    assert_eq!(bob_record.event_log_root, checkpoint.merkle_root);
}

// ---------------------------------------------------------------------------
// Test 2: behavioral validation after pruning
// ---------------------------------------------------------------------------

/// Tests that behavioral validation continues to work after event log
/// pruning. Builds a log with 20 events from two participants, prunes the
/// first 10, and validates behavioral records against the tail log root.
#[test]
fn behavioral_validation_works_after_pruning() {
    let (verifying_key, signing_key) = test_keypair();
    let did = did_from_pubkey(&verifying_key);
    let (verifying_key2, signing_key2) = test_keypair();
    let did2 = did_from_pubkey(&verifying_key2);

    let mut log = EventLog::new("ctx-behavior-test".to_owned());
    let mut prev_hash = GENESIS_PREV_HASH;
    let mut all_events = Vec::new();

    // Pre-checkpoint events (will be pruned).
    for i in 0..10u64 {
        let (actor_did, skey): (&str, &ed25519_dalek::SigningKey) = if i % 2 == 0 {
            (&did, &signing_key)
        } else {
            (&did2, &signing_key2)
        };

        let event = sign_event(
            EventType::MessageSent,
            actor_did,
            1_000_000 + i * 100,
            i,
            format!("pre-checkpoint-{i}").into_bytes(),
            prev_hash,
            skey,
        );
        tree::append(&mut log, &event).expect("append should succeed");
        let serialized = rmp_serde::to_vec(&event).expect("event serialization should succeed");
        let mut h = Sha256::new();
        h.update([0x00]);
        h.update(&serialized);
        prev_hash = h.finalize().into();
        all_events.push(event);
    }

    // Post-checkpoint events (retained).
    for i in 10..20u64 {
        let (actor_did, skey): (&str, &ed25519_dalek::SigningKey) = if i % 2 == 0 {
            (&did, &signing_key)
        } else {
            (&did2, &signing_key2)
        };

        let event = sign_event(
            EventType::MessageSent,
            actor_did,
            1_000_000 + i * 100,
            i,
            format!("post-checkpoint-{i}").into_bytes(),
            prev_hash,
            skey,
        );
        tree::append(&mut log, &event).expect("append should succeed");
        let serialized = rmp_serde::to_vec(&event).expect("event serialization should succeed");
        let mut h = Sha256::new();
        h.update([0x00]);
        h.update(&serialized);
        prev_hash = h.finalize().into();
        all_events.push(event);
    }

    // Create checkpoint at event 10 and prune.
    let checkpoint = make_checkpoint(&log, "ctx-behavior-test", 10, 1_001_000);

    let config = PruningConfig {
        retain_last_n_checkpoints: None,
        retention_secs: None,
        structural_retention_multiplier: 1.0,
    };

    let (truncated, result) =
        prune_before_checkpoint(&log, &checkpoint, &all_events, &config, 2_000_000)
            .expect("pruning should succeed");

    assert_eq!(result.events_pruned, 10);

    // Behavioral validation should work with just the post-checkpoint events.
    let post_checkpoint_events = &all_events[10..];
    let tail_root = tree::root(truncated.tail_log());

    let record = compute_behavioral_record(
        post_checkpoint_events,
        &did,
        "ctx-behavior-test",
        tail_root,
        2_000_000,
    )
    .expect("behavioral record computation should succeed");

    // Subject participated in events 10, 12, 14, 16, 18 (even indices).
    assert_eq!(record.participation_count, 5);
    assert!(record.participation_duration_seconds > 0);
}

// ---------------------------------------------------------------------------
// Test 3: behavioral validation with full (unpruned) event set
// ---------------------------------------------------------------------------

/// Tests behavioral validation with the full event set (no pruning).
/// Ensures the basic integration path works without any truncation.
#[test]
fn behavioral_validation_with_full_event_set() {
    let (log, events, _) = build_log_with_events(10, 1_000_000);
    let merkle_root = tree::root(&log);

    let actor_did = &events[0].actor_did;
    let record =
        compute_behavioral_record(&events, actor_did, "ctx-prune-test", merkle_root, 2_000_000)
            .expect("behavioral record computation should succeed");

    assert_eq!(record.participation_count, 10);
}
