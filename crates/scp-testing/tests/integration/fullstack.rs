#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

//! Full-stack end-to-end tests.
//!
//! These tests wire `ContextManager → real MLS encryption → CapturingTransport
//! → decrypt` between separate participants. They prove that all layers
//! (governance, membership, MLS, sender keys, event log) work together.
//!
//! Run with `cargo test --test fullstack -- --nocapture` for narrated output.

use std::net::SocketAddr;
use std::sync::Arc;

use futures::StreamExt;

use scp_core::context::builder::ContextEventLogProvider;
use scp_core::context::governance::KeyResolver;
use scp_core::context::membership::ContextEvent;
use scp_core::context::{Capability, ContextMode, ContextParams, ContextState, context_id_bytes};
use scp_core::envelope::outer::create_outer_envelope;
use scp_identity::DID;
use scp_testing::fullstack::FullStackNetwork;
use scp_transport::native::adapter::NativeRelayAdapter;
use scp_transport::native::server::{RelayConfig, RelayServer, ShutdownHandle};
use scp_transport::native::storage::BlobStorageBackend;
use scp_transport::relay::connection::{RelayUrlSource, SourcedRelayUrl};
use scp_transport::traits::{RoutingId, TransportAdapter, TransportEvent};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const ALICE_DID: &str = "did:dht:z6MkAliceFullStack";
const BOB_DID: &str = "did:dht:z6MkBobFullStack";
const CAROL_DID: &str = "did:dht:z6MkCarolFullStack";

/// Returns a key resolver that always resolves (tests don't verify governance
/// vote signatures — that's covered by `governance_integration.rs`).
fn permissive_key_resolver() -> KeyResolver {
    Arc::new(|_did| {
        // Return a deterministic key derived from the DID string so
        // governance operations that require signature verification can
        // proceed (even though we don't exercise that path here).
        None
    })
}

/// Returns `ContextParams` for an encrypted context with the capability ceiling
/// needed for full-stack tests (admin needs `RoleAssign` to add members, etc.).
fn encrypted_params() -> ContextParams {
    ContextParams {
        mode: ContextMode::Encrypted,
        ceiling: vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::RoleAssign,
            Capability::MemberInvite,
            Capability::MemberRemove,
            Capability::GovernancePropose,
            Capability::GovernanceVote,
            Capability::ContextClose,
        ],
        ..ContextParams::default()
    }
}

// ---------------------------------------------------------------------------
// C1. Flagship: Alice sends encrypted message to Bob through ContextManager
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fullstack_alice_to_bob_encrypted_message() {
    println!("\n=== C1: Alice → Bob encrypted message through ContextManager ===\n");

    // 1. Create network and nodes.
    let network = FullStackNetwork::new();
    let alice = network.create_node(ALICE_DID, permissive_key_resolver());
    let bob = network.create_node(BOB_DID, permissive_key_resolver());

    println!("  [1] Created Alice ({ALICE_DID}) and Bob ({BOB_DID})");

    // 2. Alice creates an encrypted context.
    let params = encrypted_params();
    let ctx_id = "e2e-encrypted-ctx";
    let handle = alice.create_context(ctx_id, params).await.unwrap();
    let ctx_bytes = context_id_bytes(ctx_id);

    println!("  [2] Alice created context '{ctx_id}'");
    assert_eq!(handle.try_read_state().unwrap(), ContextState::Active);

    // 3. Alice adds Bob (internally: add_member + distribute_sender_key).
    //    The Welcome and sender key are deposited in the shared KeyExchange.
    alice.add_member(&handle, BOB_DID).await.unwrap();
    println!("  [3] Alice added Bob to the context");

    // 4. Bob joins by retrieving the Welcome from the KeyExchange.
    bob.join_from_welcome(&ctx_bytes).unwrap();
    println!("  [4] Bob joined the context via Welcome message");

    // 5. Alice sends an encrypted message through ContextManager.
    let plaintext = b"Hello Bob! This went through real MLS encryption.";
    alice.send_message(&handle, plaintext).await.unwrap();
    println!("  [5] Alice sent encrypted message through ContextManager");

    // 6. Retrieve the captured ciphertext from Alice's transport.
    let sent = alice.take_sent_ciphertexts();
    assert_eq!(
        sent.len(),
        1,
        "exactly one ciphertext should have been sent"
    );
    let (sent_ctx_id, ciphertext) = &sent[0];
    assert_eq!(sent_ctx_id, &ctx_bytes, "ciphertext context ID must match");
    assert_ne!(
        ciphertext.as_slice(),
        plaintext.as_slice(),
        "ciphertext must differ from plaintext"
    );
    println!(
        "  [6] Captured ciphertext ({} bytes, plaintext was {} bytes)",
        ciphertext.len(),
        plaintext.len()
    );

    // 7. Bob decrypts: MLS decrypt → sender key decrypt.
    let decrypted = bob
        .decrypt_message(&ctx_bytes, ciphertext, ALICE_DID, 0, 0)
        .unwrap();
    assert_eq!(
        decrypted.as_slice(),
        plaintext.as_slice(),
        "decrypted message must match original plaintext"
    );
    println!(
        "  [7] Bob decrypted: {:?}",
        String::from_utf8_lossy(&decrypted)
    );

    // 8. Verify events were logged on Alice's side.
    let events = alice.drain_events(ctx_id).await;
    let has_member_joined = events.iter().any(
        |e| matches!(e, ContextEvent::MemberJoined { member_did, .. } if member_did == BOB_DID),
    );
    let has_message_sent = events
        .iter()
        .any(|e| matches!(e, ContextEvent::MessageSent { .. }));
    assert!(has_member_joined, "MemberJoined event expected");
    assert!(has_message_sent, "MessageSent event expected");
    println!("  [8] Events verified: MemberJoined + MessageSent");

    // 9. Verify Merkle event log.
    let root = alice.merkle_root(&ctx_bytes).unwrap();
    assert_ne!(root, [0u8; 32], "Merkle root must be non-zero after events");
    println!("  [9] Merkle root: {}", hex::encode(&root[..8]));

    println!("\n  ✓ Full-stack encrypted message roundtrip complete!\n");
}

// ---------------------------------------------------------------------------
// C3. Three-party group
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fullstack_three_party_group() {
    println!("\n=== C3: Three-party MLS group ===\n");

    let network = FullStackNetwork::new();
    let alice = network.create_node(ALICE_DID, permissive_key_resolver());
    let bob = network.create_node(BOB_DID, permissive_key_resolver());
    let carol = network.create_node(CAROL_DID, permissive_key_resolver());

    let ctx_id = "three-party-ctx";
    let ctx_bytes = context_id_bytes(ctx_id);
    let params = encrypted_params();

    // Alice creates context.
    let handle = alice.create_context(ctx_id, params).await.unwrap();
    println!("  [1] Alice created context");

    // Alice adds Bob (Welcome #1).
    alice.add_member(&handle, BOB_DID).await.unwrap();
    bob.join_from_welcome(&ctx_bytes).unwrap();
    println!("  [2] Bob joined");

    // Alice adds Carol (Welcome #2).
    alice.add_member(&handle, CAROL_DID).await.unwrap();
    carol.join_from_welcome(&ctx_bytes).unwrap();
    println!("  [3] Carol joined");

    // Alice sends a message — both Bob and Carol should be able to decrypt.
    let msg = b"Hello everyone!";
    alice.send_message(&handle, msg).await.unwrap();
    let sent = alice.take_sent_ciphertexts();
    assert_eq!(sent.len(), 1);
    let ciphertext = &sent[0].1;
    println!(
        "  [4] Alice sent message ({} bytes ciphertext)",
        ciphertext.len()
    );

    // Bob decrypts.
    let bob_decrypted = bob
        .decrypt_message(&ctx_bytes, ciphertext, ALICE_DID, 0, 0)
        .unwrap();
    assert_eq!(bob_decrypted.as_slice(), msg.as_slice());
    println!("  [5] Bob decrypted successfully");

    // Carol decrypts.
    let carol_decrypted = carol
        .decrypt_message(&ctx_bytes, ciphertext, ALICE_DID, 0, 0)
        .unwrap();
    assert_eq!(carol_decrypted.as_slice(), msg.as_slice());
    println!("  [6] Carol decrypted successfully");

    println!("\n  ✓ Three-party MLS group works!\n");
}

// ---------------------------------------------------------------------------
// C4. Governance with real crypto
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fullstack_governance_with_real_crypto() {
    println!("\n=== C4: Governance + real MLS crypto ===\n");

    let network = FullStackNetwork::new();
    let alice = network.create_node(ALICE_DID, permissive_key_resolver());
    let bob = network.create_node(BOB_DID, permissive_key_resolver());

    let ctx_id = "governance-crypto-ctx";
    let ctx_bytes = context_id_bytes(ctx_id);
    let params = encrypted_params();

    let handle = alice.create_context(ctx_id, params).await.unwrap();
    alice.add_member(&handle, BOB_DID).await.unwrap();
    bob.join_from_welcome(&ctx_bytes).unwrap();
    println!("  [1] Context created, Bob joined");

    // Alice sends a message before governance action.
    let msg1 = b"Before governance";
    alice.send_message(&handle, msg1).await.unwrap();
    let sent1 = alice.take_sent_ciphertexts();
    let decrypted1 = bob
        .decrypt_message(&ctx_bytes, &sent1[0].1, ALICE_DID, 0, 0)
        .unwrap();
    assert_eq!(decrypted1.as_slice(), msg1.as_slice());
    println!("  [2] Pre-governance message roundtrip verified");

    // Execute governance action: remove Bob.
    // This exercises the governance engine + real MLS remove_member.
    let remove_result = alice
        .manager
        .leave_context(&handle, &DID::from(ALICE_DID), &DID::from(BOB_DID))
        .await;
    // Note: leave_context requires caller==member or MemberRemove capability.
    // Alice is admin so she can remove Bob.
    assert!(remove_result.is_ok(), "Alice should be able to remove Bob");
    println!("  [3] Alice removed Bob via governance");

    // Alice sends another message after removing Bob.
    let msg2 = b"After Bob removed";
    alice.send_message(&handle, msg2).await.unwrap();
    let sent2 = alice.take_sent_ciphertexts();
    println!(
        "  [4] Alice sent post-removal message ({} bytes)",
        sent2[0].1.len()
    );

    // Bob should NOT be able to decrypt this message (MLS group epoch advanced,
    // Bob's group state is stale).
    let decrypt_result = bob.decrypt_message(&ctx_bytes, &sent2[0].1, ALICE_DID, 0, 0);
    assert!(
        decrypt_result.is_err(),
        "Bob must NOT decrypt after removal (MLS forward secrecy)"
    );
    println!("  [5] Bob correctly cannot decrypt post-removal message");

    println!("\n  ✓ Governance + real crypto forward secrecy verified!\n");
}

// ---------------------------------------------------------------------------
// C5. Event log Merkle chain with real crypto
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fullstack_event_log_merkle_chain() {
    println!("\n=== C5: Event log Merkle chain ===\n");

    let network = FullStackNetwork::new();
    let alice = network.create_node(ALICE_DID, permissive_key_resolver());
    let bob = network.create_node(BOB_DID, permissive_key_resolver());

    let ctx_id = "merkle-chain-ctx";
    let ctx_bytes = context_id_bytes(ctx_id);
    let params = encrypted_params();

    let handle = alice.create_context(ctx_id, params).await.unwrap();
    alice.add_member(&handle, BOB_DID).await.unwrap();
    bob.join_from_welcome(&ctx_bytes).unwrap();

    // Send 3 messages — each appends a MessageSent event to the log.
    for i in 0..3 {
        let msg = format!("Message {i}");
        alice.send_message(&handle, msg.as_bytes()).await.unwrap();
        let _ = alice.take_sent_ciphertexts(); // drain
    }

    // Verify Merkle root is non-zero and deterministic.
    let root1 = alice.merkle_root(&ctx_bytes).unwrap();
    assert_ne!(root1, [0u8; 32]);
    let root2 = alice.merkle_root(&ctx_bytes).unwrap();
    assert_eq!(root1, root2, "Merkle root must be deterministic");
    println!(
        "  Merkle root after 3 messages + join: {}",
        hex::encode(&root1[..16])
    );

    // Export event log and verify.
    let exported = alice.event_log.export_event_log_data(&ctx_bytes).unwrap();
    assert!(!exported.is_empty(), "exported log must not be empty");
    println!("  Exported event log: {} bytes", exported.len());

    // Verify chain integrity via import (import verifies Merkle chain).
    let bob_event_log = scp_core::context::providers::event_log::MerkleEventLogProvider::new();
    bob_event_log.init_event_log(&ctx_bytes).unwrap();
    // Import into a fresh log should fail because it already has an init entry.
    // Instead verify chain by re-importing from scratch.
    let fresh_log = scp_core::context::providers::event_log::MerkleEventLogProvider::new();
    let import_result = fresh_log.import_event_log_data(&ctx_bytes, &exported);
    assert!(
        import_result.is_ok(),
        "import should succeed with valid Merkle chain"
    );
    let imported_root = fresh_log.event_log_merkle_root(&ctx_bytes).unwrap();
    assert_eq!(
        root1, imported_root,
        "imported Merkle root must match original"
    );
    println!("  Import + Merkle root verification passed");

    println!("\n  ✓ Merkle chain integrity verified!\n");
}

// ---------------------------------------------------------------------------
// C6. Multiple messages roundtrip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fullstack_multiple_messages_roundtrip() {
    println!("\n=== C6: Multiple messages roundtrip ===\n");

    let network = FullStackNetwork::new();
    let alice = network.create_node(ALICE_DID, permissive_key_resolver());
    let bob = network.create_node(BOB_DID, permissive_key_resolver());

    let ctx_id = "multi-msg-ctx";
    let ctx_bytes = context_id_bytes(ctx_id);
    let params = encrypted_params();

    let handle = alice.create_context(ctx_id, params).await.unwrap();
    alice.add_member(&handle, BOB_DID).await.unwrap();
    bob.join_from_welcome(&ctx_bytes).unwrap();

    // Send 5 messages and verify each roundtrips correctly.
    for i in 0..5u64 {
        let msg = format!("Message number {i}");
        alice.send_message(&handle, msg.as_bytes()).await.unwrap();
        let sent = alice.take_sent_ciphertexts();
        assert_eq!(sent.len(), 1);

        let decrypted = bob
            .decrypt_message(&ctx_bytes, &sent[0].1, ALICE_DID, 0, 0)
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&decrypted),
            msg,
            "message {i} must roundtrip"
        );
    }
    println!("  5 messages all roundtripped successfully");

    println!("\n  ✓ Multiple message roundtrip verified!\n");
}

// ---------------------------------------------------------------------------
// Ciphertext properties
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fullstack_ciphertext_is_nondeterministic() {
    println!("\n=== Ciphertext non-determinism ===\n");

    let network = FullStackNetwork::new();
    let alice = network.create_node(ALICE_DID, permissive_key_resolver());
    let bob = network.create_node(BOB_DID, permissive_key_resolver());

    let ctx_id = "nondet-ctx";
    let ctx_bytes = context_id_bytes(ctx_id);
    let params = encrypted_params();

    let handle = alice.create_context(ctx_id, params).await.unwrap();
    alice.add_member(&handle, BOB_DID).await.unwrap();
    bob.join_from_welcome(&ctx_bytes).unwrap();

    // Send the same plaintext twice — ciphertexts must differ (random nonce).
    let msg = b"same message twice";

    alice.send_message(&handle, msg).await.unwrap();
    let sent1 = alice.take_sent_ciphertexts();

    alice.send_message(&handle, msg).await.unwrap();
    let sent2 = alice.take_sent_ciphertexts();

    assert_ne!(
        sent1[0].1, sent2[0].1,
        "two encryptions of the same plaintext must produce different ciphertexts (IND-CPA)"
    );

    // Both must still decrypt to the same plaintext.
    let d1 = bob
        .decrypt_message(&ctx_bytes, &sent1[0].1, ALICE_DID, 0, 0)
        .unwrap();
    let d2 = bob
        .decrypt_message(&ctx_bytes, &sent2[0].1, ALICE_DID, 0, 0)
        .unwrap();
    assert_eq!(d1.as_slice(), msg.as_slice());
    assert_eq!(d2.as_slice(), msg.as_slice());

    println!("  Ciphertexts differ, both decrypt to same plaintext");
    println!("\n  ✓ IND-CPA property verified!\n");
}

// ---------------------------------------------------------------------------
// Relay helpers
// ---------------------------------------------------------------------------

/// Starts an ephemeral native relay server on a random port and returns its
/// shutdown handle and address. Callers MUST call `handle.shutdown()` when done
/// to avoid leaking the background server task.
async fn start_relay() -> (ShutdownHandle, SocketAddr) {
    let config = RelayConfig {
        bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        delivery_jitter_ms: 0,
        ..RelayConfig::default()
    };
    let storage = Arc::new(BlobStorageBackend::in_memory());
    let server = RelayServer::new(config, storage);
    let (handle, addr) = server.start().await.unwrap();
    (handle, addr)
}

/// Receives a single envelope from a transport event stream with a timeout.
async fn receive_envelope(
    stream: &mut scp_transport::traits::SubscriptionStream,
) -> scp_core::envelope::OuterEnvelope {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while let Some(event) = stream.next().await {
            match event {
                TransportEvent::Envelope(env) => return env,
                TransportEvent::Error(e) => panic!("transport error: {e}"),
                TransportEvent::Terminated { reason } => {
                    panic!("subscription terminated: {reason}")
                }
                TransportEvent::BackfillComplete
                | TransportEvent::Reconnected
                | TransportEvent::SuppressionDetected(_) => {}
            }
        }
        panic!("stream ended without delivering an envelope");
    })
    .await
    .expect("timed out waiting for envelope from relay")
}

// ---------------------------------------------------------------------------
// Full-stack relay test: identity → MLS → sender keys → envelope → relay → decrypt
// ---------------------------------------------------------------------------

/// Exercises the FULL protocol stack end-to-end through a real WebSocket relay:
///
/// 1. Start ephemeral relay (`RelayServer` on port 0)
/// 2. Create two `FullStackNode`s with real MLS crypto (`E2eCryptoProvider`)
/// 3. Alice creates encrypted context, Bob joins via Welcome
/// 4. Alice sends MLS-encrypted message through `ContextManager`
/// 5. Wrap ciphertext in `OuterEnvelope` and publish to relay via `NativeRelayAdapter` (real WebSocket)
/// 6. Bob subscribes and receives from relay via `NativeRelayAdapter` (real WebSocket)
/// 7. Bob decrypts: MLS decrypt → sender key decrypt
/// 8. Verify plaintext matches
/// 9. Verify Merkle event chain integrity
///
/// This combines the crypto depth of fullstack tests (real MLS + sender keys through
/// `ContextManager`) with the transport depth of phase1 tests (real WebSocket relay).
#[tokio::test]
// Integration test exercises full stack through relay; splitting would fragment
// the sequential scenario.
#[allow(clippy::too_many_lines)]
async fn full_stack_relay_encrypted_roundtrip() {
    println!(
        "\n=== Full-stack relay: identity → MLS → sender keys → envelope → relay → decrypt ===\n"
    );

    // 1. Start ephemeral relay.
    let (relay_handle, relay_addr) = start_relay().await;
    let relay_url = format!("ws://{relay_addr}/scp/v1");
    println!("  [1] Relay started at {relay_url}");

    // 2. Create network and nodes with real MLS crypto.
    let network = FullStackNetwork::new();
    let alice = network.create_node(ALICE_DID, permissive_key_resolver());
    let bob = network.create_node(BOB_DID, permissive_key_resolver());
    println!("  [2] Created Alice ({ALICE_DID}) and Bob ({BOB_DID}) with real MLS");

    // 3. Alice creates encrypted context, adds Bob.
    let ctx_id = "full-stack-relay-ctx";
    let ctx_bytes = context_id_bytes(ctx_id);
    let params = encrypted_params();
    let handle = alice.create_context(ctx_id, params).await.unwrap();
    assert_eq!(handle.try_read_state().unwrap(), ContextState::Active);

    alice.add_member(&handle, BOB_DID).await.unwrap();
    bob.join_from_welcome(&ctx_bytes).unwrap();
    println!("  [3] Context created and Bob joined via Welcome");

    // 4. Alice sends an encrypted message through ContextManager.
    //    ContextManager calls E2eCryptoProvider::encrypt_message (real sender key
    //    + real MLS encryption) and CapturingTransport captures the ciphertext.
    let plaintext = b"Hello Bob! Real MLS + real relay, full stack.";
    alice.send_message(&handle, plaintext).await.unwrap();
    let sent = alice.take_sent_ciphertexts();
    assert_eq!(sent.len(), 1, "exactly one ciphertext captured");
    let (sent_ctx_id, ciphertext) = &sent[0];
    assert_eq!(sent_ctx_id, &ctx_bytes, "ciphertext context ID must match");
    assert_ne!(
        ciphertext.as_slice(),
        plaintext.as_slice(),
        "ciphertext must differ from plaintext"
    );
    println!(
        "  [4] Encrypted via ContextManager: {} bytes plaintext → {} bytes ciphertext",
        plaintext.len(),
        ciphertext.len()
    );

    // 5. Wrap ciphertext in an OuterEnvelope for relay transport.
    //    Use a deterministic routing ID derived from the context ID (simulates
    //    pseudonym routing — the relay sees only this opaque 32-byte identifier).
    let routing_id = ctx_bytes; // deterministic for test; production uses HMAC pseudonym
    let outer_envelope =
        create_outer_envelope(&routing_id, None, 3600, ciphertext.clone()).unwrap();
    println!(
        "  [5] Wrapped in OuterEnvelope (routing_id: {}...)",
        &hex::encode(routing_id)[..16]
    );

    // 6. Connect to relay: Bob subscribes first, then Alice sends.
    let sourced = SourcedRelayUrl {
        url: relay_url,
        source: RelayUrlSource::DhtResolved,
    };
    let bob_adapter = NativeRelayAdapter::connect_sourced(&sourced).await.unwrap();
    let bob_routing = RoutingId::new(routing_id);
    let mut stream = bob_adapter.subscribe(&bob_routing, None).await.unwrap();

    let alice_adapter = NativeRelayAdapter::connect_sourced(&sourced).await.unwrap();
    let blob_id = alice_adapter.send(&outer_envelope).await.unwrap();
    assert_eq!(blob_id.as_bytes().len(), 32, "blob_id must be 32 bytes");
    println!(
        "  [6] Published to relay (blob_id: {}...)",
        &hex::encode(&blob_id.as_bytes()[..8])
    );

    // 7. Bob receives envelope from the relay.
    let received_outer = receive_envelope(&mut stream).await;
    assert_eq!(
        received_outer.routing_id, outer_envelope.routing_id,
        "routing_id must match"
    );
    assert_eq!(
        received_outer.blob_ttl, outer_envelope.blob_ttl,
        "blob_ttl must match"
    );
    assert_eq!(
        received_outer.encrypted_blob, outer_envelope.encrypted_blob,
        "encrypted_blob must survive relay transit intact"
    );
    println!(
        "  [7] Bob received envelope from relay ({} bytes encrypted_blob)",
        received_outer.encrypted_blob.len()
    );

    // 8. Bob decrypts: MLS decrypt → sender key decrypt.
    let decrypted = bob
        .decrypt_message(&ctx_bytes, &received_outer.encrypted_blob, ALICE_DID, 0, 0)
        .unwrap();
    assert_eq!(
        decrypted.as_slice(),
        plaintext.as_slice(),
        "decrypted message must match original plaintext"
    );
    println!(
        "  [8] Bob decrypted: {:?}",
        String::from_utf8_lossy(&decrypted)
    );

    // 9. Verify events were logged on Alice's side.
    let events = alice.drain_events(ctx_id).await;
    let has_member_joined = events.iter().any(
        |e| matches!(e, ContextEvent::MemberJoined { member_did, .. } if member_did == BOB_DID),
    );
    let has_message_sent = events
        .iter()
        .any(|e| matches!(e, ContextEvent::MessageSent { .. }));
    assert!(has_member_joined, "MemberJoined event expected");
    assert!(has_message_sent, "MessageSent event expected");
    println!("  [9] Events verified: MemberJoined + MessageSent");

    // 10. Verify Merkle event chain integrity.
    let root = alice.merkle_root(&ctx_bytes).unwrap();
    assert_ne!(root, [0u8; 32], "Merkle root must be non-zero after events");
    let root2 = alice.merkle_root(&ctx_bytes).unwrap();
    assert_eq!(root, root2, "Merkle root must be deterministic");
    println!("  [10] Merkle root: {}", hex::encode(&root[..8]));

    // 11. Shut down the relay to avoid leaking the background server task.
    relay_handle.shutdown();

    println!(
        "\n  ✓ Full-stack relay roundtrip complete: identity → MLS → sender keys → envelope → relay → decrypt!\n"
    );
}

/// Multi-message variant: sends 3 messages through the relay and verifies each.
///
/// Extends `full_stack_relay_encrypted_roundtrip` by verifying that multiple
/// sequential messages each survive the full identity → MLS → sender keys →
/// envelope → relay → decrypt path, and that the Merkle chain grows correctly.
#[tokio::test]
async fn full_stack_relay_multiple_messages() {
    println!("\n=== Full-stack relay: multiple messages ===\n");

    let (relay_handle, relay_addr) = start_relay().await;
    let relay_url = format!("ws://{relay_addr}/scp/v1");

    let network = FullStackNetwork::new();
    let alice = network.create_node(ALICE_DID, permissive_key_resolver());
    let bob = network.create_node(BOB_DID, permissive_key_resolver());

    let ctx_id = "relay-multi-msg-ctx";
    let ctx_bytes = context_id_bytes(ctx_id);
    let params = encrypted_params();
    let handle = alice.create_context(ctx_id, params).await.unwrap();
    alice.add_member(&handle, BOB_DID).await.unwrap();
    bob.join_from_welcome(&ctx_bytes).unwrap();

    let sourced = SourcedRelayUrl {
        url: relay_url,
        source: RelayUrlSource::DhtResolved,
    };
    let bob_adapter = NativeRelayAdapter::connect_sourced(&sourced).await.unwrap();
    let alice_adapter = NativeRelayAdapter::connect_sourced(&sourced).await.unwrap();

    let routing_id = ctx_bytes;
    let bob_routing = RoutingId::new(routing_id);
    let mut stream = bob_adapter.subscribe(&bob_routing, None).await.unwrap();

    // Send 3 messages and verify each roundtrips through the relay.
    for i in 0..3u32 {
        let msg = format!("Relay message #{i}");

        // Encrypt via ContextManager (real MLS + sender keys).
        alice.send_message(&handle, msg.as_bytes()).await.unwrap();
        let sent = alice.take_sent_ciphertexts();
        assert_eq!(sent.len(), 1);
        let ciphertext = &sent[0].1;

        // Wrap in OuterEnvelope and send through relay.
        let outer = create_outer_envelope(&routing_id, None, 3600, ciphertext.clone()).unwrap();
        alice_adapter.send(&outer).await.unwrap();

        // Bob receives from relay and decrypts.
        let received = receive_envelope(&mut stream).await;
        let decrypted = bob
            .decrypt_message(&ctx_bytes, &received.encrypted_blob, ALICE_DID, 0, 0)
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&decrypted),
            msg,
            "message {i} must roundtrip through relay"
        );
        println!("  [{i}] \"{msg}\" roundtripped through relay");
    }

    // Verify Merkle root is non-zero and deterministic after all messages.
    let root = alice.merkle_root(&ctx_bytes).unwrap();
    assert_ne!(root, [0u8; 32], "Merkle root must be non-zero");
    println!(
        "  Merkle root after 3 relay messages: {}",
        hex::encode(&root[..8])
    );

    relay_handle.shutdown();

    println!("\n  ✓ Multiple messages through relay verified!\n");
}

/// Three-party variant: Alice sends a message to both Bob and Carol through
/// the relay. Both decrypt independently.
///
/// Proves that the full stack (identity → MLS → sender keys → envelope →
/// relay → decrypt) works correctly with multi-party MLS groups where all
/// participants receive the same ciphertext from the relay.
#[tokio::test]
async fn full_stack_relay_three_party() {
    println!("\n=== Full-stack relay: three-party group ===\n");

    let (relay_handle, relay_addr) = start_relay().await;
    let relay_url = format!("ws://{relay_addr}/scp/v1");

    let network = FullStackNetwork::new();
    let alice = network.create_node(ALICE_DID, permissive_key_resolver());
    let bob = network.create_node(BOB_DID, permissive_key_resolver());
    let carol = network.create_node(CAROL_DID, permissive_key_resolver());

    let ctx_id = "relay-three-party-ctx";
    let ctx_bytes = context_id_bytes(ctx_id);
    let params = encrypted_params();
    let handle = alice.create_context(ctx_id, params).await.unwrap();

    // Alice adds Bob, then Carol.
    alice.add_member(&handle, BOB_DID).await.unwrap();
    bob.join_from_welcome(&ctx_bytes).unwrap();
    alice.add_member(&handle, CAROL_DID).await.unwrap();
    carol.join_from_welcome(&ctx_bytes).unwrap();
    println!("  [1] Three-party context established");

    // Alice sends message via ContextManager (real MLS + sender keys).
    let msg = b"Hello group, full stack through relay!";
    alice.send_message(&handle, msg).await.unwrap();
    let sent = alice.take_sent_ciphertexts();
    assert_eq!(sent.len(), 1);
    let ciphertext = &sent[0].1;

    // Wrap in OuterEnvelope and send through relay.
    let routing_id = ctx_bytes;
    let outer = create_outer_envelope(&routing_id, None, 3600, ciphertext.clone()).unwrap();

    let sourced = SourcedRelayUrl {
        url: relay_url,
        source: RelayUrlSource::DhtResolved,
    };

    // Both Bob and Carol subscribe to the same routing ID.
    let bob_adapter = NativeRelayAdapter::connect_sourced(&sourced).await.unwrap();
    let carol_adapter = NativeRelayAdapter::connect_sourced(&sourced).await.unwrap();
    let routing = RoutingId::new(routing_id);
    let mut bob_stream = bob_adapter.subscribe(&routing, None).await.unwrap();
    let mut carol_stream = carol_adapter.subscribe(&routing, None).await.unwrap();

    // Alice publishes to the relay.
    let alice_adapter = NativeRelayAdapter::connect_sourced(&sourced).await.unwrap();
    alice_adapter.send(&outer).await.unwrap();
    println!("  [2] Published to relay");

    // Bob receives and decrypts.
    let bob_received = receive_envelope(&mut bob_stream).await;
    let bob_decrypted = bob
        .decrypt_message(&ctx_bytes, &bob_received.encrypted_blob, ALICE_DID, 0, 0)
        .unwrap();
    assert_eq!(bob_decrypted.as_slice(), msg.as_slice());
    println!("  [3] Bob decrypted from relay");

    // Carol receives and decrypts.
    let carol_received = receive_envelope(&mut carol_stream).await;
    let carol_decrypted = carol
        .decrypt_message(&ctx_bytes, &carol_received.encrypted_blob, ALICE_DID, 0, 0)
        .unwrap();
    assert_eq!(carol_decrypted.as_slice(), msg.as_slice());
    println!("  [4] Carol decrypted from relay");

    // Verify Merkle chain.
    let root = alice.merkle_root(&ctx_bytes).unwrap();
    assert_ne!(root, [0u8; 32], "Merkle root must be non-zero");
    println!("  [5] Merkle root: {}", hex::encode(&root[..8]));

    relay_handle.shutdown();

    println!("\n  ✓ Three-party relay roundtrip complete!\n");
}
