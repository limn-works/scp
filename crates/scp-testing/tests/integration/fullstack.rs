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
use scp_core::context::membership::ContextEvent;
use scp_core::context::{
    Capability, ContextMode, ContextParams, ContextState, context_id_bytes, context_routing_id,
};
use scp_core::envelope::outer::create_outer_envelope;
use scp_did::DID;
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
    let alice = network.create_node(ALICE_DID);
    let bob = network.create_node(BOB_DID);

    println!("  [1] Created Alice ({ALICE_DID}) and Bob ({BOB_DID})");

    // 2. Alice creates an encrypted context.
    let params = encrypted_params();
    let ctx_id = "e2e-encrypted-ctx";
    let handle = alice.create_context(ctx_id, params).await.unwrap();
    let ctx_bytes = context_id_bytes(ctx_id);

    println!("  [2] Alice created context '{ctx_id}'");
    assert_eq!(handle.state(), ContextState::Active);

    // 3. Alice adds Bob (internally: add_member + distribute_sender_key).
    //    The Welcome and sender key are deposited in the shared KeyExchange.
    alice.add_member(&handle, BOB_DID).await.unwrap();
    println!("  [3] Alice added Bob to the context");

    // 4. Bob joins by retrieving the Welcome from the KeyExchange.
    bob.join_from_welcome(ctx_id, &ctx_bytes).await.unwrap();
    println!("  [4] Bob joined the context via Welcome message");

    // 4b. Seed Bob's per-member pseudonym routing ID into Alice's manager
    //     (§9.10.4). In production Bob announces it via a PseudonymAnnouncement;
    //     here we inject it directly. Encrypted app-data now fans out to each
    //     peer's pseudonym routing ID, never the shared context_routing_id, so
    //     without this seed the send fails closed with PseudonymRegistryEmpty.
    let bob_pseudonym = [0x42u8; 32];
    alice
        .manager
        .seed_peer_pseudonym(ctx_id, DID::from(BOB_DID), bob_pseudonym)
        .await
        .unwrap();
    println!("  [4b] Seeded Bob's pseudonym routing ID into Alice's manager");

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
    let (sent_routing_id, ciphertext) = &sent[0];
    // §9.10.4: app-data is addressed to Bob's per-member pseudonym routing ID,
    // NEVER the shared context_routing_id (the deleted relay-correlation
    // fallback).
    assert_eq!(
        sent_routing_id, &bob_pseudonym,
        "transport routing ID must be the peer's per-member pseudonym (§9.10.4)"
    );
    assert_ne!(
        sent_routing_id,
        &context_routing_id(ctx_id),
        "app-data must NEVER be addressed to the shared context_routing_id (§9.10.4)"
    );
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

    // 7. Bob decrypts through the full envelope pipeline.
    let decrypted = bob
        .decrypt_message(ctx_id, &ctx_bytes, ciphertext, ALICE_DID)
        .await
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
// C2. Heartbeat send/receive (§9.9.2) — AC2 + AC3
// ---------------------------------------------------------------------------

/// AC2: `send_heartbeat` emits an empty-payload `MessageType::Heartbeat`
/// envelope through the real encrypt-and-send pipeline (a peer can open it and
/// see the heartbeat discriminator). AC3: a heartbeat carries sequence `0` and
/// does NOT advance the per-sender application sequence — a message sent before
/// and after a heartbeat keep consecutive application sequence numbers.
#[tokio::test]
async fn fullstack_heartbeat_send_does_not_advance_application_sequence() {
    use scp_core::envelope::inner::MessageType;

    let network = FullStackNetwork::new();
    let alice = network.create_node(ALICE_DID);
    let bob = network.create_node(BOB_DID);

    let ctx_id = "e2e-heartbeat-ctx";
    let ctx_bytes = context_id_bytes(ctx_id);
    let handle = alice
        .create_context(ctx_id, encrypted_params())
        .await
        .unwrap();
    alice.add_member(&handle, BOB_DID).await.unwrap();
    bob.join_from_welcome(ctx_id, &ctx_bytes).await.unwrap();

    let bob_pseudonym = [0x42u8; 32];
    alice
        .manager
        .seed_peer_pseudonym(ctx_id, DID::from(BOB_DID), bob_pseudonym)
        .await
        .unwrap();

    // 1. First application message — application sequence 0.
    alice.send_message(&handle, b"first").await.unwrap();
    // 2. Heartbeat between the two messages.
    alice.send_heartbeat(ctx_id).await.unwrap();
    // 3. Second application message — must be application sequence 1 (the
    //    heartbeat must NOT have consumed sequence 1).
    alice.send_message(&handle, b"second").await.unwrap();

    let sent = alice.take_sent_ciphertexts();
    assert_eq!(
        sent.len(),
        3,
        "three sends captured: message, heartbeat, message"
    );

    // Open each captured inner envelope (peer side) and classify it.
    let inner0 = bob
        .open_inner_envelope(ctx_id, &ctx_bytes, &sent[0].1)
        .unwrap();
    let inner_hb = bob
        .open_inner_envelope(ctx_id, &ctx_bytes, &sent[1].1)
        .unwrap();
    let inner2 = bob
        .open_inner_envelope(ctx_id, &ctx_bytes, &sent[2].1)
        .unwrap();

    // AC2: the middle send is a heartbeat — heartbeat discriminator, no
    // content. (Empty user payload survives as a minimal wrapped+padded blob,
    // so we assert on the type + sequence rather than exact byte length.)
    assert_eq!(
        inner_hb.message_type,
        MessageType::Heartbeat,
        "the heartbeat send must be tagged MessageType::Heartbeat (AC2)"
    );
    assert_eq!(
        inner_hb.sequence, 0,
        "a heartbeat always uses sequence 0 (it is not application content)"
    );

    // The two application messages are Content.
    assert_eq!(inner0.message_type, MessageType::Content);
    assert_eq!(inner2.message_type, MessageType::Content);

    // AC3: the heartbeat did NOT advance the per-sender application sequence —
    // the two application messages straddling the heartbeat have CONSECUTIVE
    // sequence numbers. Had the heartbeat consumed an application sequence,
    // `inner2.sequence` would be `inner0.sequence + 2`, leaving a gap a peer's
    // anti-replay tracker would treat as a suppressed message.
    assert_eq!(
        inner2.sequence,
        inner0.sequence + 1,
        "the two application messages straddling the heartbeat must have \
         consecutive sequence numbers — the heartbeat must NOT advance the \
         application sequence (AC3). first={}, second={}",
        inner0.sequence,
        inner2.sequence
    );
}

// ---------------------------------------------------------------------------
// C3. Three-party group
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fullstack_three_party_group() {
    println!("\n=== C3: Three-party MLS group ===\n");

    let network = FullStackNetwork::new();
    let alice = network.create_node(ALICE_DID);
    let bob = network.create_node(BOB_DID);
    let carol = network.create_node(CAROL_DID);

    let ctx_id = "three-party-ctx";
    let ctx_bytes = context_id_bytes(ctx_id);
    let params = encrypted_params();

    // Alice creates context.
    let handle = alice.create_context(ctx_id, params).await.unwrap();
    println!("  [1] Alice created context");

    // Alice adds Bob (Welcome #1).
    alice.add_member(&handle, BOB_DID).await.unwrap();
    bob.join_from_welcome(ctx_id, &ctx_bytes).await.unwrap();
    println!("  [2] Bob joined");

    // Alice adds Carol (Welcome #2).
    alice.add_member(&handle, CAROL_DID).await.unwrap();
    carol.join_from_welcome(ctx_id, &ctx_bytes).await.unwrap();
    println!("  [3] Carol joined");

    // Seed each peer's per-member pseudonym routing ID into Alice's manager
    // (§9.10.4). A multi-member encrypted send fans out the SAME MLS ciphertext
    // to EACH peer's pseudonym routing ID — never the shared context_routing_id;
    // without these seeds the send fails closed with PseudonymRegistryEmpty.
    let bob_pseudonym = [0x42u8; 32];
    let carol_pseudonym = [0x43u8; 32];
    alice
        .manager
        .seed_peer_pseudonym(ctx_id, DID::from(BOB_DID), bob_pseudonym)
        .await
        .unwrap();
    alice
        .manager
        .seed_peer_pseudonym(ctx_id, DID::from(CAROL_DID), carol_pseudonym)
        .await
        .unwrap();
    println!("  [3b] Seeded Bob's and Carol's pseudonym routing IDs");

    // Alice sends a message — both Bob and Carol should be able to decrypt.
    let msg = b"Hello everyone!";
    alice.send_message(&handle, msg).await.unwrap();
    let sent = alice.take_sent_ciphertexts();
    // §9.10.4: fan-out produces one send per peer pseudonym (Bob + Carol = 2),
    // never to the shared context_routing_id. Fan-out order is registry-iteration
    // order (non-deterministic), so match each recipient's entry by routing ID.
    assert_eq!(sent.len(), 2, "fan-out must address both peer pseudonyms");
    let captured_routing_ids: std::collections::HashSet<[u8; 32]> =
        sent.iter().map(|(rid, _)| *rid).collect();
    assert_eq!(
        captured_routing_ids,
        std::collections::HashSet::from([bob_pseudonym, carol_pseudonym]),
        "fan-out routing IDs must be exactly the two peer pseudonyms (§9.10.4)"
    );
    assert!(
        !captured_routing_ids.contains(&context_routing_id(ctx_id)),
        "app-data must NEVER be addressed to the shared context_routing_id (§9.10.4)"
    );
    let bob_ciphertext = sent
        .iter()
        .find(|(rid, _)| rid == &bob_pseudonym)
        .map(|(_, ct)| ct.clone())
        .expect("a send addressed to Bob's pseudonym must exist");
    let carol_ciphertext = sent
        .iter()
        .find(|(rid, _)| rid == &carol_pseudonym)
        .map(|(_, ct)| ct.clone())
        .expect("a send addressed to Carol's pseudonym must exist");
    println!("  [4] Alice sent message (fan-out to {} peers)", sent.len());

    // Bob decrypts his own captured ciphertext.
    let bob_decrypted = bob
        .decrypt_message(ctx_id, &ctx_bytes, &bob_ciphertext, ALICE_DID)
        .await
        .unwrap();
    assert_eq!(bob_decrypted.as_slice(), msg.as_slice());
    println!("  [5] Bob decrypted successfully");

    // Carol decrypts her own captured ciphertext.
    let carol_decrypted = carol
        .decrypt_message(ctx_id, &ctx_bytes, &carol_ciphertext, ALICE_DID)
        .await
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
    let alice = network.create_node(ALICE_DID);
    let bob = network.create_node(BOB_DID);

    let ctx_id = "governance-crypto-ctx";
    let ctx_bytes = context_id_bytes(ctx_id);
    let params = encrypted_params();

    let handle = alice.create_context(ctx_id, params).await.unwrap();
    alice.add_member(&handle, BOB_DID).await.unwrap();
    bob.join_from_welcome(ctx_id, &ctx_bytes).await.unwrap();
    println!("  [1] Context created, Bob joined");

    // Seed Bob's per-member pseudonym routing ID into Alice's manager (§9.10.4).
    // Encrypted app-data fans out to each peer's pseudonym routing ID, never the
    // shared context_routing_id; without this seed the pre-governance send fails
    // closed with PseudonymRegistryEmpty. Removing Bob below purges his pseudonym
    // from the peer registry, so the post-governance app-data send addresses no
    // peer (the removal's MLS Commit is the only post-removal transport traffic).
    let bob_pseudonym = [0x42u8; 32];
    alice
        .manager
        .seed_peer_pseudonym(ctx_id, DID::from(BOB_DID), bob_pseudonym)
        .await
        .unwrap();

    // Alice sends a message before governance action.
    let msg1 = b"Before governance";
    alice.send_message(&handle, msg1).await.unwrap();
    let sent1 = alice.take_sent_ciphertexts();
    assert_eq!(sent1.len(), 1, "pre-governance send addresses Bob only");
    let (sent1_routing_id, sent1_ct) = &sent1[0];
    // §9.10.4: app-data is addressed to Bob's per-member pseudonym, never the
    // shared context_routing_id.
    assert_eq!(
        sent1_routing_id, &bob_pseudonym,
        "pre-governance message must address Bob's per-member pseudonym (§9.10.4)"
    );
    assert_ne!(
        sent1_routing_id,
        &context_routing_id(ctx_id),
        "app-data must NEVER be addressed to the shared context_routing_id (§9.10.4)"
    );
    let decrypted1 = bob
        .decrypt_message(ctx_id, &ctx_bytes, sent1_ct, ALICE_DID)
        .await
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

    // Removing Bob broadcasts an MLS Commit (and possibly a rotated sender-key
    // distribution) so remaining members advance their epoch. This is MLS
    // GROUP-MANAGEMENT traffic and travels on the shared context_routing_id —
    // which §9.10.4 permits for management messages (the prohibition is on
    // APP-DATA carrying the shared RID). Capture every post-removal send here.
    let removal_traffic = alice.take_sent_ciphertexts();
    assert!(
        !removal_traffic.is_empty(),
        "removing Bob must broadcast at least one MLS management message \
         (epoch-advance Commit) to remaining members"
    );
    // Every captured post-removal send is management traffic: it MUST be on the
    // shared context_routing_id, never a per-member pseudonym (app-data routing).
    for (routing_id, _) in &removal_traffic {
        assert_eq!(
            routing_id,
            &context_routing_id(ctx_id),
            "post-removal management traffic must use the shared \
             context_routing_id (§9.10.4 permits management there); it must \
             NEVER be addressed to a per-member pseudonym"
        );
    }

    // Bob must NOT be able to open the removal Commit: he was just removed, so he
    // cannot derive the post-removal epoch's keys (MLS forward secrecy). The
    // first captured management blob is the epoch-advance Commit.
    let commit_bytes = &removal_traffic[0].1;
    let commit_decrypt = bob
        .decrypt_message(ctx_id, &ctx_bytes, commit_bytes, ALICE_DID)
        .await;
    assert!(
        commit_decrypt.is_err(),
        "Bob must NOT decrypt post-removal traffic (MLS forward secrecy)"
    );
    println!("  [4] Removal management traffic on shared RID; Bob cannot open it");

    // Alice sends an application message after removing Bob. Bob's pseudonym was
    // purged from the peer registry, leaving Alice the lone member. Under §9.10.4
    // app-data fans out ONLY to peer pseudonyms, so a lone-member app-data send
    // addresses no recipient: send_message returns Ok(()) as a true no-op and
    // emits NO ciphertext. Bob receives no application data at all — a strictly
    // stronger forward-secrecy guarantee than "Bob gets an undecryptable blob."
    let msg2 = b"After Bob removed";
    alice.send_message(&handle, msg2).await.unwrap();
    let sent2 = alice.take_sent_ciphertexts();
    assert!(
        sent2.is_empty(),
        "post-removal lone-member app-data send must emit NO ciphertext \
         (§9.10.4): Bob is no longer a peer, so nothing is addressed to him"
    );
    println!("  [5] Post-removal app-data send addressed no peer — no ciphertext");

    println!("\n  ✓ Governance + real crypto forward secrecy verified!\n");
}

// ---------------------------------------------------------------------------
// C5. Event log Merkle chain with real crypto
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fullstack_event_log_merkle_chain() {
    println!("\n=== C5: Event log Merkle chain ===\n");

    let network = FullStackNetwork::new();
    let alice = network.create_node(ALICE_DID);
    let bob = network.create_node(BOB_DID);

    let ctx_id = "merkle-chain-ctx";
    let ctx_bytes = context_id_bytes(ctx_id);
    let params = encrypted_params();

    let handle = alice.create_context(ctx_id, params).await.unwrap();
    alice.add_member(&handle, BOB_DID).await.unwrap();
    bob.join_from_welcome(ctx_id, &ctx_bytes).await.unwrap();

    // Seed Bob's per-member pseudonym routing ID into Alice's manager (§9.10.4).
    // Encrypted app-data fans out to each peer's pseudonym routing ID; without
    // this seed the sends below fail closed with PseudonymRegistryEmpty. This
    // test only exercises the event-log Merkle chain, so the ciphertexts are
    // drained, not inspected — one seed before the loop is all that is needed.
    let bob_pseudonym = [0x42u8; 32];
    alice
        .manager
        .seed_peer_pseudonym(ctx_id, DID::from(BOB_DID), bob_pseudonym)
        .await
        .unwrap();

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
    bob_event_log.init_event_log(&ctx_bytes).await.unwrap();
    // Import into a fresh log should fail because it already has an init entry.
    // Instead verify chain by re-importing from scratch.
    let fresh_log = scp_core::context::providers::event_log::MerkleEventLogProvider::new();
    let import_result = fresh_log.import_event_log_data(&ctx_bytes, &exported).await;
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
    let alice = network.create_node(ALICE_DID);
    let bob = network.create_node(BOB_DID);

    let ctx_id = "multi-msg-ctx";
    let ctx_bytes = context_id_bytes(ctx_id);
    let params = encrypted_params();

    let handle = alice.create_context(ctx_id, params).await.unwrap();
    alice.add_member(&handle, BOB_DID).await.unwrap();
    bob.join_from_welcome(ctx_id, &ctx_bytes).await.unwrap();

    // Seed Bob's per-member pseudonym routing ID into Alice's manager (§9.10.4).
    // Pseudonyms persist, so this is seeded once before the loop; every message
    // fans out to this same peer pseudonym. Without it the sends fail closed with
    // PseudonymRegistryEmpty.
    let bob_pseudonym = [0x42u8; 32];
    alice
        .manager
        .seed_peer_pseudonym(ctx_id, DID::from(BOB_DID), bob_pseudonym)
        .await
        .unwrap();

    // Send 5 messages and verify each roundtrips correctly.
    for i in 0..5u64 {
        let msg = format!("Message number {i}");
        alice.send_message(&handle, msg.as_bytes()).await.unwrap();
        let sent = alice.take_sent_ciphertexts();
        // Two-party context: fan-out addresses exactly one peer (Bob).
        assert_eq!(sent.len(), 1);
        let (sent_routing_id, ciphertext) = &sent[0];
        // §9.10.4: each message is addressed to Bob's per-member pseudonym,
        // never the shared context_routing_id.
        assert_eq!(
            sent_routing_id, &bob_pseudonym,
            "message {i} must address Bob's per-member pseudonym (§9.10.4)"
        );
        assert_ne!(
            sent_routing_id,
            &context_routing_id(ctx_id),
            "message {i} must NEVER address the shared context_routing_id (§9.10.4)"
        );

        let decrypted = bob
            .decrypt_message(ctx_id, &ctx_bytes, ciphertext, ALICE_DID)
            .await
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
    let alice = network.create_node(ALICE_DID);
    let bob = network.create_node(BOB_DID);

    let ctx_id = "nondet-ctx";
    let ctx_bytes = context_id_bytes(ctx_id);
    let params = encrypted_params();

    let handle = alice.create_context(ctx_id, params).await.unwrap();
    alice.add_member(&handle, BOB_DID).await.unwrap();
    bob.join_from_welcome(ctx_id, &ctx_bytes).await.unwrap();

    // Seed Bob's per-member pseudonym routing ID into Alice's manager (§9.10.4).
    // Encrypted app-data fans out to Bob's pseudonym routing ID; without this
    // seed both sends below fail closed with PseudonymRegistryEmpty. The
    // nondeterminism assertion inspects the ciphertext blob (sent[0].1), which
    // is unaffected by the routing ID the send is addressed to.
    let bob_pseudonym = [0x42u8; 32];
    alice
        .manager
        .seed_peer_pseudonym(ctx_id, DID::from(BOB_DID), bob_pseudonym)
        .await
        .unwrap();

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
        .decrypt_message(ctx_id, &ctx_bytes, &sent1[0].1, ALICE_DID)
        .await
        .unwrap();
    let d2 = bob
        .decrypt_message(ctx_id, &ctx_bytes, &sent2[0].1, ALICE_DID)
        .await
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
/// `ContextManager`) with the transport depth of `encrypted_relay_roundtrip` tests (real WebSocket relay).
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
    let alice = network.create_node(ALICE_DID);
    let bob = network.create_node(BOB_DID);
    println!("  [2] Created Alice ({ALICE_DID}) and Bob ({BOB_DID}) with real MLS");

    // 3. Alice creates encrypted context, adds Bob.
    let ctx_id = "full-stack-relay-ctx";
    let ctx_bytes = context_id_bytes(ctx_id);
    let params = encrypted_params();
    let handle = alice.create_context(ctx_id, params).await.unwrap();
    assert_eq!(handle.state(), ContextState::Active);

    alice.add_member(&handle, BOB_DID).await.unwrap();
    bob.join_from_welcome(ctx_id, &ctx_bytes).await.unwrap();
    println!("  [3] Context created and Bob joined via Welcome");

    // 3b. Seed Bob's per-member pseudonym routing ID into Alice's manager
    //     (§9.10.4). Encrypted app-data fans out to each peer's pseudonym
    //     routing ID, never the shared context_routing_id; without this seed the
    //     send fails closed with PseudonymRegistryEmpty.
    let bob_pseudonym = [0x42u8; 32];
    alice
        .manager
        .seed_peer_pseudonym(ctx_id, DID::from(BOB_DID), bob_pseudonym)
        .await
        .unwrap();
    println!("  [3b] Seeded Bob's pseudonym routing ID into Alice's manager");

    // 4. Alice sends an encrypted message through ContextManager.
    //    ContextManager calls seal (real sender key + real MLS encryption +
    //    outer envelope wrapping) and CapturingTransport captures the bytes.
    let plaintext = b"Hello Bob! Real MLS + real relay, full stack.";
    alice.send_message(&handle, plaintext).await.unwrap();
    let sent = alice.take_sent_ciphertexts();
    assert_eq!(sent.len(), 1, "exactly one ciphertext captured");
    let (sent_routing_id, ciphertext) = &sent[0];
    // §9.10.4: app-data is addressed to Bob's per-member pseudonym routing ID,
    // NEVER the shared context_routing_id.
    assert_eq!(
        sent_routing_id, &bob_pseudonym,
        "transport routing ID must be the peer's per-member pseudonym (§9.10.4)"
    );
    assert_ne!(
        sent_routing_id,
        &context_routing_id(ctx_id),
        "app-data must NEVER be addressed to the shared context_routing_id (§9.10.4)"
    );
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

    // 5. The captured bytes are a serialized OuterEnvelope. Deserialize to
    //    extract the inner envelope for relay transport, then re-wrap with the
    //    same per-member pseudonym routing ID the send addressed (§9.10.4): Bob
    //    subscribes to his own pseudonym, the routing ID the relay delivers on.
    let captured_outer: scp_core::envelope::OuterEnvelope =
        rmp_serde::from_slice(ciphertext).unwrap();
    let routing_id = bob_pseudonym; // Bob's per-member pseudonym routing ID
    let outer_envelope = create_outer_envelope(
        &routing_id,
        None,
        3600,
        captured_outer.encrypted_blob.clone(),
    )
    .unwrap();
    println!(
        "  [5] Wrapped in OuterEnvelope (routing_id: {}...)",
        &hex::encode(routing_id)[..16]
    );

    // 6. Connect to relay: Bob subscribes first, then Alice sends.
    let sourced = SourcedRelayUrl {
        url: relay_url,
        source: RelayUrlSource::DhtResolved,
    };
    let bob_adapter = NativeRelayAdapter::connect_sourced(&sourced, None)
        .await
        .unwrap();
    let bob_routing = RoutingId::new(routing_id);
    let mut stream = bob_adapter.subscribe(&bob_routing, None).await.unwrap();

    let alice_adapter = NativeRelayAdapter::connect_sourced(&sourced, None)
        .await
        .unwrap();
    let blob_id = alice_adapter.send(&outer_envelope).await.unwrap();
    assert_eq!(blob_id.as_bytes().len(), 32, "blob_id must be 32 bytes");
    println!(
        "  [6] Published to relay (blob_id: {}...)",
        hex::encode(&blob_id.as_bytes()[..8])
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

    // 8. Bob decrypts using the original captured envelope (which is the
    //    full serialized OuterEnvelope from the send pipeline).
    //    The relay roundtrip above verified the encrypted_blob survived intact.
    let decrypted = bob
        .decrypt_message(ctx_id, &ctx_bytes, ciphertext, ALICE_DID)
        .await
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
    let alice = network.create_node(ALICE_DID);
    let bob = network.create_node(BOB_DID);

    let ctx_id = "relay-multi-msg-ctx";
    let ctx_bytes = context_id_bytes(ctx_id);
    let params = encrypted_params();
    let handle = alice.create_context(ctx_id, params).await.unwrap();
    alice.add_member(&handle, BOB_DID).await.unwrap();
    bob.join_from_welcome(ctx_id, &ctx_bytes).await.unwrap();

    // Seed Bob's per-member pseudonym routing ID into Alice's manager (§9.10.4).
    // Pseudonyms persist, so this is seeded once before the send loop; every
    // message in the context fans out to this same peer pseudonym.
    let bob_pseudonym = [0x42u8; 32];
    alice
        .manager
        .seed_peer_pseudonym(ctx_id, DID::from(BOB_DID), bob_pseudonym)
        .await
        .unwrap();

    let sourced = SourcedRelayUrl {
        url: relay_url,
        source: RelayUrlSource::DhtResolved,
    };
    let bob_adapter = NativeRelayAdapter::connect_sourced(&sourced, None)
        .await
        .unwrap();
    let alice_adapter = NativeRelayAdapter::connect_sourced(&sourced, None)
        .await
        .unwrap();

    // §9.10.4: app-data is addressed to Bob's per-member pseudonym, never the
    // shared context_routing_id. Bob subscribes to his own pseudonym — the
    // routing ID the relay delivers on.
    let routing_id = bob_pseudonym;
    let bob_routing = RoutingId::new(routing_id);
    let mut stream = bob_adapter.subscribe(&bob_routing, None).await.unwrap();

    // Send 3 messages and verify each roundtrips through the relay.
    for i in 0..3u32 {
        let msg = format!("Relay message #{i}");

        // Encrypt via ContextManager (real MLS + sender keys + envelope).
        alice.send_message(&handle, msg.as_bytes()).await.unwrap();
        let sent = alice.take_sent_ciphertexts();
        assert_eq!(sent.len(), 1);
        let (sent_routing_id, ciphertext) = (&sent[0].0, &sent[0].1);
        // Each message addresses Bob's pseudonym, never the shared RID.
        assert_eq!(
            sent_routing_id, &bob_pseudonym,
            "message {i} must address the peer's per-member pseudonym (§9.10.4)"
        );
        assert_ne!(
            sent_routing_id,
            &context_routing_id(ctx_id),
            "message {i} must NEVER address the shared context_routing_id (§9.10.4)"
        );

        // The captured bytes are a serialized OuterEnvelope. Extract the
        // encrypted_blob for relay transport.
        let captured_outer: scp_core::envelope::OuterEnvelope =
            rmp_serde::from_slice(ciphertext).unwrap();
        let outer = create_outer_envelope(
            &routing_id,
            None,
            3600,
            captured_outer.encrypted_blob.clone(),
        )
        .unwrap();
        alice_adapter.send(&outer).await.unwrap();

        // Bob receives from relay and verifies blob transit, then decrypts
        // using the original captured envelope.
        let received = receive_envelope(&mut stream).await;
        assert_eq!(
            received.encrypted_blob, captured_outer.encrypted_blob,
            "encrypted_blob must survive relay transit"
        );
        let decrypted = bob
            .decrypt_message(ctx_id, &ctx_bytes, ciphertext, ALICE_DID)
            .await
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
// Integration test exercises full stack through relay with per-member
// pseudonym fan-out; splitting would fragment the sequential scenario.
#[allow(clippy::too_many_lines)]
async fn full_stack_relay_three_party() {
    println!("\n=== Full-stack relay: three-party group ===\n");

    let (relay_handle, relay_addr) = start_relay().await;
    let relay_url = format!("ws://{relay_addr}/scp/v1");

    let network = FullStackNetwork::new();
    let alice = network.create_node(ALICE_DID);
    let bob = network.create_node(BOB_DID);
    let carol = network.create_node(CAROL_DID);

    let ctx_id = "relay-three-party-ctx";
    let ctx_bytes = context_id_bytes(ctx_id);
    let params = encrypted_params();
    let handle = alice.create_context(ctx_id, params).await.unwrap();

    // Alice adds Bob, then Carol.
    alice.add_member(&handle, BOB_DID).await.unwrap();
    bob.join_from_welcome(ctx_id, &ctx_bytes).await.unwrap();
    alice.add_member(&handle, CAROL_DID).await.unwrap();
    carol.join_from_welcome(ctx_id, &ctx_bytes).await.unwrap();
    println!("  [1] Three-party context established");

    // Seed each peer's per-member pseudonym routing ID into Alice's manager
    // (§9.10.4). A multi-member encrypted send fans out the SAME MLS ciphertext
    // to EACH peer's pseudonym routing ID — never the shared context_routing_id.
    let bob_pseudonym = [0x42u8; 32];
    let carol_pseudonym = [0x43u8; 32];
    alice
        .manager
        .seed_peer_pseudonym(ctx_id, DID::from(BOB_DID), bob_pseudonym)
        .await
        .unwrap();
    alice
        .manager
        .seed_peer_pseudonym(ctx_id, DID::from(CAROL_DID), carol_pseudonym)
        .await
        .unwrap();

    // Alice sends message via ContextManager (real MLS + sender keys + envelope).
    let msg = b"Hello group, full stack through relay!";
    alice.send_message(&handle, msg).await.unwrap();
    let sent = alice.take_sent_ciphertexts();
    // §9.10.4: fan-out produces one send per peer pseudonym (Bob + Carol = 2),
    // never to the shared context_routing_id. Fan-out order is registry-iteration
    // order (non-deterministic), so match each recipient's entry by routing ID.
    assert_eq!(sent.len(), 2, "fan-out must address both peer pseudonyms");
    let captured_routing_ids: std::collections::HashSet<[u8; 32]> =
        sent.iter().map(|(rid, _)| *rid).collect();
    assert_eq!(
        captured_routing_ids,
        std::collections::HashSet::from([bob_pseudonym, carol_pseudonym]),
        "fan-out routing IDs must be exactly the two peer pseudonyms (§9.10.4)"
    );
    assert!(
        !captured_routing_ids.contains(&context_routing_id(ctx_id)),
        "app-data must NEVER be addressed to the shared context_routing_id (§9.10.4)"
    );
    let bob_ciphertext = sent
        .iter()
        .find(|(rid, _)| rid == &bob_pseudonym)
        .map(|(_, ct)| ct.clone())
        .expect("a send addressed to Bob's pseudonym must exist");
    let carol_ciphertext = sent
        .iter()
        .find(|(rid, _)| rid == &carol_pseudonym)
        .map(|(_, ct)| ct.clone())
        .expect("a send addressed to Carol's pseudonym must exist");

    // Extract each peer's encrypted_blob from its captured OuterEnvelope and
    // re-wrap addressed to that peer's own pseudonym (the routing ID the relay
    // delivers on for that recipient).
    let bob_captured_outer: scp_core::envelope::OuterEnvelope =
        rmp_serde::from_slice(&bob_ciphertext).unwrap();
    let carol_captured_outer: scp_core::envelope::OuterEnvelope =
        rmp_serde::from_slice(&carol_ciphertext).unwrap();
    let bob_outer = create_outer_envelope(
        &bob_pseudonym,
        None,
        3600,
        bob_captured_outer.encrypted_blob.clone(),
    )
    .unwrap();
    let carol_outer = create_outer_envelope(
        &carol_pseudonym,
        None,
        3600,
        carol_captured_outer.encrypted_blob.clone(),
    )
    .unwrap();

    let sourced = SourcedRelayUrl {
        url: relay_url,
        source: RelayUrlSource::DhtResolved,
    };

    // Bob and Carol each subscribe to their OWN pseudonym routing ID (§9.10.4).
    let bob_adapter = NativeRelayAdapter::connect_sourced(&sourced, None)
        .await
        .unwrap();
    let carol_adapter = NativeRelayAdapter::connect_sourced(&sourced, None)
        .await
        .unwrap();
    let bob_routing = RoutingId::new(bob_pseudonym);
    let carol_routing = RoutingId::new(carol_pseudonym);
    let mut bob_stream = bob_adapter.subscribe(&bob_routing, None).await.unwrap();
    let mut carol_stream = carol_adapter.subscribe(&carol_routing, None).await.unwrap();

    // Alice publishes each peer's envelope to the relay.
    let alice_adapter = NativeRelayAdapter::connect_sourced(&sourced, None)
        .await
        .unwrap();
    alice_adapter.send(&bob_outer).await.unwrap();
    alice_adapter.send(&carol_outer).await.unwrap();
    println!("  [2] Published per-peer envelopes to relay");

    // Bob receives on his pseudonym and verifies relay transit, then decrypts.
    let bob_received = receive_envelope(&mut bob_stream).await;
    assert_eq!(
        bob_received.encrypted_blob, bob_captured_outer.encrypted_blob,
        "encrypted_blob must survive relay transit"
    );
    let bob_decrypted = bob
        .decrypt_message(ctx_id, &ctx_bytes, &bob_ciphertext, ALICE_DID)
        .await
        .unwrap();
    assert_eq!(bob_decrypted.as_slice(), msg.as_slice());
    println!("  [3] Bob decrypted from relay");

    // Carol receives on her pseudonym and verifies relay transit, then decrypts.
    let carol_received = receive_envelope(&mut carol_stream).await;
    assert_eq!(
        carol_received.encrypted_blob, carol_captured_outer.encrypted_blob,
        "encrypted_blob must survive relay transit"
    );
    let carol_decrypted = carol
        .decrypt_message(ctx_id, &ctx_bytes, &carol_ciphertext, ALICE_DID)
        .await
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

// ---------------------------------------------------------------------------
// C-SEC: Direct-execute governance trust boundary (quorum-bypass fix)
//
// Cross-bridge KAT against the SHARED runtime substrate every FFI bridge
// dispatches into. `GovernanceCommand::ExecuteGovernanceAction` carries ONLY a
// proposal id; the runtime resolves the authoritative proposal from the context
// actor's own quorum-validated engine. A caller cannot fabricate an approved
// proposal or substitute an action.
//   - FORGERY: an untracked id is rejected and applies no membership change.
//   - GENUINE: a real quorum-approved action takes effect exactly once; a
//     direct execute-by-id of the same id is then replay-rejected.
// ---------------------------------------------------------------------------

fn majority_governance_params(voters: &[&str]) -> ContextParams {
    ContextParams {
        governance: scp_core::context::params::GovernanceModel::Majority {
            eligible_voters: voters.iter().map(|d| DID((*d).to_owned())).collect(),
        },
        ..encrypted_params()
    }
}

#[tokio::test]
async fn fullstack_direct_execute_rejects_forged_proposal_and_applies_no_change() {
    let network = FullStackNetwork::new();
    let alice = network.create_node(ALICE_DID);

    // Single-voter Majority context (creator only). A governed (non-SingleAdmin)
    // context does NOT authorize a unilateral `invite_member`, so a second MLS
    // member is admitted via the governance vote path — exercised end-to-end by
    // the native `governance_integration.rs` KATs and the deferred governed
    // invite (#2027). Here the forged execute-by-id trust boundary is what we
    // pin, and it does not depend on a second member: the fabricated proposal id
    // is rejected against the real, quorum-validated engine regardless.
    let ctx_id = "gov-direct-forgery-ctx";
    alice
        .create_context(ctx_id, majority_governance_params(&[ALICE_DID]))
        .await
        .unwrap();

    let victim = "did:dht:z6MkForgeryVictimNeverAdded";
    assert!(
        !alice.manager.is_member(ctx_id, victim).await,
        "victim must not be a member before the forged execute"
    );

    // A proposal id the engine never tracked. If the bridge trusted caller
    // data, this would have carried an AddMember{victim}; the runtime has no
    // caller action to apply.
    let fabricated = [0xABu8; 32];
    let err = alice
        .execute_governance_by_id(ctx_id, fabricated)
        .await
        .expect_err("forged direct-execute must be rejected");
    assert!(
        matches!(err, scp_core::context::ContextError::PermissionDenied(_)),
        "forged proposal must be PermissionDenied, got: {err:?}"
    );
    assert!(
        !alice.manager.is_member(ctx_id, victim).await,
        "rejected forgery must not have added the victim as a member"
    );
}

#[tokio::test]
async fn fullstack_direct_execute_genuine_runs_once_then_replay_rejected() {
    use scp_core::context::governance::{GovernanceAction, ProposalStatus};

    let network = FullStackNetwork::new();
    let alice = network.create_node(ALICE_DID);

    // Single-voter Majority context (creator only): Alice's own approval is 1/1
    // = a majority, so the proposal reaches quorum and auto-executes WITHOUT
    // adding a second member. (The full-MLS `add_member` join path re-homes the
    // context actor in this single-node harness, so a multi-member governance
    // round is exercised by the native `governance_integration.rs` KATs; here
    // we pin the by-id trust boundary against the shared runtime substrate.)
    let ctx_id = "gov-direct-genuine-ctx";
    alice
        .create_context(ctx_id, majority_governance_params(&[ALICE_DID]))
        .await
        .unwrap();

    // Genuine propose→approve→quorum. ChangeRole on Alice (the sole member).
    let action = GovernanceAction::ChangeRole {
        did: DID(ALICE_DID.to_owned()),
        new_role: "observer".to_owned(),
    };
    let proposal = alice.propose_governance(ctx_id, action).await.unwrap();
    let status = alice
        .approve_governance(ctx_id, &proposal.proposal_id)
        .await
        .unwrap();
    assert_eq!(
        status,
        ProposalStatus::Approved,
        "1/1 crosses majority quorum and the engine marks the proposal Approved"
    );

    // The engine retains the approved proposal: by-id resolution finds it.
    let tracked = alice
        .manager
        .get_proposal(ctx_id, &proposal.proposal_id)
        .await
        .expect("engine must retain the approved proposal");
    assert_eq!(tracked.status, ProposalStatus::Approved);

    // The action took effect exactly once (auto-executed at quorum). A direct
    // execute-by-id of the same tracked id is replay-rejected — proving the
    // by-id path resolves the engine's real proposal and honours the replay
    // guard rather than re-running a caller-supplied action.
    let err = alice
        .execute_governance_by_id(ctx_id, proposal.proposal_id)
        .await
        .expect_err("re-executing an already-executed proposal must be rejected");
    assert!(
        matches!(err, scp_core::context::ContextError::PermissionDenied(_)),
        "replay must be PermissionDenied, got: {err:?}"
    );
    assert!(
        format!("{err}").contains("already been executed"),
        "replay rejection should name the executed proposal: {err}"
    );
}
