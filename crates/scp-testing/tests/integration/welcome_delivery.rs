#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::significant_drop_tightening
)]

//! Integration tests: cross-process MLS Welcome delivery (spec §5.12.3, #1311).
//!
//! Proves that two separate nodes can exchange a creator-signed, HPKE-sealed
//! MLS Welcome and establish bidirectional encrypted communication over the REAL
//! join path — the joiner reserves its own `KeyPackage` from its
//! `KeyPackageStoreActor`, the creator's `invite_member` seals the Welcome, and
//! the joiner's `spawn_actor_from_welcome` stands up a live actor (ADR-049 §9
//! 2F-residual). Also validates the ECIES routing-id derivation used for secure
//! Welcome / key-package delivery over untrusted relays, and the join-time
//! sender-key distribution framing (H3).
//!
//! The legacy provider single-slot join (`prepare_key_package_for_join` +
//! `MlsCryptoProvider::join_from_welcome`) has been retired; these tests drive
//! the production `Supervisor` API. The comprehensive spawn-from-Welcome KATs
//! (signature / binding / rollback / replay) live in the runtime unit suite
//! `spawn_from_welcome_tests.rs`.

use scp_core::context::{Capability, ContextMode, ContextParams};
use scp_core::crypto::envelope_seal::{
    derive_invitation_routing_id, derive_key_package_routing_id,
};
use scp_core::crypto::mls::provider::MlsCryptoProvider;
use scp_did::DID;
use scp_testing::fullstack::FullStackNetwork;
use zeroize::Zeroizing;

/// `SingleAdmin` encrypted `ContextParams` whose ceiling grants the creator the
/// `MemberInvite` + `GovernancePropose` capabilities `invite_member` routes
/// through (a governed context would refuse a unilateral invite).
fn invite_params() -> ContextParams {
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
// 1. cross_process_welcome_delivery — real reserve + invite_member + spawn
// ---------------------------------------------------------------------------

/// Two separate nodes prove that a creator-signed, HPKE-sealed Welcome produced
/// by `invite_member` can be consumed by `spawn_actor_from_welcome` on a
/// different node, establishing a shared MLS group whose installed provider
/// state round-trips a sealed application envelope creator → joiner.
#[tokio::test]
async fn cross_process_welcome_delivery() {
    let alice_did = "did:dht:z6MkAliceAliceAliceAliceAliceAliceAliceAlic";
    let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
    let context_id_str = "cross-process-welcome-ctx";
    let context_id = scp_core::context::context_id_bytes(context_id_str);

    // Real nodes over a shared in-process network (no live relay).
    let network = FullStackNetwork::new();
    let alice = network.create_node(alice_did);
    let bob = network.create_node(bob_did);

    // Alice creates the encrypted context; add_member drives the real
    // reserve → invite_member → sealed-bundle path + sender-key distribution.
    let handle = alice
        .create_context(context_id_str, invite_params())
        .await
        .unwrap();
    alice.add_member(&handle, bob_did).await.unwrap();

    // Bob opens the sealed invitation and spawns a live actor; his provider now
    // holds the installed joined MLS group + Alice's distributed sender key.
    bob.join_from_welcome(context_id_str, &context_id)
        .await
        .unwrap();

    // Seed Bob's per-member pseudonym routing ID into Alice's manager (§9.10.4).
    // Encrypted app-data fans out to each peer's pseudonym routing ID, never the
    // shared context_routing_id, so without this seed the send fails closed with
    // PseudonymRegistryEmpty.
    alice
        .manager
        .seed_peer_pseudonym(context_id_str, DID::from(bob_did), [0x42u8; 32])
        .await
        .unwrap();

    // Alice sends an application message through the real Supervisor encrypt
    // pipeline (MLS + sender key + §9.17 access-key wrap). The ciphertext is
    // captured by her transport.
    let plaintext = b"Hello from Alice!";
    alice.send_message(&handle, plaintext).await.unwrap();
    let sent = alice.take_sent_ciphertexts();
    assert_eq!(
        sent.len(),
        1,
        "exactly one ciphertext should have been sent"
    );
    let (_routing_id, ciphertext) = &sent[0];

    // Bob opens Alice's message through the REAL actor receive path
    // (`Supervisor::deliver_commit_blob` → the context actor's
    // `decrypt_and_dispatch`) — proving the full pipeline: real MLS Welcome join
    // (spawn) + join-time sender-key distribution + encrypt + decrypt.
    let decrypted = bob
        .decrypt_message(context_id_str, &context_id, ciphertext, alice_did)
        .await
        .unwrap();
    assert_eq!(
        decrypted.as_slice(),
        plaintext.as_slice(),
        "decrypted message must match Alice's plaintext"
    );
}

// ---------------------------------------------------------------------------
// 1a. welcome_joiner_application_data_round_trips_to_creator — the joiner→creator
//     (2J landing) direction, over the REAL actor mailbox + transport.
// ---------------------------------------------------------------------------

/// A Welcome-joiner (Bob) sends a real application message the creator (Alice)
/// decrypts — the joiner→creator direction the `cross_process_welcome_delivery`
/// creator→joiner test does NOT cover. This is the "2J landing signal": pre-2J a
/// Welcome-joiner had no live send handle at all; post-2J its spawned actor
/// produces application ciphertext an incumbent opens end-to-end.
///
/// # Relocation provenance (ADR-049 PR-7, SCP-CRYPTOMOVE-001)
///
/// This is the fullstack owner of the joiner→creator APPLICATION round-trip
/// property that the runtime unit test
/// `spawn_from_welcome_application_data_round_trips_joiner_to_creator` used to
/// prove by driving `MlsCryptoProvider::seal` / `open` DIRECTLY on the provider.
/// PR-7 moved the per-context seal/open crypto off the provider and onto the live
/// actor, so the unit-level bare-provider fixture can no longer drive a real
/// seal/open round-trip (its `take_into_actor` double-take panics once the crypto
/// already lives on the actor). The full application round-trip therefore lives
/// HERE, where the real actor mailbox + transport exist. The unit test is
/// realigned to the unit-reachable invariants (spawned, registered, group
/// installed at the joined epoch, and — its distinct §9.16.6 Mitigation-1 anchor —
/// the actor ANSWERS an incumbent's sender-key PULL).
///
/// # The sender-key PULL this depends on
///
/// Application messages ride the per-sender key layer on top of the MLS group
/// key. For Alice to open Bob's traffic she must hold Bob's sender key. A
/// Welcome-joiner cannot PUSH its key (a push seals to each incumbent's stable
/// `0xFF01` wrapping key, which openmls 0.8.1 does not expose from a joined group,
/// ADR-057); incumbents PULL it (§9.16.2). That PULL runs inside
/// `join_from_welcome` via the harness `incumbents_pull_joiner_sender_key` — the
/// sanctioned stand-in for deferred #2049 request-initiation — so by the time Bob
/// sends below, Alice already holds Bob's key. If the §9.16.6 Mitigation-1
/// membership gate were reverted to the empty-`member_wrapping_keys` check, the
/// PULL inside `join_from_welcome` would fail and this test would never reach the
/// send.
#[tokio::test]
async fn welcome_joiner_application_data_round_trips_to_creator() {
    let alice_did = "did:dht:z6MkAliceAliceAliceAliceAliceAliceAliceAlic";
    let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
    let context_id_str = "welcome-joiner-to-creator-ctx";
    let context_id = scp_core::context::context_id_bytes(context_id_str);

    let network = FullStackNetwork::new();
    let alice = network.create_node(alice_did);
    let bob = network.create_node(bob_did);

    // Stand up the shared group over the real reserve → invite → spawn join path.
    // `join_from_welcome` PULLS Bob's sender key onto Alice (§9.16.2) as part of
    // the join, so Alice can open Bob's application traffic below.
    let alice_handle = alice
        .create_context(context_id_str, invite_params())
        .await
        .unwrap();
    alice.add_member(&alice_handle, bob_did).await.unwrap();
    let bob_handle = bob
        .join_from_welcome(context_id_str, &context_id)
        .await
        .unwrap();

    // Bob seeds Alice's per-member pseudonym so his send fans out to a recipient
    // routing id (§9.10.4); without it the send fails closed with
    // `PseudonymRegistryEmpty`.
    bob.manager
        .seed_peer_pseudonym(context_id_str, DID::from(alice_did), [0x37u8; 32])
        .await
        .unwrap();

    // Clear any transport residue captured on Bob during the join handshake, so
    // the assertion below sees exactly the one application ciphertext Bob sends.
    let _ = bob.take_sent_ciphertexts();

    // Bob (the Welcome-joiner) sends an application message through the REAL
    // Supervisor encrypt pipeline (MLS + his own sender key + §9.17 access-key
    // wrap). His transport captures the single application ciphertext.
    let plaintext = b"application data from the welcome-joiner (Bob) to the creator";
    bob.send_message(&bob_handle, plaintext).await.unwrap();
    let sent = bob.take_sent_ciphertexts();
    assert_eq!(
        sent.len(),
        1,
        "the joiner's send must produce exactly one application ciphertext"
    );
    let (_routing_id, ciphertext) = &sent[0];

    // Alice opens Bob's message through the REAL actor receive path
    // (`Supervisor::deliver_commit_blob` → the context actor's
    // `decrypt_and_dispatch` → §9.17 unwrap), recovering Bob's exact plaintext —
    // the joiner→creator application round-trip closed end-to-end.
    let decrypted = alice
        .decrypt_message(context_id_str, &context_id, ciphertext, bob_did)
        .await
        .unwrap();
    assert_eq!(
        decrypted.as_slice(),
        plaintext.as_slice(),
        "the creator must recover the joiner's exact application plaintext"
    );
}

// ---------------------------------------------------------------------------
// 1b. welcome_joiner_round_trips_application_traffic_in_both_directions — the
//     bidirectional round-trip, over the REAL actor mailbox + transport.
// ---------------------------------------------------------------------------

/// A Welcome-joiner (Bob) and the creator (Alice) exchange real application
/// traffic in BOTH directions within a single live context: Alice → Bob and
/// Bob → Alice, each proven by exact-plaintext equality through the real actor
/// receive path. This is the fullstack owner of the BIDIRECTIONAL round-trip
/// property the runtime unit tests
/// `spawn_from_welcome_group_round_trips_both_directions` and
/// `invite_member_round_trip_stands_up_a_bidirectional_joiner` used to prove by
/// driving `MlsCryptoProvider::mls_encrypt_management` / `open` DIRECTLY on the
/// provider (both directions, group-keyed management).
///
/// # Why APPLICATION traffic (not the units' group-keyed management path)
///
/// ADR-049 PR-7 moved the seal/open crypto onto the live actor, and the actor
/// receive path (`deliver_incoming`) classifies a group-keyed MANAGEMENT payload
/// strictly as a `SenderKeyDistributionMessage`; an arbitrary management payload
/// is rejected, and `deliver_commit_blob` returns `None` for every non-Application
/// outcome. So a literal "arbitrary group-keyed management payload" round-trip is
/// not observable through the public harness. The APPLICATION path is instead the
/// STRICTLY STRONGER proof: an application message is MLS-group-encrypted and THEN
/// sender-key-AEAD'd, so opening it exercises the same group-keyed MLS layer the
/// units' management round-trip pinned, PLUS the per-sender key layer on top. A
/// passing bidirectional application round-trip therefore subsumes the units'
/// bidirectional management round-trip property.
///
/// The joiner→creator (Bob → Alice) leg is the 2J landing signal — pre-2J the
/// joiner had no live send handle. It depends on the §9.16.2 sender-key PULL that
/// `join_from_welcome` runs (via `incumbents_pull_joiner_sender_key`) to deliver
/// Bob's key to Alice.
#[tokio::test]
async fn welcome_joiner_round_trips_application_traffic_in_both_directions() {
    let alice_did = "did:dht:z6MkAliceAliceAliceAliceAliceAliceAliceAlic";
    let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
    let context_id_str = "welcome-joiner-bidirectional-ctx";
    let context_id = scp_core::context::context_id_bytes(context_id_str);

    let network = FullStackNetwork::new();
    let alice = network.create_node(alice_did);
    let bob = network.create_node(bob_did);

    let alice_handle = alice
        .create_context(context_id_str, invite_params())
        .await
        .unwrap();
    alice.add_member(&alice_handle, bob_did).await.unwrap();
    let bob_handle = bob
        .join_from_welcome(context_id_str, &context_id)
        .await
        .unwrap();

    // Seed each party's per-member pseudonym for the other so both sends fan out
    // to a recipient routing id (§9.10.4).
    alice
        .manager
        .seed_peer_pseudonym(context_id_str, DID::from(bob_did), [0x42u8; 32])
        .await
        .unwrap();
    bob.manager
        .seed_peer_pseudonym(context_id_str, DID::from(alice_did), [0x37u8; 32])
        .await
        .unwrap();

    // Direction 1 — creator → joiner: Alice sends, Bob's installed group + Alice's
    // pulled sender key decrypt it.
    let a_to_b = b"application from the creator to the welcome-joiner";
    let _ = alice.take_sent_ciphertexts();
    alice.send_message(&alice_handle, a_to_b).await.unwrap();
    let alice_sent = alice.take_sent_ciphertexts();
    assert_eq!(
        alice_sent.len(),
        1,
        "Alice's send must produce exactly one application ciphertext"
    );
    let a_to_b_decrypted = bob
        .decrypt_message(context_id_str, &context_id, &alice_sent[0].1, alice_did)
        .await
        .unwrap();
    assert_eq!(
        a_to_b_decrypted.as_slice(),
        a_to_b.as_slice(),
        "the joiner must recover the creator's exact plaintext (creator → joiner)"
    );

    // Direction 2 — joiner → creator (the 2J landing signal): Bob sends, Alice
    // decrypts with Bob's pulled sender key.
    let b_to_a = b"application from the welcome-joiner back to the creator";
    let _ = bob.take_sent_ciphertexts();
    bob.send_message(&bob_handle, b_to_a).await.unwrap();
    let bob_sent = bob.take_sent_ciphertexts();
    assert_eq!(
        bob_sent.len(),
        1,
        "the joiner's send must produce exactly one application ciphertext"
    );
    let b_to_a_decrypted = alice
        .decrypt_message(context_id_str, &context_id, &bob_sent[0].1, bob_did)
        .await
        .unwrap();
    assert_eq!(
        b_to_a_decrypted.as_slice(),
        b_to_a.as_slice(),
        "the creator must recover the joiner's exact plaintext (joiner → creator) — \
         bidirectional application round-trip closed"
    );
}

// ---------------------------------------------------------------------------
// 1c. join_time_sender_key_distribution_uses_management_channel (H3)
// ---------------------------------------------------------------------------

/// H3: join-time sender-key distribution MUST travel over the MLS management
/// channel — MLS-wrapped as an `OuterEnvelope` so the joiner's actor receive
/// path (`Supervisor::deliver_commit_blob` → the context actor's
/// `decrypt_and_dispatch`) classifies it as a Management message and installs
/// the sender key through the gate-before-install path.
///
/// ADR-049 PR-7 (SCP-CRYPTOMOVE-001) moved the seal / wrap / open crypto off the
/// provider and onto the context actor. The inviter's in-actor MLS add now
/// pushes its MLS-wrapped sender key onto the transport during `add_member`, and
/// the joiner ingests it through the REAL actor receive path at
/// `join_from_welcome`. (The seam-level wrap → open → `OpenResult::Management`
/// round-trip is proved by the crate-internal
/// `golden_mls_encrypt_management_cross_roundtrip` KAT; this test proves the
/// end-to-end behavior over the real reserve + invite + spawn join path.)
///
/// The pre-fix bug (H3) posted the RAW HPKE-sealed
/// `SenderKeyDistributionMessage::KeyResponse` bytes straight onto the transport;
/// the receive dispatcher tried to deserialize them as an `OuterEnvelope` and
/// silently dropped them on failure. This test proves both halves:
///   * POSITIVE — after the wrapped distribution flows through the actor receive
///     path, Bob decrypts Alice's application traffic (her sender key installed).
///   * NEGATIVE — feeding the raw (un-wrapped) distribution bytes to the actor
///     receive path is rejected: they are not a valid `OuterEnvelope`, so the
///     management-channel MLS-wrap is mandatory, not optional.
#[tokio::test]
async fn join_time_sender_key_distribution_uses_management_channel() {
    let alice_did = "did:dht:z6MkAliceAliceAliceAliceAliceAliceAliceAlic";
    let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
    let context_id_str = "sender-key-mgmt-channel-ctx";
    let context_id = scp_core::context::context_id_bytes(context_id_str);

    let network = FullStackNetwork::new();
    let alice = network.create_node(alice_did);
    let bob = network.create_node(bob_did);

    // Stand up the shared group over the real join path. `add_member` runs the
    // in-actor MLS add, whose drain-and-deliver pushes Alice's MLS-WRAPPED sender
    // key onto the transport (the management channel); the harness harvests that
    // pushed blob and `join_from_welcome` feeds it to Bob's actor via
    // `deliver_commit_blob`, which classifies it as Management and installs
    // Alice's sender key through the same gate-before-install path production uses.
    let handle = alice
        .create_context(context_id_str, invite_params())
        .await
        .unwrap();
    alice.add_member(&handle, bob_did).await.unwrap();
    bob.join_from_welcome(context_id_str, &context_id)
        .await
        .unwrap();

    // POSITIVE: Alice's sender key was delivered over the management channel and
    // installed on Bob, so Bob decrypts Alice's application traffic. Seed Bob's
    // per-member pseudonym so the send fans out (§9.10.4).
    alice
        .manager
        .seed_peer_pseudonym(context_id_str, DID::from(bob_did), [0x42u8; 32])
        .await
        .unwrap();
    let plaintext = b"sender-key delivered over the management channel";
    alice.send_message(&handle, plaintext).await.unwrap();
    let sent = alice.take_sent_ciphertexts();
    assert_eq!(
        sent.len(),
        1,
        "Alice should have sent exactly one ciphertext"
    );
    let (_routing_id, ciphertext) = &sent[0];
    let decrypted = bob
        .decrypt_message(context_id_str, &context_id, ciphertext, alice_did)
        .await
        .unwrap();
    assert_eq!(
        decrypted.as_slice(),
        plaintext.as_slice(),
        "Bob must decrypt Alice's traffic — proving her sender key was delivered \
         and installed via the MLS management channel at join"
    );

    // NEGATIVE (H3 regression): the raw HPKE-sealed distribution bytes are a
    // valid `SenderKeyDistributionMessage`, but NOT a valid `OuterEnvelope`.
    // Feeding them straight to the actor receive path (the pre-fix shape) must be
    // rejected — the management-channel MLS-wrap is mandatory, not optional.
    let raw_distribution =
        scp_core::crypto::sender_keys::SenderKeyDistributionMessage::KeyResponse(
            scp_core::crypto::sender_keys::SenderKeyResponse {
                sender_did: alice_did.to_owned(),
                epoch: 1,
                hpke_sealed_key: [0u8; 48],
                ephemeral_pubkey: [0u8; 32],
                request_nonce: [0u8; 16],
            },
        )
        .to_bytes()
        .unwrap();
    let bare_open = bob
        .manager
        .deliver_commit_blob(context_id_str, raw_distribution)
        .await;
    assert!(
        bare_open.is_err(),
        "raw HPKE distribution bytes must not deserialize as an OuterEnvelope — \
         this is the regression H3 closes (silent distribution loss on join)"
    );
}

// ---------------------------------------------------------------------------
// 2. welcome_bytes_nonempty — AddMemberOutput contains data
// ---------------------------------------------------------------------------

/// The real production `MlsCryptoProvider::add_member` (unchanged by the
/// 2F-residual migration) produces a substantial Welcome + Commit when adding a
/// member's reserved `KeyPackage`. The `KeyPackage` is sourced from a real
/// `KeyPackageStoreActor` reservation (the retired legacy path was the only
/// thing that changed — the add itself is identical).
#[tokio::test]
async fn welcome_bytes_nonempty_with_key_package() {
    let alice_did = "did:dht:z6MkAliceAliceAliceAliceAliceAliceAliceAlic";
    let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
    let context_id = [0x01u8; 32];

    // Bob reserves a real KeyPackage from his own supervisor's store. Publish
    // his wrapping keypair first so the pooled KP carries the 0xFF01 leaf.
    let network = FullStackNetwork::new();
    let bob = network.create_node(bob_did);
    let (wpub, wsec) = bob.crypto.provider.wrapping_keypair_snapshot();
    bob.manager
        .set_wrapping_keys(
            DID::from(bob_did),
            wpub.to_vec(),
            Zeroizing::new(wsec.to_vec()),
        )
        .await
        .unwrap();
    let (_reservation_id, bob_kp_bytes) = bob
        .manager
        .reserve_key_package(DID::from(bob_did))
        .await
        .unwrap();

    // A bare creator provider creates a group and adds Bob's reserved KP.
    let alice_crypto = MlsCryptoProvider::new(
        alice_did.to_string(),
        std::sync::Arc::new(scp_clock::SystemClock),
    );
    alice_crypto.create_mls_group(&context_id).unwrap();
    alice_crypto.generate_sender_key(&context_id).unwrap();

    let output = alice_crypto
        .add_member(&context_id, bob_did, Some(&bob_kp_bytes))
        .unwrap();

    assert!(
        output.welcome_bytes.len() > 100,
        "Welcome should be substantial (got {} bytes)",
        output.welcome_bytes.len()
    );
    assert!(
        output.commit_bytes.len() > 10,
        "Commit should be non-trivial (got {} bytes)",
        output.commit_bytes.len()
    );
}

// ---------------------------------------------------------------------------
// 3. routing_id_determinism
// ---------------------------------------------------------------------------

#[test]
fn routing_id_determinism() {
    let did = "did:dht:z6MkSomeUser";

    let inv_id_a = derive_invitation_routing_id(did);
    let inv_id_b = derive_invitation_routing_id(did);
    assert_eq!(
        inv_id_a, inv_id_b,
        "invitation routing IDs must be deterministic"
    );

    let kp_id_a = derive_key_package_routing_id(did);
    let kp_id_b = derive_key_package_routing_id(did);
    assert_eq!(
        kp_id_a, kp_id_b,
        "key package routing IDs must be deterministic"
    );

    // Invitation and key package routing IDs must differ.
    assert_ne!(
        inv_id_a, kp_id_a,
        "invitation and key package routing IDs must use different domains"
    );

    // Different DIDs produce different routing IDs.
    let other_inv = derive_invitation_routing_id("did:dht:z6MkOtherUser");
    assert_ne!(inv_id_a, other_inv);
}
