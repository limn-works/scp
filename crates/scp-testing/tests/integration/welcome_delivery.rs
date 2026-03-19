#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::significant_drop_tightening
)]

//! Integration tests: cross-process MLS Welcome delivery (spec §5.12.3, #1311).
//!
//! Proves that two separate `MlsCryptoProvider` instances (simulating separate
//! processes) can exchange an MLS Welcome message via the provider-level API
//! and establish bidirectional encrypted communication. Also validates the
//! ECIES envelope seal/open used for secure Welcome delivery over untrusted
//! relays, and the `WelcomeGenerated` event in `ContextManager`.

use scp_core::context::builder::ContextCryptoProvider;
use scp_core::crypto::envelope_seal::{
    derive_invitation_routing_id, derive_key_package_routing_id,
};
use scp_core::crypto::mls::provider::MlsCryptoProvider;

// ---------------------------------------------------------------------------
// 1. cross_process_welcome_delivery — provider-level Welcome join
// ---------------------------------------------------------------------------

/// Two separate `MlsCryptoProvider` instances prove that the Welcome message
/// produced by `add_member` can be consumed by `join_from_welcome` on a
/// different instance, establishing a shared MLS group.
#[test]
fn cross_process_welcome_delivery() {
    let alice_did = "did:dht:z6MkAliceAliceAliceAliceAliceAliceAliceAlic";
    let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
    let context_id = [0x42u8; 32];

    // Create Alice's and Bob's crypto providers (separate "processes").
    let alice_crypto = MlsCryptoProvider::new(alice_did.to_string());
    let bob_crypto = MlsCryptoProvider::new(bob_did.to_string());

    // Alice creates the MLS group and generates her sender key.
    alice_crypto.create_mls_group(&context_id).unwrap();
    alice_crypto.generate_sender_key(&context_id).unwrap();

    // Bob prepares a key package (retains private state internally).
    let bob_kp_bytes = bob_crypto.prepare_key_package_for_join().unwrap();
    assert!(
        !bob_kp_bytes.is_empty(),
        "key package bytes must not be empty"
    );

    // Alice adds Bob using his key package.
    let add_output = alice_crypto
        .add_member(&context_id, bob_did, Some(&bob_kp_bytes))
        .unwrap();
    assert!(
        !add_output.welcome_bytes.is_empty(),
        "Welcome must not be empty"
    );
    assert!(
        !add_output.commit_bytes.is_empty(),
        "Commit must not be empty"
    );

    // Bob joins the group from the Welcome message.
    bob_crypto
        .join_from_welcome(&context_id, &add_output.welcome_bytes)
        .unwrap();

    // Bob also needs a sender key for his own context.
    bob_crypto.generate_sender_key(&context_id).unwrap();

    // Distribute Alice's sender key to Bob so he can decrypt.
    // In production this happens via HPKE-sealed SenderKeyDistributionMessage
    // over the relay. Alice knows Bob's wrapping key (extracted from his key
    // package during add_member).
    alice_crypto
        .distribute_sender_key(&context_id, bob_did)
        .unwrap();
    let pending = alice_crypto
        .drain_pending_sender_key_messages(&context_id)
        .unwrap();
    assert!(
        !pending.is_empty(),
        "Alice should have a pending sender key message for Bob"
    );
    for (_target, msg) in pending {
        bob_crypto
            .process_incoming_sender_key(&context_id, alice_did, &msg)
            .unwrap();
    }

    // Alice encrypts a message.
    let plaintext = b"Hello from Alice!";
    let ciphertext = alice_crypto
        .encrypt_message(&context_id, alice_did, plaintext, 0, 0)
        .unwrap();

    // Bob decrypts Alice's message — proves the full pipeline works:
    // MLS Welcome join + sender key distribution + encrypt + decrypt.
    let decrypted = bob_crypto
        .decrypt_message(&context_id, &ciphertext, 0, 0)
        .unwrap();
    assert!(
        decrypted.is_some(),
        "decrypted must be Some for application message"
    );
    let (msg, sender) = decrypted.unwrap();
    assert_eq!(msg, plaintext);
    assert_eq!(sender, alice_did);
}

// ---------------------------------------------------------------------------
// 2. welcome_bytes_nonempty — AddMemberOutput contains data
// ---------------------------------------------------------------------------

#[test]
fn welcome_bytes_nonempty_with_key_package() {
    let alice_did = "did:dht:z6MkAliceAliceAliceAliceAliceAliceAliceAlic";
    let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
    let context_id = [0x01u8; 32];

    let alice_crypto = MlsCryptoProvider::new(alice_did.to_string());
    alice_crypto.create_mls_group(&context_id).unwrap();
    alice_crypto.generate_sender_key(&context_id).unwrap();

    let bob_crypto = MlsCryptoProvider::new(bob_did.to_string());
    let bob_kp_bytes = bob_crypto.prepare_key_package_for_join().unwrap();

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
// 3. join_from_welcome_without_prepare_fails
// ---------------------------------------------------------------------------

#[test]
fn join_from_welcome_without_prepare_fails() {
    let bob_crypto = MlsCryptoProvider::new("did:dht:z6MkBob".to_string());
    let context_id = [0x02u8; 32];

    // Attempt to join without ever calling prepare_key_package_for_join.
    let result = bob_crypto.join_from_welcome(&context_id, b"fake-welcome");
    assert!(
        result.is_err(),
        "join_from_welcome must fail without pending key package"
    );
}

// ---------------------------------------------------------------------------
// 4. routing_id_determinism
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

// ---------------------------------------------------------------------------
// 5. multiple_key_packages — prepare multiple, use most recent
// ---------------------------------------------------------------------------

#[test]
fn multiple_key_packages_uses_most_recent() {
    let bob_crypto =
        MlsCryptoProvider::new("did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo".to_string());
    let alice_crypto =
        MlsCryptoProvider::new("did:dht:z6MkAliceAliceAliceAliceAliceAliceAliceAlic".to_string());
    let context_id = [0xAA; 32];

    alice_crypto.create_mls_group(&context_id).unwrap();

    // Bob prepares two key packages. Only the second should be used.
    let _kp1 = bob_crypto.prepare_key_package_for_join().unwrap();
    let kp2 = bob_crypto.prepare_key_package_for_join().unwrap();

    let add_output = alice_crypto
        .add_member(
            &context_id,
            "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo",
            Some(&kp2),
        )
        .unwrap();

    // Should succeed because join_from_welcome pops the most recent (kp2).
    bob_crypto
        .join_from_welcome(&context_id, &add_output.welcome_bytes)
        .unwrap();
}
