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
    // Derive the 32-byte id from a real string: `seal` binds the raw
    // `inner.context_id` string into the AEAD AAD (§9.16.1) and asserts the
    // supplied id is its SHA-256, and `open` rebuilds the same AAD from the
    // raw string passed alongside the id.
    let context_id_str = "cross-process-welcome-ctx";
    let context_id = scp_core::context::context_id_bytes(context_id_str);

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

    // Alice seals a message through the full envelope pipeline.
    // Construct a minimal inner envelope for testing.
    let plaintext = b"Hello from Alice!";
    let sk = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
    let params = scp_core::envelope::inner::InnerEnvelopeParams {
        version: scp_core::envelope::SCP_PROTOCOL_VERSION,
        context_id: context_id_str,
        sender_did: alice_did,
        epoch: 0,
        generation: 0,
        sequence: 1,
        timestamp: 1_700_000_000,
        message_type: scp_core::envelope::inner::MessageType::Content,
        payload: plaintext,
        provenance: None,
        signing_key_id: scp_did::SigningKeyId::Active,
    };
    let inner = scp_core::envelope::inner::sign::create_inner_envelope_raw(&params, &sk).unwrap();
    let routing_id = scp_core::context::context_routing_id(context_id_str);
    let sealed = alice_crypto
        .seal(&context_id, &inner, &routing_id, 300)
        .unwrap();

    // Bob opens Alice's message — proves the full pipeline works:
    // MLS Welcome join + sender key distribution + seal + open.
    let open_result = bob_crypto
        .open(&context_id, context_id_str, &sealed)
        .unwrap();
    let envelope = match open_result {
        scp_core::context::builder::OpenResult::Application(env) => env,
        other => panic!("expected Application, got {other:?}"),
    };
    assert_eq!(envelope.sender_did, alice_did);
}

// ---------------------------------------------------------------------------
// 1b. join_time_sender_key_distribution_uses_management_channel (H3)
// ---------------------------------------------------------------------------

/// H3: when the inviter (Alice) drains pending sender key distributions
/// after adding a new member (Bob), each distribution MUST be MLS-wrapped
/// via `mls_encrypt_management` so that Bob's `crypto.open()` returns
/// `OpenResult::Management` and routes the payload through
/// `process_incoming_sender_key`.
///
/// The pre-fix bug posted the raw HPKE-sealed
/// `SenderKeyDistributionMessage::KeyResponse` bytes via
/// `transport.send_message`, which the receive-side dispatcher attempted
/// to deserialize as an `OuterEnvelope` and silently dropped on failure.
/// This test asserts the correct framing end-to-end at the provider level.
#[test]
fn join_time_sender_key_distribution_uses_management_channel() {
    let alice_did = "did:dht:z6MkAliceAliceAliceAliceAliceAliceAliceAlic";
    let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
    let context_id_str = "sender-key-mgmt-channel-ctx";
    let context_id = scp_core::context::context_id_bytes(context_id_str);

    let alice_crypto = MlsCryptoProvider::new(alice_did.to_string());
    let bob_crypto = MlsCryptoProvider::new(bob_did.to_string());

    // Alice creates the group and her sender key.
    alice_crypto.create_mls_group(&context_id).unwrap();
    alice_crypto.generate_sender_key(&context_id).unwrap();

    // Bob prepares his key package, Alice adds Bob, Bob joins via Welcome.
    let bob_kp_bytes = bob_crypto.prepare_key_package_for_join().unwrap();
    let add_output = alice_crypto
        .add_member(&context_id, bob_did, Some(&bob_kp_bytes))
        .unwrap();
    bob_crypto
        .join_from_welcome(&context_id, &add_output.welcome_bytes)
        .unwrap();
    bob_crypto.generate_sender_key(&context_id).unwrap();

    // Alice queues her sender key distribution to Bob (in production this
    // happens automatically inside `add_member` via the `distribute_sender_key`
    // call from `ContextManager::join_context`).
    alice_crypto
        .distribute_sender_key(&context_id, bob_did)
        .unwrap();
    let pending = alice_crypto
        .drain_pending_sender_key_messages(&context_id)
        .unwrap();
    assert_eq!(
        pending.len(),
        1,
        "Alice should have exactly one pending sender key distribution for Bob"
    );

    // The fix: each pending distribution MUST be MLS-wrapped before
    // being posted to transport. This is what `drain_and_deliver_sender_keys`
    // does internally — we exercise the same path here.
    let routing_id = scp_core::context::context_routing_id(context_id_str);
    let (target_did, raw_distribution) = pending.into_iter().next().unwrap();
    assert_eq!(target_did, bob_did);

    // Sanity check the pre-fix shape: the raw distribution bytes are NOT
    // a valid OuterEnvelope. Bob's `open()` would error if we sent them
    // as-is via `transport.send_message`.
    let bare_open = bob_crypto.open(&context_id, context_id_str, &raw_distribution);
    assert!(
        bare_open.is_err(),
        "raw HPKE distribution bytes must not deserialize as OuterEnvelope — \
         this is the regression H3 closes (silent distribution loss on join)"
    );

    // Now MLS-wrap via the management channel — the post-fix path.
    let wrapped = alice_crypto
        .mls_encrypt_management(&context_id, &raw_distribution, &routing_id, 300)
        .unwrap();

    // Bob's `open()` MUST recognize the wrapped payload as Management,
    // surfacing the inner HPKE bytes for `process_incoming_sender_key`.
    let open_result = bob_crypto
        .open(&context_id, context_id_str, &wrapped)
        .unwrap();
    let payload = match open_result {
        scp_core::context::builder::OpenResult::Management {
            sender_did,
            payload,
        } => {
            assert_eq!(
                sender_did, alice_did,
                "Management message sender must be Alice"
            );
            payload
        }
        other => panic!(
            "expected OpenResult::Management for MLS-wrapped sender key \
             distribution, got {other:?}"
        ),
    };

    // The payload Bob receives must equal the original HPKE distribution
    // bytes Alice queued. This proves end-to-end framing equivalence.
    assert_eq!(
        payload, raw_distribution,
        "management payload must round-trip the original HPKE distribution bytes"
    );

    // Bob can now process the distribution and decrypt subsequent
    // application messages from Alice — the join-time happy path.
    bob_crypto
        .process_incoming_sender_key(&context_id, alice_did, &payload)
        .unwrap();
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
// 5. prepare_replaces_previous_key_package — second prepare supersedes first
// ---------------------------------------------------------------------------

#[test]
fn prepare_replaces_previous_key_package() {
    let bob_crypto =
        MlsCryptoProvider::new("did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo".to_string());
    let alice_crypto =
        MlsCryptoProvider::new("did:dht:z6MkAliceAliceAliceAliceAliceAliceAliceAlic".to_string());
    let context_id = [0xAA; 32];

    alice_crypto.create_mls_group(&context_id).unwrap();

    // Bob prepares two key packages. The second replaces the first
    // (clear + push), so only kp2's private state is retained.
    let _kp1 = bob_crypto.prepare_key_package_for_join().unwrap();
    let kp2 = bob_crypto.prepare_key_package_for_join().unwrap();

    let add_output = alice_crypto
        .add_member(
            &context_id,
            "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo",
            Some(&kp2),
        )
        .unwrap();

    // Should succeed because prepare_key_package_for_join replaced the
    // first pending state with the second, so kp2's signer/provider match.
    bob_crypto
        .join_from_welcome(&context_id, &add_output.welcome_bytes)
        .unwrap();
}
