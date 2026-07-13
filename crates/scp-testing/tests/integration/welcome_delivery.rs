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

use scp_core::context::supervisor::{InviteMemberOutcome, WelcomeJoinRequest};
use scp_core::context::{Capability, ContextMode, ContextParams};
use scp_core::crypto::envelope_seal::{
    derive_invitation_routing_id, derive_key_package_routing_id,
};
use scp_core::crypto::mls::provider::MlsCryptoProvider;
use scp_did::DID;
use scp_platform::testing::InMemoryKeyCustody;
use scp_testing::fullstack::{FullStackNetwork, FullStackNode};
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

/// Mirrors `FullStackNode::did_to_seed` so a test can reconstruct the exact
/// deterministic Ed25519 key each node signs with (and that the network resolver
/// resolves each DID to). Needed to supply `invite_member`'s proposer signing
/// key and to import the joiner's #active custody without a private accessor.
fn did_to_seed(did: &str) -> [u8; 32] {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    did.hash(&mut hasher);
    let h = hasher.finish();
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&h.to_le_bytes());
    seed
}

fn signing_key_for(did: &str) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&did_to_seed(did))
}

/// Stands up a shared MLS group between `alice` and `bob` over the REAL join
/// path (reserve → `invite_member` → `spawn_actor_from_welcome`) WITHOUT
/// distributing Alice's sender key to Bob. Returns nothing — both nodes' crypto
/// providers hold the installed joined group afterwards. Used by the sender-key
/// framing test, which must be the FIRST party to deliver Alice's sender key to
/// Bob (so the sender-key epoch is monotonic, not a duplicate of a join-time
/// distribution the higher-level `FullStackNode::add_member` would have made).
async fn stand_up_group_without_sender_key(
    alice: &FullStackNode,
    bob: &FullStackNode,
    alice_did: &str,
    bob_did: &str,
    context_id_str: &str,
) {
    // Bob reserves his own KeyPackage (publish his wrapping keypair first).
    let (wpub, wsec) = bob.crypto.provider.wrapping_keypair_snapshot();
    bob.manager
        .set_wrapping_keys(
            DID::from(bob_did),
            wpub.to_vec(),
            Zeroizing::new(wsec.to_vec()),
        )
        .await
        .unwrap();
    let (reservation_id, kp_bytes) = bob
        .manager
        .reserve_key_package(DID::from(bob_did))
        .await
        .unwrap();

    // Alice creates the context and invites Bob (real in-actor MLS add + sealed
    // bundle). `invite_member` does NOT distribute sender keys — exactly the
    // property this helper preserves.
    alice
        .create_context(context_id_str, invite_params())
        .await
        .unwrap();
    let outcome = alice
        .manager
        .invite_member(
            context_id_str.to_owned(),
            DID::from(alice_did),
            DID::from(bob_did),
            kp_bytes,
            vec![],
            &signing_key_for(alice_did),
        )
        .await
        .unwrap();
    let InviteMemberOutcome::Sealed { bundle, .. } = outcome;

    // Bob opens the sealed bundle under his #active custody and spawns a live
    // actor (installs the joined group into his provider).
    let custody = InMemoryKeyCustody::new();
    let active_handle = custody
        .import_ed25519_key(&signing_key_for(bob_did).to_bytes())
        .await;
    let enc: [u8; 32] = bundle.enc.as_slice().try_into().unwrap();
    let req = WelcomeJoinRequest {
        context_id: bundle.context_id.clone(),
        creator_did: bundle.creator_did.clone(),
        sealed_bundle_enc: enc,
        sealed_bundle_ct: bundle.ciphertext.clone(),
        reservation_id,
        local_pseudonym: Some([0x5au8; 32]),
    };
    bob.manager
        .spawn_actor_from_welcome(DID::from(bob_did), &custody, &active_handle, req)
        .await
        .unwrap();
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

    // Alice seals a message through the full envelope pipeline on her provider
    // (which retains the group after create_context — the actor shares it).
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
    let sealed = alice
        .crypto
        .provider
        .seal(&context_id, &inner, &routing_id, 300)
        .unwrap();

    // Bob opens Alice's message on his provider — proves the full pipeline:
    // real MLS Welcome join (spawn) + sender-key distribution + seal + open.
    let open_result = bob
        .crypto
        .provider
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

/// H3: when the inviter (Alice) drains a pending sender-key distribution for a
/// member (Bob), the distribution MUST be MLS-wrapped via
/// `mls_encrypt_management` so Bob's `crypto.open()` returns
/// `OpenResult::Management` and routes the payload through
/// `process_incoming_sender_key`.
///
/// The pre-fix bug posted the raw HPKE-sealed
/// `SenderKeyDistributionMessage::KeyResponse` bytes via
/// `transport.send_message`, which the receive-side dispatcher attempted to
/// deserialize as an `OuterEnvelope` and silently dropped on failure. This test
/// asserts the correct framing end-to-end at the provider level, over a group
/// stood up through the REAL reserve + invite + spawn join path.
#[tokio::test]
async fn join_time_sender_key_distribution_uses_management_channel() {
    let alice_did = "did:dht:z6MkAliceAliceAliceAliceAliceAliceAliceAlic";
    let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
    let context_id_str = "sender-key-mgmt-channel-ctx";
    let context_id = scp_core::context::context_id_bytes(context_id_str);

    let network = FullStackNetwork::new();
    let alice = network.create_node(alice_did);
    let bob = network.create_node(bob_did);

    // Stand up the shared group over the real join path, WITHOUT distributing
    // Alice's sender key (so this test's distribution is the first — a monotonic,
    // non-duplicate sender-key epoch for Bob).
    stand_up_group_without_sender_key(&alice, &bob, alice_did, bob_did, context_id_str).await;

    // Alice queues a fresh sender-key distribution to Bob and drains it.
    let alice_crypto = &alice.crypto.provider;
    let bob_crypto = &bob.crypto.provider;
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

    let routing_id = scp_core::context::context_routing_id(context_id_str);
    let (target_did, raw_distribution) = pending.into_iter().next().unwrap();
    assert_eq!(target_did, bob_did);

    // Sanity check the pre-fix shape: the raw distribution bytes are NOT a valid
    // OuterEnvelope. Bob's `open()` would error if we sent them as-is.
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

    // Bob's `open()` MUST recognize the wrapped payload as Management, surfacing
    // the inner HPKE bytes for `process_incoming_sender_key`.
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

    // The payload Bob receives must equal the original HPKE distribution bytes
    // Alice queued. This proves end-to-end framing equivalence.
    assert_eq!(
        payload, raw_distribution,
        "management payload must round-trip the original HPKE distribution bytes"
    );

    // Bob can now process the distribution. ADR-049 PR-6: process returns
    // (key, epoch) without installing; install unchecked.
    let (key, _epoch) = bob_crypto
        .process_incoming_sender_key(&context_id, alice_did, &payload)
        .unwrap();
    bob_crypto.set_sender_key_unchecked(&context_id, alice_did, key);
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
