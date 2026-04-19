#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::similar_names
)]

//! B8: Encryption integration tests.
//!
//! Exercises MLS group lifecycle (create, add, join, remove, destroy),
//! forward secrecy, sender key generation/encrypt/decrypt, pull protocol
//! (epoch advance + verify), block notification roundtrip, double encryption
//! (inner to seal to open), pseudonym derivation, bucket padding, and chunking.

use openmls::prelude::*;
use scp_core::crypto::mls::credential::ScpCredential;
use scp_core::crypto::mls::encrypt::{decrypt, encrypt, serialize_ciphertext};
use scp_core::crypto::mls::group::{
    add_member, create_group, destroy_group, generate_key_package, join_group, remove_member,
};
use scp_core::crypto::sender_keys::{
    NonceDedup, decrypt_sender_layer, encrypt_sender_layer, generate_sender_key,
    publish_sender_key_epoch_advance, send_block_notification, verify_block_notification,
    verify_epoch_advance,
};
use scp_core::envelope::{
    InnerEnvelope, InnerEnvelopeParams, MessageType, Provenance, create_inner_envelope,
    derive_pseudonym, pad_to_bucket, seal_envelope, strip_padding,
};
use scp_core::identity::SigningKeyId;
use scp_platform::testing::InMemoryKeyCustody;
use scp_platform::traits::{KeyCustody, KeyType};
use tls_codec::{Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait};

// ---------------------------------------------------------------------------
// 1. mls_create_group
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mls_create_group() {
    let cred = ScpCredential::new(
        "did:dht:z6MkCreator123".to_owned(),
        None,
        SigningKeyId::Active,
    )
    .unwrap();

    let group = create_group(&cred).unwrap();
    assert_eq!(group.epoch().unwrap(), 0);
    assert_eq!(group.members().unwrap().len(), 1);
}

// ---------------------------------------------------------------------------
// 2. mls_add_member
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mls_add_member() {
    let creator_cred = ScpCredential::new(
        "did:dht:z6MkCreator456".to_owned(),
        None,
        SigningKeyId::Active,
    )
    .unwrap();

    let mut group = create_group(&creator_cred).unwrap();
    let initial_epoch = group.epoch().unwrap();
    assert_eq!(initial_epoch, 0);

    // Generate a key package for the new member.
    let member_cred = ScpCredential::new(
        "did:dht:z6MkMember789".to_owned(),
        None,
        SigningKeyId::Active,
    )
    .unwrap();
    let (key_package_bundle, _signer, _provider) = generate_key_package(&member_cred).unwrap();

    // Convert KeyPackageBundle to KeyPackageIn for add_member.
    let kp_bytes = key_package_bundle
        .key_package()
        .tls_serialize_detached()
        .unwrap();
    let kp_in = KeyPackageIn::tls_deserialize(&mut kp_bytes.as_slice()).unwrap();

    let result = add_member(&mut group, kp_in).unwrap();
    assert!(group.epoch().unwrap() > initial_epoch);
    assert_eq!(group.members().unwrap().len(), 2);

    // Result has commit and welcome messages.
    let _ = result.commit;
    let _ = result.welcome;
}

// ---------------------------------------------------------------------------
// 3. mls_join_group
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mls_join_group() {
    let creator_cred = ScpCredential::new(
        "did:dht:z6MkCreatorJoin".to_owned(),
        None,
        SigningKeyId::Active,
    )
    .unwrap();

    let mut group = create_group(&creator_cred).unwrap();

    let member_cred = ScpCredential::new(
        "did:dht:z6MkMemberJoin".to_owned(),
        None,
        SigningKeyId::Active,
    )
    .unwrap();
    let (key_package_bundle, signer, provider) = generate_key_package(&member_cred).unwrap();

    let kp_bytes = key_package_bundle
        .key_package()
        .tls_serialize_detached()
        .unwrap();
    let kp_in = KeyPackageIn::tls_deserialize(&mut kp_bytes.as_slice()).unwrap();

    let add_result = add_member(&mut group, kp_in).unwrap();

    // Join the group from the new member's side using the Welcome.
    let joined_group = join_group(&add_result.welcome, provider, signer).unwrap();

    // Both sides should be at the same epoch.
    assert_eq!(group.epoch().unwrap(), joined_group.epoch().unwrap());
}

// ---------------------------------------------------------------------------
// 4. mls_remove_member
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mls_remove_member() {
    let creator_cred = ScpCredential::new(
        "did:dht:z6MkCreatorRm".to_owned(),
        None,
        SigningKeyId::Active,
    )
    .unwrap();

    let mut group = create_group(&creator_cred).unwrap();

    let member_cred = ScpCredential::new(
        "did:dht:z6MkMemberRm".to_owned(),
        None,
        SigningKeyId::Active,
    )
    .unwrap();
    let (key_package_bundle, _signer, _provider) = generate_key_package(&member_cred).unwrap();

    let kp_bytes = key_package_bundle
        .key_package()
        .tls_serialize_detached()
        .unwrap();
    let kp_in = KeyPackageIn::tls_deserialize(&mut kp_bytes.as_slice()).unwrap();

    add_member(&mut group, kp_in).unwrap();
    assert_eq!(group.members().unwrap().len(), 2);

    let epoch_after_add = group.epoch().unwrap();

    // Find the member to remove (not self).
    let own_leaf = group.own_leaf_index().unwrap();
    let members = group.members().unwrap();
    let other = members
        .iter()
        .find(|m| m.index != own_leaf)
        .expect("should find non-self member");
    let other_index = other.index;

    remove_member(&mut group, other_index).unwrap();
    assert!(group.epoch().unwrap() > epoch_after_add);
    assert_eq!(group.members().unwrap().len(), 1);
}

// ---------------------------------------------------------------------------
// 5. mls_destroy_group
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mls_destroy_group() {
    let cred = ScpCredential::new(
        "did:dht:z6MkCreatorDest".to_owned(),
        None,
        SigningKeyId::Active,
    )
    .unwrap();

    let mut group = create_group(&cred).unwrap();
    assert!(group.epoch().is_ok());

    destroy_group(&mut group).unwrap();

    // Subsequent operations fail.
    assert!(group.epoch().is_err());
    assert!(group.members().is_err());

    // Destroying again fails.
    assert!(destroy_group(&mut group).is_err());
}

// ---------------------------------------------------------------------------
// 6. mls_forward_secrecy
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mls_forward_secrecy() {
    use scp_core::crypto::mls::epoch_grace::EpochGraceStore;
    use scp_core::crypto::mls::ratchet::{process_commit, serialize_mls_message};

    // Forward secrecy: ciphertext from epoch N must be undecryptable after
    // max_past_epochs+1 epoch advances discard the key material.
    // max_past_epochs=2 (SCP default).

    // Step 1: Create a 2-member group (Alice + Bob).
    let alice_cred =
        ScpCredential::new("did:dht:z6MkAliceFS".to_owned(), None, SigningKeyId::Active).unwrap();
    let bob_cred =
        ScpCredential::new("did:dht:z6MkBobFS".to_owned(), None, SigningKeyId::Active).unwrap();

    let mut alice_group = create_group(&alice_cred).unwrap();
    let (bob_kpb, bob_signer, bob_provider) = generate_key_package(&bob_cred).unwrap();
    let bob_kp_bytes = bob_kpb.key_package().tls_serialize_detached().unwrap();
    let bob_kp_in = KeyPackageIn::tls_deserialize(&mut bob_kp_bytes.as_slice()).unwrap();
    let add_result = add_member(&mut alice_group, bob_kp_in).unwrap();
    let mut bob_group = join_group(&add_result.welcome, bob_provider, bob_signer).unwrap();
    assert_eq!(alice_group.epoch().unwrap(), 1);
    assert_eq!(bob_group.epoch().unwrap(), 1);

    // Step 2: Encrypt at epoch 1. Bob can decrypt — proves the group works.
    let plaintext = b"epoch 1 secret";
    let ct = encrypt(&mut alice_group, plaintext).unwrap();
    let epoch1_ct_bytes = serialize_ciphertext(&ct).unwrap();
    let decrypted = decrypt(&mut bob_group, &epoch1_ct_bytes).unwrap();
    assert_eq!(decrypted.as_slice(), plaintext);

    // Step 3: Advance BOTH groups past max_past_epochs (2) via add_member.
    // Each add_member on Alice produces a Commit; Bob processes it to stay in sync.
    let mut bob_grace = EpochGraceStore::new();
    for i in 0..3 {
        let temp_cred =
            ScpCredential::new(format!("did:dht:z6MkTempFS{i}"), None, SigningKeyId::Active)
                .unwrap();
        let (temp_kpb, _signer, _provider) = generate_key_package(&temp_cred).unwrap();
        let kp_bytes = temp_kpb.key_package().tls_serialize_detached().unwrap();
        let kp_in = KeyPackageIn::tls_deserialize(&mut kp_bytes.as_slice()).unwrap();
        let result = add_member(&mut alice_group, kp_in).unwrap();

        // Bob processes Alice's Commit to advance his epoch too.
        let commit_bytes = serialize_mls_message(&result.commit).unwrap();
        process_commit(&mut bob_group, &commit_bytes, &mut bob_grace).unwrap();
    }

    // Both groups are now at epoch 4. With max_past_epochs=2, epoch 1 material
    // should have been discarded by OpenMLS.
    assert!(alice_group.epoch().unwrap() >= 4);
    assert!(bob_group.epoch().unwrap() >= 4);

    // Step 4: Attempt to decrypt the epoch-1 ciphertext with Bob's advanced group.
    // This MUST fail — if it succeeds, forward secrecy is broken.
    let replay_result = decrypt(&mut bob_group, &epoch1_ct_bytes);
    assert!(
        replay_result.is_err(),
        "forward secrecy violated: epoch 1 ciphertext was decryptable at epoch {}",
        bob_group.epoch().unwrap()
    );
}

// ---------------------------------------------------------------------------
// 7. sender_key_generation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sender_key_generation() {
    let key = generate_sender_key();
    assert_eq!(key.as_bytes().len(), 32);

    // Two keys should be different (with overwhelming probability).
    let key2 = generate_sender_key();
    assert_ne!(key.as_bytes(), key2.as_bytes());
}

// ---------------------------------------------------------------------------
// 8. sender_layer_roundtrip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sender_layer_roundtrip() {
    let key = generate_sender_key();
    let plaintext = b"Hello, SCP! This is a secret message.";

    let ciphertext =
        encrypt_sender_layer(&key, plaintext, "ctx-test", "did:dht:z6MkSender", 0, 0).unwrap();
    assert_ne!(&ciphertext, &plaintext[..]);

    let decrypted =
        decrypt_sender_layer(&key, &ciphertext, "ctx-test", "did:dht:z6MkSender", 0, 0).unwrap();
    assert_eq!(decrypted, plaintext);
}

// ---------------------------------------------------------------------------
// 9. sender_layer_aad_binding (wrong key fails)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sender_layer_aad_binding() {
    let key1 = generate_sender_key();
    let key2 = generate_sender_key();
    let plaintext = b"message for key1 only";

    let ciphertext =
        encrypt_sender_layer(&key1, plaintext, "ctx-test", "did:dht:z6MkSender", 0, 0).unwrap();

    // Decrypt with wrong key should fail (AES-GCM auth tag mismatch).
    let result = decrypt_sender_layer(&key2, &ciphertext, "ctx-test", "did:dht:z6MkSender", 0, 0);
    assert!(result.is_err(), "decrypting with wrong key should fail");
}

// ---------------------------------------------------------------------------
// 10. sender_key_pull_protocol
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sender_key_pull_protocol() {
    let custody = InMemoryKeyCustody::from_seed_bytes({
        let mut __s = [0u8; 32];
        __s[..8].copy_from_slice(&(10u64).to_le_bytes());
        __s
    });
    let signing_key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
    let public_key = custody.public_key(&signing_key).await.unwrap();

    let context_id = "ctx-pull-test";
    let sender_did = "did:dht:z6MkPullSender";

    // Publish an epoch advance.
    let advance_bytes = publish_sender_key_epoch_advance(
        &custody,
        &signing_key,
        context_id,
        sender_did,
        1, // epoch
        SigningKeyId::Active,
    )
    .await
    .unwrap();

    // Deserialize and verify the epoch advance.
    let advance: scp_core::crypto::sender_keys::SenderKeyEpochAdvance =
        rmp_serde::from_slice(&advance_bytes).unwrap();
    assert_eq!(advance.sender_did, sender_did);
    assert_eq!(advance.epoch, 1);

    let valid = verify_epoch_advance(&advance, context_id, public_key.as_bytes()).unwrap();
    assert!(valid, "epoch advance signature should be valid");
}

// ---------------------------------------------------------------------------
// 11. sender_key_request_response (end-to-end key exchange)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sender_key_request_response() {
    use scp_core::crypto::sender_keys::{
        HandleRequestParams, SenderKeyRequest, SenderKeyResponse, handle_sender_key_request,
        open_sender_key_response, request_sender_key,
    };
    use std::collections::HashSet;

    let requester_custody = InMemoryKeyCustody::from_seed_bytes({
        let mut __s = [0u8; 32];
        __s[..8].copy_from_slice(&(100u64).to_le_bytes());
        __s
    });
    let requester_sign_key = requester_custody
        .generate_keypair(KeyType::Ed25519)
        .await
        .unwrap();
    let requester_pub = requester_custody
        .public_key(&requester_sign_key)
        .await
        .unwrap();
    let requester_did = "did:dht:z6MkRequester";
    let sender_did = "did:dht:z6MkSender";

    // Generate a sender key to distribute.
    let sender_key = generate_sender_key();

    // Requester creates a request.
    let clock = scp_primitives::SystemClock;
    let request_result = request_sender_key(
        &requester_custody,
        &requester_sign_key,
        requester_did,
        sender_did,
        1, // epoch
        &clock,
    )
    .await
    .unwrap();

    // Deserialize the request.
    let request: SenderKeyRequest = rmp_serde::from_slice(&request_result.request_message).unwrap();
    assert_eq!(request.requester_did, requester_did);
    assert_eq!(request.sender_did, sender_did);
    assert_eq!(request.epoch, 1);

    // Sender handles the request.
    let block_list: HashSet<String> = HashSet::new();
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let params = HandleRequestParams {
        sender_key: &sender_key,
        context_id: "ctx-request-test",
        sender_did,
        epoch: 1,
        block_list: &block_list,
        context_members: None,
        now_secs,
    };
    let mut nonce_dedup = NonceDedup::new();

    let response_bytes = handle_sender_key_request(
        &request,
        requester_pub.as_bytes(),
        &params,
        &mut nonce_dedup,
    )
    .await
    .unwrap();

    // Response should be Some (requester is not blocked).
    assert!(
        response_bytes.is_some(),
        "non-blocked requester should get a response"
    );
    let response_bytes = response_bytes.unwrap();

    // Requester opens the response.
    let response: SenderKeyResponse = rmp_serde::from_slice(&response_bytes).unwrap();
    let recovered_key = open_sender_key_response(
        &requester_custody,
        &request_result.wrapping_key_handle,
        "ctx-request-test",
        &response,
    )
    .await
    .unwrap();

    // The recovered key should match the original sender key.
    assert_eq!(
        recovered_key.as_bytes(),
        sender_key.as_bytes(),
        "recovered key must match original sender key"
    );
}

// ---------------------------------------------------------------------------
// 12. sender_key_nonce_dedup
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sender_key_nonce_dedup() {
    let mut dedup = NonceDedup::new();
    let nonce = [0xABu8; 16];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // First check — not yet seen.
    assert!(!dedup.is_replayed(&nonce, now));

    // Record it.
    dedup.record(nonce, now);

    // Second check — now it's a replay.
    assert!(dedup.is_replayed(&nonce, now));
}

// ---------------------------------------------------------------------------
// 13. block_notification_roundtrip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn block_notification_roundtrip() {
    use scp_core::crypto::sender_keys::BlockNotification;

    let custody = InMemoryKeyCustody::from_seed_bytes({
        let mut __s = [0u8; 32];
        __s[..8].copy_from_slice(&(13u64).to_le_bytes());
        __s
    });
    let blocker_key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
    let blocker_pub = custody.public_key(&blocker_key).await.unwrap();

    let context_id = "ctx-block";
    let blocker_did = "did:dht:z6MkBlocker";
    let blocked_did = "did:dht:z6MkBlocked";

    // Send a block notification.
    let clock = scp_primitives::SystemClock;
    let notification_bytes = send_block_notification(
        &custody,
        &blocker_key,
        context_id,
        blocker_did,
        blocked_did,
        SigningKeyId::Active,
        &clock,
    )
    .await
    .unwrap();

    // Deserialize and verify.
    let notification: BlockNotification = rmp_serde::from_slice(&notification_bytes).unwrap();
    assert_eq!(notification.blocker, blocker_did);
    assert_eq!(notification.blocked, blocked_did);

    let valid =
        verify_block_notification(&notification, context_id, blocker_pub.as_bytes()).unwrap();
    assert!(valid, "block notification signature should be valid");
}

// ---------------------------------------------------------------------------
// 14. double_encryption_roundtrip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn double_encryption_roundtrip() {
    let custody = InMemoryKeyCustody::from_seed_bytes({
        let mut __s = [0u8; 32];
        __s[..8].copy_from_slice(&(14u64).to_le_bytes());
        __s
    });
    let signing_key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();

    let creator_cred = ScpCredential::new(
        "did:dht:z6MkCreatorDE".to_owned(),
        None,
        SigningKeyId::Active,
    )
    .unwrap();

    let mut creator_group = create_group(&creator_cred).unwrap();
    let sender_key = generate_sender_key();

    let payload = b"secret payload for double encryption test";
    let params = InnerEnvelopeParams {
        version: 1,
        context_id: "ctx-double-enc",
        sender_did: "did:dht:z6MkCreatorDE",
        epoch: 0,
        generation: 0,
        sequence: 0,
        timestamp: 1_700_000_000_000,
        message_type: MessageType::Content,
        payload,
        provenance: Some(Provenance {
            source: "test".to_owned(),
            upstream_hash: None,
        }),
        signing_key_id: SigningKeyId::Active,
    };

    let inner = create_inner_envelope(&params, &custody, &signing_key)
        .await
        .unwrap();

    // Verify inner envelope fields.
    assert_eq!(inner.context_id, "ctx-double-enc");
    assert_eq!(inner.sender_did, "did:dht:z6MkCreatorDE");

    // Test seal: inner -> sender key encrypt -> MLS encrypt -> outer envelope.
    let routing_id = [0x42u8; 32];
    let outer = seal_envelope(
        &inner,
        &mut creator_group,
        &sender_key,
        &routing_id,
        None,
        3600,
    )
    .unwrap();

    assert_eq!(outer.routing_id, routing_id);
    assert_eq!(outer.blob_ttl, 3600);
    assert!(!outer.encrypted_blob.is_empty());

    // Verify the layers are applied correctly by checking that the
    // encrypted blob differs from any plaintext representation.
    let inner_bytes = rmp_serde::to_vec_named(&inner).unwrap();
    assert_ne!(outer.encrypted_blob, inner_bytes);

    // Also verify the sender key layer independently:
    // encrypt then decrypt with the same key.
    let sk_encrypted = encrypt_sender_layer(
        &sender_key,
        &inner_bytes,
        "ctx-double-enc",
        "did:dht:z6MkSenderDE",
        0,
        0,
    )
    .unwrap();
    let sk_decrypted = decrypt_sender_layer(
        &sender_key,
        &sk_encrypted,
        "ctx-double-enc",
        "did:dht:z6MkSenderDE",
        0,
        0,
    )
    .unwrap();
    assert_eq!(sk_decrypted, inner_bytes);

    // And the MLS layer independently: encrypt then decrypt (needs 2 members).
    let joiner_cred = ScpCredential::new(
        "did:dht:z6MkJoinerDE".to_owned(),
        None,
        SigningKeyId::Active,
    )
    .unwrap();
    let (joiner_kp_bundle, joiner_signer, joiner_provider) =
        generate_key_package(&joiner_cred).unwrap();
    let kp_bytes = joiner_kp_bundle
        .key_package()
        .tls_serialize_detached()
        .unwrap();
    let kp_in = KeyPackageIn::tls_deserialize(&mut kp_bytes.as_slice()).unwrap();

    // Create a fresh group for the MLS layer test.
    let mut mls_sender_group = create_group(&creator_cred).unwrap();
    let add_result = add_member(&mut mls_sender_group, kp_in).unwrap();
    let mut mls_receiver_group =
        join_group(&add_result.welcome, joiner_provider, joiner_signer).unwrap();

    let mls_msg = encrypt(&mut mls_sender_group, &inner_bytes).unwrap();
    let mls_serialized = serialize_ciphertext(&mls_msg).unwrap();
    let mls_decrypted = decrypt(&mut mls_receiver_group, &mls_serialized).unwrap();
    assert_eq!(mls_decrypted, inner_bytes);

    // Deserialize back to inner envelope — full roundtrip through both layers.
    let recovered_inner: InnerEnvelope = rmp_serde::from_slice(&mls_decrypted).unwrap();
    let recovered_payload = strip_padding(&recovered_inner.payload).unwrap();
    assert_eq!(recovered_payload, payload);
    assert_eq!(recovered_inner.context_id, "ctx-double-enc");
    assert_eq!(recovered_inner.sender_did, "did:dht:z6MkCreatorDE");
}

// ---------------------------------------------------------------------------
// 15. pseudonym_derivation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pseudonym_derivation() {
    let custody = InMemoryKeyCustody::from_seed_bytes({
        let mut __s = [0u8; 32];
        __s[..8].copy_from_slice(&(15u64).to_le_bytes());
        __s
    });
    let identity_key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();

    let ctx_a = b"context-alpha";
    let ctx_b = b"context-beta";

    let pseudo_a = derive_pseudonym(&custody, &identity_key, ctx_a)
        .await
        .unwrap();
    let pseudo_b = derive_pseudonym(&custody, &identity_key, ctx_b)
        .await
        .unwrap();

    // Same identity, different contexts -> different pseudonyms.
    assert_ne!(
        pseudo_a.public_key, pseudo_b.public_key,
        "different contexts must produce different pseudonyms"
    );

    // Same identity, same context -> deterministic (same pseudonym).
    let pseudo_a2 = derive_pseudonym(&custody, &identity_key, ctx_a)
        .await
        .unwrap();
    assert_eq!(
        pseudo_a.public_key, pseudo_a2.public_key,
        "same inputs must produce the same pseudonym"
    );
}

// ---------------------------------------------------------------------------
// 16. padding_roundtrip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn padding_roundtrip() {
    // Small payload.
    let data = b"hello padding!";
    let padded = pad_to_bucket(data).unwrap();
    assert!(padded.len() >= data.len());
    // Padded size should be one of the bucket sizes.
    let bucket_sizes = [256, 1024, 4096, 16384, 65536, 262_144];
    assert!(
        bucket_sizes.contains(&padded.len()),
        "padded size {} is not a valid bucket size",
        padded.len()
    );

    let recovered = strip_padding(&padded).unwrap();
    assert_eq!(recovered, data);

    // Larger payload.
    let large_data = vec![0xABu8; 5000];
    let padded_large = pad_to_bucket(&large_data).unwrap();
    assert!(padded_large.len() >= large_data.len());
    assert!(bucket_sizes.contains(&padded_large.len()));

    let recovered_large = strip_padding(&padded_large).unwrap();
    assert_eq!(recovered_large, large_data);
}

// ---------------------------------------------------------------------------
// 17. mls_application_message_roundtrip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mls_application_message_roundtrip() {
    // MLS cannot decrypt own messages — need two members.
    let creator_cred = ScpCredential::new(
        "did:dht:z6MkCreatorMsg".to_owned(),
        None,
        SigningKeyId::Active,
    )
    .unwrap();
    let joiner_cred = ScpCredential::new(
        "did:dht:z6MkJoinerMsg".to_owned(),
        None,
        SigningKeyId::Active,
    )
    .unwrap();

    let mut creator_group = create_group(&creator_cred).unwrap();

    // Add joiner to group.
    let (joiner_kpb, joiner_signer, joiner_provider) = generate_key_package(&joiner_cred).unwrap();

    let kp_bytes = joiner_kpb.key_package().tls_serialize_detached().unwrap();
    let kp_in = KeyPackageIn::tls_deserialize(&mut kp_bytes.as_slice()).unwrap();

    let add_result = add_member(&mut creator_group, kp_in).unwrap();
    let mut joiner_group = join_group(&add_result.welcome, joiner_provider, joiner_signer).unwrap();

    // Creator encrypts a message.
    let plaintext = b"application-level message for MLS encrypt/decrypt test";
    let mls_message = encrypt(&mut creator_group, plaintext).unwrap();

    // Serialize the MLS ciphertext (as it would be on the wire).
    let serialized = serialize_ciphertext(&mls_message).unwrap();
    assert!(!serialized.is_empty());

    // Joiner decrypts.
    let decrypted = decrypt(&mut joiner_group, &serialized).unwrap();
    assert_eq!(decrypted, plaintext);
}
