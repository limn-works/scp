//! Runtime-coupled tests for the `scp_wrapping_key` `LeafNode` extension.
//!
//! The synchronous helpers under test live in the wasm32-safe `scp-mls` crate
//! (ADR-057), but these tests exercise the **runtime** sender-key protocol
//! (`crate::crypto::sender_keys`, `scp_platform` async key custody), which is
//! tokio-coupled and node-only. They therefore stay in `scp-runtime` and drive
//! `scp_mls::wrapping_extension` from the runtime side. The pure-sync extension
//! tests moved with the file into `scp_mls::wrapping_extension`.

#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::doc_markdown)]

use openmls::prelude::*;

use scp_mls::wrapping_extension::{
    SCP_WRAPPING_KEY_EXTENSION_TYPE, extract_own_wrapping_key, make_wrapping_key_extension,
};

fn test_credential(name: &str) -> scp_mls::ScpCredential {
    scp_mls::ScpCredential::new(
        format!("did:dht:z6Mk{name}"),
        None,
        scp_did::SigningKeyId::Active,
    )
    .unwrap()
}

/// AC: generate_wrapping_keypair produces distinct 32-byte keypairs.
#[test]
fn generate_wrapping_keypair_produces_valid_keypair() {
    let (pub1, sec1) = crate::crypto::sender_keys::key_protocol::generate_wrapping_keypair();
    let (pub2, sec2) = crate::crypto::sender_keys::key_protocol::generate_wrapping_keypair();

    assert_eq!(pub1.len(), 32);
    assert_eq!(sec1.len(), 32);
    assert_ne!(pub1, pub2, "wrapping keypairs must be distinct");
    assert_ne!(sec1, sec2, "wrapping secret keys must be distinct");

    // Verify the public key is derived from the secret key.
    let secret = x25519_dalek::StaticSecret::from(sec1);
    let derived_pub = x25519_dalek::PublicKey::from(&secret);
    assert_eq!(
        pub1,
        derived_pub.to_bytes(),
        "public key must derive from secret key"
    );
}

/// AC: send SenderKeyRequest -> response is HPKE-sealed to the requester's
/// wrapping key -> requester decrypts successfully.
#[tokio::test]
async fn sender_key_request_response_with_wrapping_key() {
    use crate::crypto::sender_keys::key_protocol::{
        HandleRequestParams, NonceDedup, handle_sender_key_request, open_sender_key_response,
        request_sender_key,
    };
    use scp_platform::testing::InMemoryKeyCustody;
    use scp_platform::traits::{KeyCustody, KeyType};
    use scp_protocol::crypto::sender_keys::generate_sender_key;
    use std::collections::HashSet;

    let custody = InMemoryKeyCustody::new();

    // Alice: the sender with a sender key.
    let _alice_signing = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
    let sender_key = generate_sender_key();

    // Bob: the requester who needs the key.
    let bob_signing = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
    let bob_pubkey = custody.public_key(&bob_signing).await.unwrap();

    // Bob creates a request with an ephemeral wrapping key.
    let clock = scp_clock::SystemClock;
    let request_result = request_sender_key(
        &custody,
        &bob_signing,
        "did:dht:bob",
        "did:dht:alice",
        1,
        &clock,
    )
    .await
    .unwrap();

    let request: scp_protocol::crypto::sender_keys::SenderKeyRequest =
        rmp_serde::from_slice(&request_result.request_message).unwrap();

    // Alice handles the request.
    let block_list: HashSet<String> = HashSet::new();
    let mut nonce_dedup = NonceDedup::new();
    let response_bytes = handle_sender_key_request(
        &request,
        bob_pubkey.as_bytes(),
        &HandleRequestParams {
            sender_key: &sender_key,
            context_id: "ctx-roundtrip",
            sender_did: "did:dht:alice",
            epoch: 1,
            block_list: &block_list,
            context_members: None,
            now_secs: request.timestamp,
        },
        &mut nonce_dedup,
    )
    .await
    .unwrap()
    .expect("Alice should respond to non-blocked Bob");

    let response: scp_protocol::crypto::sender_keys::SenderKeyResponse =
        rmp_serde::from_slice(&response_bytes).unwrap();

    // Bob decrypts the response using his ephemeral wrapping key handle.
    let recovered = open_sender_key_response(
        &custody,
        &request_result.wrapping_key_handle,
        "ctx-roundtrip",
        &response,
    )
    .await
    .unwrap();

    assert_eq!(
        recovered.as_bytes(),
        sender_key.as_bytes(),
        "Bob must recover Alice's sender key"
    );
}

/// AC: tamper with wrapping key -> HPKE open fails.
/// The `SenderKeyRequest` signature covers the `wrapping_pubkey`, so
/// tampering with the wrapping key causes signature verification failure.
#[tokio::test]
async fn tampered_wrapping_key_prevents_decryption() {
    use crate::crypto::sender_keys::key_protocol::{
        HandleRequestParams, NonceDedup, generate_wrapping_keypair, handle_sender_key_request,
        request_sender_key,
    };
    use scp_platform::testing::InMemoryKeyCustody;
    use scp_platform::traits::{KeyCustody, KeyType};
    use scp_protocol::crypto::sender_keys::generate_sender_key;
    use std::collections::HashSet;

    let custody = InMemoryKeyCustody::new();

    let _alice_signing = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
    let sender_key = generate_sender_key();

    let bob_signing = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
    let bob_pubkey = custody.public_key(&bob_signing).await.unwrap();

    let clock = scp_clock::SystemClock;
    let request_result = request_sender_key(
        &custody,
        &bob_signing,
        "did:dht:bob",
        "did:dht:alice",
        1,
        &clock,
    )
    .await
    .unwrap();

    let mut request: scp_protocol::crypto::sender_keys::SenderKeyRequest =
        rmp_serde::from_slice(&request_result.request_message).unwrap();

    // Tamper: replace Bob's wrapping pubkey with a random key.
    let (fake_pub, _fake_sec) = generate_wrapping_keypair();
    request.wrapping_pubkey = fake_pub;

    // Alice handles the tampered request. The signature covers the
    // wrapping_pubkey, so verification must fail.
    let block_list: HashSet<String> = HashSet::new();
    let mut nonce_dedup = NonceDedup::new();
    let result = handle_sender_key_request(
        &request,
        bob_pubkey.as_bytes(),
        &HandleRequestParams {
            sender_key: &sender_key,
            context_id: "ctx-roundtrip",
            sender_did: "did:dht:alice",
            epoch: 1,
            block_list: &block_list,
            context_members: None,
            now_secs: request.timestamp,
        },
        &mut nonce_dedup,
    )
    .await;

    // The tampered request should fail signature verification.
    assert!(
        result.is_err(),
        "tampered wrapping key must cause signature verification failure"
    );
}

/// Conformance test: sender-keys-wrapping-stable-001
///
/// Each member maintains a stable wrapping keypair per context, published
/// as the `scp_wrapping_key` `LeafNode` extension.
#[test]
fn sender_keys_wrapping_stable_001() {
    use crate::crypto::sender_keys::key_protocol::generate_wrapping_keypair;

    let (pub_key, sec_key) = generate_wrapping_keypair();

    // 1. Wrapping keypair is valid (public derives from secret).
    let secret = x25519_dalek::StaticSecret::from(sec_key);
    let derived_pub = x25519_dalek::PublicKey::from(&secret);
    assert_eq!(pub_key, derived_pub.to_bytes(), "public key derivation");

    // 2. Extension publishes 32-byte X25519 public key.
    let ext = make_wrapping_key_extension(&pub_key);
    assert_eq!(
        ext.extension_type(),
        ExtensionType::Unknown(SCP_WRAPPING_KEY_EXTENSION_TYPE),
        "extension type ID must be 0xFF01"
    );

    // 3. Create group with wrapping key -> LeafNode contains extension.
    let cred = test_credential("conformance");
    let group = scp_mls::group::create_group_with_wrapping_key(&cred, Some(&pub_key)).unwrap();
    let extracted = extract_own_wrapping_key(&group).unwrap();
    assert_eq!(extracted, Some(pub_key), "wrapping key in LeafNode");

    // 4. Extension survives as the same value across MLS Updates when
    //    the wrapping key is explicitly preserved.
    let bob_cred = test_credential("bob");
    let (bob_kp, _bob_signer, _bob_provider) =
        scp_mls::group::generate_key_package(&bob_cred).unwrap();
    let bob_kp_in: KeyPackageIn = bob_kp.key_package().clone().into();

    let mut group_mut = group;
    let _add = scp_mls::group::add_member(&mut group_mut, bob_kp_in).unwrap();

    let _commit =
        scp_mls::ratchet::propose_update_with_wrapping_key(&mut group_mut, &pub_key).unwrap();

    let after_update = extract_own_wrapping_key(&group_mut).unwrap();
    assert_eq!(
        after_update,
        Some(pub_key),
        "wrapping key must be stable across epoch advance"
    );

    // 5. Wrapping key can be rotated (identity key rotation simulation).
    let (new_pub, _new_sec) = generate_wrapping_keypair();
    let _commit2 =
        scp_mls::ratchet::propose_update_with_wrapping_key(&mut group_mut, &new_pub).unwrap();

    let after_rotation = extract_own_wrapping_key(&group_mut).unwrap();
    assert_eq!(
        after_rotation,
        Some(new_pub),
        "wrapping key must change on rotation"
    );
    assert_ne!(
        after_rotation,
        Some(pub_key),
        "rotated key must differ from original"
    );
}
