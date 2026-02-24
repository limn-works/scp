//! Phase 1 Integration Test — proves all 7 ADRs work together.
//!
//! Alice and Bob exchange encrypted messages through the SCP native relay.
//! The relay sees nothing — no DIDs, no context IDs, no message content,
//! only routing pseudonyms and blob TTLs.
//!
//! Steps exercised:
//! 1. Alice creates a did:dht identity (ADR-003) using in-memory key custody (ADR-006)
//! 2. Bob creates a did:dht identity (ADR-003) using in-memory key custody (ADR-006)
//! 3. Alice creates an MLS group (ADR-001)
//! 4. Alice generates a sender key (ADR-007) and publishes a `SenderKeyEpochAdvance`
//! 5. Bob publishes `KeyPackages` (ADR-001)
//! 6. Alice adds Bob to the group using his `KeyPackage` (ADR-001)
//! 7. Bob requests and receives Alice's sender key via pull-based protocol (ADR-007)
//! 8. Alice creates a message, encrypts with sender key (ADR-007), wraps in inner
//!    envelope (ADR-002), encrypts with MLS (ADR-001), wraps in outer envelope with
//!    pseudonym routing (ADR-002)
//! 9. Alice sends the outer envelope via the native relay (ADR-004) using the
//!    transport trait (ADR-005)
//! 10. Bob receives the outer envelope via relay subscription (ADR-004, ADR-005)
//! 11. Bob decrypts MLS layer (ADR-001), decrypts sender key layer (ADR-007),
//!     verifies inner envelope signature (ADR-002)
//! 12. Bob reads Alice's message — content matches original
//! 13. The relay never saw: Alice's DID, Bob's DID, the context ID, the message
//!     content, or any metadata beyond the routing pseudonym and blob TTL
//!
//! See `.docs/adrs/phase-1.md` for the full Phase 1 ADR design.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashSet;
use std::fmt::Write;
use std::net::SocketAddr;

use futures::StreamExt;

use scp_core::crypto::mls::credential::ScpCredential;
use scp_core::crypto::mls::group::{add_member, create_group, generate_key_package, join_group};
use scp_core::crypto::sender_keys::{
    SenderKeyStore, decrypt_sender_layer, encrypt_sender_layer, generate_sender_key,
    handle_sender_key_request, open_sender_key_response, publish_sender_key_epoch_advance,
    request_sender_key, verify_epoch_advance,
};
use scp_core::envelope::inner::create_inner_envelope;
use scp_core::envelope::outer::{open_envelope, seal_envelope};
use scp_core::envelope::padding::strip_padding;
use scp_core::envelope::pseudonym::derive_pseudonym;
use scp_core::identity::{DidDht, DidMethod, ScpIdentity};
use scp_platform::testing::InMemoryKeyCustody;
use scp_platform::traits::KeyCustody;
use scp_transport::native::adapter::NativeRelayAdapter;
use scp_transport::native::server::{RelayConfig, RelayServer};
use scp_transport::native::storage::InMemoryBlobStorage;
use scp_transport::traits::{RoutingId, TransportAdapter, TransportEvent};

/// Starts a native relay server on an ephemeral port and returns its address.
async fn start_relay() -> SocketAddr {
    let config = RelayConfig {
        bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        ..RelayConfig::default()
    };
    let storage = InMemoryBlobStorage::new();
    let server = RelayServer::new(config, storage);
    server.start().await.unwrap()
}

/// Creates an SCP identity using the in-memory DID:DHT method.
///
/// Returns the identity, the key custody instance, and the active signing
/// key's public key bytes.
async fn create_identity() -> (ScpIdentity, InMemoryKeyCustody, Vec<u8>) {
    let custody = InMemoryKeyCustody::new();
    let dht_method = DidDht::new();
    let (identity, _doc): (ScpIdentity, _) = dht_method.create(&custody).await.unwrap();
    let pubkey = custody
        .public_key(&identity.active_signing_key)
        .await
        .unwrap();
    (identity, custody, pubkey.as_bytes().to_vec())
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
                // BackfillComplete, Reconnected — skip silently.
                TransportEvent::BackfillComplete | TransportEvent::Reconnected => {}
            }
        }
        panic!("stream ended without delivering an envelope");
    })
    .await
    .expect("timed out waiting for envelope from relay")
}

/// Phase 1 end-to-end integration test.
///
/// Exercises all 7 Phase 1 ADRs: identity (ADR-003), MLS (ADR-001),
/// envelope (ADR-002), transport trait (ADR-005), native relay (ADR-004),
/// platform adapters (ADR-006), and sender keys (ADR-007).
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn phase1_alice_bob_encrypted_message_via_relay() {
    // ---------------------------------------------------------------
    // Step 1 & 2: Alice and Bob create did:dht identities (ADR-003, ADR-006)
    // ---------------------------------------------------------------
    let (alice_id, alice_custody, alice_pubkey) = create_identity().await;
    let (bob_id, bob_custody, bob_pubkey) = create_identity().await;

    let ctx_id = "test-context-phase1";

    // ---------------------------------------------------------------
    // Step 3: Alice creates an MLS group (ADR-001)
    // ---------------------------------------------------------------
    let alice_cred = ScpCredential::new(alice_id.did.clone(), None);
    let mut alice_group = create_group(&alice_cred).unwrap();

    // ---------------------------------------------------------------
    // Step 4: Alice generates a sender key and publishes epoch advance (ADR-007)
    // ---------------------------------------------------------------
    let alice_sender_key = generate_sender_key();
    let mut alice_sk_store = SenderKeyStore::new();
    alice_sk_store.set(ctx_id, &alice_id.did, alice_sender_key.clone());

    let advance_bytes = publish_sender_key_epoch_advance(
        &alice_custody,
        &alice_id.active_signing_key,
        ctx_id,
        &alice_id.did,
        1,
    )
    .await
    .unwrap();

    // Verify the epoch advance is valid.
    let advance: scp_core::crypto::sender_keys::SenderKeyEpochAdvance =
        serde_json::from_slice(&advance_bytes).unwrap();
    let advance_ok = verify_epoch_advance(&advance, ctx_id, &alice_pubkey).unwrap();
    assert!(advance_ok, "epoch advance signature must verify");

    // ---------------------------------------------------------------
    // Step 5: Bob publishes key packages (ADR-001)
    // ---------------------------------------------------------------
    let bob_cred = ScpCredential::new(bob_id.did.clone(), None);
    let (bob_kp_bundle, bob_signer, bob_provider) = generate_key_package(&bob_cred).unwrap();

    // ---------------------------------------------------------------
    // Step 6: Alice adds Bob to the group using his key package (ADR-001)
    // ---------------------------------------------------------------
    let bob_kp_in: openmls::prelude::KeyPackageIn = bob_kp_bundle.key_package().clone().into();
    let add_result = add_member(&mut alice_group, bob_kp_in).unwrap();

    // Bob joins the group via the Welcome message.
    let mut bob_group = join_group(&add_result.welcome, bob_provider, bob_signer).unwrap();

    // Both should see 2 members at epoch 1.
    assert_eq!(alice_group.members().unwrap().len(), 2);
    assert_eq!(bob_group.members().unwrap().len(), 2);
    assert_eq!(alice_group.epoch().unwrap(), 1);
    assert_eq!(bob_group.epoch().unwrap(), 1);

    // ---------------------------------------------------------------
    // Step 7: Bob requests and receives Alice's sender key (ADR-007)
    // ---------------------------------------------------------------
    let req_result = request_sender_key(
        &bob_custody,
        &bob_id.active_signing_key,
        &bob_id.did,
        &alice_id.did,
        1,
    )
    .await
    .unwrap();

    // Alice handles the request (verifies signature, HPKE-encrypts the key).
    let sk_request: scp_core::crypto::sender_keys::SenderKeyRequest =
        serde_json::from_slice(&req_result.request_message).unwrap();

    let block_list: HashSet<String> = HashSet::new();
    let resp_bytes = handle_sender_key_request(
        &sk_request,
        &bob_pubkey,
        &alice_sender_key,
        &alice_id.did,
        1,
        &block_list,
    )
    .await
    .unwrap()
    .expect("response should not be None (Bob is not blocked)");

    // Bob decrypts the response to obtain Alice's sender key.
    let sk_response: scp_core::crypto::sender_keys::SenderKeyResponse =
        serde_json::from_slice(&resp_bytes).unwrap();
    let received_sk =
        open_sender_key_response(&bob_custody, &req_result.wrapping_key_handle, &sk_response)
            .await
            .unwrap();

    // Verify the key material matches.
    assert_eq!(
        received_sk.as_bytes(),
        alice_sender_key.as_bytes(),
        "Bob must receive Alice's exact sender key"
    );

    // Bob stores Alice's sender key.
    let mut bob_sk_store = SenderKeyStore::new();
    bob_sk_store.set(ctx_id, &alice_id.did, received_sk);

    // ---------------------------------------------------------------
    // Step 8: Alice encrypts message with sender key, wraps in envelopes (ADR-002, ADR-007)
    // ---------------------------------------------------------------
    let original_msg = b"Hello Bob, this is a secret message from Alice!";

    // 8a. Encrypt with sender key (ADR-007).
    let sk_encrypted = encrypt_sender_layer(&alice_sender_key, original_msg).unwrap();

    // 8b. Create inner envelope with signature (ADR-002).
    let inner_env = create_inner_envelope(
        ctx_id,
        &alice_id.did,
        alice_group.epoch().unwrap(),
        0, // generation
        1, // sequence
        1_700_000_000,
        &sk_encrypted,
        None, // no provenance for this test
        &alice_custody,
        &alice_id.active_signing_key,
    )
    .await
    .unwrap();

    // 8c. Derive pseudonym for routing (ADR-002).
    let pseudonym = derive_pseudonym(&alice_custody, &alice_id.identity_key, ctx_id.as_bytes())
        .await
        .unwrap();

    let routing_bytes = pseudonym.public_key.as_bytes();
    let routing_arr: [u8; 32] = routing_bytes.try_into().unwrap();

    // 8d. Seal: serialize inner, encrypt with MLS, wrap in outer envelope (ADR-001, ADR-002).
    let outer_env = seal_envelope(
        &inner_env,
        &mut alice_group,
        &routing_arr,
        None, // broadcast
        3600, // 1 hour TTL
    )
    .unwrap();

    // ---------------------------------------------------------------
    // Step 9 & 10: Alice sends via relay, Bob receives (ADR-004, ADR-005)
    // ---------------------------------------------------------------
    let relay_addr = start_relay().await;
    let relay_url = format!("ws://{relay_addr}/scp/v1");

    // Bob subscribes first so the relay delivers the message when Alice sends.
    let bob_adapter = NativeRelayAdapter::connect(&relay_url).await.unwrap();
    let bob_routing = RoutingId::new(routing_arr);
    let mut stream = bob_adapter.subscribe(&bob_routing, None).await.unwrap();

    // Alice connects and sends.
    let alice_adapter = NativeRelayAdapter::connect(&relay_url).await.unwrap();
    let _blob_id = alice_adapter.send(&outer_env).await.unwrap();

    let received_outer = receive_envelope(&mut stream).await;

    // Verify the outer envelope preserves routing metadata.
    assert_eq!(
        received_outer.routing_id, outer_env.routing_id,
        "routing_id must match"
    );
    assert_eq!(
        received_outer.blob_ttl, outer_env.blob_ttl,
        "blob_ttl must match"
    );

    // ---------------------------------------------------------------
    // Step 11: Bob decrypts MLS layer, decrypts sender key layer,
    //          verifies inner envelope signature (ADR-001, ADR-002, ADR-007)
    // ---------------------------------------------------------------

    // 11a. Open outer envelope: MLS decrypt + inner signature verification.
    let verified_inner = open_envelope(&received_outer, &mut bob_group, &alice_pubkey).unwrap();

    // 11b. Strip padding to get the sender-key-encrypted payload.
    let sk_encrypted_payload = strip_padding(&verified_inner.payload).unwrap();

    // 11c. Decrypt sender key layer (ADR-007).
    let bob_alice_sk = bob_sk_store
        .get(ctx_id, &alice_id.did)
        .expect("Bob must have Alice's sender key");
    let decrypted_msg = decrypt_sender_layer(bob_alice_sk, &sk_encrypted_payload).unwrap();

    // ---------------------------------------------------------------
    // Step 12: Bob reads Alice's message — content matches original
    // ---------------------------------------------------------------
    assert_eq!(
        decrypted_msg, original_msg,
        "decrypted message must match original"
    );

    // ---------------------------------------------------------------
    // Step 13: Verify relay never saw sensitive metadata
    // ---------------------------------------------------------------
    // The outer envelope only contains: routing_id, recipient_hint, blob_ttl,
    // encrypted_blob. None of these reveal:
    // - Alice's DID (hidden inside MLS-encrypted inner envelope)
    // - Bob's DID (hidden inside MLS-encrypted inner envelope)
    // - The context ID (hidden inside MLS-encrypted inner envelope)
    // - The message content (double-encrypted: sender key + MLS)
    //
    // The routing_id is a pseudonym derived from Alice's identity key and the
    // context ID — unlinkable to Alice's DID without the identity key material.

    // Verify the routing_id is NOT Alice's DID or any recognizable identifier.
    let routing_hex = hex_encode(&received_outer.routing_id);
    assert!(
        !routing_hex.contains(&alice_id.did),
        "routing_id must not contain Alice's DID"
    );
    assert!(
        !routing_hex.contains(&bob_id.did),
        "routing_id must not contain Bob's DID"
    );

    // Verify the encrypted blob cannot be deserialized as an InnerEnvelope.
    let inner_attempt: Result<scp_core::envelope::inner::InnerEnvelope, _> =
        rmp_serde::from_slice(&received_outer.encrypted_blob);
    assert!(
        inner_attempt.is_err(),
        "relay's encrypted_blob must not be deserializable as InnerEnvelope"
    );

    // Verify context_id is not present in the outer envelope bytes.
    let outer_bytes = received_outer.to_bytes().unwrap();
    assert!(
        !contains_subsequence(&outer_bytes, ctx_id.as_bytes()),
        "outer envelope bytes must not contain the context ID"
    );
}

/// Integration test: native relay adapter send/receive roundtrip.
///
/// Tests that the transport adapter trait (ADR-005) correctly routes
/// envelopes through the native relay server (ADR-004).
#[tokio::test]
async fn native_relay_adapter_send_receive_roundtrip() {
    let relay_addr = start_relay().await;
    let relay_url = format!("ws://{relay_addr}/scp/v1");

    // Create a minimal outer envelope for transport testing.
    let routing_id = [0xAA; 32];
    let outer = scp_core::envelope::outer::create_outer_envelope(
        &routing_id,
        None,
        3600,
        vec![0x01, 0x02, 0x03, 0x04],
    )
    .unwrap();

    // Connect sender and subscriber adapters.
    let send_adapter = NativeRelayAdapter::connect(&relay_url).await.unwrap();
    let recv_adapter = NativeRelayAdapter::connect(&relay_url).await.unwrap();

    // Subscribe first, then send.
    let routing = RoutingId::new(routing_id);
    let mut stream = recv_adapter.subscribe(&routing, None).await.unwrap();

    let blob_id = send_adapter.send(&outer).await.unwrap();
    assert_eq!(blob_id.as_bytes().len(), 32, "blob_id must be 32 bytes");

    // Receive the envelope.
    let got = receive_envelope(&mut stream).await;

    assert_eq!(got.routing_id, outer.routing_id);
    assert_eq!(got.blob_ttl, outer.blob_ttl);
    assert_eq!(got.encrypted_blob, outer.encrypted_blob);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Hex-encodes bytes for assertion messages.
fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

/// Checks if `haystack` contains `needle` as a contiguous subsequence.
fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
