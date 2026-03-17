//! Encrypted relay roundtrip — proves all 7 Phase 1 ADRs work together.
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
use std::net::SocketAddr;
use std::sync::Arc;

use futures::StreamExt;

use scp_core::crypto::mls::credential::ScpCredential;
use scp_core::crypto::mls::group::{
    ScpMlsGroup, add_member, create_group, generate_key_package, join_group,
};
use scp_core::crypto::sender_keys::{
    SenderKeyStore, generate_sender_key, handle_sender_key_request, open_sender_key_response,
    publish_sender_key_epoch_advance, request_sender_key, verify_epoch_advance,
};
use scp_core::envelope::inner::{InnerEnvelopeParams, MessageType, create_inner_envelope};
use scp_core::envelope::outer::{open_envelope, seal_envelope};
use scp_core::envelope::padding::strip_padding;
use scp_core::envelope::pseudonym::derive_pseudonym;
use scp_identity::{DidDht, DidMethod, ScpIdentity};
use scp_platform::error::PlatformError;
use scp_platform::testing::InMemoryKeyCustody;
use scp_platform::traits::{
    CustodyType, KeyCustody, KeyHandle, KeyType, PseudonymKeypair, PublicKey, SharedSecret,
    Signature,
};
use scp_transport::native::adapter::NativeRelayAdapter;
use scp_transport::native::server::{RelayConfig, RelayServer};
use scp_transport::native::storage::BlobStorageBackend;
use scp_transport::relay::connection::{RelayUrlSource, SourcedRelayUrl};
use scp_transport::traits::{RoutingId, TransportAdapter, TransportEvent};

/// A [`KeyCustody`] adapter that delegates signing to an [`ScpMlsGroup`]'s
/// MLS signer key. This is used in integration tests to create inner envelopes
/// signed by the correct MLS key, as required by SCP-177.
///
/// Only `sign` and `public_key` are implemented; other methods return errors
/// since they are not needed for inner envelope creation.
struct MlsGroupKeyCustody<'a> {
    group: &'a ScpMlsGroup,
}

#[allow(clippy::manual_async_fn)]
impl KeyCustody for MlsGroupKeyCustody<'_> {
    fn generate_keypair(
        &self,
        _key_type: KeyType,
    ) -> impl Future<Output = Result<KeyHandle, PlatformError>> + Send {
        async { Err(PlatformError::CustodyError("not supported".into())) }
    }

    fn sign(
        &self,
        _key: &KeyHandle,
        data: &[u8],
    ) -> impl Future<Output = Result<Signature, PlatformError>> + Send {
        let result = self
            .group
            .sign(data)
            .map(Signature::new)
            .map_err(|e| PlatformError::CustodyError(e.to_string()));
        async { result }
    }

    fn public_key(
        &self,
        _key: &KeyHandle,
    ) -> impl Future<Output = Result<PublicKey, PlatformError>> + Send {
        let result = self
            .group
            .signer_public_key()
            .map(PublicKey::new)
            .map_err(|e| PlatformError::CustodyError(e.to_string()));
        async { result }
    }

    fn destroy_key(
        &self,
        _key: &KeyHandle,
    ) -> impl Future<Output = Result<(), PlatformError>> + Send {
        async { Err(PlatformError::CustodyError("not supported".into())) }
    }

    fn dh_agree(
        &self,
        _key: &KeyHandle,
        _peer_public: &[u8; 32],
    ) -> impl Future<Output = Result<SharedSecret, PlatformError>> + Send {
        async { Err(PlatformError::CustodyError("not supported".into())) }
    }

    fn derive_pseudonym(
        &self,
        _key: &KeyHandle,
        _context_id: &[u8],
    ) -> impl Future<Output = Result<PseudonymKeypair, PlatformError>> + Send {
        async { Err(PlatformError::CustodyError("not supported".into())) }
    }

    fn derive_rotatable_pseudonym(
        &self,
        _key: &KeyHandle,
        _context_id: &[u8],
        _pseudonym_epoch: u64,
    ) -> impl Future<Output = Result<PseudonymKeypair, PlatformError>> + Send {
        async { Err(PlatformError::CustodyError("not supported".into())) }
    }

    fn custody_type(&self, _key: &KeyHandle) -> CustodyType {
        CustodyType::InMemory
    }
}

/// Starts a native relay server on an ephemeral port and returns its address.
async fn start_relay() -> SocketAddr {
    let config = RelayConfig {
        bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        delivery_jitter_ms: 0,
        ..RelayConfig::default()
    };
    let storage = Arc::new(BlobStorageBackend::in_memory());
    let server = RelayServer::new(config, storage);
    let (_handle, addr) = server.start().await.unwrap();
    addr
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
                // BackfillComplete, Reconnected, SuppressionDetected — skip silently.
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

/// Phase 1 end-to-end integration test.
///
/// Exercises all 7 Phase 1 ADRs: identity (ADR-003), MLS (ADR-001),
/// envelope (ADR-002), transport trait (ADR-005), native relay (ADR-004),
/// platform adapters (ADR-006), and sender keys (ADR-007).
#[tokio::test]
// Integration test exercises full Phase 1 flow; splitting would
// fragment the sequential scenario.
#[allow(clippy::too_many_lines)]
async fn alice_bob_encrypted_message_via_relay() {
    // ---------------------------------------------------------------
    // Step 1 & 2: Alice and Bob create did:dht identities (ADR-003, ADR-006)
    // ---------------------------------------------------------------
    let (alice_id, alice_custody, alice_pubkey) = create_identity().await;
    let (bob_id, bob_custody, bob_pubkey) = create_identity().await;

    let ctx_id = "test-context-roundtrip";

    // ---------------------------------------------------------------
    // Step 3: Alice creates an MLS group (ADR-001)
    // ---------------------------------------------------------------
    let alice_cred = ScpCredential::new(
        alice_id.did.clone(),
        None,
        scp_identity::SigningKeyId::Active,
    )
    .unwrap();
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
        scp_identity::SigningKeyId::Active,
    )
    .await
    .unwrap();

    // Verify the epoch advance is valid.
    let advance: scp_core::crypto::sender_keys::SenderKeyEpochAdvance =
        rmp_serde::from_slice(&advance_bytes).unwrap();
    let advance_ok = verify_epoch_advance(&advance, ctx_id, &alice_pubkey).unwrap();
    assert!(advance_ok, "epoch advance signature must verify");

    // ---------------------------------------------------------------
    // Step 5: Bob publishes key packages (ADR-001)
    // ---------------------------------------------------------------
    let bob_cred =
        ScpCredential::new(bob_id.did.clone(), None, scp_identity::SigningKeyId::Active).unwrap();
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
        rmp_serde::from_slice(&req_result.request_message).unwrap();

    let block_list: HashSet<String> = HashSet::new();
    let mut nonce_dedup = scp_core::crypto::sender_keys::NonceDedup::new();
    let resp_bytes = handle_sender_key_request(
        &sk_request,
        &bob_pubkey,
        &scp_core::crypto::sender_keys::HandleRequestParams {
            sender_key: &alice_sender_key,
            context_id: "ctx-1",
            sender_did: &alice_id.did,
            epoch: 1,
            block_list: &block_list,
            context_members: None,
            now_secs: sk_request.timestamp,
        },
        &mut nonce_dedup,
    )
    .await
    .unwrap()
    .expect("response should not be None (Bob is not blocked)");

    // Bob decrypts the response to obtain Alice's sender key.
    let sk_response: scp_core::crypto::sender_keys::SenderKeyResponse =
        rmp_serde::from_slice(&resp_bytes).unwrap();
    let received_sk = open_sender_key_response(
        &bob_custody,
        &req_result.wrapping_key_handle,
        "ctx-1",
        &sk_response,
    )
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
    // Step 8: Alice wraps message in envelopes with sender key + MLS (ADR-002, ADR-007)
    // ---------------------------------------------------------------
    let original_msg = b"Hello Bob, this is a secret message from Alice!";

    // 8a. Create inner envelope with signature (ADR-002).
    //     The inner envelope must be signed with the MLS group signer's key
    //     (not Alice's identity key) because open_envelope resolves the
    //     sender's public key from the MLS group tree (SCP-177).
    let alice_mls_custody = MlsGroupKeyCustody {
        group: &alice_group,
    };
    // The handle value doesn't matter — MlsGroupKeyCustody ignores it
    // and always delegates to the group's signer.
    let dummy_handle = KeyHandle::new(0);
    let inner_env = create_inner_envelope(
        &InnerEnvelopeParams {
            context_id: ctx_id,
            sender_did: &alice_id.did,
            epoch: alice_group.epoch().unwrap(),
            generation: 0,
            sequence: 1,
            timestamp: 1_700_000_000,
            message_type: MessageType::Content,
            payload: original_msg,
            provenance: None,
            signing_key_id: scp_core::identity::SigningKeyId::Active,
            version: scp_core::envelope::inner::SCP_INNER_ENVELOPE_VERSION,
        },
        &alice_mls_custody,
        &dummy_handle,
    )
    .await
    .unwrap();

    // 8b. Derive pseudonym for routing (ADR-002).
    let pseudonym = derive_pseudonym(&alice_custody, &alice_id.identity_key, ctx_id.as_bytes())
        .await
        .unwrap();

    let routing_bytes = pseudonym.public_key.as_bytes();
    let routing_arr: [u8; 32] = routing_bytes.try_into().unwrap();

    // 8c. Seal: serialize inner, encrypt with sender key, encrypt with MLS,
    //     wrap in outer envelope (ADR-001, ADR-002, ADR-007).
    let outer_env = seal_envelope(
        &inner_env,
        &mut alice_group,
        &alice_sender_key,
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

    // Connect via connect_sourced with DhtResolved source (local ws:// relay, §10.12.6).
    let sourced = SourcedRelayUrl {
        url: relay_url,
        source: RelayUrlSource::DhtResolved,
    };

    // Bob subscribes first so the relay delivers the message when Alice sends.
    let bob_adapter = NativeRelayAdapter::connect_sourced(&sourced).await.unwrap();
    let bob_routing = RoutingId::new(routing_arr);
    let mut stream = bob_adapter.subscribe(&bob_routing, None).await.unwrap();

    // Alice connects and sends.
    let alice_adapter = NativeRelayAdapter::connect_sourced(&sourced).await.unwrap();
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

    // 11a. Open outer envelope: MLS decrypt + sender key decrypt + inner
    //      signature verification (ADR-001, ADR-002, ADR-007).
    //      The sender's Ed25519 public key is resolved internally from the
    //      MLS group state (SCP-177) — no explicit public key argument needed.
    let bob_alice_sk = bob_sk_store
        .get(ctx_id, &alice_id.did)
        .expect("Bob must have Alice's sender key");
    let verified_inner = open_envelope(
        &received_outer,
        &mut bob_group,
        bob_alice_sk,
        &inner_env.context_id,
        &inner_env.sender_did,
        inner_env.epoch,
        inner_env.sequence,
    )
    .unwrap();

    // 11b. Strip padding to recover original plaintext.
    let decrypted_msg = strip_padding(&verified_inner.payload).unwrap();

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
    let routing_hex = hex::encode(&received_outer.routing_id);
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

    // Connect sender and subscriber adapters via connect_sourced with
    // DhtResolved source (local ws:// relay, §10.12.6).
    let sourced = SourcedRelayUrl {
        url: relay_url,
        source: RelayUrlSource::DhtResolved,
    };
    let send_adapter = NativeRelayAdapter::connect_sourced(&sourced).await.unwrap();
    let recv_adapter = NativeRelayAdapter::connect_sourced(&sourced).await.unwrap();

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

/// Integration test: ws:// relay connection with provenance-based validation (SCP-234, AC7).
///
/// Tests that the `connect_sourced` path:
/// 1. Permits ws:// from DHT-resolved sources (self-hosted relay behind NAT)
/// 2. Permits ws:// to loopback from any source (loopback exemption, §10.12.6)
/// 3. Rejects ws:// to non-loopback hosts from non-DHT sources
/// 4. Delivers messages end-to-end over a ws:// relay when provenance is valid
///
/// This ensures `validate_relay_url` is wired into the actual connection path,
/// not just exercised in isolation by unit tests.
#[tokio::test]
async fn ws_relay_connect_sourced_validation_scp234() {
    let relay_addr = start_relay().await;
    let relay_url = format!("ws://{relay_addr}/scp/v1");

    // --- 1. ws:// from DhtResolved is permitted and delivers messages ---
    let dht_sourced = SourcedRelayUrl {
        url: relay_url.clone(),
        source: RelayUrlSource::DhtResolved,
    };

    let send_adapter = NativeRelayAdapter::connect_sourced(&dht_sourced)
        .await
        .expect("ws:// from DhtResolved should be permitted");
    let recv_adapter = NativeRelayAdapter::connect_sourced(&dht_sourced)
        .await
        .expect("ws:// from DhtResolved should be permitted");

    // Create a minimal outer envelope for transport testing.
    let routing_id = [0xBB; 32];
    let outer = scp_core::envelope::outer::create_outer_envelope(
        &routing_id,
        None,
        3600,
        vec![0x10, 0x20, 0x30],
    )
    .unwrap();

    // Subscribe first, then send.
    let routing = RoutingId::new(routing_id);
    let mut stream = recv_adapter.subscribe(&routing, None).await.unwrap();

    let blob_id = send_adapter.send(&outer).await.unwrap();
    assert_eq!(blob_id.as_bytes().len(), 32, "blob_id must be 32 bytes");

    // Receive the envelope — proves end-to-end delivery over ws://.
    let got = receive_envelope(&mut stream).await;
    assert_eq!(got.routing_id, outer.routing_id);
    assert_eq!(got.encrypted_blob, outer.encrypted_blob);

    // --- 2. ws:// to loopback is permitted from ANY source (loopback exemption) ---
    // The relay binds to 127.0.0.1, so all these sources should succeed.
    for (source, label) in [
        (RelayUrlSource::WellKnown, "WellKnown"),
        (RelayUrlSource::Explicit, "Explicit"),
        (RelayUrlSource::PeerDiscovered, "PeerDiscovered"),
    ] {
        let sourced = SourcedRelayUrl {
            url: relay_url.clone(),
            source,
        };
        NativeRelayAdapter::connect_sourced(&sourced)
            .await
            .unwrap_or_else(|e| {
                panic!("ws:// to loopback from {label} should be permitted (loopback exemption), got: {e}")
            });
    }

    // --- 3. ws:// to non-loopback from non-DHT sources is still rejected ---
    // We can't connect to a fake host, but `validate_relay_url` is the gate
    // wired into `connect_sourced`, so exercising it directly proves the rule.
    let non_loopback = "ws://203.0.113.1:9999/scp/v1";
    for (source, label) in [
        (RelayUrlSource::WellKnown, "WellKnown"),
        (RelayUrlSource::Explicit, "Explicit"),
        (RelayUrlSource::PeerDiscovered, "PeerDiscovered"),
    ] {
        let result = scp_transport::relay::connection::validate_relay_url(non_loopback, &source);
        assert!(
            result.is_err(),
            "ws:// to non-loopback from {label} must be rejected"
        );
    }
    // DHT-resolved to non-loopback is still allowed.
    scp_transport::relay::connection::validate_relay_url(
        non_loopback,
        &RelayUrlSource::DhtResolved,
    )
    .expect("ws:// to non-loopback from DhtResolved should be permitted");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Checks if `haystack` contains `needle` as a contiguous subsequence.
fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
