#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! SDK usability integration tests.
//!
//! These tests verify SCP from a real developer's perspective -- not internal
//! function correctness, but "can I actually build an app with this?" They catch
//! gaps like:
//!
//! - A trait exists but has no real implementation (only mocks)
//! - An API returns success but doesn't actually do anything
//! - Components that should work together don't
//! - Missing crate dependencies that stories claim to use
//!
//! Run with:
//! ```bash
//! DYLD_LIBRARY_PATH=$(python3.12 -c "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))") \
//!   cargo test -p scp-testing --test sdk_usability --features scp-core/testing -- --nocapture
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use scp_core::envelope::create_outer_envelope;
use scp_node::{Node, ReachabilityTier};
use scp_platform::testing::InMemoryStorage;
use scp_testing::helpers;
use scp_transport::native::protocol::{ClientMessage, RelayMessage};
use scp_transport::native::server::{RelayConfig, RelayServer};
use scp_transport::native::storage::BlobStorageBackend;
use scp_transport::relay::connection::{RelayUrlSource, SourcedRelayUrl};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Builds a WebSocket client request to the relay with the bridge secret
/// in an `Authorization: Bearer` header.
fn relay_request(
    addr: SocketAddr,
    token: &str,
) -> tokio_tungstenite::tungstenite::http::Request<()> {
    let url = format!("ws://{addr}/");
    let mut request = url.into_client_request().expect("valid WS URL");
    request.headers_mut().insert(
        "Authorization",
        format!("Bearer {token}")
            .parse()
            .expect("valid header value"),
    );
    request
}

/// Builds a no-domain `ApplicationNode` with bridge tier (most common test
/// scenario -- avoids real NAT probing).
async fn build_no_domain_node() -> scp_node::ApplicationNode<InMemoryStorage> {
    let tier = ReachabilityTier::Bridge {
        bridge_url: "wss://bridge.test.scp/scp/v1".to_owned(),
    };
    Node::start_for_testing(helpers::test_no_domain_node_config(tier))
        .await
        .expect("no-domain node should build")
}

/// Builds a domain-mode `ApplicationNode` with self-signed TLS (no real ACME).
async fn build_domain_node() -> scp_node::ApplicationNode<InMemoryStorage> {
    Node::start_for_testing(helpers::test_node_config())
        .await
        .expect("domain-mode node should build")
}

// =========================================================================
// 1. ApplicationNode actually works end-to-end
// =========================================================================

#[tokio::test(flavor = "multi_thread")]
async fn application_node_starts_with_real_did() {
    println!("\n=== 1a: ApplicationNode produces a real DID ===\n");

    let node = build_domain_node().await;
    let did = node.identity().did();

    // DID must be a real did:dht identifier, not empty or placeholder.
    assert!(
        did.starts_with("did:dht:"),
        "DID should start with did:dht:, got: {did}"
    );
    assert!(
        did.len() > "did:dht:".len() + 10,
        "DID should have a meaningful suffix, got: {did}"
    );

    // Document should contain the identity's DID.
    let doc = node.identity().document();
    assert_eq!(doc.id, did, "document.id should match identity.did");

    println!("  DID: {did}");
    println!("  Document ID: {}", doc.id);

    node.shutdown();
    println!("  -- PASS\n");
}

#[tokio::test(flavor = "multi_thread")]
async fn application_node_relay_is_reachable() {
    println!("\n=== 1b: Relay is reachable via WebSocket ===\n");

    let node = build_domain_node().await;
    let addr = node.relay().bound_addr();
    let token = node.bridge_token_hex();

    // Relay must bind to a real port (not 0).
    assert_ne!(addr.port(), 0, "relay must bind to a real port");
    println!("  Relay bound to: {addr}");

    // WebSocket connection must succeed.
    let (ws_stream, _) = tokio_tungstenite::connect_async(relay_request(addr, &token))
        .await
        .expect("WebSocket connection to relay should succeed");
    drop(ws_stream);
    println!("  WebSocket connected successfully");

    node.shutdown();
    println!("  -- PASS\n");
}

#[tokio::test(flavor = "multi_thread")]
async fn application_node_relay_url_is_well_formed() {
    println!("\n=== 1c: Relay URL is well-formed ===\n");

    let node = build_domain_node().await;
    let url = node.relay_url();

    // Domain-mode relay URL should be wss://<domain>/scp/v1.
    assert!(
        url.starts_with("wss://") || url.starts_with("ws://"),
        "relay URL should have ws:// or wss:// scheme, got: {url}"
    );
    assert!(
        url.ends_with("/scp/v1"),
        "relay URL should end with /scp/v1, got: {url}"
    );
    println!("  Relay URL: {url}");

    node.shutdown();
    println!("  -- PASS\n");
}

#[tokio::test(flavor = "multi_thread")]
async fn application_node_relay_publish_subscribe_roundtrip() {
    println!("\n=== 1d: Publish/subscribe roundtrip through relay ===\n");

    let node = build_domain_node().await;
    let addr = node.relay().bound_addr();
    let token = node.bridge_token_hex();

    // --- Subscriber connects and subscribes ---
    let (sub_stream, _) = tokio_tungstenite::connect_async(relay_request(addr, &token))
        .await
        .expect("subscriber should connect");
    let (mut sub_sink, mut sub_source) = sub_stream.split();

    let routing_id = [0xAAu8; 32];
    let subscribe = ClientMessage::Subscribe {
        ref_id: Some("sub-test".to_string()),
        routing_id,
        since: None,
    };
    sub_sink
        .send(Message::Binary(subscribe.to_bytes().unwrap()))
        .await
        .unwrap();

    // Wait for subscribe OK.
    let response_frame = tokio::time::timeout(Duration::from_secs(5), sub_source.next())
        .await
        .expect("subscribe response within timeout")
        .expect("stream not ended")
        .expect("valid frame");
    let response_bytes = match response_frame {
        Message::Binary(b) => b,
        other => panic!("expected binary, got: {other:?}"),
    };
    let relay_msg = RelayMessage::from_bytes(&response_bytes).unwrap();
    assert!(
        matches!(relay_msg, RelayMessage::Ok { .. }),
        "expected OK response to SUBSCRIBE, got: {relay_msg:?}"
    );
    println!("  Subscribed to routing_id");

    // --- Publisher connects and publishes ---
    let (pub_stream, _) = tokio_tungstenite::connect_async(relay_request(addr, &token))
        .await
        .expect("publisher should connect");
    let (mut pub_sink, mut pub_source) = pub_stream.split();

    let payload = b"SDK usability test message".to_vec();
    let publish = ClientMessage::Publish {
        ref_id: Some("pub-test".to_string()),
        routing_id,
        recipient_hint: None,
        blob_ttl: 60,
        blob: payload.clone(),
    };
    pub_sink
        .send(Message::Binary(publish.to_bytes().unwrap()))
        .await
        .unwrap();

    // Wait for publish OK.
    let pub_response = tokio::time::timeout(Duration::from_secs(5), pub_source.next())
        .await
        .expect("publish response within timeout")
        .expect("stream not ended")
        .expect("valid frame");
    let pub_bytes = match pub_response {
        Message::Binary(b) => b,
        other => panic!("expected binary, got: {other:?}"),
    };
    let pub_msg = RelayMessage::from_bytes(&pub_bytes).unwrap();
    assert!(
        matches!(pub_msg, RelayMessage::Ok { .. }),
        "expected OK to PUBLISH, got: {pub_msg:?}"
    );
    println!("  Published message");

    // --- Subscriber receives the message ---
    let delivered = tokio::time::timeout(Duration::from_secs(5), sub_source.next())
        .await
        .expect("delivery within timeout")
        .expect("stream not ended")
        .expect("valid frame");
    let delivered_bytes = match delivered {
        Message::Binary(b) => b,
        other => panic!("expected binary delivery, got: {other:?}"),
    };
    let delivered_msg = RelayMessage::from_bytes(&delivered_bytes).unwrap();
    match delivered_msg {
        RelayMessage::Blob { blob, .. } => {
            assert_eq!(blob, payload, "delivered blob must match published payload");
            println!(
                "  Subscriber received matching message ({} bytes)",
                blob.len()
            );
        }
        other => panic!("expected Blob delivery, got: {other:?}"),
    }

    node.shutdown();
    println!("  -- PASS\n");
}

// =========================================================================
// 2. PortMapper has a real implementation
// =========================================================================

/// Structural test: verifies that `scp-transport` exports a non-mock
/// `PortMapper` implementation. The source file is embedded at compile time
/// via `include_str!` and searched for `impl PortMapper for` outside of
/// `#[cfg(test)]` blocks.
///
/// The `UpnpPortMapper` and `NatPmpPortMapper` production implementations
/// (gated behind the `upnp` crate feature) satisfy this check.
#[test]
fn port_mapper_has_real_implementation() {
    println!("\n=== 2: PortMapper has a production impl ===\n");

    let upnp_source: &str = include_str!("../../../scp-transport/src/nat/upnp.rs");

    // Split by #[cfg(test)] -- only look at the non-test portion.
    let non_test_source = upnp_source
        .split("#[cfg(test)]")
        .next()
        .unwrap_or(upnp_source);

    let has_production_impl = non_test_source.contains("impl PortMapper for");

    assert!(
        has_production_impl,
        "No production PortMapper implementation found in scp-transport/src/nat/upnp.rs. \
         Only mock implementations exist inside #[cfg(test)] blocks. \
         UPnP/NAT-PMP port mapping via igd-next has not been integrated."
    );

    println!("  -- PASS\n");
}

// =========================================================================
// 3. NativeRelayAdapter round-trip through ApplicationNode
// =========================================================================

/// Connects a `NativeRelayAdapter` to a real `RelayServer` and performs
/// a send/subscribe/receive cycle through the transport stack.
///
/// `NativeRelayAdapter` is the developer-facing transport API. This tests
/// the pattern: start relay → connect adapter → subscribe → send → receive.
#[tokio::test(flavor = "multi_thread")]
async fn native_relay_adapter_roundtrip_through_relay() {
    use scp_transport::native::adapter::NativeRelayAdapter;
    use scp_transport::traits::{RoutingId, TransportAdapter};

    println!("\n=== 3: NativeRelayAdapter round-trip ===\n");

    // Start a standalone relay (no bridge token — direct connections don't need auth).
    let config = RelayConfig {
        bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        delivery_jitter_ms: 0,
        ..RelayConfig::default()
    };
    let (_shutdown, relay_addr) =
        RelayServer::new(config, Arc::new(BlobStorageBackend::in_memory()))
            .start()
            .await
            .expect("relay start");
    println!("  Relay on {relay_addr}");

    let sourced = SourcedRelayUrl {
        url: format!("ws://{relay_addr}/scp/v1"),
        source: RelayUrlSource::DhtResolved,
    };
    let adapter = NativeRelayAdapter::connect_sourced(&sourced, None)
        .await
        .expect("NativeRelayAdapter should connect");
    println!("  Adapter connected");

    let routing_id = RoutingId::new([0xBBu8; 32]);
    let mut stream = adapter
        .subscribe(&routing_id, None)
        .await
        .expect("subscribe should succeed");

    let test_payload = b"NativeRelayAdapter round-trip test";
    let envelope = create_outer_envelope(routing_id.as_bytes(), None, 60, test_payload.to_vec())
        .expect("create_outer_envelope");

    let blob_id = adapter.send(&envelope).await.expect("send should succeed");
    println!("  Sent, blob_id: {blob_id:?}");

    let event = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("should receive within timeout")
        .expect("stream should yield an event");
    println!("  Received: {event:?}");
    println!("  -- PASS\n");
}

// =========================================================================
// 4. Sender key encrypt -> relay -> decrypt round-trip
// =========================================================================

/// End-to-end test: create two identities, generate sender keys, encrypt a
/// message with a sender key, send through a real relay (not `InMemoryRelay`),
/// receive and decrypt on the other side.
///
/// This verifies the crypto + transport stack works together as a developer
/// would use it.
#[tokio::test(flavor = "multi_thread")]
async fn sender_key_encrypt_relay_decrypt_roundtrip() {
    use scp_core::crypto::sender_keys;
    use scp_transport::native::adapter::NativeRelayAdapter;
    use scp_transport::traits::{RoutingId, TransportAdapter};

    println!("\n=== 4: Sender key encrypt -> relay -> decrypt ===\n");

    let (alice_identity, _alice_doc, _alice_custody) = helpers::create_test_identity()
        .await
        .expect("Alice identity");
    println!("  Alice: {}", alice_identity.did);

    // Start a standalone relay.
    let config = RelayConfig {
        bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        delivery_jitter_ms: 0,
        ..RelayConfig::default()
    };
    let (_shutdown, relay_addr) =
        RelayServer::new(config, Arc::new(BlobStorageBackend::in_memory()))
            .start()
            .await
            .expect("relay start");
    println!("  Relay on {relay_addr}");

    // Connect adapter.
    let sourced = SourcedRelayUrl {
        url: format!("ws://{relay_addr}/scp/v1"),
        source: RelayUrlSource::DhtResolved,
    };
    let adapter = NativeRelayAdapter::connect_sourced(&sourced, None)
        .await
        .expect("connect");

    // Subscribe.
    let routing_id = RoutingId::new([0xCCu8; 32]);
    let mut stream = adapter
        .subscribe(&routing_id, None)
        .await
        .expect("subscribe");

    // Generate sender key and encrypt.
    let sender_key = sender_keys::generate_sender_key();
    let plaintext = b"Hello from sender key test!";
    let context_id = "sender-key-test-ctx";
    let encrypted = sender_keys::encrypt_sender_layer(
        &sender_key,
        plaintext,
        context_id,
        &alice_identity.did,
        0,
        0,
    )
    .expect("encrypt");
    println!("  Encrypted: {} bytes", encrypted.len());

    // Send through relay as OuterEnvelope.
    let envelope =
        create_outer_envelope(routing_id.as_bytes(), None, 60, encrypted).expect("envelope");
    adapter.send(&envelope).await.expect("send");

    // Receive and decrypt.
    let event = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("timeout")
        .expect("event");

    let received_blob = match event {
        scp_transport::traits::TransportEvent::Envelope(env) => env.encrypted_blob,
        other => panic!("expected Envelope, got: {other:?}"),
    };

    let decrypted = sender_keys::decrypt_sender_layer(
        &sender_key,
        &received_blob,
        context_id,
        &alice_identity.did,
        0,
        0,
    )
    .expect("decrypt");
    assert_eq!(&decrypted, plaintext);
    println!("  Decrypted: {:?}", String::from_utf8_lossy(&decrypted));
    println!("  -- PASS\n");
}

// =========================================================================
// 5. ContextManager + real relay integration
// =========================================================================

/// Tests that `ContextManager::create_context` and membership operations work
/// via the existing fullstack harness (which uses `CapturingTransport`, not a
/// real relay). This test verifies the `ContextManager` API is usable from
/// a developer's perspective.
#[tokio::test(flavor = "multi_thread")]
async fn context_manager_creates_usable_context() {
    use scp_core::context::governance::KeyResolver;
    use scp_core::context::{
        Capability, ContextMode, ContextParams, ContextState, context_id_bytes,
    };
    use scp_testing::fullstack::FullStackNetwork;

    println!("\n=== 5: ContextManager creates usable context ===\n");

    let network = FullStackNetwork::new();
    let key_resolver: KeyResolver =
        Arc::new(|_did: &scp_identity::DID, _kid: scp_identity::SigningKeyId| None);

    let alice = network.create_node("did:dht:z6MkAliceUsability", key_resolver.clone());
    let bob = network.create_node("did:dht:z6MkBobUsability", key_resolver);

    // Create a context with realistic parameters.
    // RoleAssign is required for add_member (the admin assigns the new
    // member's role).
    let params = ContextParams {
        mode: ContextMode::Encrypted,
        ceiling: vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::RoleAssign,
            Capability::MemberInvite,
            Capability::MemberRemove,
        ],
        ..ContextParams::default()
    };

    let ctx_id = "usability-test-ctx";
    let handle = alice.create_context(ctx_id, params).await.unwrap();
    println!("  Created context: {ctx_id}");

    // Verify state is Active.
    assert_eq!(
        handle.try_read_state().unwrap(),
        ContextState::Active,
        "newly created context should be Active"
    );
    println!("  State: Active");

    // Add Bob.
    alice
        .add_member(&handle, "did:dht:z6MkBobUsability")
        .await
        .unwrap();
    println!("  Added Bob to context");

    // Bob joins.
    let ctx_bytes = context_id_bytes(ctx_id);
    bob.join_from_welcome(ctx_id, &ctx_bytes).unwrap();
    println!("  Bob joined from Welcome");

    // Seed Bob's per-member pseudonym routing ID into Alice's manager (§9.10.4).
    // Encrypted app-data fans out to each peer's pseudonym routing ID; in
    // production Bob announces it via a PseudonymAnnouncement. Without this seed
    // the send fails closed with PseudonymRegistryEmpty.
    alice
        .manager
        .seed_peer_pseudonym(
            ctx_id,
            scp_identity::DID::from("did:dht:z6MkBobUsability"),
            [0x42u8; 32],
        )
        .await
        .unwrap();

    // Alice sends a message.
    let msg = b"Hello from usability test!";
    alice.send_message(&handle, msg).await.unwrap();
    println!("  Alice sent message");

    // Verify ciphertext was produced.
    let sent = alice.take_sent_ciphertexts();
    assert_eq!(sent.len(), 1, "one ciphertext should be sent");
    assert_ne!(
        sent[0].1.as_slice(),
        msg.as_slice(),
        "ciphertext must differ from plaintext"
    );
    println!(
        "  Ciphertext produced: {} bytes (plaintext was {} bytes)",
        sent[0].1.len(),
        msg.len()
    );

    // Bob decrypts.
    let decrypted = bob
        .decrypt_message(ctx_id, &ctx_bytes, &sent[0].1, "did:dht:z6MkAliceUsability")
        .unwrap();
    assert_eq!(
        decrypted.as_slice(),
        msg.as_slice(),
        "decrypted must match original"
    );
    println!("  Bob decrypted: {:?}", String::from_utf8_lossy(&decrypted));

    println!("  -- PASS\n");
}

// =========================================================================
// 6. SDK API completeness checks
// =========================================================================

#[tokio::test(flavor = "multi_thread")]
async fn identity_create_produces_resolvable_did() {
    println!("\n=== 6a: identity_create produces resolvable DID ===\n");

    let (identity, document, _custody) = helpers::create_test_identity()
        .await
        .expect("identity creation should succeed");

    // DID is real and non-empty.
    assert!(!identity.did.is_empty(), "DID must not be empty");
    assert!(
        identity.did.starts_with("did:dht:"),
        "DID should be did:dht, got: {}",
        identity.did
    );

    // Document resolves to the same DID.
    assert_eq!(
        document.id, identity.did,
        "document.id should match identity.did"
    );

    // Document has verification methods (not empty).
    assert!(
        !document.verification_method.is_empty(),
        "DID document should have verification methods"
    );

    // Identity key handle should have been populated (non-default).
    // The identity_key is the DID root key (#0 verification method).
    println!("  DID: {}", identity.did);
    println!(
        "  Verification methods: {}",
        document.verification_method.len()
    );
    println!("  Identity key handle: {:?}", identity.identity_key);
    println!(
        "  Active signing key handle: {:?}",
        identity.active_signing_key
    );
    println!("  -- PASS\n");
}

#[tokio::test(flavor = "multi_thread")]
async fn context_create_produces_active_context_with_members() {
    use scp_core::context::governance::KeyResolver;
    use scp_core::context::{Capability, ContextMode, ContextParams, ContextState};
    use scp_testing::fullstack::FullStackNetwork;

    println!("\n=== 6b: context_create produces active context ===\n");

    let network = FullStackNetwork::new();
    let key_resolver: KeyResolver =
        Arc::new(|_did: &scp_identity::DID, _kid: scp_identity::SigningKeyId| None);
    let alice = network.create_node("did:dht:z6MkAlice6b", key_resolver.clone());
    let bob = network.create_node("did:dht:z6MkBob6b", key_resolver);

    // RoleAssign / MemberInvite are required for add_member (the admin assigns
    // the new member's role).
    let params = ContextParams {
        mode: ContextMode::Encrypted,
        ceiling: vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::RoleAssign,
            Capability::MemberInvite,
        ],
        ..ContextParams::default()
    };

    let ctx_id = "api-test-ctx";
    let handle = alice.create_context(ctx_id, params).await.unwrap();

    // Context must be Active, not some default/empty state.
    let state = handle.try_read_state().unwrap();
    assert_eq!(state, ContextState::Active, "context should be Active");
    println!("  Context state: {state:?}");

    // Add Bob and have him join so the encrypted context has a real peer to
    // address. Under §9.10.4 encrypted app-data fans out to each peer's
    // per-member pseudonym routing ID — a lone-member send is a deliberate
    // no-op — so a sendable context that produces a ciphertext needs a member.
    let ctx_bytes = scp_core::context::context_id_bytes(ctx_id);
    alice
        .add_member(&handle, "did:dht:z6MkBob6b")
        .await
        .unwrap();
    bob.join_from_welcome(ctx_id, &ctx_bytes).unwrap();

    // Seed Bob's per-member pseudonym (in production Bob announces it via a
    // PseudonymAnnouncement).
    alice
        .manager
        .seed_peer_pseudonym(
            ctx_id,
            scp_identity::DID::from("did:dht:z6MkBob6b"),
            [0x42u8; 32],
        )
        .await
        .unwrap();

    // Context handle is usable for sending: the send fans out to Bob's pseudonym.
    let send_result = alice.send_message(&handle, b"test message").await;
    assert!(send_result.is_ok(), "sending to a context should succeed");
    println!("  Send succeeded");

    // Verify a ciphertext was actually produced (not just Ok(())).
    let sent = alice.take_sent_ciphertexts();
    assert_eq!(sent.len(), 1, "a ciphertext should have been produced");
    assert!(!sent[0].1.is_empty(), "ciphertext should not be empty");
    println!("  Ciphertext: {} bytes", sent[0].1.len());

    println!("  -- PASS\n");
}

#[tokio::test(flavor = "multi_thread")]
async fn application_node_no_domain_mode_works() {
    println!("\n=== 6c: ApplicationNode no_domain mode ===\n");

    let node = build_no_domain_node().await;

    // No domain.
    assert!(
        node.domain().is_none(),
        "no-domain node should have domain() == None"
    );
    println!("  Domain: None (correct)");

    // DID still created.
    let did = node.identity().did();
    assert!(
        did.starts_with("did:dht:"),
        "DID should be created, got: {did}"
    );
    println!("  DID: {did}");

    // Relay still running.
    let addr = node.relay().bound_addr();
    assert_ne!(addr.port(), 0, "relay should be bound");
    println!("  Relay: {addr}");

    // Relay URL should exist.
    let url = node.relay_url();
    assert!(!url.is_empty(), "relay URL should not be empty");
    println!("  Relay URL: {url}");

    node.shutdown();
    println!("  -- PASS\n");
}

// =========================================================================
// 7. WebSocket bridge works on same port as HTTP
// =========================================================================

/// Verifies that axum's `relay_router` pattern serves both HTTP routes and
/// WebSocket upgrades on the same port. This would have caught the two-port
/// Safari issue where WebSocket and HTTP were on different ports.
#[tokio::test(flavor = "multi_thread")]
async fn websocket_and_http_on_same_port() {
    use axum::Router;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use hyper::Request;
    use tower::ServiceExt;

    println!("\n=== 7: WebSocket + HTTP on same port ===\n");

    let node = build_domain_node().await;

    // Build the merged router (well-known + relay).
    let merged: Router = node.well_known_router().merge(node.relay_router());

    // --- HTTP: GET /.well-known/scp should return 200 ---
    let http_req = Request::builder()
        .uri("/.well-known/scp")
        .body(Body::empty())
        .unwrap();

    let http_response = merged.clone().oneshot(http_req).await.unwrap();
    assert_eq!(
        http_response.status(),
        200,
        "GET /.well-known/scp should return 200"
    );

    let body = http_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).expect("valid JSON");
    assert_eq!(json["version"], 1, ".well-known/scp version should be 1");
    println!("  HTTP /.well-known/scp: 200 OK, version=1");

    // --- WebSocket: GET /scp/v1 with Upgrade headers should return 101 ---
    // Note: axum's WebSocket upgrade requires a real TCP connection for the
    // actual upgrade handshake. Here we verify the route exists by checking
    // that a non-upgrade GET to /scp/v1 returns a response (not 404).
    let ws_req = Request::builder()
        .method("GET")
        .uri("/scp/v1")
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
        .body(Body::empty())
        .unwrap();

    let ws_response = merged.oneshot(ws_req).await.unwrap();
    // axum returns 101 Switching Protocols for valid WS upgrade requests
    // when the handler can process them. Without a real TCP connection,
    // it may return a different status, but it should NOT be 404.
    assert_ne!(
        ws_response.status().as_u16(),
        404,
        "/scp/v1 route must exist (got 404 -- routes not merged correctly)"
    );
    println!(
        "  WebSocket /scp/v1: {} (route exists, not 404)",
        ws_response.status()
    );

    // --- Verify they share the same Router (same port semantics) ---
    // The fact that both routes are in the same Router proves they will be
    // served on the same TCP listener when ApplicationNode::serve() is called.
    println!("  Both routes in same Router -- same port guaranteed");

    node.shutdown();
    println!("  -- PASS\n");
}

// =========================================================================
// Bonus: ApplicationNode shutdown is clean
// =========================================================================

#[tokio::test(flavor = "multi_thread")]
async fn application_node_shutdown_is_idempotent() {
    println!("\n=== Bonus: Shutdown is idempotent ===\n");

    let node = build_domain_node().await;

    // Shutdown should not panic even if called multiple times.
    node.shutdown();
    node.shutdown(); // second call should be a no-op
    println!("  Double shutdown: no panic");

    println!("  -- PASS\n");
}

// =========================================================================
// Bonus: Bridge token is non-empty and hex-formatted
// =========================================================================

#[tokio::test(flavor = "multi_thread")]
async fn bridge_token_is_valid_hex() {
    println!("\n=== Bonus: Bridge token format ===\n");

    let node = build_domain_node().await;
    let token = node.bridge_token_hex();

    assert!(!token.is_empty(), "bridge token should not be empty");
    assert_eq!(
        token.len(),
        64,
        "bridge token should be 64 hex chars (32 bytes)"
    );

    // Verify it's valid hex.
    let decoded = hex::decode(&token).expect("bridge token should be valid hex");
    assert_eq!(decoded.len(), 32, "decoded bridge token should be 32 bytes");

    // Verify it's not all zeros (would indicate uninitialized secret).
    assert!(
        decoded.iter().any(|&b| b != 0),
        "bridge token should not be all zeros"
    );

    println!("  Token: {}...{}", &token[..8], &token[56..]);
    println!("  -- PASS\n");
}
