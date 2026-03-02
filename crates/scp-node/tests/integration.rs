//! End-to-end integration tests for the addressability and deployment layer.
//!
//! Tests the four scenarios specified in section 18.7, 18.8, and ADR-032:
//!
//! 1. `ApplicationNode` starts -> DID published -> .well-known/scp reachable -> relay accepts connections
//! 2. Client discovers relay via .well-known/scp -> connects -> subscribes
//! 3. Client discovers operator DID -> finds `SCPRelay` service entry -> connects
//! 4. scp:// URI roundtrip through creation and parsing

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use http_body_util::BodyExt;
use hyper::Request;
use tower::ServiceExt;

use scp_core::context::ContextMode;
use scp_core::uri::ScpUri;
use scp_core::well_known::WellKnownScp;
use scp_identity::cache::SystemClock;
use scp_identity::dht::DidDht;
use scp_identity::dht_client::InMemoryDhtClient;
use scp_identity::{DidCache, DidMethod};
use scp_node::ApplicationNodeBuilder;
use scp_platform::testing::{InMemoryKeyCustody, InMemoryStorage};
use scp_transport::native::protocol::{ClientMessage, RelayMessage};

/// Concrete `DidDht` type used in tests (in-memory DHT and system clock).
type TestDidDht = DidDht<InMemoryDhtClient, SystemClock>;

/// Creates a shared `InMemoryDhtClient` and a `DidDht` that uses it.
///
/// Returns both so the DHT client can be shared with a second resolver
/// for client-side DID resolution tests.
fn make_shared_dht(custody: &Arc<InMemoryKeyCustody>) -> (Arc<InMemoryDhtClient>, TestDidDht) {
    let dht_client = Arc::new(InMemoryDhtClient::new());
    let cache = Arc::new(DidCache::new());
    let sign_fn = TestDidDht::make_sign_fn(Arc::clone(custody));
    let did_dht = DidDht::with_client_and_signer(Arc::clone(&dht_client), cache, sign_fn);
    (dht_client, did_dht)
}

/// Helper: builds an `ApplicationNode` and returns it along with the shared
/// DHT client (for client-side resolution tests).
async fn build_test_node() -> (
    scp_node::ApplicationNode<InMemoryStorage>,
    Arc<InMemoryDhtClient>,
) {
    let custody = Arc::new(InMemoryKeyCustody::new());
    let (dht_client, did_dht) = make_shared_dht(&custody);

    let node = ApplicationNodeBuilder::new()
        .storage(Arc::new(InMemoryStorage::new()))
        .domain("test.example.com")
        .generate_identity_with(custody, Arc::new(did_dht))
        .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
        .build()
        .await
        .expect("ApplicationNode should build successfully");

    (node, dht_client)
}

// =========================================================================
// Scenario 1: ApplicationNode starts -> DID published -> .well-known/scp
//             reachable -> relay accepts connections
// =========================================================================

#[tokio::test]
async fn scenario1_node_build_publishes_did_and_serves_well_known() {
    let (node, _dht_client) = build_test_node().await;

    // --- Assert: DID is published and has SCPRelay service entries ---
    let did = node.identity().did();
    assert!(
        did.starts_with("did:dht:"),
        "DID should start with did:dht:, got: {did}"
    );

    let relay_urls = node.identity().document().relay_service_urls();
    assert_eq!(relay_urls.len(), 1);
    assert_eq!(relay_urls[0], "wss://test.example.com/scp/v1");

    // --- Assert: GET /.well-known/scp returns valid JSON ---
    let router = node.well_known_router();
    let req = Request::builder()
        .uri("/.well-known/scp")
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), 200);

    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let well_known: WellKnownScp =
        serde_json::from_slice(&body_bytes).expect("response should be valid JSON");

    assert_eq!(well_known.version, 1);
    assert_eq!(well_known.did, did);
    assert_eq!(well_known.relay, "wss://test.example.com/scp/v1");

    // --- Assert: relay accepts WebSocket connections with bridge token ---
    let addr = node.relay().bound_addr();
    let token = node.bridge_token_hex();
    let url = format!("ws://{addr}/?token={token}");
    let (ws_stream, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("relay should accept WebSocket connections with valid token");
    drop(ws_stream);
}

// =========================================================================
// Scenario 2: Client discovers relay via .well-known/scp -> connects ->
//             subscribes to routing_id -> receives published message
// =========================================================================

#[tokio::test]
async fn scenario2_client_discovers_relay_via_well_known_and_subscribes() {
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let (node, _dht_client) = build_test_node().await;

    // --- Step 1: Client fetches .well-known/scp ---
    let router = node.well_known_router();
    let req = Request::builder()
        .uri("/.well-known/scp")
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let well_known: WellKnownScp = serde_json::from_slice(&body_bytes).unwrap();

    // Verify the well-known document has the expected relay URL.
    assert_eq!(well_known.relay, "wss://test.example.com/scp/v1");

    // --- Step 2: Client connects to the relay ---
    // In a real scenario, the client would connect to the wss:// relay URL
    // from .well-known/scp. In tests, we connect to the local bound address
    // with the bridge token.
    let relay_addr = node.relay().bound_addr();
    let token = node.bridge_token_hex();
    let url = format!("ws://{relay_addr}/?token={token}");
    let (ws_stream, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("should connect to relay");
    let (mut ws_sink, mut ws_source) = ws_stream.split();

    // --- Step 3: Client sends SUBSCRIBE for a routing_id ---
    let routing_id = [0xABu8; 32];
    let subscribe_msg = ClientMessage::Subscribe {
        ref_id: Some("sub-1".to_string()),
        routing_id,
        since: None,
    };
    let subscribe_bytes = subscribe_msg.to_bytes().unwrap();
    ws_sink
        .send(Message::Binary(subscribe_bytes))
        .await
        .unwrap();

    // --- Step 4: Relay responds with OK ---
    let response_frame = tokio::time::timeout(std::time::Duration::from_secs(5), ws_source.next())
        .await
        .expect("should receive response within timeout")
        .expect("stream should not end")
        .expect("frame should be valid");

    let response_bytes = match response_frame {
        Message::Binary(b) => b,
        other => panic!("expected binary frame, got: {other:?}"),
    };
    let relay_response = RelayMessage::from_bytes(&response_bytes).unwrap();

    match relay_response {
        RelayMessage::Ok { ref_id, .. } => {
            assert_eq!(ref_id.as_deref(), Some("sub-1"));
        }
        other => panic!("expected OK response to SUBSCRIBE, got: {other:?}"),
    }

    // --- Step 5: Publish a message to the same routing_id ---
    // Use a second WebSocket connection to publish (reuses the same token URL).
    let (pub_stream, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("publisher should connect with valid token");
    let (mut pub_sink, mut pub_source) = pub_stream.split();

    let blob_content = b"hello from SCP integration test".to_vec();
    let publish_msg = ClientMessage::Publish {
        ref_id: Some("pub-1".to_string()),
        routing_id,
        recipient_hint: None,
        blob_ttl: 60,
        blob: blob_content.clone(),
    };
    let publish_bytes = publish_msg.to_bytes().unwrap();
    pub_sink.send(Message::Binary(publish_bytes)).await.unwrap();

    // Wait for PUBLISH OK on the publisher connection.
    let pub_response_frame =
        tokio::time::timeout(std::time::Duration::from_secs(5), pub_source.next())
            .await
            .expect("publisher should get OK response")
            .expect("stream should not end")
            .expect("frame should be valid");

    let pub_response_bytes = match pub_response_frame {
        Message::Binary(b) => b,
        other => panic!("expected binary frame, got: {other:?}"),
    };
    let pub_response = RelayMessage::from_bytes(&pub_response_bytes).unwrap();
    assert!(
        matches!(pub_response, RelayMessage::Ok { ref ref_id, .. } if ref_id.as_deref() == Some("pub-1")),
        "publisher should receive OK, got: {pub_response:?}"
    );

    // --- Step 6: Subscriber receives the BLOB ---
    let blob_frame = tokio::time::timeout(std::time::Duration::from_secs(5), ws_source.next())
        .await
        .expect("subscriber should receive blob within timeout")
        .expect("stream should not end")
        .expect("frame should be valid");

    let blob_bytes = match blob_frame {
        Message::Binary(b) => b,
        other => panic!("expected binary frame for BLOB, got: {other:?}"),
    };
    let blob_msg = RelayMessage::from_bytes(&blob_bytes).unwrap();

    match blob_msg {
        RelayMessage::Blob {
            routing_id: rid,
            blob,
            ..
        } => {
            assert_eq!(rid, routing_id);
            assert_eq!(blob, blob_content);
        }
        other => panic!("expected BLOB delivery, got: {other:?}"),
    }
}

// =========================================================================
// Scenario 3: Client resolves operator DID via DHT -> extracts SCPRelay
//             service entries -> connects to relay URL
// =========================================================================

#[tokio::test]
async fn scenario3_client_discovers_relay_via_did_resolution() {
    let (node, dht_client) = build_test_node().await;
    let operator_did = node.identity().did().to_string();

    // --- Step 1: Client resolves the operator DID via the shared DHT ---
    // The client uses a resolve-only DidDht (no signing) with the same
    // in-memory DHT backend, simulating DHT network access.
    let client_resolver: DidDht<InMemoryDhtClient, SystemClock> = DidDht::with_client(dht_client);

    let resolved_doc = client_resolver
        .resolve(&operator_did)
        .await
        .expect("DID resolution should succeed");

    // --- Step 2: Extract SCPRelay service entries ---
    let relay_urls = resolved_doc.relay_service_urls();
    assert!(
        !relay_urls.is_empty(),
        "resolved DID document should contain SCPRelay service entries"
    );
    assert_eq!(relay_urls[0], "wss://test.example.com/scp/v1");

    // --- Step 3: Connect to the relay ---
    // In production the client would connect to the wss:// URL from the DID
    // document. In tests we use the local relay address with the bridge token.
    let relay_addr = node.relay().bound_addr();
    let token = node.bridge_token_hex();
    let url = format!("ws://{relay_addr}/?token={token}");
    let (ws_stream, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("should connect to relay discovered via DID resolution");
    drop(ws_stream);
}

// =========================================================================
// Scenario 4: scp:// URI roundtrip through creation and parsing
// =========================================================================

#[tokio::test]
async fn scenario4_scp_uri_roundtrip() {
    // --- Encrypted context URI with single relay ---
    let uri = ScpUri::Context {
        context_id: "a1b2c3d4e5f6".to_owned(),
        relays: vec!["wss://relay.example.com/scp/v1".to_owned()],
        mode: Some(ContextMode::Encrypted),
        name: None,
        handle: None,
    };

    let serialized = uri.to_string();
    let parsed: ScpUri = serialized
        .parse()
        .expect("serialized URI should parse back");
    assert_eq!(uri, parsed);

    // --- Broadcast context URI with multiple relays and name ---
    let uri_broadcast = ScpUri::Context {
        context_id: "deadbeef0123".to_owned(),
        relays: vec![
            "wss://relay1.example.com/scp/v1".to_owned(),
            "wss://relay2.example.com/scp/v1".to_owned(),
        ],
        mode: Some(ContextMode::Broadcast),
        name: Some("Tech News".to_owned()),
        handle: None,
    };

    let serialized = uri_broadcast.to_string();
    let parsed: ScpUri = serialized.parse().expect("broadcast URI should parse back");
    assert_eq!(uri_broadcast, parsed);
    assert_eq!(parsed.context_id(), "deadbeef0123");
    assert_eq!(parsed.relays().len(), 2);
    assert_eq!(parsed.mode(), Some(ContextMode::Broadcast));
    assert_eq!(parsed.name(), Some("Tech News"));

    // --- Context URI with no optional params ---
    let uri_minimal = ScpUri::Context {
        context_id: "abcdef012345".to_owned(),
        relays: vec!["wss://relay.example.com/scp/v1".to_owned()],
        mode: None,
        name: None,
        handle: None,
    };

    let serialized = uri_minimal.to_string();
    let parsed: ScpUri = serialized.parse().expect("minimal URI should parse back");
    assert_eq!(uri_minimal, parsed);

    // --- Legacy broadcast alias normalizes to universal format ---
    let legacy_input = "scp://broadcast/a1b2c3d4?relay=wss%3A%2F%2Frelay.example.com%2Fscp%2Fv1";
    let parsed_legacy: ScpUri = legacy_input
        .parse()
        .expect("legacy broadcast alias should parse");
    assert_eq!(parsed_legacy.context_id(), "a1b2c3d4");
    assert_eq!(parsed_legacy.mode(), Some(ContextMode::Broadcast));
    // Serialization always uses universal format.
    let reserialized = parsed_legacy.to_string();
    assert!(
        reserialized.starts_with("scp://context/"),
        "should normalize to universal format"
    );
    assert!(reserialized.contains("mode=broadcast"));
    // Roundtrip from reserialized form.
    let reparsed: ScpUri = reserialized
        .parse()
        .expect("re-serialized URI should parse back");
    assert_eq!(parsed_legacy, reparsed);

    // --- Name with special characters roundtrips ---
    let uri_special = ScpUri::Context {
        context_id: "aabbccdd".to_owned(),
        relays: vec!["wss://relay.example.com/scp/v1".to_owned()],
        mode: None,
        name: Some("Hello World & Friends!".to_owned()),
        handle: None,
    };
    let serialized = uri_special.to_string();
    let parsed: ScpUri = serialized
        .parse()
        .expect("URI with special chars should parse");
    assert_eq!(uri_special, parsed);
}

// =========================================================================
// Scenario 5: Bridge secret rejects unauthenticated connections (#85)
// =========================================================================

#[tokio::test]
async fn scenario5_relay_rejects_connection_without_bridge_token() {
    let (node, _dht_client) = build_test_node().await;
    let addr = node.relay().bound_addr();

    // Attempt 1: No token at all — should be rejected.
    let url_no_token = format!("ws://{addr}");
    let result = tokio_tungstenite::connect_async(&url_no_token).await;
    assert!(
        result.is_err(),
        "relay should reject connections without a bridge token"
    );

    // Attempt 2: Wrong token — should be rejected.
    let wrong_token = "00".repeat(32);
    let url_wrong_token = format!("ws://{addr}/?token={wrong_token}");
    let result = tokio_tungstenite::connect_async(&url_wrong_token).await;
    assert!(
        result.is_err(),
        "relay should reject connections with an invalid bridge token"
    );

    // Attempt 3: Malformed token (too short) — should be rejected.
    let url_short_token = format!("ws://{addr}/?token=abcd");
    let result = tokio_tungstenite::connect_async(&url_short_token).await;
    assert!(
        result.is_err(),
        "relay should reject connections with a malformed bridge token"
    );

    // Attempt 4: Correct token — should succeed.
    let token = node.bridge_token_hex();
    let url_valid = format!("ws://{addr}/?token={token}");
    let (ws_stream, _) = tokio_tungstenite::connect_async(&url_valid)
        .await
        .expect("relay should accept connections with valid bridge token");
    drop(ws_stream);
}
