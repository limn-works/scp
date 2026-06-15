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
use scp_node::{DhtMode, IdentitySource, Node, NodeConfig, Reach};
use scp_platform::testing::{InMemoryKeyCustody, InMemoryStorage};
use scp_transport::native::protocol::{ClientMessage, RelayMessage};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

/// Builds a WebSocket client request to the relay with the bridge secret
/// in an `Authorization: Bearer` header (instead of a query parameter).
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

    // Default `TlsMode::SelfSigned` reproduces the dropped local
    // `SucceedingTlsProvider` (both generate a self-signed cert for the domain).
    // `Domain` is a publishing reach → `DhtMode::Production` (M2; advisory in P1
    // — the in-memory DHT client publishes nothing).
    let node = Node::start_for_testing(NodeConfig {
        bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
        dht: DhtMode::Production,
        ..NodeConfig::defaults(
            Reach::Domain {
                domain: "test.example.com".to_owned(),
            },
            IdentitySource::Generate {
                custody,
                did_method: Arc::new(did_dht),
            },
            InMemoryStorage::new(),
        )
    })
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
    let (ws_stream, _) = tokio_tungstenite::connect_async(relay_request(addr, &token))
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
    // with the bridge token in the Authorization header.
    let relay_addr = node.relay().bound_addr();
    let token = node.bridge_token_hex();
    let (ws_stream, _) = tokio_tungstenite::connect_async(relay_request(relay_addr, &token))
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
    // Use a second WebSocket connection to publish.
    let (pub_stream, _) = tokio_tungstenite::connect_async(relay_request(relay_addr, &token))
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
    // document. In tests we use the local relay address with the bridge token
    // in the Authorization header.
    let relay_addr = node.relay().bound_addr();
    let token = node.bridge_token_hex();
    let (ws_stream, _) = tokio_tungstenite::connect_async(relay_request(relay_addr, &token))
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

    // Attempt 1: No Authorization header at all — should be rejected.
    let url_no_token = format!("ws://{addr}/");
    let result = tokio_tungstenite::connect_async(&url_no_token).await;
    assert!(
        result.is_err(),
        "relay should reject connections without a bridge token"
    );

    // Attempt 2: Wrong token in Authorization header — should be rejected.
    let wrong_token = "00".repeat(32);
    let result = tokio_tungstenite::connect_async(relay_request(addr, &wrong_token)).await;
    assert!(
        result.is_err(),
        "relay should reject connections with an invalid bridge token"
    );

    // Attempt 3: Malformed token (too short) in header — should be rejected.
    let result = tokio_tungstenite::connect_async(relay_request(addr, "abcd")).await;
    assert!(
        result.is_err(),
        "relay should reject connections with a malformed bridge token"
    );

    // Attempt 4: Correct token in Authorization header — should succeed.
    let token = node.bridge_token_hex();
    let (ws_stream, _) = tokio_tungstenite::connect_async(relay_request(addr, &token))
        .await
        .expect("relay should accept connections with valid bridge token");
    drop(ws_stream);
}

// =========================================================================
// Scenario 6: Dev API reachable on localhost while public server runs on
//             separate port (SCP-245)
// =========================================================================

/// Builds a test node with the dev API enabled on an OS-assigned port.
async fn build_test_node_with_dev_api() -> (
    scp_node::ApplicationNode<InMemoryStorage>,
    Arc<InMemoryDhtClient>,
) {
    let custody = Arc::new(InMemoryKeyCustody::new());
    let (dht_client, did_dht) = make_shared_dht(&custody);

    // Same as `build_test_node` plus the dev API on an OS-assigned port
    // (`local_api`). Default `TlsMode::SelfSigned` reproduces the dropped
    // `SucceedingTlsProvider`; `Domain` → `DhtMode::Production` (M2).
    let node = Node::start_for_testing(NodeConfig {
        bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
        local_api: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
        dht: DhtMode::Production,
        ..NodeConfig::defaults(
            Reach::Domain {
                domain: "test.example.com".to_owned(),
            },
            IdentitySource::Generate {
                custody,
                did_method: Arc::new(did_dht),
            },
            InMemoryStorage::new(),
        )
    })
    .await
    .expect("ApplicationNode with dev API should build successfully");

    (node, dht_client)
}

/// Sends a raw HTTP/1.1 request to `addr` and returns the full response as a string.
///
/// Uses raw TCP to avoid adding `hyper-util` as a dev-dependency.
async fn raw_http_request(addr: SocketAddr, request: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("should connect");

    stream.write_all(request.as_bytes()).await.unwrap();

    // Read the response. The server sees `Connection: close` and will
    // close its end after sending, which unblocks read_to_string.
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    response
}

#[tokio::test]
async fn scenario6_dev_router_returns_none_when_not_configured() {
    let (node, _) = build_test_node().await;
    assert!(
        node.dev_router().is_none(),
        "dev_router() should return None when local_api was not configured"
    );
}

#[tokio::test]
async fn scenario6_dev_api_reachable_alongside_public_server() {
    let (node, _dht_client) = build_test_node_with_dev_api().await;

    // --- Assert: dev_router() returns Some when local_api was configured ---
    let dev_router = node
        .dev_router()
        .expect("dev_router() should return Some when local_api was configured");

    let dev_token = node
        .dev_token()
        .expect("dev_token() should return Some when local_api was configured")
        .to_owned();

    // --- Bind the dev API to a real TCP listener (port 0) ---
    let dev_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("should bind dev API listener");
    let dev_addr = dev_listener
        .local_addr()
        .expect("should get dev API local addr");

    // --- Also bind the public router to a real TCP listener (port 0) ---
    let public_router = node.well_known_router().merge(node.relay_router());
    let public_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("should bind public listener");
    let public_addr = public_listener
        .local_addr()
        .expect("should get public local addr");

    // --- Verify the two listeners are on different ports ---
    assert_ne!(
        dev_addr.port(),
        public_addr.port(),
        "dev API and public server must run on different ports"
    );

    // --- Start both servers concurrently ---
    tokio::spawn(async move {
        axum::serve(dev_listener, dev_router).await.ok();
    });
    tokio::spawn(async move {
        axum::serve(public_listener, public_router).await.ok();
    });

    // Wait for the spawned servers to start accepting connections.
    // A fixed sleep is flaky under CI load; instead, retry with backoff.
    for addr in [dev_addr, public_addr] {
        let mut retries = 0u64;
        loop {
            match tokio::net::TcpStream::connect(addr).await {
                Ok(_) => break,
                Err(_) if retries < 10 => {
                    retries += 1;
                    tokio::time::sleep(std::time::Duration::from_millis(10 * retries)).await;
                }
                Err(e) => panic!("server at {addr} failed to start: {e}"),
            }
        }
    }

    // --- Make authenticated HTTP request to the dev API health endpoint ---
    let response = raw_http_request(
        dev_addr,
        &format!(
            "GET /scp/dev/v1/health HTTP/1.1\r\n\
             Host: {dev_addr}\r\n\
             Authorization: Bearer {dev_token}\r\n\
             Connection: close\r\n\
             \r\n"
        ),
    )
    .await;

    assert!(
        response.starts_with("HTTP/1.1 200"),
        "dev API health endpoint should return 200, got: {}",
        response.lines().next().unwrap_or("")
    );
    assert!(
        response.contains("uptime_seconds"),
        "health response should include uptime_seconds"
    );
    assert!(
        response.contains("storage_status"),
        "health response should include storage_status"
    );

    // --- Verify public server is also reachable ---
    let response = raw_http_request(
        public_addr,
        &format!(
            "GET /.well-known/scp HTTP/1.1\r\n\
             Host: {public_addr}\r\n\
             Connection: close\r\n\
             \r\n"
        ),
    )
    .await;

    assert!(
        response.starts_with("HTTP/1.1 200"),
        "public .well-known/scp endpoint should return 200, got: {}",
        response.lines().next().unwrap_or("")
    );

    // --- Verify unauthenticated dev API request is rejected ---
    let response = raw_http_request(
        dev_addr,
        &format!(
            "GET /scp/dev/v1/health HTTP/1.1\r\n\
             Host: {dev_addr}\r\n\
             Connection: close\r\n\
             \r\n"
        ),
    )
    .await;

    assert!(
        response.starts_with("HTTP/1.1 401"),
        "dev API should reject unauthenticated requests, got: {}",
        response.lines().next().unwrap_or("")
    );
}

// =========================================================================
// Scenario 7 (TLS): serve() terminates TLS when cert_data is present (#230)
// =========================================================================

#[tokio::test]
async fn scenario7_serve_terminates_tls_when_configured() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Test the TLS accept loop directly via `tls::serve_tls`.
    let cert_data =
        scp_node::tls::generate_self_signed("test.example.com").expect("self-signed should work");
    let (tls_cfg, _resolver) =
        scp_node::tls::build_reloadable_tls_config(&cert_data).expect("TLS config should build");
    let tls_config = Arc::new(tls_cfg);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("should bind");
    let addr = listener.local_addr().expect("should get addr");

    let shutdown_token = tokio_util::sync::CancellationToken::new();
    let shutdown_clone = shutdown_token.clone();

    let app = axum::Router::new().route("/", axum::routing::get(|| async { "hello from TLS" }));

    // Start the TLS server in a background task.
    let server_handle = tokio::spawn(async move {
        scp_node::tls::serve_tls(listener, tls_config, app, shutdown_token)
            .await
            .expect("serve_tls should not error");
    });

    // Wait for the server to start accepting.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Connect with a TLS client using a custom rustls config that trusts
    // the self-signed certificate.
    let certs = cert_data
        .certificate_chain_der()
        .expect("should parse certs");

    let mut root_store = rustls::RootCertStore::empty();
    for cert in &certs {
        root_store.add(cert.clone()).expect("should add cert");
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let client_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("protocol versions should be valid")
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let tcp_stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("should connect via TCP");

    let server_name = rustls::pki_types::ServerName::try_from("test.example.com")
        .expect("should parse server name");

    let mut tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .expect("TLS handshake should succeed with trusted self-signed cert");

    // Send an HTTP/1.1 request over the TLS stream.
    let request = "GET / HTTP/1.1\r\nHost: test.example.com\r\nConnection: close\r\n\r\n";
    tls_stream
        .write_all(request.as_bytes())
        .await
        .expect("should write request");

    let mut response = String::new();
    tls_stream
        .read_to_string(&mut response)
        .await
        .expect("should read response");

    assert!(
        response.starts_with("HTTP/1.1 200"),
        "TLS server should respond with 200 OK, got: {}",
        response.lines().next().unwrap_or("")
    );
    assert!(
        response.contains("hello from TLS"),
        "response body should contain the expected content"
    );

    // Shutdown the server.
    shutdown_clone.cancel();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), server_handle).await;
}

/// Verifies that a plain TCP connection to the TLS server fails the
/// handshake (no unencrypted fallback).
#[tokio::test]
async fn scenario7_tls_server_rejects_plain_tcp() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let cert_data =
        scp_node::tls::generate_self_signed("test.example.com").expect("self-signed should work");
    let (tls_cfg, _resolver) =
        scp_node::tls::build_reloadable_tls_config(&cert_data).expect("TLS config should build");
    let tls_config = Arc::new(tls_cfg);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("should bind");
    let addr = listener.local_addr().expect("should get addr");

    let shutdown_token = tokio_util::sync::CancellationToken::new();
    let shutdown_clone = shutdown_token.clone();

    let app =
        axum::Router::new().route("/", axum::routing::get(|| async { "should not see this" }));

    tokio::spawn(async move {
        scp_node::tls::serve_tls(listener, tls_config, app, shutdown_token)
            .await
            .ok();
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Send plain HTTP (no TLS) — the server should not respond with valid HTTP.
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("TCP connect should succeed");

    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
        .await
        .expect("write should succeed");

    let mut buf = vec![0u8; 512];
    let result =
        tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut buf)).await;

    match result {
        Ok(Ok(0) | Err(_)) | Err(_) => {
            // Expected: server closes connection, timeout, or connection
            // error (TLS handshake fails on non-TLS data).
        }
        Ok(Ok(n)) => {
            let response = String::from_utf8_lossy(&buf[..n]);
            assert!(
                !response.starts_with("HTTP/1.1 200"),
                "plain TCP should NOT get a valid HTTP 200 response from a TLS server"
            );
        }
    }

    shutdown_clone.cancel();
}

// =========================================================================
// Scenario 8: Broadcast projection endpoints coexist with .well-known/scp
//             on the same public listener (SCP-249)
// =========================================================================

#[tokio::test]
async fn scenario8_projection_endpoints_coexist_with_well_known() {
    let (node, _dht_client) = build_test_node().await;

    // Merge well-known, relay, and broadcast projection routers — the same
    // composition that serve() performs internally.
    let router = node
        .well_known_router()
        .merge(node.relay_router())
        .merge(node.broadcast_projection_router());

    // --- Assert: GET /.well-known/scp still works ---
    let well_known_req = Request::builder()
        .uri("/.well-known/scp")
        .body(Body::empty())
        .unwrap();

    let response = router.clone().oneshot(well_known_req).await.unwrap();
    assert_eq!(response.status(), 200, ".well-known/scp should return 200");

    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let well_known: WellKnownScp =
        serde_json::from_slice(&body_bytes).expect("response should be valid JSON");
    assert_eq!(well_known.version, 1);

    // --- Assert: GET /scp/broadcast/<routing_id>/feed returns 404 (no projected context) ---
    // Use a fake routing_id hex — the route is matched but the handler
    // returns 404 because no context with that routing_id is projected.
    let fake_routing_id = "aa".repeat(32); // 64 hex chars = 32 bytes
    let feed_req = Request::builder()
        .uri(format!("/scp/broadcast/{fake_routing_id}/feed"))
        .body(Body::empty())
        .unwrap();

    let response = router.clone().oneshot(feed_req).await.unwrap();
    assert_eq!(
        response.status(),
        404,
        "feed endpoint should return 404 for unknown routing_id"
    );

    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8_lossy(&body_bytes);
    assert!(
        body_str.contains("unknown routing_id"),
        "404 response should indicate unknown routing_id, got: {body_str}"
    );

    // --- Assert: GET /scp/broadcast/<routing_id>/messages/<blob_id> returns 404 ---
    let fake_blob_id = "bb".repeat(32);
    let message_req = Request::builder()
        .uri(format!(
            "/scp/broadcast/{fake_routing_id}/messages/{fake_blob_id}"
        ))
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(message_req).await.unwrap();
    assert_eq!(
        response.status(),
        404,
        "message endpoint should return 404 for unknown routing_id"
    );
}

// ---------------------------------------------------------------------------
// ApplicationNode::dev() convenience constructor
// ---------------------------------------------------------------------------

/// Verifies that `ApplicationNode::dev(port)` creates a fully functional node
/// with in-memory storage, auto-generated DID identity, self-signed TLS, and
/// a relay bound to localhost.
#[tokio::test]
async fn dev_constructor_creates_working_node() {
    use scp_node::ApplicationNode;

    // Port 0 lets the OS assign an available port.
    let node = ApplicationNode::dev(0).await.unwrap();

    // Identity was auto-generated with did:dht method.
    assert!(
        node.identity().did().starts_with("did:dht:"),
        "DID should start with did:dht:, got: {}",
        node.identity().did()
    );

    // DID document has an SCPRelay service entry pointing to localhost.
    let relay_urls = node.identity().document().relay_service_urls();
    assert_eq!(relay_urls.len(), 1);
    assert_eq!(relay_urls[0], "wss://localhost/scp/v1");

    // Domain is "localhost".
    assert_eq!(node.domain(), Some("localhost"));
    assert_eq!(node.relay_url(), "wss://localhost/scp/v1");

    // Relay is actually bound to a real port on localhost.
    let addr = node.relay().bound_addr();
    assert!(addr.ip().is_loopback(), "relay should be bound to loopback");
    assert_ne!(addr.port(), 0, "relay should be bound to a real port");

    // Storage is accessible.
    let _storage = node.storage();

    // Clean shutdown.
    node.shutdown();
}
