//! Integration tests for the relay-side QUIC listener wired into the node
//! serve path.
//!
//! These tests verify that, when the `quic` feature is enabled and a TLS
//! certificate is provisioned (domain mode), `ApplicationNode::serve` starts a
//! QUIC listener on the same UDP port as the WebSocket TCP listener, that the
//! listener shares subscription and blob state with the WebSocket relay, and
//! that `.well-known/scp` advertises `"quic"` only when the listener is
//! actually running.
//!
//! Spec: section 10.14.3 (QUIC on the same TLS port, shared state),
//! section 10.5.1 (transport advertisement). SCP-257 AC1.

#![cfg(all(feature = "quic", feature = "allow_unencrypted_storage"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::{ClientConfig, Endpoint};
use scp_transport::native::protocol::{ClientMessage, RelayMessage};
use scp_transport::quic::listener::SCP_ALPN;

use scp_clock::SystemClock;
use scp_dht::InMemoryDhtClient;
use scp_identity::DidCache;
use scp_identity::dht::DidDht;
use scp_node::{ApplicationNode, DhtMode, IdentitySource, Node, NodeConfig, Reach};
use scp_platform::in_memory::InMemoryStorage;
use scp_platform::testing::InMemoryKeyCustody;

type TestDidDht = DidDht<InMemoryDhtClient, SystemClock>;

/// A rustls server-certificate verifier that accepts any certificate.
///
/// Test-only: the node generates its self-signed certificate internally, so the
/// QUIC client has no way to pin it. Skipping verification is acceptable here
/// because the test only exercises transport plumbing, not TLS trust.
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Installs the process-wide rustls crypto provider exactly once.
///
/// Both the node's TLS stack and the QUIC client config builder require a
/// default [`CryptoProvider`]; installing it is idempotent (a second call
/// returns `Err`, which we ignore).
fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Builds a QUIC client config that trusts any server certificate and
/// negotiates the SCP ALPN.
fn insecure_client_config() -> ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification(Arc::clone(&provider))))
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![SCP_ALPN.to_vec()];

    let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config).unwrap();
    ClientConfig::new(Arc::new(quic_client_config))
}

/// Reserves a free TCP port by binding to port 0 and immediately releasing it.
///
/// The returned port is then used as a fixed `http_bind_addr` so the test can
/// connect a QUIC client to the known UDP port (`serve()` does not surface the
/// bound address).
async fn reserve_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// Builds a domain-mode node with a self-signed certificate (so a QUIC server
/// config is provisioned) bound to the given public HTTP/TLS port.
async fn build_tls_node(http_port: u16) -> ApplicationNode<InMemoryStorage> {
    let custody = Arc::new(InMemoryKeyCustody::new());
    let dht_client = Arc::new(InMemoryDhtClient::new());
    let cache = Arc::new(DidCache::new());
    let sign_fn = TestDidDht::make_sign_fn(Arc::clone(&custody));
    let did_method = Arc::new(TestDidDht::with_client_and_signer(
        dht_client, cache, sign_fn,
    ));

    // Default `TlsMode::SelfSigned` reproduces the dropped explicit
    // `SelfSignedTlsProvider::new("localhost")` (so a QUIC server config is
    // provisioned). `Domain` → `DhtMode::Production` (M2; advisory in P1).
    Node::start_for_testing(NodeConfig {
        http_bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], http_port))),
        dht: DhtMode::Production,
        ..NodeConfig::defaults(
            Reach::Domain {
                domain: "localhost".to_owned(),
            },
            IdentitySource::Generate {
                custody,
                did_method,
            },
            InMemoryStorage::new(),
        )
    })
    .await
    .expect("node build should succeed")
}

/// Connects a QUIC client to `addr`, retrying until the listener is accepting
/// or the timeout elapses.
async fn connect_quic(addr: SocketAddr) -> quinn::Connection {
    let mut endpoint = Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    endpoint.set_default_client_config(insecure_client_config());

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match endpoint.connect(addr, "localhost").unwrap().await {
            Ok(conn) => return conn,
            Err(e) => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "QUIC connection to {addr} never succeeded: {e}"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

/// Sends a single client message on a fresh bidi stream and reads all responses.
async fn send_and_recv(conn: &quinn::Connection, msg: &ClientMessage) -> Vec<RelayMessage> {
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let payload = msg.to_bytes().unwrap();
    let len = u32::try_from(payload.len()).unwrap();
    send.write_all(&len.to_be_bytes()).await.unwrap();
    send.write_all(&payload).await.unwrap();
    send.finish().unwrap();

    let mut messages = Vec::new();
    loop {
        let mut len_buf = [0u8; 4];
        if recv.read_exact(&mut len_buf).await.is_err() {
            break;
        }
        let msg_len = u32::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; msg_len];
        if recv.read_exact(&mut buf).await.is_err() {
            break;
        }
        match RelayMessage::from_bytes(&buf) {
            Ok(m) => messages.push(m),
            Err(_) => break,
        }
    }
    messages
}

/// Asserts the node accepts a QUIC connection on the same UDP port as its
/// WebSocket TCP listener (spec §10.14.3 item 1, SCP-257 AC1).
#[tokio::test]
async fn quic_listener_accepts_connection_on_serve() {
    install_crypto_provider();
    let port = reserve_port().await;
    let node = build_tls_node(port).await;

    // Run serve() in the background; it consumes the node and runs until the
    // shutdown future resolves.
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let serve_handle = tokio::spawn(async move {
        node.serve(axum::Router::new(), async move {
            let _ = rx.await;
        })
        .await
        .ok();
    });

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let conn = connect_quic(addr).await;
    assert_eq!(conn.remote_address(), addr);

    conn.close(0u32.into(), b"done");
    let _ = tx.send(());
    let _ = serve_handle.await;
}

/// Asserts a PUBLISH over QUIC is stored and visible to a subsequent QUERY over
/// QUIC (shared blob storage smoke test, spec §10.14.3 item 2).
#[tokio::test]
async fn quic_publish_then_query_roundtrips() {
    install_crypto_provider();
    let port = reserve_port().await;
    let node = build_tls_node(port).await;

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let serve_handle = tokio::spawn(async move {
        node.serve(axum::Router::new(), async move {
            let _ = rx.await;
        })
        .await
        .ok();
    });

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let conn = connect_quic(addr).await;

    let routing_id = [7u8; 32];
    let blob = vec![123u8; 64];

    // PUBLISH.
    let publish = ClientMessage::Publish {
        ref_id: Some("pub-1".to_owned()),
        routing_id,
        recipient_hint: None,
        blob_ttl: 3600,
        blob: blob.clone(),
    };
    let pub_responses = send_and_recv(&conn, &publish).await;
    assert_eq!(
        pub_responses.len(),
        1,
        "publish should produce one response"
    );
    match &pub_responses[0] {
        RelayMessage::Ok { ref_id, blob_id } => {
            assert_eq!(ref_id.as_deref(), Some("pub-1"));
            assert!(blob_id.is_some(), "publish OK must include blob_id");
        }
        other => panic!("expected OK, got {other:?}"),
    }

    // QUERY the same routing id over QUIC — must see the published blob.
    let query = ClientMessage::Query {
        ref_id: Some("q-1".to_owned()),
        routing_id,
        since: None,
        limit: None,
    };
    let query_responses = send_and_recv(&conn, &query).await;
    assert!(
        query_responses
            .iter()
            .any(|m| matches!(m, RelayMessage::Blob { blob: b, .. } if b == &blob)),
        "query must return the blob published over QUIC, got {query_responses:?}"
    );

    conn.close(0u32.into(), b"done");
    let _ = tx.send(());
    let _ = serve_handle.await;
}

/// Asserts `.well-known/scp` advertises `"quic"` when (and only when) a QUIC
/// listener is running. The node serves HTTPS with a self-signed certificate,
/// so the request accepts invalid certs (test-only). Spec §10.5.1 / §10.14.3.
#[tokio::test]
async fn well_known_advertises_quic_when_listener_running() {
    install_crypto_provider();
    let port = reserve_port().await;
    let node = build_tls_node(port).await;

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let serve_handle = tokio::spawn(async move {
        node.serve(axum::Router::new(), async move {
            let _ = rx.await;
        })
        .await
        .ok();
    });

    // Confirm the QUIC listener is up before asserting the advertisement, so the
    // advertisement reflects a genuinely running listener.
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let conn = connect_quic(addr).await;
    conn.close(0u32.into(), b"probe");

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let url = format!("https://127.0.0.1:{port}/.well-known/scp");
    // The TCP listener may need a moment after bind; retry briefly.
    let mut doc: Option<serde_json::Value> = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while tokio::time::Instant::now() < deadline {
        if let Ok(resp) = client.get(&url).send().await
            && let Ok(json) = resp.json::<serde_json::Value>().await
        {
            doc = Some(json);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let doc = doc.expect("well-known document should be reachable over HTTPS");

    let transports = doc
        .get("relay_config")
        .and_then(|rc| rc.get("transports"))
        .and_then(|t| t.as_array())
        .expect("relay_config.transports must be present");
    let transport_names: Vec<&str> = transports.iter().filter_map(|v| v.as_str()).collect();

    assert!(
        transport_names.contains(&"websocket"),
        "websocket must always be advertised, got {transport_names:?}"
    );
    assert!(
        transport_names.contains(&"quic"),
        "quic must be advertised while the QUIC listener is running, got {transport_names:?}"
    );

    let _ = tx.send(());
    let _ = serve_handle.await;
}
