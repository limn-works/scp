//! Integration test for cross-transport blob delivery on a single node.
//!
//! PR-3b wired the relay-side QUIC listener into the node serve path so that,
//! in domain mode, one `ApplicationNode` serves BOTH the WebSocket relay (over
//! TCP) and the QUIC listener (over UDP) on the same port, sharing a single
//! [`SubscriptionRegistry`] and blob storage backend. This test proves the
//! cross-transport path: a subscriber on one transport receives a blob that was
//! published over the OTHER transport.
//!
//! The WebSocket and QUIC paths register their subscriber channels in the same
//! shared registry (`routing_id -> Vec<SubscriberEntry>`), so a PUBLISH on
//! either transport fans out to every subscriber regardless of which transport
//! it arrived on. This test exercises both directions and asserts the exact
//! published payload is delivered.
//!
//! Spec: section 10.14.3 (QUIC on the same TLS port, shared subscription and
//! blob state). SCP-257 AC6.

#![cfg(all(feature = "quic", feature = "allow_unencrypted_storage"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use quinn::{ClientConfig, Endpoint};
use scp_transport::native::protocol::{ClientMessage, RelayMessage};
use scp_transport::quic::listener::SCP_ALPN;
use tokio_tungstenite::tungstenite::Message as WsMessage;

use scp_identity::DidCache;
use scp_identity::InMemoryDhtClient;
use scp_identity::cache::SystemClock;
use scp_identity::dht::DidDht;
use scp_node::{ApplicationNode, DhtMode, IdentitySource, Node, NodeConfig, Reach};
use scp_platform::testing::{InMemoryKeyCustody, InMemoryStorage};

type TestDidDht = DidDht<InMemoryDhtClient, SystemClock>;

// ---------------------------------------------------------------------------
// Shared TLS certificate verifier (test-only)
// ---------------------------------------------------------------------------

/// A rustls server-certificate verifier that accepts any certificate.
///
/// Test-only: the node generates its self-signed certificate internally, so the
/// QUIC and WebSocket clients have no way to pin it. Skipping verification is
/// acceptable here because the test only exercises transport plumbing, not TLS
/// trust.
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
/// Both the node's TLS stack and the client config builders require a default
/// [`CryptoProvider`]; installing it is idempotent (a second call returns
/// `Err`, which we ignore).
fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

// ---------------------------------------------------------------------------
// QUIC client helpers
// ---------------------------------------------------------------------------

/// Builds a QUIC client config that trusts any server certificate and
/// negotiates the SCP ALPN.
fn insecure_quic_client_config() -> ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification(Arc::clone(&provider))))
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![SCP_ALPN.to_vec()];

    let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config).unwrap();
    ClientConfig::new(Arc::new(quic_client_config))
}

/// Connects a QUIC client to `addr`, retrying until the listener is accepting
/// or the timeout elapses.
async fn connect_quic(addr: SocketAddr) -> quinn::Connection {
    let mut endpoint = Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    endpoint.set_default_client_config(insecure_quic_client_config());

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

/// Sends a single client message on a fresh QUIC bidi stream and returns the
/// length-prefixed frames as `RelayMessage`s, reading until the stream is
/// finished by the relay. Suitable for request/response operations (PUBLISH,
/// QUERY) that close their stream.
async fn quic_send_and_recv(conn: &quinn::Connection, msg: &ClientMessage) -> Vec<RelayMessage> {
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

/// Opens a long-lived QUIC SUBSCRIBE stream for `routing_id` and waits for the
/// server's initial `OK` acknowledgement. Returns the send/recv halves so the
/// caller can keep reading pushed `BLOB` frames.
///
/// The QUIC subscribe handler keeps the bidi stream open and writes each
/// delivered blob as a length-prefixed frame (4-byte big-endian length, then
/// `MessagePack`). Because no `since` is provided there is no backfill — the
/// first frame is `OK`, and subsequent frames are live `BLOB` pushes.
async fn quic_subscribe(
    conn: &quinn::Connection,
    routing_id: [u8; 32],
) -> (quinn::SendStream, quinn::RecvStream) {
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let subscribe = ClientMessage::Subscribe {
        ref_id: Some("quic-sub".to_owned()),
        routing_id,
        since: None,
    };
    let payload = subscribe.to_bytes().unwrap();
    let len = u32::try_from(payload.len()).unwrap();
    send.write_all(&len.to_be_bytes()).await.unwrap();
    send.write_all(&payload).await.unwrap();
    // Do NOT finish the stream: the subscribe handler delivers blobs on this
    // same stream for the lifetime of the subscription.

    let first = read_quic_frame(&mut recv)
        .await
        .expect("subscribe must ack");
    assert!(
        matches!(&first, RelayMessage::Ok { ref_id, .. } if ref_id.as_deref() == Some("quic-sub")),
        "first QUIC subscribe frame must be OK, got {first:?}"
    );
    (send, recv)
}

/// Reads one length-prefixed `RelayMessage` frame from a QUIC recv stream.
/// Returns `None` if the stream ends before a complete frame is available.
async fn read_quic_frame(recv: &mut quinn::RecvStream) -> Option<RelayMessage> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await.ok()?;
    let msg_len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; msg_len];
    recv.read_exact(&mut buf).await.ok()?;
    RelayMessage::from_bytes(&buf).ok()
}

/// Reads QUIC subscription frames until a `BLOB` arrives or the timeout
/// elapses, returning the first delivered blob payload.
async fn quic_recv_blob(recv: &mut quinn::RecvStream) -> Vec<u8> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(!remaining.is_zero(), "timed out waiting for QUIC BLOB");
        let frame = tokio::time::timeout(remaining, read_quic_frame(recv))
            .await
            .expect("timed out waiting for QUIC BLOB");
        match frame {
            Some(RelayMessage::Blob { blob, .. }) => return blob,
            // A non-blob relay frame (e.g. an event): keep reading.
            Some(_other) => {}
            None => panic!("QUIC subscribe stream closed before delivering a BLOB"),
        }
    }
}

// ---------------------------------------------------------------------------
// WebSocket (WSS) client helpers
// ---------------------------------------------------------------------------

/// A connected WebSocket stream to the node's `/scp/v1` relay endpoint, served
/// over TLS by the same node that serves QUIC.
type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>;

/// Connects a WebSocket client to `wss://127.0.0.1:{port}/scp/v1`, terminating
/// TLS with a no-verify rustls config.
///
/// The node's TLS listener advertises ALPN `["h2", "http/1.1"]`; WebSocket
/// upgrades require HTTP/1.1, so the client offers only `http/1.1` to force the
/// HTTP/1.1 path. Retries the TCP connect + handshake until the listener is up
/// or the timeout elapses.
async fn connect_ws(port: u16) -> WsStream {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification(Arc::clone(&provider))))
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let url = format!("wss://localhost:{port}/scp/v1");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let attempt = async {
            let tcp = tokio::net::TcpStream::connect(addr).await?;
            let tls = connector.connect(server_name.clone(), tcp).await?;
            let (ws, _resp) = tokio_tungstenite::client_async(&url, tls)
                .await
                .map_err(std::io::Error::other)?;
            Ok::<WsStream, std::io::Error>(ws)
        };

        match attempt.await {
            Ok(ws) => return ws,
            Err(e) => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "WebSocket connection to {url} never succeeded: {e}"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

/// Sends a `ClientMessage` over the WebSocket as a single binary frame. WS
/// framing is message-oriented, so each binary frame carries exactly one
/// `MessagePack` message (no length prefix, unlike QUIC).
async fn ws_send(ws: &mut WsStream, msg: &ClientMessage) {
    let payload = msg.to_bytes().unwrap();
    ws.send(WsMessage::Binary(payload)).await.unwrap();
}

/// Reads the next `RelayMessage` from a WebSocket binary frame, ignoring
/// non-binary control frames (Ping/Pong), or `None` if the socket closes.
async fn ws_recv(ws: &mut WsStream) -> Option<RelayMessage> {
    loop {
        match ws.next().await {
            Some(Ok(WsMessage::Binary(data))) => {
                return Some(RelayMessage::from_bytes(&data).unwrap());
            }
            // Close frame, end of stream, or transport error: no more messages.
            Some(Ok(WsMessage::Close(_)) | Err(_)) | None => return None,
            // Any other frame (Ping/Pong/Text/Frame): skip and keep reading.
            Some(Ok(_)) => {}
        }
    }
}

/// Subscribes the WebSocket client to `routing_id` and waits for the server's
/// initial `OK` acknowledgement. No `since` is provided, so there is no
/// backfill — the first frame is `OK` and later frames are live `BLOB` pushes.
async fn ws_subscribe(ws: &mut WsStream, routing_id: [u8; 32]) {
    let subscribe = ClientMessage::Subscribe {
        ref_id: Some("ws-sub".to_owned()),
        routing_id,
        since: None,
    };
    ws_send(ws, &subscribe).await;
    let first = ws_recv(ws).await.expect("subscribe must ack");
    assert!(
        matches!(&first, RelayMessage::Ok { ref_id, .. } if ref_id.as_deref() == Some("ws-sub")),
        "first WS subscribe frame must be OK, got {first:?}"
    );
}

/// Publishes a blob over the WebSocket and asserts the relay's `OK` (with a
/// `blob_id`) response. Returns nothing — the assertion is the point.
async fn ws_publish(ws: &mut WsStream, routing_id: [u8; 32], blob: Vec<u8>) {
    let publish = ClientMessage::Publish {
        ref_id: Some("ws-pub".to_owned()),
        routing_id,
        recipient_hint: None,
        blob_ttl: 3600,
        blob,
    };
    ws_send(ws, &publish).await;
    let resp = ws_recv(ws).await.expect("publish must respond");
    match resp {
        RelayMessage::Ok { ref_id, blob_id } => {
            assert_eq!(ref_id.as_deref(), Some("ws-pub"));
            assert!(blob_id.is_some(), "publish OK must include blob_id");
        }
        other => panic!("expected OK for WS publish, got {other:?}"),
    }
}

/// Reads WS frames until a `BLOB` arrives or the timeout elapses, returning the
/// delivered blob payload.
async fn ws_recv_blob(ws: &mut WsStream) -> Vec<u8> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(!remaining.is_zero(), "timed out waiting for WS BLOB");
        let frame = tokio::time::timeout(remaining, ws_recv(ws))
            .await
            .expect("timed out waiting for WS BLOB");
        match frame {
            Some(RelayMessage::Blob { blob, .. }) => return blob,
            // A non-blob relay frame (e.g. an event): keep reading.
            Some(_other) => {}
            None => panic!("WS stream closed before delivering a BLOB"),
        }
    }
}

// ---------------------------------------------------------------------------
// Node setup
// ---------------------------------------------------------------------------

/// Reserves a free TCP port by binding to port 0 and immediately releasing it.
///
/// The returned port is then used as a fixed `http_bind_addr` so the test can
/// connect both a QUIC client (UDP) and a WebSocket client (TCP) to the same
/// known port (`serve()` does not surface the bound address).
async fn reserve_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// Builds a domain-mode node with a self-signed certificate (so a QUIC server
/// config is provisioned) bound to the given public HTTP/TLS port. The same
/// node serves the WebSocket relay over TCP and the QUIC listener over UDP on
/// this port, sharing one subscription registry and blob storage backend.
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Cross-transport delivery, QUIC subscriber <- WebSocket publisher.
///
/// A QUIC client subscribes to a routing ID; a WebSocket client then publishes
/// a blob to the same routing ID. Because both transports share the node's
/// single subscription registry, the QUIC subscriber must receive the exact
/// blob published over WebSocket (spec §10.14.3 item 2, SCP-257 AC6).
#[tokio::test]
async fn quic_subscriber_receives_websocket_publish() {
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
    let routing_id = [0x5Au8; 32];
    let payload = vec![0xA1u8; 96];

    // Subscribe over QUIC first so the subscription is registered before the
    // WebSocket publish fans out.
    let quic_conn = connect_quic(addr).await;
    let (_quic_send, mut quic_recv) = quic_subscribe(&quic_conn, routing_id).await;

    // Publish over WebSocket to the same routing ID.
    let mut ws = connect_ws(port).await;
    ws_publish(&mut ws, routing_id, payload.clone()).await;

    // The QUIC subscriber must receive the exact payload published over WS.
    let delivered = quic_recv_blob(&mut quic_recv).await;
    assert_eq!(
        delivered, payload,
        "QUIC subscriber must receive the exact blob published over WebSocket"
    );

    let _ = ws.close(None).await;
    quic_conn.close(0u32.into(), b"done");
    let _ = tx.send(());
    let _ = serve_handle.await;
}

/// Cross-transport delivery, WebSocket subscriber <- QUIC publisher (reverse).
///
/// A WebSocket client subscribes to a routing ID; a QUIC client then publishes
/// a blob to the same routing ID. The WebSocket subscriber must receive the
/// exact blob published over QUIC (spec §10.14.3 item 2, SCP-257 AC6).
#[tokio::test]
async fn websocket_subscriber_receives_quic_publish() {
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
    let routing_id = [0xC3u8; 32];
    let payload = vec![0x7Eu8; 128];

    // Subscribe over WebSocket first so the subscription is registered before
    // the QUIC publish fans out.
    let mut ws = connect_ws(port).await;
    ws_subscribe(&mut ws, routing_id).await;

    // Publish over QUIC to the same routing ID.
    let quic_conn = connect_quic(addr).await;
    let publish = ClientMessage::Publish {
        ref_id: Some("quic-pub".to_owned()),
        routing_id,
        recipient_hint: None,
        blob_ttl: 3600,
        blob: payload.clone(),
    };
    let pub_responses = quic_send_and_recv(&quic_conn, &publish).await;
    assert_eq!(
        pub_responses.len(),
        1,
        "QUIC publish should produce one response"
    );
    match &pub_responses[0] {
        RelayMessage::Ok { ref_id, blob_id } => {
            assert_eq!(ref_id.as_deref(), Some("quic-pub"));
            assert!(blob_id.is_some(), "publish OK must include blob_id");
        }
        other => panic!("expected OK for QUIC publish, got {other:?}"),
    }

    // The WebSocket subscriber must receive the exact payload published over QUIC.
    let delivered = ws_recv_blob(&mut ws).await;
    assert_eq!(
        delivered, payload,
        "WebSocket subscriber must receive the exact blob published over QUIC"
    );

    let _ = ws.close(None).await;
    quic_conn.close(0u32.into(), b"done");
    let _ = tx.send(());
    let _ = serve_handle.await;
}
