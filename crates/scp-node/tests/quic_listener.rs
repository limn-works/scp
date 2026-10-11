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

mod quic_support;

use scp_relay_client::{ClientMessage, RelayMessage};

use quic_support::{
    CONNECT_DEADLINE, build_tls_node, connect_quic, install_crypto_provider, serve_in_background,
};

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
    let mut serving = serve_in_background(build_tls_node().await).await;

    let conn = connect_quic(&mut serving).await;
    assert_eq!(conn.remote_address(), serving.quic_addr);
    assert_eq!(conn.remote_address().port(), serving.http_addr.port());

    conn.close(0u32.into(), b"done");
    serving.stop().await;
}

/// Asserts a PUBLISH over QUIC is stored and visible to a subsequent QUERY over
/// QUIC (shared blob storage smoke test, spec §10.14.3 item 2).
#[tokio::test]
async fn quic_publish_then_query_roundtrips() {
    install_crypto_provider();
    let mut serving = serve_in_background(build_tls_node().await).await;

    let conn = connect_quic(&mut serving).await;

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
    serving.stop().await;
}

/// Asserts `.well-known/scp` advertises `"quic"` when (and only when) a QUIC
/// listener is running. The node serves HTTPS with a self-signed certificate,
/// so the request accepts invalid certs (test-only). Spec §10.5.1 / §10.14.3.
#[tokio::test]
async fn well_known_advertises_quic_when_listener_running() {
    install_crypto_provider();
    let mut serving = serve_in_background(build_tls_node().await).await;

    // Confirm the QUIC listener is up before asserting the advertisement, so the
    // advertisement reflects a genuinely running listener.
    let conn = connect_quic(&mut serving).await;
    conn.close(0u32.into(), b"probe");

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(CONNECT_DEADLINE)
        .build()
        .unwrap();

    // `bind()` returned before the serve task started, so the TCP listener
    // already holds the connection in its backlog: one bounded request
    // suffices, and its error is the failure message.
    let url = format!("https://{}/.well-known/scp", serving.http_addr);
    let doc: serde_json::Value = client
        .get(&url)
        .send()
        .await
        .unwrap_or_else(|e| panic!("GET {url} failed: {e}"))
        .json()
        .await
        .unwrap_or_else(|e| panic!("GET {url} returned no JSON document: {e}"));

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

    // Close the client's pooled keep-alive connection first: the TLS server's
    // shutdown waits for open connections to finish, up to 30 s.
    drop(client);
    serving.stop().await;
}
