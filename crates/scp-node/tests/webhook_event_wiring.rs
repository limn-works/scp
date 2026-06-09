//! End-to-end integration test for the local-event → webhook wire (§12.10.5).
//!
//! Proves the production consumer path that connects `Supervisor` events to
//! the outbound [`WebhookDispatcher`](scp_node::webhook::WebhookDispatcher):
//!
//! ```text
//! Supervisor event channel (broadcast)
//!   → spawn_event_consumer  (the production consumer task)
//!     → map_context_event   (ContextEvent → event_type + payload)
//!       → WebhookDispatcher::dispatch_event
//!         → HTTPS POST with X-SCP-Signature (Ed25519)
//! ```
//!
//! A real `tokio::sync::broadcast` channel — the exact type returned by
//! `Supervisor::subscribe_events()` — feeds a `ContextEvent` into the
//! consumer, and a local HTTPS capture server asserts the POST arrives with the
//! correct event type, structured body, and a valid Ed25519 signature.
//!
//! The producer half (a live `Supervisor` emitting events on real context
//! operations) is covered by the `event_channel_*` tests in `scp-runtime`; this
//! test covers the node-side consumer wire that was previously unreachable in
//! production.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{SigningKey, Verifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use scp_core::context::membership::ContextEvent;
use scp_identity::DID;
use scp_node::webhook::{WebhookDispatcher, WebhookTarget, spawn_event_consumer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// Captured webhook request: the raw HTTP request bytes received by the server.
struct CapturedRequest {
    raw: Vec<u8>,
}

impl CapturedRequest {
    /// Returns the header value for `name` (case-insensitive), if present.
    fn header(&self, name: &str) -> Option<String> {
        let text = String::from_utf8_lossy(&self.raw);
        for line in text.lines() {
            if line.is_empty() {
                break; // end of headers
            }
            if let Some((k, v)) = line.split_once(':')
                && k.trim().eq_ignore_ascii_case(name)
            {
                return Some(v.trim().to_owned());
            }
        }
        None
    }

    /// Returns the request body (everything after the blank line).
    fn body(&self) -> Vec<u8> {
        // Find the CRLFCRLF header/body boundary.
        let needle = b"\r\n\r\n";
        self.raw
            .windows(needle.len())
            .position(|w| w == needle)
            .map(|pos| self.raw[pos + needle.len()..].to_vec())
            .unwrap_or_default()
    }
}

/// A running local HTTPS capture server.
struct CaptureServer {
    /// The hostname placed in the cert SAN and used in the webhook URL.
    host: String,
    /// The bound socket address (127.0.0.1:<port>).
    addr: SocketAddr,
    /// PEM-encoded self-signed certificate the client must trust.
    cert_pem: String,
    /// Resolves once the first request is captured.
    captured: tokio::sync::oneshot::Receiver<CapturedRequest>,
}

/// Starts a local HTTPS server that captures the first POST and returns 200.
///
/// The certificate SAN is a non-resolvable hostname so that
/// `WebhookDispatcher`'s SSRF DNS pre-resolution treats it as allowed (it does
/// not resolve to any blocked IP), while the reqwest client reaches it via an
/// explicit `.resolve()` override to 127.0.0.1.
async fn start_capture_server() -> CaptureServer {
    let host = "webhook.scp-test.invalid".to_owned();
    let cert = rcgen::generate_simple_self_signed(vec![host.clone()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_der = PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());

    let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(rustls::DEFAULT_VERSIONS)
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert_der], key_der)
    .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel::<CapturedRequest>();
    let tx = Arc::new(tokio::sync::Mutex::new(Some(tx)));

    tokio::spawn(async move {
        loop {
            let Ok((stream, _peer)) = listener.accept().await else {
                continue;
            };
            let acceptor = acceptor.clone();
            let tx = Arc::clone(&tx);
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                // Read until the full request (headers + body) has arrived.
                // The body is small, so a single bounded read loop suffices.
                let mut raw = Vec::new();
                let mut buf = [0u8; 2048];
                loop {
                    match tls.read(&mut buf).await {
                        // EOF (0 bytes) or read error: stop reading.
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            raw.extend_from_slice(&buf[..n]);
                            // Stop once we have headers and a body terminator.
                            if has_complete_request(&raw) {
                                break;
                            }
                        }
                    }
                }
                // Respond 200 OK so dispatch reports success.
                let response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = tls.write_all(response).await;
                let _ = tls.flush().await;
                let _ = tls.shutdown().await;
                let sender = tx.lock().await.take();
                if let Some(sender) = sender {
                    let _ = sender.send(CapturedRequest { raw });
                }
            });
        }
    });

    CaptureServer {
        host,
        addr,
        cert_pem,
        captured: rx,
    }
}

/// Returns true once `raw` contains a full HTTP request with a body matching its
/// declared `Content-Length` (or a terminated header block with no body).
fn has_complete_request(raw: &[u8]) -> bool {
    let needle = b"\r\n\r\n";
    let Some(boundary) = raw.windows(needle.len()).position(|w| w == needle) else {
        return false;
    };
    let header_text = String::from_utf8_lossy(&raw[..boundary]);
    let declared_len = header_text
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    let body_len = raw.len() - (boundary + needle.len());
    body_len >= declared_len
}

/// Builds a reqwest client that trusts the capture server's self-signed cert and
/// resolves the test hostname to the server's loopback address. Mirrors the
/// production hardening (no redirects) but pins a local root instead of `WebPKI`.
fn trusting_client(cert_pem: &str, host: &str, addr: SocketAddr) -> reqwest::Client {
    let cert = reqwest::Certificate::from_pem(cert_pem.as_bytes()).unwrap();
    reqwest::Client::builder()
        .add_root_certificate(cert)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .resolve(host, addr)
        .build()
        .unwrap()
}

/// Full wire: a `ContextEvent` sent on the broadcast channel is consumed by the
/// production [`spawn_event_consumer`], mapped, and dispatched as a signed HTTPS
/// POST to a registered webhook target.
#[tokio::test]
async fn context_event_reaches_webhook_dispatcher_end_to_end() {
    let server = start_capture_server().await;

    // Dispatcher uses a client that trusts the local cert and resolves the test
    // host to the capture server — everything else is production behavior.
    let client = trusting_client(&server.cert_pem, &server.host, server.addr);
    let dispatcher = Arc::new(WebhookDispatcher::with_client(client));

    // Register a webhook target scoped to the context we will emit for.
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let webhook_url = format!("https://{}:{}/hook", server.host, server.addr.port());
    let registered = dispatcher
        .register(
            "bridge-under-test".to_owned(),
            WebhookTarget {
                url: webhook_url,
                signing_key: signing_key.clone(),
                context_ids: vec!["ctx-wire".to_owned()],
            },
        )
        .await;
    assert!(registered, "target registration should succeed");

    // The exact channel type Supervisor::subscribe_events() hands out.
    let (tx, rx) = tokio::sync::broadcast::channel::<(String, ContextEvent)>(1024);
    let consumer = spawn_event_consumer(rx, Arc::clone(&dispatcher));

    // Emit a MemberJoined event exactly as the actor handlers would.
    tx.send((
        "ctx-wire".to_owned(),
        ContextEvent::MemberJoined {
            member_did: DID::from("did:key:carol"),
            role_name: "admin".to_owned(),
        },
    ))
    .expect("send on broadcast channel");

    // Await the captured request (bounded — fail fast if the wire is broken).
    let captured = tokio::time::timeout(Duration::from_secs(10), server.captured)
        .await
        .expect("webhook should be delivered before timeout")
        .expect("capture channel should yield a request");

    // Tear down the consumer so the test does not leak the task.
    consumer.abort();

    // 1. Headers carry the signature contract (§12.10.2).
    assert_eq!(
        captured.header("content-type").as_deref(),
        Some("application/json"),
        "Content-Type must be application/json"
    );
    let sig_hex = captured
        .header("x-scp-signature")
        .expect("X-SCP-Signature header must be present");
    let ts_str = captured
        .header("x-scp-timestamp")
        .expect("X-SCP-Timestamp header must be present");
    let timestamp: u64 = ts_str.parse().expect("timestamp must be a u64");

    // 2. Body is the mapped MemberJoined event (proves map_context_event ran).
    let body = captured.body();
    let body_json: serde_json::Value =
        serde_json::from_slice(&body).expect("body must be valid JSON");
    assert_eq!(
        body_json["event_type"], "member.joined",
        "MemberJoined must map to the member.joined webhook event type"
    );
    assert_eq!(body_json["context_id"], "ctx-wire");
    assert_eq!(body_json["payload"]["member_did"], "did:key:carol");
    assert_eq!(body_json["payload"]["role_name"], "admin");

    // 3. The Ed25519 signature verifies over the domain-separated payload.
    let sig_bytes = hex::decode(&sig_hex).expect("signature must be valid hex");
    let signature =
        ed25519_dalek::Signature::from_slice(&sig_bytes).expect("signature must be 64 bytes");
    let mut signing_payload = Vec::new();
    signing_payload.extend_from_slice(b"SCP-WEBHOOK-V1:");
    signing_payload.extend_from_slice(&timestamp.to_be_bytes());
    signing_payload.extend_from_slice(&body);
    verifying_key
        .verify(&signing_payload, &signature)
        .expect("Ed25519 signature must verify");
}

/// A target scoped to a different context must NOT receive the event. Proves the
/// consumer honors `WebhookDispatcher`'s per-context routing rather than
/// fanning every event to every registered target.
#[tokio::test]
async fn consumer_respects_context_scoping() {
    let server = start_capture_server().await;
    let client = trusting_client(&server.cert_pem, &server.host, server.addr);
    let dispatcher = Arc::new(WebhookDispatcher::with_client(client));

    let signing_key = SigningKey::from_bytes(&[9u8; 32]);
    let webhook_url = format!("https://{}:{}/hook", server.host, server.addr.port());
    dispatcher
        .register(
            "other-context-bridge".to_owned(),
            WebhookTarget {
                url: webhook_url,
                signing_key,
                // Subscribed only to ctx-other, not ctx-wire.
                context_ids: vec!["ctx-other".to_owned()],
            },
        )
        .await;

    let (tx, rx) = tokio::sync::broadcast::channel::<(String, ContextEvent)>(1024);
    let consumer = spawn_event_consumer(rx, Arc::clone(&dispatcher));

    tx.send((
        "ctx-wire".to_owned(),
        ContextEvent::MemberLeft {
            member_did: DID::from("did:key:dave"),
        },
    ))
    .expect("send on broadcast channel");

    // The capture server must NOT receive a request: assert a short timeout
    // elapses without delivery.
    let result = tokio::time::timeout(Duration::from_millis(750), server.captured).await;
    consumer.abort();
    assert!(
        result.is_err(),
        "event for ctx-wire must not be delivered to a ctx-other-scoped target"
    );
}

/// A lagging/closed channel must not panic the consumer. Sending after the
/// receiver is wired, then dropping the sender, closes the channel and the
/// consumer task completes cleanly (fail-safe behavior — §12.10.5 best-effort).
#[tokio::test]
async fn consumer_exits_cleanly_on_channel_close() {
    let dispatcher = Arc::new(WebhookDispatcher::new());
    let (tx, rx) = tokio::sync::broadcast::channel::<(String, ContextEvent)>(8);
    let consumer = spawn_event_consumer(rx, dispatcher);

    // Drop the sender → channel closes → consumer should return (not hang).
    drop(tx);

    tokio::time::timeout(Duration::from_secs(5), consumer)
        .await
        .expect("consumer must exit when the channel closes")
        .expect("consumer task must not panic");
}
