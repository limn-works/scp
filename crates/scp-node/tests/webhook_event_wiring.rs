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
//! operations) is covered by
//! `supervisor_send_emits_stripped_message_sent_to_subscriber` in
//! `scp-runtime/tests/event_channel_producer.rs`; this test covers the
//! node-side consumer wire that was previously unreachable in production.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use ed25519_dalek::{SigningKey, Verifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use scp_core::context::membership::{ContextEvent, ContextEventEnvelope};
use scp_did::DID;
use scp_node::webhook::{WebhookDispatcher, WebhookTarget, spawn_event_consumer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// Monotonic counter giving each capture server a unique SAN host, so a single
/// reqwest client can route to several servers via per-host `.resolve()`.
static SERVER_SEQ: AtomicU64 = AtomicU64::new(0);

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
    start_capture_server_with_delay(Duration::ZERO).await
}

/// Like [`start_capture_server`], but the server waits `response_delay` after
/// reading the request before sending its 200 response. Used to model a slow
/// (or unreachable-feeling) webhook target so the consumer's drain-vs-dispatch
/// decoupling can be observed: a slow target must NOT stall delivery to a fast
/// target on another context.
///
/// Each server uses a distinct, non-resolvable SAN host so a single reqwest
/// client can route to multiple capture servers via per-host `.resolve()`
/// overrides.
async fn start_capture_server_with_delay(response_delay: Duration) -> CaptureServer {
    // A unique host per server so the client can resolve each independently.
    let host = format!(
        "webhook-{}.scp-test.invalid",
        SERVER_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
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
                // Model a slow target: hold the response so the consumer's
                // drain-vs-dispatch decoupling can be observed.
                if !response_delay.is_zero() {
                    tokio::time::sleep(response_delay).await;
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

/// Builds a reqwest client that trusts several capture servers' self-signed
/// certs and resolves each server's host to its loopback address. Lets one
/// dispatcher fan out to multiple capture servers (slow + fast targets).
fn trusting_multi_client(servers: &[&CaptureServer]) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10));
    for server in servers {
        let cert = reqwest::Certificate::from_pem(server.cert_pem.as_bytes()).unwrap();
        builder = builder
            .add_root_certificate(cert)
            .resolve(&server.host, server.addr);
    }
    builder.build().unwrap()
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
    let dispatcher = Arc::new(WebhookDispatcher::with_client_for_test(client));

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
    let (tx, rx) = tokio::sync::broadcast::channel::<ContextEventEnvelope>(1024);
    let consumer = spawn_event_consumer(rx, Arc::clone(&dispatcher));

    // Emit a MemberJoined event exactly as the actor handlers would.
    tx.send(ContextEventEnvelope::new(
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
    let dispatcher = Arc::new(WebhookDispatcher::with_client_for_test(client));

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

    let (tx, rx) = tokio::sync::broadcast::channel::<ContextEventEnvelope>(1024);
    let consumer = spawn_event_consumer(rx, Arc::clone(&dispatcher));

    tx.send(ContextEventEnvelope::new(
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
    let (tx, rx) = tokio::sync::broadcast::channel::<ContextEventEnvelope>(8);
    let consumer = spawn_event_consumer(rx, dispatcher);

    // Drop the sender → channel closes → consumer should return (not hang).
    drop(tx);

    tokio::time::timeout(Duration::from_secs(5), consumer)
        .await
        .expect("consumer must exit when the channel closes")
        .expect("consumer task must not panic");
}

/// The recv loop must drain at channel speed, not at dispatch speed: a slow
/// target on one context must NOT stall delivery of a later event to a fast
/// target on another context. Regression guard for the drain-vs-dispatch
/// coupling that would let one high-latency webhook target silently evict
/// another context's audit events from the shared broadcast channel.
///
/// Two targets share one dispatcher: a SLOW server (holds its response for
/// `SLOW_DELAY`) scoped to `ctx-slow`, and a FAST server scoped to `ctx-fast`.
/// The slow event is enqueued first, then the fast event. If dispatch were
/// awaited inline in the recv loop, the fast delivery could not occur until the
/// slow dispatch returned (>= `SLOW_DELAY`). With the per-event spawn, the fast
/// delivery lands promptly — well under `SLOW_DELAY`.
#[tokio::test]
async fn consumer_drains_past_a_slow_target() {
    const SLOW_DELAY: Duration = Duration::from_secs(3);

    let slow_server = start_capture_server_with_delay(SLOW_DELAY).await;
    let fast_server = start_capture_server_with_delay(Duration::ZERO).await;

    let client = trusting_multi_client(&[&slow_server, &fast_server]);
    let dispatcher = Arc::new(WebhookDispatcher::with_client_for_test(client));

    // Slow target — scoped to ctx-slow.
    let slow_url = format!(
        "https://{}:{}/hook",
        slow_server.host,
        slow_server.addr.port()
    );
    dispatcher
        .register(
            "slow-bridge".to_owned(),
            WebhookTarget {
                url: slow_url,
                signing_key: SigningKey::from_bytes(&[1u8; 32]),
                context_ids: vec!["ctx-slow".to_owned()],
            },
        )
        .await;

    // Fast target — scoped to ctx-fast.
    let fast_url = format!(
        "https://{}:{}/hook",
        fast_server.host,
        fast_server.addr.port()
    );
    dispatcher
        .register(
            "fast-bridge".to_owned(),
            WebhookTarget {
                url: fast_url,
                signing_key: SigningKey::from_bytes(&[2u8; 32]),
                context_ids: vec!["ctx-fast".to_owned()],
            },
        )
        .await;

    let (tx, rx) = tokio::sync::broadcast::channel::<ContextEventEnvelope>(1024);
    let consumer = spawn_event_consumer(rx, Arc::clone(&dispatcher));

    // Enqueue the SLOW-context event first, then the FAST-context event.
    tx.send(ContextEventEnvelope::new(
        "ctx-slow".to_owned(),
        ContextEvent::MemberJoined {
            member_did: DID::from("did:key:slow"),
            role_name: "member".to_owned(),
        },
    ))
    .expect("send slow event");
    tx.send(ContextEventEnvelope::new(
        "ctx-fast".to_owned(),
        ContextEvent::MemberJoined {
            member_did: DID::from("did:key:fast"),
            role_name: "member".to_owned(),
        },
    ))
    .expect("send fast event");

    // The fast delivery must arrive well before the slow target would respond.
    // Allow generous headroom (1s) for TLS + scheduling while staying far under
    // the 3s slow delay — an inline-await consumer could not meet this bound.
    let start = std::time::Instant::now();
    let fast = tokio::time::timeout(Duration::from_millis(1500), fast_server.captured)
        .await
        .expect("fast target must be delivered without waiting on the slow target")
        .expect("fast capture channel should yield a request");
    let elapsed = start.elapsed();

    consumer.abort();

    assert!(
        elapsed < SLOW_DELAY,
        "fast delivery ({elapsed:?}) must complete before the slow target's {SLOW_DELAY:?} response"
    );

    // Sanity: the fast target received the fast-context event, not the slow one.
    let body = fast.body();
    let body_json: serde_json::Value =
        serde_json::from_slice(&body).expect("fast body must be valid JSON");
    assert_eq!(body_json["context_id"], "ctx-fast");
    assert_eq!(body_json["payload"]["member_did"], "did:key:fast");
}

/// A running local HTTPS server that reports two lifecycle signals separately:
/// when it has READ a full request (`received`), and — after a hold window — a
/// boolean on `client_still_connected` reporting whether the client's
/// connection is STILL OPEN at that point.
///
/// Connection liveness is detected by READING (not writing): a torn-down client
/// closes the TLS connection (TCP FIN / TLS close-notify), which the server
/// observes as `Ok(0)`/error on a read; a live client awaiting the response
/// keeps the connection open with nothing more to send, so the read pends and
/// times out. Reading is reliable here where writing is NOT — a single small
/// write to a peer that has just closed can still succeed into the local socket
/// buffer before any RST arrives, so write success is not proof the client is
/// alive.
///
/// This lets a test distinguish "the client's in-flight HTTP task was torn down
/// mid-flight" (`client_still_connected` reports `false`) from "the task ran on
/// as a detached task that outlived shutdown" (`client_still_connected` reports
/// `true`).
struct TwoPhaseServer {
    host: String,
    addr: SocketAddr,
    cert_pem: String,
    received: tokio::sync::oneshot::Receiver<()>,
    client_still_connected: tokio::sync::oneshot::Receiver<bool>,
}

/// Starts a [`TwoPhaseServer`]. After reading a full request it fires `received`,
/// sleeps `response_delay`, then probes the connection with a short-timeout read
/// and reports liveness on `client_still_connected` (`true` = read pended →
/// connection still open; `false` = read saw EOF/error → connection torn down).
async fn start_two_phase_server(response_delay: Duration) -> TwoPhaseServer {
    let host = format!(
        "webhook-{}.scp-test.invalid",
        SERVER_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
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

    let (received_tx, received_rx) = tokio::sync::oneshot::channel::<()>();
    let (liveness_tx, liveness_rx) = tokio::sync::oneshot::channel::<bool>();
    let received_tx = Arc::new(tokio::sync::Mutex::new(Some(received_tx)));
    let liveness_tx = Arc::new(tokio::sync::Mutex::new(Some(liveness_tx)));

    tokio::spawn(async move {
        loop {
            let Ok((stream, _peer)) = listener.accept().await else {
                continue;
            };
            let acceptor = acceptor.clone();
            let received_tx = Arc::clone(&received_tx);
            let liveness_tx = Arc::clone(&liveness_tx);
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                let mut raw = Vec::new();
                let mut buf = [0u8; 2048];
                loop {
                    match tls.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            raw.extend_from_slice(&buf[..n]);
                            if has_complete_request(&raw) {
                                break;
                            }
                        }
                    }
                }
                // Signal that the request was fully read.
                let sender = received_tx.lock().await.take();
                if let Some(tx) = sender {
                    let _ = tx.send(());
                }
                // Hold the connection open for the delay window. The test aborts
                // the consumer during this window; if the client's leaf HTTP task
                // is torn down (not detached), the client closes its end here.
                tokio::time::sleep(response_delay).await;
                // Probe liveness by READING, not writing. A live client awaiting
                // our (still-unsent) response has nothing more to send, so this
                // read pends and times out → still connected. A torn-down client
                // closed the connection, so the read returns EOF/error promptly →
                // not connected. (Writing would be unreliable: a small write can
                // succeed into the local buffer even after the peer closed.)
                let still_connected = match tokio::time::timeout(
                    Duration::from_millis(500),
                    tls.read(&mut buf),
                )
                .await
                {
                    // Read pended past the probe window: peer is still there.
                    Err(_elapsed) => true,
                    // EOF or read error: peer closed the connection.
                    Ok(Ok(0) | Err(_)) => false,
                    // Unexpected extra bytes on an idle connection: treat as
                    // still connected (the peer is clearly alive and sending).
                    Ok(Ok(_)) => true,
                };
                let sender = liveness_tx.lock().await.take();
                if let Some(tx) = sender {
                    let _ = tx.send(still_connected);
                }
                let _ = tls.shutdown().await;
            });
        }
    });

    TwoPhaseServer {
        host,
        addr,
        cert_pem,
        received: received_rx,
        client_still_connected: liveness_rx,
    }
}

/// Inner-fan-out teardown guard: aborting the consumer (instance shutdown) must
/// tear down the IN-FLIGHT per-target HTTP task, not detach it to outlive
/// shutdown.
///
/// `WebhookDispatcher::dispatch_event` owns its per-target fan-out in a
/// locally-scoped `JoinSet`. When the consumer task is aborted at its `.await`,
/// the outer dispatch future is dropped, which drops that inner `JoinSet`, which
/// aborts the per-target HTTP task. With the previous bare-`tokio::spawn`
/// fan-out, the inner task was DETACHED and would run the full retry ladder
/// after shutdown, holding a `reqwest` client and socket on the process-global
/// runtime.
///
/// The server reads the request, holds for `HOLD`, then probes connection
/// liveness via a read. The test waits for `received`, aborts the consumer, and
/// asserts the server observes the client connection as CLOSED. If the inner
/// task were detached (bare `tokio::spawn`), it would keep the connection open
/// across shutdown and the probe would report it still connected.
#[tokio::test]
async fn consumer_abort_tears_down_in_flight_inner_dispatch() {
    // Long enough that the consumer is reliably aborted (and the abort has
    // propagated, closing the client connection) before the server probes
    // liveness, but bounded so the test stays fast.
    const HOLD: Duration = Duration::from_secs(2);

    let server = start_two_phase_server(HOLD).await;
    let client = trusting_client(&server.cert_pem, &server.host, server.addr);
    let dispatcher = Arc::new(WebhookDispatcher::with_client_for_test(client));

    let webhook_url = format!("https://{}:{}/hook", server.host, server.addr.port());
    let registered = dispatcher
        .register(
            "held-bridge".to_owned(),
            WebhookTarget {
                url: webhook_url,
                signing_key: SigningKey::from_bytes(&[5u8; 32]),
                context_ids: vec!["ctx-held".to_owned()],
            },
        )
        .await;
    assert!(registered, "target registration should succeed");

    let (tx, rx) = tokio::sync::broadcast::channel::<ContextEventEnvelope>(1024);
    let consumer = spawn_event_consumer(rx, Arc::clone(&dispatcher));

    tx.send(ContextEventEnvelope::new(
        "ctx-held".to_owned(),
        ContextEvent::MemberJoined {
            member_did: DID::from("did:key:held"),
            role_name: "member".to_owned(),
        },
    ))
    .expect("send held event");

    // Wait until the server has read the request and is holding the connection
    // open — at this point the client's per-target HTTP task is in-flight,
    // awaiting the (delayed) response.
    tokio::time::timeout(Duration::from_secs(10), server.received)
        .await
        .expect("server should read the request before the hold window elapses")
        .expect("received signal channel should yield");

    // Simulate instance shutdown: abort the consumer task. This drops the outer
    // dispatch future and, with it, the inner per-target `JoinSet` — aborting
    // the in-flight HTTP task and closing the connection.
    consumer.abort();

    // After the hold the server probes connection liveness. The abort must have
    // torn down the in-flight per-target HTTP task, closing the client end — so
    // the server must observe the connection as CLOSED. A detached inner task
    // (the old bare-`tokio::spawn` behavior) would have held the connection open
    // across shutdown, and the probe would report `true`.
    let still_connected =
        tokio::time::timeout(HOLD + Duration::from_secs(5), server.client_still_connected)
            .await
            .expect("server should report connection liveness before the timeout")
            .expect("liveness signal channel should yield");
    assert!(
        !still_connected,
        "aborting the consumer must tear down the in-flight per-target HTTP task; \
         the client connection must be closed after shutdown (a detached inner \
         task would have kept it open)"
    );
}
