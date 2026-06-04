//! QUIC connection-migration survival.
//!
//! Exercises QUIC's connection-migration property (RFC 9000 §9, spec §10.14):
//! when the client's local UDP address changes, the connection survives because
//! the QUIC connection ID decouples the connection from the UDP 4-tuple. A
//! WebSocket (TCP) connection would be severed by the same event.
//!
//! ## What this test actually verifies (honest scope)
//!
//! - A live subscription stream and the bidirectional request/response streams
//!   (`send`) keep working after the **client** endpoint swaps its local UDP
//!   socket via [`quinn::Endpoint::rebind`].
//! - `rebind` genuinely changes the client's local socket address: the
//!   post-rebind `local_addr()` differs from the pre-rebind one, so the
//!   server observes packets arriving from a new source `ip:port` (the migration
//!   trigger), and the in-flight `quinn::Connection` is migrated onto it.
//!
//! ## What this test does NOT claim
//!
//! - It does not exercise a realistic multi-hop network path, NAT translation,
//!   or an adversarial path-validation/amplification scenario. Both endpoints
//!   are on loopback; only the client's *local* address changes. quinn still
//!   runs RFC 9000 §9.3 path validation (a `PATH_CHALLENGE`/`PATH_RESPONSE`
//!   round-trip) against the new client address before fully migrating, so the
//!   survival demonstrated here is the connection-ID-based migration mechanism,
//!   not the network conditions that trigger it in production.
//! - It does not assert anything about the server-side (relay) endpoint
//!   rebinding; only the client migrates.

#![cfg(feature = "quic")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use futures::StreamExt;
use scp_core::envelope::outer::create_outer_envelope;
use scp_transport::quic::test_support::{connect_adapter_with_endpoint, start_test_listener};
use scp_transport::traits::{BlobId, RoutingId, TransportAdapter, TransportEvent};

/// SHA-256 of the full MessagePack-serialized envelope — the blob identity a
/// relay assigns on PUBLISH and the one a delivered envelope must reproduce.
fn envelope_blob_id(env: &scp_core::envelope::OuterEnvelope) -> BlobId {
    let bytes = env
        .to_bytes()
        .expect("envelope re-serialization should succeed");
    BlobId::from_sha256(&bytes)
}

/// Drains up to `max_events` events from a subscription stream (2s per-event
/// timeout) looking for an `Envelope` whose blob identity equals `target`.
/// Returns `true` if found. Ignores non-Envelope events (e.g. `Reconnected`
/// emitted around a migration) rather than treating them as failures.
async fn await_envelope(
    stream: &mut (impl StreamExt<Item = TransportEvent> + Unpin),
    target: BlobId,
    max_events: usize,
) -> bool {
    for _ in 0..max_events {
        match tokio::time::timeout(Duration::from_secs(2), stream.next()).await {
            Ok(Some(TransportEvent::Envelope(env))) => {
                if envelope_blob_id(&env) == target {
                    return true;
                }
            }
            // Migration may surface transient transport events; keep draining.
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => return false,
        }
    }
    false
}

/// A live subscription survives the client migrating to a new local UDP socket.
///
/// 1. Establish a QUIC connection and a live (`since = None`) subscription.
/// 2. Publish envelope #1, confirm it arrives on the subscription (baseline:
///    the live path works before migration).
/// 3. `rebind` the client endpoint onto a fresh loopback UDP socket and assert
///    the local address actually changed.
/// 4. Publish envelope #2 over the *same* connection (now driven by the new
///    socket) and confirm it still arrives on the *same* subscription stream —
///    proving the connection and its streams survived the address change.
#[tokio::test]
async fn subscription_survives_client_socket_rebind() {
    let (handle, addr, certs, _storage, _subs) = start_test_listener();

    let (adapter, endpoint) = connect_adapter_with_endpoint(addr, &certs).await;

    let routing_id = RoutingId::new([0x5A; 32]);

    // Live subscription (no backfill) — only blobs published *after* this point
    // are delivered, so each publish below is unambiguously a post-subscription
    // delivery over the live stream.
    let mut stream = adapter
        .subscribe(&routing_id, None)
        .await
        .expect("subscribe should succeed");

    // (2) Baseline: publish before migration and confirm live delivery.
    let env_before =
        create_outer_envelope(routing_id.as_bytes(), None, 3600, b"pre-migration".to_vec())
            .expect("envelope construction should succeed");
    let blob_before = adapter
        .send(&env_before)
        .await
        .expect("pre-migration send should succeed");
    assert!(
        await_envelope(&mut stream, blob_before, 10).await,
        "subscription should deliver the pre-migration envelope (baseline live delivery)"
    );

    // (3) Migrate the client: bind a brand-new UDP socket on loopback and swap
    // the endpoint onto it. This changes the client's source ip:port — the
    // exact event QUIC connection migration is designed to survive.
    let addr_before = endpoint
        .local_addr()
        .expect("endpoint should have a local addr");
    let new_socket = UdpSocket::bind(SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0)))
        .expect("rebind socket should bind");
    let new_socket_addr = new_socket
        .local_addr()
        .expect("new socket should have a local addr");
    endpoint.rebind(new_socket).expect("rebind should succeed");
    let addr_after = endpoint
        .local_addr()
        .expect("endpoint should have a local addr");

    assert_ne!(
        addr_before, addr_after,
        "rebind must change the client's local address (before={addr_before}, after={addr_after})"
    );
    assert_eq!(
        addr_after, new_socket_addr,
        "endpoint local address should now be the rebound socket's address"
    );

    // (4) Post-migration: publish over the SAME connection (now driven by the
    // new socket) and confirm the SAME subscription stream still delivers it.
    let env_after = create_outer_envelope(
        routing_id.as_bytes(),
        None,
        3600,
        b"post-migration".to_vec(),
    )
    .expect("envelope construction should succeed");
    let blob_after = adapter
        .send(&env_after)
        .await
        .expect("post-migration send should succeed over the migrated connection");
    assert!(
        await_envelope(&mut stream, blob_after, 10).await,
        "subscription stream should survive the client socket rebind and deliver the post-migration envelope"
    );

    handle.shutdown();
}
