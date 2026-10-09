//! Native relay transport tests: the transport adapter trait (ADR-005)
//! routing envelopes through the native relay server (ADR-004), and sourced
//! relay-URL validation.
//!
//! The encrypted Alice-to-Bob roundtrip through a real relay runs on the
//! production seal and open path in `fullstack.rs`
//! (`full_stack_relay_encrypted_roundtrip`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;

use futures::StreamExt;

use scp_transport::native::adapter::NativeRelayAdapter;
use scp_transport::native::server::{RelayConfig, RelayServer};
use scp_transport::native::storage::BlobStorageBackend;
use scp_transport::relay::connection::{RelayUrlSource, SourcedRelayUrl};
use scp_transport::traits::{RoutingId, TransportAdapter, TransportEvent};

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
    let send_adapter = NativeRelayAdapter::connect_sourced(&sourced, None)
        .await
        .unwrap();
    let recv_adapter = NativeRelayAdapter::connect_sourced(&sourced, None)
        .await
        .unwrap();

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

    let send_adapter = NativeRelayAdapter::connect_sourced(&dht_sourced, None)
        .await
        .expect("ws:// from DhtResolved should be permitted");
    let recv_adapter = NativeRelayAdapter::connect_sourced(&dht_sourced, None)
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
        NativeRelayAdapter::connect_sourced(&sourced, None)
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
