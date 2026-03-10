#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Integration tests for SCP native relay transport layer.
//!
//! Tests cover relay server lifecycle, in-memory blob storage, native relay
//! adapter connectivity, and send/subscribe/query/delete round-trips.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use futures::StreamExt;
use scp_core::envelope::{self, OuterEnvelope};
use scp_transport::native::NativeRelayAdapter;
use scp_transport::native::server::{RelayConfig, RelayServer, ShutdownHandle};
use scp_transport::native::storage::{BlobStorage, BlobStorageBackend, InMemoryBlobStorage};
use scp_transport::relay::connection::{RelayUrlSource, SourcedRelayUrl};
use scp_transport::traits::{BlobId, RoutingId, TransportAdapter, TransportEvent};

/// Helper: create an `OuterEnvelope` with a given `routing_id` and payload.
fn make_envelope(routing_id: &[u8; 32], payload: &[u8]) -> OuterEnvelope {
    envelope::create_outer_envelope(routing_id, None, 3600, payload.to_vec()).unwrap()
}

/// Helper: start a relay server on an ephemeral port (port 0) with in-memory
/// storage, returning the shutdown handle and the bound address.
async fn start_ephemeral_relay() -> (ShutdownHandle, std::net::SocketAddr) {
    let config = RelayConfig {
        bind_addr: ([127, 0, 0, 1], 0).into(),
        delivery_jitter_ms: 0, // Disable jitter for deterministic tests.
        ..RelayConfig::default()
    };
    let storage = Arc::new(BlobStorageBackend::in_memory());
    let server = RelayServer::new(config, storage);
    server.start().await.unwrap()
}

/// Helper: connect a `NativeRelayAdapter` to a local relay at the given address.
async fn connect_adapter(addr: std::net::SocketAddr) -> NativeRelayAdapter {
    let sourced = SourcedRelayUrl {
        url: format!("ws://127.0.0.1:{}/scp/v1", addr.port()),
        source: RelayUrlSource::DhtResolved,
    };
    NativeRelayAdapter::connect_sourced(&sourced).await.unwrap()
}

// -----------------------------------------------------------------------
// Test 1: relay_server_start
// -----------------------------------------------------------------------

#[tokio::test]
async fn relay_server_start() {
    let (shutdown, addr) = start_ephemeral_relay().await;

    // Verify we got a non-zero port (ephemeral port was assigned).
    assert_ne!(addr.port(), 0);
    assert_eq!(addr.ip(), std::net::IpAddr::from([127, 0, 0, 1]));

    shutdown.shutdown();
}

// -----------------------------------------------------------------------
// Test 2: relay_adapter_connect
// -----------------------------------------------------------------------

#[tokio::test]
async fn relay_adapter_connect() {
    let (shutdown, addr) = start_ephemeral_relay().await;

    let _adapter = connect_adapter(addr).await;
    // If we get here without error, the connection succeeded.

    shutdown.shutdown();
}

// -----------------------------------------------------------------------
// Test 3: send_subscribe_roundtrip
// -----------------------------------------------------------------------

#[tokio::test]
async fn send_subscribe_roundtrip() {
    let (shutdown, addr) = start_ephemeral_relay().await;

    let adapter = connect_adapter(addr).await;

    let routing_id_bytes = [0xAA; 32];
    let routing_id = RoutingId::new(routing_id_bytes);

    // Subscribe before sending so we receive delivery.
    let mut stream = adapter.subscribe(&routing_id, None).await.unwrap();

    let env = make_envelope(&routing_id_bytes, &[1, 2, 3, 4]);
    let _blob_id = adapter.send(&env).await.unwrap();

    // Receive the envelope from the subscription stream.
    let event = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
        .await
        .expect("timed out waiting for subscription event")
        .expect("stream ended unexpectedly");

    match event {
        TransportEvent::Envelope(received) => {
            assert_eq!(received.routing_id, env.routing_id);
        }
        other => panic!("expected Envelope event, got {other:?}"),
    }

    shutdown.shutdown();
}

// -----------------------------------------------------------------------
// Test 4: query_returns_stored
// -----------------------------------------------------------------------

#[tokio::test]
async fn query_returns_stored() {
    let (shutdown, addr) = start_ephemeral_relay().await;

    let adapter = connect_adapter(addr).await;

    let routing_id_bytes = [0xBB; 32];
    let routing_id = RoutingId::new(routing_id_bytes);

    let env = make_envelope(&routing_id_bytes, &[10, 20, 30]);
    let _blob_id = adapter.send(&env).await.unwrap();

    // Allow a brief moment for the relay to store the blob.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let results = adapter.query(&routing_id, None).await.unwrap();
    assert!(!results.is_empty(), "query should return at least one blob");
    assert_eq!(results[0].routing_id, env.routing_id);

    shutdown.shutdown();
}

// -----------------------------------------------------------------------
// Test 5: delete_removes_blob
// -----------------------------------------------------------------------

#[tokio::test]
async fn delete_removes_blob() {
    let (shutdown, addr) = start_ephemeral_relay().await;

    let adapter = connect_adapter(addr).await;

    let routing_id_bytes = [0xCC; 32];
    let routing_id = RoutingId::new(routing_id_bytes);

    let env = make_envelope(&routing_id_bytes, &[5, 6, 7]);
    let blob_id = adapter.send(&env).await.unwrap();

    // Allow a brief moment for the relay to store the blob.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Delete the blob.
    adapter.delete(&blob_id).await.unwrap();

    // Allow time for deletion to take effect.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Query should return empty after deletion.
    let results = adapter.query(&routing_id, None).await.unwrap();
    assert!(results.is_empty(), "query should return empty after delete");

    shutdown.shutdown();
}

// -----------------------------------------------------------------------
// Test 6: relay_config_defaults
// -----------------------------------------------------------------------

#[tokio::test]
async fn relay_config_defaults() {
    let config = RelayConfig::default();

    // Verify defaults match ADR-004 spec values.
    assert_eq!(config.bind_addr, ([127, 0, 0, 1], 9000).into());
    assert_eq!(config.max_blob_size, 262_144); // 256 KB
    assert_eq!(config.max_blob_ttl, 604_800); // 7 days
    assert_eq!(config.max_subscriptions_per_connection, 100);
    assert_eq!(config.max_query_limit, 1000);
    assert_eq!(
        config.ttl_check_interval,
        std::time::Duration::from_secs(10)
    );
    assert_eq!(config.max_connections_per_ip, 10);
    assert_eq!(config.max_total_connections, 1000);
    assert_eq!(config.rate_limit_publishes_per_second, 100);
    assert_eq!(config.rate_limit_subscribes_per_minute, 20);
    assert_eq!(config.delivery_jitter_ms, 50);
    assert!(config.bridge_secret.is_none());
    assert!(!config.supports_bridge);
}

// -----------------------------------------------------------------------
// Test 7: blob_storage_roundtrip
// -----------------------------------------------------------------------

#[tokio::test]
async fn blob_storage_roundtrip() {
    let storage = InMemoryBlobStorage::new();

    let routing_id = [0xDD; 32];
    let blob_data = vec![10, 20, 30, 40, 50];
    let blob_id = BlobId::from_sha256(&blob_data);

    // Store
    let stored = storage
        .store(
            routing_id,
            *blob_id.as_bytes(),
            None,
            3600,
            blob_data.clone(),
        )
        .await
        .unwrap();

    assert_eq!(stored.routing_id, routing_id);
    assert_eq!(stored.blob_id, *blob_id.as_bytes());
    assert_eq!(stored.blob, blob_data);
    assert_eq!(stored.blob_ttl, 3600);

    // Get
    let retrieved = storage.get(blob_id.as_bytes()).await.unwrap().unwrap();
    assert_eq!(retrieved.blob, blob_data);

    // Query
    let results = storage.query(&routing_id, None, 100).await.unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].blob, blob_data);

    // Delete
    let deleted = storage.delete(blob_id.as_bytes()).await.unwrap();
    assert!(deleted);

    // Verify gone
    let gone = storage.get(blob_id.as_bytes()).await.unwrap();
    assert!(gone.is_none());

    let empty = storage.query(&routing_id, None, 100).await.unwrap();
    assert!(empty.is_empty());
}

// -----------------------------------------------------------------------
// Test 8: blob_expiry
// -----------------------------------------------------------------------

#[tokio::test]
async fn blob_expiry() {
    let clock_value = Arc::new(AtomicU64::new(1_000_000));
    let cv = clock_value.clone();
    let clock: scp_transport::native::storage::ClockFn =
        Arc::new(move || cv.load(Ordering::Relaxed));
    let storage = InMemoryBlobStorage::with_clock(clock);

    let routing_id = [0xEE; 32];
    let blob_data = vec![1, 2, 3];
    let blob_id = BlobId::from_sha256(&blob_data);

    // Store with TTL of 10 seconds.
    storage
        .store(routing_id, *blob_id.as_bytes(), None, 10, blob_data)
        .await
        .unwrap();

    // Verify blob exists before expiry.
    let exists = storage.get(blob_id.as_bytes()).await.unwrap();
    assert!(exists.is_some());

    // Advance clock past expiry.
    clock_value.store(1_000_011, Ordering::Relaxed);

    // purge_expired should remove it.
    let purged = storage.purge_expired().await.unwrap();
    assert_eq!(purged, 1);

    // Verify gone.
    let gone = storage.get(blob_id.as_bytes()).await.unwrap();
    assert!(gone.is_none());
}

// -----------------------------------------------------------------------
// Test 9: shutdown_handle
// -----------------------------------------------------------------------

#[tokio::test]
async fn shutdown_handle() {
    let (shutdown, _addr) = start_ephemeral_relay().await;

    // Initially not shut down.
    assert!(!shutdown.is_shutdown());

    // Shutdown.
    shutdown.shutdown();

    // After shutdown signaled.
    assert!(shutdown.is_shutdown());
}
