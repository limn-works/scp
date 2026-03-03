# Implementing a Custom TransportAdapter

This guide walks through implementing a custom SCP transport adapter. It covers the `TransportAdapter` trait contract, a concrete MQTT implementation example, conformance testing, and registration with `TransportManager`.

**Prerequisites:** Familiarity with SCP's envelope model (`OuterEnvelope`, `RoutingId`, `BlobId`), async Rust (tokio, futures), and the transport you are targeting.

---

## 1. TransportAdapter Trait Contract

The trait lives in `scp-transport::traits` and defines five async methods. All return boxed futures for dyn-compatibility. The trait requires `Send + Sync`.

```rust
pub trait TransportAdapter: Send + Sync {
    fn send(&self, envelope: &OuterEnvelope) -> BoxFuture<'_, Result<BlobId, TransportError>>;

    fn subscribe(
        &self,
        routing_id: &RoutingId,
        since: Option<u64>,
    ) -> BoxFuture<'_, Result<SubscriptionStream, TransportError>>;

    fn unsubscribe(&self, routing_id: &RoutingId) -> BoxFuture<'_, Result<(), TransportError>>;

    fn query(
        &self,
        routing_id: &RoutingId,
        since: Option<u64>,
    ) -> BoxFuture<'_, Result<Vec<OuterEnvelope>, TransportError>>;

    fn delete(&self, blob_id: &BlobId) -> BoxFuture<'_, Result<(), TransportError>>;
}
```

### Method semantics

| Method | Purpose | Returns | Key invariants |
|--------|---------|---------|----------------|
| `send` | Deliver an `OuterEnvelope` to the network, routed by its `routing_id` field. | `BlobId` -- the SHA-256 hash of the serialized envelope bytes. | The returned `BlobId` must equal `BlobId::from_sha256(&wire_bytes)`. |
| `subscribe` | Open a live stream for a `RoutingId`. If `since` is provided (epoch seconds), backfill stored envelopes newer than that timestamp before switching to live delivery. | `SubscriptionStream` yielding `TransportEvent` variants. | Must emit `BackfillComplete` after the backfill phase when `since` is set. Must emit `Reconnected` after any reconnection (callers deduplicate via `BlobId`). |
| `unsubscribe` | Stop delivery for a `RoutingId`. | `()` | In-flight events may still arrive before the stream terminates. No new events after the stream ends. |
| `query` | One-shot fetch of stored envelopes matching a `RoutingId`, optionally filtered by `since`. | `Vec<OuterEnvelope>` | Does not create a live subscription. Returns an empty vec if nothing matches. |
| `delete` | Request deletion of a blob by its `BlobId`. | `()` | Best-effort. Untrusted transports may ignore this. Callers must not assume the blob is actually gone. |

### TransportEvent variants

Your subscription stream must yield these correctly:

- `Envelope(OuterEnvelope)` -- a received envelope.
- `Error(TransportError)` -- transient transport error; the stream may continue (adapter handles reconnection internally).
- `BackfillComplete` -- all stored envelopes newer than `since` have been delivered. Only emitted when `since` was provided.
- `Reconnected` -- transport reconnected; duplicates may follow.
- `Terminated { reason }` -- subscription permanently ended (relay shutdown, auth revoked, etc.).
- `SuppressionDetected(SuppressionWarning)` -- fewer than half the expected relays delivered a blob within the cross-check window.

### Error mapping

Map transport-specific errors to `TransportError` variants:

- `NotConnected` -- no active connection to the remote endpoint.
- `ConnectionFailed(String)` -- connection attempt failed.
- `SendFailed(String)` -- envelope delivery failed after connection was established.
- `SubscriptionFailed(String)` -- subscription request rejected.
- `Timeout` -- operation timed out.
- `ProtocolError(String)` -- unexpected message format, version mismatch, etc.
- `BlobIntegrityError { expected, actual }` -- received blob does not match its declared hash.

---

## 2. Step-by-Step Implementation: MQTT Adapter

MQTT v5.0 has the cleanest mapping to the `TransportAdapter` contract among Tier 2 adapters. The spec mapping brief (section 10.5.2) defines:

| TransportAdapter method | MQTT operation |
|-------------------------|----------------|
| `send` | `PUBLISH` to topic `scp/{hex(routing_id)}`, QoS 1 |
| `subscribe` | `SUBSCRIBE` to topic `scp/{hex(routing_id)}` |
| `unsubscribe` | `UNSUBSCRIBE` from topic |
| `query` | MQTT 5.0 Request/Response with correlation data, or retained messages |
| `delete` | Publish empty retained message (limited -- clears retained only) |

### Crate setup

```toml
# Cargo.toml for scp-transport-mqtt
[package]
name = "scp-transport-mqtt"
version = "0.1.0"
edition = "2021"

[dependencies]
scp-core = { path = "../scp-core" }
scp-transport = { path = "../scp-transport" }
rumqttc = { version = "0.24", features = ["v5"] }  # MQTT v5 client
tokio = { workspace = true }
futures = { workspace = true }
hex = "0.4"
tracing = { workspace = true }

[dev-dependencies]
scp-testing = { path = "../scp-testing" }
```

### Struct definition

```rust
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;

use futures::Stream;
use rumqttc::v5::{AsyncClient, EventLoop, MqttOptions};
use scp_core::envelope::OuterEnvelope;
use scp_transport::{
    BlobId, RoutingId, SubscriptionStream, TransportAdapter, TransportError, TransportEvent,
};
use tokio::sync::{Mutex, broadcast};

type BoxFuture<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

pub struct MqttTransportAdapter {
    client: AsyncClient,
    /// Active subscription streams keyed by routing_id hex.
    subscriptions: Arc<Mutex<HashMap<String, broadcast::Sender<TransportEvent>>>>,
}
```

### Construction

```rust
impl MqttTransportAdapter {
    pub async fn connect(broker_url: &str, client_id: &str) -> Result<Self, TransportError> {
        let mut opts = MqttOptions::new(client_id, broker_url, 1883);
        opts.set_clean_start(false); // Persistent session for offline queuing

        let (client, mut event_loop) = AsyncClient::new(opts, 256);

        let subscriptions: Arc<Mutex<HashMap<String, broadcast::Sender<TransportEvent>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Spawn the event loop handler
        let subs = Arc::clone(&subscriptions);
        tokio::spawn(async move {
            loop {
                match event_loop.poll().await {
                    Ok(notification) => {
                        Self::handle_notification(notification, &subs).await;
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "MQTT event loop error");
                        // Reconnection is handled internally by rumqttc
                    }
                }
            }
        });

        Ok(Self {
            client,
            subscriptions,
        })
    }
}
```

### Method implementations

#### `send`

```rust
fn send(&self, envelope: &OuterEnvelope) -> BoxFuture<'_, Result<BlobId, TransportError>> {
    Box::pin(async move {
        let wire_bytes = scp_core::envelope::serialize(envelope)
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        let blob_id = BlobId::from_sha256(&wire_bytes);

        let topic = format!("scp/{}", hex::encode(&envelope.routing_id));

        self.client
            .publish(&topic, rumqttc::v5::mqttbytes::QoS::AtLeastOnce, false, wire_bytes)
            .await
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;

        Ok(blob_id)
    })
}
```

The `BlobId` is the SHA-256 hash of the serialized envelope bytes -- this is the canonical derivation used across all adapters.

#### `subscribe`

```rust
fn subscribe(
    &self,
    routing_id: &RoutingId,
    since: Option<u64>,
) -> BoxFuture<'_, Result<SubscriptionStream, TransportError>> {
    let routing_id = *routing_id;
    Box::pin(async move {
        let topic = format!("scp/{}", hex::encode(routing_id.as_bytes()));
        let topic_hex = hex::encode(routing_id.as_bytes());

        // Subscribe at MQTT level
        self.client
            .subscribe(&topic, rumqttc::v5::mqttbytes::QoS::AtLeastOnce)
            .await
            .map_err(|e| TransportError::SubscriptionFailed(e.to_string()))?;

        // Create a broadcast channel for this subscription
        let (tx, rx) = broadcast::channel(256);
        self.subscriptions.lock().await.insert(topic_hex, tx);

        // If `since` is provided, handle backfill.
        // MQTT retained messages only store the last message per topic,
        // so full backfill requires a broker-side plugin or external store.
        // Emit BackfillComplete after any available retained messages arrive.
        if since.is_some() {
            // Backfill is limited in MQTT -- see constraints below.
            // The BackfillComplete event is emitted by the event loop handler
            // after retained messages are delivered.
        }

        let stream = BroadcastStream::new(rx);
        Ok(Box::pin(stream) as SubscriptionStream)
    })
}
```

#### `unsubscribe`

```rust
fn unsubscribe(&self, routing_id: &RoutingId) -> BoxFuture<'_, Result<(), TransportError>> {
    let routing_id = *routing_id;
    Box::pin(async move {
        let topic = format!("scp/{}", hex::encode(routing_id.as_bytes()));
        let topic_hex = hex::encode(routing_id.as_bytes());

        self.client
            .unsubscribe(&topic)
            .await
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;

        self.subscriptions.lock().await.remove(&topic_hex);
        Ok(())
    })
}
```

#### `query`

```rust
fn query(
    &self,
    routing_id: &RoutingId,
    since: Option<u64>,
) -> BoxFuture<'_, Result<Vec<OuterEnvelope>, TransportError>> {
    let routing_id = *routing_id;
    Box::pin(async move {
        // MQTT 5.0 Request/Response pattern:
        // Publish a query request with a Response Topic and Correlation Data,
        // then await the response on the response topic.
        //
        // If the broker doesn't support this (or no query-service plugin is
        // running), fall back to returning the retained message only.
        //
        // Full backfill requires broker-side storage or an external query
        // service. This is a known MQTT constraint (see spec section 10.5.2).
        let _topic = format!("scp/{}", hex::encode(routing_id.as_bytes()));

        // Placeholder: implement broker-specific query mechanism
        Ok(Vec::new())
    })
}
```

#### `delete`

```rust
fn delete(&self, blob_id: &BlobId) -> BoxFuture<'_, Result<(), TransportError>> {
    let _blob_id = *blob_id;
    Box::pin(async move {
        // MQTT delete is limited: publishing an empty retained message clears
        // the retained value for that topic, but does not affect messages
        // already queued for delivery.
        //
        // Since we route by routing_id (not blob_id), and MQTT topics are
        // per-routing_id, we cannot selectively delete a single blob.
        // This is best-effort by design (spec section 10.5.2).
        //
        // If the broker supports message expiry (MQTT 5.0 Message Expiry
        // Interval), TTL-based cleanup handles the common case.
        Ok(())
    })
}
```

### MQTT-specific constraints

These are documented in the spec (section 10.5.2) and worth internalizing:

- **No full backfill.** MQTT retained messages store only the last message per topic. `subscribe` with `since` cannot replay history without a broker-side plugin or external storage. If your adapter needs full backfill, pair MQTT with a storage backend and implement `query` against it.
- **Binary payloads natively supported.** No base64 encoding needed (unlike Nostr or Matrix). Envelopes go on the wire as MessagePack bytes directly.
- **Persistent sessions.** `CleanStart=false` enables offline message queuing -- messages published while a client is disconnected are delivered on reconnect. This maps well to SCP's async delivery model.
- **QoS 1 (at-least-once).** Guarantees delivery but may produce duplicates. The `TransportManager`'s deduplication layer (LRU cache keyed by `BlobId`) handles this transparently.

---

## 3. Testing with `transport_conformance!()`

The `scp-testing` crate provides a conformance test macro that validates any `TransportAdapter` implementation against the trait contract. Passing means your adapter satisfies the same invariants as the reference `InMemoryTransport` implementation.

### Usage

```rust
// In your adapter crate's tests
#[cfg(test)]
mod tests {
    use super::*;
    use scp_testing::transport_conformance;

    transport_conformance!(|| MqttTransportAdapter::new_test_instance());
}
```

The constructor closure must return an instance of your adapter ready to send and receive. For transports that require external infrastructure (an MQTT broker, a Nostr relay, etc.), spin up a test instance in the constructor or use a test container.

### What it tests

The macro expands into a test module with these cases:

| Test | What it verifies |
|------|------------------|
| `send_subscribe_roundtrip` | Send an envelope, subscribe to its `routing_id`, verify the envelope is delivered. |
| `backfill_with_since` | Store 3 envelopes, subscribe with `since` = timestamp of the 2nd, verify only the 2nd and 3rd are backfilled. |
| `unsubscribe_stops_delivery` | Subscribe, unsubscribe, send another envelope, verify it is not delivered to the old stream. |
| `query_returns_stored` | Store envelopes, query by `routing_id`, verify results match. |
| `delete_removes_blob` | Store a blob, delete it, query again, verify it is gone. |

### What passing means

- Your adapter correctly routes envelopes by `routing_id`.
- Backfill with `since` filters stored envelopes by timestamp.
- Unsubscribe actually stops delivery.
- Query returns stored data without creating a live subscription.
- Delete removes blobs (best-effort is acceptable -- the test verifies the request completes without error).

### Adapters with limited capabilities

Some transports cannot support all five methods fully. For example, MQTT has no native full backfill, libp2p has no durable storage for `query`, and BLE has no `delete`. In these cases:

- Implement the method to the extent the transport supports it. Return an empty `Vec` from `query` if there is no storage backend. Return `Ok(())` from `delete` if deletion is not supported.
- Document the limitation in the adapter's module-level doc comment.
- The conformance suite tests the contract -- if your transport fundamentally cannot pass a test (e.g., no backfill), you may need to pair it with a storage backend or skip that test with a documented justification.

Tier 1 adapters (SCP native relay, QUIC, WebTransport, UDP/DTLS) must pass the full conformance suite. Tier 2 adapters should pass as many tests as the transport's native capabilities allow.

---

## 4. Registration with TransportManager

Once your adapter implements the trait, register it with `TransportManager` so the SDK routes through it.

### Single adapter (Phase 1)

```rust
use scp_transport::TransportManager;

let adapter = MqttTransportAdapter::connect("broker.example.com", "scp-client-1")
    .await?;

let manager = TransportManager::new(Box::new(adapter));
```

### Multiple adapters (Phase 2)

```rust
use scp_transport::{TransportConfig, TransportManager};
use scp_transport::relay::connection::{RelayUrlSource, SourcedRelayUrl};

let config = TransportConfig::default();
let mut manager = TransportManager::with_config(&config);

// Register the native relay adapter (connect_sourced validates ws:// vs wss:// per §10.12.6)
let native = NativeRelayAdapter::connect_sourced(&SourcedRelayUrl {
    url: "wss://relay.example.com/scp/v1".to_owned(),
    source: RelayUrlSource::Explicit,
}).await?;
manager.add_adapter(Box::new(native));

// Register an MQTT adapter for IoT devices
let mqtt = MqttTransportAdapter::connect("broker.example.com", "scp-client-1").await?;
manager.add_adapter(Box::new(mqtt));

// Register a Nostr adapter for decentralized relay infrastructure
let nostr = NostrTransportAdapter::connect("wss://nostr-relay.example.com").await?;
manager.add_adapter(Box::new(nostr));
```

When multiple adapters are registered, `TransportManager` distributes contexts across them:

- `assign_relay_set` assigns at least 3 adapters per context for suppression resistance (spec section 9.9.2).
- `send_to_context` publishes envelopes to all adapters in a context's relay set concurrently. At least 2 must succeed.
- `subscribe_context` merges streams from all adapters in the relay set, deduplicating by `BlobId` via an LRU cache.
- Per-adapter reliability scoring tracks delivery success rates. Adapters with poor reliability are deprioritized in relay set assignment.

The `TransportManager::builder()` constructor creates a manager with no adapters -- use `add_adapter` to register them before performing any operations.

---

## 5. Reference: Tier 2 Adapter Mapping Briefs

The spec (section 10.5.2) documents method mappings for all 12 Tier 2 adapters. Each brief covers how the five `TransportAdapter` methods map to the adapter's native primitives, the connection model, and key constraints.

### Adapter tier system (section 10.5.1)

| Tier | Spec depth | Requirement |
|------|------------|-------------|
| **Tier 1** (SCP native relay, QUIC, WebTransport, UDP/DTLS) | Full wire format mapping, conformance suite, fallback behavior | Must pass `transport_conformance!()`. |
| **Tier 2** (Nostr, Matrix, libp2p, Hyperswarm, WebRTC, MQTT, NATS, Tor, I2P, BLE, Yggdrasil/cjdns, ZeroMQ) | Method mapping documented per adapter | Must document how each of the 5 methods maps to native primitives. |
| **Tier 3** (SSB) | Feasibility confirmed | Spec pending. |

### Quick reference for select Tier 2 adapters

**Nostr:** Routes via Nostr events (kind=30078). `subscribe` maps to `REQ` with filter. `query` uses `REQ` with `since` filter, collects until `EOSE`. JSON format adds ~33% overhead from base64 blob encoding.

**NATS:** Near-identical to SCP's semantics. `send` maps to `PUB`, `subscribe` to `SUB`. JetStream required for `query` (persistent storage) and `delete`. Sub-millisecond latency locally.

**libp2p:** GossipSub pub/sub. No durable storage -- `query` requires a custom protocol or external storage. Best for real-time P2P between online peers.

**Tor/I2P:** Delegation adapters. All 5 methods delegate to an underlying adapter (WebSocket or QUIC) routed through the anonymity network. No adapter-specific logic beyond connection setup.

For the full mapping briefs, see `.docs/specs/10-infrastructure-and-self-hosting.md` section 10.5.2.
