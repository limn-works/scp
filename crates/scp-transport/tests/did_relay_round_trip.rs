//! ADR-062 Slice 11 — DID relay-resolution READ+WRITE round-trip tests
//! (§3.10.4/§3.10.5/§3.10.8, §9.10.12 Model A).
//!
//! Exercises the concrete relay path end to end:
//! `TransportRelayPublisher` (WRITE) → SCPR kind-1 frame → a raw-blob transport
//! adapter → `TransportRelayQuerier` (READ) → `RealMultiRelayQuerier` composer →
//! `DualLayerResolver`. Uses an in-memory raw-blob adapter (below) so the raw
//! public-record path (`publish_raw`/`query_raw`) is driven without a live relay.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::similar_names
)]

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signer, SigningKey};

use scp_core::envelope::OuterEnvelope;
use scp_core::envelope::scpr;
use scp_dht::{DhtClient, DisabledDhtClient, InMemoryDhtClient, bep44_signable};
use scp_did::DidDocument;
use scp_identity::republish::{RELAY_BLOB_TTL_SECS, RelayPublisher};
use scp_identity::resolver::{DidResolver, DualLayerResolver, ResolutionSource};
use scp_identity::{DidCache, RealMultiRelayQuerier, did_from_ed25519_public_key, did_routing_id};
use scp_transport::error::TransportError;
use scp_transport::traits::{BlobId, RoutingId, SubscriptionStream, TransportAdapter};
use scp_transport::{
    LiveTransport, TransportManager, TransportRelayPublisher, TransportRelayQuerier,
};

// ---------------------------------------------------------------------------
// In-memory raw-blob transport adapter (test double)
// ---------------------------------------------------------------------------

/// A transport adapter that stores only RAW public-record blobs, keyed by
/// routing ID. The `OuterEnvelope` message methods are inert — this double
/// exercises only the Model-A raw-blob path (`publish_raw`/`query_raw`).
#[derive(Default)]
struct InMemoryRawRelay {
    blobs: Mutex<HashMap<[u8; 32], Vec<Vec<u8>>>>,
}

type Fut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

impl TransportAdapter for InMemoryRawRelay {
    fn send(&self, _envelope: &OuterEnvelope) -> Fut<'_, Result<BlobId, TransportError>> {
        Box::pin(async { Err(TransportError::NotConnected) })
    }

    fn subscribe(
        &self,
        _routing_id: &RoutingId,
        _since: Option<u64>,
    ) -> Fut<'_, Result<SubscriptionStream, TransportError>> {
        Box::pin(async { Err(TransportError::NotConnected) })
    }

    fn unsubscribe(&self, _routing_id: &RoutingId) -> Fut<'_, Result<(), TransportError>> {
        Box::pin(async { Ok(()) })
    }

    fn query(
        &self,
        _routing_id: &RoutingId,
        _since: Option<u64>,
    ) -> Fut<'_, Result<Vec<OuterEnvelope>, TransportError>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn delete(&self, _blob_id: &BlobId) -> Fut<'_, Result<(), TransportError>> {
        Box::pin(async { Ok(()) })
    }

    fn publish_raw(
        &self,
        routing_id: &RoutingId,
        _blob_ttl: u64,
        blob: Vec<u8>,
    ) -> Fut<'_, Result<BlobId, TransportError>> {
        let rid = *routing_id.as_bytes();
        let id = BlobId::from_sha256(&blob);
        self.blobs
            .lock()
            .unwrap()
            .entry(rid)
            .or_default()
            .push(blob);
        Box::pin(async move { Ok(id) })
    }

    fn query_raw(&self, routing_id: &RoutingId) -> Fut<'_, Result<Vec<Vec<u8>>, TransportError>> {
        let rid = *routing_id.as_bytes();
        let blobs = self
            .blobs
            .lock()
            .unwrap()
            .get(&rid)
            .cloned()
            .unwrap_or_default();
        Box::pin(async move { Ok(blobs) })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Builds a live transport backed by a fresh in-memory raw-blob relay.
fn live_relay() -> LiveTransport {
    let manager = TransportManager::new(Box::new(InMemoryRawRelay::default()));
    let live = LiveTransport::new();
    *live.slot().write().unwrap() = Some(Arc::new(manager));
    live
}

/// A test identity: signing key, DID string, and the signed `(value, sig, seq)`.
struct TestId {
    did: String,
    public_key: [u8; 32],
    value: Vec<u8>,
    signature: [u8; 64],
    seq: u64,
}

fn make_identity(seed: u8, seq: u64) -> TestId {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let vk = sk.verifying_key();
    let did = did_from_ed25519_public_key(vk.as_bytes());
    let doc = DidDocument::new(&did, vk.as_bytes(), &[2u8; 32], &[3u8; 32]);
    let value = doc.to_json().unwrap().into_bytes();
    let signable = bep44_signable(&value, seq);
    let signature: [u8; 64] = sk.sign(&signable).to_bytes();
    TestId {
        did,
        public_key: *vk.as_bytes(),
        value,
        signature,
        seq,
    }
}

/// Publishes a DID record to the relay via the real `TransportRelayPublisher`
/// (SCPR-wrapping the triple, exactly as the FFI write path does).
async fn publish_to_relay(live: &LiveTransport, id: &TestId) {
    let publisher = TransportRelayPublisher::new(live.clone());
    let blob = scpr::encode_did_record(&id.value, &id.signature, id.seq);
    let routing_id = did_routing_id(&id.did);
    publisher
        .publish(&routing_id, RELAY_BLOB_TTL_SECS, &blob)
        .await
        .expect("relay publish succeeds against a connected transport");
}

fn relay_resolver<D: DhtClient + 'static>(
    live: &LiveTransport,
    dht: Arc<D>,
) -> DualLayerResolver<RealMultiRelayQuerier<TransportRelayQuerier>, D, Arc<scp_clock::SystemClock>>
{
    let querier = Arc::new(RealMultiRelayQuerier::new(Arc::new(
        TransportRelayQuerier::new(live.clone()),
    )));
    let cache = Arc::new(DidCache::with_clock(Arc::new(scp_clock::SystemClock)));
    DualLayerResolver::new(
        querier,
        dht,
        cache,
        vec!["mem://relay-1".to_owned(), "mem://relay-2".to_owned()],
    )
}

// ---------------------------------------------------------------------------
// AC10 — publish→resolve round-trip (relay-only) + suppression resilience
// ---------------------------------------------------------------------------

/// AC10: publish a DID document ONLY to a relay via the real `RelayPublisher`
/// and resolve it back via the real `MultiRelayQuerier` — proving the write and
/// read halves interoperate over the raw SCPR path, with the DHT layer disabled.
#[tokio::test]
async fn publish_then_resolve_relay_only_round_trip() {
    let live = live_relay();
    let id = make_identity(11, 1);

    publish_to_relay(&live, &id).await;

    // DHT disabled — resolution can only come from the relay.
    let resolver = relay_resolver(&live, Arc::new(DisabledDhtClient));
    let resolved = resolver
        .resolve(&id.did)
        .await
        .expect("resolve ok")
        .expect("relay-published DID resolves");

    assert_eq!(resolved.seq, 1);
    assert!(
        matches!(resolved.source, ResolutionSource::ScpRelay { .. }),
        "expected ScpRelay source, got {:?}",
        resolved.source
    );
    assert_eq!(resolved.document.id, id.did);
}

/// AC10: dual-layer suppression resilience (§3.10.8). Suppression on one layer
/// is defeated by the other: (a) relay empty, DHT populated → resolves via DHT;
/// (b) DHT disabled, relay populated → resolves via relay.
#[tokio::test]
async fn suppression_on_one_layer_defeated_by_other() {
    // (a) Relay suppressed (empty), DHT has the record.
    let live = live_relay();
    let id = make_identity(22, 1);
    let dht = Arc::new(InMemoryDhtClient::new());
    dht.publish(&id.public_key, &id.signature, &id.value, id.seq)
        .await
        .unwrap();

    let resolver = relay_resolver(&live, Arc::clone(&dht));
    let resolved = resolver.resolve(&id.did).await.unwrap().unwrap();
    assert_eq!(
        resolved.source,
        ResolutionSource::MainlineDht,
        "DHT defeats relay suppression"
    );

    // (b) DHT disabled (suppressed), relay has the record.
    let live2 = live_relay();
    let id2 = make_identity(33, 1);
    publish_to_relay(&live2, &id2).await;

    let resolver2 = relay_resolver(&live2, Arc::new(DisabledDhtClient));
    let resolved2 = resolver2.resolve(&id2.did).await.unwrap().unwrap();
    assert!(
        matches!(resolved2.source, ResolutionSource::ScpRelay { .. }),
        "relay defeats DHT suppression"
    );
}

// ---------------------------------------------------------------------------
// AC11 — A2 completion: DhtMode::Disabled node resolves self + peer via relay
// ---------------------------------------------------------------------------

/// AC11 (SCP-CAPINJECT-001 A2): a `DhtMode::Disabled` node (modeled by
/// `DisabledDhtClient`) publishes its OWN DID to the relay via the real
/// `RelayPublisher`, resolves its own DID back via the real
/// `MultiRelayQuerier`, AND resolves a PEER's DID published to the relay —
/// confirming self-DID + peer resolution come online with the write half.
#[tokio::test]
async fn disabled_node_resolves_self_and_peer_via_relay() {
    // A shared relay both the node and its peer publish to.
    let live = live_relay();

    let own = make_identity(44, 1);
    let peer = make_identity(55, 1);

    // The Disabled node publishes its OWN DID via the relay (write half), and a
    // peer's DID is also present on the relay.
    publish_to_relay(&live, &own).await;
    publish_to_relay(&live, &peer).await;

    // DHT layer OFF — every resolution must come from the relay.
    let resolver = relay_resolver(&live, Arc::new(DisabledDhtClient));

    let self_resolved = resolver
        .resolve(&own.did)
        .await
        .unwrap()
        .expect("Disabled node resolves its own DID via relay");
    assert!(matches!(
        self_resolved.source,
        ResolutionSource::ScpRelay { .. }
    ));
    assert_eq!(self_resolved.document.id, own.did);

    let peer_resolved = resolver
        .resolve(&peer.did)
        .await
        .unwrap()
        .expect("Disabled node resolves a peer's DID via relay");
    assert!(matches!(
        peer_resolved.source,
        ResolutionSource::ScpRelay { .. }
    ));
    assert_eq!(peer_resolved.document.id, peer.did);
}

/// A malformed relay blob (not a valid SCPR frame) is skipped, and a valid
/// record for the same routing ID still resolves (§3.10.4 — malformed framing
/// is discarded, never partially parsed).
#[tokio::test]
async fn malformed_relay_blob_skipped_valid_still_resolves() {
    let live = live_relay();
    let id = make_identity(66, 1);

    // Inject a garbage blob at the DID routing ID via the raw path, then a valid
    // SCPR frame.
    let manager = live.current().unwrap();
    let routing_id = RoutingId::new(did_routing_id(&id.did));
    manager
        .publish_raw(
            &routing_id,
            RELAY_BLOB_TTL_SECS,
            b"not-an-scpr-frame".to_vec(),
        )
        .await
        .unwrap();
    publish_to_relay(&live, &id).await;

    let resolver = relay_resolver(&live, Arc::new(DisabledDhtClient));
    let resolved = resolver.resolve(&id.did).await.unwrap();
    assert!(
        resolved.is_some(),
        "valid SCPR record resolves despite a co-located malformed blob"
    );
}
