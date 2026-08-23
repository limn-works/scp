//! The relay layer of production DID resolution (spec §3.10.2, §3.10.4).
//!
//! Every test here composes the resolver through
//! [`scp_ffi_common::build_production_did_resolver`] — the one builder the
//! `PyO3`, napi-rs, and `UniFFI` bridges call — so these assertions bind the shipped
//! composition, not a shape a test invented.
//!
//! What the tests establish:
//!
//! 1. A DID published ONLY to a relay resolves, with relay provenance.
//! 2. A DID published ONLY to the DHT still resolves, so wiring the relay layer
//!    did not break the DHT layer.
//! 3. A relay layer that cannot answer is distinguishable from a DID nobody
//!    published: the first yields `LayerStatus::Unavailable` and
//!    `ResolutionError::NetworkUnavailable`, the second yields two `Answered`
//!    layers and `ResolutionError::NotFound` (§3.10.4, "One layer fails, the
//!    other reports the DID absent").
//! 4. A relay bound AFTER the resolver was built is still queried, which is what
//!    a bridge needs: it builds its resolver at FFI init and connects relays
//!    later.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::pin::Pin;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};

use scp_core::envelope::OuterEnvelope;
use scp_dht::{DhtClient, InMemoryDhtClient, bep44_signable};
use scp_did::DidDocument;
use scp_ffi_common::{IdentityBackedDidResolver, ResolutionError, build_production_did_resolver};
use scp_identity::DidCache;
use scp_identity::resolver::{DidResolver, LayerStatus, ResolutionOutcome, ResolutionSource};
use scp_protocol::envelope::did_record::DidRecordV1;
use scp_transport::error::TransportError;
use scp_transport::native::TransportRelayQuerier;
use scp_transport::traits::{BlobId, RoutingId, SubscriptionStream, TransportAdapter};

const RELAY_URL: &str = "wss://relay.relay-did-resolution.test/scp/v1";

// ---------------------------------------------------------------------------
// Test transports
// ---------------------------------------------------------------------------

type BoxFut<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// How a test relay behaves when the resolver runs a DID QUERY over it.
enum RelayBehavior {
    /// The relay answers with these raw blobs.
    Serves(Vec<Vec<u8>>),
    /// The relay connection errors, so the relay does not answer at all.
    Errors,
}

/// A relay transport whose only meaningful method is `query_raw` — the DID
/// resolution READ path (§3.10.2). Every other method reports "not connected"
/// rather than fabricating a success.
struct TestRelayAdapter {
    behavior: RelayBehavior,
}

impl TestRelayAdapter {
    const fn serving(blobs: Vec<Vec<u8>>) -> Self {
        Self {
            behavior: RelayBehavior::Serves(blobs),
        }
    }

    const fn erroring() -> Self {
        Self {
            behavior: RelayBehavior::Errors,
        }
    }
}

impl TransportAdapter for TestRelayAdapter {
    fn send(&self, _envelope: &OuterEnvelope) -> BoxFut<'_, Result<BlobId, TransportError>> {
        Box::pin(async { Err(TransportError::NotConnected) })
    }

    fn subscribe(
        &self,
        _routing_id: &RoutingId,
        _since: Option<u64>,
    ) -> BoxFut<'_, Result<SubscriptionStream, TransportError>> {
        Box::pin(async { Err(TransportError::NotConnected) })
    }

    fn unsubscribe(&self, _routing_id: &RoutingId) -> BoxFut<'_, Result<(), TransportError>> {
        Box::pin(async { Err(TransportError::NotConnected) })
    }

    fn query(
        &self,
        _routing_id: &RoutingId,
        _since: Option<u64>,
    ) -> BoxFut<'_, Result<Vec<OuterEnvelope>, TransportError>> {
        Box::pin(async { Err(TransportError::NotConnected) })
    }

    fn delete(&self, _blob_id: &BlobId) -> BoxFut<'_, Result<(), TransportError>> {
        Box::pin(async { Err(TransportError::NotConnected) })
    }

    fn query_raw(
        &self,
        _routing_id: &RoutingId,
        _since: Option<u64>,
        _limit: u32,
    ) -> BoxFut<'_, Result<Vec<Vec<u8>>, TransportError>> {
        match &self.behavior {
            RelayBehavior::Serves(blobs) => {
                let blobs = blobs.clone();
                Box::pin(async move { Ok(blobs) })
            }
            RelayBehavior::Errors => Box::pin(async {
                Err(TransportError::SendFailed(
                    "test relay connection dropped".to_owned(),
                ))
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// One published DID: its string, its document, and the BEP44 triple that both
/// the relay frame and the DHT record carry.
struct PublishedDid {
    did: String,
    public_key: [u8; 32],
    value: Vec<u8>,
    signature: [u8; 64],
    seq: u64,
}

impl PublishedDid {
    fn new(seed: u8, seq: u64) -> Self {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let verifying_key = signing_key.verifying_key();
        let did = format!("did:dht:z{}", zbase32::encode(verifying_key.as_bytes()));
        let document = DidDocument::new(&did, verifying_key.as_bytes(), &[2u8; 32], &[3u8; 32]);
        let value = document.to_json().unwrap().into_bytes();
        let signature: [u8; 64] = signing_key.sign(&bep44_signable(&value, seq)).to_bytes();
        Self {
            did,
            public_key: *verifying_key.as_bytes(),
            value,
            signature,
            seq,
        }
    }

    /// The §9.10.12 DID-record frame a relay stores for this DID.
    fn relay_frame(&self) -> Vec<u8> {
        DidRecordV1::try_new(
            self.public_key,
            self.seq,
            self.signature,
            self.value.clone(),
        )
        .expect("DID record frame builds")
        .encode()
    }

    async fn publish_to_dht(&self, dht: &InMemoryDhtClient) {
        dht.publish(&self.public_key, &self.signature, &self.value, self.seq)
            .await
            .expect("in-memory DHT publish");
    }
}

/// Composes the production resolver over `dht`, plus the relay querier the test
/// binds transports into.
fn production_resolver(
    dht: Arc<InMemoryDhtClient>,
) -> (
    Arc<scp_ffi_common::ProductionDidResolver<InMemoryDhtClient>>,
    Arc<TransportRelayQuerier>,
) {
    production_resolver_with_cache(dht, Arc::new(DidCache::new()))
}

/// Composes the production resolver over `dht` and a caller-supplied cache, so a
/// test can seed the cache the resolver reads on step 1 and step 3a.
fn production_resolver_with_cache(
    dht: Arc<InMemoryDhtClient>,
    cache: Arc<DidCache>,
) -> (
    Arc<scp_ffi_common::ProductionDidResolver<InMemoryDhtClient>>,
    Arc<TransportRelayQuerier>,
) {
    let relay_querier = Arc::new(TransportRelayQuerier::new());
    let resolver = build_production_did_resolver(Arc::clone(&relay_querier), dht, cache);
    (resolver, relay_querier)
}

// ---------------------------------------------------------------------------
// 1. A DID held only by a relay resolves
// ---------------------------------------------------------------------------

#[tokio::test]
async fn did_published_only_to_a_relay_resolves_through_the_relay_layer() {
    let published = PublishedDid::new(11, 3);
    let (resolver, relay_querier) = production_resolver(Arc::new(InMemoryDhtClient::new()));
    relay_querier.bind(
        RELAY_URL,
        Arc::new(TestRelayAdapter::serving(vec![published.relay_frame()])),
    );

    let outcome = resolver
        .resolve(&published.did)
        .await
        .expect("resolution must not fail");

    match outcome {
        ResolutionOutcome::Found(found) => {
            assert_eq!(found.seq, published.seq);
            assert_eq!(found.document.id, published.did);
            assert_eq!(
                found.source,
                ResolutionSource::ScpRelay {
                    relay_url: RELAY_URL.to_owned()
                },
                "the DHT holds nothing, so the relay layer served this document"
            );
        }
        ResolutionOutcome::Absent { layers } => panic!(
            "a DID held only by a bound relay must resolve; layers were {layers:?} — the relay \
             layer is not reaching the relay"
        ),
    }
}

/// The bind is load-bearing: the same fixture with no relay bound resolves to
/// nothing, and names the relay layer unavailable.
#[tokio::test]
async fn the_same_did_does_not_resolve_when_no_relay_is_bound() {
    let published = PublishedDid::new(11, 3);
    let (resolver, _relay_querier) = production_resolver(Arc::new(InMemoryDhtClient::new()));

    let outcome = resolver
        .resolve(&published.did)
        .await
        .expect("the DHT answered, so resolution must not fail");

    match outcome {
        ResolutionOutcome::Absent { layers } => {
            assert_eq!(layers.relay, LayerStatus::Unavailable);
            assert_eq!(layers.dht, LayerStatus::Answered);
        }
        ResolutionOutcome::Found(found) => {
            panic!("nothing was published anywhere, yet resolution returned {found:?}")
        }
    }
}

// ---------------------------------------------------------------------------
// 2. The DHT layer still works
// ---------------------------------------------------------------------------

#[tokio::test]
async fn did_published_only_to_the_dht_still_resolves() {
    let published = PublishedDid::new(22, 5);
    let dht = Arc::new(InMemoryDhtClient::new());
    published.publish_to_dht(&dht).await;

    // No relay is bound: the relay layer cannot answer, and the DHT layer must
    // still serve the document.
    let (resolver, _relay_querier) = production_resolver(dht);

    let outcome = resolver
        .resolve(&published.did)
        .await
        .expect("resolution must not fail");

    match outcome {
        ResolutionOutcome::Found(found) => {
            assert_eq!(found.seq, published.seq);
            assert_eq!(found.source, ResolutionSource::MainlineDht);
        }
        ResolutionOutcome::Absent { layers } => {
            panic!("the DHT holds this document; layers were {layers:?}")
        }
    }
}

// ---------------------------------------------------------------------------
// 3. A layer that cannot answer is not a DID that nobody published
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_failing_relay_reports_the_relay_layer_unavailable() {
    let published = PublishedDid::new(33, 1);
    let (resolver, relay_querier) = production_resolver(Arc::new(InMemoryDhtClient::new()));
    relay_querier.bind(RELAY_URL, Arc::new(TestRelayAdapter::erroring()));

    let outcome = resolver
        .resolve(&published.did)
        .await
        .expect("the DHT answered, so resolution must not fail");

    match outcome {
        ResolutionOutcome::Absent { layers } => {
            assert_eq!(
                layers.relay,
                LayerStatus::Unavailable,
                "the bound relay errored, so the relay layer did not answer"
            );
            assert_eq!(
                layers.dht,
                LayerStatus::Answered,
                "the DHT answered that it holds nothing"
            );
            assert!(layers.any_unavailable());
            assert_eq!(layers.unavailable_layers(), "SCP relay layer");
        }
        ResolutionOutcome::Found(found) => panic!("nothing was published, yet got {found:?}"),
    }
}

#[tokio::test]
async fn both_layers_answering_reports_a_genuine_absence() {
    let published = PublishedDid::new(44, 1);
    let (resolver, relay_querier) = production_resolver(Arc::new(InMemoryDhtClient::new()));
    // A reachable relay that holds no record for this routing ID.
    relay_querier.bind(RELAY_URL, Arc::new(TestRelayAdapter::serving(Vec::new())));

    let outcome = resolver
        .resolve(&published.did)
        .await
        .expect("both layers answered, so resolution must not fail");

    match outcome {
        ResolutionOutcome::Absent { layers } => {
            assert_eq!(layers.relay, LayerStatus::Answered);
            assert_eq!(layers.dht, LayerStatus::Answered);
            assert!(
                !layers.any_unavailable(),
                "both layers answered, so this absence IS evidence that nobody published the DID"
            );
        }
        ResolutionOutcome::Found(found) => panic!("nothing was published, yet got {found:?}"),
    }
}

/// The two absences reach a caller as two DIFFERENT typed errors through
/// `IdentityBackedDidResolver`, which is the seam every bridge's UCAN validation
/// and attestation verification reads.
#[tokio::test]
async fn the_bridge_resolver_separates_an_unreachable_layer_from_a_missing_did() {
    let unreachable = {
        let published = PublishedDid::new(55, 1);
        let (resolver, relay_querier) = production_resolver(Arc::new(InMemoryDhtClient::new()));
        relay_querier.bind(RELAY_URL, Arc::new(TestRelayAdapter::erroring()));
        let bridge_resolver =
            IdentityBackedDidResolver::new(resolver, tokio::runtime::Handle::current());
        bridge_resolver
            .resolve_typed(&published.did)
            .await
            .expect_err("no document was published")
    };
    assert!(
        matches!(unreachable, ResolutionError::NetworkUnavailable(_)),
        "an unreachable relay layer must surface as NetworkUnavailable, got {unreachable:?}"
    );

    let missing = {
        let published = PublishedDid::new(66, 1);
        let (resolver, relay_querier) = production_resolver(Arc::new(InMemoryDhtClient::new()));
        relay_querier.bind(RELAY_URL, Arc::new(TestRelayAdapter::serving(Vec::new())));
        let bridge_resolver =
            IdentityBackedDidResolver::new(resolver, tokio::runtime::Handle::current());
        bridge_resolver
            .resolve_typed(&published.did)
            .await
            .expect_err("no document was published")
    };
    assert!(
        matches!(missing, ResolutionError::NotFound(_)),
        "a DID that every reachable layer reports absent must surface as NotFound, got {missing:?}"
    );
}

// ---------------------------------------------------------------------------
// 4. A relay bound after the resolver was built is still queried
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_relay_bound_after_the_resolver_was_built_is_queried() {
    let published = PublishedDid::new(77, 9);
    let (resolver, relay_querier) = production_resolver(Arc::new(InMemoryDhtClient::new()));

    // Resolve once with nothing bound: the relay layer cannot answer.
    let before = resolver
        .resolve(&published.did)
        .await
        .expect("the DHT answered");
    assert!(
        matches!(before, ResolutionOutcome::Absent { layers } if layers.relay.is_unavailable()),
        "with no relay bound the relay layer must report itself unavailable"
    );

    // A bridge connects a relay AFTER building its resolver. The resolver reads
    // the bound set on every resolve, so the new relay is reachable without
    // rebuilding the resolver (§3.10.4 step 3a).
    relay_querier.bind(
        RELAY_URL,
        Arc::new(TestRelayAdapter::serving(vec![published.relay_frame()])),
    );

    let after = resolver
        .resolve(&published.did)
        .await
        .expect("resolution must not fail");
    match after {
        ResolutionOutcome::Found(found) => assert_eq!(
            found.source,
            ResolutionSource::ScpRelay {
                relay_url: RELAY_URL.to_owned()
            }
        ),
        ResolutionOutcome::Absent { layers } => panic!(
            "the relay bound after resolver construction must be queried; layers were {layers:?}"
        ),
    }
}
