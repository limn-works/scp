//! Unified DID resolution across SCP relays and Mainline DHT.
//!
//! Implements the parallel dual-layer resolution protocol defined in §3.10.10
//! and §3.10.4. Both layers (SCP relay QUERY and Mainline DHT BEP44 lookup)
//! are queried in parallel via `tokio::join!`. The result with the highest seq
//! wins per section 3.10.7. "Valid" means the BEP44 signature verifies against
//! the public key encoded in the DID string AND the sequence number is greater
//! than or equal to the last known sequence number for that DID.
//!
//! When both layers return valid documents, the document with the highest
//! sequence number is accepted. On a tie, the relay result is preferred
//! (lower latency for subsequent operations).
//!
//! When both layers return valid documents with different sequence numbers,
//! protocol-level healing (§3.10.7) re-publishes the fresher document to the
//! stale layer. Healing is asynchronous (does not block the resolve call) and
//! best-effort (failure is logged, not propagated).
//!
//! # Architecture
//!
//! - [`DidResolver`] — Trait for unified DID resolution (§3.10.10).
//! - [`ResolutionOutcome`] — Found, or absent with each layer's status.
//! - [`LayerAvailability`] / [`LayerStatus`] — Which layers answered (§3.10.4).
//! - [`ResolvedDidDocument`] — Resolution result with provenance metadata.
//! - [`ResolutionSource`] — Which layer served the document.
//! - [`MultiRelayQuerier`] — Trait abstracting SCP relay QUERY operations.
//! - [`BootstrapRelays`] — Supplies the relay URLs to query (§3.10.4 step 3a).
//! - [`HealingPublisher`] — Trait abstracting republish to a stale layer (§3.10.7).
//! - [`DualLayerResolver`] — Composes relay + DHT resolution in parallel.
//!
//! # Absence is not failure
//!
//! A layer that cannot answer never reads as "no such DID". The resolver records
//! each layer as [`LayerStatus::Answered`] or [`LayerStatus::Unavailable`] and
//! hands that record to the caller in [`ResolutionOutcome::Absent`]; when neither
//! layer answers it returns [`IdentityError::ResolutionFailed`] (§3.10.4).
//!
//! See SCP-241 and SCP-245 in `.docs/prds/reachability.json`.

use std::cmp::Ordering;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::IdentityError;
use crate::cache::DidCache;
use crate::dht::extract_public_key;
use crate::republish::RelayPublisher;
use crate::resolution::{did_routing_id, verify_relay_record};
use scp_clock::{Clock, SystemClock};
use scp_dht::{DhtClient, DhtLookup};
use scp_did::{DidDocument, decode_multibase_key};

// ---------------------------------------------------------------------------
// Core types (§3.10.10)
// ---------------------------------------------------------------------------

/// Unified DID resolution across SCP relays and Mainline DHT.
///
/// Implements the parallel dual-layer resolution protocol (§3.10.4).
/// The existing [`super::DidMethod::resolve()`] interface continues to work
/// for single-layer DHT resolution — `DidResolver` is an additive layer, not
/// a replacement.
pub trait DidResolver: Send + Sync {
    /// Resolves a DID string to its document via parallel dual-layer resolution.
    ///
    /// Returns [`ResolutionOutcome::Found`] when a layer (or the cache) served a
    /// document that verified against the DID-derived key. Returns
    /// [`ResolutionOutcome::Absent`] when no layer served a document; the
    /// [`LayerAvailability`] it carries tells the caller which layers answered,
    /// so a DID nobody published is distinguishable from a DID whose only holder
    /// was unreachable (§3.10.4, "One layer fails, the other reports the DID
    /// absent"). Returns [`IdentityError::ResolutionFailed`] when no layer could
    /// answer and the cache holds nothing (§3.10.4, "Both layers fail").
    fn resolve(
        &self,
        did: &str,
    ) -> impl Future<Output = Result<ResolutionOutcome, IdentityError>> + Send;
}

/// Whether one resolution layer answered a query (§3.10.4).
///
/// **The criterion the resolver applies:** a layer **answered** when a source in
/// it gave the resolver usable evidence about this DID — either a record that
/// verified against the DID-derived key and passed the rollback guard, or an
/// affirmative report from a reached source that it holds no record. A layer is
/// **unavailable** in every other case, because the resolver learned nothing
/// about the DID from it.
///
/// The evidence that a layer gave no usable answer (each of these makes a layer
/// unavailable, and the list is what the criterion admits, not the criterion
/// itself): every source errored or timed out; no source had a live connection;
/// the arm is switched off; every record a source served failed BEP44
/// verification, failed self-certification, failed to decode as a DID-record
/// frame, or carried a sequence number below the cache high-water mark.
///
/// Splitting the two is load-bearing. `Answered` on both layers is what makes an
/// [`ResolutionOutcome::Absent`] read as "nobody published this DID", so a layer
/// that reported `Answered` without asking anyone would let whoever suppressed
/// that layer manufacture a proof of absence (§3.10.4, "One layer fails, the
/// other reports the DID absent").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayerStatus {
    /// A source in this layer gave the resolver usable evidence about the DID.
    Answered,
    /// No source in this layer gave the resolver usable evidence about the DID.
    Unavailable,
}

impl LayerStatus {
    /// Returns `true` when this layer could not answer.
    #[must_use]
    pub const fn is_unavailable(self) -> bool {
        matches!(self, Self::Unavailable)
    }
}

/// Which resolution layers answered a resolution attempt (§3.10.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayerAvailability {
    /// The SCP relay layer (§3.10.2).
    pub relay: LayerStatus,
    /// The Mainline DHT layer (§3.10.3).
    pub dht: LayerStatus,
}

impl LayerAvailability {
    /// Returns `true` when at least one layer could not answer, so the caller
    /// must not read the absent result as proof that nobody published the DID.
    #[must_use]
    pub const fn any_unavailable(self) -> bool {
        self.relay.is_unavailable() || self.dht.is_unavailable()
    }

    /// Names the layers that could not answer, for an error message a reader
    /// can act on. Returns an empty string when both layers answered.
    #[must_use]
    pub const fn unavailable_layers(self) -> &'static str {
        match (self.relay, self.dht) {
            (LayerStatus::Unavailable, LayerStatus::Unavailable) => "SCP relay layer, Mainline DHT",
            (LayerStatus::Unavailable, LayerStatus::Answered) => "SCP relay layer",
            (LayerStatus::Answered, LayerStatus::Unavailable) => "Mainline DHT",
            (LayerStatus::Answered, LayerStatus::Answered) => "",
        }
    }
}

/// What a resolution attempt produced (§3.10.4).
#[derive(Debug, Clone)]
pub enum ResolutionOutcome {
    /// A layer (or the cache) served a document that verified against the key
    /// the DID string encodes.
    Found(ResolvedDidDocument),
    /// No layer served a document for this DID.
    ///
    /// `layers` records which layers answered. A caller reads
    /// [`LayerAvailability::any_unavailable`] to decide whether this absence is
    /// evidence that nobody published the DID (both layers answered) or only
    /// evidence that the layers it could reach hold nothing (§3.10.4).
    Absent {
        /// Which layers answered this attempt.
        layers: LayerAvailability,
    },
}

impl ResolutionOutcome {
    /// Returns the resolved document when a layer served one.
    #[must_use]
    pub const fn found(&self) -> Option<&ResolvedDidDocument> {
        match self {
            Self::Found(doc) => Some(doc),
            Self::Absent { .. } => None,
        }
    }

    /// Consumes the outcome and returns the resolved document when a layer
    /// served one.
    #[must_use]
    pub fn into_found(self) -> Option<ResolvedDidDocument> {
        match self {
            Self::Found(doc) => Some(doc),
            Self::Absent { .. } => None,
        }
    }
}

/// A resolved DID document with provenance metadata.
#[derive(Debug, Clone)]
pub struct ResolvedDidDocument {
    /// The verified DID document.
    pub document: DidDocument,
    /// The BEP44 sequence number.
    ///
    /// Deliberately `u64` despite BEP44's signed integer wire format. SCP never
    /// publishes negative sequence numbers; the bencode encoder/decoder handles
    /// `u64` ↔ `i64` transparently for values up to `i64::MAX`.
    pub seq: u64,
    /// Which resolution layer served this document.
    pub source: ResolutionSource,
}

/// Provenance of a resolved DID document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolutionSource {
    /// Resolved via QUERY to an SCP relay.
    ScpRelay {
        /// The relay URL that served the document.
        relay_url: String,
    },
    /// Resolved via Mainline DHT BEP44 lookup.
    MainlineDht,
    /// Served from local cache (original source recorded at cache time).
    Cache,
}

// ---------------------------------------------------------------------------
// Relay querier abstraction
// ---------------------------------------------------------------------------

/// A relay resolution result, containing the same data as a DHT record plus
/// the relay URL that served it.
#[derive(Debug, Clone)]
pub struct RelayRecord {
    /// The serialized DID document bytes (BEP44 signed blob).
    pub value: Vec<u8>,
    /// The Ed25519 signature over the BEP44 encoded payload.
    pub signature: [u8; 64],
    /// The BEP44 sequence number.
    ///
    /// Deliberately `u64` despite BEP44's signed integer wire format. SCP never
    /// publishes negative sequence numbers; the bencode encoder/decoder handles
    /// `u64` ↔ `i64` transparently for values up to `i64::MAX`.
    pub seq: u64,
    /// The relay URL that served this record.
    pub relay_url: String,
}

/// Abstracts SCP relay QUERY operations for DID document resolution across
/// multiple relays.
///
/// The relay querier sends a QUERY with `routing_id = did_routing_id(did_string)`
/// and a bounded multi-candidate limit to known SCP relays (§3.10.2). It
/// returns the **highest-seq valid** BEP44-signed record found across all
/// queried relays and candidates, or `None` if no relay has the document.
/// Both bad-signature and stale-but-valid co-located frames are defeated by
/// iterating every candidate and selecting highest-seq (§3.10.7, §3.10.8).
///
/// Named `MultiRelayQuerier` to distinguish from [`super::resolution::RelayQuerier`]
/// which operates on a single relay URL. This trait takes a slice of relay URLs
/// and returns the single best result.
///
/// See §3.10.2 and §3.10.4 for the relay-based resolution protocol.
pub trait MultiRelayQuerier: Send + Sync {
    /// Queries SCP relays for a DID document.
    ///
    /// # Arguments
    ///
    /// * `did` — The DID string to resolve.
    /// * `relay_urls` — Relay URLs to query, in priority order.
    ///
    /// # Returns
    ///
    /// `Ok(Some(record))` when a relay served a record that verified.
    /// `Ok(None)` when at least one relay responded and stored nothing at the
    /// routing ID — the honest "a relay I reached holds nothing" answer.
    ///
    /// # Errors
    ///
    /// Returns `Err(...)` when no relay reported on the DID: the URL list was
    /// empty, or every queried relay errored, timed out, had no live
    /// connection, or served only records the resolver discarded (§3.10.4
    /// discards a bad signature and an undecodable frame each "as if the relay
    /// had failed"). The [`DualLayerResolver`] reports that as
    /// [`LayerStatus::Unavailable`] rather than folding it into a not-found
    /// (§3.10.4, "One layer fails, the other reports the DID absent").
    fn query(
        &self,
        did: &str,
        relay_urls: &[String],
    ) -> impl Future<Output = Result<Option<RelayRecord>, IdentityError>> + Send;
}

// ---------------------------------------------------------------------------
// Bootstrap relay supply (§3.10.4 step 3a, §18.5.1)
// ---------------------------------------------------------------------------

/// Supplies the relay URLs a resolver queries when it holds no cached relay list
/// for a DID (§3.10.4 step 3a: "identity's published relays if known, else
/// bootstrap relays from §18.5.1").
///
/// The resolver reads this on every `resolve` rather than capturing a list at
/// construction time. A bridge builds its DID resolver at FFI init, before any
/// relay connection exists, so a construction-time snapshot would pin the
/// resolver to the empty set forever. The production implementation in
/// `scp-transport` returns the relay URLs whose transports are currently bound,
/// which is spec §18.5.1 priority 1 — the relays the caller explicitly
/// configured and the bridge connected.
pub trait BootstrapRelays: Send + Sync {
    /// Returns the relay URLs to query, in priority order.
    ///
    /// An empty result means the caller configured no relay, which the relay
    /// layer reports as unavailable rather than as "no relay holds this DID".
    fn bootstrap_relay_urls(&self) -> Vec<String>;
}

/// A fixed relay list, for a caller that knows its relays up front and never
/// changes them (an operator-configured resolver, a test).
impl BootstrapRelays for Vec<String> {
    fn bootstrap_relay_urls(&self) -> Vec<String> {
        self.clone()
    }
}

// ---------------------------------------------------------------------------
// Healing publisher abstraction (§3.10.7, SCP-245)
// ---------------------------------------------------------------------------

/// Identifies which resolution layer has the stale document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StaleLayer {
    /// The SCP relay returned a lower sequence number than the DHT.
    /// Contains relay URLs that were queried (hints for where to republish).
    Relay {
        /// Relay URLs that returned the stale document.
        relay_urls: Vec<String>,
    },
    /// The Mainline DHT returned a lower sequence number than the relay.
    Dht,
}

/// Abstracts the ability to republish a fresher DID document to the resolution
/// layer that returned a stale copy (protocol-level healing per §3.10.7).
///
/// When `DualLayerResolver` detects that both layers returned valid documents
/// with different sequence numbers, it fires a healing republish to the stale
/// layer via this trait. The call is spawned asynchronously and is best-effort:
/// failures are logged, not propagated to the caller.
///
/// Production implementations may delegate to [`super::republish::RelayPublisher`]
/// for relay healing and [`scp_dht::DhtClient`] for DHT healing.
/// Test implementations record calls for assertion.
pub trait HealingPublisher: Send + Sync {
    /// Republishes the fresher document to the stale layer.
    ///
    /// # Arguments
    ///
    /// * `did` — The DID string whose document diverged across layers.
    /// * `stale_layer` — Which layer had the stale document.
    /// * `document_bytes` — The BEP44-signed DID document bytes (fresher copy).
    /// * `signature` — The Ed25519 signature for the BEP44 record.
    /// * `seq` — The sequence number of the fresher document.
    /// * `public_key` — The 32-byte Ed25519 public key from the DID.
    ///
    /// # Errors
    ///
    /// Returns `Err` on publish failure. The caller logs the error and
    /// discards it (best-effort healing).
    fn heal(
        &self,
        did: &str,
        stale_layer: &StaleLayer,
        document_bytes: &[u8],
        signature: &[u8; 64],
        seq: u64,
        public_key: &[u8; 32],
    ) -> impl Future<Output = Result<(), IdentityError>> + Send;
}

// `verify_relay_record` (imported from `crate::resolution`) is the single shared
// BEP44-verify + UTF-8/JSON-deser + self-cert path used by both this resolver
// and `RealMultiRelayQuerier`, ensuring relay and DHT records are validated
// identically without duplication.

// ---------------------------------------------------------------------------
// DualLayerResolver
// ---------------------------------------------------------------------------

/// Per-layer timeout for parallel resolution. Each of the relay and DHT layers
/// is given this much time to respond; a layer that exceeds it reports
/// [`LayerStatus::Unavailable`].
const LAYER_TIMEOUT: Duration = Duration::from_secs(10);

/// How old a cached document may be and still be served when neither layer
/// answered (§3.10.4, "Both layers fail": "less than 7 days old").
///
/// This is not the cache's refresh TTL. [`DidCache::get`] refreshes an active
/// contact every 24 hours, and step 1 of `resolve` applies that TTL. This
/// constant governs the separate last-resort path: both layers gave the
/// resolver nothing, so a document the cache still holds beats failing the
/// caller's UCAN or attestation check.
const BOTH_LAYERS_FAIL_CACHE_MAX_AGE_SECS: u64 = 7 * 24 * 60 * 60;

/// Composes SCP relay QUERY with Mainline DHT resolution in parallel.
///
/// On `resolve()`:
/// 1. Check cache. If a fresh entry exists, return with `ResolutionSource::Cache`.
/// 2. Extract the public key from the DID string.
/// 3. Initiate both relay QUERY and DHT resolve concurrently via `tokio::join!`
///    with per-layer 10-second timeouts.
/// 4. Both layers are awaited; each layer's record is BEP44-verified and checked
///    against the cache's sequence high-water mark.
/// 5. The surviving record with the highest sequence number wins; on a tie the
///    relay record wins (lower latency for subsequent ops).
/// 6. When one layer gives no usable evidence, the other's verified record is
///    used.
/// 7. When at least one layer answered and neither served a record, returns
///    `Ok(ResolutionOutcome::Absent { layers })`. When neither layer answered,
///    returns a cached document under
///    [`BOTH_LAYERS_FAIL_CACHE_MAX_AGE_SECS`] old, and
///    `Err(IdentityError::ResolutionFailed)` when the cache holds none.
/// 8. Cache the result.
/// 9. If both layers returned valid documents with different seq numbers,
///    trigger protocol-level healing (§3.10.7): asynchronously republish the
///    fresher document to the stale layer.
///
/// See §3.10.4 and §3.10.7 for the full resolution protocol.
pub struct DualLayerResolver<
    R: MultiRelayQuerier,
    D: DhtClient,
    C: Clock = SystemClock,
    H: HealingPublisher = NoHealing,
> {
    relay_querier: Arc<R>,
    dht_client: Arc<D>,
    cache: Arc<DidCache<C>>,
    /// Supplies the relay URLs to query when the cache holds no relay list for
    /// the DID (§3.10.4 step 3a). Read on every `resolve`, never snapshotted at
    /// construction, because a bridge builds its resolver before it connects a
    /// relay.
    bootstrap_relays: Arc<dyn BootstrapRelays>,
    /// Optional healing publisher for protocol-level healing (§3.10.7, SCP-245).
    ///
    /// When set, the resolver triggers an asynchronous best-effort republish
    /// of the fresher document to the layer that returned a stale copy.
    healing_publisher: Option<Arc<H>>,
}

/// The healing-publisher type parameter for a resolver built without healing.
///
/// Uninhabited by construction: [`DualLayerResolver::new`] expresses "no healing"
/// by storing `healing_publisher: None`, and no value of this type exists, so a
/// caller cannot hand [`DualLayerResolver::with_healing`] a publisher that
/// reports a successful republish without publishing anything.
pub enum NoHealing {}

#[allow(clippy::manual_async_fn)]
impl HealingPublisher for NoHealing {
    // `NoHealing` is uninhabited, so no `&NoHealing` can exist at run time and
    // this body is unreachable by construction. `clippy::uninhabited_references`
    // warns that dereferencing a reference to an uninhabited type is undefined
    // behaviour; producing that reference in the first place is what no caller
    // can do. The zero-arm `match` is what makes this impl total without
    // fabricating a success value the caller would read as a completed
    // republish.
    #[allow(clippy::uninhabited_references)]
    fn heal(
        &self,
        _did: &str,
        _stale_layer: &StaleLayer,
        _document_bytes: &[u8],
        _signature: &[u8; 64],
        _seq: u64,
        _public_key: &[u8; 32],
    ) -> impl Future<Output = Result<(), IdentityError>> + Send {
        async move { match *self {} }
    }
}

/// Production healing publisher that delegates to [`DhtClient`] and
/// [`RelayPublisher`] for the respective stale layers (§3.10.7, SCP-245).
///
/// When the stale layer is `Dht`, the fresher document is published via the
/// `DhtClient::publish` method. When the stale layer is `Relay`, the document
/// is published via `RelayPublisher::publish` to each relay URL that returned
/// the stale copy.
pub struct DualLayerHealingPublisher<D: DhtClient, R: RelayPublisher> {
    dht_client: Arc<D>,
    relay_publisher: Arc<R>,
}

impl<D: DhtClient, R: RelayPublisher> DualLayerHealingPublisher<D, R> {
    /// Creates a new production healing publisher.
    #[must_use]
    pub const fn new(dht_client: Arc<D>, relay_publisher: Arc<R>) -> Self {
        Self {
            dht_client,
            relay_publisher,
        }
    }
}

/// DID document blob TTL for relay publishing: 7 days (§3.10.2).
const DID_DOCUMENT_BLOB_TTL_SECS: u64 = 604_800;

#[allow(clippy::manual_async_fn)]
impl<D: DhtClient + 'static, R: RelayPublisher + 'static> HealingPublisher
    for DualLayerHealingPublisher<D, R>
{
    fn heal(
        &self,
        did: &str,
        stale_layer: &StaleLayer,
        document_bytes: &[u8],
        signature: &[u8; 64],
        seq: u64,
        public_key: &[u8; 32],
    ) -> impl Future<Output = Result<(), IdentityError>> + Send {
        let dht_client = Arc::clone(&self.dht_client);
        let relay_publisher = Arc::clone(&self.relay_publisher);
        let stale_layer = stale_layer.clone();
        let document_bytes = document_bytes.to_vec();
        let signature = *signature;
        let public_key = *public_key;
        let did = did.to_owned();

        async move {
            match stale_layer {
                StaleLayer::Dht => {
                    debug!(did = %did, seq, "healing: republishing to DHT");
                    // The DHT transport yields `DhtError`; map it into this
                    // crate's `IdentityError` so both match arms share a type.
                    dht_client
                        .publish(&public_key, &signature, &document_bytes, seq)
                        .await
                        .map_err(IdentityError::from)
                }
                StaleLayer::Relay { relay_urls: _ } => {
                    // Publish the fresher document to relays via the relay
                    // publisher. The relay publisher distributes to the
                    // identity's own relays + bootstrap relays (§18.5.1).
                    let routing_id = did_routing_id(&did);
                    debug!(did = %did, seq, "healing: republishing to relay");
                    relay_publisher
                        .publish(&routing_id, DID_DOCUMENT_BLOB_TTL_SECS, &document_bytes)
                        .await
                }
            }
        }
    }
}

impl<R: MultiRelayQuerier, D: DhtClient, C: Clock> DualLayerResolver<R, D, C> {
    /// Creates a new dual-layer resolver without healing.
    ///
    /// `bootstrap_relays` is read on every `resolve`, so a caller may pass a
    /// live source (the relay querier's bound-transport set) and connect relays
    /// after this call.
    #[must_use]
    pub const fn new(
        relay_querier: Arc<R>,
        dht_client: Arc<D>,
        cache: Arc<DidCache<C>>,
        bootstrap_relays: Arc<dyn BootstrapRelays>,
    ) -> Self {
        Self {
            relay_querier,
            dht_client,
            cache,
            bootstrap_relays,
            healing_publisher: None,
        }
    }
}

impl<R: MultiRelayQuerier, D: DhtClient, C: Clock, H: HealingPublisher>
    DualLayerResolver<R, D, C, H>
{
    /// Creates a new dual-layer resolver with protocol-level healing (§3.10.7).
    ///
    /// When both resolution layers return valid documents with different
    /// sequence numbers, the resolver asynchronously republishes the fresher
    /// document to the layer that returned the stale copy. Healing is
    /// best-effort: failures are logged, not propagated to the caller.
    #[must_use]
    pub const fn with_healing(
        relay_querier: Arc<R>,
        dht_client: Arc<D>,
        cache: Arc<DidCache<C>>,
        bootstrap_relays: Arc<dyn BootstrapRelays>,
        healing_publisher: Arc<H>,
    ) -> Self {
        Self {
            relay_querier,
            dht_client,
            cache,
            bootstrap_relays,
            healing_publisher: Some(healing_publisher),
        }
    }
}

// Trait uses RPITIT with explicit `+ Send` bound; async fn in trait
// does not guarantee Send futures, so manual impl Future is required.
#[allow(clippy::manual_async_fn)]
impl<
    R: MultiRelayQuerier + 'static,
    D: DhtClient + 'static,
    C: Clock + 'static,
    H: HealingPublisher + 'static,
> DidResolver for DualLayerResolver<R, D, C, H>
{
    fn resolve(
        &self,
        did: &str,
    ) -> impl Future<Output = Result<ResolutionOutcome, IdentityError>> + Send {
        let did = did.to_owned();
        let relay_querier = Arc::clone(&self.relay_querier);
        let dht_client = Arc::clone(&self.dht_client);
        let cache = Arc::clone(&self.cache);
        let bootstrap_relays = Arc::clone(&self.bootstrap_relays);
        let healing_publisher = self.healing_publisher.clone();

        async move {
            // Step 1: Check cache for a fresh entry.
            if let Some(cached) = cache.get(&did).await {
                return Ok(ResolutionOutcome::Found(ResolvedDidDocument {
                    document: cached.document,
                    seq: cached.sequence,
                    source: ResolutionSource::Cache,
                }));
            }

            // Step 2: Extract the public key from the DID string.
            let public_key = extract_public_key(&did)?;

            // Step 3: Determine relay URLs, in the priority order §3.10.4 step
            // 3a states: "the identity's own relays (from a previously cached
            // DID document), then bootstrap relays". Both lists are queried, so
            // a DID document that advertises a relay this instance never
            // connected does not displace the relays it did connect. Reading the
            // bootstrap source here — not at construction — is what lets a
            // bridge build its resolver before it connects a relay (§18.5.1
            // priority 1).
            let relay_urls = relay_query_order(
                cache.cached_relay_urls(&did).await.unwrap_or_default(),
                bootstrap_relays.bootstrap_relay_urls(),
            );

            // Step 4: Initiate both layers in parallel using tokio::join!
            // with per-layer timeouts (LAYER_TIMEOUT). Both layers are
            // awaited; the result with the highest sequence number wins.
            //
            // A timeout, an error, and "no source in this layer answered" are
            // all the SAME thing to a caller — the layer could not answer — and
            // each is recorded as `LayerStatus::Unavailable` rather than folded
            // into a not-found (§3.10.4, "One layer fails, the other reports the
            // DID absent").
            let relay_fut = async {
                match tokio::time::timeout(LAYER_TIMEOUT, relay_querier.query(&did, &relay_urls))
                    .await
                {
                    Ok(result) => result,
                    Err(_elapsed) => {
                        debug!(did = %did, "relay layer timed out");
                        Err(IdentityError::RelayQueryFailed(format!(
                            "every relay query exceeded the {}s layer timeout",
                            LAYER_TIMEOUT.as_secs()
                        )))
                    }
                }
            };
            let dht_fut = async {
                match tokio::time::timeout(LAYER_TIMEOUT, dht_client.resolve(&public_key)).await {
                    Ok(result) => result.map_err(IdentityError::from),
                    Err(_elapsed) => {
                        debug!(did = %did, "DHT layer timed out");
                        Err(IdentityError::DhtResolveFailed(format!(
                            "the DHT lookup exceeded the {}s layer timeout",
                            LAYER_TIMEOUT.as_secs()
                        )))
                    }
                }
            };

            let (relay_result, dht_result) = tokio::join!(relay_fut, dht_fut);

            // Step 5: Verify each layer's record and reject one whose sequence
            // number is below the last cached sequence. The rollback guard
            // defeats an attacker who replays a validly-signed but superseded
            // document after cache TTL expiry.
            //
            // Each layer's status is read off the SURVIVING evidence, never off
            // the raw querier result. §3.10.4 discards a bad signature and an
            // undecodable frame each "as if the layer had failed", so a layer
            // whose every record the resolver discarded must report
            // `Unavailable` — otherwise tampering on one layer manufactures the
            // caller-visible claim that nobody published the DID.
            let cached_seq = cache.cached_sequence(&did).await;
            let relay_evidence = relay_evidence(relay_result, &did, &public_key, cached_seq);
            let dht_evidence = dht_evidence(dht_result, &did, &public_key, cached_seq);

            let layers = LayerAvailability {
                relay: relay_evidence.status(),
                dht: dht_evidence.status(),
            };

            // §3.10.4 "Both layers fail": neither layer gave the resolver usable
            // evidence. Serve a cached document under 7 days old — step 1
            // already returned any entry inside its refresh TTL, which is 24
            // hours for an active contact, so this path covers the window
            // between that TTL and 7 days. The resolver never fabricates a
            // document: with no such entry it reports the failure.
            if layers.relay.is_unavailable() && layers.dht.is_unavailable() {
                if let Some(cached) = cache
                    .get_within_max_age(&did, BOTH_LAYERS_FAIL_CACHE_MAX_AGE_SECS)
                    .await
                {
                    warn!(
                        did = %did,
                        unavailable_layers = %layers.unavailable_layers(),
                        "no resolution layer answered — serving the cached document (§3.10.4)"
                    );
                    return Ok(ResolutionOutcome::Found(ResolvedDidDocument {
                        document: cached.document,
                        seq: cached.sequence,
                        source: ResolutionSource::Cache,
                    }));
                }
                return Err(IdentityError::ResolutionFailed {
                    did: did.clone(),
                    reason: format!(
                        "no resolution layer answered ({}) and the cache holds no document under {} days old",
                        layers.unavailable_layers(),
                        BOTH_LAYERS_FAIL_CACHE_MAX_AGE_SECS / (24 * 60 * 60),
                    ),
                });
            }

            let relay_validated = relay_evidence.into_record();
            let dht_validated = dht_evidence.into_record();

            // Step 6: Pick the result with the highest sequence number.
            // On a tie, prefer relay (lower latency for subsequent operations).
            // Also detect sequence divergence for protocol-level healing.
            let (result, healing_info) =
                pick_winner_and_detect_divergence(relay_validated, dht_validated, &relay_urls);

            // Step 7: Cache the result.
            if let Some(ref resolved) = result {
                cache
                    .insert(&did, resolved.document.clone(), resolved.seq)
                    .await;
            }

            // Step 8: Trigger protocol-level healing (§3.10.7, SCP-245).
            maybe_trigger_healing(healing_info, healing_publisher, &did, &public_key);

            Ok(
                result.map_or(ResolutionOutcome::Absent { layers }, |resolved| {
                    ResolutionOutcome::Found(resolved)
                }),
            )
        }
    }
}

/// Orders the relays a resolve queries: the identity's own relays first, then
/// the bootstrap relays, with each URL appearing once (§3.10.4 step 3a).
///
/// Both lists are queried. Returning only the identity's own relays would drop
/// the relays this instance actually connected out of the query set, and the
/// production querier answers only for a relay it has a live transport for, so
/// a DID document advertising an unbound relay would make the relay layer
/// unavailable for that DID forever.
fn relay_query_order(identity_relays: Vec<String>, bootstrap_relays: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::with_capacity(identity_relays.len() + bootstrap_relays.len());
    let mut ordered = Vec::with_capacity(identity_relays.len() + bootstrap_relays.len());
    for url in identity_relays.into_iter().chain(bootstrap_relays) {
        if seen.insert(url.clone()) {
            ordered.push(url);
        }
    }
    ordered
}

/// What one resolution layer gave the resolver about a DID (§3.10.4).
///
/// **The criterion:** a layer answered when a source in it gave the resolver
/// usable evidence — a record that survived verification and the rollback
/// guard, or an affirmative report from a reached source that it holds no
/// record. Every other outcome is [`Self::NoAnswer`], which the resolver
/// reports as [`LayerStatus::Unavailable`].
///
/// This type exists so the status is a function of what SURVIVED validation.
/// Deriving it from the querier's `Ok`/`Err` alone let a layer that served only
/// tampered records report that it answered, which turned relay tampering into
/// a caller-visible claim that nobody published the DID.
enum LayerEvidence {
    /// A source served a record that verified and passed the rollback guard.
    Record(Box<ValidatedRecord>),
    /// A reached source reported that it holds no record for this DID.
    HoldsNothing,
    /// No source gave usable evidence about this DID.
    NoAnswer,
}

impl LayerEvidence {
    /// Reports whether this layer answered, per the criterion on
    /// [`LayerStatus`].
    const fn status(&self) -> LayerStatus {
        match self {
            Self::Record(_) | Self::HoldsNothing => LayerStatus::Answered,
            Self::NoAnswer => LayerStatus::Unavailable,
        }
    }

    /// Returns the surviving record, if this layer served one.
    fn into_record(self) -> Option<ValidatedRecord> {
        match self {
            Self::Record(record) => Some(*record),
            Self::HoldsNothing | Self::NoAnswer => None,
        }
    }
}

/// Builds the relay layer's evidence from the composer's result (§3.10.4).
fn relay_evidence(
    result: Result<Option<RelayRecord>, IdentityError>,
    did: &str,
    public_key: &[u8; 32],
    cached_seq: Option<u64>,
) -> LayerEvidence {
    let record = match result {
        Ok(Some(record)) => record,
        Ok(None) => {
            debug!(did, "a relay reported that it holds no record for this DID");
            return LayerEvidence::HoldsNothing;
        }
        Err(e) => {
            debug!(did, layer = "SCP relay", error = %e, "resolution layer gave no usable evidence");
            return LayerEvidence::NoAnswer;
        }
    };

    // Defense in depth: the composer already verified this record, and the
    // resolver verifies it again against the DID-derived key.
    let validated = match verify_relay_record(
        did,
        public_key,
        &record.value,
        &record.signature,
        record.seq,
    ) {
        Ok(document) => ValidatedRecord {
            resolved: ResolvedDidDocument {
                document,
                seq: record.seq,
                source: ResolutionSource::ScpRelay {
                    relay_url: record.relay_url,
                },
            },
            raw_value: record.value,
            raw_signature: record.signature,
        },
        Err(e) => {
            warn!(did, error = %e, "relay record verification failed — discarding it as if the relay had failed (§3.10.4)");
            return LayerEvidence::NoAnswer;
        }
    };

    guard_rollback(validated, cached_seq, did, "SCP relay")
}

/// Builds the DHT layer's evidence from the client's lookup (§3.10.4).
fn dht_evidence(
    result: Result<DhtLookup, IdentityError>,
    did: &str,
    public_key: &[u8; 32],
    cached_seq: Option<u64>,
) -> LayerEvidence {
    let record = match result {
        Ok(DhtLookup::Record(record)) => record,
        Ok(DhtLookup::NoRecord) => {
            debug!(
                did,
                "a DHT source reported that it holds no record for this DID"
            );
            return LayerEvidence::HoldsNothing;
        }
        Err(e) => {
            debug!(did, layer = "Mainline DHT", error = %e, "resolution layer gave no usable evidence");
            return LayerEvidence::NoAnswer;
        }
    };

    let validated = match verify_relay_record(
        did,
        public_key,
        &record.value,
        &record.signature,
        record.seq,
    ) {
        Ok(document) => ValidatedRecord {
            resolved: ResolvedDidDocument {
                document,
                seq: record.seq,
                source: ResolutionSource::MainlineDht,
            },
            raw_value: record.value,
            raw_signature: record.signature,
        },
        Err(e) => {
            warn!(did, error = %e, "DHT record verification failed — discarding it as if the layer had failed (§3.10.4)");
            return LayerEvidence::NoAnswer;
        }
    };

    guard_rollback(validated, cached_seq, did, "Mainline DHT")
}

/// Drops a validated record whose sequence number is below the last sequence the
/// cache recorded for this DID, and reports the layer as having given no usable
/// evidence.
///
/// This is the rollback guard: an attacker who replays a validly-signed but
/// superseded document after the cache TTL expires would otherwise reinstate a
/// rotated-out key (§3.10.7). A replayed record is a suppression attempt, not a
/// report that the layer holds nothing, so the layer reports `Unavailable`
/// rather than letting the replay become evidence of absence. The rejection is
/// logged with both sequence numbers because a caller sees only the status.
fn guard_rollback(
    record: ValidatedRecord,
    cached_seq: Option<u64>,
    did: &str,
    layer_name: &str,
) -> LayerEvidence {
    if let Some(min_seq) = cached_seq
        && record.resolved.seq < min_seq
    {
        warn!(
            did,
            layer = layer_name,
            received_seq = record.resolved.seq,
            cached_seq = min_seq,
            "resolution layer returned a stale sequence number, rejecting it as if the layer had failed"
        );
        return LayerEvidence::NoAnswer;
    }
    LayerEvidence::Record(Box::new(record))
}

/// Picks the winning resolution result and detects sequence divergence for
/// protocol-level healing (§3.10.7, SCP-245).
///
/// Returns the winning `ResolvedDidDocument` (highest seq, relay preferred on
/// tie) and an optional `HealingInfo` when both layers returned valid
/// documents with different sequence numbers.
fn pick_winner_and_detect_divergence(
    relay: Option<ValidatedRecord>,
    dht: Option<ValidatedRecord>,
    relay_urls: &[String],
) -> (Option<ResolvedDidDocument>, Option<HealingInfo>) {
    match (relay, dht) {
        (Some(relay_rec), Some(dht_rec)) => {
            // Detect divergence for healing.
            let healing = match relay_rec.resolved.seq.cmp(&dht_rec.resolved.seq) {
                Ordering::Greater => Some(HealingInfo {
                    stale_layer: StaleLayer::Dht,
                    raw_value: relay_rec.raw_value.clone(),
                    raw_signature: relay_rec.raw_signature,
                    fresher_seq: relay_rec.resolved.seq,
                }),
                Ordering::Less => Some(HealingInfo {
                    stale_layer: StaleLayer::Relay {
                        relay_urls: relay_urls.to_vec(),
                    },
                    raw_value: dht_rec.raw_value.clone(),
                    raw_signature: dht_rec.raw_signature,
                    fresher_seq: dht_rec.resolved.seq,
                }),
                Ordering::Equal => {
                    // §3.10.4: "Both layers succeed, same sequence number. The
                    // documents MUST be byte-identical (same key signs both,
                    // same content). If they differ despite identical sequence
                    // numbers, this indicates a bug in the publishing
                    // implementation. The resolver MUST log a warning and accept
                    // either document." Compare the signed BEP44 bytes, because
                    // those are what the owner's key actually covers.
                    if relay_rec.raw_value != dht_rec.raw_value {
                        warn!(
                            did = %relay_rec.resolved.document.id,
                            seq = relay_rec.resolved.seq,
                            "the relay and the Mainline DHT hold different documents at the same \
                             sequence number, which means the publisher signed two documents at \
                             one seq — accepting the relay's copy (§3.10.4)"
                        );
                    }
                    None
                }
            };

            // Highest seq wins; on tie, relay preferred.
            let winner = if relay_rec.resolved.seq >= dht_rec.resolved.seq {
                relay_rec.resolved
            } else {
                dht_rec.resolved
            };
            (Some(winner), healing)
        }
        (Some(relay_rec), None) => (Some(relay_rec.resolved), None),
        (None, Some(dht_rec)) => (Some(dht_rec.resolved), None),
        (None, None) => (None, None),
    }
}

/// Triggers protocol-level healing asynchronously if divergence was detected
/// (§3.10.7, SCP-245).
///
/// Healing is best-effort: the republish is spawned on the tokio runtime and
/// does not block the resolve call. Failures are logged at `warn` level and
/// discarded.
fn maybe_trigger_healing<H: HealingPublisher + 'static>(
    healing_info: Option<HealingInfo>,
    healing_publisher: Option<Arc<H>>,
    did: &str,
    public_key: &[u8; 32],
) {
    let Some(healing) = healing_info else { return };
    let Some(healer) = healing_publisher else {
        return;
    };

    let did_owned = did.to_owned();
    let pk = *public_key;
    let stale = healing.stale_layer;
    let raw_value = healing.raw_value;
    let raw_sig = healing.raw_signature;
    let fresher_seq = healing.fresher_seq;

    info!(
        did = %did_owned,
        fresher_seq = fresher_seq,
        stale_layer = ?stale,
        "triggering protocol-level healing (§3.10.7)"
    );

    let handle = tokio::spawn(async move {
        if let Err(e) = healer
            .heal(&did_owned, &stale, &raw_value, &raw_sig, fresher_seq, &pk)
            .await
        {
            warn!(
                did = %did_owned,
                stale_layer = ?stale,
                error = %e,
                "protocol-level healing failed (best-effort, §3.10.7)"
            );
        }
    });

    // Monitor for panics in the healing task (defense in depth).
    tokio::spawn(async move {
        if let Err(e) = handle.await
            && e.is_panic()
        {
            warn!("protocol-level healing task panicked: {e}");
        }
    });
}

/// Internal struct holding information needed for protocol-level healing
/// (§3.10.7, SCP-245).
struct HealingInfo {
    /// Which layer had the stale document.
    stale_layer: StaleLayer,
    /// The raw BEP44-signed document bytes from the fresher layer.
    raw_value: Vec<u8>,
    /// The Ed25519 signature from the fresher layer's BEP44 record.
    raw_signature: [u8; 64],
    /// The sequence number of the fresher document.
    fresher_seq: u64,
}

/// A validated resolution result bundling the `ResolvedDidDocument` with the
/// raw BEP44 record data. The raw bytes are retained for protocol-level
/// healing (§3.10.7, SCP-245) — when both layers return valid documents
/// with different sequence numbers, the resolver republishes the fresher
/// document's raw bytes to the stale layer.
struct ValidatedRecord {
    /// The verified and deserialized resolution result.
    resolved: ResolvedDidDocument,
    /// The raw BEP44-signed document bytes (pre-deserialization).
    raw_value: Vec<u8>,
    /// The Ed25519 signature from the BEP44 record.
    raw_signature: [u8; 64],
}

// ---------------------------------------------------------------------------
// Document → verifying-key extraction (ADR-053 / spec §10.17)
// ---------------------------------------------------------------------------

/// Extracts the Ed25519 verifying key for a specific signing key from a resolved
/// DID document, keyed by the requested [`SigningKeyId`](scp_did::SigningKeyId).
///
/// This is the single, pure, sync document→key extraction shared by every
/// participant that verifies governance vote signatures against a voter's
/// *document-derived* key (ADR-039 §3a):
///
/// - the FFI bridges' `IdentityBackedDidResolver::verifying_key_for`
///   (`scp-ffi-common`), wrapped into the bridge `KeyResolver` by
///   `document_vm_key_resolver`; and
/// - the co-located self-host participant `Supervisor` (`scp-node`,
///   `self_host.rs`), per ADR-053 / spec §10.17 — a co-located participant is a
///   real participant and MUST use the real document-derived resolver, never a
///   `|_, _| None` stub.
///
/// It lives here, in the lowest layer that owns every primitive it needs
/// ([`DidDocument::verification_method_by_fragment`], [`decode_multibase_key`],
/// `ed25519-dalek`), so both consumers call ONE tested helper rather than
/// duplicating the extraction — a second copy is exactly the "resolver silently
/// ignores the `SigningKeyId`" failure mode ADR-053 §Rejected-Alternatives-3
/// warns against. `scp-ffi-common` depends on `scp-node`, so `scp-node` cannot
/// call the bridge copy without a crate cycle; hoisting the pure extraction here
/// breaks that cycle.
///
/// The lookup is keyed by [`SigningKeyId::fragment`](scp_did::SigningKeyId::fragment)
/// (`"active"` / `"agent"`) — the `SigningKeyId` is honored, never ignored:
/// resolving [`SigningKeyId::Agent`](scp_did::SigningKeyId::Agent) returns
/// the document's distinct `#agent` key, not the `#active` key.
///
/// # Purity and downgrade protection
///
/// This is a **pure** function of `(document, kid)`: it performs no resolution,
/// no I/O, and advances no sequence/rotation state. The load-bearing
/// anti-rollback guard is the shared `DualLayerResolver`/[`DidCache`] sequence
/// check performed during [`resolve`](DidResolver::resolve) (which produced the
/// `document`); this helper deliberately re-implements no per-instance rotation
/// ratchet on top of it.
///
/// # Returns
///
/// `Some(key)` when the requested verification method is present and decodes to
/// a valid Ed25519 curve point; `None` when the verification method is absent,
/// its `publicKeyMultibase` cannot be decoded, or the bytes are not a valid
/// Ed25519 public key. `None` is the safe per-lookup miss — a caller building a
/// governance `KeyResolver` maps it to "vote rejected" (fail closed).
#[must_use]
pub fn verifying_key_from_document(
    document: &DidDocument,
    kid: scp_did::SigningKeyId,
) -> Option<ed25519_dalek::VerifyingKey> {
    let vm = document.verification_method_by_fragment(kid.fragment())?;
    let bytes = decode_multibase_key(&vm.public_key_multibase).ok()?;
    ed25519_dalek::VerifyingKey::from_bytes(&bytes).ok()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::similar_names
)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use ed25519_dalek::{Signer, SigningKey};
    use tokio::sync::Mutex;

    use sha2::{Digest, Sha256};

    use super::*;
    use crate::cache::DidCache;
    use crate::resolution::did_routing_id;
    use scp_clock::TestClock;
    use scp_dht::bep44_signable;
    use scp_dht::{DhtError, InMemoryDhtClient};
    use scp_did::{DidDocument, SigningKeyId};

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    /// Creates a test identity: signing key, DID string, and DID document.
    fn make_test_identity() -> (SigningKey, String, DidDocument) {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let public_key = signing_key.verifying_key();
        let did = format!("did:dht:z{}", zbase32::encode(public_key.as_bytes()));
        let doc = DidDocument::new(&did, public_key.as_bytes(), &[2u8; 32], &[3u8; 32]);
        (signing_key, did, doc)
    }

    /// Signs a DID document as a BEP44 record.
    fn sign_document(signing_key: &SigningKey, doc: &DidDocument, seq: u64) -> (Vec<u8>, [u8; 64]) {
        let doc_json = doc.to_json().unwrap();
        let value = doc_json.into_bytes();
        let signable = bep44_signable(&value, seq);
        let signature: [u8; 64] = signing_key.sign(&signable).to_bytes();
        (value, signature)
    }

    /// An in-memory relay querier for testing with configurable delays.
    struct InMemoryRelayQuerier {
        records: Mutex<std::collections::HashMap<String, RelayRecord>>,
        delay: Duration,
        should_fail: Mutex<bool>,
    }

    impl InMemoryRelayQuerier {
        fn with_delay(delay: Duration) -> Self {
            Self {
                records: Mutex::new(std::collections::HashMap::new()),
                delay,
                should_fail: Mutex::new(false),
            }
        }

        async fn insert(&self, did: &str, record: RelayRecord) {
            let mut records = self.records.lock().await;
            records.insert(did.to_owned(), record);
        }

        async fn set_should_fail(&self, fail: bool) {
            let mut should_fail = self.should_fail.lock().await;
            *should_fail = fail;
        }
    }

    impl MultiRelayQuerier for InMemoryRelayQuerier {
        fn query(
            &self,
            did: &str,
            _relay_urls: &[String],
        ) -> impl Future<Output = Result<Option<RelayRecord>, IdentityError>> + Send {
            let did = did.to_owned();
            let records = &self.records;
            let delay = self.delay;
            let should_fail = &self.should_fail;

            async move {
                tokio::time::sleep(delay).await;

                let fail = *should_fail.lock().await;
                if fail {
                    return Err(IdentityError::DhtResolveFailed(
                        "relay query failed (test)".to_owned(),
                    ));
                }

                let records = records.lock().await;
                Ok(records.get(&did).cloned())
            }
        }
    }

    /// A delayed DHT client that wraps `InMemoryDhtClient` with a configurable delay.
    struct DelayedDhtClient {
        inner: InMemoryDhtClient,
        delay: Duration,
        should_fail: Mutex<bool>,
    }

    impl DelayedDhtClient {
        fn new(delay: Duration) -> Self {
            Self {
                inner: InMemoryDhtClient::new(),
                delay,
                should_fail: Mutex::new(false),
            }
        }

        async fn set_should_fail(&self, fail: bool) {
            let mut should_fail = self.should_fail.lock().await;
            *should_fail = fail;
        }
    }

    #[allow(clippy::manual_async_fn)]
    impl DhtClient for DelayedDhtClient {
        fn publish(
            &self,
            public_key: &[u8; 32],
            signature: &[u8; 64],
            value: &[u8],
            seq: u64,
        ) -> impl Future<Output = Result<(), DhtError>> + Send {
            self.inner.publish(public_key, signature, value, seq)
        }

        fn resolve(
            &self,
            public_key: &[u8; 32],
        ) -> impl Future<Output = Result<DhtLookup, DhtError>> + Send {
            let delay = self.delay;
            let key = *public_key;
            async move {
                tokio::time::sleep(delay).await;

                let fail = *self.should_fail.lock().await;
                if fail {
                    return Err(DhtError::DhtResolveFailed(
                        "DHT resolve failed (test)".to_owned(),
                    ));
                }

                self.inner.resolve(&key).await
            }
        }
    }

    /// Creates a `DualLayerResolver` with the given relay querier and DHT client.
    fn make_resolver<R: MultiRelayQuerier, D: DhtClient>(
        relay: Arc<R>,
        dht: Arc<D>,
        cache: Arc<DidCache<Arc<TestClock>>>,
    ) -> DualLayerResolver<R, D, Arc<TestClock>> {
        DualLayerResolver::new(
            relay,
            dht,
            cache,
            Arc::new(vec!["wss://bootstrap.example.com/scp/v1".to_owned()]),
        )
    }

    // -----------------------------------------------------------------------
    // Relay query order (§3.10.4 step 3a)
    // -----------------------------------------------------------------------

    /// A relay layer that records the URL list the resolver handed it, and
    /// answers only for the URLs the test names as holding the record.
    struct UrlRecordingRelayQuerier {
        /// The URL list from the most recent `query`, in the order received.
        seen_urls: Mutex<Vec<String>>,
        /// URL -> the record that relay serves.
        records: Mutex<std::collections::HashMap<String, RelayRecord>>,
    }

    impl UrlRecordingRelayQuerier {
        fn new() -> Self {
            Self {
                seen_urls: Mutex::new(Vec::new()),
                records: Mutex::new(std::collections::HashMap::new()),
            }
        }

        async fn serve(&self, relay_url: &str, record: RelayRecord) {
            self.records
                .lock()
                .await
                .insert(relay_url.to_owned(), record);
        }

        async fn seen(&self) -> Vec<String> {
            self.seen_urls.lock().await.clone()
        }
    }

    impl MultiRelayQuerier for UrlRecordingRelayQuerier {
        fn query(
            &self,
            _did: &str,
            relay_urls: &[String],
        ) -> impl Future<Output = Result<Option<RelayRecord>, IdentityError>> + Send {
            let urls = relay_urls.to_vec();
            async move {
                *self.seen_urls.lock().await = urls.clone();
                let records = self.records.lock().await;
                // Mirror the production composer: a URL nothing serves is a
                // relay that could not be reached.
                let mut any_reached = false;
                let mut best: Option<RelayRecord> = None;
                for url in &urls {
                    if let Some(record) = records.get(url) {
                        any_reached = true;
                        if best.as_ref().is_none_or(|b| record.seq > b.seq) {
                            best = Some(record.clone());
                        }
                    }
                }
                if any_reached {
                    Ok(best)
                } else {
                    Err(IdentityError::RelayQueryFailed(
                        "no relay in the list was reachable (test)".to_owned(),
                    ))
                }
            }
        }
    }

    /// `relay_query_order` puts the identity's own relays first and the
    /// bootstrap relays after, and lists each URL once.
    #[test]
    fn relay_query_order_puts_identity_relays_first_and_keeps_bootstrap() {
        let ordered = relay_query_order(
            vec![
                "wss://alice/scp/v1".to_owned(),
                "wss://both/scp/v1".to_owned(),
            ],
            vec![
                "wss://both/scp/v1".to_owned(),
                "wss://bound/scp/v1".to_owned(),
            ],
        );

        assert_eq!(
            ordered,
            vec![
                "wss://alice/scp/v1".to_owned(),
                "wss://both/scp/v1".to_owned(),
                "wss://bound/scp/v1".to_owned(),
            ],
            "§3.10.4 step 3a orders the identity's own relays before the bootstrap relays, \
             and a URL in both lists is queried once"
        );
    }

    /// A DID whose cached document advertises relays this instance never
    /// connected must not lose the relays it DID connect.
    ///
    /// The production querier answers only for a relay with a live transport
    /// and never dials, so replacing the bootstrap set with the cached list
    /// would make the relay layer unavailable forever for exactly the
    /// identities whose relays the cache knows.
    #[tokio::test]
    async fn a_dids_own_advertised_relays_do_not_displace_the_bootstrap_relays() {
        let (signing_key, did, mut doc) = make_test_identity();

        // The cached document advertises a relay nothing connected.
        doc.set_relay_services(&["wss://alice-relay.example.com/scp/v1"])
            .unwrap();
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(Arc::clone(&clock)));
        cache.insert(&did, doc.clone(), 1).await;
        // Age past the inactive refresh TTL so step 1 does not short-circuit,
        // while `cached_relay_urls` still reads the advertised relay.
        clock.advance(8 * 24 * 60 * 60);

        // The BOOTSTRAP relay — the one this instance connected — holds seq 4.
        let (value, signature) = sign_document(&signing_key, &doc, 4);
        let relay = Arc::new(UrlRecordingRelayQuerier::new());
        relay
            .serve(
                "wss://bootstrap.example.com/scp/v1",
                RelayRecord {
                    value,
                    signature,
                    seq: 4,
                    relay_url: "wss://bootstrap.example.com/scp/v1".to_owned(),
                },
            )
            .await;

        let dht = Arc::new(InMemoryDhtClient::new());
        let resolver = make_resolver(Arc::clone(&relay), dht, cache);

        let outcome = resolver
            .resolve(&did)
            .await
            .expect("resolution must succeed");

        assert_eq!(
            relay.seen().await,
            vec![
                "wss://alice-relay.example.com/scp/v1".to_owned(),
                "wss://bootstrap.example.com/scp/v1".to_owned(),
            ],
            "the DID's own relay is queried first, and the bound bootstrap relay still follows"
        );
        let found = outcome
            .found()
            .expect("the bootstrap relay served the record");
        assert_eq!(found.seq, 4);
        assert_eq!(
            found.source,
            ResolutionSource::ScpRelay {
                relay_url: "wss://bootstrap.example.com/scp/v1".to_owned()
            }
        );
    }

    /// The other half of the order: a record held ONLY by the relay the DID's
    /// own document advertises resolves, once that relay is reachable.
    #[tokio::test]
    async fn a_did_resolves_from_the_relay_only_its_own_document_names() {
        let (signing_key, did, mut doc) = make_test_identity();

        doc.set_relay_services(&["wss://alice-relay.example.com/scp/v1"])
            .unwrap();
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(Arc::clone(&clock)));
        cache.insert(&did, doc.clone(), 1).await;
        clock.advance(8 * 24 * 60 * 60);

        let (value, signature) = sign_document(&signing_key, &doc, 6);
        let relay = Arc::new(UrlRecordingRelayQuerier::new());
        relay
            .serve(
                "wss://alice-relay.example.com/scp/v1",
                RelayRecord {
                    value,
                    signature,
                    seq: 6,
                    relay_url: "wss://alice-relay.example.com/scp/v1".to_owned(),
                },
            )
            .await;

        let resolver = make_resolver(relay, Arc::new(InMemoryDhtClient::new()), cache);

        let outcome = resolver
            .resolve(&did)
            .await
            .expect("resolution must succeed");
        let found = outcome
            .found()
            .expect("the DID's own relay served the record");

        assert_eq!(found.seq, 6);
        assert_eq!(
            found.source,
            ResolutionSource::ScpRelay {
                relay_url: "wss://alice-relay.example.com/scp/v1".to_owned()
            },
            "a relay URL that appears only inside the DID's own document is queried"
        );
    }

    // -----------------------------------------------------------------------
    // Unit tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn relay_responds_first_with_valid_doc() {
        // Relay has 10ms delay, DHT has 100ms delay. Both respond, but relay
        // has a valid doc and DHT also has the same doc. Relay result is used
        // since both have same seq and relay is preferred on tie.
        let (signing_key, did, doc) = make_test_identity();
        let (value, signature) = sign_document(&signing_key, &doc, 1);
        let public_key = signing_key.verifying_key();

        let relay = Arc::new(InMemoryRelayQuerier::with_delay(Duration::from_millis(10)));
        relay
            .insert(
                &did,
                RelayRecord {
                    value: value.clone(),
                    signature,
                    seq: 1,
                    relay_url: "wss://relay1.example.com/scp/v1".to_owned(),
                },
            )
            .await;

        let dht = Arc::new(DelayedDhtClient::new(Duration::from_millis(100)));
        dht.inner
            .publish(public_key.as_bytes(), &signature, &value, 1)
            .await
            .unwrap();

        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(Arc::clone(&clock)));
        let resolver = make_resolver(relay, dht, cache);

        let result = tokio::time::timeout(Duration::from_secs(2), resolver.resolve(&did))
            .await
            .expect("should not timeout — both layers respond quickly")
            .unwrap();

        let resolved = result.into_found().expect("should resolve successfully");
        assert_eq!(resolved.seq, 1);
        // On tie (both seq=1), relay is preferred.
        assert_eq!(
            resolved.source,
            ResolutionSource::ScpRelay {
                relay_url: "wss://relay1.example.com/scp/v1".to_owned()
            }
        );
        assert_eq!(resolved.document, doc);
    }

    #[tokio::test]
    async fn dht_only_responds_with_valid_doc() {
        // DHT has 10ms delay, relay has no document (empty).
        // DHT result should be used since relay returns None.
        let (signing_key, did, doc) = make_test_identity();
        let (value, signature) = sign_document(&signing_key, &doc, 1);
        let public_key = signing_key.verifying_key();

        // Relay has no document stored.
        let relay = Arc::new(InMemoryRelayQuerier::with_delay(Duration::from_millis(10)));

        let dht = Arc::new(DelayedDhtClient::new(Duration::from_millis(10)));
        dht.inner
            .publish(public_key.as_bytes(), &signature, &value, 1)
            .await
            .unwrap();

        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(Arc::clone(&clock)));
        let resolver = make_resolver(relay, dht, cache);

        let result = tokio::time::timeout(Duration::from_secs(2), resolver.resolve(&did))
            .await
            .expect("should not timeout — both layers respond quickly")
            .unwrap();

        let resolved = result.into_found().expect("should resolve successfully");
        assert_eq!(resolved.seq, 1);
        assert_eq!(resolved.source, ResolutionSource::MainlineDht);
        assert_eq!(resolved.document, doc);
    }

    #[tokio::test]
    async fn both_respond_higher_seq_wins() {
        // Both layers respond quickly, but with different sequence numbers.
        // With join!, both are awaited and the highest seq wins.
        let (signing_key, did, doc_v1) = make_test_identity();
        let public_key = signing_key.verifying_key();

        // Create two versions with different seq numbers.
        let (value_v1, sig_v1) = sign_document(&signing_key, &doc_v1, 1);

        // Create v2 document (same structure, different seq).
        let doc_v2 = DidDocument::new(&did, public_key.as_bytes(), &[20u8; 32], &[30u8; 32]);
        let (value_v2, sig_v2) = sign_document(&signing_key, &doc_v2, 5);

        // Relay returns seq=5 (higher) with short delay.
        let relay = Arc::new(InMemoryRelayQuerier::with_delay(Duration::from_millis(10)));
        relay
            .insert(
                &did,
                RelayRecord {
                    value: value_v2.clone(),
                    signature: sig_v2,
                    seq: 5,
                    relay_url: "wss://relay1.example.com/scp/v1".to_owned(),
                },
            )
            .await;

        // DHT returns seq=1 (lower) with short delay.
        let dht = Arc::new(DelayedDhtClient::new(Duration::from_millis(10)));
        dht.inner
            .publish(public_key.as_bytes(), &sig_v1, &value_v1, 1)
            .await
            .unwrap();

        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(Arc::clone(&clock)));
        let resolver = make_resolver(relay, dht, cache);

        let result = tokio::time::timeout(Duration::from_secs(2), resolver.resolve(&did))
            .await
            .expect("should not timeout")
            .unwrap();

        let resolved = result.into_found().expect("should resolve successfully");
        // Both layers are awaited via join!. Relay has seq=5, DHT has seq=1.
        // Highest seq wins, so relay's seq=5 must be the result.
        assert_eq!(resolved.seq, 5);
    }

    #[tokio::test]
    async fn both_respond_dht_has_higher_seq() {
        // Relay responds fast with seq=1, DHT responds slow with seq=5.
        // With join!, both are awaited and the highest seq wins — DHT's seq=5.
        let (signing_key, did, _) = make_test_identity();
        let public_key = signing_key.verifying_key();

        // Create two versions.
        let doc_v1 = DidDocument::new(&did, public_key.as_bytes(), &[2u8; 32], &[3u8; 32]);
        let (value_v1, sig_v1) = sign_document(&signing_key, &doc_v1, 1);

        let doc_v5 = DidDocument::new(&did, public_key.as_bytes(), &[20u8; 32], &[30u8; 32]);
        let (value_v5, sig_v5) = sign_document(&signing_key, &doc_v5, 5);

        // Relay returns seq=1 (lower), fast (10ms).
        let relay = Arc::new(InMemoryRelayQuerier::with_delay(Duration::from_millis(10)));
        relay
            .insert(
                &did,
                RelayRecord {
                    value: value_v1,
                    signature: sig_v1,
                    seq: 1,
                    relay_url: "wss://relay1.example.com/scp/v1".to_owned(),
                },
            )
            .await;

        // DHT returns seq=5 (higher), slow (500ms — but still within timeout).
        let dht = Arc::new(DelayedDhtClient::new(Duration::from_millis(500)));
        dht.inner
            .publish(public_key.as_bytes(), &sig_v5, &value_v5, 5)
            .await
            .unwrap();

        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(Arc::clone(&clock)));
        let resolver = make_resolver(relay, dht, cache);

        let result = tokio::time::timeout(Duration::from_secs(2), resolver.resolve(&did))
            .await
            .expect("should not timeout")
            .unwrap();

        let resolved = result.into_found().expect("should resolve successfully");
        // With join!, both layers are awaited. DHT has higher seq (5), so it wins.
        assert_eq!(resolved.seq, 5);
        assert_eq!(resolved.source, ResolutionSource::MainlineDht);
    }

    #[tokio::test]
    async fn relay_fails_dht_result_accepted() {
        // Relay fails, DHT succeeds. DHT result should be returned.
        let (signing_key, did, doc) = make_test_identity();
        let (value, signature) = sign_document(&signing_key, &doc, 1);
        let public_key = signing_key.verifying_key();

        let relay = Arc::new(InMemoryRelayQuerier::with_delay(Duration::from_millis(10)));
        relay.set_should_fail(true).await;

        let dht = Arc::new(DelayedDhtClient::new(Duration::from_millis(10)));
        dht.inner
            .publish(public_key.as_bytes(), &signature, &value, 1)
            .await
            .unwrap();

        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(Arc::clone(&clock)));
        let resolver = make_resolver(relay, dht, cache);

        let result = tokio::time::timeout(Duration::from_secs(2), resolver.resolve(&did))
            .await
            .expect("should not timeout")
            .unwrap();

        let resolved = result.into_found().expect("should resolve successfully");
        assert_eq!(resolved.seq, 1);
        assert_eq!(resolved.source, ResolutionSource::MainlineDht);
    }

    #[tokio::test]
    async fn dht_fails_relay_result_accepted() {
        // DHT fails, relay succeeds. Relay result should be returned.
        let (signing_key, did, doc) = make_test_identity();
        let (value, signature) = sign_document(&signing_key, &doc, 1);

        let relay = Arc::new(InMemoryRelayQuerier::with_delay(Duration::from_millis(10)));
        relay
            .insert(
                &did,
                RelayRecord {
                    value,
                    signature,
                    seq: 1,
                    relay_url: "wss://relay1.example.com/scp/v1".to_owned(),
                },
            )
            .await;

        let dht = Arc::new(DelayedDhtClient::new(Duration::from_millis(10)));
        dht.set_should_fail(true).await;

        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(Arc::clone(&clock)));
        let resolver = make_resolver(relay, dht, cache);

        let result = tokio::time::timeout(Duration::from_secs(2), resolver.resolve(&did))
            .await
            .expect("should not timeout")
            .unwrap();

        let resolved = result.into_found().expect("should resolve successfully");
        assert_eq!(resolved.seq, 1);
        assert_eq!(
            resolved.source,
            ResolutionSource::ScpRelay {
                relay_url: "wss://relay1.example.com/scp/v1".to_owned()
            }
        );
    }

    #[tokio::test]
    async fn both_layers_failing_is_an_error_not_an_absence() {
        // §3.10.4 "Both layers fail": with no usable cache entry the resolver
        // reports DID_RESOLUTION_FAILED. Returning an absence here would tell
        // the caller nobody published the DID, which the resolver did not learn.
        let (_signing_key, did, _doc) = make_test_identity();

        let relay = Arc::new(InMemoryRelayQuerier::with_delay(Duration::from_millis(10)));
        relay.set_should_fail(true).await;

        let dht = Arc::new(DelayedDhtClient::new(Duration::from_millis(10)));
        dht.set_should_fail(true).await;

        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(Arc::clone(&clock)));
        let resolver = make_resolver(relay, dht, cache);

        let result = tokio::time::timeout(Duration::from_secs(2), resolver.resolve(&did))
            .await
            .expect("should not timeout");

        match result {
            Err(IdentityError::ResolutionFailed { did: failed, .. }) => assert_eq!(failed, did),
            other => panic!("both layers failed, expected ResolutionFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn relay_failure_is_distinguishable_from_a_did_nobody_published() {
        // §3.10.4 "One layer fails, the other reports the DID absent": the
        // absent result names the relay layer as unavailable, so a caller does
        // not read an unreachable relay as proof the DID does not exist.
        let (_signing_key, did, _doc) = make_test_identity();

        let relay = Arc::new(InMemoryRelayQuerier::with_delay(Duration::from_millis(10)));
        relay.set_should_fail(true).await;
        let dht = Arc::new(DelayedDhtClient::new(Duration::from_millis(10)));

        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(Arc::clone(&clock)));
        let resolver = make_resolver(relay, dht, cache);

        let result = tokio::time::timeout(Duration::from_secs(2), resolver.resolve(&did))
            .await
            .expect("should not timeout")
            .expect("the DHT answered, so resolution must not fail");

        match result {
            ResolutionOutcome::Absent { layers } => {
                assert_eq!(layers.relay, LayerStatus::Unavailable);
                assert_eq!(layers.dht, LayerStatus::Answered);
                assert!(layers.any_unavailable());
                assert_eq!(layers.unavailable_layers(), "SCP relay layer");
            }
            ResolutionOutcome::Found(doc) => panic!("nothing was published, yet got {doc:?}"),
        }
    }

    #[tokio::test]
    async fn neither_layer_has_document_returns_none() {
        // Neither layer has the document (no records stored). Should return Ok(None).
        let (_signing_key, did, _doc) = make_test_identity();

        let relay = Arc::new(InMemoryRelayQuerier::with_delay(Duration::from_millis(10)));
        let dht = Arc::new(DelayedDhtClient::new(Duration::from_millis(10)));

        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(Arc::clone(&clock)));
        let resolver = make_resolver(relay, dht, cache);

        let result = tokio::time::timeout(Duration::from_secs(2), resolver.resolve(&did))
            .await
            .expect("should not timeout")
            .unwrap();

        // Both layers ANSWERED and neither holds the document, so this is a
        // genuine absence — not a layer failure (§3.10.4).
        match result {
            ResolutionOutcome::Absent { layers } => {
                assert_eq!(layers.relay, LayerStatus::Answered);
                assert_eq!(layers.dht, LayerStatus::Answered);
            }
            ResolutionOutcome::Found(doc) => {
                panic!("no documents stored, yet resolution returned {doc:?}")
            }
        }
    }

    #[tokio::test]
    async fn cache_returns_cached_result() {
        // Pre-populate cache. Resolution should return from cache without
        // hitting either layer.
        let (_signing_key, did, doc) = make_test_identity();

        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(Arc::clone(&clock)));
        cache.insert(&did, doc.clone(), 3).await;

        // Both layers have 5s delay — should never be reached.
        let relay = Arc::new(InMemoryRelayQuerier::with_delay(Duration::from_secs(5)));
        let dht = Arc::new(DelayedDhtClient::new(Duration::from_secs(5)));

        let resolver = make_resolver(relay, dht, cache);

        let result = tokio::time::timeout(Duration::from_millis(100), resolver.resolve(&did))
            .await
            .expect("should return from cache immediately")
            .unwrap();

        let resolved = result.into_found().expect("should resolve from cache");
        assert_eq!(resolved.seq, 3);
        assert_eq!(resolved.source, ResolutionSource::Cache);
        assert_eq!(resolved.document, doc);
    }

    #[tokio::test]
    async fn result_is_cached_after_resolution() {
        // Resolve from DHT, then verify the result is cached.
        let (signing_key, did, doc) = make_test_identity();
        let (value, signature) = sign_document(&signing_key, &doc, 2);
        let public_key = signing_key.verifying_key();

        let relay = Arc::new(InMemoryRelayQuerier::with_delay(Duration::from_millis(10)));
        let dht = Arc::new(DelayedDhtClient::new(Duration::from_millis(10)));
        dht.inner
            .publish(public_key.as_bytes(), &signature, &value, 2)
            .await
            .unwrap();

        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(Arc::clone(&clock)));
        let resolver = make_resolver(relay, dht, Arc::clone(&cache));

        // First resolve — from DHT.
        let result = resolver.resolve(&did).await.unwrap();
        assert!(result.found().is_some());

        // Verify it's now cached.
        let cached = cache.get(&did).await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().sequence, 2);
    }

    #[tokio::test]
    async fn did_routing_id_is_deterministic() {
        let did = "did:dht:zTest123";
        let id1 = did_routing_id(did);
        let id2 = did_routing_id(did);
        assert_eq!(id1, id2, "did_routing_id should be deterministic");

        // Different DID produces different routing ID.
        let id3 = did_routing_id("did:dht:zOther456");
        assert_ne!(
            id1, id3,
            "different DIDs should produce different routing IDs"
        );
    }

    #[tokio::test]
    async fn did_routing_id_uses_domain_separator() {
        // Verify the domain separator "scp:did:" is used.
        let did = "did:dht:zTest123";
        let mut hasher = Sha256::new();
        hasher.update(b"scp:did:");
        hasher.update(did.as_bytes());
        let expected = hasher.finalize();
        let mut expected_bytes = [0u8; 32];
        expected_bytes.copy_from_slice(&expected);

        assert_eq!(
            did_routing_id(did),
            expected_bytes,
            "should use scp:did: domain separator"
        );
    }

    #[tokio::test]
    async fn resolved_did_document_has_correct_fields() {
        let doc = DidDocument::new("did:dht:zTest", &[1u8; 32], &[2u8; 32], &[3u8; 32]);
        let resolved = ResolvedDidDocument {
            document: doc.clone(),
            seq: 42,
            source: ResolutionSource::MainlineDht,
        };

        assert_eq!(resolved.document, doc);
        assert_eq!(resolved.seq, 42);
        assert_eq!(resolved.source, ResolutionSource::MainlineDht);
    }

    #[tokio::test]
    async fn resolution_source_variants() {
        // Verify all ResolutionSource variants exist and are distinct.
        let relay = ResolutionSource::ScpRelay {
            relay_url: "wss://relay.example.com/scp/v1".to_owned(),
        };
        let dht = ResolutionSource::MainlineDht;
        let cache = ResolutionSource::Cache;

        assert_ne!(relay, dht);
        assert_ne!(dht, cache);
        assert_ne!(relay, cache);
    }

    #[tokio::test]
    async fn relay_verification_error_logged_dht_still_resolves() {
        // Relay returns a document with a corrupt signature. DHT returns a valid
        // document. The resolver should log the relay verification error and
        // return the DHT result.
        let (signing_key, did, doc) = make_test_identity();
        let (value, signature) = sign_document(&signing_key, &doc, 1);
        let public_key = signing_key.verifying_key();

        // Relay: corrupt the signature so verification fails.
        let mut corrupt_sig = signature;
        corrupt_sig[0] ^= 0xFF;

        let relay = Arc::new(InMemoryRelayQuerier::with_delay(Duration::from_millis(10)));
        relay
            .insert(
                &did,
                RelayRecord {
                    value: value.clone(),
                    signature: corrupt_sig,
                    seq: 1,
                    relay_url: "wss://relay1.example.com/scp/v1".to_owned(),
                },
            )
            .await;

        // DHT: valid document.
        let dht = Arc::new(DelayedDhtClient::new(Duration::from_millis(10)));
        dht.inner
            .publish(public_key.as_bytes(), &signature, &value, 1)
            .await
            .unwrap();

        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(Arc::clone(&clock)));
        let resolver = make_resolver(relay, dht, cache);

        let result = tokio::time::timeout(Duration::from_secs(2), resolver.resolve(&did))
            .await
            .expect("should not timeout")
            .unwrap();

        // Relay's corrupt signature should be logged and ignored.
        // DHT's valid result should be returned.
        let resolved = result
            .into_found()
            .expect("should resolve from DHT despite relay verification error");
        assert_eq!(resolved.seq, 1);
        assert_eq!(resolved.source, ResolutionSource::MainlineDht);
        assert_eq!(resolved.document, doc);
    }

    #[tokio::test]
    async fn stale_seq_rejected_after_cache_expiry() {
        // Pre-populate cache with seq=5, then let it expire. Both layers
        // return seq=1 (validly signed but stale). Resolver must reject
        // both because seq=1 < cached seq=5.
        let (signing_key, did, doc) = make_test_identity();
        let (value, signature) = sign_document(&signing_key, &doc, 1);
        let public_key = signing_key.verifying_key();

        // Pre-populate cache with seq=5 to establish the high-water mark.
        let doc_v5 = DidDocument::new(&did, public_key.as_bytes(), &[20u8; 32], &[30u8; 32]);
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(Arc::clone(&clock)));
        cache.insert(&did, doc_v5, 5).await;

        // Expire the cache entry so the resolver queries both layers.
        clock.advance(8 * 24 * 60 * 60); // 8 days > 7-day inactive TTL

        // Both layers return seq=1 (stale).
        let relay = Arc::new(InMemoryRelayQuerier::with_delay(Duration::from_millis(10)));
        relay
            .insert(
                &did,
                RelayRecord {
                    value: value.clone(),
                    signature,
                    seq: 1,
                    relay_url: "wss://relay1.example.com/scp/v1".to_owned(),
                },
            )
            .await;

        let dht = Arc::new(DelayedDhtClient::new(Duration::from_millis(10)));
        dht.inner
            .publish(public_key.as_bytes(), &signature, &value, 1)
            .await
            .unwrap();

        let resolver = make_resolver(relay, dht, cache);

        let error = tokio::time::timeout(Duration::from_secs(2), resolver.resolve(&did))
            .await
            .expect("should not timeout")
            .expect_err(
                "both layers served a replayed seq=1 record and the resolver discarded both, so \
                 neither layer reported on the DID",
            );

        // A replay is a suppression attempt, not a report that the layer holds
        // nothing. Reporting `Absent { relay: Answered, dht: Answered }` here
        // would tell the caller nobody published a DID whose owner is publishing
        // it at seq=5. The 8-day-old cache entry is past the §3.10.4 7-day
        // bound, so the resolver has nothing left to serve and fails.
        assert!(
            matches!(error, IdentityError::ResolutionFailed { .. }),
            "expected ResolutionFailed, got {error:?}"
        );
    }

    /// Both layers rejected for staleness, with a cache entry inside the
    /// §3.10.4 7-day bound: the resolver serves the cached document rather than
    /// failing the caller's UCAN or attestation check.
    #[tokio::test]
    async fn both_layers_unavailable_serves_a_cached_document_under_seven_days() {
        let (signing_key, did, doc) = make_test_identity();
        let (value, signature) = sign_document(&signing_key, &doc, 1);
        let public_key = signing_key.verifying_key();

        let doc_v5 = DidDocument::new(&did, public_key.as_bytes(), &[20u8; 32], &[30u8; 32]);
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(Arc::clone(&clock)));
        cache.insert(&did, doc_v5, 5).await;
        // Mark the DID an active contact, whose refresh TTL is 24 hours, then
        // advance past that TTL but stay inside the 7-day bound.
        cache.mark_active(&did).await;
        clock.advance(30 * 60 * 60);

        // Both layers replay seq=1, which the rollback guard discards.
        let relay = Arc::new(InMemoryRelayQuerier::with_delay(Duration::from_millis(10)));
        relay
            .insert(
                &did,
                RelayRecord {
                    value: value.clone(),
                    signature,
                    seq: 1,
                    relay_url: "wss://relay1.example.com/scp/v1".to_owned(),
                },
            )
            .await;
        let dht = Arc::new(DelayedDhtClient::new(Duration::from_millis(10)));
        dht.inner
            .publish(public_key.as_bytes(), &signature, &value, 1)
            .await
            .unwrap();

        let resolver = make_resolver(relay, dht, Arc::clone(&cache));

        let outcome = tokio::time::timeout(Duration::from_secs(2), resolver.resolve(&did))
            .await
            .expect("should not timeout")
            .expect("a cached document under 7 days old is served when no layer answers");

        let found = outcome.found().expect("the cached document is served");
        assert_eq!(
            found.seq, 5,
            "the cached seq=5 document, not the seq=1 replay"
        );
        assert!(
            matches!(found.source, ResolutionSource::Cache),
            "§3.10.4 labels this answer resolution_source: cache, got {:?}",
            found.source
        );
    }

    #[tokio::test]
    async fn fresh_seq_accepted_after_cache_expiry() {
        // Pre-populate cache with seq=5, expire it. DHT returns seq=7
        // (fresh). Should be accepted.
        let (signing_key, did, _) = make_test_identity();
        let public_key = signing_key.verifying_key();

        let doc_v5 = DidDocument::new(&did, public_key.as_bytes(), &[20u8; 32], &[30u8; 32]);
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(Arc::clone(&clock)));
        cache.insert(&did, doc_v5, 5).await;

        // Expire the cache.
        clock.advance(8 * 24 * 60 * 60);

        let doc_v7 = DidDocument::new(&did, public_key.as_bytes(), &[70u8; 32], &[71u8; 32]);
        let (value_v7, sig_v7) = sign_document(&signing_key, &doc_v7, 7);

        let relay = Arc::new(InMemoryRelayQuerier::with_delay(Duration::from_millis(10)));
        let dht = Arc::new(DelayedDhtClient::new(Duration::from_millis(10)));
        dht.inner
            .publish(public_key.as_bytes(), &sig_v7, &value_v7, 7)
            .await
            .unwrap();

        let resolver = make_resolver(relay, dht, cache);

        let result = tokio::time::timeout(Duration::from_secs(2), resolver.resolve(&did))
            .await
            .expect("should not timeout")
            .unwrap();

        let resolved = result
            .into_found()
            .expect("seq=7 > cached seq=5, should be accepted");
        assert_eq!(resolved.seq, 7);
    }

    // -----------------------------------------------------------------------
    // Protocol-level healing tests (§3.10.7, SCP-245)
    // -----------------------------------------------------------------------

    /// A recorded healing call for test assertions.
    #[derive(Debug, Clone)]
    struct RecordedHeal {
        did: String,
        stale_layer: StaleLayer,
        document_bytes: Vec<u8>,
        signature: [u8; 64],
        seq: u64,
        public_key: [u8; 32],
    }

    /// In-memory healing publisher for testing (SCP-245).
    ///
    /// Records all `heal()` calls so tests can inspect which layer was healed,
    /// the document bytes, and the sequence number.
    struct InMemoryHealingPublisher {
        heals: Mutex<Vec<RecordedHeal>>,
        should_fail: Mutex<bool>,
    }

    impl InMemoryHealingPublisher {
        fn new() -> Self {
            Self {
                heals: Mutex::new(Vec::new()),
                should_fail: Mutex::new(false),
            }
        }

        async fn recorded_heals(&self) -> Vec<RecordedHeal> {
            let heals = self.heals.lock().await;
            heals.clone()
        }

        async fn set_should_fail(&self, fail: bool) {
            let mut should_fail = self.should_fail.lock().await;
            *should_fail = fail;
        }
    }

    #[allow(clippy::manual_async_fn)]
    impl HealingPublisher for InMemoryHealingPublisher {
        fn heal(
            &self,
            did: &str,
            stale_layer: &StaleLayer,
            document_bytes: &[u8],
            signature: &[u8; 64],
            seq: u64,
            public_key: &[u8; 32],
        ) -> impl Future<Output = Result<(), IdentityError>> + Send {
            let stale_layer = stale_layer.clone();
            async move {
                let fail = *self.should_fail.lock().await;
                if fail {
                    return Err(IdentityError::RelayPublishFailed(
                        "healing publish failed (test)".to_owned(),
                    ));
                }
                let mut heals = self.heals.lock().await;
                heals.push(RecordedHeal {
                    did: did.to_owned(),
                    stale_layer,
                    document_bytes: document_bytes.to_vec(),
                    signature: *signature,
                    seq,
                    public_key: *public_key,
                });
                drop(heals);
                Ok(())
            }
        }
    }

    /// Creates a `DualLayerResolver` with healing enabled.
    fn make_resolver_with_healing<R: MultiRelayQuerier, D: DhtClient>(
        relay: Arc<R>,
        dht: Arc<D>,
        cache: Arc<DidCache<Arc<TestClock>>>,
        healer: Arc<InMemoryHealingPublisher>,
    ) -> DualLayerResolver<R, D, Arc<TestClock>, InMemoryHealingPublisher> {
        DualLayerResolver::with_healing(
            relay,
            dht,
            cache,
            Arc::new(vec!["wss://bootstrap.example.com/scp/v1".to_owned()]),
            healer,
        )
    }

    #[tokio::test]
    async fn healing_triggered_when_relay_stale_dht_fresher() {
        // Relay returns seq=1, DHT returns seq=5. The resolver should trigger
        // healing to republish the DHT's seq=5 document to the relay layer.
        let (signing_key, did, _) = make_test_identity();
        let public_key = signing_key.verifying_key();

        // Relay: seq=1 (stale).
        let doc_v1 = DidDocument::new(&did, public_key.as_bytes(), &[2u8; 32], &[3u8; 32]);
        let (value_v1, sig_v1) = sign_document(&signing_key, &doc_v1, 1);

        let relay = Arc::new(InMemoryRelayQuerier::with_delay(Duration::from_millis(10)));
        relay
            .insert(
                &did,
                RelayRecord {
                    value: value_v1,
                    signature: sig_v1,
                    seq: 1,
                    relay_url: "wss://relay1.example.com/scp/v1".to_owned(),
                },
            )
            .await;

        // DHT: seq=5 (fresher).
        let doc_v5 = DidDocument::new(&did, public_key.as_bytes(), &[20u8; 32], &[30u8; 32]);
        let (value_v5, sig_v5) = sign_document(&signing_key, &doc_v5, 5);

        let dht = Arc::new(DelayedDhtClient::new(Duration::from_millis(10)));
        dht.inner
            .publish(public_key.as_bytes(), &sig_v5, &value_v5, 5)
            .await
            .unwrap();

        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(Arc::clone(&clock)));
        let healer = Arc::new(InMemoryHealingPublisher::new());
        let resolver =
            make_resolver_with_healing(relay, dht, Arc::clone(&cache), Arc::clone(&healer));

        let result = tokio::time::timeout(Duration::from_secs(2), resolver.resolve(&did))
            .await
            .expect("should not timeout")
            .unwrap();

        // DHT's seq=5 should win.
        let resolved = result.into_found().expect("should resolve successfully");
        assert_eq!(resolved.seq, 5);
        assert_eq!(resolved.source, ResolutionSource::MainlineDht);

        // Give the spawned healing task time to complete.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Verify healing was triggered: DHT doc republished to relay layer.
        let heals = healer.recorded_heals().await;
        assert_eq!(heals.len(), 1, "exactly one healing call expected");
        assert!(matches!(heals[0].stale_layer, StaleLayer::Relay { .. }));
        assert_eq!(heals[0].seq, 5);
        assert_eq!(heals[0].did, did);
        assert_eq!(heals[0].public_key, *public_key.as_bytes());
        // The raw document bytes should be the DHT's fresher document.
        assert_eq!(heals[0].document_bytes, value_v5);
        assert_eq!(heals[0].signature, sig_v5);
    }

    #[tokio::test]
    async fn healing_triggered_when_dht_stale_relay_fresher() {
        // Relay returns seq=5, DHT returns seq=1. The resolver should trigger
        // healing to republish the relay's seq=5 document to the DHT layer.
        let (signing_key, did, _) = make_test_identity();
        let public_key = signing_key.verifying_key();

        // Relay: seq=5 (fresher).
        let doc_v5 = DidDocument::new(&did, public_key.as_bytes(), &[20u8; 32], &[30u8; 32]);
        let (value_v5, sig_v5) = sign_document(&signing_key, &doc_v5, 5);

        let relay = Arc::new(InMemoryRelayQuerier::with_delay(Duration::from_millis(10)));
        relay
            .insert(
                &did,
                RelayRecord {
                    value: value_v5.clone(),
                    signature: sig_v5,
                    seq: 5,
                    relay_url: "wss://relay1.example.com/scp/v1".to_owned(),
                },
            )
            .await;

        // DHT: seq=1 (stale).
        let doc_v1 = DidDocument::new(&did, public_key.as_bytes(), &[2u8; 32], &[3u8; 32]);
        let (value_v1, sig_v1) = sign_document(&signing_key, &doc_v1, 1);

        let dht = Arc::new(DelayedDhtClient::new(Duration::from_millis(10)));
        dht.inner
            .publish(public_key.as_bytes(), &sig_v1, &value_v1, 1)
            .await
            .unwrap();

        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(Arc::clone(&clock)));
        let healer = Arc::new(InMemoryHealingPublisher::new());
        let resolver =
            make_resolver_with_healing(relay, dht, Arc::clone(&cache), Arc::clone(&healer));

        let result = tokio::time::timeout(Duration::from_secs(2), resolver.resolve(&did))
            .await
            .expect("should not timeout")
            .unwrap();

        // Relay's seq=5 should win.
        let resolved = result.into_found().expect("should resolve successfully");
        assert_eq!(resolved.seq, 5);
        assert_eq!(
            resolved.source,
            ResolutionSource::ScpRelay {
                relay_url: "wss://relay1.example.com/scp/v1".to_owned()
            }
        );

        // Give the spawned healing task time to complete.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Verify healing was triggered: relay doc republished to DHT layer.
        let heals = healer.recorded_heals().await;
        assert_eq!(heals.len(), 1, "exactly one healing call expected");
        assert_eq!(heals[0].stale_layer, StaleLayer::Dht);
        assert_eq!(heals[0].seq, 5);
        assert_eq!(heals[0].did, did);
        assert_eq!(heals[0].public_key, *public_key.as_bytes());
        // The raw document bytes should be the relay's fresher document.
        assert_eq!(heals[0].document_bytes, value_v5);
        assert_eq!(heals[0].signature, sig_v5);
    }

    #[tokio::test]
    async fn healing_not_triggered_when_seqs_equal() {
        // Both layers return seq=3. No healing should be triggered.
        let (signing_key, did, doc) = make_test_identity();
        let (value, signature) = sign_document(&signing_key, &doc, 3);
        let public_key = signing_key.verifying_key();

        let relay = Arc::new(InMemoryRelayQuerier::with_delay(Duration::from_millis(10)));
        relay
            .insert(
                &did,
                RelayRecord {
                    value: value.clone(),
                    signature,
                    seq: 3,
                    relay_url: "wss://relay1.example.com/scp/v1".to_owned(),
                },
            )
            .await;

        let dht = Arc::new(DelayedDhtClient::new(Duration::from_millis(10)));
        dht.inner
            .publish(public_key.as_bytes(), &signature, &value, 3)
            .await
            .unwrap();

        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(Arc::clone(&clock)));
        let healer = Arc::new(InMemoryHealingPublisher::new());
        let resolver =
            make_resolver_with_healing(relay, dht, Arc::clone(&cache), Arc::clone(&healer));

        let result = tokio::time::timeout(Duration::from_secs(2), resolver.resolve(&did))
            .await
            .expect("should not timeout")
            .unwrap();

        let resolved = result.into_found().expect("should resolve");
        assert_eq!(resolved.seq, 3);

        // Give time for any healing task to complete (there should be none).
        tokio::time::sleep(Duration::from_millis(100)).await;

        let heals = healer.recorded_heals().await;
        assert!(
            heals.is_empty(),
            "no healing should be triggered when seqs are equal"
        );
    }

    #[tokio::test]
    async fn healing_not_triggered_when_only_one_layer_responds() {
        // Only relay responds (DHT has no document). No healing.
        let (signing_key, did, doc) = make_test_identity();
        let (value, signature) = sign_document(&signing_key, &doc, 3);

        let relay = Arc::new(InMemoryRelayQuerier::with_delay(Duration::from_millis(10)));
        relay
            .insert(
                &did,
                RelayRecord {
                    value,
                    signature,
                    seq: 3,
                    relay_url: "wss://relay1.example.com/scp/v1".to_owned(),
                },
            )
            .await;

        let dht = Arc::new(DelayedDhtClient::new(Duration::from_millis(10)));
        // DHT has no document stored.

        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(Arc::clone(&clock)));
        let healer = Arc::new(InMemoryHealingPublisher::new());
        let resolver =
            make_resolver_with_healing(relay, dht, Arc::clone(&cache), Arc::clone(&healer));

        let result = tokio::time::timeout(Duration::from_secs(2), resolver.resolve(&did))
            .await
            .expect("should not timeout")
            .unwrap();

        let resolved = result.into_found().expect("should resolve from relay");
        assert_eq!(resolved.seq, 3);

        tokio::time::sleep(Duration::from_millis(100)).await;

        let heals = healer.recorded_heals().await;
        assert!(heals.is_empty(), "no healing when only one layer responds");
    }

    #[tokio::test]
    async fn healing_failure_does_not_affect_resolve_result() {
        // Relay returns seq=1, DHT returns seq=5. Healing publisher is
        // configured to fail. The resolve result should still be the fresher
        // document (seq=5), and the healing failure should be silently
        // absorbed (logged but not propagated).
        let (signing_key, did, _) = make_test_identity();
        let public_key = signing_key.verifying_key();

        // Relay: seq=1 (stale).
        let doc_v1 = DidDocument::new(&did, public_key.as_bytes(), &[2u8; 32], &[3u8; 32]);
        let (value_v1, sig_v1) = sign_document(&signing_key, &doc_v1, 1);

        let relay = Arc::new(InMemoryRelayQuerier::with_delay(Duration::from_millis(10)));
        relay
            .insert(
                &did,
                RelayRecord {
                    value: value_v1,
                    signature: sig_v1,
                    seq: 1,
                    relay_url: "wss://relay1.example.com/scp/v1".to_owned(),
                },
            )
            .await;

        // DHT: seq=5 (fresher).
        let doc_v5 = DidDocument::new(&did, public_key.as_bytes(), &[20u8; 32], &[30u8; 32]);
        let (value_v5, sig_v5) = sign_document(&signing_key, &doc_v5, 5);

        let dht = Arc::new(DelayedDhtClient::new(Duration::from_millis(10)));
        dht.inner
            .publish(public_key.as_bytes(), &sig_v5, &value_v5, 5)
            .await
            .unwrap();

        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(Arc::clone(&clock)));

        // Healing publisher configured to FAIL.
        let healer = Arc::new(InMemoryHealingPublisher::new());
        healer.set_should_fail(true).await;

        let resolver =
            make_resolver_with_healing(relay, dht, Arc::clone(&cache), Arc::clone(&healer));

        let result = tokio::time::timeout(Duration::from_secs(2), resolver.resolve(&did))
            .await
            .expect("should not timeout")
            .unwrap();

        // The resolve result must NOT be affected by healing failure.
        let resolved = result
            .into_found()
            .expect("should resolve despite healing failure");
        assert_eq!(resolved.seq, 5);
        assert_eq!(resolved.source, ResolutionSource::MainlineDht);

        // Give the spawned healing task time to attempt and fail.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // The healing publisher was called but failed. No recorded heals
        // (the failure path does not record the call).
        let heals = healer.recorded_heals().await;
        assert!(heals.is_empty(), "healing failure should not record a heal");
    }

    #[tokio::test]
    async fn healing_not_triggered_without_healing_publisher() {
        // Use the regular make_resolver (no healing). Seq divergence should
        // NOT trigger healing (no publisher configured).
        let (signing_key, did, _) = make_test_identity();
        let public_key = signing_key.verifying_key();

        let doc_v1 = DidDocument::new(&did, public_key.as_bytes(), &[2u8; 32], &[3u8; 32]);
        let (value_v1, sig_v1) = sign_document(&signing_key, &doc_v1, 1);

        let relay = Arc::new(InMemoryRelayQuerier::with_delay(Duration::from_millis(10)));
        relay
            .insert(
                &did,
                RelayRecord {
                    value: value_v1,
                    signature: sig_v1,
                    seq: 1,
                    relay_url: "wss://relay1.example.com/scp/v1".to_owned(),
                },
            )
            .await;

        let doc_v5 = DidDocument::new(&did, public_key.as_bytes(), &[20u8; 32], &[30u8; 32]);
        let (value_v5, sig_v5) = sign_document(&signing_key, &doc_v5, 5);

        let dht = Arc::new(DelayedDhtClient::new(Duration::from_millis(10)));
        dht.inner
            .publish(public_key.as_bytes(), &sig_v5, &value_v5, 5)
            .await
            .unwrap();

        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(Arc::clone(&clock)));
        let resolver = make_resolver(relay, dht, cache);

        let result = tokio::time::timeout(Duration::from_secs(2), resolver.resolve(&did))
            .await
            .expect("should not timeout")
            .unwrap();

        // Should still resolve correctly.
        let resolved = result.into_found().expect("should resolve");
        assert_eq!(resolved.seq, 5);

        // No healing publisher configured — nothing should happen (no panic).
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // -----------------------------------------------------------------------
    // verifying_key_from_document (ADR-053 / spec §10.17, SHB-008)
    // -----------------------------------------------------------------------

    /// The hoisted pure extraction resolves the requested verification method,
    /// honors the `SigningKeyId` (Active vs Agent are distinct keys, never
    /// collapsed), and returns `None` when the requested method is absent.
    ///
    /// Builds a DID document with distinct `#active` and `#agent` verification
    /// methods (via [`DidDocument::new_with_agent_key`]) and asserts:
    /// - `SigningKeyId::Active` → `Some(active_key)`;
    /// - `SigningKeyId::Agent` → `Some(agent_key)`, distinct from the active key;
    /// - a document with NO `#agent` method → `None` for `SigningKeyId::Agent`.
    #[test]
    fn verifying_key_from_document_resolves_active_agent_and_rejects_missing() {
        // Distinct Ed25519 keys for identity (#0), active (#active), and agent
        // (#agent) so the SigningKeyId routing is observable, not a coincidence.
        let active_signing = SigningKey::from_bytes(&[7u8; 32]);
        let agent_signing = SigningKey::from_bytes(&[9u8; 32]);
        let active_key = active_signing.verifying_key();
        let agent_key = agent_signing.verifying_key();
        assert_ne!(
            active_key.as_bytes(),
            agent_key.as_bytes(),
            "test setup: active and agent keys must differ"
        );

        let identity_pub = SigningKey::from_bytes(&[5u8; 32]).verifying_key();
        let did = format!("did:dht:z{}", zbase32::encode(identity_pub.as_bytes()));

        // Document carrying BOTH #active and #agent (ADR-039 shared-DID shape).
        let doc_with_agent = DidDocument::new_with_agent_key(
            &did,
            identity_pub.as_bytes(),
            active_key.as_bytes(),
            &[3u8; 32],
            Some(agent_key.as_bytes()),
        );

        // Active resolves to the active key.
        let resolved_active = verifying_key_from_document(&doc_with_agent, SigningKeyId::Active)
            .expect("active VM must resolve");
        assert_eq!(
            resolved_active.as_bytes(),
            active_key.as_bytes(),
            "SigningKeyId::Active must return the #active key"
        );

        // Agent resolves to the agent key — distinct from active (kid honored).
        let resolved_agent = verifying_key_from_document(&doc_with_agent, SigningKeyId::Agent)
            .expect("agent VM must resolve");
        assert_eq!(
            resolved_agent.as_bytes(),
            agent_key.as_bytes(),
            "SigningKeyId::Agent must return the #agent key"
        );
        assert_ne!(
            resolved_agent.as_bytes(),
            resolved_active.as_bytes(),
            "the Agent key must be distinct from the Active key — the SigningKeyId \
             is honored, not ignored"
        );

        // A document with NO #agent method returns None for the agent lookup
        // (the requested verification method is absent).
        let doc_no_agent = DidDocument::new(
            &did,
            identity_pub.as_bytes(),
            active_key.as_bytes(),
            &[3u8; 32],
        );
        assert!(
            verifying_key_from_document(&doc_no_agent, SigningKeyId::Agent).is_none(),
            "a missing #agent verification method must resolve to None"
        );
        // The active key is still resolvable on the agent-less document.
        assert!(
            verifying_key_from_document(&doc_no_agent, SigningKeyId::Active).is_some(),
            "the #active method is present and must still resolve"
        );
    }
}
