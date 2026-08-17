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
//! - [`ResolvedDidDocument`] — Resolution result with provenance metadata.
//! - [`ResolutionSource`] — Which layer served the document.
//! - [`MultiRelayQuerier`] — Trait abstracting SCP relay QUERY operations.
//! - [`HealingPublisher`] — Trait abstracting republish to a stale layer (§3.10.7).
//! - [`DualLayerResolver`] — Composes relay + DHT resolution in parallel.
//!
//! See SCP-241 and SCP-245 in `.docs/prds/reachability.json`.

use std::cmp::Ordering;
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::IdentityError;
use crate::cache::DidCache;
use crate::dht::extract_public_key;
use crate::republish::RelayPublisher;
use crate::resolution::verify_relay_record;
use scp_clock::{Clock, SystemClock};
use scp_dht::{DhtClient, DhtRecord};
use scp_did::DidDocument;
use scp_protocol::envelope::did_record::DidRecordV1;

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
    /// Returns `Ok(Some(resolved))` if the DID was found on any layer or in
    /// cache. Returns `Ok(None)` if neither layer has the document and the
    /// cache is empty. Returns `Err(...)` only on unrecoverable errors.
    fn resolve(
        &self,
        did: &str,
    ) -> impl Future<Output = Result<Option<ResolvedDidDocument>, IdentityError>> + Send;
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
    /// `Ok(Some(record))` if a relay has the document. `Ok(None)` if no relay
    /// has it. `Err(...)` on network/protocol errors.
    fn query(
        &self,
        did: &str,
        relay_urls: &[String],
    ) -> impl Future<Output = Result<Option<RelayRecord>, IdentityError>> + Send;
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
    /// # Why a `&DidRecordV1` and not four loose fields
    ///
    /// The fresher record's `(public_key, seq, signature, value)` is one
    /// indivisible BEP44 unit: a signature only verifies against the exact
    /// `(value, seq)` it was made over, and only under the key the DID binds to.
    /// Passing them as four positional parameters let a caller reorder or mix
    /// them silently, and made "the public key" a second, independently-supplied
    /// answer to a question the record already answers. `DidRecordV1` can only
    /// be built through the validating [`DidRecordV1::try_new`], so both layers
    /// receive one already-well-formed unit (see
    /// [`RelayPublisher`] for the same
    /// discipline on the publish path).
    ///
    /// # Arguments
    ///
    /// * `did` — The DID string whose document diverged across layers. Used for
    ///   log correlation; the authoritative key is `record.public_key()`.
    /// * `stale_layer` — Which layer had the stale document.
    /// * `record` — The fresher signed record to republish.
    ///
    /// # Errors
    ///
    /// Returns `Err` on publish failure. The caller logs the error and
    /// discards it (best-effort healing).
    fn heal(
        &self,
        did: &str,
        stale_layer: &StaleLayer,
        record: &DidRecordV1,
    ) -> impl Future<Output = Result<(), IdentityError>> + Send;
}

// `verify_relay_record` (imported from `crate::resolution`) is the single shared
// BEP44-verify + UTF-8/JSON-deser + self-cert path used by both this resolver
// and `RealMultiRelayQuerier`, ensuring relay and DHT records are validated
// identically without duplication.

// ---------------------------------------------------------------------------
// DualLayerResolver
// ---------------------------------------------------------------------------

/// Per-layer timeout for parallel resolution. Each of the relay and DHT
/// layers is given this much time to respond before being treated as a
/// timeout (returning `Ok(None)`).
const LAYER_TIMEOUT: Duration = Duration::from_secs(10);

/// Composes SCP relay QUERY with Mainline DHT resolution in parallel.
///
/// On `resolve()`:
/// 1. Check cache. If a fresh entry exists, return with `ResolutionSource::Cache`.
/// 2. Extract the public key from the DID string.
/// 3. Initiate both relay QUERY and DHT resolve concurrently via `tokio::join!`
///    with per-layer 10-second timeouts.
/// 4. Both layers are awaited; the result with the highest sequence number wins.
/// 5. On a seq tie, the relay result is preferred (lower latency for subsequent ops).
/// 6. When one layer times out, the other's valid result is used.
/// 7. When both fail or return nothing, returns `Ok(None)`.
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
    H: HealingPublisher = NoOpHealer,
> {
    relay_querier: Arc<R>,
    dht_client: Arc<D>,
    cache: Arc<DidCache<C>>,
    /// Bootstrap relay URLs used when the identity's relays are not known.
    bootstrap_relays: Vec<String>,
    /// Optional healing publisher for protocol-level healing (§3.10.7, SCP-245).
    ///
    /// When set, the resolver triggers an asynchronous best-effort republish
    /// of the fresher document to the layer that returned a stale copy.
    healing_publisher: Option<Arc<H>>,
}

/// A no-op healing publisher used as the default type parameter.
///
/// This exists only to provide a concrete default for the `H` type parameter
/// on [`DualLayerResolver`] so that existing construction sites that do not
/// need healing remain unchanged.
pub struct NoOpHealer;

#[allow(clippy::manual_async_fn)]
impl HealingPublisher for NoOpHealer {
    fn heal(
        &self,
        _did: &str,
        _stale_layer: &StaleLayer,
        _record: &DidRecordV1,
    ) -> impl Future<Output = Result<(), IdentityError>> + Send {
        async { Ok(()) }
    }
}

/// A no-op relay querier that always returns `Ok(None)`.
///
/// Used when no production relay querier is available (e.g., before transport
/// setup). The `DualLayerResolver` falls back to DHT-only resolution when the
/// relay layer returns `None`.
pub struct NoOpRelayQuerier;

#[allow(clippy::manual_async_fn)]
impl MultiRelayQuerier for NoOpRelayQuerier {
    fn query(
        &self,
        _did: &str,
        _relay_urls: &[String],
    ) -> impl Future<Output = Result<Option<RelayRecord>, IdentityError>> + Send {
        async { Ok(None) }
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
        record: &DidRecordV1,
    ) -> impl Future<Output = Result<(), IdentityError>> + Send {
        let dht_client = Arc::clone(&self.dht_client);
        let relay_publisher = Arc::clone(&self.relay_publisher);
        let stale_layer = stale_layer.clone();
        let did = did.to_owned();
        // The record arrives already framed and validated, so both arms read
        // the SAME `(public_key, seq, signature, value)` unit.
        let public_key = *record.public_key();
        let signature = *record.signature();
        let seq = record.seq();
        let document_bytes = record.value().to_vec();
        let record = record.clone();

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
                    // Healing publishes the SAME self-certifying frame the
                    // republish loop does. The publisher distributes it to the
                    // identity's own relays + bootstrap relays (§18.5.1) and
                    // derives the routing_id from the frame's own key; the heal
                    // arm never passes one.
                    debug!(did = %did, seq, "healing: republishing to relay");
                    relay_publisher
                        .publish(DID_DOCUMENT_BLOB_TTL_SECS, &record)
                        .await
                        .map(|_| ())
                }
            }
        }
    }
}

impl<R: MultiRelayQuerier, D: DhtClient, C: Clock> DualLayerResolver<R, D, C> {
    /// Creates a new dual-layer resolver without healing.
    #[must_use]
    pub const fn new(
        relay_querier: Arc<R>,
        dht_client: Arc<D>,
        cache: Arc<DidCache<C>>,
        bootstrap_relays: Vec<String>,
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
        bootstrap_relays: Vec<String>,
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
    ) -> impl Future<Output = Result<Option<ResolvedDidDocument>, IdentityError>> + Send {
        let did = did.to_owned();
        let relay_querier = Arc::clone(&self.relay_querier);
        let dht_client = Arc::clone(&self.dht_client);
        let cache = Arc::clone(&self.cache);
        let bootstrap_relays = self.bootstrap_relays.clone();
        let healing_publisher = self.healing_publisher.clone();

        async move {
            // Step 1: Check cache for a fresh entry.
            if let Some(cached) = cache.get(&did).await {
                return Ok(Some(ResolvedDidDocument {
                    document: cached.document,
                    seq: cached.sequence,
                    source: ResolutionSource::Cache,
                }));
            }

            // Step 2: Extract the public key from the DID string.
            let public_key = extract_public_key(&did)?;

            // Step 3: Determine relay URLs.
            // Use cached relay URLs (even from expired entries) to prefer an
            // identity's known relays over bootstrap relays. Falls back to
            // bootstrap relays when no cached entry exists at all.
            let relay_urls = cache
                .cached_relay_urls(&did)
                .await
                .unwrap_or(bootstrap_relays);

            // Step 4: Initiate both layers in parallel using tokio::join!
            // with per-layer timeouts (LAYER_TIMEOUT). Both layers are
            // awaited; the result with the highest sequence number wins.
            let relay_fut = async {
                match tokio::time::timeout(LAYER_TIMEOUT, relay_querier.query(&did, &relay_urls))
                    .await
                {
                    Ok(result) => result,
                    Err(_elapsed) => {
                        debug!(did = %did, "relay layer timed out");
                        Ok(None)
                    }
                }
            };
            let dht_fut = async {
                match tokio::time::timeout(LAYER_TIMEOUT, dht_client.resolve(&public_key)).await {
                    Ok(result) => result,
                    Err(_elapsed) => {
                        debug!(did = %did, "DHT layer timed out");
                        Ok(None)
                    }
                }
            };

            let (relay_result, dht_result) = tokio::join!(relay_fut, dht_fut);

            // Validate both results independently. The validate functions
            // return `ValidatedRecord` which bundles the resolved document with
            // the raw BEP44 bytes and signature needed for healing (SCP-245).
            let relay_validated = validate_relay_result(relay_result, &did, &public_key);
            // The DHT transport yields `DhtError`; map it into `IdentityError`
            // so `validate_dht_result` keeps its single error taxonomy.
            let dht_validated =
                validate_dht_result(dht_result.map_err(IdentityError::from), &did, &public_key);

            // Step 5: Reject results with sequence numbers lower than the
            // last known cached sequence. Prevents rollback attacks where an
            // attacker serves a validly-signed but outdated document after
            // cache TTL expiry.
            let cached_seq = cache.cached_sequence(&did).await;
            let relay_validated = relay_validated.and_then(|rec| {
                if let Some(min_seq) = cached_seq
                    && rec.resolved.seq < min_seq
                {
                    warn!(
                        did = %did,
                        received_seq = rec.resolved.seq,
                        cached_seq = min_seq,
                        "relay returned stale seq, rejecting"
                    );
                    return None;
                }
                Some(rec)
            });
            let dht_validated = dht_validated.and_then(|rec| {
                if let Some(min_seq) = cached_seq
                    && rec.resolved.seq < min_seq
                {
                    warn!(
                        did = %did,
                        received_seq = rec.resolved.seq,
                        cached_seq = min_seq,
                        "DHT returned stale seq, rejecting"
                    );
                    return None;
                }
                Some(rec)
            });

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

            Ok(result)
        }
    }
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
                Ordering::Equal => None,
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
    let stale = healing.stale_layer;
    let fresher_seq = healing.fresher_seq;

    // Frame ONCE, here, before either layer is touched. A framing failure means
    // NOTHING was published to either layer, so it is reported as a framing
    // error — never as a relay/DHT publish failure, which would misattribute a
    // local well-formedness bug to a remote layer.
    let record = match DidRecordV1::try_new(
        *public_key,
        fresher_seq,
        healing.raw_signature,
        healing.raw_value,
    )
    .map_err(|e| {
        IdentityError::DidRecordFramingFailed(format!(
            "healing: fresher DID document cannot be wrapped into a DID-record \
             frame (§9.10.12): {e}"
        ))
    }) {
        Ok(record) => record,
        Err(e) => {
            warn!(
                did = %did_owned,
                stale_layer = ?stale,
                error = %e,
                "protocol-level healing skipped — nothing was published to either \
                 layer (best-effort, §3.10.7)"
            );
            return;
        }
    };

    info!(
        did = %did_owned,
        fresher_seq = fresher_seq,
        stale_layer = ?stale,
        "triggering protocol-level healing (§3.10.7)"
    );

    let handle = tokio::spawn(async move {
        if let Err(e) = healer.heal(&did_owned, &stale, &record).await {
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

/// Validates a relay resolution result: verifies BEP44 signature, deserializes
/// document, and wraps in `ValidatedRecord`.
///
/// Network errors and verification failures are logged (not silently swallowed)
/// and mapped to `None` so that the other layer can still provide a result.
///
/// The raw BEP44 bytes and signature are retained in the `ValidatedRecord` for
/// protocol-level healing (§3.10.7, SCP-245).
fn validate_relay_result(
    result: Result<Option<RelayRecord>, IdentityError>,
    did: &str,
    public_key: &[u8; 32],
) -> Option<ValidatedRecord> {
    let record = match result {
        Ok(Some(record)) => record,
        Ok(None) => {
            debug!(did, "relay returned no document");
            return None;
        }
        Err(e) => {
            debug!(did, error = %e, "relay query failed");
            return None;
        }
    };

    match verify_relay_record(
        did,
        public_key,
        &record.value,
        &record.signature,
        record.seq,
    ) {
        Ok(document) => Some(ValidatedRecord {
            resolved: ResolvedDidDocument {
                document,
                seq: record.seq,
                source: ResolutionSource::ScpRelay {
                    relay_url: record.relay_url,
                },
            },
            raw_value: record.value,
            raw_signature: record.signature,
        }),
        Err(e) => {
            warn!(did, error = %e, "relay record verification failed");
            None
        }
    }
}

/// Validates a DHT resolution result: verifies BEP44 signature, deserializes
/// document, and wraps in `ValidatedRecord`.
///
/// Network errors and verification failures are logged (not silently swallowed)
/// and mapped to `None` so that the other layer can still provide a result.
///
/// The raw BEP44 bytes and signature are retained in the `ValidatedRecord` for
/// protocol-level healing (§3.10.7, SCP-245).
fn validate_dht_result(
    result: Result<Option<DhtRecord>, IdentityError>,
    did: &str,
    public_key: &[u8; 32],
) -> Option<ValidatedRecord> {
    let record = match result {
        Ok(Some(record)) => record,
        Ok(None) => {
            debug!(did, "DHT returned no document");
            return None;
        }
        Err(e) => {
            debug!(did, error = %e, "DHT resolve failed");
            return None;
        }
    };

    match verify_relay_record(
        did,
        public_key,
        &record.value,
        &record.signature,
        record.seq,
    ) {
        Ok(document) => Some(ValidatedRecord {
            resolved: ResolvedDidDocument {
                document,
                seq: record.seq,
                source: ResolutionSource::MainlineDht,
            },
            raw_value: record.value,
            raw_signature: record.signature,
        }),
        Err(e) => {
            warn!(did, error = %e, "DHT record verification failed");
            None
        }
    }
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
/// ([`DidDocument::signing_key_for`], `ed25519-dalek`), so both consumers call
/// ONE tested helper rather than duplicating the extraction — a second copy is
/// exactly the "resolver silently ignores the `SigningKeyId`" failure mode
/// ADR-053 §Rejected-Alternatives-3 warns against. `scp-ffi-common` depends on
/// `scp-node`, so `scp-node` cannot call the bridge copy without a crate cycle;
/// hoisting the pure extraction here breaks that cycle.
///
/// [`DidDocument::signing_key_for`] keys the lookup on `kid`, so the
/// `SigningKeyId` is honored, never ignored: resolving
/// [`SigningKeyId::Agent`](scp_did::SigningKeyId::Agent) returns the document's
/// distinct `#agent` key, not the `#active` key.
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
/// `Some(key)` when `document` authorizes the requested verification method for
/// signing an assertion and its key decodes to a valid Ed25519 curve point.
///
/// `None` when any one of these holds:
///
/// - `document` carries no method identified as `{document.id}#{fragment}`
///   exactly once — a method some other DID identifies inside it counts for
///   nothing, and neither does a repeated identifier;
/// - that method declares a type other than `Ed25519VerificationKey2020`;
/// - that method names a controller other than `document`'s own DID;
/// - `document`'s `assertionMethod` array does not reference that method, which
///   is what a Layer 1 rotation withdraws (§9.7.4 of the security-model spec);
/// - its `publicKeyMultibase` value does not decode to a valid Ed25519 curve
///   point.
///
/// `None` is the safe per-lookup miss — a caller building a governance
/// `KeyResolver` maps it to "vote rejected" (fail closed).
#[must_use]
pub fn verifying_key_from_document(
    document: &DidDocument,
    kid: scp_did::SigningKeyId,
) -> Option<ed25519_dalek::VerifyingKey> {
    let bytes = document
        .signing_key_for(kid, scp_did::VerificationRelationship::Assertion)
        .ok()?;
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
    use scp_dht::{DhtError, DhtRecord, InMemoryDhtClient};
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
        ) -> impl Future<Output = Result<Option<DhtRecord>, DhtError>> + Send {
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
            vec!["wss://bootstrap.example.com/scp/v1".to_owned()],
        )
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

        let resolved = result.expect("should resolve successfully");
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

        let resolved = result.expect("should resolve successfully");
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

        let resolved = result.expect("should resolve successfully");
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

        let resolved = result.expect("should resolve successfully");
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

        let resolved = result.expect("should resolve successfully");
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

        let resolved = result.expect("should resolve successfully");
        assert_eq!(resolved.seq, 1);
        assert_eq!(
            resolved.source,
            ResolutionSource::ScpRelay {
                relay_url: "wss://relay1.example.com/scp/v1".to_owned()
            }
        );
    }

    #[tokio::test]
    async fn both_fail_returns_none() {
        // Both layers fail. Should return Ok(None).
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
            .expect("should not timeout")
            .unwrap();

        assert!(result.is_none(), "both layers failed, should return None");
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

        assert!(result.is_none(), "no documents stored, should return None");
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

        let resolved = result.expect("should resolve from cache");
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
        assert!(result.is_some());

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
        let resolved = result.expect("should resolve from DHT despite relay verification error");
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

        let result = tokio::time::timeout(Duration::from_secs(2), resolver.resolve(&did))
            .await
            .expect("should not timeout")
            .unwrap();

        // Both seq=1 results must be rejected (< cached seq=5).
        assert!(
            result.is_none(),
            "stale seq=1 should be rejected when cached seq=5 exists"
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

        let resolved = result.expect("seq=7 > cached seq=5, should be accepted");
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
            record: &DidRecordV1,
        ) -> impl Future<Output = Result<(), IdentityError>> + Send {
            let stale_layer = stale_layer.clone();
            let did = did.to_owned();
            // Unpack the frame back into loose fields so existing assertions
            // keep checking the SAME bytes reached the healer.
            let document_bytes = record.value().to_vec();
            let signature = *record.signature();
            let seq = record.seq();
            let public_key = *record.public_key();
            async move {
                let fail = *self.should_fail.lock().await;
                if fail {
                    return Err(IdentityError::RelayPublishFailed(
                        "healing publish failed (test)".to_owned(),
                    ));
                }
                let mut heals = self.heals.lock().await;
                heals.push(RecordedHeal {
                    did,
                    stale_layer,
                    document_bytes,
                    signature,
                    seq,
                    public_key,
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
            vec!["wss://bootstrap.example.com/scp/v1".to_owned()],
            healer,
        )
    }

    /// AC (heal-arm frames correctly): the production `DualLayerHealingPublisher`
    /// Relay arm publishes a DID-record FRAME (§9.10.12), never bare document
    /// bytes. Drive `heal` directly with a `StaleLayer::Relay` and assert the
    /// `InMemoryRelayPublisher` recorded a blob that decodes to the same
    /// `(public_key, signature, seq, value)` (with `value` == `document_bytes`).
    #[tokio::test]
    async fn healing_relay_arm_publishes_did_record_frame() {
        use crate::republish::InMemoryRelayPublisher;
        use scp_dht::InMemoryDhtClient;

        let dht = Arc::new(InMemoryDhtClient::new());
        let relay_pub = Arc::new(InMemoryRelayPublisher::new());
        let healer = DualLayerHealingPublisher::new(Arc::clone(&dht), Arc::clone(&relay_pub));

        // Consistent identity: DID derived from the public key, so the
        // frame-key-derived routing_id equals did_routing_id(did).
        let public_key = [0x11; 32];
        let did = crate::did_from_ed25519_public_key(&public_key);
        let signature = [0x22; 64];
        let document_bytes = b"fresher signed DID document".to_vec();
        let seq = 7u64;

        let record = DidRecordV1::try_new(public_key, seq, signature, document_bytes.clone())
            .expect("frame invariants hold");
        healer
            .heal(
                &did,
                &StaleLayer::Relay {
                    relay_urls: vec!["wss://relay1.example.com/scp/v1".to_owned()],
                },
                &record,
            )
            .await
            .expect("relay heal succeeds");

        let publishes = relay_pub.recorded_publishes().await;
        assert_eq!(publishes.len(), 1, "exactly one relay heal PUBLISH");
        assert_eq!(
            publishes[0].routing_id,
            did_routing_id(&did),
            "healed record is published at the frame-key-derived DID routing_id"
        );
        let frame = DidRecordV1::decode(&publishes[0].blob)
            .expect("healed relay blob must be a DID-record frame, not bare bytes");
        assert_eq!(frame.public_key(), &public_key);
        assert_eq!(frame.signature(), &signature);
        assert_eq!(frame.seq(), seq);
        assert_eq!(frame.value(), &document_bytes[..]);
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
        let resolved = result.expect("should resolve successfully");
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
        let resolved = result.expect("should resolve successfully");
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

        let resolved = result.expect("should resolve");
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

        let resolved = result.expect("should resolve from relay");
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
        let resolved = result.expect("should resolve despite healing failure");
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
        let resolved = result.expect("should resolve");
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
