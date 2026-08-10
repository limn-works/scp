//! Automatic DID document republishing for active identities.
//!
//! DID documents are published to both SCP relays and Mainline DHT to ensure
//! maximum reachability (anti-segmentation invariant, §3.10.6). The
//! [`RepublishManager`] manages background tokio tasks for both layers:
//!
//! - **DHT layer**: 2-hour republish cycle (Mainline DHT records expire).
//! - **Relay layer**: 6-day republish cycle (relay blob TTL is 7 days,
//!   1-day safety margin per §3.10.2).
//!
//! # Lifecycle
//!
//! - Republishing starts when an identity is loaded or created.
//! - Republishing stops when the identity is unloaded or the manager is shut down.
//! - On startup, all registered identities are republished immediately.
//!
//! # Failure Handling
//!
//! Exponential backoff on publish failure: 30s, 1m, 2m, 4m, 8m, 16m, capped
//! at 30 minutes. After 6 consecutive failures, a [`DhtPublishDegraded`] or
//! [`RelayPublishDegraded`] warning is emitted via the respective warning
//! callback. A relay publish that reaches only SOME of the bound relays warns
//! immediately instead — see the relay republish loop's docs.
//!
//! # Anti-Segmentation Invariant (§3.10.6)
//!
//! Publishing to both layers is a MUST. Disabling either requires explicit
//! opt-out via [`RepublishConfig`] and logs a warning:
//! "DID resolution layer disabled. This identity may not be resolvable by all peers."
//!
//! See ADR-003 in `.docs/adrs/phase-1.md` for the full design.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;

use super::IdentityError;
use scp_dht::DhtClient;
use scp_protocol::envelope::did_record::{DidRecordBuildError, DidRecordV1};

/// Republish interval for DHT: every 2 hours (in seconds).
pub const REPUBLISH_INTERVAL_SECS: u64 = 2 * 60 * 60;

/// Default republish interval for SCP relays: every 6 days (in seconds).
///
/// Relay blob TTL is 604800 seconds (7 days). Republishing every 6 days
/// provides a 1-day safety margin before TTL expiry (§3.10.2).
///
/// This is the default value when `RepublishConfig::relay_blob_ttl_secs` is
/// set to the default (7 days). Configurable via ADR-043.
pub const RELAY_REPUBLISH_INTERVAL_SECS: u64 = 6 * 24 * 60 * 60;

/// Default relay blob TTL: 7 days (in seconds), per §3.10.2.
///
/// Configurable via `RepublishConfig::relay_blob_ttl_secs` (ADR-043).
pub const RELAY_BLOB_TTL_SECS: u64 = 604_800;

/// Derives the relay republish interval from a given TTL.
///
/// Formula: `max(ttl.saturating_sub(86400), ttl / 2, 60)` (ADR-043).
/// - At 7-day TTL: 518400s (current default).
/// - At 1-hour TTL: 1800s (half the TTL).
/// - At TTL <= 1: 60s (floor prevents spin loop).
#[must_use]
pub const fn derive_republish_interval(ttl_secs: u64) -> u64 {
    let margin = ttl_secs.saturating_sub(86_400);
    let half = ttl_secs / 2;
    // max(margin, half, 60) — implemented without std::cmp::max (not const)
    let mut result = margin;
    if half > result {
        result = half;
    }
    if 60 > result {
        result = 60;
    }
    result
}

/// Initial backoff on failure: 30 seconds.
const INITIAL_BACKOFF_SECS: u64 = 30;

/// Maximum backoff cap: 30 minutes (in seconds).
const MAX_BACKOFF_SECS: u64 = 30 * 60;

/// Number of consecutive failures before emitting a degraded warning.
const DEGRADED_THRESHOLD: u32 = 6;

/// How often an UNBOUND relay repeats its report once it has been made.
///
/// "No relay is bound" is a configuration state, not a fault: no retry heals it
/// and no operator action is available while nothing binds a relay client. At
/// the 30-minute backoff cap this is roughly one report every 12 hours instead
/// of one every 30 minutes for the life of the node. The absence stays
/// detectable — it just stops being a heartbeat.
const UNBOUND_REPORT_EVERY: u32 = 24;

/// Anti-segmentation warning logged when a publishing layer is disabled.
const LAYER_DISABLED_WARNING: &str =
    "DID resolution layer disabled. This identity may not be resolvable by all peers.";

// ---------------------------------------------------------------------------
// RelayPublisher trait
// ---------------------------------------------------------------------------

/// The result of one relay PUBLISH fan-out: how many of the relays that were
/// attempted actually accepted the DID record (§3.10.2 multi-relay publishing).
///
/// # Why the outcome is not collapsed to `()`
///
/// Multi-relay publishing is best-effort for *availability* — one relay
/// accepting means the record is live — but "at least one accepted" and "every
/// relay accepted" are different security states. A single relay that silently
/// rejects every PUBLISH is the §3.10.8 intra-relay suppression signature:
/// resolvers that consult only that relay never see the record, while the
/// publisher sees a plain success and never retries or warns. Returning the
/// counts lets the relay republish loop distinguish the two and surface a
/// partial accept instead of swallowing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayPublishOutcome {
    /// Relays that accepted the PUBLISH.
    ///
    /// In an `Ok` result this is always `>= 1`: zero accepts is
    /// [`IdentityError::RelayPublishFailed`], never a success.
    pub accepted: usize,
    /// Relays the PUBLISH was attempted against — the bound relay set at the
    /// moment of the call. Always `>= accepted`.
    pub attempted: usize,
}

impl RelayPublishOutcome {
    /// Every attempted relay accepted the record — the only fully healthy state.
    ///
    /// The `accepted > 0` conjunct is load-bearing, not redundant: `0 >= 0`
    /// would make a `{ accepted: 0, attempted: 0 }` outcome vacuously "complete",
    /// and [`relay_republish_loop`](crate::republish) treats a complete outcome by
    /// resetting the failure counter and sleeping the FULL republish interval — so
    /// a publisher that reached nothing would be reported as fully healthy for six
    /// days. The `accepted >= 1` invariant on the field is a doc comment, and
    /// [`RelayPublisher`] is a public trait any implementor can satisfy, so the
    /// predicate enforces here what the type does not.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.accepted > 0 && self.accepted >= self.attempted
    }

    /// Relays that were attempted but did not accept.
    #[must_use]
    pub const fn rejected(&self) -> usize {
        self.attempted.saturating_sub(self.accepted)
    }
}

/// Abstraction over SCP relay PUBLISH operations for DID documents (§3.10.2).
///
/// `scp-identity` defines the trait; `scp-transport` implements the production
/// `TransportRelayPublisher`. This avoids a direct dependency from
/// `scp-identity` to `scp-transport`. `InMemoryRelayPublisher`
/// (test-harness-only, gated behind `#[cfg(any(test, feature = "testing"))]`)
/// records all PUBLISH operations for assertion.
///
/// # Why the contract carries a [`DidRecordV1`], not `&[u8]`
///
/// **This is the authoritative statement of the frame-contract invariant; other
/// sites point here rather than restate it.**
///
/// The DID relay blob MUST be the DID-record frame (§9.10.12) carrying the full
/// BEP44 `(public_key, seq, signature, value)` — not the bare DID-document
/// bytes. An earlier opaque `blob: &[u8]` contract let a caller pass bare
/// `document_bytes`, which silently **dropped the BEP44 signature and sequence**
/// (it caused a heal-arm bare-bytes bug too). Taking a `&DidRecordV1` — a type
/// that can only be built through the validating [`DidRecordV1::try_new`] —
/// makes the signature and sequence *structurally* part of what is published,
/// and unframed bytes **unrepresentable**. The same discipline governs the
/// address: the routing ID is derived from the frame's own key
/// ([`did_record_routing_id`](crate::did_record_routing_id)) rather than passed
/// in, so a frame published at a mismatched routing ID is equally
/// unrepresentable (SCP-RELAYRES-004).
pub trait RelayPublisher: Send + Sync {
    /// Publishes a DID-record frame to SCP relays at the routing ID derived from
    /// the frame's own key, with the given TTL.
    ///
    /// Corresponds to the PUBLISH operation defined in ADR-004 (§3.10.2):
    /// ```text
    /// PUBLISH {
    ///     routing_id: <32-byte hash>,
    ///     blob_ttl: <seconds>,
    ///     blob: <DidRecordV1 frame bytes (§9.10.12)>,
    /// }
    /// ```
    ///
    /// The implementation [`encode`](DidRecordV1::encode)s `record` into its
    /// canonical frame bytes and publishes those bytes — never the bare
    /// `record.value()`. Implementations SHOULD publish to the identity's own
    /// relays plus bootstrap relays from the fallback relay list (§18.5.1). See
    /// the trait docs for why neither the blob nor the address is a free
    /// parameter.
    ///
    /// # Arguments
    ///
    /// * `blob_ttl_secs` — TTL in seconds (604800 for DID documents).
    /// * `record` — The DID-record frame carrying the BEP44
    ///   `(public_key, seq, signature, value)` (§9.10.12).
    ///
    /// # Returns
    ///
    /// A [`RelayPublishOutcome`] reporting how many attempted relays accepted.
    /// A partial accept is a **success** for availability but is reported so the
    /// caller can surface it (§3.10.8); it is never silently collapsed to a
    /// plain `Ok(())`.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::RelayPublishFailed`] if no relay accepted the
    /// record — including when no relay is bound at all (fail-closed; never a
    /// phantom success).
    fn publish(
        &self,
        blob_ttl_secs: u64,
        record: &DidRecordV1,
    ) -> impl Future<Output = Result<RelayPublishOutcome, IdentityError>> + Send;
}

// ---------------------------------------------------------------------------
// InMemoryRelayPublisher (test double)
// ---------------------------------------------------------------------------

/// A recorded PUBLISH operation for test assertions.
///
/// Produced exclusively by [`InMemoryRelayPublisher`]; gated to the same
/// test-harness cfg so no dead test-double support type ships (ADR-062
/// §Decision 5, E4).
#[cfg(any(test, feature = "testing"))]
#[derive(Debug, Clone)]
pub struct RecordedRelayPublish {
    /// The routing ID used in the PUBLISH operation.
    pub routing_id: [u8; 32],
    /// The blob TTL used in the PUBLISH operation.
    pub blob_ttl: u64,
    /// The blob bytes sent in the PUBLISH operation.
    pub blob: Vec<u8>,
}

/// In-memory relay publisher for testing.
///
/// Records all PUBLISH operations so tests can inspect routing IDs, TTLs,
/// and blob contents without network access.
///
/// Test-harness-only: gated behind `#[cfg(any(test, feature = "testing"))]` so
/// it is ABSENT from every shipped (non-testing) build — it can never be bound
/// on a production `RepublishManager` path (ADR-062 §Decision 5, E4; mirrors
/// E1's `InMemoryDhtClient` and E2's `InMemoryCredentialStore` demotions).
#[cfg(any(test, feature = "testing"))]
#[derive(Debug, Default)]
pub struct InMemoryRelayPublisher {
    /// All recorded PUBLISH operations, in order.
    publishes: Mutex<Vec<RecordedRelayPublish>>,
}

#[cfg(any(test, feature = "testing"))]
impl InMemoryRelayPublisher {
    /// Creates a new empty in-memory relay publisher.
    #[must_use]
    pub fn new() -> Self {
        Self {
            publishes: Mutex::new(Vec::new()),
        }
    }

    /// Returns a snapshot of all recorded PUBLISH operations.
    pub async fn recorded_publishes(&self) -> Vec<RecordedRelayPublish> {
        let publishes = self.publishes.lock().await;
        publishes.clone()
    }

    /// Clears all recorded PUBLISH operations.
    pub async fn clear(&self) {
        let mut publishes = self.publishes.lock().await;
        publishes.clear();
    }
}

// Trait uses RPITIT with explicit `+ Send` bound; async fn in trait does
// not guarantee Send futures, so manual impl Future is required.
#[cfg(any(test, feature = "testing"))]
#[allow(clippy::manual_async_fn)]
impl RelayPublisher for InMemoryRelayPublisher {
    fn publish(
        &self,
        blob_ttl_secs: u64,
        record: &DidRecordV1,
    ) -> impl Future<Output = Result<RelayPublishOutcome, IdentityError>> + Send {
        // Derive the routing_id from the frame's own key (§9.10.12 binding) —
        // exactly as a real publisher does — and record the encoded FRAME bytes,
        // what a real relay would store, so tests decode `blob` back via
        // `DidRecordV1::decode` and confirm the full `(public_key, seq, signature,
        // value)` reached the wire.
        let routing_id = crate::did_record_routing_id(record);
        let blob = record.encode();
        async move {
            let mut publishes = self.publishes.lock().await;
            publishes.push(RecordedRelayPublish {
                routing_id,
                blob_ttl: blob_ttl_secs,
                blob,
            });
            drop(publishes);
            // The recorder models a single always-accepting relay.
            Ok(RelayPublishOutcome {
                accepted: 1,
                attempted: 1,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// RepublishConfig
// ---------------------------------------------------------------------------

/// Thread-safe callback for layer-disabled warnings.
type LayerDisabledCallback = Arc<dyn Fn(&str) + Send + Sync>;

/// Configuration for which publishing layers are enabled.
///
/// By default, both DHT and relay layers are enabled per the anti-segmentation
/// invariant (§3.10.6). Disabling either layer requires explicit opt-out and
/// the SDK logs a warning.
///
/// The `relay_blob_ttl_secs` field is configurable per ADR-043. The republish
/// interval is derived from the TTL via [`derive_republish_interval`].
#[derive(Clone)]
pub struct RepublishConfig {
    /// Whether DHT publishing is enabled.
    dht_enabled: bool,
    /// Whether relay publishing is enabled.
    relay_enabled: bool,
    /// Warning callback invoked when a layer is disabled.
    layer_disabled_callback: Option<LayerDisabledCallback>,
    /// Relay blob TTL in seconds. Defaults to [`RELAY_BLOB_TTL_SECS`] (7 days).
    /// Configurable by relay operators (ADR-043).
    relay_blob_ttl_secs: u64,
}

impl std::fmt::Debug for RepublishConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RepublishConfig")
            .field("dht_enabled", &self.dht_enabled)
            .field("relay_enabled", &self.relay_enabled)
            .field("relay_blob_ttl_secs", &self.relay_blob_ttl_secs)
            .field(
                "layer_disabled_callback",
                &self.layer_disabled_callback.as_ref().map(|_| "..."),
            )
            .finish()
    }
}

impl Default for RepublishConfig {
    fn default() -> Self {
        Self {
            dht_enabled: true,
            relay_enabled: true,
            layer_disabled_callback: None,
            relay_blob_ttl_secs: RELAY_BLOB_TTL_SECS,
        }
    }
}

impl RepublishConfig {
    /// Creates a default config with both layers enabled.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets an ADDITIONAL callback invoked when a layer is disabled.
    ///
    /// The callback receives the warning message string. It is never the only
    /// notification: [`disable_dht`](Self::disable_dht) /
    /// [`disable_relay`](Self::disable_relay) log the §3.10.6 warning
    /// unconditionally. Wire this only to surface the event somewhere else too
    /// (an SDK event stream, a health endpoint).
    #[must_use]
    pub fn with_layer_disabled_callback(mut self, callback: LayerDisabledCallback) -> Self {
        self.layer_disabled_callback = Some(callback);
        self
    }

    /// Disables DHT publishing.
    ///
    /// **WARNING:** This violates the anti-segmentation invariant (§3.10.6).
    /// The identity may not be resolvable by peers that only check the DHT.
    pub fn disable_dht(&mut self) {
        self.dht_enabled = false;
        self.warn_layer_disabled("dht");
    }

    /// Disables relay publishing.
    ///
    /// **WARNING:** This violates the anti-segmentation invariant (§3.10.6).
    /// The identity may not be resolvable by peers that only check SCP relays.
    pub fn disable_relay(&mut self) {
        self.relay_enabled = false;
        self.warn_layer_disabled("relay");
    }

    /// Emits the §3.10.6 mandated layer-disabled warning.
    ///
    /// The `tracing::warn!` is UNCONDITIONAL: the spec makes the warning a
    /// `MUST`, so it cannot depend on a caller having remembered to wire a
    /// callback (`Default` has none). The optional callback is an additional
    /// surface, not the mechanism.
    fn warn_layer_disabled(&self, layer: &str) {
        tracing::warn!(
            layer,
            warning = LAYER_DISABLED_WARNING,
            "§3.10.6 DID resolution layer disabled"
        );
        if let Some(ref cb) = self.layer_disabled_callback {
            cb(LAYER_DISABLED_WARNING);
        }
    }

    /// Returns whether DHT publishing is enabled.
    #[must_use]
    pub const fn is_dht_enabled(&self) -> bool {
        self.dht_enabled
    }

    /// Returns whether relay publishing is enabled.
    #[must_use]
    pub const fn is_relay_enabled(&self) -> bool {
        self.relay_enabled
    }

    /// Sets the relay blob TTL (in seconds) and derives the republish interval.
    ///
    /// Defaults to [`RELAY_BLOB_TTL_SECS`] (7 days). Configurable per ADR-043.
    #[must_use]
    pub const fn with_relay_blob_ttl_secs(mut self, ttl_secs: u64) -> Self {
        self.relay_blob_ttl_secs = ttl_secs;
        self
    }

    /// Returns the configured relay blob TTL in seconds.
    #[must_use]
    pub const fn relay_blob_ttl_secs(&self) -> u64 {
        self.relay_blob_ttl_secs
    }

    /// Returns the derived relay republish interval in seconds.
    #[must_use]
    pub const fn relay_republish_interval_secs(&self) -> u64 {
        derive_republish_interval(self.relay_blob_ttl_secs)
    }
}

// ---------------------------------------------------------------------------
// Warning types
// ---------------------------------------------------------------------------

/// A signed BEP44 DID record: everything needed to (re)publish a DID document
/// to either resolution layer.
///
/// This is the OUTPUT of the signing step (`DidMethod::publish`), never
/// something reconstructed from a storage or network read-back — so both layers
/// receive byte-identical `(value, signature, sequence)` (§3.10.5).
///
/// # There is no `did` field
///
/// The DID is not stored alongside `public_key`; it is *derived* from it by
/// [`did`](Self::did). Two independent fields that MUST agree are two fields
/// that can disagree — and since the wire address (`routing_id`) is derived from
/// `public_key`, a stored-but-stale `did` would be a second, silently divergent
/// answer to "whose record is this?". Deriving keeps exactly one answer.
#[derive(Debug, Clone)]
pub struct RepublishEntry {
    /// The 32-byte Ed25519 identity public key. The DID, and the relay
    /// `routing_id`, are both derived from this.
    pub public_key: [u8; 32],
    /// The serialized DID document bytes (the BEP44 `value`).
    pub document_bytes: Vec<u8>,
    /// The 64-byte Ed25519 signature for BEP44.
    pub signature: [u8; 64],
    /// The current BEP44 sequence number.
    pub sequence: u64,
}

impl RepublishEntry {
    /// The `did:dht` string this record belongs to, derived from
    /// [`public_key`](Self::public_key).
    #[must_use]
    pub fn did(&self) -> String {
        crate::did_from_ed25519_public_key(&self.public_key)
    }

    /// Wraps this entry's BEP44 `(public_key, seq, signature, value)` into the
    /// DID-record relay frame (§9.10.12) that the relay layer stores.
    ///
    /// The single place the relay-republish path turns an entry into a
    /// publishable frame (see [`RelayPublisher`] for the frame contract).
    ///
    /// # Errors
    ///
    /// Returns [`DidRecordBuildError`] if `document_bytes` is empty or exceeds
    /// the maximum frame `value` length (§9.10.12) — the frame invariants
    /// enforced at construction by [`DidRecordV1::try_new`].
    pub fn to_did_record(&self) -> Result<DidRecordV1, DidRecordBuildError> {
        DidRecordV1::try_new(
            self.public_key,
            self.sequence,
            self.signature,
            self.document_bytes.clone(),
        )
    }
}

/// A warning event emitted when DID publishing has degraded.
#[derive(Debug, Clone)]
pub struct DhtPublishDegraded {
    /// The DID that failed to publish.
    pub did: String,
    /// Number of consecutive publish failures.
    pub consecutive_failures: u32,
}

/// Callback type for degraded warnings.
pub type WarningCallback = Arc<dyn Fn(DhtPublishDegraded) + Send + Sync>;

/// A warning event emitted when relay publishing has degraded — either it is
/// failing outright, or it is only *partially* reaching the bound relay set.
#[derive(Debug, Clone)]
pub struct RelayPublishDegraded {
    /// The DID whose relay publishing degraded.
    pub did: String,
    /// Number of consecutive relay republish cycles that did not reach EVERY
    /// bound relay. A total failure and a partial accept both count; only a
    /// complete accept resets it.
    pub consecutive_failures: u32,
    /// The per-relay breakdown of the most recent PUBLISH, when one exists.
    ///
    /// `Some` on a partial accept (the degradation IS the breakdown). `None`
    /// when the publisher returned an error: no relay accepted, and the error
    /// carries no structured per-relay counts — reporting a fabricated `0 of 0`
    /// would assert "no relay was bound", which a total rejection by N bound
    /// relays is not. Absence is the honest answer.
    pub last_outcome: Option<RelayPublishOutcome>,
}

/// Callback type for relay degraded warnings.
pub type RelayWarningCallback = Arc<dyn Fn(RelayPublishDegraded) + Send + Sync>;

// ---------------------------------------------------------------------------
// RepublishManager
// ---------------------------------------------------------------------------

/// Manages background republishing of DID documents on both DHT and SCP relays.
///
/// Each registered identity gets background tokio tasks that republish its DID
/// document on the configured layers:
/// - **DHT**: every 2 hours (existing cycle, unchanged).
/// - **Relay**: every 6 days (blob TTL is 7 days, 1-day margin per §3.10.2).
///
/// Both layers are enabled by default per the anti-segmentation invariant
/// (§3.10.6). Use [`RepublishConfig`] to disable either layer (with warnings).
///
/// # Type Parameters
///
/// * `D` — The DHT client implementation. Use `InMemoryDhtClient` for
///   testing, or a production pkarr-based client for real DHT access.
/// * `R` — The relay publisher implementation. A production relay client for
///   real relay access, or `InMemoryRelayPublisher` (test-harness-only, gated
///   behind `#[cfg(any(test, feature = "testing"))]`) for tests. There is no
///   default: every caller MUST name a publisher explicitly, so no shipped
///   `RepublishManager` can silently bind the in-memory dev double (ADR-062
///   §Decision 5, E4 — mirrors E1's `DidDht<D>` default severance).
pub struct RepublishManager<D: DhtClient, R: RelayPublisher> {
    dht_client: Arc<D>,
    relay_publisher: Option<Arc<R>>,
    config: RepublishConfig,
    /// Active DHT republish tasks, keyed by DID string.
    dht_tasks: Mutex<HashMap<String, TaskHandle>>,
    /// Active relay republish tasks, keyed by DID string.
    relay_tasks: Mutex<HashMap<String, TaskHandle>>,
    /// Optional callback for degraded DHT warnings.
    warning_callback: Option<WarningCallback>,
    /// Optional callback for degraded relay warnings.
    relay_warning_callback: Option<RelayWarningCallback>,
}

impl<D: DhtClient, R: RelayPublisher> std::fmt::Debug for RepublishManager<D, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RepublishManager")
            .field("config", &self.config)
            .field(
                "warning_callback",
                &self.warning_callback.as_ref().map(|_| "..."),
            )
            .field(
                "relay_warning_callback",
                &self.relay_warning_callback.as_ref().map(|_| "..."),
            )
            .finish_non_exhaustive()
    }
}

/// Handle to a running republish task, including its abort handle.
#[derive(Debug)]
struct TaskHandle {
    abort_handle: tokio::task::AbortHandle,
}

impl<D: DhtClient + 'static, R: RelayPublisher> RepublishManager<D, R> {
    /// Creates a new republish manager with DHT-only publishing.
    ///
    /// The relay publisher type `R` must still be named by the caller (there is
    /// no default type parameter — ADR-062 §Decision 5, E4), even though this
    /// constructor leaves it unset (`relay_publisher: None`). Relay publishing
    /// is not available until a [`RelayPublisher`] is provided via
    /// [`with_relay_publisher`](RepublishManager::with_relay_publisher).
    #[must_use]
    pub fn new(dht_client: Arc<D>) -> Self {
        Self {
            dht_client,
            relay_publisher: None,
            config: RepublishConfig::default(),
            dht_tasks: Mutex::new(HashMap::new()),
            relay_tasks: Mutex::new(HashMap::new()),
            warning_callback: None,
            relay_warning_callback: None,
        }
    }

    /// Creates a new republish manager with a warning callback (DHT-only).
    #[must_use]
    pub fn with_warning_callback(dht_client: Arc<D>, callback: WarningCallback) -> Self {
        Self {
            dht_client,
            relay_publisher: None,
            config: RepublishConfig::default(),
            dht_tasks: Mutex::new(HashMap::new()),
            relay_tasks: Mutex::new(HashMap::new()),
            warning_callback: Some(callback),
            relay_warning_callback: None,
        }
    }
}

impl<D: DhtClient + 'static, R: RelayPublisher + 'static> RepublishManager<D, R> {
    /// Creates a new republish manager with both DHT and relay publishing.
    #[must_use]
    pub fn with_relay_publisher(
        dht_client: Arc<D>,
        relay_publisher: Arc<R>,
        config: RepublishConfig,
    ) -> Self {
        Self {
            dht_client,
            relay_publisher: Some(relay_publisher),
            config,
            dht_tasks: Mutex::new(HashMap::new()),
            relay_tasks: Mutex::new(HashMap::new()),
            warning_callback: None,
            relay_warning_callback: None,
        }
    }

    /// Creates a new republish manager with both DHT and relay publishing,
    /// plus a warning callback for degraded DHT publish events.
    #[must_use]
    pub fn with_relay_publisher_and_warning(
        dht_client: Arc<D>,
        relay_publisher: Arc<R>,
        config: RepublishConfig,
        callback: WarningCallback,
    ) -> Self {
        Self {
            dht_client,
            relay_publisher: Some(relay_publisher),
            config,
            dht_tasks: Mutex::new(HashMap::new()),
            relay_tasks: Mutex::new(HashMap::new()),
            warning_callback: Some(callback),
            relay_warning_callback: None,
        }
    }

    /// Sets the relay warning callback for degraded relay publish events.
    ///
    /// The callback is invoked when relay publishing has failed at least
    /// `DEGRADED_THRESHOLD` consecutive times.
    #[must_use]
    pub fn with_relay_warning_callback(mut self, callback: RelayWarningCallback) -> Self {
        self.relay_warning_callback = Some(callback);
        self
    }

    /// Starts republishing a DID document on all enabled layers.
    ///
    /// - **DHT** (if enabled): immediate publish, then every 2 hours.
    /// - **Relay** (if enabled and publisher configured): immediate publish,
    ///   then every 6 days.
    ///
    /// # This is also the re-seed operation
    ///
    /// If the DID is already being republished, its existing tasks are aborted
    /// and replaced — so calling this again with a NEWLY-SIGNED entry is how a
    /// caller re-points a running cycle at the current record after a
    /// re-publish (a DID document is re-published on, e.g., a NAT tier change,
    /// which assigns a new `(value, signature, seq)`).
    ///
    /// There is deliberately no separate `reseed`/`update_entry` method: each
    /// running loop captured its [`RepublishEntry`] by value when it was spawned,
    /// so replacing the task is the only way to change what it publishes — a
    /// second method would be a second spelling of this one.
    ///
    /// The abort and the insert happen under the same task-map lock, so a
    /// re-seed cannot double-spawn, and the old and new tasks cannot both
    /// survive. A re-seed landing while a loop is mid-publish drops that
    /// in-flight request; the replacement publishes immediately with a higher
    /// sequence, which supersedes it on both layers.
    pub async fn start_republishing(&self, entry: RepublishEntry) {
        // The task-map key is the entry's DERIVED DID (`RepublishEntry` stores
        // no `did` field — see its docs), computed once so both arms key the
        // same identity.
        let entry_did = entry.did();

        // Start DHT republish task if enabled.
        if self.config.dht_enabled {
            let mut dht_tasks = self.dht_tasks.lock().await;

            if let Some(handle) = dht_tasks.remove(&entry_did) {
                handle.abort_handle.abort();
            }

            let dht_client = Arc::clone(&self.dht_client);
            let warning_cb = self.warning_callback.clone();
            let did = entry_did.clone();
            let entry_clone = entry.clone();

            let join_handle = tokio::spawn(dht_republish_loop(dht_client, entry_clone, warning_cb));

            dht_tasks.insert(
                did,
                TaskHandle {
                    abort_handle: join_handle.abort_handle(),
                },
            );
        }

        // Start relay republish task if enabled and publisher is configured.
        if self.config.relay_enabled
            && let Some(ref relay_publisher) = self.relay_publisher
        {
            let mut relay_tasks = self.relay_tasks.lock().await;

            if let Some(handle) = relay_tasks.remove(&entry_did) {
                handle.abort_handle.abort();
            }

            let relay_pub = Arc::clone(relay_publisher);
            let did = entry_did;
            let relay_warning_cb = self.relay_warning_callback.clone();

            let blob_ttl = self.config.relay_blob_ttl_secs;
            let republish_interval = self.config.relay_republish_interval_secs();

            let join_handle = tokio::spawn(relay_republish_loop(
                relay_pub,
                entry,
                relay_warning_cb,
                blob_ttl,
                republish_interval,
            ));

            relay_tasks.insert(
                did,
                TaskHandle {
                    abort_handle: join_handle.abort_handle(),
                },
            );
        }
    }

    /// Stops republishing a specific DID on all layers.
    pub async fn stop_republishing(&self, did: &str) {
        let mut dht_tasks = self.dht_tasks.lock().await;
        if let Some(handle) = dht_tasks.remove(did) {
            handle.abort_handle.abort();
        }
        drop(dht_tasks);

        let mut relay_tasks = self.relay_tasks.lock().await;
        if let Some(handle) = relay_tasks.remove(did) {
            handle.abort_handle.abort();
        }
    }

    /// Stops all republishing tasks on all layers (shutdown).
    pub async fn stop_all(&self) {
        let mut dht_tasks = self.dht_tasks.lock().await;
        for (_, handle) in dht_tasks.drain() {
            handle.abort_handle.abort();
        }
        drop(dht_tasks);

        let mut relay_tasks = self.relay_tasks.lock().await;
        for (_, handle) in relay_tasks.drain() {
            handle.abort_handle.abort();
        }
    }

    /// Returns the number of active DHT republish tasks.
    pub async fn active_count(&self) -> usize {
        let dht_tasks = self.dht_tasks.lock().await;
        dht_tasks.len()
    }

    /// Returns the number of active relay republish tasks.
    pub async fn active_relay_count(&self) -> usize {
        let relay_tasks = self.relay_tasks.lock().await;
        relay_tasks.len()
    }

    /// Returns whether a specific DID is being republished (on any layer).
    pub async fn is_republishing(&self, did: &str) -> bool {
        let dht_tasks = self.dht_tasks.lock().await;
        let relay_tasks = self.relay_tasks.lock().await;
        dht_tasks.contains_key(did) || relay_tasks.contains_key(did)
    }
}

/// Computes the backoff duration for a given attempt number (0-indexed).
///
/// Sequence: 30s, 60s, 120s, 240s, 480s, 960s, 1800s (capped at 30m), and
/// monotone non-decreasing for EVERY `attempt` thereafter. `checked_shl`, not
/// `wrapping_shl`: the latter masks the shift to `attempt & 63`, so attempt 64
/// wrapped back to a 30-second backoff and re-ramped the whole ladder — a
/// permanently-failing arm would emit a retry burst every ~30 hours, forever.
fn backoff_secs(attempt: u32) -> u64 {
    1u64.checked_shl(attempt)
        .map_or(u64::MAX, |factor| {
            INITIAL_BACKOFF_SECS.saturating_mul(factor)
        })
        .min(MAX_BACKOFF_SECS)
}

/// The DHT republish loop for a single identity.
///
/// Publishes immediately, then waits for the DHT republish interval (2 hours)
/// before the next publish. On failure, retries with exponential backoff.
async fn dht_republish_loop<D: DhtClient>(
    dht_client: Arc<D>,
    entry: RepublishEntry,
    warning_cb: Option<WarningCallback>,
) {
    let did = entry.did();
    let mut consecutive_failures: u32 = 0;

    loop {
        // Attempt to publish.
        let result = dht_client
            .publish(
                &entry.public_key,
                &entry.signature,
                &entry.document_bytes,
                entry.sequence,
            )
            .await;

        if result.is_ok() {
            consecutive_failures = 0;
            // Wait for the republish interval before next publish.
            tokio::time::sleep(tokio::time::Duration::from_secs(REPUBLISH_INTERVAL_SECS)).await;
        } else {
            consecutive_failures = consecutive_failures.saturating_add(1);

            // Emit degraded warning after threshold.
            if consecutive_failures >= DEGRADED_THRESHOLD
                && let Some(ref cb) = warning_cb
            {
                cb(DhtPublishDegraded {
                    did: did.clone(),
                    consecutive_failures,
                });
            }

            // Backoff before retry.
            let backoff = backoff_secs(consecutive_failures.saturating_sub(1));
            tokio::time::sleep(tokio::time::Duration::from_secs(backoff)).await;
        }
    }
}

/// The relay republish loop for a single identity.
///
/// Publishes immediately using the PUBLISH operation with:
/// - `routing_id` = `did_routing_id(did_string)` (§3.10.2)
/// - `blob_ttl` = config-derived TTL (default 604800 = 7 days, §3.10.2)
/// - `blob` = the DID-record frame (§9.10.12) carrying the BEP44
///   `(public_key, seq, signature, value=document_bytes)` — NOT the bare
///   document bytes (which would drop the signature and sequence)
///
/// Then waits for the derived republish interval before the next publish.
/// On failure, retries with exponential backoff.
///
/// The frame is built ONCE, up front, via [`RepublishEntry::to_did_record`]
/// (see [`RelayPublisher`] for the frame contract). A malformed entry
/// (empty/oversize `document_bytes`) can never encode to a valid frame, so the
/// loop fails closed: it logs and returns rather than spinning.
///
/// # Partial success is reported, not swallowed (§3.10.8)
///
/// A publish that reaches *some* bound relays succeeds for availability, but a
/// relay that permanently rejects is the intra-relay suppression signature: a
/// resolver consulting only that relay never sees the record. A partial accept
/// therefore fires the degraded callback on the FIRST occurrence rather than
/// after [`DEGRADED_THRESHOLD`] cycles. The asymmetry is deliberate: a *total*
/// failure is indistinguishable from "this node is offline", which the backoff
/// absorbs and which usually heals itself; a *partial* accept proves the other
/// relays are reachable and healthy, so no retry heals it and there is nothing
/// to wait for. It still sleeps the normal interval rather than backing off —
/// the record IS live on at least one relay, so hammering the healthy relays
/// would be a self-inflicted denial of service.
async fn relay_republish_loop<R: RelayPublisher>(
    relay_publisher: Arc<R>,
    entry: RepublishEntry,
    warning_cb: Option<RelayWarningCallback>,
    blob_ttl_secs: u64,
    republish_interval_secs: u64,
) {
    let did = entry.did();
    let record = match entry.to_did_record() {
        Ok(record) => record,
        Err(e) => {
            tracing::error!(
                did = %did,
                error = %e,
                "relay republish: DID document cannot be wrapped into a DID-record \
                 frame (§9.10.12); relay republishing disabled for this identity"
            );
            return;
        }
    };

    let mut consecutive_failures: u32 = 0;

    loop {
        match relay_publisher.publish(blob_ttl_secs, &record).await {
            Ok(outcome) if outcome.is_complete() => {
                consecutive_failures = 0;
                tokio::time::sleep(tokio::time::Duration::from_secs(republish_interval_secs)).await;
            }
            Ok(outcome) => {
                consecutive_failures = consecutive_failures.saturating_add(1);
                tracing::warn!(
                    did = %did,
                    accepted = outcome.accepted,
                    attempted = outcome.attempted,
                    rejected = outcome.rejected(),
                    consecutive_failures,
                    "relay republish reached only SOME bound relays — the rejecting \
                     relay(s) suppress this DID for any resolver that consults them \
                     (§3.10.8)"
                );
                if let Some(ref cb) = warning_cb {
                    cb(RelayPublishDegraded {
                        did: did.clone(),
                        consecutive_failures,
                        last_outcome: Some(outcome),
                    });
                }
                // The record is live on >= 1 relay: wait the normal cycle.
                tokio::time::sleep(tokio::time::Duration::from_secs(republish_interval_secs)).await;
            }
            Err(e) => {
                consecutive_failures = consecutive_failures.saturating_add(1);
                // A CONFIGURED relay that is failing is actionable and can heal,
                // so every attempt is reported. "No relay bound at all" cannot:
                // reporting it every cycle would make a healthy node log
                // DEGRADED forever for a condition its operator has no API to
                // clear. Report its onset and its crossing into degraded, then
                // repeat rarely. See [`UNBOUND_REPORT_EVERY`].
                let report = !matches!(e, IdentityError::NoRelayBound)
                    || consecutive_failures == 1
                    || consecutive_failures == DEGRADED_THRESHOLD
                    || consecutive_failures.is_multiple_of(UNBOUND_REPORT_EVERY);

                if report {
                    tracing::warn!(
                        did = %did,
                        error = %e,
                        consecutive_failures,
                        "relay republish reached no relay — retrying with backoff"
                    );
                }

                // Emit degraded warning after threshold.
                if consecutive_failures >= DEGRADED_THRESHOLD
                    && report
                    && let Some(ref cb) = warning_cb
                {
                    cb(RelayPublishDegraded {
                        did: did.clone(),
                        consecutive_failures,
                        last_outcome: None,
                    });
                }

                let backoff = backoff_secs(consecutive_failures.saturating_sub(1));
                tokio::time::sleep(tokio::time::Duration::from_secs(backoff)).await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Migration Republishing
// ---------------------------------------------------------------------------

/// Default interval for migration republishing: 1 hour (in seconds).
pub const MIGRATION_REPUBLISH_INTERVAL_SECS: u64 = 60 * 60;

/// Periodically republishes an old DID document with an `alsoKnownAs` redirect
/// to the new DID after identity migration.
///
/// After a DID migration, the old DID document needs to be periodically
/// republished with a redirect so that resolvers looking up the old DID can
/// discover the new one. This struct manages that background task.
///
/// # Cancellation
///
/// The returned [`MigrationHandle`] can be used to cancel the background task.
/// The task also stops if the handle is dropped.
pub struct MigrationRepublisher<D: DhtClient> {
    dht_client: Arc<D>,
    interval_secs: u64,
}

/// Handle to a running migration republish task.
///
/// Dropping the handle or calling [`cancel`](Self::cancel) stops the
/// background republish task.
pub struct MigrationHandle {
    abort_handle: tokio::task::AbortHandle,
}

impl MigrationHandle {
    /// Cancels the migration republish task.
    pub fn cancel(&self) {
        self.abort_handle.abort();
    }

    /// Returns whether the background task is still running.
    #[must_use]
    pub fn is_active(&self) -> bool {
        !self.abort_handle.is_finished()
    }
}

impl<D: DhtClient + 'static> MigrationRepublisher<D> {
    /// Creates a new migration republisher with the default interval (1 hour).
    #[must_use]
    pub const fn new(dht_client: Arc<D>) -> Self {
        Self {
            dht_client,
            interval_secs: MIGRATION_REPUBLISH_INTERVAL_SECS,
        }
    }

    /// Creates a new migration republisher with a custom interval.
    #[must_use]
    pub const fn with_interval(dht_client: Arc<D>, interval_secs: u64) -> Self {
        Self {
            dht_client,
            interval_secs,
        }
    }

    /// Starts the migration republish background task.
    ///
    /// The task immediately republishes the old DID document with the redirect,
    /// then repeats at the configured interval. Returns a [`MigrationHandle`]
    /// that can cancel the task.
    #[must_use]
    pub fn start(&self, entry: RepublishEntry) -> MigrationHandle {
        let dht_client = Arc::clone(&self.dht_client);
        let interval_secs = self.interval_secs;

        let join_handle = tokio::spawn(migration_republish_loop(dht_client, entry, interval_secs));

        MigrationHandle {
            abort_handle: join_handle.abort_handle(),
        }
    }
}

/// Background loop that periodically republishes a migration redirect.
async fn migration_republish_loop<D: DhtClient>(
    dht_client: Arc<D>,
    entry: RepublishEntry,
    interval_secs: u64,
) {
    loop {
        // Attempt to publish the old DID document (which should already contain
        // the alsoKnownAs redirect to the new DID).
        let _ = dht_client
            .publish(
                &entry.public_key,
                &entry.signature,
                &entry.document_bytes,
                entry.sequence,
            )
            .await;

        tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::resolution::did_routing_id;
    use scp_dht::InMemoryDhtClient;

    /// An entry for the identity owning `public_key`. The DID is DERIVED (the
    /// entry has no `did` field), so a test can never construct an entry whose
    /// DID and key disagree.
    fn make_entry(public_key: [u8; 32]) -> RepublishEntry {
        RepublishEntry {
            public_key,
            document_bytes: b"test document".to_vec(),
            signature: [2u8; 64],
            sequence: 1,
        }
    }

    /// The DID a test entry is keyed under — recomposed here from the raw key
    /// rather than via `RepublishEntry::did()`, so the assertion is an
    /// independent oracle rather than the production accessor checking itself.
    fn entry_did(public_key: [u8; 32]) -> String {
        crate::did_from_ed25519_public_key(&public_key)
    }

    #[test]
    fn backoff_sequence_is_correct() {
        assert_eq!(backoff_secs(0), 30);
        assert_eq!(backoff_secs(1), 60);
        assert_eq!(backoff_secs(2), 120);
        assert_eq!(backoff_secs(3), 240);
        assert_eq!(backoff_secs(4), 480);
        assert_eq!(backoff_secs(5), 960);
        assert_eq!(backoff_secs(6), MAX_BACKOFF_SECS);
        assert_eq!(backoff_secs(7), MAX_BACKOFF_SECS);
    }

    /// The backoff is monotone non-decreasing for EVERY attempt, including past
    /// the 64th.
    ///
    /// Against the `wrapping_shl` predecessor this fails at attempt 64: the
    /// shift was masked to `attempt & 63`, so the backoff collapsed from the
    /// 30-minute cap back to 30s and re-ramped the whole ladder. A permanently
    /// failing arm reaches attempt 64 in ~30 hours and then emits a retry burst
    /// on that cycle, forever. Reachable in production ever since the arm stopped
    /// being latched off while unbound.
    #[test]
    fn backoff_never_regresses_however_many_attempts_have_failed() {
        let mut previous = 0;
        for attempt in 0..=200u32 {
            let backoff = backoff_secs(attempt);
            assert!(
                backoff >= previous,
                "backoff regressed at attempt {attempt}: {previous} -> {backoff}"
            );
            assert!(backoff <= MAX_BACKOFF_SECS);
            previous = backoff;
        }
        assert_eq!(backoff_secs(63), MAX_BACKOFF_SECS);
        assert_eq!(
            backoff_secs(64),
            MAX_BACKOFF_SECS,
            "the shift-wrap boundary"
        );
        assert_eq!(backoff_secs(65), MAX_BACKOFF_SECS);
        assert_eq!(backoff_secs(u32::MAX), MAX_BACKOFF_SECS);
    }

    #[tokio::test]
    async fn start_and_stop_republishing() {
        let dht = Arc::new(InMemoryDhtClient::new());
        let manager: RepublishManager<InMemoryDhtClient, InMemoryRelayPublisher> =
            RepublishManager::new(Arc::clone(&dht));
        let entry = make_entry([1u8; 32]);
        let did = entry_did([1u8; 32]);

        manager.start_republishing(entry).await;
        assert_eq!(manager.active_count().await, 1);
        assert!(
            manager.is_republishing(&did).await,
            "the task is keyed under the DID DERIVED from the entry's public key"
        );

        // Give the background task time to publish.
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Verify the document was published to the in-memory DHT.
        let record = dht.resolve(&[1u8; 32]).await.unwrap();
        assert!(record.is_some());

        manager.stop_republishing(&did).await;
        assert_eq!(manager.active_count().await, 0);
    }

    #[tokio::test]
    async fn stop_all_clears_all_tasks() {
        let dht = Arc::new(InMemoryDhtClient::new());
        let manager: RepublishManager<InMemoryDhtClient, InMemoryRelayPublisher> =
            RepublishManager::new(Arc::clone(&dht));

        manager.start_republishing(make_entry([1u8; 32])).await;
        manager.start_republishing(make_entry([2u8; 32])).await;
        assert_eq!(
            manager.active_count().await,
            2,
            "two DISTINCT keys derive two distinct DIDs -> two tasks"
        );

        manager.stop_all().await;
        assert_eq!(manager.active_count().await, 0);
    }

    #[tokio::test]
    async fn replacing_existing_task_aborts_old_one() {
        let dht = Arc::new(InMemoryDhtClient::new());
        let manager: RepublishManager<InMemoryDhtClient, InMemoryRelayPublisher> =
            RepublishManager::new(Arc::clone(&dht));

        manager.start_republishing(make_entry([1u8; 32])).await;
        manager.start_republishing(make_entry([1u8; 32])).await;

        assert_eq!(
            manager.active_count().await,
            1,
            "the same key derives the same DID -> the second start replaces the first"
        );
        manager.stop_all().await;
    }

    #[tokio::test]
    async fn immediate_publish_on_start() {
        let dht = Arc::new(InMemoryDhtClient::new());
        let manager: RepublishManager<InMemoryDhtClient, InMemoryRelayPublisher> =
            RepublishManager::new(Arc::clone(&dht));
        let entry = make_entry([1u8; 32]);

        manager.start_republishing(entry).await;

        // Give the task time to do its first publish.
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let record = dht.resolve(&[1u8; 32]).await.unwrap();
        assert!(record.is_some());
        assert_eq!(record.unwrap().seq, 1);

        manager.stop_all().await;
    }

    // --- Relay publish tests (SCP-239) ---

    #[tokio::test]
    async fn relay_publish_uses_correct_routing_id_and_ttl() {
        let dht = Arc::new(InMemoryDhtClient::new());
        let relay = Arc::new(InMemoryRelayPublisher::new());
        let config = RepublishConfig::new();

        let manager =
            RepublishManager::with_relay_publisher(Arc::clone(&dht), Arc::clone(&relay), config);

        // A consistent identity: the DID is derived from the public key, so the
        // frame-key-derived routing_id equals SHA-256("scp:did:" || did_string).
        let public_key = [7u8; 32];
        let did_str = crate::did_from_ed25519_public_key(&public_key);
        let entry = RepublishEntry {
            public_key,
            document_bytes: b"BEP44-signed DID document".to_vec(),
            signature: [2u8; 64],
            sequence: 1,
        };

        manager.start_republishing(entry).await;

        // Give both tasks time to do their first publish.
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Verify relay PUBLISH was sent with correct routing_id and blob_ttl.
        let publishes = relay.recorded_publishes().await;
        assert_eq!(publishes.len(), 1, "exactly one relay PUBLISH expected");

        let publish = &publishes[0];
        let expected_routing_id = did_routing_id(&did_str);
        assert_eq!(
            publish.routing_id, expected_routing_id,
            "routing_id must be SHA-256('scp:did:' || did_string), derived from the frame key"
        );
        assert_eq!(
            publish.blob_ttl, RELAY_BLOB_TTL_SECS,
            "blob_ttl must be 604800 (7 days)"
        );

        // The blob is the DID-record FRAME (§9.10.12), NOT the bare document
        // bytes. Decoding it must recover the full (public_key, seq, signature,
        // value) — the exact assertion the old bare-`document_bytes` publish
        // would fail (the frame prefix ≠ the document bytes).
        assert_ne!(
            publish.blob, b"BEP44-signed DID document",
            "blob must be the framed record, never the bare document bytes"
        );
        let frame = DidRecordV1::decode(&publish.blob)
            .expect("relay blob must decode as a DidRecordV1 frame");
        assert_eq!(frame.public_key(), &public_key, "frame carries public_key");
        assert_eq!(frame.seq(), 1, "frame carries the BEP44 sequence");
        assert_eq!(frame.signature(), &[2u8; 64], "frame carries the signature");
        assert_eq!(
            frame.value(),
            b"BEP44-signed DID document",
            "frame value is the document bytes"
        );

        // Verify DHT publish also happened.
        let dht_record = dht.resolve(&public_key).await.unwrap();
        assert!(
            dht_record.is_some(),
            "DHT publish should also have occurred"
        );

        manager.stop_all().await;
    }

    /// AC 2: the relay-republish loop publishes the FULL DID-record frame — the
    /// signature and sequence are no longer dropped. Decoding the recorded blob
    /// via `DidRecordV1::decode` recovers the SAME `(public_key, signature, seq,
    /// value)` as the source `RepublishEntry` (`value` == `document_bytes`). This
    /// test would FAIL against the pre-fix bare-`document_bytes` publish (the
    /// recorded blob would be the bare document, not a frame, and would not decode).
    #[tokio::test]
    async fn relay_republish_publishes_full_frame_not_bare_document_bytes() {
        let dht = Arc::new(InMemoryDhtClient::new());
        let relay = Arc::new(InMemoryRelayPublisher::new());
        let manager = RepublishManager::with_relay_publisher(
            Arc::clone(&dht),
            Arc::clone(&relay),
            RepublishConfig::new(),
        );

        let source = RepublishEntry {
            public_key: [0xAB; 32],
            document_bytes: b"the signed DID document body".to_vec(),
            signature: [0xCD; 64],
            sequence: 42,
        };

        manager.start_republishing(source.clone()).await;
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let publishes = relay.recorded_publishes().await;
        assert_eq!(publishes.len(), 1, "exactly one relay PUBLISH expected");

        // The recorded blob is a frame — decode it and compare field-by-field.
        let frame = DidRecordV1::decode(&publishes[0].blob)
            .expect("recorded blob must be a valid DID-record frame, not bare bytes");
        assert_eq!(frame.public_key(), &source.public_key);
        assert_eq!(frame.signature(), &source.signature);
        assert_eq!(frame.seq(), source.sequence);
        assert_eq!(frame.value(), &source.document_bytes[..]);

        // Cross-check: the frame is strictly larger than the bare document
        // (105-byte fixed prefix + value), so a bare-bytes publish is ruled out.
        assert_eq!(publishes[0].blob.len(), 105 + source.document_bytes.len());

        manager.stop_all().await;
    }

    /// A malformed entry (empty `document_bytes`) can never wrap into a valid
    /// frame; the relay loop fails closed (no publish) rather than emit unframed
    /// or empty bytes.
    #[tokio::test]
    async fn relay_republish_fails_closed_on_unframeable_entry() {
        let dht = Arc::new(InMemoryDhtClient::new());
        let relay = Arc::new(InMemoryRelayPublisher::new());
        let manager = RepublishManager::with_relay_publisher(
            Arc::clone(&dht),
            Arc::clone(&relay),
            RepublishConfig::new(),
        );

        let entry = RepublishEntry {
            public_key: [1u8; 32],
            document_bytes: Vec::new(), // empty → unframeable (§9.10.12)
            signature: [2u8; 64],
            sequence: 1,
        };
        assert!(
            entry.to_did_record().is_err(),
            "empty document must be unframeable"
        );

        manager.start_republishing(entry).await;
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        assert!(
            relay.recorded_publishes().await.is_empty(),
            "no relay publish must occur for an unframeable entry (fail-closed)"
        );

        manager.stop_all().await;
    }

    #[tokio::test]
    async fn relay_publish_default_blob_ttl_is_seven_days() {
        // Default blob_ttl = 604800 (7 days).
        assert_eq!(RELAY_BLOB_TTL_SECS, 604_800);
        let config = RepublishConfig::new();
        assert_eq!(config.relay_blob_ttl_secs(), RELAY_BLOB_TTL_SECS);
    }

    #[tokio::test]
    async fn relay_default_republish_interval_is_six_days() {
        // Default republish timer fires at 6-day interval.
        let config = RepublishConfig::new();
        assert_eq!(config.relay_republish_interval_secs(), 518_400);
        assert_eq!(RELAY_REPUBLISH_INTERVAL_SECS, 518_400);
    }

    #[tokio::test]
    async fn relay_republish_interval_derived_from_custom_ttl() {
        // TTL = 3600 (1 hour) → interval = max(3600-86400, 1800, 60) = 1800
        let config = RepublishConfig::new().with_relay_blob_ttl_secs(3600);
        assert_eq!(config.relay_republish_interval_secs(), 1800);
    }

    #[tokio::test]
    async fn relay_republish_interval_floor_prevents_spin_loop() {
        // TTL = 1 → interval = max(1-86400, 0, 60) = 60 (floor)
        let config = RepublishConfig::new().with_relay_blob_ttl_secs(1);
        assert_eq!(config.relay_republish_interval_secs(), 60);
    }

    #[tokio::test]
    async fn relay_republish_interval_zero_ttl_uses_floor() {
        // TTL = 0 → interval = max(0, 0, 60) = 60
        let config = RepublishConfig::new().with_relay_blob_ttl_secs(0);
        assert_eq!(config.relay_republish_interval_secs(), 60);
    }

    #[tokio::test]
    async fn relay_and_dht_tasks_managed_independently() {
        let dht = Arc::new(InMemoryDhtClient::new());
        let relay = Arc::new(InMemoryRelayPublisher::new());
        let config = RepublishConfig::new();

        let manager =
            RepublishManager::with_relay_publisher(Arc::clone(&dht), Arc::clone(&relay), config);

        let entry = make_entry([1u8; 32]);
        manager.start_republishing(entry).await;

        assert_eq!(manager.active_count().await, 1, "one DHT task");
        assert_eq!(manager.active_relay_count().await, 1, "one relay task");

        manager.stop_all().await;

        assert_eq!(manager.active_count().await, 0, "DHT tasks cleared");
        assert_eq!(manager.active_relay_count().await, 0, "relay tasks cleared");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // Guard is explicitly dropped before await
    async fn disable_dht_skips_dht_publishing() {
        let dht = Arc::new(InMemoryDhtClient::new());
        let relay = Arc::new(InMemoryRelayPublisher::new());

        let warnings: Arc<std::sync::Mutex<Vec<String>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let warnings_clone = Arc::clone(&warnings);

        let mut config =
            RepublishConfig::new().with_layer_disabled_callback(Arc::new(move |msg: &str| {
                let mut w = warnings_clone.lock().unwrap();
                w.push(msg.to_owned());
            }));
        config.disable_dht();

        let manager =
            RepublishManager::with_relay_publisher(Arc::clone(&dht), Arc::clone(&relay), config);

        let entry = make_entry([1u8; 32]);
        manager.start_republishing(entry).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // DHT should NOT have been published to.
        assert_eq!(manager.active_count().await, 0, "no DHT tasks");
        let dht_record = dht.resolve(&[1u8; 32]).await.unwrap();
        assert!(dht_record.is_none(), "DHT should have no records");

        // Relay SHOULD have been published to.
        assert_eq!(manager.active_relay_count().await, 1, "one relay task");
        let publishes = relay.recorded_publishes().await;
        assert_eq!(publishes.len(), 1, "relay publish should have occurred");

        // Warning should have been logged.
        let logged_warnings = warnings.lock().unwrap();
        assert_eq!(logged_warnings.len(), 1);
        assert_eq!(logged_warnings[0], LAYER_DISABLED_WARNING);
        drop(logged_warnings);

        manager.stop_all().await;
    }

    #[tokio::test]
    async fn disable_relay_skips_relay_publishing() {
        let dht = Arc::new(InMemoryDhtClient::new());
        let relay = Arc::new(InMemoryRelayPublisher::new());

        let mut config = RepublishConfig::new();
        config.disable_relay();

        let manager =
            RepublishManager::with_relay_publisher(Arc::clone(&dht), Arc::clone(&relay), config);

        let entry = make_entry([1u8; 32]);
        manager.start_republishing(entry).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // DHT SHOULD have been published to.
        assert_eq!(manager.active_count().await, 1, "one DHT task");
        let dht_record = dht.resolve(&[1u8; 32]).await.unwrap();
        assert!(dht_record.is_some(), "DHT should have a record");

        // Relay should NOT have been published to.
        assert_eq!(manager.active_relay_count().await, 0, "no relay tasks");
        let publishes = relay.recorded_publishes().await;
        assert!(
            publishes.is_empty(),
            "no relay publishes should have occurred"
        );

        manager.stop_all().await;
    }

    #[test]
    fn config_defaults_to_both_layers_enabled() {
        let config = RepublishConfig::new();
        assert!(config.is_dht_enabled());
        assert!(config.is_relay_enabled());
    }

    #[test]
    fn config_disable_dht_sets_flag() {
        let mut config = RepublishConfig::new();
        config.disable_dht();
        assert!(!config.is_dht_enabled());
        assert!(config.is_relay_enabled());
    }

    #[test]
    fn config_disable_relay_sets_flag() {
        let mut config = RepublishConfig::new();
        config.disable_relay();
        assert!(config.is_dht_enabled());
        assert!(!config.is_relay_enabled());
    }

    /// B3 / §3.10.6: disabling EITHER layer emits the mandated warning on a
    /// `Default` config — one that wired NO callback.
    ///
    /// The spec makes the warning a `MUST`, so it cannot be conditional on a
    /// caller having remembered to wire a callback: this asserts the mechanical
    /// guarantee by capturing the `tracing` output itself. The optional callback
    /// is an additional surface, covered by
    /// `disabling_a_layer_also_invokes_the_optional_callback`.
    #[test]
    fn disabling_either_layer_always_logs_the_mandated_warning() {
        let logs = capture_tracing(|| {
            let mut relay_off = RepublishConfig::new();
            relay_off.disable_relay();
            let mut dht_off = RepublishConfig::new();
            dht_off.disable_dht();
        });

        assert_eq!(
            logs.matches(LAYER_DISABLED_WARNING).count(),
            2,
            "each disable must warn even with no callback wired — neither layer \
             may be turned off silently. Captured: {logs}"
        );
        assert!(
            logs.contains("layer=\"relay\"") || logs.contains("layer=relay"),
            "{logs}"
        );
        assert!(
            logs.contains("layer=\"dht\"") || logs.contains("layer=dht"),
            "{logs}"
        );
    }

    /// The optional callback is invoked IN ADDITION to the unconditional log.
    #[test]
    fn disabling_a_layer_also_invokes_the_optional_callback() {
        let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let mut config =
            RepublishConfig::new().with_layer_disabled_callback(Arc::new(move |m: &str| {
                sink.lock().unwrap().push(m.to_owned());
            }));
        config.disable_relay();

        assert_eq!(seen.lock().unwrap().as_slice(), [LAYER_DISABLED_WARNING]);
    }

    /// Runs `body` with a scoped `tracing` subscriber and returns everything it
    /// emitted, so a test can assert on a log line that no callback observes.
    fn capture_tracing(body: impl FnOnce()) -> String {
        #[derive(Clone)]
        struct SharedBuf(Arc<std::sync::Mutex<Vec<u8>>>);

        impl std::io::Write for SharedBuf {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedBuf {
            type Writer = Self;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        let buf = SharedBuf(Arc::new(std::sync::Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, body);
        let bytes = buf.0.lock().unwrap().clone();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    // --- Migration republisher tests ---

    fn make_migration_entry() -> RepublishEntry {
        // Simulate an old DID document that already has alsoKnownAs set.
        RepublishEntry {
            public_key: [3u8; 32],
            document_bytes: b"old document with alsoKnownAs redirect".to_vec(),
            signature: [4u8; 64],
            sequence: 2,
        }
    }

    #[tokio::test]
    async fn migration_republisher_publishes_old_doc_with_redirect() {
        let dht = Arc::new(InMemoryDhtClient::new());
        let republisher = MigrationRepublisher::with_interval(Arc::clone(&dht), 3600);
        let entry = make_migration_entry();

        let handle = republisher.start(entry);

        // Give the task time to do its first publish.
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Verify the old DID document was published.
        let record = dht.resolve(&[3u8; 32]).await.unwrap();
        assert!(record.is_some());
        let rec = record.unwrap();
        assert_eq!(rec.value, b"old document with alsoKnownAs redirect");
        assert_eq!(rec.seq, 2);

        handle.cancel();
    }

    #[tokio::test]
    async fn migration_republisher_respects_configurable_interval() {
        let dht = Arc::new(InMemoryDhtClient::new());
        // Use default interval — verify it's configurable.
        let default_republisher = MigrationRepublisher::new(Arc::clone(&dht));
        assert_eq!(
            default_republisher.interval_secs,
            MIGRATION_REPUBLISH_INTERVAL_SECS
        );

        // Use custom interval.
        let custom_republisher = MigrationRepublisher::with_interval(Arc::clone(&dht), 42);
        assert_eq!(custom_republisher.interval_secs, 42);

        // Start with a short interval and verify immediate publish happens.
        let entry = make_migration_entry();
        let handle = custom_republisher.start(entry);

        // Give the task time to do its first publish.
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let record = dht.resolve(&[3u8; 32]).await.unwrap();
        assert!(record.is_some(), "first publish should happen immediately");

        handle.cancel();
    }

    #[tokio::test]
    async fn migration_republisher_stops_on_cancel() {
        let dht = Arc::new(InMemoryDhtClient::new());
        let republisher = MigrationRepublisher::with_interval(Arc::clone(&dht), 3600);
        let entry = make_migration_entry();

        let handle = republisher.start(entry);
        assert!(handle.is_active());

        handle.cancel();

        // Give the runtime time to process the abort.
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        assert!(!handle.is_active());
    }

    // --- Relay degraded warning tests ---

    /// A relay publisher that always fails, for testing degraded warnings.
    struct AlwaysFailRelayPublisher;

    // Trait uses RPITIT with explicit `+ Send` bound; async fn in trait
    // does not guarantee Send futures, so manual impl Future is required.
    #[allow(clippy::manual_async_fn)]
    impl RelayPublisher for AlwaysFailRelayPublisher {
        fn publish(
            &self,
            _blob_ttl_secs: u64,
            _record: &DidRecordV1,
        ) -> impl Future<Output = Result<RelayPublishOutcome, IdentityError>> + Send {
            async move { Err(IdentityError::RelayPublishFailed("always fails".into())) }
        }
    }

    /// A relay publisher modelling `accepted` of `attempted` bound relays
    /// accepting — the §3.10.8 partial-suppression shape. `accepted >= 1`, so
    /// every call is an `Ok` (the record IS live) that is nonetheless not
    /// complete.
    struct PartialAcceptRelayPublisher {
        accepted: usize,
        attempted: usize,
        calls: std::sync::atomic::AtomicUsize,
    }

    #[allow(clippy::manual_async_fn)]
    impl RelayPublisher for PartialAcceptRelayPublisher {
        fn publish(
            &self,
            _blob_ttl_secs: u64,
            _record: &DidRecordV1,
        ) -> impl Future<Output = Result<RelayPublishOutcome, IdentityError>> + Send {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let outcome = RelayPublishOutcome {
                accepted: self.accepted,
                attempted: self.attempted,
            };
            async move { Ok(outcome) }
        }
    }

    #[test]
    fn outcome_completeness_and_rejected_count() {
        let complete = RelayPublishOutcome {
            accepted: 3,
            attempted: 3,
        };
        assert!(complete.is_complete());
        assert_eq!(complete.rejected(), 0);

        let partial = RelayPublishOutcome {
            accepted: 1,
            attempted: 3,
        };
        assert!(!partial.is_complete());
        assert_eq!(partial.rejected(), 2);

        // "Reached nothing" is never "fully healthy". `accepted >= attempted`
        // alone is vacuously true here, and the loop's complete-arm resets the
        // failure counter and sleeps the full 6-day interval — so a publisher
        // that published to no one would report as healthy for six days. No
        // production publisher constructs this today (an empty relay set is
        // `NoRelayBound` and zero accepts is `RelayPublishFailed`), but
        // `RelayPublisher` is a public trait and the invariant is only a doc
        // comment on the field, so the predicate must not depend on it.
        let reached_nothing = RelayPublishOutcome {
            accepted: 0,
            attempted: 0,
        };
        assert!(
            !reached_nothing.is_complete(),
            "a 0/0 outcome must never count as a complete publish"
        );
        assert_eq!(reached_nothing.rejected(), 0);
    }

    /// B4 / §3.10.8: an attacker controlling 1 of N relays must not get SILENT
    /// permanent partial suppression. A publish that only SOME bound relays
    /// accept is an `Ok` — the record is live — but it fires the degraded
    /// callback on the FIRST cycle, carrying the per-relay breakdown. Against
    /// the pre-fix code (`publish -> Result<(), _>`, `is_ok()` resets the
    /// failure counter) this test cannot even be written: the loop had no way
    /// to observe the rejection.
    #[tokio::test(start_paused = true)]
    #[allow(clippy::await_holding_lock)] // Guard is explicitly dropped before await
    async fn partial_relay_accept_fires_degraded_callback_immediately() {
        let dht = Arc::new(InMemoryDhtClient::new());
        let relay = Arc::new(PartialAcceptRelayPublisher {
            accepted: 1,
            attempted: 3,
            calls: std::sync::atomic::AtomicUsize::new(0),
        });

        let warnings: Arc<std::sync::Mutex<Vec<RelayPublishDegraded>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let warnings_clone = Arc::clone(&warnings);

        let manager = RepublishManager::with_relay_publisher(
            Arc::clone(&dht),
            Arc::clone(&relay),
            RepublishConfig::new(),
        )
        .with_relay_warning_callback(Arc::new(move |degraded| {
            warnings_clone.lock().unwrap().push(degraded);
        }));

        let entry = make_entry([9u8; 32]);
        manager.start_republishing(entry).await;

        // One poll of the spawned task is enough: no time advance, so the
        // warning cannot have come from a later cycle.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        let logged = warnings.lock().unwrap();
        assert_eq!(
            logged.len(),
            1,
            "a partial accept fires the degraded callback on the FIRST cycle, \
             not after {DEGRADED_THRESHOLD} of them"
        );
        assert_eq!(logged[0].did, entry_did([9u8; 32]));
        assert_eq!(logged[0].consecutive_failures, 1);
        assert_eq!(
            logged[0].last_outcome,
            Some(RelayPublishOutcome {
                accepted: 1,
                attempted: 3,
            }),
            "the callback carries the per-relay breakdown that makes the \
             suppression legible"
        );
        drop(logged);

        manager.stop_all().await;
    }

    /// The complement: a COMPLETE accept is silent. Without this, the test
    /// above would pass even if the loop warned on every publish.
    #[tokio::test(start_paused = true)]
    #[allow(clippy::await_holding_lock)] // Guard is explicitly dropped before await
    async fn complete_relay_accept_fires_no_degraded_callback() {
        let dht = Arc::new(InMemoryDhtClient::new());
        let relay = Arc::new(PartialAcceptRelayPublisher {
            accepted: 3,
            attempted: 3,
            calls: std::sync::atomic::AtomicUsize::new(0),
        });

        let warnings: Arc<std::sync::Mutex<Vec<RelayPublishDegraded>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let warnings_clone = Arc::clone(&warnings);

        let manager = RepublishManager::with_relay_publisher(
            Arc::clone(&dht),
            Arc::clone(&relay),
            RepublishConfig::new(),
        )
        .with_relay_warning_callback(Arc::new(move |degraded| {
            warnings_clone.lock().unwrap().push(degraded);
        }));

        manager.start_republishing(make_entry([9u8; 32])).await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        assert!(
            warnings.lock().unwrap().is_empty(),
            "every bound relay accepted -> no degradation to report"
        );
        assert!(
            relay.calls.load(std::sync::atomic::Ordering::Relaxed) >= 1,
            "the publish actually ran (the assertion above is not vacuous)"
        );

        manager.stop_all().await;
    }

    #[tokio::test(start_paused = true)]
    #[allow(clippy::await_holding_lock)] // Guard is explicitly dropped before await
    async fn relay_warning_callback_fires_after_degraded_threshold() {
        let dht = Arc::new(InMemoryDhtClient::new());
        let relay = Arc::new(AlwaysFailRelayPublisher);
        let config = RepublishConfig::new();

        let warnings: Arc<std::sync::Mutex<Vec<RelayPublishDegraded>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let warnings_clone = Arc::clone(&warnings);

        let manager =
            RepublishManager::with_relay_publisher(Arc::clone(&dht), Arc::clone(&relay), config)
                .with_relay_warning_callback(Arc::new(move |degraded| {
                    let mut w = warnings_clone.lock().unwrap();
                    w.push(degraded);
                }));

        let entry = make_entry([0x5Au8; 32]);
        manager.start_republishing(entry).await;

        // With start_paused, advance time through the backoff schedule step by
        // step so the spawned task gets polled between each timer expiry.
        //
        // Attempt 1: immediate, fails, backoff 30s
        // Attempt 2: after 30s, fails, backoff 60s
        // Attempt 3: after 60s, fails, backoff 120s
        // Attempt 4: after 120s, fails, backoff 240s
        // Attempt 5: after 240s, fails, backoff 480s
        // Attempt 6: after 480s, fails -> WARNING fires
        //
        // Yield after the spawn to let attempt 1 run immediately.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        // Advance through each backoff, yielding between to let the task process.
        for backoff in [30u64, 60, 120, 240, 480] {
            tokio::time::advance(tokio::time::Duration::from_secs(backoff + 1)).await;
            tokio::task::yield_now().await;
            tokio::task::yield_now().await;
        }

        let logged = warnings.lock().unwrap();
        assert!(
            !logged.is_empty(),
            "relay degraded warning should have fired after {DEGRADED_THRESHOLD} consecutive failures",
        );
        assert_eq!(logged[0].did, entry_did([0x5Au8; 32]));
        assert_eq!(logged[0].consecutive_failures, DEGRADED_THRESHOLD);
        assert_eq!(
            logged[0].last_outcome, None,
            "a TOTAL failure has no per-relay breakdown — reporting a \
             fabricated `0 of 0` would assert 'no relay was bound'"
        );
        drop(logged);

        manager.stop_all().await;
    }
}
