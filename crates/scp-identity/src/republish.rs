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
//! callback.
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
use super::resolution::did_routing_id;
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

/// Anti-segmentation warning logged when a publishing layer is disabled.
const LAYER_DISABLED_WARNING: &str =
    "DID resolution layer disabled. This identity may not be resolvable by all peers.";

// ---------------------------------------------------------------------------
// RelayPublisher trait
// ---------------------------------------------------------------------------

/// Abstraction over SCP relay PUBLISH operations for DID documents (§3.10.2).
///
/// Production implementations wrap the relay client from `scp-transport`
/// (`TransportRelayPublisher`). `InMemoryRelayPublisher` (test-harness-only,
/// gated behind `#[cfg(any(test, feature = "testing"))]`) provides a test
/// implementation that records all PUBLISH operations for assertion.
///
/// `scp-identity` defines the trait; `scp-transport` implements the production
/// [`TransportRelayPublisher`]. This avoids a direct dependency from
/// `scp-identity` to `scp-transport`.
///
/// # Why the contract carries a [`DidRecordV1`], not `&[u8]`
///
/// The DID relay blob MUST be the DID-record frame (§9.10.12) that carries the
/// full BEP44 `(public_key, seq, signature, value)` — not the bare DID-document
/// bytes. An earlier opaque `blob: &[u8]` contract let a caller pass bare
/// `document_bytes`, which silently **dropped the BEP44 signature and sequence**
/// (an api-design review flagged the opaque contract as exactly that footgun, and
/// it caused a heal-arm bare-bytes bug too). By taking a `&DidRecordV1` — a type
/// that can only be built through the validating [`DidRecordV1::try_new`] — the
/// signature and sequence are *structurally* part of what is published, and
/// unframed bytes are **unrepresentable**. Frame-wrapping happens in exactly one
/// place: the implementation calls [`DidRecordV1::encode`] on the record it is
/// handed (SCP-RELAYRES-004).
pub trait RelayPublisher: Send + Sync {
    /// Publishes a DID-record frame to SCP relays at the routing ID **derived
    /// from the frame's own key** (not a caller argument — see below), with the
    /// given TTL.
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
    /// `record.value()` — at the DID `routing_id` **derived from the frame's own
    /// key** ([`did_record_routing_id`]). The routing ID is not a caller argument:
    /// a DID record can only be published at the one routing ID its
    /// `public_key` binds to (§9.10.12 DID→`routing_id` binding), so a valid frame
    /// published at a mismatched routing ID is unrepresentable — the same
    /// misuse-resistance discipline that made bare bytes unrepresentable.
    /// Implementations SHOULD publish to the identity's own relays plus bootstrap
    /// relays from the fallback relay list (§18.5.1).
    ///
    /// # Arguments
    ///
    /// * `blob_ttl` — TTL in seconds (604800 for DID documents).
    /// * `record` — The DID-record frame carrying the BEP44
    ///   `(public_key, seq, signature, value)` (§9.10.12).
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::RelayPublishFailed`] if the publish fails.
    fn publish(
        &self,
        blob_ttl: u64,
        record: &DidRecordV1,
    ) -> impl Future<Output = Result<(), IdentityError>> + Send;
}

/// The DID `routing_id` a DID-record frame MUST be published at, and resolved
/// from: `SHA-256("scp:did:" || did:dht(record.public_key()))` (§3.10.2 routing
/// derivation, §9.10.12 DID→`routing_id` binding).
///
/// Deriving the routing ID from the frame's own key — rather than accepting it
/// as an independent argument — makes a frame/`routing_id` mismatch
/// **unrepresentable**: a frame can only ever be published at the single routing
/// ID its `public_key` binds to. That binding is exactly what a validating relay
/// re-checks on PUBLISH (SCP-RELAYRES-003 `did_slot`, which derives it via the
/// same [`did_from_ed25519_public_key`](crate::did_from_ed25519_public_key) +
/// [`did_routing_id`]). The whole relay DID-record path is `did:dht`-specific
/// (§9.10.12).
#[must_use]
pub fn did_record_routing_id(record: &DidRecordV1) -> [u8; 32] {
    did_routing_id(&crate::did_from_ed25519_public_key(record.public_key()))
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
        blob_ttl: u64,
        record: &DidRecordV1,
    ) -> impl Future<Output = Result<(), IdentityError>> + Send {
        // Derive the routing_id from the frame's own key (§9.10.12 binding) —
        // exactly as a real publisher does — and record the encoded FRAME bytes,
        // what a real relay would store, so tests decode `blob` back via
        // `DidRecordV1::decode` and confirm the full `(public_key, seq, signature,
        // value)` reached the wire, never the bare document bytes.
        let routing_id = did_record_routing_id(record);
        let blob = record.encode();
        async move {
            let mut publishes = self.publishes.lock().await;
            publishes.push(RecordedRelayPublish {
                routing_id,
                blob_ttl,
                blob,
            });
            drop(publishes);
            Ok(())
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

    /// Sets the callback invoked when a layer is disabled.
    ///
    /// The callback receives the warning message string. In production,
    /// this would typically log via `tracing::warn!` or equivalent.
    #[must_use]
    pub fn with_layer_disabled_callback(mut self, callback: LayerDisabledCallback) -> Self {
        self.layer_disabled_callback = Some(callback);
        self
    }

    /// Disables DHT publishing.
    ///
    /// **WARNING:** This violates the anti-segmentation invariant (§3.10.6).
    /// The identity may not be resolvable by peers that only check the DHT.
    /// A warning is logged via the configured callback.
    pub fn disable_dht(&mut self) {
        self.dht_enabled = false;
        if let Some(ref cb) = self.layer_disabled_callback {
            cb(LAYER_DISABLED_WARNING);
        }
    }

    /// Disables relay publishing.
    ///
    /// **WARNING:** This violates the anti-segmentation invariant (§3.10.6).
    /// The identity may not be resolvable by peers that only check SCP relays.
    /// A warning is logged via the configured callback.
    pub fn disable_relay(&mut self) {
        self.relay_enabled = false;
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

/// Information needed to republish a DID document.
#[derive(Debug, Clone)]
pub struct RepublishEntry {
    /// The DID string being republished.
    pub did: String,
    /// The 32-byte Ed25519 public key (derived from the DID).
    pub public_key: [u8; 32],
    /// The serialized DID document bytes.
    pub document_bytes: Vec<u8>,
    /// The 64-byte Ed25519 signature for BEP44.
    pub signature: [u8; 64],
    /// The current BEP44 sequence number.
    pub sequence: u64,
}

impl RepublishEntry {
    /// Wraps this entry's BEP44 `(public_key, seq, signature, value)` into the
    /// DID-record relay frame (§9.10.12) that the relay layer stores.
    ///
    /// This is the single place the relay-republish path turns an entry into a
    /// publishable frame: the [`relay_republish_loop`] builds the frame once via
    /// this method before it publishes, so the loop can NEVER publish bare
    /// `document_bytes` (which would drop the signature and sequence).
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

/// A warning event emitted when relay publishing has degraded.
#[derive(Debug, Clone)]
pub struct RelayPublishDegraded {
    /// The DID that failed to publish to relays.
    pub did: String,
    /// Number of consecutive relay publish failures.
    pub consecutive_failures: u32,
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
    /// If the DID is already being republished, existing tasks are replaced.
    pub async fn start_republishing(&self, entry: RepublishEntry) {
        // Start DHT republish task if enabled.
        if self.config.dht_enabled {
            let mut dht_tasks = self.dht_tasks.lock().await;

            if let Some(handle) = dht_tasks.remove(&entry.did) {
                handle.abort_handle.abort();
            }

            let dht_client = Arc::clone(&self.dht_client);
            let warning_cb = self.warning_callback.clone();
            let did = entry.did.clone();
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

            if let Some(handle) = relay_tasks.remove(&entry.did) {
                handle.abort_handle.abort();
            }

            let relay_pub = Arc::clone(relay_publisher);
            let did = entry.did.clone();
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
/// Sequence: 30s, 60s, 120s, 240s, 480s, 960s, 1800s (capped at 30m).
fn backoff_secs(attempt: u32) -> u64 {
    let backoff = INITIAL_BACKOFF_SECS.saturating_mul(1u64.wrapping_shl(attempt));
    backoff.min(MAX_BACKOFF_SECS)
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
                    did: entry.did.clone(),
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
/// The frame is built ONCE, up front, via [`RepublishEntry::to_did_record`].
/// A malformed entry (empty/oversize `document_bytes`) can never encode to a
/// valid frame, so the loop fails closed: it logs and returns rather than
/// spinning or ever publishing unframed bytes.
async fn relay_republish_loop<R: RelayPublisher>(
    relay_publisher: Arc<R>,
    entry: RepublishEntry,
    warning_cb: Option<RelayWarningCallback>,
    blob_ttl_secs: u64,
    republish_interval_secs: u64,
) {
    // Build the DID-record frame once. This is the sole wrap site for the loop;
    // publishing the bare `document_bytes` (dropping the BEP44 signature/seq) is
    // now structurally impossible — the publisher only accepts a `DidRecordV1`,
    // and it derives the routing_id from the frame's own key (§9.10.12 binding),
    // so the loop never hands over a routing_id at all.
    let record = match entry.to_did_record() {
        Ok(record) => record,
        Err(e) => {
            tracing::error!(
                did = %entry.did,
                error = %e,
                "relay republish: DID document cannot be wrapped into a DID-record \
                 frame (§9.10.12); relay republishing disabled for this identity"
            );
            return;
        }
    };

    let mut consecutive_failures: u32 = 0;

    loop {
        let result = relay_publisher.publish(blob_ttl_secs, &record).await;

        if result.is_ok() {
            consecutive_failures = 0;
            tokio::time::sleep(tokio::time::Duration::from_secs(republish_interval_secs)).await;
        } else {
            consecutive_failures = consecutive_failures.saturating_add(1);

            // Emit degraded warning after threshold.
            if consecutive_failures >= DEGRADED_THRESHOLD
                && let Some(ref cb) = warning_cb
            {
                cb(RelayPublishDegraded {
                    did: entry.did.clone(),
                    consecutive_failures,
                });
            }

            let backoff = backoff_secs(consecutive_failures.saturating_sub(1));
            tokio::time::sleep(tokio::time::Duration::from_secs(backoff)).await;
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

    fn make_entry(did: &str) -> RepublishEntry {
        RepublishEntry {
            did: did.to_owned(),
            public_key: [1u8; 32],
            document_bytes: b"test document".to_vec(),
            signature: [2u8; 64],
            sequence: 1,
        }
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

    #[tokio::test]
    async fn start_and_stop_republishing() {
        let dht = Arc::new(InMemoryDhtClient::new());
        let manager: RepublishManager<InMemoryDhtClient, InMemoryRelayPublisher> =
            RepublishManager::new(Arc::clone(&dht));
        let entry = make_entry("did:dht:zTest1");

        manager.start_republishing(entry).await;
        assert_eq!(manager.active_count().await, 1);
        assert!(manager.is_republishing("did:dht:zTest1").await);

        // Give the background task time to publish.
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Verify the document was published to the in-memory DHT.
        let record = dht.resolve(&[1u8; 32]).await.unwrap();
        assert!(record.is_some());

        manager.stop_republishing("did:dht:zTest1").await;
        assert_eq!(manager.active_count().await, 0);
    }

    #[tokio::test]
    async fn stop_all_clears_all_tasks() {
        let dht = Arc::new(InMemoryDhtClient::new());
        let manager: RepublishManager<InMemoryDhtClient, InMemoryRelayPublisher> =
            RepublishManager::new(Arc::clone(&dht));

        manager
            .start_republishing(make_entry("did:dht:zTest1"))
            .await;
        manager
            .start_republishing(make_entry("did:dht:zTest2"))
            .await;
        assert_eq!(manager.active_count().await, 2);

        manager.stop_all().await;
        assert_eq!(manager.active_count().await, 0);
    }

    #[tokio::test]
    async fn replacing_existing_task_aborts_old_one() {
        let dht = Arc::new(InMemoryDhtClient::new());
        let manager: RepublishManager<InMemoryDhtClient, InMemoryRelayPublisher> =
            RepublishManager::new(Arc::clone(&dht));

        manager
            .start_republishing(make_entry("did:dht:zTest1"))
            .await;
        manager
            .start_republishing(make_entry("did:dht:zTest1"))
            .await;

        assert_eq!(manager.active_count().await, 1);
        manager.stop_all().await;
    }

    #[tokio::test]
    async fn immediate_publish_on_start() {
        let dht = Arc::new(InMemoryDhtClient::new());
        let manager: RepublishManager<InMemoryDhtClient, InMemoryRelayPublisher> =
            RepublishManager::new(Arc::clone(&dht));
        let entry = make_entry("did:dht:zTest1");

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
            did: did_str.clone(),
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

        let did_str = "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let source = RepublishEntry {
            did: did_str.to_owned(),
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
            did: "did:dht:zEmptyDoc".to_owned(),
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

        let entry = make_entry("did:dht:zTest1");
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

        let entry = make_entry("did:dht:zTest1");
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

        let entry = make_entry("did:dht:zTest1");
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

    // --- Migration republisher tests ---

    fn make_migration_entry() -> RepublishEntry {
        // Simulate an old DID document that already has alsoKnownAs set.
        RepublishEntry {
            did: "did:dht:zOldDid".to_owned(),
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
            _blob_ttl: u64,
            _record: &DidRecordV1,
        ) -> impl Future<Output = Result<(), IdentityError>> + Send {
            async move { Err(IdentityError::RelayPublishFailed("always fails".into())) }
        }
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

        let entry = make_entry("did:dht:zTestRelay");
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
        assert_eq!(logged[0].did, "did:dht:zTestRelay");
        assert_eq!(logged[0].consecutive_failures, DEGRADED_THRESHOLD);
        drop(logged);

        manager.stop_all().await;
    }
}
