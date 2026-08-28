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
/// Production implementations wrap the relay client from `scp-transport`.
/// `InMemoryRelayPublisher` (test-harness-only, gated behind
/// `#[cfg(any(test, feature = "testing"))]`) provides a test implementation
/// that records all PUBLISH operations for assertion.
///
/// `scp-core` defines the trait; `scp-transport` implements it. This avoids
/// a direct dependency from `scp-core` to `scp-transport`.
pub trait RelayPublisher: Send + Sync {
    /// Publishes a blob to SCP relays with the given routing ID and TTL.
    ///
    /// Corresponds to the PUBLISH operation defined in ADR-004:
    /// ```text
    /// PUBLISH {
    ///     routing_id: <32-byte hash>,
    ///     blob_ttl: <seconds>,
    ///     blob: <BEP44-signed DID document bytes>,
    /// }
    /// ```
    ///
    /// Implementations SHOULD publish to the identity's own relays plus
    /// bootstrap relays from the fallback relay list (§18.5.1).
    ///
    /// # Arguments
    ///
    /// * `routing_id` — The 32-byte routing ID derived via [`did_routing_id`].
    /// * `blob_ttl` — TTL in seconds (604800 for DID documents).
    /// * `blob` — The BEP44-signed DID document bytes.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::RelayPublishFailed`] if the publish fails.
    fn publish(
        &self,
        routing_id: &[u8; 32],
        blob_ttl: u64,
        blob: &[u8],
    ) -> impl Future<Output = Result<(), IdentityError>> + Send;
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
        routing_id: &[u8; 32],
        blob_ttl: u64,
        blob: &[u8],
    ) -> impl Future<Output = Result<(), IdentityError>> + Send {
        async move {
            let mut publishes = self.publishes.lock().await;
            publishes.push(RecordedRelayPublish {
                routing_id: *routing_id,
                blob_ttl,
                blob: blob.to_vec(),
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
/// - `blob` = BEP44-signed DID document bytes
///
/// Then waits for the derived republish interval before the next publish.
/// On failure, retries with exponential backoff.
async fn relay_republish_loop<R: RelayPublisher>(
    relay_publisher: Arc<R>,
    entry: RepublishEntry,
    warning_cb: Option<RelayWarningCallback>,
    blob_ttl_secs: u64,
    republish_interval_secs: u64,
) {
    let routing_id = did_routing_id(&entry.did);
    let mut consecutive_failures: u32 = 0;

    loop {
        let result = relay_publisher
            .publish(&routing_id, blob_ttl_secs, &entry.document_bytes)
            .await;

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

/// Default lifetime of a migration republish task: 90 days (in seconds).
///
/// ADR-003 §4b (`.docs/adrs/phase-1.md`) states that `migrate_identity`
/// "Starts a background republish task for the old DID document (forwarding
/// record maintenance, recommended 90 days)." This constant is that 90 days.
///
/// The bound is what makes the task finite. A migration redirect exists so a
/// resolver holding the OLD DID can discover the new one; after 90 days of
/// forwarding, every such resolver has had ample opportunity to follow
/// `alsoKnownAs`, and continuing to re-put the old record only keeps a
/// superseded identity alive on the DHT. Without the bound the loop runs until
/// the process exits, which is a task leak per migration — the loop holds an
/// `Arc<D>` and a `RepublishEntry` and nothing ever frees them.
pub const MIGRATION_REPUBLISH_DURATION_SECS: u64 = 90 * 24 * 60 * 60;

/// Periodically republishes an old DID document with an `alsoKnownAs` redirect
/// to the new DID after identity migration.
///
/// After a DID migration, the old DID document needs to be periodically
/// republished with a redirect so that resolvers looking up the old DID can
/// discover the new one. This struct manages that background task.
///
/// # Lifetime
///
/// The task stops on its own after [`MIGRATION_REPUBLISH_DURATION_SECS`]
/// (90 days, ADR-003 §4b) — or after the duration
/// [`with_interval_and_duration`](Self::with_interval_and_duration) names.
/// A caller that wants to stop it earlier calls
/// [`MigrationHandle::cancel`] on the returned handle.
///
/// # Cancellation
///
/// A caller stops the background task early by calling
/// [`MigrationHandle::cancel`] on the returned handle. Dropping the handle
/// does NOT stop the task: [`MigrationHandle`] holds a
/// [`tokio::task::AbortHandle`], which releases the permission to abort when
/// it drops and leaves the spawned task running (tokio 1.50.0,
/// `src/runtime/task/abort.rs`: "Dropping an `AbortHandle` releases the
/// permission to terminate the task --- it does *not* abort the task").
/// Aborting on drop would defeat ADR-003 §4b: a caller that ignores the
/// returned handle would publish the redirect once and never again, so the
/// old DID would stop resolving as soon as its DHT record expired. The
/// 90-day bound, not the handle's drop, is what makes the task finite.
pub struct MigrationRepublisher<D: DhtClient> {
    dht_client: Arc<D>,
    interval_secs: u64,
    duration_secs: u64,
}

/// Handle to a running migration republish task.
///
/// [`cancel`](Self::cancel) stops the background republish task early.
/// Dropping this handle does NOT stop it — the inner
/// [`tokio::task::AbortHandle`] only releases the permission to abort when it
/// drops, so the spawned task keeps republishing until it reaches its own
/// duration bound (see [`MigrationRepublisher`]) or the runtime shuts down.
///
/// Cloning the handle yields a second holder of the same abort permission.
/// [`cancel`](Self::cancel) is idempotent, so two holders cancelling the same
/// task is well defined.
#[derive(Debug, Clone)]
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
    /// Creates a new migration republisher with the default interval (1 hour)
    /// and the default 90-day duration (ADR-003 §4b).
    #[must_use]
    pub const fn new(dht_client: Arc<D>) -> Self {
        Self {
            dht_client,
            interval_secs: MIGRATION_REPUBLISH_INTERVAL_SECS,
            duration_secs: MIGRATION_REPUBLISH_DURATION_SECS,
        }
    }

    /// Creates a new migration republisher with a custom interval and the
    /// default 90-day duration (ADR-003 §4b).
    #[must_use]
    pub const fn with_interval(dht_client: Arc<D>, interval_secs: u64) -> Self {
        Self {
            dht_client,
            interval_secs,
            duration_secs: MIGRATION_REPUBLISH_DURATION_SECS,
        }
    }

    /// Creates a new migration republisher with a custom interval and a custom
    /// duration.
    ///
    /// `duration_secs` bounds the total lifetime of the spawned task. A value
    /// of `0` still performs the first publish and then stops, because the
    /// loop publishes before it checks the deadline.
    #[must_use]
    pub const fn with_interval_and_duration(
        dht_client: Arc<D>,
        interval_secs: u64,
        duration_secs: u64,
    ) -> Self {
        Self {
            dht_client,
            interval_secs,
            duration_secs,
        }
    }

    /// Returns the total lifetime, in seconds, of the tasks this republisher
    /// starts.
    #[must_use]
    pub const fn duration_secs(&self) -> u64 {
        self.duration_secs
    }

    /// Starts the migration republish background task.
    ///
    /// The task immediately republishes the old DID document with the redirect,
    /// then repeats at the configured interval until the configured duration
    /// elapses. Returns a [`MigrationHandle`] that cancels the task early.
    #[must_use]
    pub fn start(&self, entry: RepublishEntry) -> MigrationHandle {
        let dht_client = Arc::clone(&self.dht_client);
        let interval_secs = self.interval_secs;
        let duration_secs = self.duration_secs;

        let join_handle = tokio::spawn(migration_republish_loop(
            dht_client,
            entry,
            interval_secs,
            duration_secs,
        ));

        MigrationHandle {
            abort_handle: join_handle.abort_handle(),
        }
    }
}

/// Background loop that periodically republishes a migration redirect, then
/// stops.
///
/// The loop publishes the entry, then sleeps `interval_secs`, and repeats until
/// `duration_secs` have elapsed since it started (ADR-003 §4b, "forwarding
/// record maintenance, recommended 90 days"). The deadline is measured on
/// [`tokio::time::Instant`], so a paused-clock test advances it
/// deterministically.
///
/// A failed publish is logged and retried on the same exponential backoff
/// [`dht_republish_loop`] uses, never swallowed. The redirect is what keeps the
/// OLD DID resolving to the new one, so an operator whose forwarding record is
/// lapsing has to be able to see it lapse.
async fn migration_republish_loop<D: DhtClient>(
    dht_client: Arc<D>,
    entry: RepublishEntry,
    interval_secs: u64,
    duration_secs: u64,
) {
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(duration_secs);
    let mut consecutive_failures: u32 = 0;

    loop {
        // Attempt to publish the old DID document (which should already contain
        // the alsoKnownAs redirect to the new DID).
        let result = dht_client
            .publish(
                &entry.public_key,
                &entry.signature,
                &entry.document_bytes,
                entry.sequence,
            )
            .await;

        let wait_secs = match result {
            Ok(()) => {
                consecutive_failures = 0;
                interval_secs
            }
            Err(e) => {
                consecutive_failures = consecutive_failures.saturating_add(1);
                tracing::warn!(
                    did = %entry.did,
                    error = %e,
                    consecutive_failures,
                    "migration redirect republish failed — the old DID's alsoKnownAs \
                     redirect may lapse from the DHT; retrying with backoff (ADR-003 §4b)"
                );
                backoff_secs(consecutive_failures.saturating_sub(1))
            }
        };

        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }

        // Never sleep past the deadline: a caller that names a duration shorter
        // than one interval gets one publish and a prompt stop, not a full
        // interval of idling.
        let sleep_for = tokio::time::Duration::from_secs(wait_secs)
            .min(deadline.saturating_duration_since(now));
        tokio::time::sleep(sleep_for).await;
    }

    tracing::info!(
        did = %entry.did,
        duration_secs,
        "migration republish task reached its forwarding-maintenance bound and stopped; \
         the old DID document will stop being refreshed on the DHT (ADR-003 §4b)"
    );
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

        let did_str = "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let entry = RepublishEntry {
            did: did_str.to_owned(),
            public_key: [1u8; 32],
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
        let expected_routing_id = did_routing_id(did_str);
        assert_eq!(
            publish.routing_id, expected_routing_id,
            "routing_id must be SHA-256('scp:did:' || did_string)"
        );
        assert_eq!(
            publish.blob_ttl, RELAY_BLOB_TTL_SECS,
            "blob_ttl must be 604800 (7 days)"
        );
        assert_eq!(
            publish.blob, b"BEP44-signed DID document",
            "blob must be the BEP44-signed DID document bytes"
        );

        // Verify DHT publish also happened.
        let dht_record = dht.resolve(&[1u8; 32]).await.unwrap();
        assert!(
            dht_record.is_some(),
            "DHT publish should also have occurred"
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
    async fn migration_republisher_defaults_to_the_adr003_ninety_day_bound() {
        let dht = Arc::new(InMemoryDhtClient::new());
        let republisher = MigrationRepublisher::new(dht);
        assert_eq!(
            republisher.duration_secs(),
            MIGRATION_REPUBLISH_DURATION_SECS,
            "the default migration republisher must carry the 90-day forwarding \
             bound ADR-003 §4b names"
        );
        assert_eq!(
            MIGRATION_REPUBLISH_DURATION_SECS,
            90 * 24 * 60 * 60,
            "MIGRATION_REPUBLISH_DURATION_SECS must be 90 days in seconds"
        );

        // `with_interval` keeps the same bound — only the interval changes.
        let dht2 = Arc::new(InMemoryDhtClient::new());
        assert_eq!(
            MigrationRepublisher::with_interval(dht2, 42).duration_secs(),
            MIGRATION_REPUBLISH_DURATION_SECS
        );
    }

    /// Counts every `publish` call and forwards to an in-memory DHT.
    ///
    /// `InMemoryDhtClient` treats a re-put at the same BEP44 sequence as an
    /// idempotent no-op, so the stored record alone cannot distinguish one
    /// publish from two thousand. The counter is the only signal that the
    /// forwarding loop kept re-putting the redirect.
    #[derive(Default)]
    struct CountingDhtClient {
        publishes: std::sync::atomic::AtomicU32,
        inner: InMemoryDhtClient,
    }

    impl CountingDhtClient {
        fn new() -> Self {
            Self {
                publishes: std::sync::atomic::AtomicU32::new(0),
                inner: InMemoryDhtClient::new(),
            }
        }

        fn count(&self) -> u32 {
            self.publishes.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[allow(clippy::manual_async_fn)]
    impl scp_dht::DhtClient for CountingDhtClient {
        fn publish(
            &self,
            public_key: &[u8; 32],
            signature: &[u8; 64],
            value: &[u8],
            seq: u64,
        ) -> impl Future<Output = Result<(), scp_dht::DhtError>> + Send {
            let pk = *public_key;
            let sig = *signature;
            let val = value.to_vec();
            async move {
                self.publishes
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                self.inner.publish(&pk, &sig, &val, seq).await
            }
        }

        fn resolve(
            &self,
            public_key: &[u8; 32],
        ) -> impl Future<Output = Result<Option<scp_dht::DhtRecord>, scp_dht::DhtError>> + Send
        {
            let pk = *public_key;
            async move { self.inner.resolve(&pk).await }
        }
    }

    /// The forwarding task republishes on its interval and then STOPS at its
    /// duration bound — it does not run for the life of the process
    /// (ADR-003 §4b, "recommended 90 days").
    ///
    /// The clock is paused, so tokio advances time only when every task is
    /// idle; the test's own `sleep` is what lets the loop's 2160 hourly cycles
    /// run to completion in milliseconds of wall time.
    #[tokio::test(start_paused = true)]
    async fn migration_republish_loop_stops_at_its_duration_bound() {
        let dht = Arc::new(CountingDhtClient::new());
        let republisher = MigrationRepublisher::with_interval_and_duration(
            Arc::clone(&dht),
            MIGRATION_REPUBLISH_INTERVAL_SECS,
            MIGRATION_REPUBLISH_DURATION_SECS,
        );

        let handle = republisher.start(make_migration_entry());
        assert!(handle.is_active());

        // Halfway through the bound the task is still republishing.
        tokio::time::sleep(tokio::time::Duration::from_secs(
            MIGRATION_REPUBLISH_DURATION_SECS / 2,
        ))
        .await;
        assert!(
            handle.is_active(),
            "the forwarding task must still run 45 days into a 90-day bound"
        );
        let halfway = dht.count();
        assert!(
            halfway > 1000,
            "an hourly loop must have published far more than once after 45 days; got {halfway}"
        );

        // Past the bound it has stopped on its own, with no cancel call.
        tokio::time::sleep(tokio::time::Duration::from_secs(
            MIGRATION_REPUBLISH_DURATION_SECS / 2 + 7200,
        ))
        .await;
        assert!(
            !handle.is_active(),
            "the forwarding task must stop at its 90-day bound without being cancelled"
        );

        let final_count = dht.count();
        assert!(
            final_count > halfway,
            "the task must keep republishing between the halfway point and the bound"
        );

        // And it publishes nothing more afterwards.
        tokio::time::sleep(tokio::time::Duration::from_secs(
            MIGRATION_REPUBLISH_DURATION_SECS,
        ))
        .await;
        assert_eq!(
            dht.count(),
            final_count,
            "a stopped forwarding task must publish nothing further"
        );
    }

    /// A duration shorter than one interval yields exactly one publish and a
    /// prompt stop, rather than one publish followed by a full interval of
    /// idling.
    #[tokio::test(start_paused = true)]
    async fn migration_republish_loop_honors_a_sub_interval_duration() {
        let dht = Arc::new(CountingDhtClient::new());
        let republisher =
            MigrationRepublisher::with_interval_and_duration(Arc::clone(&dht), 3600, 60);

        let handle = republisher.start(make_migration_entry());

        tokio::time::sleep(tokio::time::Duration::from_secs(120)).await;

        assert!(
            !handle.is_active(),
            "a 60-second bound must stop the task well inside one 3600-second interval"
        );
        assert_eq!(
            dht.count(),
            2,
            "a 60-second bound at a 3600-second interval publishes once immediately \
             and once at the deadline"
        );
    }

    /// A DHT that rejects every publish, so the forwarding loop's failure arm
    /// runs.
    #[derive(Default)]
    struct AlwaysFailDhtClient {
        attempts: std::sync::atomic::AtomicU32,
    }

    #[allow(clippy::manual_async_fn)]
    impl scp_dht::DhtClient for AlwaysFailDhtClient {
        fn publish(
            &self,
            _public_key: &[u8; 32],
            _signature: &[u8; 64],
            _value: &[u8],
            _seq: u64,
        ) -> impl Future<Output = Result<(), scp_dht::DhtError>> + Send {
            self.attempts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async move {
                Err(scp_dht::DhtError::DhtPublishFailed(
                    "simulated DHT rejection".to_owned(),
                ))
            }
        }

        fn resolve(
            &self,
            _public_key: &[u8; 32],
        ) -> impl Future<Output = Result<Option<scp_dht::DhtRecord>, scp_dht::DhtError>> + Send
        {
            async move { Ok(None) }
        }
    }

    /// A failing publish is retried on backoff rather than swallowed, and the
    /// duration bound still stops the task.
    #[tokio::test(start_paused = true)]
    async fn migration_republish_loop_retries_failures_and_still_stops() {
        let dht = Arc::new(AlwaysFailDhtClient::default());
        let republisher = MigrationRepublisher::with_interval_and_duration(
            Arc::clone(&dht),
            MIGRATION_REPUBLISH_INTERVAL_SECS,
            // Two hours: long enough for several 30s-to-30min backoff retries,
            // short enough to keep the assertion legible.
            2 * 60 * 60,
        );

        let handle = republisher.start(make_migration_entry());

        tokio::time::sleep(tokio::time::Duration::from_mins(2 * 60 + 1)).await;

        let attempts = dht.attempts.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            attempts >= 5,
            "a failing publish must retry on the 30s/1m/2m/4m/8m backoff inside two \
             hours, not wait a full hour between attempts; got {attempts}"
        );
        assert!(
            !handle.is_active(),
            "the duration bound must stop the task even while every publish fails"
        );
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
            _routing_id: &[u8; 32],
            _blob_ttl: u64,
            _blob: &[u8],
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
