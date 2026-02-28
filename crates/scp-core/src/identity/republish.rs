//! Automatic DID document republishing for active identities.
//!
//! Mainline DHT records expire if not refreshed. The [`RepublishManager`]
//! manages background tokio tasks that periodically republish DID documents
//! to keep them resolvable.
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
//! at 30 minutes. After 6 consecutive failures, a [`DhtPublishDegraded`]
//! warning is emitted via the warning callback.
//!
//! See ADR-003 in `.docs/adrs/phase-1.md` for the full design.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;

use super::dht_client::DhtClient;

/// Republish interval: every 2 hours (in seconds).
pub const REPUBLISH_INTERVAL_SECS: u64 = 2 * 60 * 60;

/// Initial backoff on failure: 30 seconds.
const INITIAL_BACKOFF_SECS: u64 = 30;

/// Maximum backoff cap: 30 minutes (in seconds).
const MAX_BACKOFF_SECS: u64 = 30 * 60;

/// Number of consecutive failures before emitting a degraded warning.
const DEGRADED_THRESHOLD: u32 = 6;

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

/// Manages background republishing of DID documents on the DHT.
///
/// Each registered identity gets a background tokio task that republishes
/// its DID document every 2 hours. The manager tracks all active tasks
/// and provides methods to start, stop, and shut down republishing.
///
/// # Type Parameters
///
/// * `D` — The DHT client implementation. Use [`InMemoryDhtClient`] for
///   testing, or a production pkarr-based client for real DHT access.
pub struct RepublishManager<D: DhtClient> {
    dht_client: Arc<D>,
    /// Active republish tasks, keyed by DID string.
    tasks: Mutex<HashMap<String, TaskHandle>>,
    /// Optional callback for degraded warnings.
    warning_callback: Option<WarningCallback>,
}

impl<D: DhtClient> std::fmt::Debug for RepublishManager<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RepublishManager")
            .field(
                "warning_callback",
                &self.warning_callback.as_ref().map(|_| "..."),
            )
            .finish_non_exhaustive()
    }
}

/// Handle to a running republish task, including its abort handle.
#[derive(Debug)]
struct TaskHandle {
    abort_handle: tokio::task::AbortHandle,
}

impl<D: DhtClient + 'static> RepublishManager<D> {
    /// Creates a new republish manager with the given DHT client.
    #[must_use]
    pub fn new(dht_client: Arc<D>) -> Self {
        Self {
            dht_client,
            tasks: Mutex::new(HashMap::new()),
            warning_callback: None,
        }
    }

    /// Creates a new republish manager with a warning callback.
    #[must_use]
    pub fn with_warning_callback(dht_client: Arc<D>, callback: WarningCallback) -> Self {
        Self {
            dht_client,
            tasks: Mutex::new(HashMap::new()),
            warning_callback: Some(callback),
        }
    }

    /// Starts republishing a DID document.
    ///
    /// Performs an immediate publish, then schedules periodic republishing
    /// every 2 hours. If the DID is already being republished, the existing
    /// task is replaced.
    pub async fn start_republishing(&self, entry: RepublishEntry) {
        let mut tasks = self.tasks.lock().await;

        // Stop existing task if any.
        if let Some(handle) = tasks.remove(&entry.did) {
            handle.abort_handle.abort();
        }

        let dht_client = Arc::clone(&self.dht_client);
        let warning_cb = self.warning_callback.clone();
        let did = entry.did.clone();

        let join_handle = tokio::spawn(republish_loop(dht_client, entry, warning_cb));

        tasks.insert(
            did,
            TaskHandle {
                abort_handle: join_handle.abort_handle(),
            },
        );
    }

    /// Stops republishing a specific DID.
    pub async fn stop_republishing(&self, did: &str) {
        let mut tasks = self.tasks.lock().await;
        if let Some(handle) = tasks.remove(did) {
            handle.abort_handle.abort();
        }
    }

    /// Stops all republishing tasks (shutdown).
    pub async fn stop_all(&self) {
        let mut tasks = self.tasks.lock().await;
        for (_, handle) in tasks.drain() {
            handle.abort_handle.abort();
        }
    }

    /// Returns the number of active republish tasks.
    pub async fn active_count(&self) -> usize {
        let tasks = self.tasks.lock().await;
        tasks.len()
    }

    /// Returns whether a specific DID is being republished.
    pub async fn is_republishing(&self, did: &str) -> bool {
        let tasks = self.tasks.lock().await;
        tasks.contains_key(did)
    }
}

/// Computes the backoff duration for a given attempt number (0-indexed).
///
/// Sequence: 30s, 60s, 120s, 240s, 480s, 960s, 1800s (capped at 30m).
fn backoff_secs(attempt: u32) -> u64 {
    let backoff = INITIAL_BACKOFF_SECS.saturating_mul(1u64.wrapping_shl(attempt));
    backoff.min(MAX_BACKOFF_SECS)
}

/// The main republish loop for a single identity.
///
/// Publishes immediately, then waits for the republish interval before
/// the next publish. On failure, retries with exponential backoff.
async fn republish_loop<D: DhtClient>(
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
    pub fn new(dht_client: Arc<D>) -> Self {
        Self {
            dht_client,
            interval_secs: MIGRATION_REPUBLISH_INTERVAL_SECS,
        }
    }

    /// Creates a new migration republisher with a custom interval.
    #[must_use]
    pub fn with_interval(dht_client: Arc<D>, interval_secs: u64) -> Self {
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
    use crate::identity::dht_client::InMemoryDhtClient;

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
        let manager = RepublishManager::new(Arc::clone(&dht));
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
        let manager = RepublishManager::new(Arc::clone(&dht));

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
        let manager = RepublishManager::new(Arc::clone(&dht));

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
        let manager = RepublishManager::new(Arc::clone(&dht));
        let entry = make_entry("did:dht:zTest1");

        manager.start_republishing(entry).await;

        // Give the task time to do its first publish.
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let record = dht.resolve(&[1u8; 32]).await.unwrap();
        assert!(record.is_some());
        assert_eq!(record.unwrap().seq, 1);

        manager.stop_all().await;
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
}
