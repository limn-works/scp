//! DID resolution cache with TTL-based staleness detection.
//!
//! Caches resolved DID documents to avoid redundant DHT lookups. Implements
//! two TTL tiers per ADR-003 Decision 9:
//!
//! - **Active contacts:** 24-hour refresh interval
//! - **Inactive contacts:** 7-day refresh interval
//!
//! A cached entry becomes stale when its age exceeds the expected republish
//! window (2 hours + 30 minute grace period). Stale entries are still returned
//! (the last known document is better than nothing) but carry a staleness
//! indicator so callers can decide whether to attempt a fresh DHT resolution.
//!
//! See ADR-003 in `.docs/adrs/phase-1.md` for the full design.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;

use super::document::DidDocument;

/// Refresh interval for active contacts: 24 hours in seconds.
const ACTIVE_REFRESH_SECS: u64 = 24 * 60 * 60;

/// Refresh interval for inactive contacts: 7 days in seconds.
const INACTIVE_REFRESH_SECS: u64 = 7 * 24 * 60 * 60;

/// Expected republish window: 2 hours + 30 minutes grace, in seconds.
/// If a cached entry was last verified more than this long ago, it is
/// considered stale (the publisher may have stopped republishing).
const STALENESS_THRESHOLD_SECS: u64 = 2 * 60 * 60 + 30 * 60;

/// Indicates whether a cached DID resolution result is fresh or stale.
///
/// A result is stale when the cached document has not been verified against
/// the DHT within the expected republish window (2h + 30m grace). Stale
/// results may reflect outdated key material (e.g., a key rotation occurred
/// but the cache has not seen it yet).
///
/// See ADR-003 acceptance criterion 2 (stale DID resolution).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Staleness {
    /// The cached result was verified within the expected republish window.
    Fresh,
    /// The cached result has not been verified recently. `last_verified` is the
    /// Unix timestamp (seconds) when the entry was last confirmed via DHT.
    Stale {
        /// Unix timestamp of last successful DHT verification.
        last_verified: u64,
    },
}

/// The result of a DID resolution, including the document and staleness
/// information.
///
/// See ADR-003 acceptance criterion 2.
#[derive(Debug, Clone)]
pub struct DidResolutionResult {
    /// The resolved DID document.
    pub document: DidDocument,
    /// Whether this result is fresh or stale.
    pub staleness: Staleness,
    /// The BEP44 sequence number of the cached document.
    pub sequence: u64,
}

/// A single cached entry for a DID.
#[derive(Debug, Clone)]
struct CacheEntry {
    /// The resolved DID document.
    document: DidDocument,
    /// BEP44 sequence number of the cached document.
    sequence: u64,
    /// Unix timestamp (seconds) when this entry was last verified via DHT.
    last_verified: u64,
    /// Whether this DID is an active contact (shorter refresh interval).
    active: bool,
}

/// Provides a time source for the cache, enabling deterministic testing.
///
/// Production code uses [`SystemClock`]. Tests use [`TestClock`] to control
/// time progression without waiting for real time to pass.
pub trait Clock: Send + Sync {
    /// Returns the current time as a Unix timestamp in seconds.
    fn now(&self) -> u64;
}

/// Clock implementation that uses the real system clock.
#[derive(Debug, Clone, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    #[allow(clippy::expect_used)]
    fn now(&self) -> u64 {
        // The Clock trait returns u64 (not Result), so we cannot propagate the
        // error. A system clock before the Unix epoch is an unrecoverable
        // environment failure — panicking is the correct behaviour here, as
        // silently returning 0 would bypass UCAN expiry and nonce freshness
        // checks.
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock is unavailable or before Unix epoch")
            .as_secs()
    }
}

/// Clock implementation for tests that allows manual time control.
#[derive(Debug)]
pub struct TestClock {
    now: std::sync::atomic::AtomicU64,
}

impl TestClock {
    /// Creates a new test clock starting at the given Unix timestamp.
    #[must_use]
    pub const fn new(start: u64) -> Self {
        Self {
            now: std::sync::atomic::AtomicU64::new(start),
        }
    }

    /// Advances the clock by the given number of seconds.
    pub fn advance(&self, secs: u64) {
        self.now
            .fetch_add(secs, std::sync::atomic::Ordering::Relaxed);
    }

    /// Sets the clock to a specific timestamp.
    pub fn set(&self, timestamp: u64) {
        self.now
            .store(timestamp, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Clock for TestClock {
    fn now(&self) -> u64 {
        self.now.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Blanket implementation for `Arc<T>` so clocks can be shared between the
/// cache and test code that needs to advance time.
impl<T: Clock> Clock for Arc<T> {
    fn now(&self) -> u64 {
        (**self).now()
    }
}

/// TTL-based cache for resolved DID documents.
///
/// Stores resolved DID documents indexed by DID string. Each entry tracks
/// its last verification time and whether it belongs to an active contact.
/// Active contacts use a 24-hour refresh interval; inactive contacts use
/// a 7-day refresh interval.
///
/// The cache does not proactively evict entries. It simply reports whether
/// a cached entry needs refresh or is stale based on the current time.
///
/// # Thread Safety
///
/// All state is protected by a `tokio::sync::Mutex`.
#[derive(Debug)]
pub struct DidCache<C: Clock = SystemClock> {
    entries: Mutex<HashMap<String, CacheEntry>>,
    clock: C,
}

impl DidCache<SystemClock> {
    /// Creates a new DID cache with the system clock.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            clock: SystemClock,
        }
    }
}

impl Default for DidCache<SystemClock> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: Clock> DidCache<C> {
    /// Creates a new DID cache with a custom clock (for testing).
    #[must_use]
    pub fn with_clock(clock: C) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            clock,
        }
    }

    /// Looks up a cached DID document.
    ///
    /// Returns `Some(result)` with staleness information if the entry exists
    /// and has not exceeded its TTL. Returns `None` if the entry does not
    /// exist or has exceeded its TTL (needs re-resolution from DHT).
    ///
    /// An entry that is stale (not verified within the republish window) is
    /// still returned — the caller should attempt a fresh resolution but can
    /// fall back to the stale result if the DHT is unreachable.
    pub async fn get(&self, did: &str) -> Option<DidResolutionResult> {
        let entries = self.entries.lock().await;
        let entry = entries.get(did)?.clone();
        drop(entries);

        let now = self.clock.now();
        let age = now.saturating_sub(entry.last_verified);

        // Check TTL: if the entry has exceeded its refresh interval, it should
        // be re-resolved. We return None to signal that a fresh resolution is
        // needed.
        let ttl = if entry.active {
            ACTIVE_REFRESH_SECS
        } else {
            INACTIVE_REFRESH_SECS
        };

        if age > ttl {
            return None;
        }

        // Entry is within TTL but may be stale (publisher may have stopped
        // republishing within the expected 2h + 30m window).
        let staleness = if age > STALENESS_THRESHOLD_SECS {
            Staleness::Stale {
                last_verified: entry.last_verified,
            }
        } else {
            Staleness::Fresh
        };

        Some(DidResolutionResult {
            document: entry.document,
            staleness,
            sequence: entry.sequence,
        })
    }

    /// Inserts or updates a cached DID document.
    ///
    /// If the DID already exists in the cache, the entry is only updated if
    /// the new sequence number is strictly greater than the existing one
    /// (BEP44 ordering). The `last_verified` timestamp is set to the current
    /// time.
    ///
    /// New entries default to inactive. Use [`mark_active`](DidCache::mark_active)
    /// to set a DID as an active contact.
    pub async fn insert(&self, did: &str, document: DidDocument, sequence: u64) {
        let mut entries = self.entries.lock().await;
        let now = self.clock.now();

        // If entry exists, only update if new sequence is strictly greater.
        if let Some(existing) = entries.get(did)
            && sequence <= existing.sequence
        {
            return;
        }

        let active = entries.get(did).is_some_and(|e| e.active);

        entries.insert(
            did.to_owned(),
            CacheEntry {
                document,
                sequence,
                last_verified: now,
                active,
            },
        );
    }

    /// Marks a DID as an active contact (24-hour refresh interval).
    ///
    /// Active contacts are refreshed more frequently because they are
    /// communicating partners whose key material changes matter more.
    pub async fn mark_active(&self, did: &str) {
        let mut entries = self.entries.lock().await;
        if let Some(entry) = entries.get_mut(did) {
            entry.active = true;
        }
    }

    /// Marks a DID as inactive (7-day refresh interval).
    pub async fn mark_inactive(&self, did: &str) {
        let mut entries = self.entries.lock().await;
        if let Some(entry) = entries.get_mut(did) {
            entry.active = false;
        }
    }

    /// Checks whether a cached entry needs refresh (TTL exceeded) without
    /// returning the entry.
    pub async fn needs_refresh(&self, did: &str) -> bool {
        let entries = self.entries.lock().await;
        let Some(entry) = entries.get(did) else {
            return true;
        };

        let age = self.clock.now().saturating_sub(entry.last_verified);
        let ttl = if entry.active {
            ACTIVE_REFRESH_SECS
        } else {
            INACTIVE_REFRESH_SECS
        };
        drop(entries);

        age > ttl
    }

    /// Returns the cached sequence number for a DID, if present.
    pub async fn cached_sequence(&self, did: &str) -> Option<u64> {
        let entries = self.entries.lock().await;
        entries.get(did).map(|e| e.sequence)
    }

    /// Removes a DID from the cache.
    pub async fn remove(&self, did: &str) {
        let mut entries = self.entries.lock().await;
        entries.remove(did);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn make_document(did: &str) -> DidDocument {
        DidDocument::new(did, &[1u8; 32], &[2u8; 32], &[3u8; 32])
    }

    #[tokio::test]
    async fn insert_and_get_returns_fresh_result() {
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = DidCache::with_clock(clock);
        let did = "did:dht:zTest123";
        let doc = make_document(did);

        cache.insert(did, doc.clone(), 1).await;
        let result = cache.get(did).await.unwrap();

        assert_eq!(result.document, doc);
        assert_eq!(result.sequence, 1);
        assert_eq!(result.staleness, Staleness::Fresh);
    }

    #[tokio::test]
    async fn get_returns_none_for_missing_did() {
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = DidCache::with_clock(clock);

        assert!(cache.get("did:dht:zMissing").await.is_none());
    }

    #[tokio::test]
    async fn entry_becomes_stale_after_staleness_threshold() {
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = DidCache::with_clock(Arc::clone(&clock));
        let did = "did:dht:zTest123";
        let doc = make_document(did);

        cache.insert(did, doc, 1).await;

        // Advance past staleness threshold (2h30m + 1s)
        clock.advance(STALENESS_THRESHOLD_SECS + 1);

        let result = cache.get(did).await.unwrap();
        assert!(matches!(
            result.staleness,
            Staleness::Stale {
                last_verified: 1_000_000
            }
        ));
    }

    #[tokio::test]
    async fn inactive_entry_expires_after_7_days() {
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = DidCache::with_clock(Arc::clone(&clock));
        let did = "did:dht:zTest123";
        let doc = make_document(did);

        cache.insert(did, doc, 1).await;

        // Advance past 7-day TTL
        clock.advance(INACTIVE_REFRESH_SECS + 1);

        assert!(cache.get(did).await.is_none());
    }

    #[tokio::test]
    async fn active_entry_expires_after_24_hours() {
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = DidCache::with_clock(Arc::clone(&clock));
        let did = "did:dht:zTest123";
        let doc = make_document(did);

        cache.insert(did, doc, 1).await;
        cache.mark_active(did).await;

        // Advance past 24-hour TTL
        clock.advance(ACTIVE_REFRESH_SECS + 1);

        assert!(cache.get(did).await.is_none());
    }

    #[tokio::test]
    async fn active_entry_survives_within_24_hours() {
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = DidCache::with_clock(Arc::clone(&clock));
        let did = "did:dht:zTest123";
        let doc = make_document(did);

        cache.insert(did, doc, 1).await;
        cache.mark_active(did).await;

        // Just under 24 hours
        clock.advance(ACTIVE_REFRESH_SECS - 1);

        assert!(cache.get(did).await.is_some());
    }

    #[tokio::test]
    async fn insert_with_lower_sequence_is_ignored() {
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = DidCache::with_clock(clock);
        let did = "did:dht:zTest123";
        let doc1 = make_document(did);
        let doc2 = DidDocument::new(did, &[10u8; 32], &[20u8; 32], &[30u8; 32]);

        cache.insert(did, doc1.clone(), 5).await;
        cache.insert(did, doc2, 3).await;

        let result = cache.get(did).await.unwrap();
        assert_eq!(result.document, doc1);
        assert_eq!(result.sequence, 5);
    }

    #[tokio::test]
    async fn insert_with_same_sequence_is_rejected() {
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = DidCache::with_clock(clock);
        let did = "did:dht:zTest123";
        let doc1 = make_document(did);
        let doc2 = DidDocument::new(did, &[10u8; 32], &[20u8; 32], &[30u8; 32]);

        cache.insert(did, doc1.clone(), 5).await;
        cache.insert(did, doc2, 5).await;

        let result = cache.get(did).await.unwrap();
        assert_eq!(result.document, doc1);
        assert_eq!(result.sequence, 5);
    }

    #[tokio::test]
    async fn insert_with_higher_sequence_updates_entry() {
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = DidCache::with_clock(clock);
        let did = "did:dht:zTest123";
        let doc1 = make_document(did);
        let doc2 = DidDocument::new(did, &[10u8; 32], &[20u8; 32], &[30u8; 32]);

        cache.insert(did, doc1, 1).await;
        cache.insert(did, doc2.clone(), 2).await;

        let result = cache.get(did).await.unwrap();
        assert_eq!(result.document, doc2);
        assert_eq!(result.sequence, 2);
    }

    #[tokio::test]
    async fn mark_active_preserves_existing_entry() {
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = DidCache::with_clock(clock);
        let did = "did:dht:zTest123";
        let doc = make_document(did);

        cache.insert(did, doc.clone(), 1).await;
        cache.mark_active(did).await;

        let result = cache.get(did).await.unwrap();
        assert_eq!(result.document, doc);
    }

    #[tokio::test]
    async fn needs_refresh_returns_true_for_missing() {
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = DidCache::with_clock(clock);

        assert!(cache.needs_refresh("did:dht:zMissing").await);
    }

    #[tokio::test]
    async fn needs_refresh_returns_false_for_fresh() {
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = DidCache::with_clock(clock);
        let did = "did:dht:zTest123";
        let doc = make_document(did);

        cache.insert(did, doc, 1).await;

        assert!(!cache.needs_refresh(did).await);
    }

    #[tokio::test]
    async fn remove_deletes_entry() {
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = DidCache::with_clock(clock);
        let did = "did:dht:zTest123";
        let doc = make_document(did);

        cache.insert(did, doc, 1).await;
        cache.remove(did).await;

        assert!(cache.get(did).await.is_none());
    }

    #[tokio::test]
    async fn staleness_is_fresh_within_republish_window() {
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = DidCache::with_clock(Arc::clone(&clock));
        let did = "did:dht:zTest123";
        let doc = make_document(did);

        cache.insert(did, doc, 1).await;

        // Advance to just within the staleness threshold
        clock.advance(STALENESS_THRESHOLD_SECS - 1);

        let result = cache.get(did).await.unwrap();
        assert_eq!(result.staleness, Staleness::Fresh);
    }
}
