//! Handle-based addressing and resolution cache for SCP discovery.
//!
//! Provides a bounded LRU cache for resolved handle-to-target mappings. The
//! cache has a configurable capacity (default: 10,000 entries) to prevent
//! unbounded memory growth that could be exploited as a denial-of-service vector.
//!
//! The cache also supports TTL-based expiry via [`evict_expired`] as a
//! defense-in-depth mechanism alongside LRU eviction.
//!
//! See spec section 22.9.

use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use lru::LruCache;

use super::handles::HandleTarget;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default maximum capacity of the resolution cache.
pub const DEFAULT_CACHE_CAPACITY: usize = 10_000;

/// Default TTL for cache entries (10 minutes).
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(600);

// ---------------------------------------------------------------------------
// CacheEntry
// ---------------------------------------------------------------------------

/// A cached resolution result with expiry metadata.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// The resolved target.
    pub target: HandleTarget,
    /// When this entry was inserted into the cache.
    pub inserted_at: Instant,
    /// Time-to-live for this entry.
    pub ttl: Duration,
}

impl CacheEntry {
    /// Returns `true` if this entry has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.inserted_at.elapsed() >= self.ttl
    }
}

// ---------------------------------------------------------------------------
// ResolutionCache
// ---------------------------------------------------------------------------

/// Bounded LRU cache for handle resolution results.
///
/// Uses `lru::LruCache` to enforce a maximum capacity, evicting the least
/// recently used entry when full. Entries also have a configurable TTL;
/// expired entries are returned as cache misses and can be proactively
/// cleaned via [`evict_expired`].
///
/// # Why LRU instead of unbounded `HashMap`
///
/// An unbounded cache is a denial-of-service vector: an attacker can flood the resolver
/// with unique handles to exhaust memory. The LRU bound caps memory usage
/// at `O(capacity)` regardless of query volume.
pub struct ResolutionCache {
    /// The bounded LRU cache.
    cache: LruCache<String, CacheEntry>,
    /// Default TTL for new entries.
    default_ttl: Duration,
}

impl ResolutionCache {
    /// Creates a new resolution cache with the given capacity and default TTL.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is 0. Use [`DEFAULT_CACHE_CAPACITY`] for the
    /// standard default.
    #[must_use]
    pub fn new(capacity: usize, default_ttl: Duration) -> Self {
        let cap = NonZeroUsize::new(capacity).unwrap_or_else(|| {
            NonZeroUsize::new(DEFAULT_CACHE_CAPACITY).unwrap_or(
                // SAFETY: DEFAULT_CACHE_CAPACITY (10_000) is non-zero.
                NonZeroUsize::MIN,
            )
        });
        Self {
            cache: LruCache::new(cap),
            default_ttl,
        }
    }

    /// Creates a new resolution cache with default capacity and TTL.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_CACHE_CAPACITY, DEFAULT_CACHE_TTL)
    }

    /// Inserts a resolution result into the cache.
    ///
    /// If the cache is at capacity, the least recently used entry is evicted.
    /// If the handle already exists, its entry is replaced and promoted to
    /// most-recently-used.
    pub fn insert(&mut self, handle: String, target: HandleTarget) {
        let entry = CacheEntry {
            target,
            inserted_at: Instant::now(),
            ttl: self.default_ttl,
        };
        self.cache.put(handle, entry);
    }

    /// Inserts a resolution result with a custom TTL.
    pub fn insert_with_ttl(&mut self, handle: String, target: HandleTarget, ttl: Duration) {
        let entry = CacheEntry {
            target,
            inserted_at: Instant::now(),
            ttl,
        };
        self.cache.put(handle, entry);
    }

    /// Looks up a handle in the cache.
    ///
    /// Returns `None` if the handle is not cached or if the cached entry has
    /// expired. Expired entries are lazily removed on access.
    pub fn get(&mut self, handle: &str) -> Option<&HandleTarget> {
        // Check if the entry exists and is not expired.
        let expired = self.cache.peek(handle).is_some_and(CacheEntry::is_expired);

        if expired {
            self.cache.pop(handle);
            return None;
        }

        self.cache.get(handle).map(|entry| &entry.target)
    }

    /// Removes a specific handle from the cache.
    ///
    /// Returns `true` if the handle was present and removed.
    pub fn remove(&mut self, handle: &str) -> bool {
        self.cache.pop(handle).is_some()
    }

    /// Evicts all expired entries from the cache.
    ///
    /// This is a defense-in-depth mechanism that proactively removes expired
    /// entries. LRU eviction handles memory bounding; this handles staleness.
    ///
    /// Returns the number of entries evicted.
    pub fn evict_expired(&mut self) -> usize {
        // Collect expired keys first to avoid borrowing issues.
        let expired_keys: Vec<String> = self
            .cache
            .iter()
            .filter(|(_, entry)| entry.is_expired())
            .map(|(key, _)| key.clone())
            .collect();

        let count = expired_keys.len();
        for key in expired_keys {
            self.cache.pop(&key);
        }
        count
    }

    /// Returns the number of entries currently in the cache.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Returns `true` if the cache contains no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Returns the maximum capacity of the cache.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.cache.cap().get()
    }
}

impl Default for ResolutionCache {
    fn default() -> Self {
        Self::with_defaults()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::identity::DID;

    fn identity_target(did: &str) -> HandleTarget {
        HandleTarget::Identity(DID::from(did))
    }

    fn context_target(ctx: &str) -> HandleTarget {
        HandleTarget::Context(ctx.to_owned())
    }

    // -- Construction --------------------------------------------------------

    #[test]
    fn with_defaults_creates_cache_with_expected_capacity() {
        let cache = ResolutionCache::with_defaults();
        assert_eq!(cache.capacity(), DEFAULT_CACHE_CAPACITY);
        assert!(cache.is_empty());
    }

    #[test]
    fn custom_capacity_is_respected() {
        let cache = ResolutionCache::new(100, DEFAULT_CACHE_TTL);
        assert_eq!(cache.capacity(), 100);
    }

    #[test]
    fn zero_capacity_falls_back_to_default() {
        let cache = ResolutionCache::new(0, DEFAULT_CACHE_TTL);
        assert_eq!(cache.capacity(), DEFAULT_CACHE_CAPACITY);
    }

    // -- Insert and get ------------------------------------------------------

    #[test]
    fn insert_and_get_returns_target() {
        let mut cache = ResolutionCache::with_defaults();
        cache.insert("alice@scp".to_owned(), identity_target("did:dht:z6MkAlice"));

        let target = cache.get("alice@scp").unwrap();
        assert_eq!(*target, identity_target("did:dht:z6MkAlice"));
    }

    #[test]
    fn get_unknown_returns_none() {
        let mut cache = ResolutionCache::with_defaults();
        assert!(cache.get("unknown@scp").is_none());
    }

    #[test]
    fn insert_replaces_existing_entry() {
        let mut cache = ResolutionCache::with_defaults();
        cache.insert("alice@scp".to_owned(), identity_target("did:dht:z6MkAlice"));
        cache.insert("alice@scp".to_owned(), context_target("ctx-new"));

        let target = cache.get("alice@scp").unwrap();
        assert_eq!(*target, context_target("ctx-new"));
    }

    // -- LRU eviction --------------------------------------------------------

    #[test]
    fn lru_eviction_when_at_capacity() {
        let mut cache = ResolutionCache::new(2, DEFAULT_CACHE_TTL);

        cache.insert("a@scp".to_owned(), identity_target("did:a"));
        cache.insert("b@scp".to_owned(), identity_target("did:b"));

        // Access "a" to make it recently used.
        let _ = cache.get("a@scp");

        // Insert "c" -- should evict "b" (least recently used).
        cache.insert("c@scp".to_owned(), identity_target("did:c"));

        assert!(cache.get("a@scp").is_some(), "a should still be cached");
        assert!(cache.get("b@scp").is_none(), "b should have been evicted");
        assert!(cache.get("c@scp").is_some(), "c should be cached");
    }

    #[test]
    fn capacity_is_bounded() {
        let mut cache = ResolutionCache::new(3, DEFAULT_CACHE_TTL);

        for i in 0..100 {
            cache.insert(format!("handle-{i}"), identity_target("did:test"));
        }

        // Cache should never exceed capacity.
        assert_eq!(cache.len(), 3);
    }

    // -- TTL expiry ----------------------------------------------------------

    #[test]
    fn expired_entry_returns_none_on_get() {
        let mut cache = ResolutionCache::new(100, Duration::from_millis(0));

        cache.insert("alice@scp".to_owned(), identity_target("did:dht:z6MkAlice"));

        // With TTL=0, the entry is immediately expired.
        assert!(cache.get("alice@scp").is_none());
    }

    #[test]
    fn evict_expired_removes_stale_entries() {
        let mut cache = ResolutionCache::new(100, Duration::from_millis(0));

        cache.insert("a@scp".to_owned(), identity_target("did:a"));
        cache.insert("b@scp".to_owned(), identity_target("did:b"));

        // Both entries are expired (TTL=0).
        let evicted = cache.evict_expired();
        assert_eq!(evicted, 2);
        assert!(cache.is_empty());
    }

    #[test]
    fn evict_expired_keeps_fresh_entries() {
        let mut cache = ResolutionCache::new(100, Duration::from_secs(3600));

        cache.insert("fresh@scp".to_owned(), identity_target("did:fresh"));

        let evicted = cache.evict_expired();
        assert_eq!(evicted, 0);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn insert_with_custom_ttl() {
        let mut cache = ResolutionCache::new(100, Duration::from_secs(3600));

        // Insert with TTL=0 (immediately expired).
        cache.insert_with_ttl(
            "short@scp".to_owned(),
            identity_target("did:short"),
            Duration::from_millis(0),
        );

        // Insert with default (long) TTL.
        cache.insert("long@scp".to_owned(), identity_target("did:long"));

        assert!(
            cache.get("short@scp").is_none(),
            "short TTL should be expired"
        );
        assert!(cache.get("long@scp").is_some(), "long TTL should be fresh");
    }

    // -- Remove --------------------------------------------------------------

    #[test]
    fn remove_deletes_entry() {
        let mut cache = ResolutionCache::with_defaults();
        cache.insert("alice@scp".to_owned(), identity_target("did:dht:z6MkAlice"));

        assert!(cache.remove("alice@scp"));
        assert!(cache.get("alice@scp").is_none());
    }

    #[test]
    fn remove_unknown_returns_false() {
        let mut cache = ResolutionCache::with_defaults();
        assert!(!cache.remove("unknown@scp"));
    }

    // -- len / is_empty ------------------------------------------------------

    #[test]
    fn len_tracks_insertions_and_removals() {
        let mut cache = ResolutionCache::with_defaults();
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());

        cache.insert("a@scp".to_owned(), identity_target("did:a"));
        assert_eq!(cache.len(), 1);
        assert!(!cache.is_empty());

        cache.remove("a@scp");
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }
}
