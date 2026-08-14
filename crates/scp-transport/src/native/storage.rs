//! Blob storage trait and implementations for the SCP native relay.
//!
//! The [`BlobStorage`] trait defines the storage interface used by the relay
//! server. Phase 1 provides [`InMemoryBlobStorage`], a `HashMap`-backed
//! implementation suitable for development and testing.
//!
//! [`BlobStorageBackend`] is a concrete enum that wraps all available storage
//! implementations, eliminating the need for generic type parameters on
//! [`RelayServer`](super::server::RelayServer) and its downstream consumers.
//! New storage backends are added as enum variants.
//!
//! Blobs are keyed by `(routing_id, blob_id)` and carry a TTL. The storage
//! layer is responsible for tracking when blobs expire so the relay's
//! background task can purge them.
//!
//! See ADR-004 in `.docs/adrs/phase-1.md` for the full specification.

use scp_clock::Clock;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use futures::stream::{self, Stream, StreamExt};
use tokio::sync::RwLock;

/// A clock function that returns the current Unix timestamp in seconds.
///
/// Used by blob storage implementations for TTL enforcement. Production
/// code uses [`system_clock`]. Conformance tests supply a controllable
/// clock (e.g., backed by `AtomicU64`) for deterministic TTL testing.
pub type ClockFn = Arc<dyn Fn() -> u64 + Send + Sync>;

/// Returns a [`ClockFn`] backed by the real system clock.
///
/// # Panics
///
/// Panics if the system clock is before the Unix epoch (unrecoverable
/// environment failure — see `scp_clock` for rationale).
#[must_use]
pub fn system_clock() -> ClockFn {
    Arc::new(|| scp_clock::SystemClock.now_secs())
}

/// A stored blob with its metadata.
#[derive(Debug, Clone)]
pub struct StoredBlob {
    /// Per-context pseudonym this blob was published to (32 bytes).
    pub routing_id: [u8; 32],
    /// SHA-256 hash identifying the blob (32 bytes).
    pub blob_id: [u8; 32],
    /// Optional recipient pseudonym for directed delivery (32 bytes).
    pub recipient_hint: Option<[u8; 32]>,
    /// TTL at time of storage (seconds).
    pub blob_ttl: u32,
    /// Unix timestamp when the relay stored the blob.
    pub stored_at: u64,
    /// The opaque blob content.
    pub blob: Vec<u8>,
}

/// Errors that can occur during blob storage operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum StorageError {
    /// The storage backend is full and cannot accept new blobs.
    #[error("storage full")]
    StorageFull,

    /// An internal storage error occurred.
    #[error("internal error: {0}")]
    Internal(String),
}

/// Blob metadata without the body. Returned by streaming operations
/// so metadata is available before the body stream is consumed.
#[derive(Debug, Clone)]
pub struct BlobMetadata {
    /// Per-context pseudonym this blob was published to (32 bytes).
    pub routing_id: [u8; 32],
    /// SHA-256 hash identifying the blob (32 bytes).
    pub blob_id: [u8; 32],
    /// Optional recipient pseudonym for directed delivery (32 bytes).
    pub recipient_hint: Option<[u8; 32]>,
    /// TTL at time of storage (seconds).
    pub blob_ttl: u32,
    /// Unix timestamp when the relay stored the blob.
    pub stored_at: u64,
    /// Content length in bytes, if known.
    pub content_length: Option<u64>,
}

impl From<&StoredBlob> for BlobMetadata {
    fn from(sb: &StoredBlob) -> Self {
        Self {
            routing_id: sb.routing_id,
            blob_id: sb.blob_id,
            recipient_hint: sb.recipient_hint,
            blob_ttl: sb.blob_ttl,
            stored_at: sb.stored_at,
            content_length: Some(sb.blob.len() as u64),
        }
    }
}

/// A stream of blob body chunks.
pub type BlobBodyStream = Pin<Box<dyn Stream<Item = Result<Bytes, StorageError>> + Send>>;

/// Trait defining the blob storage interface for the SCP native relay.
///
/// Implementations must be `Send + Sync` to support concurrent access from
/// multiple connection handlers. All methods are async to allow for
/// future persistent backends (`SQLite`, redb).
///
/// # Phase 1
///
/// Phase 1 provides [`InMemoryBlobStorage`], a `HashMap`-backed implementation.
/// Persistent backends are planned for later phases.
#[async_trait::async_trait]
pub trait BlobStorage: Send + Sync {
    /// Stores a blob and returns the stored metadata.
    ///
    /// The `stored_at` timestamp is set by the storage implementation.
    /// If a blob with the same `blob_id` already exists under the same
    /// `routing_id`, the implementation may overwrite or ignore.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::StorageFull`] if the backend cannot accept
    /// more blobs.
    async fn store(
        &self,
        routing_id: [u8; 32],
        blob_id: [u8; 32],
        recipient_hint: Option<[u8; 32]>,
        blob_ttl: u32,
        blob: Vec<u8>,
    ) -> Result<StoredBlob, StorageError>;

    /// Retrieves a specific blob by its `blob_id`.
    ///
    /// Returns `None` if the blob does not exist or has expired.
    async fn get(&self, blob_id: &[u8; 32]) -> Result<Option<StoredBlob>, StorageError>;

    /// Queries stored blobs for a `routing_id`, optionally filtered by a
    /// `since` timestamp, with an optional `limit`.
    ///
    /// Results are ordered oldest-first (ascending `stored_at` timestamp).
    async fn query(
        &self,
        routing_id: &[u8; 32],
        since: Option<u64>,
        limit: u32,
    ) -> Result<Vec<StoredBlob>, StorageError>;

    /// Deletes a blob by its `blob_id`. Best-effort; returns `true` if
    /// the blob was found and removed.
    async fn delete(&self, blob_id: &[u8; 32]) -> Result<bool, StorageError>;

    /// Removes all blobs whose TTL has expired. Returns the number of
    /// blobs purged.
    async fn purge_expired(&self) -> Result<usize, StorageError>;

    /// Returns the total number of blobs currently stored.
    ///
    /// Used by the dev API health/status endpoints to report storage
    /// metrics. Implementations should return the count of non-expired
    /// blobs where feasible, but may include expired-but-not-yet-purged
    /// blobs if a precise count is expensive.
    async fn count(&self) -> Result<usize, StorageError>;

    /// Stores a blob from a stream of chunks.
    ///
    /// Default implementation collects the stream to `Vec<u8>` and delegates
    /// to [`store`](Self::store). Backends where streaming avoids materialization
    /// (e.g., S3) override this.
    async fn store_streaming(
        &self,
        routing_id: [u8; 32],
        blob_id: [u8; 32],
        recipient_hint: Option<[u8; 32]>,
        blob_ttl: u32,
        content_length: Option<u64>,
        mut body: BlobBodyStream,
    ) -> Result<BlobMetadata, StorageError> {
        // content_length is advisory — used only as a capacity hint.
        // Cap at 64 MiB to prevent a malicious hint from causing OOM.
        const MAX_PREALLOC: u64 = 64 * 1024 * 1024;
        #[allow(clippy::cast_possible_truncation)]
        let mut buf = content_length.map_or_else(Vec::new, |len| {
            Vec::with_capacity(len.min(MAX_PREALLOC) as usize)
        });
        while let Some(chunk) = body.next().await {
            buf.extend_from_slice(&chunk?);
        }
        let stored = self
            .store(routing_id, blob_id, recipient_hint, blob_ttl, buf)
            .await?;
        Ok(BlobMetadata::from(&stored))
    }

    /// Retrieves a blob as metadata + body stream.
    ///
    /// Default implementation calls [`get`](Self::get) and wraps the `Vec<u8>`
    /// in a single-chunk stream. Backends where streaming avoids materialization
    /// (e.g., S3) override this.
    async fn get_streaming(
        &self,
        blob_id: &[u8; 32],
    ) -> Result<Option<(BlobMetadata, BlobBodyStream)>, StorageError> {
        let Some(stored) = self.get(blob_id).await? else {
            return Ok(None);
        };
        let meta = BlobMetadata::from(&stored);
        let body: BlobBodyStream =
            Box::pin(stream::once(async move { Ok(Bytes::from(stored.blob)) }));
        Ok(Some((meta, body)))
    }
}

/// Internal entry stored in the in-memory map.
#[derive(Debug, Clone)]
struct BlobEntry {
    stored_blob: StoredBlob,
    /// Absolute expiry time (unix timestamp).
    expires_at: u64,
}

/// Secondary index mapping `routing_id` to a list of `blob_id`s.
type RoutingIndex = Arc<RwLock<HashMap<[u8; 32], Vec<[u8; 32]>>>>;

/// Default maximum number of blobs that can be stored.
const DEFAULT_MAX_BLOBS: usize = 100_000;

/// In-memory blob storage backed by a `HashMap`.
///
/// Suitable for development and testing. Not persistent -- all data is lost
/// when the process exits.
///
/// Thread-safe via `Arc<RwLock<...>>`. Clone is cheap (shared inner state).
#[derive(Clone)]
pub struct InMemoryBlobStorage {
    /// Map from `blob_id` to blob entry.
    blobs: Arc<RwLock<HashMap<[u8; 32], BlobEntry>>>,
    /// Secondary index: `routing_id` -> set of `blob_id`s.
    routing_index: RoutingIndex,
    /// Maximum number of blobs this storage will accept.
    max_blobs: usize,
    /// Clock function for timestamps. Defaults to [`system_clock`].
    clock: ClockFn,
}

impl std::fmt::Debug for InMemoryBlobStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryBlobStorage")
            .field("blobs", &self.blobs)
            .field("routing_index", &self.routing_index)
            .field("max_blobs", &self.max_blobs)
            .field("clock", &"<fn>")
            .finish()
    }
}

impl InMemoryBlobStorage {
    /// Creates a new, empty in-memory blob storage with default capacity.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_BLOBS)
    }

    /// Creates a new, empty in-memory blob storage with the given capacity limit.
    #[must_use]
    pub fn with_capacity(max_blobs: usize) -> Self {
        Self {
            blobs: Arc::new(RwLock::new(HashMap::new())),
            routing_index: Arc::new(RwLock::new(HashMap::new())),
            max_blobs,
            clock: system_clock(),
        }
    }

    /// Creates a new, empty in-memory blob storage with a controllable clock.
    ///
    /// Used by conformance tests to deterministically control TTL expiry
    /// without relying on real time.
    #[must_use]
    pub fn with_clock(clock: ClockFn) -> Self {
        Self {
            blobs: Arc::new(RwLock::new(HashMap::new())),
            routing_index: Arc::new(RwLock::new(HashMap::new())),
            max_blobs: DEFAULT_MAX_BLOBS,
            clock,
        }
    }
}

impl Default for InMemoryBlobStorage {
    fn default() -> Self {
        Self::new()
    }
}

// Lock guards are held for the minimal scope needed across async operations.
#[allow(clippy::significant_drop_tightening)]
#[async_trait::async_trait]
impl BlobStorage for InMemoryBlobStorage {
    async fn store(
        &self,
        routing_id: [u8; 32],
        blob_id: [u8; 32],
        recipient_hint: Option<[u8; 32]>,
        blob_ttl: u32,
        blob: Vec<u8>,
    ) -> Result<StoredBlob, StorageError> {
        let stored_at = (self.clock)();
        let expires_at = stored_at.saturating_add(u64::from(blob_ttl));

        let stored_blob = StoredBlob {
            routing_id,
            blob_id,
            recipient_hint,
            blob_ttl,
            stored_at,
            blob,
        };

        let entry = BlobEntry {
            stored_blob: stored_blob.clone(),
            expires_at,
        };

        let old_routing_id = {
            let mut blobs = self.blobs.write().await;
            // Enforce capacity limit. Overwrites of existing blob_ids are allowed.
            if blobs.len() >= self.max_blobs && !blobs.contains_key(&blob_id) {
                return Err(StorageError::StorageFull);
            }
            let old = blobs.insert(blob_id, entry);
            old.map(|e| e.stored_blob.routing_id)
        };

        {
            let mut index = self.routing_index.write().await;
            // Remove stale routing index entry on overwrite.
            if let Some(old_rid) = old_routing_id
                && let Some(ids) = index.get_mut(&old_rid)
            {
                ids.retain(|id| id != &blob_id);
                if ids.is_empty() {
                    index.remove(&old_rid);
                }
            }
            index.entry(routing_id).or_default().push(blob_id);
        }

        Ok(stored_blob)
    }

    async fn get(&self, blob_id: &[u8; 32]) -> Result<Option<StoredBlob>, StorageError> {
        let blobs = self.blobs.read().await;
        let now = (self.clock)();

        Ok(blobs.get(blob_id).and_then(|entry| {
            if entry.expires_at > now {
                Some(entry.stored_blob.clone())
            } else {
                None
            }
        }))
    }

    async fn query(
        &self,
        routing_id: &[u8; 32],
        since: Option<u64>,
        limit: u32,
    ) -> Result<Vec<StoredBlob>, StorageError> {
        let blobs = self.blobs.read().await;
        let index = self.routing_index.read().await;
        let now = (self.clock)();

        let Some(blob_ids) = index.get(routing_id) else {
            return Ok(Vec::new());
        };

        let mut results: Vec<StoredBlob> = blob_ids
            .iter()
            .filter_map(|id| {
                let entry = blobs.get(id)?;
                // Skip expired blobs.
                if entry.expires_at <= now {
                    return None;
                }
                // Apply since filter.
                if let Some(since_ts) = since
                    && entry.stored_blob.stored_at <= since_ts
                {
                    return None;
                }
                Some(entry.stored_blob.clone())
            })
            .collect();

        // Sort oldest-first (ascending stored_at).
        results.sort_by_key(|b| b.stored_at);

        // Apply limit.
        results.truncate(limit as usize);

        Ok(results)
    }

    async fn delete(&self, blob_id: &[u8; 32]) -> Result<bool, StorageError> {
        let mut blobs = self.blobs.write().await;

        if let Some(entry) = blobs.remove(blob_id) {
            let routing_id = entry.stored_blob.routing_id;
            drop(blobs); // Release blobs lock before acquiring index lock.

            let mut index = self.routing_index.write().await;
            if let Some(ids) = index.get_mut(&routing_id) {
                ids.retain(|id| id != blob_id);
                if ids.is_empty() {
                    index.remove(&routing_id);
                }
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn purge_expired(&self) -> Result<usize, StorageError> {
        let now = (self.clock)();

        // Single write lock to avoid TOCTOU: a concurrent store() with the same
        // blob_id between a read-scan and write-remove could delete a renewed blob.
        let mut blobs = self.blobs.write().await;
        let mut index = self.routing_index.write().await;

        let expired_ids: Vec<([u8; 32], [u8; 32])> = blobs
            .iter()
            .filter(|(_, entry)| entry.expires_at <= now)
            .map(|(blob_id, entry)| (*blob_id, entry.stored_blob.routing_id))
            .collect();

        for (blob_id, routing_id) in &expired_ids {
            blobs.remove(blob_id);
            if let Some(ids) = index.get_mut(routing_id) {
                ids.retain(|id| id != blob_id);
                if ids.is_empty() {
                    index.remove(routing_id);
                }
            }
        }

        Ok(expired_ids.len())
    }

    async fn count(&self) -> Result<usize, StorageError> {
        Ok(self.blobs.read().await.len())
    }
}

// ---------------------------------------------------------------------------
// Enum dispatch: concrete storage backend (eliminates generic propagation)
// ---------------------------------------------------------------------------

/// Concrete blob storage backend used by [`RelayServer`](super::server::RelayServer).
///
/// Wraps all available [`BlobStorage`] implementations behind an enum,
/// eliminating the `<S: BlobStorage>` generic parameter from `RelayServer`
/// and all downstream handler functions. This trades a single `match` per
/// storage call (negligible cost vs. the I/O itself) for removing turbofish
/// operators and generic propagation across the entire server stack.
///
/// New backends (e.g., `SQLite`, redb) are added as variants here.
///
/// See issue [#242](https://github.com/limn-works/scp/issues/242).
#[derive(Debug, Clone)]
pub enum BlobStorageBackend {
    /// In-memory `HashMap`-backed storage (development / testing).
    InMemory(InMemoryBlobStorage),
    /// SQLite-backed blob storage.
    #[cfg(feature = "sqlite-blob")]
    Sqlite(super::sqlite_blob::SqliteBlobStore),
    /// redb-backed blob storage.
    #[cfg(feature = "redb-blob")]
    Redb(super::redb_blob::RedbBlobStore),
    /// S3-compatible blob storage.
    #[cfg(feature = "s3-blob")]
    S3(super::s3_blob::S3BlobStore),
    /// PostgreSQL-backed blob storage.
    #[cfg(feature = "postgres-blob")]
    Postgres(super::postgres_blob::PostgresBlobStore),
    /// Combined SQLCipher-backed node storage (protocol + blob in one DB).
    #[cfg(feature = "combined")]
    Combined(super::combined::CombinedNodeStorage),
    /// Size-limited local blob cache wrapping another backend.
    #[cfg(feature = "local-cache")]
    Cached(Box<super::local_cache::LocalBlobCache<BlobStorageBackend>>),
}

impl BlobStorageBackend {
    /// Creates a new in-memory backend with default capacity.
    #[must_use]
    pub fn in_memory() -> Self {
        Self::InMemory(InMemoryBlobStorage::new())
    }

    /// Creates a new in-memory backend with the given capacity limit.
    #[must_use]
    pub fn in_memory_with_capacity(max_blobs: usize) -> Self {
        Self::InMemory(InMemoryBlobStorage::with_capacity(max_blobs))
    }

    /// Opens an SQLite-backed blob storage at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] if the database cannot be opened.
    #[cfg(feature = "sqlite-blob")]
    pub fn sqlite(path: &std::path::Path) -> Result<Self, StorageError> {
        Ok(Self::Sqlite(super::sqlite_blob::SqliteBlobStore::open(
            path,
        )?))
    }

    /// Opens a redb-backed blob storage at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] if the database cannot be opened.
    #[cfg(feature = "redb-blob")]
    pub fn redb(path: &std::path::Path) -> Result<Self, StorageError> {
        Ok(Self::Redb(super::redb_blob::RedbBlobStore::open(path)?))
    }

    /// Opens a combined SQLCipher-backed node storage at `dir/node.db`.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] if the database cannot be opened.
    #[cfg(feature = "combined")]
    pub fn combined(dir: &std::path::Path, key: &[u8]) -> Result<Self, StorageError> {
        Ok(Self::Combined(super::combined::CombinedNodeStorage::open(
            dir, key,
        )?))
    }

    /// Wraps an existing backend in a size-limited local cache.
    #[cfg(feature = "local-cache")]
    #[must_use]
    pub fn cached(self, max_cache_size: usize) -> Self {
        Self::Cached(Box::new(super::local_cache::LocalBlobCache::new(
            self,
            max_cache_size,
        )))
    }
}

// NOTE (SCP-CAPINJECT-010 / ADR-062 §Decision 5, spec §17.17.1): this enum has
// deliberately NO `Default` implementation. `InMemory` is a durability-only
// development arm (SCP-CAPSEL-8010/8011): it may be selected EXPLICITLY
// (`in_memory()` / `in_memory_with_capacity()`), but it must never be
// manufactured as a default or reached as a fallback. A `Default` that returned
// `in_memory()` was a live SCP-CAPSEL-8011 violation (the runtime silently
// selecting the dev arm the operator never chose); the backend is now a required,
// non-`Option` selection made by the caller at the relay/node construction
// boundary (see `scp-node`'s `NodeConfig::blob_storage` / `self_host`).

impl From<InMemoryBlobStorage> for BlobStorageBackend {
    fn from(storage: InMemoryBlobStorage) -> Self {
        Self::InMemory(storage)
    }
}

#[cfg(feature = "sqlite-blob")]
impl From<super::sqlite_blob::SqliteBlobStore> for BlobStorageBackend {
    fn from(storage: super::sqlite_blob::SqliteBlobStore) -> Self {
        Self::Sqlite(storage)
    }
}

#[cfg(feature = "redb-blob")]
impl From<super::redb_blob::RedbBlobStore> for BlobStorageBackend {
    fn from(storage: super::redb_blob::RedbBlobStore) -> Self {
        Self::Redb(storage)
    }
}

#[cfg(feature = "s3-blob")]
impl From<super::s3_blob::S3BlobStore> for BlobStorageBackend {
    fn from(storage: super::s3_blob::S3BlobStore) -> Self {
        Self::S3(storage)
    }
}

#[cfg(feature = "postgres-blob")]
impl From<super::postgres_blob::PostgresBlobStore> for BlobStorageBackend {
    fn from(storage: super::postgres_blob::PostgresBlobStore) -> Self {
        Self::Postgres(storage)
    }
}

#[cfg(feature = "combined")]
impl From<super::combined::CombinedNodeStorage> for BlobStorageBackend {
    fn from(storage: super::combined::CombinedNodeStorage) -> Self {
        Self::Combined(storage)
    }
}

#[cfg(feature = "local-cache")]
impl From<super::local_cache::LocalBlobCache<BlobStorageBackend>> for BlobStorageBackend {
    fn from(cache: super::local_cache::LocalBlobCache<BlobStorageBackend>) -> Self {
        Self::Cached(Box::new(cache))
    }
}

/// Dispatch macro — generates a match arm for every `BlobStorageBackend` variant,
/// forwarding to the inner implementation. Keeps the 7 trait methods DRY.
macro_rules! dispatch {
    ($self:expr, $method:ident ( $($arg:expr),* $(,)? )) => {
        match $self {
            BlobStorageBackend::InMemory(s) => s.$method($($arg),*).await,
            #[cfg(feature = "sqlite-blob")]
            BlobStorageBackend::Sqlite(s) => s.$method($($arg),*).await,
            #[cfg(feature = "redb-blob")]
            BlobStorageBackend::Redb(s) => s.$method($($arg),*).await,
            #[cfg(feature = "s3-blob")]
            BlobStorageBackend::S3(s) => s.$method($($arg),*).await,
            #[cfg(feature = "postgres-blob")]
            BlobStorageBackend::Postgres(s) => s.$method($($arg),*).await,
            #[cfg(feature = "combined")]
            BlobStorageBackend::Combined(s) => s.$method($($arg),*).await,
            #[cfg(feature = "local-cache")]
            BlobStorageBackend::Cached(s) => s.$method($($arg),*).await,
        }
    };
}

#[async_trait::async_trait]
impl BlobStorage for BlobStorageBackend {
    async fn store(
        &self,
        routing_id: [u8; 32],
        blob_id: [u8; 32],
        recipient_hint: Option<[u8; 32]>,
        blob_ttl: u32,
        blob: Vec<u8>,
    ) -> Result<StoredBlob, StorageError> {
        dispatch!(
            self,
            store(routing_id, blob_id, recipient_hint, blob_ttl, blob)
        )
    }

    async fn get(&self, blob_id: &[u8; 32]) -> Result<Option<StoredBlob>, StorageError> {
        dispatch!(self, get(blob_id))
    }

    async fn query(
        &self,
        routing_id: &[u8; 32],
        since: Option<u64>,
        limit: u32,
    ) -> Result<Vec<StoredBlob>, StorageError> {
        dispatch!(self, query(routing_id, since, limit))
    }

    async fn delete(&self, blob_id: &[u8; 32]) -> Result<bool, StorageError> {
        dispatch!(self, delete(blob_id))
    }

    async fn purge_expired(&self) -> Result<usize, StorageError> {
        dispatch!(self, purge_expired())
    }

    async fn count(&self) -> Result<usize, StorageError> {
        dispatch!(self, count())
    }

    async fn store_streaming(
        &self,
        routing_id: [u8; 32],
        blob_id: [u8; 32],
        recipient_hint: Option<[u8; 32]>,
        blob_ttl: u32,
        content_length: Option<u64>,
        body: BlobBodyStream,
    ) -> Result<BlobMetadata, StorageError> {
        dispatch!(
            self,
            store_streaming(
                routing_id,
                blob_id,
                recipient_hint,
                blob_ttl,
                content_length,
                body
            )
        )
    }

    async fn get_streaming(
        &self,
        blob_id: &[u8; 32],
    ) -> Result<Option<(BlobMetadata, BlobBodyStream)>, StorageError> {
        dispatch!(self, get_streaming(blob_id))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn make_blob_id(data: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(data);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hash);
        out
    }

    #[tokio::test]
    async fn store_and_get_returns_blob() {
        let storage = InMemoryBlobStorage::new();
        let routing_id = [0xAA; 32];
        let blob_data = vec![1, 2, 3, 4];
        let blob_id = make_blob_id(&blob_data);

        let stored = storage
            .store(routing_id, blob_id, None, 3600, blob_data.clone())
            .await
            .unwrap();

        assert_eq!(stored.blob_id, blob_id);
        assert_eq!(stored.routing_id, routing_id);
        assert_eq!(stored.blob, blob_data);
        assert_eq!(stored.blob_ttl, 3600);
        assert!(stored.stored_at > 0);

        let retrieved = storage.get(&blob_id).await.unwrap().unwrap();
        assert_eq!(retrieved.blob, blob_data);
        assert_eq!(retrieved.blob_id, blob_id);
    }

    #[tokio::test]
    async fn get_nonexistent_returns_none() {
        let storage = InMemoryBlobStorage::new();
        let blob_id = [0xFF; 32];
        let result = storage.get(&blob_id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn delete_removes_blob() {
        let storage = InMemoryBlobStorage::new();
        let routing_id = [0xAA; 32];
        let blob_data = vec![5, 6, 7];
        let blob_id = make_blob_id(&blob_data);

        storage
            .store(routing_id, blob_id, None, 3600, blob_data)
            .await
            .unwrap();

        let deleted = storage.delete(&blob_id).await.unwrap();
        assert!(deleted);

        let result = storage.get(&blob_id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn delete_nonexistent_returns_false() {
        let storage = InMemoryBlobStorage::new();
        let blob_id = [0xFF; 32];
        let deleted = storage.delete(&blob_id).await.unwrap();
        assert!(!deleted);
    }

    #[tokio::test]
    async fn query_returns_blobs_for_routing_id() {
        let storage = InMemoryBlobStorage::new();
        let routing_id = [0xAA; 32];

        for i in 0u8..5 {
            let data = vec![i; 10];
            let blob_id = make_blob_id(&data);
            storage
                .store(routing_id, blob_id, None, 3600, data)
                .await
                .unwrap();
        }

        let results = storage.query(&routing_id, None, 100).await.unwrap();
        assert_eq!(results.len(), 5);
    }

    #[tokio::test]
    async fn query_respects_limit() {
        let storage = InMemoryBlobStorage::new();
        let routing_id = [0xBB; 32];

        for i in 0u8..10 {
            let data = vec![i; 10];
            let blob_id = make_blob_id(&data);
            storage
                .store(routing_id, blob_id, None, 3600, data)
                .await
                .unwrap();
        }

        let results = storage.query(&routing_id, None, 3).await.unwrap();
        assert_eq!(results.len(), 3);
    }

    #[tokio::test]
    async fn query_returns_oldest_first() {
        let storage = InMemoryBlobStorage::new();
        let routing_id = [0xCC; 32];

        for i in 0u8..3 {
            let data = vec![i; 10];
            let blob_id = make_blob_id(&data);
            storage
                .store(routing_id, blob_id, None, 3600, data)
                .await
                .unwrap();
        }

        let results = storage.query(&routing_id, None, 100).await.unwrap();
        // All should be sorted by stored_at ascending.
        for window in results.windows(2) {
            assert!(window[0].stored_at <= window[1].stored_at);
        }
    }

    #[tokio::test]
    async fn query_different_routing_id_returns_empty() {
        let storage = InMemoryBlobStorage::new();
        let routing_id_a = [0xAA; 32];
        let routing_id_b = [0xBB; 32];

        let data = vec![1, 2, 3];
        let blob_id = make_blob_id(&data);
        storage
            .store(routing_id_a, blob_id, None, 3600, data)
            .await
            .unwrap();

        let results = storage.query(&routing_id_b, None, 100).await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn store_with_recipient_hint_preserves_it() {
        let storage = InMemoryBlobStorage::new();
        let routing_id = [0xAA; 32];
        let hint = [0xBB; 32];
        let data = vec![1, 2, 3];
        let blob_id = make_blob_id(&data);

        let stored = storage
            .store(routing_id, blob_id, Some(hint), 3600, data)
            .await
            .unwrap();

        assert_eq!(stored.recipient_hint, Some(hint));

        let retrieved = storage.get(&blob_id).await.unwrap().unwrap();
        assert_eq!(retrieved.recipient_hint, Some(hint));
    }

    #[tokio::test]
    async fn purge_expired_removes_old_blobs() {
        use std::sync::atomic::{AtomicU64, Ordering};

        let clock_value = Arc::new(AtomicU64::new(1_000_000));
        let cv = clock_value.clone();
        let clock: ClockFn = Arc::new(move || cv.load(Ordering::Relaxed));
        let storage = InMemoryBlobStorage::with_clock(clock);
        let routing_id = [0xAA; 32];
        let data = vec![1, 2, 3];
        let blob_id = make_blob_id(&data);

        // Store with TTL of 10 seconds.
        storage
            .store(routing_id, blob_id, None, 10, data)
            .await
            .unwrap();

        // Advance clock past expiry.
        clock_value.store(1_000_011, Ordering::Relaxed);

        let purged = storage.purge_expired().await.unwrap();
        assert_eq!(purged, 1);

        let result = storage.get(&blob_id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn purge_expired_does_not_remove_active_blobs() {
        let storage = InMemoryBlobStorage::new();
        let routing_id = [0xAA; 32];
        let data = vec![4, 5, 6];
        let blob_id = make_blob_id(&data);

        storage
            .store(routing_id, blob_id, None, 3600, data)
            .await
            .unwrap();

        let purged = storage.purge_expired().await.unwrap();
        assert_eq!(purged, 0);

        let result = storage.get(&blob_id).await.unwrap();
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn default_creates_empty_storage() {
        let storage = InMemoryBlobStorage::default();
        let blob_id = [0xFF; 32];
        let result = storage.get(&blob_id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn delete_cleans_up_routing_index() {
        let storage = InMemoryBlobStorage::new();
        let routing_id = [0xDD; 32];
        let data = vec![7, 8, 9];
        let blob_id = make_blob_id(&data);

        storage
            .store(routing_id, blob_id, None, 3600, data)
            .await
            .unwrap();

        storage.delete(&blob_id).await.unwrap();

        // After deletion, query should return empty.
        let results = storage.query(&routing_id, None, 100).await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn store_rejects_when_at_capacity() {
        let storage = InMemoryBlobStorage::with_capacity(3);
        let routing_id = [0xAA; 32];

        // Fill to capacity.
        for i in 0u8..3 {
            let data = vec![i; 10];
            let blob_id = make_blob_id(&data);
            storage
                .store(routing_id, blob_id, None, 3600, data)
                .await
                .unwrap();
        }

        // The 4th store should fail.
        let data = vec![99u8; 10];
        let blob_id = make_blob_id(&data);
        let result = storage.store(routing_id, blob_id, None, 3600, data).await;
        assert!(matches!(result, Err(StorageError::StorageFull)));
    }

    #[tokio::test]
    async fn store_allows_overwrite_at_capacity() {
        let storage = InMemoryBlobStorage::with_capacity(2);
        let routing_id = [0xAA; 32];

        let data1 = vec![1u8; 10];
        let blob_id1 = make_blob_id(&data1);
        storage
            .store(routing_id, blob_id1, None, 3600, data1.clone())
            .await
            .unwrap();

        let data2 = vec![2u8; 10];
        let blob_id2 = make_blob_id(&data2);
        storage
            .store(routing_id, blob_id2, None, 3600, data2)
            .await
            .unwrap();

        // At capacity (2/2). Overwriting an existing blob_id should succeed.
        let updated_data = vec![1u8; 20];
        let result = storage
            .store(routing_id, blob_id1, None, 7200, updated_data)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn store_succeeds_after_delete_frees_capacity() {
        let storage = InMemoryBlobStorage::with_capacity(2);
        let routing_id = [0xAA; 32];

        let data1 = vec![1u8; 10];
        let blob_id1 = make_blob_id(&data1);
        storage
            .store(routing_id, blob_id1, None, 3600, data1)
            .await
            .unwrap();

        let data2 = vec![2u8; 10];
        let blob_id2 = make_blob_id(&data2);
        storage
            .store(routing_id, blob_id2, None, 3600, data2)
            .await
            .unwrap();

        // Delete one blob to free capacity.
        storage.delete(&blob_id1).await.unwrap();

        // Now a new store should succeed.
        let data3 = vec![3u8; 10];
        let blob_id3 = make_blob_id(&data3);
        let result = storage.store(routing_id, blob_id3, None, 3600, data3).await;
        assert!(result.is_ok());
    }
}
