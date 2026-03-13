# Implementing Storage Backends

## Overview

SCP defines two storage abstractions: the `Storage` trait for general-purpose key-value persistence and the `BlobStorage` trait for relay blob storage. Both are designed for pluggable backends -- the protocol core never knows whether data is stored in memory, SQLite, S3, or any other backend. Each trait has a conformance test macro that validates any implementation against the protocol specification.

The `Storage` trait (defined in `crates/scp-platform/src/traits.rs`) is used by the SDK for identity persistence, MLS state, UCAN nonce tracking, and `ProtocolStore` domain operations. The `BlobStorage` trait (defined in `crates/scp-transport/src/native/storage.rs`) is used by relay servers for storing and querying encrypted blobs.

**Contents:**
1. [The Storage Trait](#1-the-storage-trait)
2. [Implementing a Storage Backend](#2-implementing-a-storage-backend)
3. [Testing with `storage_conformance!`](#3-testing-with-storage_conformance)
4. [The BlobStorage Trait](#4-the-blobstorage-trait)
5. [Implementing a BlobStorage Backend](#5-implementing-a-blobstorage-backend)
6. [Testing with `blob_store_conformance!`](#6-testing-with-blob_store_conformance)
7. [Performance Considerations](#7-performance-considerations)
8. [Available Implementations](#8-available-implementations)

---

## 1. The Storage Trait

The `Storage` trait is a persistent key-value byte store. Keys are UTF-8 strings; values are opaque byte slices. It abstracts platform-specific secure storage (Keychain, encrypted SQLite, browser IndexedDB) behind a uniform async interface.

```rust
// Defined in crates/scp-platform/src/traits.rs
pub trait Storage: Send + Sync {
    fn store(&self, key: &str, data: &[u8])
        -> impl Future<Output = Result<(), PlatformError>> + Send;

    fn retrieve(&self, key: &str)
        -> impl Future<Output = Result<Option<Vec<u8>>, PlatformError>> + Send;

    fn delete(&self, key: &str)
        -> impl Future<Output = Result<(), PlatformError>> + Send;

    fn list_keys(&self, prefix: &str)
        -> impl Future<Output = Result<Vec<String>, PlatformError>> + Send;

    fn delete_prefix(&self, prefix: &str)
        -> impl Future<Output = Result<u64, PlatformError>> + Send;

    fn exists(&self, key: &str)
        -> impl Future<Output = Result<bool, PlatformError>> + Send;
}
```

### Method semantics

| Method | Purpose | Returns | Key invariants |
|--------|---------|---------|----------------|
| `store` | Write a byte slice under a string key. Overwrites any existing value. | `()` | Must be durable (persist across process restarts for non-in-memory backends). |
| `retrieve` | Read the byte slice stored under a key. | `Option<Vec<u8>>` | Returns `None` if the key does not exist. Never errors on missing keys. |
| `delete` | Remove a key and its value. | `()` | No-op if the key does not exist. Must not error on missing keys. |
| `list_keys` | List all keys matching a prefix, sorted lexicographically. | `Vec<String>` | Empty prefix `""` returns all keys. Results must be sorted ascending. |
| `delete_prefix` | Delete all keys matching a prefix. | `u64` (count deleted) | Returns 0 if no keys match. Used for context cleanup. |
| `exists` | Check whether a key exists without reading its value. | `bool` | Used for UCAN nonce replay prevention. Must be consistent with `retrieve`. |

### Error type

All methods return `Result<T, PlatformError>`. The relevant variant is `PlatformError::StorageError(String)`. Storage operations should only error on I/O failures, not on missing keys or empty results.

### Arc blanket implementation

A blanket `impl<T: Storage> Storage for Arc<T>` is provided in `crates/scp-platform/src/traits.rs`. This enables sharing a single storage backend across multiple owners (e.g., `ProtocolStore`, identity layer, FFI bridge) via `Arc`. You do not need to implement this yourself.

---

## 2. Implementing a Storage Backend

Here is a step-by-step guide using a hypothetical Redis-backed implementation.

### Step 1: Define the struct

```rust
use scp_platform::error::PlatformError;
use scp_platform::traits::Storage;

pub struct RedisStorage {
    client: redis::Client,
    prefix: String,
}

impl RedisStorage {
    pub fn new(url: &str, prefix: &str) -> Result<Self, PlatformError> {
        let client = redis::Client::open(url)
            .map_err(|e| PlatformError::StorageError(e.to_string()))?;
        Ok(Self {
            client,
            prefix: prefix.to_owned(),
        })
    }

    fn prefixed_key(&self, key: &str) -> String {
        format!("{}{}", self.prefix, key)
    }
}
```

### Step 2: Implement the trait

```rust
impl Storage for RedisStorage {
    async fn store(&self, key: &str, data: &[u8]) -> Result<(), PlatformError> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| PlatformError::StorageError(e.to_string()))?;

        redis::cmd("SET")
            .arg(self.prefixed_key(key))
            .arg(data)
            .query_async(&mut conn)
            .await
            .map_err(|e| PlatformError::StorageError(e.to_string()))
    }

    async fn retrieve(&self, key: &str) -> Result<Option<Vec<u8>>, PlatformError> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| PlatformError::StorageError(e.to_string()))?;

        let result: Option<Vec<u8>> = redis::cmd("GET")
            .arg(self.prefixed_key(key))
            .query_async(&mut conn)
            .await
            .map_err(|e| PlatformError::StorageError(e.to_string()))?;

        Ok(result)
    }

    async fn delete(&self, key: &str) -> Result<(), PlatformError> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| PlatformError::StorageError(e.to_string()))?;

        redis::cmd("DEL")
            .arg(self.prefixed_key(key))
            .query_async(&mut conn)
            .await
            .map_err(|e| PlatformError::StorageError(e.to_string()))?;

        Ok(())
    }

    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, PlatformError> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| PlatformError::StorageError(e.to_string()))?;

        let pattern = format!("{}{}*", self.prefix, prefix);
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(&pattern)
            .query_async(&mut conn)
            .await
            .map_err(|e| PlatformError::StorageError(e.to_string()))?;

        // Strip the storage prefix and sort lexicographically.
        let mut result: Vec<String> = keys
            .into_iter()
            .filter_map(|k| k.strip_prefix(&self.prefix).map(String::from))
            .collect();
        result.sort();
        Ok(result)
    }

    async fn delete_prefix(&self, prefix: &str) -> Result<u64, PlatformError> {
        let keys = self.list_keys(prefix).await?;
        let count = keys.len() as u64;
        for key in &keys {
            self.delete(key).await?;
        }
        Ok(count)
    }

    async fn exists(&self, key: &str) -> Result<bool, PlatformError> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| PlatformError::StorageError(e.to_string()))?;

        let exists: bool = redis::cmd("EXISTS")
            .arg(self.prefixed_key(key))
            .query_async(&mut conn)
            .await
            .map_err(|e| PlatformError::StorageError(e.to_string()))?;

        Ok(exists)
    }
}
```

### Step 3: Key invariants to maintain

- **`list_keys` must return sorted results.** The conformance suite verifies lexicographic ordering. Sort explicitly if your backend does not guarantee order.
- **`delete` must be idempotent.** Deleting a nonexistent key must succeed silently.
- **`store` overwrites.** Storing under an existing key replaces the value. No upsert distinction.
- **`retrieve` returns `None` for missing keys.** Not an error. Do not convert "key not found" into `PlatformError`.
- **Empty values are valid.** Storing `b""` must roundtrip to `Some(vec![])`, not `None`.
- **Thread safety.** The `Send + Sync` bound is required because storage is shared across async tasks. Use `Arc<RwLock<...>>` or connection pooling as appropriate.

---

## 3. Testing with `storage_conformance!`

The `storage_conformance!` macro (defined in `crates/scp-testing/src/conformance/storage.rs`) generates 13 test cases that validate any `Storage` implementation. See spec sections 17.11 and 17.13.

### Usage

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use scp_testing::storage_conformance;

    // The macro argument is an expression that creates a fresh storage instance.
    // It is called once per test to ensure isolation.
    storage_conformance!(RedisStorage::new("redis://localhost", "test/").unwrap());
}
```

### What it tests

| # | Test | What it verifies |
|---|------|------------------|
| 1 | `roundtrip` | `store` then `retrieve` returns the same bytes |
| 2 | `missing_returns_none` | `retrieve` for a nonexistent key returns `None` |
| 3 | `delete_removes` | `store`, `delete`, `retrieve` returns `None` |
| 4 | `list_keys_sorted` | Keys are returned in lexicographic order |
| 5 | `list_keys_prefix_sorted` | Prefix filtering returns only matching keys, sorted |
| 6 | `delete_prefix_removes` | `delete_prefix` removes matching keys, preserves others |
| 7 | `delete_prefix_zero` | `delete_prefix` with no matching keys returns 0 |
| 8 | `exists_true` | `exists` returns true for a stored key |
| 9 | `exists_false` | `exists` returns false for a missing key |
| 10 | `exists_after_delete` | `exists` returns false after deleting the key |
| 11 | `overwrite` | Storing under an existing key replaces the value |
| 12 | `concurrent_access` | 10 concurrent store/retrieve operations are safe |
| 13 | `store_empty_value` | Storing `b""` roundtrips to `Some(vec![])` |

The `concurrent_access` test wraps the storage in `Arc` and spawns 10 tokio tasks that store and retrieve concurrently. Your implementation must be safe under concurrent access.

---

## 4. The BlobStorage Trait

The `BlobStorage` trait is the relay's blob storage interface. Unlike `Storage` (general-purpose key-value), `BlobStorage` is specialized for the relay use case: blobs are keyed by `(routing_id, blob_id)`, carry a TTL, and support temporal queries.

```rust
// Defined in crates/scp-transport/src/native/storage.rs
#[async_trait::async_trait]
pub trait BlobStorage: Send + Sync {
    async fn store(
        &self,
        routing_id: [u8; 32],
        blob_id: [u8; 32],
        recipient_hint: Option<[u8; 32]>,
        blob_ttl: u32,
        blob: Vec<u8>,
    ) -> Result<StoredBlob, StorageError>;

    async fn get(&self, blob_id: &[u8; 32]) -> Result<Option<StoredBlob>, StorageError>;

    async fn query(
        &self,
        routing_id: &[u8; 32],
        since: Option<u64>,
        limit: u32,
    ) -> Result<Vec<StoredBlob>, StorageError>;

    async fn delete(&self, blob_id: &[u8; 32]) -> Result<bool, StorageError>;

    async fn purge_expired(&self) -> Result<usize, StorageError>;

    async fn count(&self) -> Result<usize, StorageError>;

    // Default implementations provided:
    async fn store_streaming(...) -> Result<BlobMetadata, StorageError>;
    async fn get_streaming(...) -> Result<Option<(BlobMetadata, BlobBodyStream)>, StorageError>;
}
```

### Method semantics

| Method | Purpose | Returns | Key invariants |
|--------|---------|---------|----------------|
| `store` | Store a blob with routing ID, TTL, and optional recipient hint. | `StoredBlob` with `stored_at` timestamp set by the backend | `blob_id` must equal SHA-256 of the content bytes. |
| `get` | Retrieve a blob by `blob_id`. | `Option<StoredBlob>` | Returns `None` if the blob does not exist or has expired. |
| `query` | Query blobs by `routing_id`, optionally filtered by `since` timestamp. | `Vec<StoredBlob>` ordered by `stored_at` ascending | `since` filter is exclusive: only blobs with `stored_at > since`. `limit` caps result count. |
| `delete` | Delete a blob by `blob_id`. | `bool` (true if found and removed) | Second delete returns false. Best-effort. |
| `purge_expired` | Remove all blobs whose TTL has expired. | `usize` (count purged) | Called periodically by the relay's background task. |
| `count` | Total number of stored blobs. | `usize` | Used by health/status endpoints. May include expired-but-not-yet-purged blobs. |
| `store_streaming` | Store a blob from a stream of chunks. | `BlobMetadata` | Default implementation collects to `Vec<u8>` and delegates to `store`. Override for streaming backends (S3). |
| `get_streaming` | Retrieve a blob as metadata + body stream. | `Option<(BlobMetadata, BlobBodyStream)>` | Default implementation wraps `get` result in a single-chunk stream. Override for streaming backends. |

### Supporting types

```rust
pub struct StoredBlob {
    pub routing_id: [u8; 32],
    pub blob_id: [u8; 32],
    pub recipient_hint: Option<[u8; 32]>,
    pub blob_ttl: u32,
    pub stored_at: u64,
    pub blob: Vec<u8>,
}

pub struct BlobMetadata {
    pub routing_id: [u8; 32],
    pub blob_id: [u8; 32],
    pub recipient_hint: Option<[u8; 32]>,
    pub blob_ttl: u32,
    pub stored_at: u64,
    pub content_length: Option<u64>,
}

pub type BlobBodyStream = Pin<Box<dyn Stream<Item = Result<Bytes, StorageError>> + Send>>;
pub type ClockFn = Arc<dyn Fn() -> u64 + Send + Sync>;
```

### Error type

`StorageError` has two variants: `StorageFull` (backend cannot accept more blobs) and `Internal(String)` (all other failures).

---

## 5. Implementing a BlobStorage Backend

### Step 1: Define the struct with a clock

All `BlobStorage` implementations must use a `ClockFn` for timestamp operations. This enables the conformance suite to control time deterministically.

```rust
use std::sync::Arc;
use scp_transport::native::storage::{
    BlobStorage, BlobMetadata, BlobBodyStream, ClockFn, StorageError, StoredBlob,
    system_clock,
};

pub struct MyBlobStore {
    // ... your backend state ...
    clock: ClockFn,
}

impl MyBlobStore {
    /// Production constructor using the real system clock.
    pub fn new(/* backend config */) -> Self {
        Self {
            // ... initialize backend ...
            clock: system_clock(),
        }
    }

    /// Test constructor with a controllable clock.
    pub fn with_clock(/* backend config, */ clock: ClockFn) -> Self {
        Self {
            // ... initialize backend ...
            clock,
        }
    }
}
```

### Step 2: Implement core methods

```rust
#[async_trait::async_trait]
impl BlobStorage for MyBlobStore {
    async fn store(
        &self,
        routing_id: [u8; 32],
        blob_id: [u8; 32],
        recipient_hint: Option<[u8; 32]>,
        blob_ttl: u32,
        blob: Vec<u8>,
    ) -> Result<StoredBlob, StorageError> {
        let stored_at = (self.clock)();
        let stored = StoredBlob {
            routing_id,
            blob_id,
            recipient_hint,
            blob_ttl,
            stored_at,
            blob,
        };
        // Write to your backend here.
        // Track expires_at = stored_at + blob_ttl for purge_expired.
        Ok(stored)
    }

    async fn get(&self, blob_id: &[u8; 32]) -> Result<Option<StoredBlob>, StorageError> {
        // Read from backend. Check TTL expiry using current clock.
        let now = (self.clock)();
        // If stored_at + blob_ttl <= now, return None (expired).
        todo!()
    }

    async fn query(
        &self,
        routing_id: &[u8; 32],
        since: Option<u64>,
        limit: u32,
    ) -> Result<Vec<StoredBlob>, StorageError> {
        // Query backend by routing_id.
        // Filter: stored_at > since (if provided).
        // Filter: not expired (stored_at + blob_ttl > now).
        // Order by stored_at ascending.
        // Cap at limit results.
        todo!()
    }

    async fn delete(&self, blob_id: &[u8; 32]) -> Result<bool, StorageError> {
        // Remove from backend. Return true if found and removed.
        todo!()
    }

    async fn purge_expired(&self) -> Result<usize, StorageError> {
        let now = (self.clock)();
        // Remove all blobs where stored_at + blob_ttl <= now.
        // Return count removed.
        todo!()
    }

    async fn count(&self) -> Result<usize, StorageError> {
        // Return total blob count.
        todo!()
    }
}
```

### Step 3: Override streaming methods for streaming backends

The default `store_streaming` collects the entire body into a `Vec<u8>` before calling `store`. The default `get_streaming` wraps the `Vec<u8>` from `get` in a single-chunk stream. For backends that support native streaming (S3, large file stores), override these methods to avoid materializing the entire blob in memory.

```rust
async fn store_streaming(
    &self,
    routing_id: [u8; 32],
    blob_id: [u8; 32],
    recipient_hint: Option<[u8; 32]>,
    blob_ttl: u32,
    content_length: Option<u64>,
    body: BlobBodyStream,
) -> Result<BlobMetadata, StorageError> {
    // Stream chunks directly to your backend (e.g., S3 multipart upload).
    // content_length is advisory -- the actual streamed length governs.
    // Cap preallocation at 64 MiB to prevent OOM from malicious hints.
    todo!()
}
```

### Key invariants

- **`stored_at` must use the clock function.** Production code uses `system_clock()`. Conformance tests inject a controllable `AtomicU64` clock.
- **TTL expiry is enforced on read.** `get` and `query` must not return expired blobs, regardless of whether `purge_expired` has run.
- **`query` results must be ordered by `stored_at` ascending.** The conformance suite checks ordering.
- **`query` since filter is exclusive.** Only blobs with `stored_at > since` are returned.
- **`delete` returns `false` on second call.** Idempotent but must report whether the blob existed.
- **Thread safety.** The relay spawns one task per WebSocket connection; all share the same `BlobStorage` via `Arc`. Use `RwLock`, connection pooling, or atomic operations as appropriate.

---

## 6. Testing with `blob_store_conformance!`

The `blob_store_conformance!` macro (defined in `crates/scp-testing/src/conformance/blob_store.rs`) generates 19 test cases. The factory expression must return a `(impl BlobStorage, Arc<AtomicU64>)` tuple -- the storage instance and a controllable clock.

### Usage

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use scp_testing::blob_store_conformance;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;

    blob_store_conformance!({
        let clock = Arc::new(AtomicU64::new(1_000_000));
        let clock_fn = {
            let c = clock.clone();
            Arc::new(move || c.load(std::sync::atomic::Ordering::Relaxed))
        };
        let store = MyBlobStore::with_clock(clock_fn);
        (store, clock)
    });
}
```

The `scp_testing::conformance::blob_store::test_helpers` module provides `make_test_clock()` for convenience:

```rust
use scp_testing::conformance::blob_store::test_helpers::make_test_clock;

blob_store_conformance!({
    let (clock_fn, clock) = make_test_clock();
    let store = MyBlobStore::with_clock(clock_fn);
    (store, clock)
});
```

### What it tests

| # | Test | What it verifies |
|---|------|------------------|
| 1 | `roundtrip` | Store/get preserves all fields |
| 2 | `missing_returns_none` | Get for nonexistent blob returns None |
| 3 | `ttl_expiry` | Expired blob not returned by get (clock advanced) |
| 4 | `query_routing_order` | Query results ordered by `stored_at` ascending |
| 5 | `query_since` | Since filter excludes older blobs |
| 6 | `query_limit` | Limit parameter caps result count |
| 7 | `delete` | Delete removes blob, second delete returns false |
| 8 | `store_returns_blob_id` | Returned blob_id matches SHA-256 of content |
| 9 | `concurrent_store_purge` | Concurrent store + purge_expired is safe |
| 10 | `purge_expired_only` | Purge removes only expired blobs |
| 11 | `query_empty_returns_empty` | Query for unknown routing_id returns empty Vec |
| 12 | `store_streaming_roundtrip` | Store via stream, verify via get |
| 13 | `get_streaming_roundtrip` | Store normally, retrieve via get_streaming |
| 14 | `store_streaming_get_streaming_roundtrip` | Full streaming roundtrip |
| 15 | `store_streaming_empty_body` | Streaming store with empty body |
| 16 | `store_streaming_content_length_hint` | Content length hint is advisory |
| 17 | `get_streaming_nonexistent` | get_streaming for missing blob returns None |
| 18 | `store_streaming_query_interop` | Streaming-stored blob findable via query |
| 19 | `get_streaming_expired` | get_streaming returns None for expired blobs |

---

## 7. Performance Considerations

### Storage trait

- **Prefix operations (`list_keys`, `delete_prefix`) can be expensive.** For backends without native prefix support, these scan all keys. Use a hierarchical key scheme (e.g., `ctx/{context_id}/mls/...`) to limit scan scope.
- **`exists` should be cheaper than `retrieve`.** For SQLite, this is `SELECT 1 ... LIMIT 1` vs reading the blob. For Redis, `EXISTS` vs `GET`. Implement `exists` independently rather than delegating to `retrieve`.
- **Concurrency model matters.** The `concurrent_access` conformance test spawns 10 tasks. For SQLite, use WAL mode with a connection pool. For in-memory backends, `RwLock` with short critical sections.

### BlobStorage trait

- **TTL expiry on read avoids background purge latency.** Always check `stored_at + blob_ttl > now` in `get` and `query`, even if `purge_expired` has not run recently.
- **`purge_expired` runs on a 10-second default interval** (configurable via `RelayConfig::ttl_check_interval`). It must not block the relay's connection handlers. For SQLite, use `DELETE WHERE expires_at <= ?` in a single statement. For in-memory, iterate and remove under a write lock.
- **`query` ordering by `stored_at` ascending** means a B-tree or ordered index on `(routing_id, stored_at)` is essential for any persistent backend. The in-memory implementation maintains a secondary `RoutingIndex` for this purpose.
- **Streaming overrides** (`store_streaming`, `get_streaming`) avoid materializing the entire blob in memory. This matters for large blobs (up to 256 KB default, configurable via `RelayConfig::max_blob_size`). For S3, stream directly to/from the object store. For SQLite, the default collect-and-delegate approach is fine since blob sizes are bounded.
- **`BlobStorageBackend` eliminates generics.** The relay uses `BlobStorageBackend` (a concrete enum wrapping all backends) rather than a generic type parameter. New backends are added as enum variants in `crates/scp-transport/src/native/storage.rs`.

---

## 8. Available Implementations

### Storage implementations

| Implementation | Location | Use case |
|----------------|----------|----------|
| `InMemoryStorage` | `crates/scp-platform/src/testing.rs` | Testing and development. Data lost on restart. |
| `SqliteStorage` | `crates/scp-platform/src/sqlite/` | Production. SQLCipher-encrypted. |
| `FilesystemStorage` | `crates/scp-platform/src/filesystem.rs` | Simple file-backed storage. |

### BlobStorage implementations

| Implementation | Location | Use case | Env var value |
|----------------|----------|----------|---------------|
| `InMemoryBlobStorage` | `crates/scp-transport/src/native/storage.rs` | Testing and development | `memory` |
| `SqliteBlobStore` | `crates/scp-transport/src/native/sqlite_blob.rs` | Default production backend | `sqlite` |
| `RedbBlobStore` | `crates/scp-transport/src/native/redb_blob.rs` | Embedded alternative | `redb` |
| `PostgresBlobStore` | `crates/scp-transport/src/native/postgres_blob.rs` | Scalable production backend | `postgres` |
| `S3BlobStore` | `crates/scp-transport/src/native/s3_blob.rs` | Object storage | `s3` |

The `BlobStorageBackend` enum wraps all five implementations. The relay binary selects the backend via the `SCP_RELAY_STORAGE_BACKEND` environment variable (default: `sqlite`). See [Relay Operations](relay-operations.md) for configuration details.

---

## Spec Cross-References

| Topic | Spec Section |
|-------|-------------|
| Platform adapter design (Storage, KeyCustody, etc.) | ADR-006 |
| Custom storage adapter requirements | SS17.11 |
| Conformance testing extensions | SS17.13 |
| Storage key conventions | SS17.3 |
| ProtocolStore domain methods | SS17.4 |
| Blob storage specification | ADR-004 |
