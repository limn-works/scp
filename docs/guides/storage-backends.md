# Implementing Storage Backends

This guide covers how to implement a new storage backend for SCP. There are two independent storage traits serving different roles: `Storage` for client SDK state and `BlobStorage` for relay-side encrypted message blobs. You may implement one or both depending on your use case.

**Spec reference:** `.docs/specs/17-persistence-and-storage.md`

---

## Overview

SCP uses a two-layer persistence architecture:

```
Protocol Engine (structured domain operations)
        |
ProtocolStore (key conventions + MessagePack serialization)
        |
Storage trait (flat KV: store/retrieve/delete/list_keys/delete_prefix/exists)
        |
Your backend adapter
```

The `Storage` trait (defined in `scp-platform`) is deliberately thin -- six async methods operating on `(key: &str, data: &[u8])` pairs. All structured protocol logic (context state, membership, event logs, nonces) lives in `ProtocolStore` in `scp-core/store/`. You implement six methods. The protocol layer handles everything else and is tested once.

For relay operators, there is a separate trait:

```
Relay Server (blob routing, TTL enforcement, subscription registry)
        |
BlobStorage trait (store/get/query/delete/purge_expired + streaming)
        |
Your backend adapter
```

The `BlobStorage` trait (defined in `scp-transport/native/storage.rs`) handles encrypted message blobs with routing metadata and TTL semantics.

**Why thin traits?** Three approaches were considered: rich traits (expensive adapter authoring, couples adapters to protocol evolution), optional override patterns (two code paths, conformance nightmare), and thin traits (any developer writes an adapter in 30 minutes, protocol evolution never touches adapters). Thin traits won.

---

## Storage Trait

The full trait definition lives in `crates/scp-platform/src/traits.rs`:

```rust
pub trait Storage: Send + Sync {
    /// Store a byte slice under the given key.
    /// Overwrites any existing value for the same key.
    fn store(
        &self,
        key: &str,
        data: &[u8],
    ) -> impl Future<Output = Result<(), PlatformError>> + Send;

    /// Retrieve the byte slice stored under the given key.
    /// Returns None if the key does not exist.
    fn retrieve(
        &self,
        key: &str,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, PlatformError>> + Send;

    /// Delete the value stored under the given key.
    /// No-op if the key does not exist.
    fn delete(&self, key: &str) -> impl Future<Output = Result<(), PlatformError>> + Send;

    /// List all keys matching the given prefix in lexicographic order.
    fn list_keys(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<Vec<String>, PlatformError>> + Send;

    /// Delete all keys matching the given prefix.
    /// Returns the number of keys deleted.
    fn delete_prefix(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<u64, PlatformError>> + Send;

    /// Check whether a key exists without reading its value.
    fn exists(&self, key: &str) -> impl Future<Output = Result<bool, PlatformError>> + Send;
}
```

### Method-by-method

| Method | Purpose | Key invariant |
|--------|---------|---------------|
| `store` | Upsert a key-value pair | Overwrites silently on conflict |
| `retrieve` | Read a value by key | Returns `Ok(None)` for missing keys, never errors |
| `delete` | Remove a key | No-op if key does not exist |
| `list_keys` | Prefix scan | **Must return keys in lexicographic order** |
| `delete_prefix` | Bulk delete by prefix | Returns count of deleted keys |
| `exists` | Existence check without read | Used for UCAN nonce replay prevention |

The **lexicographic ordering** guarantee on `list_keys` is critical. SCP uses zero-padded sequence numbers in keys (e.g., `context/{id}/event/00000000000000000042`) so that lexicographic order matches numeric order, enabling efficient range queries.

All errors are reported via `PlatformError::StorageError(String)`.

---

## BlobStorage Trait

The full trait definition lives in `crates/scp-transport/src/native/storage.rs`:

```rust
#[async_trait::async_trait]
pub trait BlobStorage: Send + Sync {
    /// Store a blob. Returns the stored metadata including server-assigned stored_at.
    async fn store(
        &self,
        routing_id: [u8; 32],
        blob_id: [u8; 32],
        recipient_hint: Option<[u8; 32]>,
        blob_ttl: u32,
        blob: Vec<u8>,
    ) -> Result<StoredBlob, StorageError>;

    /// Retrieve a specific blob by blob_id. Returns None if missing or expired.
    async fn get(&self, blob_id: &[u8; 32]) -> Result<Option<StoredBlob>, StorageError>;

    /// Query blobs for a routing_id, filtered by since timestamp, with limit.
    /// Results ordered oldest-first (ascending stored_at).
    async fn query(
        &self,
        routing_id: &[u8; 32],
        since: Option<u64>,
        limit: u32,
    ) -> Result<Vec<StoredBlob>, StorageError>;

    /// Delete a blob by blob_id. Returns true if found and removed.
    async fn delete(&self, blob_id: &[u8; 32]) -> Result<bool, StorageError>;

    /// Remove all expired blobs. Returns count of purged blobs.
    async fn purge_expired(&self) -> Result<usize, StorageError>;

    /// Store a blob from a stream of chunks (default: collects to Vec, delegates to store).
    async fn store_streaming(...) -> Result<BlobMetadata, StorageError> { /* default impl */ }

    /// Retrieve a blob as metadata + body stream (default: wraps get in single-chunk stream).
    async fn get_streaming(...) -> Result<Option<(BlobMetadata, BlobBodyStream)>, StorageError> { /* default impl */ }
}
```

### Key differences from Storage

| Aspect | `Storage` | `BlobStorage` |
|--------|-----------|---------------|
| Purpose | Client SDK state | Relay-side blob routing |
| Keys | UTF-8 strings | 32-byte `blob_id` (SHA-256 hash) |
| Values | Opaque bytes | Blobs with routing metadata and TTL |
| Indexing | Prefix-based | `routing_id` secondary index |
| Expiry | No TTL | TTL with `purge_expired` |
| Trait style | RPITIT (`impl Future`) | `#[async_trait]` (dyn-compatible) |
| Streaming | Not applicable | `store_streaming` / `get_streaming` with defaults |
| Crate | `scp-platform` | `scp-transport` |

`BlobStorage` uses `#[async_trait]` (boxed futures) because the relay server holds `Box<dyn BlobStorage>` via the `BlobStorageBackend` enum dispatch. `Storage` uses RPITIT because it is used as a generic type parameter on `ProtocolStore<S: Storage>`.

---

## Implementing Storage

### Step 1: Create your backend struct

Your struct must be `Send + Sync`. Use interior mutability as needed.

```rust
use scp_platform::error::PlatformError;
use scp_platform::traits::Storage;

pub struct MyStorage {
    // Your backend state. For example, a connection pool:
    conn: std::sync::Mutex<MyConnection>,
}

impl MyStorage {
    pub fn new(/* config */) -> Result<Self, PlatformError> {
        // Initialize your backend
        Ok(Self { conn: std::sync::Mutex::new(/* ... */) })
    }
}
```

**Reference:** `SqliteStorage` in `crates/scp-platform/src/sqlite/mod.rs` uses `std::sync::Mutex<Connection>` (not `tokio::sync::Mutex`) because all SQLite operations are sub-millisecond single-row KV on WAL mode -- blocking the async runtime for that duration is cheaper than `spawn_blocking` overhead.

`FilesystemStorage` in `crates/scp-platform/src/filesystem/mod.rs` maps keys to file paths with atomic writes (write to temp file, then rename).

### Step 2: Implement the six methods

The trait uses RPITIT -- each method returns `impl Future<Output = ...> + Send`. The pattern used by all existing implementations is to capture owned copies of the parameters and return an `async move` block:

```rust
#[allow(clippy::manual_async_fn)]
impl Storage for MyStorage {
    fn store(
        &self,
        key: &str,
        data: &[u8],
    ) -> impl Future<Output = Result<(), PlatformError>> + Send {
        let key = key.to_owned();
        let data = data.to_vec();
        async move {
            // Your write logic here.
            // Map all backend errors to PlatformError::StorageError(String).
            Ok(())
        }
    }

    fn retrieve(
        &self,
        key: &str,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, PlatformError>> + Send {
        let key = key.to_owned();
        async move {
            // Return Ok(None) for missing keys. Never error on "not found".
            Ok(None)
        }
    }

    fn delete(&self, key: &str) -> impl Future<Output = Result<(), PlatformError>> + Send {
        let key = key.to_owned();
        async move {
            // No-op if key does not exist.
            Ok(())
        }
    }

    fn list_keys(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<Vec<String>, PlatformError>> + Send {
        let prefix = prefix.to_owned();
        async move {
            // MUST return keys in lexicographic order.
            // Use a range scan, not a full scan + filter.
            Ok(vec![])
        }
    }

    fn delete_prefix(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<u64, PlatformError>> + Send {
        let prefix = prefix.to_owned();
        async move {
            // Delete all keys starting with prefix. Return count.
            Ok(0)
        }
    }

    fn exists(&self, key: &str) -> impl Future<Output = Result<bool, PlatformError>> + Send {
        let key = key.to_owned();
        async move {
            // Check existence without reading the value.
            Ok(false)
        }
    }
}
```

### Step 3: Prefix query technique

The `list_keys` and `delete_prefix` methods need efficient prefix matching. The SQLite implementation uses a B-tree range scan technique rather than `LIKE` queries:

1. Compute the prefix's lexicographic successor (increment the last non-`0xFF` byte).
2. Query with `key >= prefix AND key < successor`.

This gives O(log n) performance via the clustered index. See `prefix_successor` in `crates/scp-platform/src/sqlite/mod.rs` for the algorithm. If your backend supports native prefix scans (e.g., RocksDB `seek_for_prev`, redb range queries), use them.

### Step 4: Wire into ProtocolStore

`ProtocolStore<S: Storage>` is generic over any `Storage` implementation. No registration step is needed -- pass your backend as the type parameter:

```rust
use scp_core::store::ProtocolStore;

let storage = MyStorage::new(/* ... */)?;
let protocol_store = ProtocolStore::new(storage);
```

---

## Implementing BlobStorage

### Step 1: Create your backend struct

Must be `Send + Sync + Clone` (the relay server clones storage handles across connection handlers). Use `Arc` for shared state.

```rust
use scp_transport::native::storage::{
    BlobStorage, ClockFn, StorageError, StoredBlob, system_clock,
};

#[derive(Clone)]
pub struct MyBlobStore {
    inner: Arc<Mutex<MyBackend>>,
    clock: ClockFn,
}

impl MyBlobStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(MyBackend::new())),
            clock: system_clock(),
        }
    }

    /// Constructor with controllable clock for conformance tests.
    pub fn with_clock(clock: ClockFn) -> Self {
        Self {
            inner: Arc::new(Mutex::new(MyBackend::new())),
            clock,
        }
    }
}
```

All blob store implementations must accept a `ClockFn` for testing. `ClockFn` is `Arc<dyn Fn() -> u64 + Send + Sync>`. Production code uses `system_clock()`. Tests supply an `AtomicU64`-backed clock for deterministic TTL testing.

### Step 2: Implement the five required methods

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
        let expires_at = stored_at.saturating_add(u64::from(blob_ttl));

        // Store the blob with its metadata.
        // Maintain a secondary index on routing_id for query().
        // Return StoredBlob with all fields populated.

        Ok(StoredBlob {
            routing_id,
            blob_id,
            recipient_hint,
            blob_ttl,
            stored_at,
            blob,
        })
    }

    async fn get(&self, blob_id: &[u8; 32]) -> Result<Option<StoredBlob>, StorageError> {
        // Look up by blob_id. If found, check expiry against clock.
        // Return None for expired blobs (do not delete them here --
        // that is purge_expired's job).
        Ok(None)
    }

    async fn query(
        &self,
        routing_id: &[u8; 32],
        since: Option<u64>,
        limit: u32,
    ) -> Result<Vec<StoredBlob>, StorageError> {
        // Query by routing_id. Filter out expired blobs.
        // If since is Some, exclude blobs with stored_at <= since.
        // Sort results ascending by stored_at (oldest first).
        // Truncate to limit.
        Ok(vec![])
    }

    async fn delete(&self, blob_id: &[u8; 32]) -> Result<bool, StorageError> {
        // Remove blob and its routing index entry.
        // Return true if found, false if not found.
        Ok(false)
    }

    async fn purge_expired(&self) -> Result<usize, StorageError> {
        let now = (self.clock)();
        // Scan for blobs where expires_at <= now.
        // Remove them and their routing index entries.
        // Return count of purged blobs.
        Ok(0)
    }
}
```

### Step 3: Streaming methods (optional)

The `store_streaming` and `get_streaming` methods have default implementations that collect to/from `Vec<u8>`. Override them only if your backend can avoid full materialization -- for example, S3 multipart uploads or streaming reads from object storage.

```rust
// Only override if your backend benefits from streaming.
async fn store_streaming(
    &self,
    routing_id: [u8; 32],
    blob_id: [u8; 32],
    recipient_hint: Option<[u8; 32]>,
    blob_ttl: u32,
    content_length: Option<u64>,
    mut body: BlobBodyStream,
) -> Result<BlobMetadata, StorageError> {
    // content_length is advisory only -- do not trust it for allocation.
    // Cap preallocation at a reasonable limit (the default caps at 64 MiB).
    // ...
}
```

### Step 4: Register as a BlobStorageBackend variant

The relay server uses `BlobStorageBackend`, a concrete enum that eliminates generic propagation. To add your backend:

1. Add a variant to the `BlobStorageBackend` enum in `crates/scp-transport/src/native/storage.rs`:

```rust
pub enum BlobStorageBackend {
    InMemory(InMemoryBlobStorage),
    #[cfg(feature = "sqlite-blob")]
    Sqlite(super::sqlite_blob::SqliteBlobStore),
    // Add your variant:
    #[cfg(feature = "my-blob")]
    MyBackend(super::my_blob::MyBlobStore),
}
```

2. Add your variant to the `dispatch!` macro arms and implement `From<MyBlobStore>`.
3. Gate behind a cargo feature flag (e.g., `my-blob`).

---

## Testing with Conformance Macros

Both traits have conformance test macros in `scp-testing` that validate your implementation against the protocol specification.

### Storage conformance

The `storage_conformance!()` macro generates 13 tests covering: store/retrieve roundtrip, missing key returns None, delete removes value, `list_keys` returns sorted results, `list_keys` with prefix filtering, `delete_prefix` removes matching keys, `exists` correctness, overwrite behavior, concurrent access safety, and empty value storage.

```rust
// crates/my-crate/tests/conformance.rs

#![allow(clippy::unwrap_used, clippy::expect_used)]

use my_crate::MyStorage;

fn make_my_storage() -> MyStorage {
    // Create a fresh, empty instance per test.
    // If your backend uses files, use tempfile::tempdir() and leak the TempDir
    // so it outlives the async test.
    let dir = tempfile::tempdir().expect("tempdir should succeed");
    let dir_path = dir.path().to_path_buf();
    let _ = Box::leak(Box::new(dir));
    MyStorage::new(&dir_path).expect("MyStorage::new should succeed")
}

scp_testing::storage_conformance!(make_my_storage());
```

The macro expands into a `mod storage_conformance` containing individual `#[tokio::test]` functions. It references `scp_platform::Storage` internally -- if you invoke it from within the `scp-platform` crate itself, you need `extern crate self as scp_platform;` in your test module.

### Blob store conformance

The `blob_store_conformance!()` macro generates 19 tests covering: store/get roundtrip, TTL expiry, query ordering and filtering, delete behavior, concurrent store + purge safety, SHA-256 blob ID verification, and all streaming operations.

The macro takes a factory expression returning `(impl BlobStorage, Arc<AtomicU64>)` -- the store and its controllable clock:

```rust
// crates/my-crate/tests/blob_conformance.rs

#![cfg(feature = "my-blob")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use scp_transport::native::storage::ClockFn;
use my_crate::MyBlobStore;

fn make_my_blob_store() -> (MyBlobStore, Arc<AtomicU64>) {
    let clock = Arc::new(AtomicU64::new(1_000_000));
    let clock_fn: ClockFn = {
        let c = clock.clone();
        Arc::new(move || c.load(std::sync::atomic::Ordering::Relaxed))
    };
    let store = MyBlobStore::with_clock(clock_fn);
    (store, clock)
}

scp_testing::blob_store_conformance!(make_my_blob_store());
```

The clock must start at a nonzero value (the conformance tests advance it to test TTL expiry). The factory is called once per test to ensure isolation.

### Running conformance tests

```bash
# Storage conformance
cargo test -p my-crate --test conformance

# Blob store conformance (with feature flag)
cargo test -p my-crate --test blob_conformance --features my-blob
```

If all tests pass, your implementation is correct. No additional validation is required.

---

## Performance Considerations

### Serialization

`ProtocolStore` serializes all domain types to `MessagePack` via `rmp-serde` before calling `Storage::store`, and deserializes on `retrieve`. Your `Storage` implementation never sees structured data -- only opaque byte slices. This means:

- Values are compact (MessagePack is ~30% smaller than JSON).
- Your backend does not need schema awareness or migrations for protocol changes.
- Version envelopes are handled by `ProtocolStore`, not the storage adapter.

### Key design

All storage keys follow the convention `{namespace}/{entity_id}/{sub_key}`:

```
identity/{did}/document
context/{context_id}/state
context/{context_id}/event/00000000000000000042
context/{context_id}/membership/{did}
```

This means:
- **Prefix scans are the primary query pattern.** Optimize `list_keys` and `delete_prefix` for prefix-based access, not point lookups.
- **Keys are hierarchical.** Backends that support directory-like structures (filesystem, S3) can map `/` to path separators.
- **Sequence numbers are zero-padded to 20 digits.** Lexicographic order equals numeric order. No custom comparators needed.

### Transaction patterns

The `Storage` trait has no transaction primitive. Each method call is an independent operation. `ProtocolStore` sequences calls to avoid data corruption, but individual operations are not grouped into atomic transactions.

If your backend supports transactions, you can use them internally for `delete_prefix` (which should atomically delete all matching keys) but the trait does not require cross-method atomicity.

For `BlobStorage`, `purge_expired` should be internally consistent -- do not leave orphaned routing index entries when deleting expired blobs.

### Concurrency

Both traits require `Send + Sync`. The relay server handles concurrent requests from multiple connections. The client SDK may access storage from multiple async tasks.

- **SQLite backend:** Uses `std::sync::Mutex` (not tokio) because operations are sub-millisecond. WAL mode enables concurrent readers with one writer.
- **redb backend:** Uses `tokio::sync::Mutex` around the `Database` handle.
- **In-memory backends:** Use `Arc<RwLock<HashMap>>` for maximum read concurrency.

Choose the synchronization primitive that matches your backend's I/O characteristics. For sub-millisecond operations, `std::sync::Mutex` avoids the overhead of `spawn_blocking`. For operations that may block (network I/O, disk sync), use `tokio::sync::Mutex` or `spawn_blocking`.

### Blob store indexing

`BlobStorage` requires a secondary index on `routing_id` for the `query` method. How you implement this depends on your backend:

- **SQLite:** `CREATE INDEX idx_routing ON blobs (routing_id, stored_at)` for efficient range queries.
- **redb:** Separate `MultimapTable<&[u8; 32], &[u8; 32]>` mapping `routing_id` to `blob_id` sets.
- **In-memory:** `HashMap<[u8; 32], Vec<[u8; 32]>>` as a secondary routing index.

TTL enforcement also benefits from an expiry index (`CREATE INDEX idx_expiry ON blobs (expires_at)` in SQLite), though some backends (redb, in-memory) use periodic full scans instead.
