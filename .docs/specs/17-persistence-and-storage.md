# 17. Persistence and Storage

## 17.1 Storage Architecture Overview

SCP has two independent persistence surfaces: client-side storage for SDK state and relay-side storage for encrypted message blobs. These serve different roles, different operators, and different access patterns. They share no trait, no backend, and no coupling.

### Client SDK Storage Stack

```
Protocol Engine (structured domain operations)
        |
ProtocolStore (key conventions + serde serialization)
        |
Storage trait (flat KV: store/retrieve/delete/list_keys/delete_prefix/exists)
        |
Backend adapter (SQLite, wa-sqlite, filesystem, in-memory)
```

The `Storage` trait (defined in `scp-platform`) is deliberately thin — six async methods operating on `(key: &str, data: &[u8])` pairs. All structured protocol operations (context state, membership, event logs, nonces, caches) are mapped to flat KV operations by `ProtocolStore` in `scp-core`. Adapter authors implement six methods. The protocol layer handles all domain logic and is tested once.

### Relay Storage Stack

```
Relay Server (blob routing, TTL enforcement, subscription registry)
        |
BlobStore trait (store/get/list/delete/expire with routing_id + TTL)
        |
Backend adapter (SQLite, redb, PostgreSQL, S3-compatible, in-memory)
```

The `BlobStore` trait (defined in `scp-transport/native/`) handles encrypted message blobs with routing metadata and time-to-live semantics. Relay operators choose a backend based on deployment scale.

### Why Thin Trait + Thick Protocol Layer

Three approaches were considered:

- **Rich trait** (store_context, list_active_contexts, append_event...): Makes adapter authoring expensive, couples the adapter interface to protocol evolution. Every protocol change requires every adapter to update.
- **Optional override pattern** (thin trait with optional rich methods): Creates two code paths, a conformance testing nightmare, ambiguous contracts.
- **Thin trait** (flat KV): Any developer writes an adapter in 30 minutes. The protocol layer handles all structured logic and is tested once. Protocol evolution never touches adapter implementations.

The thin trait approach was chosen. Adapters are dumb storage. The protocol is smart.

## 17.2 Storage Trait Evolution

The existing `Storage` trait (ADR-006) provides four methods: `store`, `retrieve`, `delete`, `list_keys`. Two additions are required for the protocol's actual access patterns:

```rust
/// scp-platform/src/trait.rs (additions to existing Storage trait)

pub trait Storage: Send + Sync {
    // Existing methods (ADR-006):
    async fn store(&self, key: &str, data: &[u8]) -> Result<(), PlatformError>;
    async fn retrieve(&self, key: &str) -> Result<Option<Vec<u8>>, PlatformError>;
    async fn delete(&self, key: &str) -> Result<(), PlatformError>;
    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, PlatformError>;

    // New methods:

    /// Delete all keys matching a prefix. Returns the count of keys deleted.
    /// Atomic: either all matching keys are deleted or none are (on error).
    /// Used for context cleanup — delete_prefix("context/{id}/") removes
    /// all state for a context in one operation.
    async fn delete_prefix(&self, prefix: &str) -> Result<u64, PlatformError>;

    /// Check if a key exists without reading the value.
    /// Used for UCAN nonce replay prevention — check existence is cheaper
    /// than deserializing the full value.
    async fn exists(&self, key: &str) -> Result<bool, PlatformError>;
}
```

**Key ordering guarantee:** `list_keys` returns keys in **lexicographic order**. This enables range queries on event logs via zero-padded sequence numbers (e.g., listing `context/{id}/event/000000000000000050` through `context/{id}/event/000000000000000099` returns events 50-99 in order). All `Storage` implementations MUST maintain this invariant. The `storage_conformance!()` macro tests for it.

## 17.3 Key Convention

All keys follow `{namespace}/{entity_id}/{sub_key}` with `/` as the hierarchy separator. Keys are UTF-8 strings. Entity IDs are deterministic (DIDs, context IDs, hashes). Sub-keys are type-specific.

```
identity/{did}/document
identity/{did}/active_signing_key
identity/{did}/private_state/{seq:020d}

context/{context_id}/state
context/{context_id}/params
context/{context_id}/membership/{did}
context/{context_id}/sender_key/{did}
context/{context_id}/nonce/{nonce_hash}
context/{context_id}/event/{seq:020d}
context/{context_id}/event_meta/count
context/{context_id}/event_meta/root
context/{context_id}/event_tree/{level}/{index}
context/{context_id}/tool/{tool_id}
context/{context_id}/tool_session/{session_id}
context/{context_id}/role/{role_name}
context/{context_id}/ucan_revocation/{token_id}

did_cache/{did}
tofu/{did}
key_package/{relay_url}/{index}
relay_score/{relay_url}

mls/{context_id}/...
```

**Zero-padded sequences.** Event sequence numbers and private state sequence numbers use `:020d` formatting (20-digit zero-padded decimal). This ensures lexicographic ordering matches numeric ordering, enabling efficient range queries via `list_keys`. Example: event 42 is stored at `context/{id}/event/00000000000000000042`.

**Nonce keys.** UCAN nonce replay prevention uses `context/{context_id}/nonce/{SHA256(nonce_string)}` — the nonce string is hashed to a fixed-length key. The value stores `(first_seen_timestamp, token_expiry_timestamp)` for pruning. The `exists()` method enables O(1) replay checks without deserializing.

**Context cleanup.** When a context is closed or expired, `delete_prefix("context/{context_id}/")` removes all context state atomically. No enumeration required.

## 17.4 ProtocolStore

`ProtocolStore` is a concrete struct in `scp-core/store/` that wraps `Arc<dyn Storage>` and provides typed domain methods. These are NOT trait methods — adapters do not implement them. `ProtocolStore` is the single interface between protocol logic and persistent storage.

```rust
/// scp-core/src/store/mod.rs

pub struct ProtocolStore {
    storage: Arc<dyn Storage>,
}

impl ProtocolStore {
    pub fn new(storage: Arc<dyn Storage>) -> Self;

    // --- Context state ---
    pub async fn store_context_state(&self, context_id: &ContextId, state: &ContextState) -> Result<(), StoreError>;
    pub async fn load_context_state(&self, context_id: &ContextId) -> Result<Option<ContextState>, StoreError>;
    pub async fn store_context_params(&self, context_id: &ContextId, params: &ContextParams) -> Result<(), StoreError>;
    pub async fn load_context_params(&self, context_id: &ContextId) -> Result<Option<ContextParams>, StoreError>;
    pub async fn list_active_contexts(&self) -> Result<Vec<ContextId>, StoreError>;
    pub async fn delete_context(&self, context_id: &ContextId) -> Result<u64, StoreError>;

    // --- Membership ---
    pub async fn store_membership(&self, context_id: &ContextId, did: &DID, role: &str) -> Result<(), StoreError>;
    pub async fn load_membership(&self, context_id: &ContextId, did: &DID) -> Result<Option<String>, StoreError>;
    pub async fn list_members(&self, context_id: &ContextId) -> Result<Vec<(DID, String)>, StoreError>;
    pub async fn remove_membership(&self, context_id: &ContextId, did: &DID) -> Result<(), StoreError>;

    // --- Sender keys ---
    pub async fn store_sender_key(&self, context_id: &ContextId, did: &DID, key: &SenderKey) -> Result<(), StoreError>;
    pub async fn load_sender_key(&self, context_id: &ContextId, did: &DID) -> Result<Option<SenderKey>, StoreError>;
    pub async fn list_sender_keys(&self, context_id: &ContextId) -> Result<Vec<(DID, SenderKey)>, StoreError>;
    pub async fn remove_sender_key(&self, context_id: &ContextId, did: &DID) -> Result<(), StoreError>;

    // --- UCAN nonces ---
    pub async fn check_and_record_nonce(
        &self,
        context_id: &ContextId,
        nonce_hash: &[u8; 32],
        first_seen: u64,
        token_expiry: u64,
    ) -> Result<bool, StoreError>; // true = new nonce, false = replay
    pub async fn prune_expired_nonces(&self, context_id: &ContextId, now: u64) -> Result<u64, StoreError>;

    // --- Event log ---
    pub async fn append_event(&self, context_id: &ContextId, seq: u64, event_hash: &[u8; 32]) -> Result<(), StoreError>;
    pub async fn load_event(&self, context_id: &ContextId, seq: u64) -> Result<Option<Vec<u8>>, StoreError>;
    pub async fn load_event_range(&self, context_id: &ContextId, start: u64, end: u64) -> Result<Vec<Vec<u8>>, StoreError>;
    pub async fn event_count(&self, context_id: &ContextId) -> Result<u64, StoreError>;
    pub async fn store_event_root(&self, context_id: &ContextId, root: &[u8; 32]) -> Result<(), StoreError>;
    pub async fn load_event_root(&self, context_id: &ContextId) -> Result<Option<[u8; 32]>, StoreError>;
    pub async fn store_event_tree_node(&self, context_id: &ContextId, level: u32, index: u64, hash: &[u8; 32]) -> Result<(), StoreError>;
    pub async fn load_event_tree_node(&self, context_id: &ContextId, level: u32, index: u64) -> Result<Option<[u8; 32]>, StoreError>;

    // --- DID cache ---
    pub async fn cache_did_document(&self, did: &DID, doc: &[u8], expires_at: u64) -> Result<(), StoreError>;
    pub async fn load_cached_did_document(&self, did: &DID) -> Result<Option<Vec<u8>>, StoreError>;

    // --- TOFU records ---
    pub async fn store_tofu_record(&self, did: &DID, record: &[u8]) -> Result<(), StoreError>;
    pub async fn load_tofu_record(&self, did: &DID) -> Result<Option<Vec<u8>>, StoreError>;

    // --- Tools ---
    pub async fn store_tool(&self, context_id: &ContextId, tool_id: &ToolId, registration: &[u8]) -> Result<(), StoreError>;
    pub async fn load_tool(&self, context_id: &ContextId, tool_id: &ToolId) -> Result<Option<Vec<u8>>, StoreError>;
    pub async fn list_tools(&self, context_id: &ContextId) -> Result<Vec<ToolId>, StoreError>;

    // --- Tool sessions ---
    pub async fn store_tool_session(&self, context_id: &ContextId, session_id: &str, session: &[u8]) -> Result<(), StoreError>;
    pub async fn load_tool_session(&self, context_id: &ContextId, session_id: &str) -> Result<Option<Vec<u8>>, StoreError>;
    pub async fn delete_tool_session(&self, context_id: &ContextId, session_id: &str) -> Result<(), StoreError>;

    // --- Relay scores ---
    pub async fn store_relay_score(&self, relay_url: &str, score: &[u8]) -> Result<(), StoreError>;
    pub async fn load_relay_score(&self, relay_url: &str) -> Result<Option<Vec<u8>>, StoreError>;
    pub async fn list_relay_scores(&self) -> Result<Vec<(String, Vec<u8>)>, StoreError>;

    // --- Identity ---
    pub async fn store_identity_document(&self, did: &DID, doc: &[u8]) -> Result<(), StoreError>;
    pub async fn load_identity_document(&self, did: &DID) -> Result<Option<Vec<u8>>, StoreError>;
    pub async fn store_identity_private_state(&self, did: &DID, seq: u64, state: &[u8]) -> Result<(), StoreError>;
    pub async fn load_identity_private_state(&self, did: &DID, seq: u64) -> Result<Option<Vec<u8>>, StoreError>;

    // --- KeyPackages ---
    pub async fn store_key_package(&self, relay_url: &str, index: u32, kp: &[u8]) -> Result<(), StoreError>;
    pub async fn load_key_packages(&self, relay_url: &str) -> Result<Vec<Vec<u8>>, StoreError>;
    pub async fn delete_key_package(&self, relay_url: &str, index: u32) -> Result<(), StoreError>;

    // --- UCAN revocations ---
    pub async fn store_revocation(&self, context_id: &ContextId, token_id: &str) -> Result<(), StoreError>;
    pub async fn is_revoked(&self, context_id: &ContextId, token_id: &str) -> Result<bool, StoreError>;
}
```

Every `ProtocolStore` method translates to one or two `Storage` trait calls using the key convention from section 17.3. There is no query optimizer, no batch API, no transaction boundary beyond what `delete_prefix` provides. If performance profiling reveals hot paths, batch writes can be added to `Storage` as an optional method with a default implementation that loops (Phase 6).

### Module Structure

```
scp-core/src/store/
    mod.rs          # ProtocolStore struct, StoreError type, re-exports
    context.rs      # Context state, params, membership, sender keys
    event_log.rs    # Event log persistence, tree nodes, roots
    identity.rs     # Identity documents, private state, TOFU, DID cache
    nonce.rs        # UCAN nonce tracking, pruning
    tools.rs        # Tool registration, sessions
    transport.rs    # Relay scores, key packages
```

## 17.5 Serialization

**Format: MessagePack (`rmp-serde`).** Already the wire format for envelopes (ADR-002) and the relay protocol (ADR-004). No additional dependency. MessagePack is compact, fast, and has mature libraries in all target languages.

**Version envelope for forward compatibility:**

```rust
/// scp-core/src/store/mod.rs

#[derive(Serialize, Deserialize)]
pub struct StoredValue<T> {
    pub version: u16,
    pub data: T,
}
```

Every value written by `ProtocolStore` is wrapped in `StoredValue`. On read, `version` is checked before deserializing `data`. This enables lazy migration (section 17.10) without requiring schema-level versioning in the storage backend.

**Encryption at rest** is a platform concern, not a storage layer concern. The `Storage` trait operates on opaque bytes. Encryption happens below:

| Platform | Mechanism | Notes |
|----------|-----------|-------|
| Native (iOS, Android, macOS, Linux, Windows, Python, Node) | `rusqlite` with `bundled-sqlcipher` feature | AES-256 encryption, PBKDF2 with SHA-512 key derivation (256K iterations). Encryption key derived from identity key material stored in platform key custody (Keychain/Keystore). |
| Browser (WASM) | Value-level AES-GCM encryption | SQLCipher unavailable in WASM. Each value is encrypted with a key derived from the identity's WebCrypto key before writing to wa-sqlite. |
| iOS | `NSFileProtectionCompleteUntilFirstUserAuthentication` | Allows background processing while device is locked. Applied to the SQLite database file. |
| Android | TEE-backed key for SQLCipher key derivation | Android Keystore generates the key; SQLCipher uses it for database encryption. StrongBox opt-in only (dramatically slow). |

## 17.6 First-Party Storage Adapters (Client SDK)

| Adapter | Backend | Platform | Good for | Ships in |
|---------|---------|----------|----------|----------|
| `InMemoryStorage` | `HashMap<String, Vec<u8>>` + `RwLock` | All | Testing, CI, short-lived agents | Phase 1 (update for new methods) |
| `SqliteStorage` | `rusqlite` + `bundled-sqlcipher`, WAL mode | Native (all) | **Default production backend** — universal | Phase 2 |
| `FilesystemStorage` | Key -> file path | POSIX systems | Server/CLI, inspectable/debuggable storage | Phase 2 |
| `WasmSqliteStorage` | wa-sqlite (TypeScript) | Browser WASM | Browser default | Phase 4 |

### SQLite Is the Universal Default

Via `rusqlite`, SQLite works on every native platform: iOS, Android, macOS, Linux, Windows, Python (PyO3), Node (napi-rs). The Rust core bundles its own SQLite — no system dependency. Platform-specific ORMs (SwiftData, Room, Core Data) are unnecessary; the SDK calls through FFI into the Rust core's bundled SQLite. This is the same pattern Mozilla uses for Firefox mobile.

**SQLite schema:**

```sql
CREATE TABLE kv (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
) WITHOUT ROWID;
```

`WITHOUT ROWID` uses a clustered index on the primary key, which is optimal for KV workloads (no secondary rowid lookup). WAL mode enables concurrent readers with one writer. The schema is intentionally minimal — all structure lives in the key convention, not the table schema.

**SQLCipher configuration:**

```rust
// Applied on connection open
conn.execute_batch("
    PRAGMA key = '<derived_key>';
    PRAGMA cipher_page_size = 4096;
    PRAGMA kdf_iter = 256000;
    PRAGMA cipher_hmac_algorithm = HMAC_SHA512;
    PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512;
")?;
```

### Browser: The One Exception

The Rust core's `rusqlite` cannot target browser WASM (no filesystem). **wa-sqlite** with **OPFSCoopSyncVFS** is the browser backend:

- Supports 1GB+ databases
- Works in all major browsers (Chrome, Firefox, Safari, Edge)
- Falls back to **IDBBatchAtomicVFS** for Safari incognito (no OPFS access)
- This is a TypeScript adapter, not Rust — it implements the `Storage` trait interface in TypeScript and communicates with the Rust WASM core via the binding layer

### PostgreSQL Is NOT First-Party for Client Storage

The client SDK does not need Postgres — SQLite covers all native platforms including server-side agents. Server-side deployments wanting Postgres can implement the 6-method trait trivially. PostgreSQL IS first-party for `BlobStore` (relay storage) — see section 17.7.

### FilesystemStorage

Maps keys to file paths: `{base_dir}/{key}` where `/` in keys maps to directory separators. Values are written atomically (write to temp file, rename). Useful for server-side deployments where inspectability matters (debugging, backup, migration). Not recommended for mobile or performance-sensitive use.

```
base_dir/
  context/
    {context_id}/
      state          # serialized ContextState
      membership/
        {did}        # serialized role string
      event/
        00000000000000000001  # serialized event
```

## 17.7 First-Party BlobStore Adapters (Relay/Server)

| Adapter | Backend | Good for | Ships in |
|---------|---------|----------|----------|
| `InMemoryBlobStore` | `HashMap` + secondary index | Testing, dev | Phase 1 (exists) |
| `SqliteBlobStore` | `rusqlite` | Personal relays, agent workstations, small deployments | Phase 2 |
| `RedbBlobStore` | redb (pure Rust B-tree DB) | Medium relays, embedded scenarios | Phase 2 |
| `PostgresBlobStore` | `sqlx` + PostgreSQL | Production/enterprise relays | Phase 5 |
| `S3BlobStore` | `aws-sdk-s3` (Apache-2.0) | Large-scale relays, cloud deployments | Phase 5 |

### Why redb

Pure Rust (no C/C++ dependency), stable on-disk format (v3), active maintenance, better write performance than SQLite for KV workloads. Fills the gap between SQLite (personal) and PostgreSQL (production). Replaces sled in all spec references — sled is in perpetual beta with an unstable on-disk format, violating the "no DOA decisions" tenet.

### Why S3-Compatible

One adapter covers the entire S3-compatible ecosystem: AWS S3, MinIO, Ceph, SeaweedFS, Garage, Cloudflare R2, Backblaze B2. Uses `aws-sdk-s3` (Apache-2.0 license). Documented as "S3-compatible object storage," not "AWS S3."

**S3 key layout:**

```
{bucket}/
  blobs/{blob_id_hex}                    # blob content
  routing/{routing_id_hex}/{blob_id_hex} # routing index (empty object, metadata has stored_at/expires_at)
  expiry/{expires_at}/{blob_id_hex}      # expiry index (for efficient TTL enforcement via prefix listing)
```

### SqliteBlobStore Schema

```sql
CREATE TABLE blobs (
    blob_id BLOB PRIMARY KEY,
    routing_id BLOB NOT NULL,
    recipient_hint BLOB,
    blob_ttl INTEGER NOT NULL,
    stored_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    blob BLOB NOT NULL
) WITHOUT ROWID;

CREATE INDEX idx_routing ON blobs (routing_id, stored_at);
CREATE INDEX idx_expiry ON blobs (expires_at);
```

### RedbBlobStore

Uses redb's native table API with two tables:

- `blobs: Table<&[u8; 32], &[u8]>` — blob_id -> serialized StoredBlob
- `routing: MultimapTable<&[u8; 32], &[u8; 32]>` — routing_id -> blob_id set

TTL enforcement via periodic scan of the blobs table (redb does not support secondary indexes natively; the routing multimap serves as the primary index for listing).

## 17.8 Platform-Specific Key Custody

Key custody is NOT part of this spec — it is the existing `KeyCustody` trait (ADR-006). Referenced here for completeness of the persistence picture:

| Platform | Key Storage | Key Types | Notes |
|----------|-------------|-----------|-------|
| iOS/macOS | Apple Keychain (generic password items) | Ed25519, X25519 (software-backed) | Secure Enclave only supports P-256; Ed25519 keys are software-backed in Keychain |
| Android | Android Keystore (TEE-backed, API 33+ for Ed25519) | Ed25519, X25519 | StrongBox available but dramatically slow — opt-in only |
| Browser | WebCrypto + IndexedDB (non-extractable CryptoKey) | Ed25519 (Chrome 113+, Firefox 130+, Safari 17+) | Ephemeral in incognito |
| Python/Node/Server | Software keys in SQLCipher-encrypted SQLite | Ed25519, X25519 | No hardware key store on typical servers |
| Testing | `InMemoryKeyCustody` | Ed25519, X25519 | Already defined (ADR-006) |

## 17.9 OpenMLS StorageProvider Bridge

OpenMLS requires a `StorageProvider` trait implementation for persisting MLS group state (tree nodes, key schedules, proposals, etc.). `MlsStorageBridge` wraps `ProtocolStore` and delegates to the `mls/{context_id}/...` key prefix.

```rust
/// scp-core/src/crypto/mls/storage.rs

pub struct MlsStorageBridge {
    store: Arc<ProtocolStore>,
    context_id: ContextId,
}

impl MlsStorageBridge {
    pub fn new(store: Arc<ProtocolStore>, context_id: ContextId) -> Self;
}

impl openmls_traits::storage::StorageProvider for MlsStorageBridge {
    // All methods delegate to self.store.storage with key prefix "mls/{context_id}/..."
    // OpenMLS key types are serialized via MessagePack before storage.
    // This is a mechanical mapping — no protocol logic.
}
```

**Key prefix mapping:** OpenMLS storage types map to sub-prefixes under `mls/{context_id}/`:

```
mls/{context_id}/group_state
mls/{context_id}/tree/{leaf_index}
mls/{context_id}/key_schedule/{epoch}
mls/{context_id}/proposal/{hash}
mls/{context_id}/key_package/{hash}
mls/{context_id}/encryption_key/{epoch}/{generation}
```

The exact sub-prefix structure follows OpenMLS's `StorageProvider` method signatures. The bridge is a thin translation layer — it adds no behavior beyond key construction and serialization.

## 17.10 Migration Strategy

**Lazy on-read migration.** `ProtocolStore` checks the version envelope on every read:

- `version == current` -> deserialize directly
- `version < current` -> apply migration chain, write back upgraded value
- `version > current` -> return `StoreError::IncompatibleVersion` (newer SCP version wrote this data)

```rust
/// scp-core/src/store/mod.rs

pub trait Migratable: Sized + Serialize + DeserializeOwned {
    /// Current version number for this type.
    const CURRENT_VERSION: u16;

    /// Migrate from `old_version` data bytes to current version.
    /// Returns None if migration from this version is not supported.
    fn migrate(old_version: u16, data: &[u8]) -> Option<Self>;
}
```

**Migration functions are pure.** No I/O, no side effects, independently testable. Each migration step transforms bytes from version N to version N+1. The chain is applied iteratively until reaching `CURRENT_VERSION`.

**Key-space migrations** (changing the key convention itself) are rare and handled differently. On startup, `ProtocolStore` checks a `_meta/schema_version` key. If the key-space version is behind, a one-time startup migration runs before normal operation. Key-space migrations are the only blocking startup operation.

**No downgrade support.** Once data is migrated forward, it cannot be read by older SCP versions. This is intentional — downgrade paths create combinatorial testing requirements and invite data corruption. Users who need to roll back must restore from backup.

## 17.11 Extension Points

### Custom Storage Adapters

Implement the 6 async methods of the `Storage` trait. Run the `storage_conformance!()` macro against your implementation. If all tests pass, the adapter is correct.

```rust
#[cfg(test)]
storage_conformance!(|| MyCustomStorage::new());
```

The conformance suite tests: store/retrieve roundtrip, missing key returns None, delete removes, list_keys with prefix filtering, list_keys returns sorted results, delete_prefix removes all matching keys, exists returns true/false correctly, and concurrent access safety.

### Custom BlobStore Adapters

Implement the 5 async methods of the `BlobStore` trait. Run the `blob_store_conformance!()` macro.

```rust
#[cfg(test)]
blob_store_conformance!(|| MyCustomBlobStore::new(clock.clone()));
```

The conformance suite tests: store/retrieve roundtrip, missing blob returns None, TTL expiry, list by routing_id in stored_at order, list with since filter, delete removes blob, store returns SHA-256 blob_id, and concurrent store + expire safety.

## 17.12 Third-Party Adapter Candidates

The following are explicitly named as "build your own" — not first-party, but viable for specific use cases:

| Technology | Trait | Notes |
|------------|-------|-------|
| RocksDB | `BlobStore` | Best for extremely write-heavy relays. C++ dependency, heavy binary. |
| LMDB (heed/heed3) | `Storage` or `BlobStore` | Best read performance. heed3 has encryption-at-rest. C dependency. |
| MySQL/MariaDB | `BlobStore` | One sqlx feature flag away from the PostgreSQL adapter. |
| Valkey (Redis fork, BSD-3) | -- | Cache layer in front of persistent BlobStore. Not a direct adapter. |

**Explicitly excluded:** sled (perpetual beta, unstable on-disk format), LevelDB (superseded by RocksDB), FoundationDB/TiKV (cluster-only, too heavy for protocol-level storage), DuckDB (OLAP, wrong use case), Redis (non-OSI license since 2024 — use Valkey instead).

## 17.13 Conformance Testing

### Storage Conformance Extensions

The `storage_conformance!()` macro (section 16.12.2) is extended with tests for the two new methods and the ordering guarantee:

```rust
// Added to storage_conformance!() in scp-testing/src/conformance/storage.rs

#[tokio::test]
async fn delete_prefix_removes_matching() {
    // Store "ctx/a/1", "ctx/a/2", "ctx/b/1", "other/x".
    // delete_prefix("ctx/a/") -> returns 2.
    // Verify "ctx/a/1" and "ctx/a/2" are gone.
    // Verify "ctx/b/1" and "other/x" still exist.
}

#[tokio::test]
async fn delete_prefix_returns_zero_for_no_match() {
    // delete_prefix("nonexistent/") -> returns 0.
}

#[tokio::test]
async fn exists_returns_true_for_stored() {
    // Store "key", exists("key") -> true.
}

#[tokio::test]
async fn exists_returns_false_for_missing() {
    // exists("missing") -> false.
}

#[tokio::test]
async fn exists_returns_false_after_delete() {
    // Store "key", delete "key", exists("key") -> false.
}

#[tokio::test]
async fn list_keys_returns_sorted() {
    // Store keys "c", "a", "b".
    // list_keys("") -> ["a", "b", "c"].
}

#[tokio::test]
async fn list_keys_prefix_returns_sorted() {
    // Store "ctx/z", "ctx/a", "ctx/m", "other/x".
    // list_keys("ctx/") -> ["ctx/a", "ctx/m", "ctx/z"].
}
```

### ProtocolStore Integration Tests

These test the protocol layer's use of storage, not the storage adapters themselves. They run against `InMemoryStorage` (fast, deterministic) and should also be run against `SqliteStorage` as a secondary gate.

| Test | Verifies |
|------|----------|
| `context_lifecycle_persists` | Create context, store state, reload from storage, verify state matches |
| `context_delete_removes_all` | Create context with members, events, tools. `delete_context` removes everything. Verify no keys with context prefix remain. |
| `event_log_range_query` | Append 100 events, load range 50-75, verify correct events in order |
| `nonce_replay_rejected` | Record nonce, attempt same nonce again, verify rejection |
| `nonce_pruning` | Record nonce with short expiry, advance time, prune, verify nonce is gone |
| `membership_roundtrip` | Store membership, load, verify role matches |
| `sender_key_roundtrip` | Store sender key, load, verify key matches |
| `did_cache_roundtrip` | Cache DID document, load, verify matches |
| `relay_score_list` | Store scores for 3 relays, list all, verify all returned |

## 17.14 Phase Integration

### Phase 1

- `InMemoryStorage` implements all 6 `Storage` methods including `delete_prefix` and `exists`
- Skeleton `ProtocolStore` with context state, membership, and nonce methods
- `MlsStorageBridge` skeleton (OpenMLS `StorageProvider` implementation)
- `storage_conformance!()` macro covers all 6 methods, ordering, and concurrency
- `InMemoryStorage` passes full conformance suite

### Phase 2

- Full `ProtocolStore` with all domain methods
- `SqliteStorage` (bundled-sqlcipher, WAL mode)
- `FilesystemStorage`
- `SqliteBlobStore` for relay storage
- `RedbBlobStore` for relay storage
- ADR-008 context lifecycle uses `ProtocolStore` for state persistence
- ADR-011 event log uses `ProtocolStore` for Merkle tree persistence
- All new adapters pass their respective conformance suites

### Phase 3

- Python SDK uses `ProtocolStore` via FFI (SQLite default, auto-configured)
- Python `Storage` adapter configuration via `scp.Config`

### Phase 4

- `WasmSqliteStorage` (wa-sqlite + OPFSCoopSyncVFS, IDBBatchAtomicVFS fallback) for browser
- TypeScript SDK storage configuration

### Phase 5

- `PostgresBlobStore` (sqlx + PostgreSQL) for production relays
- `S3BlobStore` (aws-sdk-s3) for large-scale relays
- Platform-specific encryption configuration:
  - iOS: `NSFileProtectionCompleteUntilFirstUserAuthentication`
  - Android: TEE-backed key derivation for SQLCipher

### Phase 6

- Event log pruning and checkpointing (compact old events behind Merkle root)
- Performance optimization: batch writes, connection pooling
- `ProtocolStore` profiling and hot-path optimization
