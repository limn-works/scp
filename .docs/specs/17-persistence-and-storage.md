# 17. Persistence and Storage

## 17.1 Storage Architecture Overview

SCP has two independent persistence surfaces: client-side storage for SDK state and relay-side storage for encrypted message blobs. These serve different roles, different operators, and different access patterns. They share no trait, no backend, and no coupling.

### Client SDK Storage Stack

```
Protocol Engine (structured domain operations)
        |
ProtocolRepository (key conventions + serde serialization)
        |
Storage trait (flat KV: store/retrieve/delete/list_keys/delete_prefix/exists)
        |
Backend adapter (SQLite, wa-sqlite, filesystem, in-memory)
```

The `Storage` trait (defined in `scp-platform`) is deliberately thin — six async methods operating on `(key: &str, data: &[u8])` pairs. All structured protocol operations (context state, membership, event logs, nonces, caches) are mapped to flat KV operations by `ProtocolRepository` in `scp-core`. Adapter authors implement six methods. The protocol layer handles all domain logic and is tested once.

### Relay Storage Stack

```
Relay Server (blob routing, TTL enforcement, subscription registry)
        |
BlobStorage trait (store/get/query/delete/purge_expired with routing_id + TTL)
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

## 17.2 Storage Trait

The `Storage` trait (ADR-006, `scp-platform/src/traits.rs`) provides six async methods operating on `(key: &str, data: &[u8])` pairs:

```rust
pub trait Storage: Send + Sync {
    /// Store a byte slice under the given key. Overwrites any existing value.
    async fn store(&self, key: &str, data: &[u8]) -> Result<(), PlatformError>;

    /// Retrieve the byte slice stored under the given key. Returns None if absent.
    async fn retrieve(&self, key: &str) -> Result<Option<Vec<u8>>, PlatformError>;

    /// Delete the value stored under the given key. No-op if absent.
    async fn delete(&self, key: &str) -> Result<(), PlatformError>;

    /// List all keys matching a prefix, in lexicographic order.
    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, PlatformError>;

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
_meta/schema_version
scp/identity

identity/{did}/document
identity/{did}/active_signing_key
identity/{did}/agent_signing_key
identity/{did}/private_state/{seq:020d}
identity/{did}/block_list_events
identity/{did}/adapter_credentials/{adapter_id}

context/{context_id}/state
context/{context_id}/params
context/{context_id}/full_snapshot
context/{context_id}/membership/{did}
context/{context_id}/sender_key/{did}
context/{context_id}/role/{role_name}
context/{context_id}/nonce/{nonce_hash}
context/{context_id}/nonce/_last_prune
context/{context_id}/event/{seq:020d}
context/{context_id}/event_data/{seq:020d}
context/{context_id}/event_meta/count
context/{context_id}/event_meta/root
context/{context_id}/event_tree/{level}/{index}
context/{context_id}/merkle_event_log/{seq:020d}
context/{context_id}/tool/{tool_id}
context/{context_id}/tool_session/{session_id}
context/{context_id}/ucan_token/{token_id}
context/{context_id}/ucan_revocation/{token_id}
context/{context_id}/broadcast_state
context/{context_id}/broadcast_block/{author_did}
context/{context_id}/ephemeral_metadata

context/{context_id}/governance/config
context/{context_id}/governance/proposal/{proposal_id_hex}
context/{context_id}/governance/proposal_index/pending
context/{context_id}/governance/proposal_index/resolved
context/{context_id}/governance/deadlock_state

context/{context_id}/access_key/{did_hex}
context/{context_id}/access_key/{did_hex}/epoch

context/{context_id}/economic_policy
context/{context_id}/payment_receipt/{receipt_id}
context/{context_id}/spending_ucan/{token_id}

wrapping_key/{context_id}/{did}/public
wrapping_key/{context_id}/{did}/secret

did_cache/{did}
tofu/{did}
key_package/{sha256_hex(relay_url)}/{index}
relay_score/{sha256_hex(relay_url)}
cert_pin/{sha256_hex(relay_url)}

tls/certificate_chain
tls/private_key

mls/{context_id}/...
```

**Identity bootstrap key.** The `scp/identity` key stores a `StoredValue<PersistedIdentity>` containing the node's `ScpIdentity` and `DidDocument`. This is a top-level singleton key (no entity ID) because it is read during identity bootstrap before any DID is known. Written via the `Storage` trait directly, not through `ProtocolRepository` domain methods (see §17.4 for the exception rationale).

**Zero-padded sequences.** Event sequence numbers and private state sequence numbers use `:020d` formatting (20-digit zero-padded decimal). This ensures lexicographic ordering matches numeric ordering, enabling efficient range queries via `list_keys`. Example: event 42 is stored at `context/{id}/event/00000000000000000042`.

**Event data payloads.** The `event/{seq:020d}` key stores only the 32-byte SHA-256 leaf hash for Merkle tree verification. The `event_data/{seq:020d}` key stores the full MessagePack-serialized `Event` struct (event type, actor DID, timestamp, sequence, payload, prev_hash, signature). This dual-key design preserves the compact Merkle tree structure while enabling event replay and query without transport-layer round-trips. Events persisted before the `event_data/` key convention was introduced will have hash-only entries; `load_event_data` returns `None` for these (backward compatible).

**Merkle event log entries.** Each `EventLogEntry` is stored individually under `merkle_event_log/{seq:020d}` (MessagePack-serialized), matching the per-event key pattern used by `event/{seq:020d}`. This enables O(1) append persistence — only the new entry is written, rather than re-serializing the entire list. Restore loads all entries by `list_keys("context/{id}/merkle_event_log/")` prefix scan, which returns keys in lexicographic (= sequence) order. Prune deletes removed entries by prefix and rewrites the retained entries with renumbered sequence keys starting from 0. After pruning, the first entry's `prev_hash` references a discarded predecessor — chain verification must accept any `prev_hash` for the first entry. See §9.9, #636, #710.

**Nonce keys.** UCAN nonce replay prevention uses `context/{context_id}/nonce/{SHA256(nonce_string)}` — the nonce string is hashed to a fixed-length key. The value stores `(first_seen_timestamp, token_expiry_timestamp)` for pruning. The `exists()` method enables O(1) replay checks without deserializing.

**Nonce pruning.** Expired nonces (where `token_expiry < now`) must be cleaned up to prevent unbounded growth. Pruning is triggered in two places:

1. **At startup.** `restore_all_contexts` calls `prune_expired_nonces` for each restored context, clearing the backlog accumulated during the previous process lifetime.
2. **Time-gated inline.** `check_and_record_nonce` tracks the last prune time per context via a storage key (`context/{context_id}/nonce/_last_prune`). If more than 1 hour has elapsed since the last prune, a full prune pass runs before the nonce check. This adds one extra storage read per nonce check (the last-prune timestamp), which is negligible relative to the two reads and one write the nonce check already performs. The expensive full scan only runs hourly.

The in-memory `NonceTracker` remains the primary, synchronised replay defense on the hot path. `ProtocolRepository` nonce tracking is defense-in-depth for crash recovery. The time-gated prune ensures the persistent nonce store does not grow without bound even in long-running processes that never restart.

**Context cleanup.** When a context is closed or expired, `delete_prefix("context/{context_id}/")` removes all context state atomically. No enumeration required.

## 17.4 ProtocolRepository

`ProtocolRepository` is a concrete generic struct in `scp-core/store/` that wraps a `Storage` implementation and provides typed domain methods. These are NOT trait methods — adapters do not implement them. `ProtocolRepository` is the primary interface between protocol logic and persistent storage, with two documented exceptions (see below). The type parameter `S` is the concrete storage backend. The `Storage` trait uses RPITIT (return-position `impl Trait` in traits) and is not dyn-compatible, so `ProtocolRepository` is generic rather than using `Arc<dyn Storage>`.

```rust
/// scp-core/src/store/mod.rs

pub struct ProtocolRepository<S: Storage> {
    storage: S,
}

/// Production constructor — requires EncryptedStorage (sealed marker trait).
/// Only storage backends that encrypt at rest satisfy this bound.
impl<S: EncryptedStorage> ProtocolRepository<S> {
    pub fn new(storage: S) -> Self;
}

/// Testing constructor — accepts any Storage without encryption.
/// Available under #[cfg(test)] and behind the `allow_unencrypted_storage`
/// feature flag. Production code must use `new()` with an EncryptedStorage
/// backend (e.g., SqliteStorage, EncryptingAdapter<InMemoryStorage>).
#[cfg(any(test, feature = "allow_unencrypted_storage"))]
impl<S: Storage> ProtocolRepository<S> {
    pub fn new_for_testing(storage: S) -> Self;
}

impl<S: Storage> ProtocolRepository<S> {
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

    // --- Merkle event log entries (§9.9, #636, #710) ---
    pub async fn store_merkle_event_log_entry(&self, context_id: &str, seq: usize, entry: &EventLogEntry) -> Result<(), StoreError>;
    pub async fn store_merkle_event_log_entries(&self, context_id: &str, entries: &[EventLogEntry]) -> Result<(), StoreError>;
    pub async fn load_merkle_event_log_entries(&self, context_id: &str) -> Result<Option<Vec<EventLogEntry>>, StoreError>;
    pub async fn delete_merkle_event_log_entries(&self, context_id: &str) -> Result<(), StoreError>;

    // --- DID cache ---
    pub async fn cache_did_document(&self, did: &DID, doc: &[u8], expires_at: u64) -> Result<(), StoreError>;
    // `now` parameter enables testable expiry checks without hidden clock dependencies.
    pub async fn load_cached_did_document(&self, did: &DID, now: u64) -> Result<Option<Vec<u8>>, StoreError>;

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

    // --- Economic governance (§19) ---
    pub async fn store_economic_policy(&self, context_id: &ContextId, policy: &[u8]) -> Result<(), StoreError>;
    pub async fn load_economic_policy(&self, context_id: &ContextId) -> Result<Option<Vec<u8>>, StoreError>;
    pub async fn store_payment_receipt(&self, context_id: &ContextId, receipt_id: &[u8; 32], receipt: &[u8]) -> Result<(), StoreError>;
    pub async fn load_payment_receipt(&self, context_id: &ContextId, receipt_id: &[u8; 32]) -> Result<Option<Vec<u8>>, StoreError>;
    pub async fn list_payment_receipts(&self, context_id: &ContextId) -> Result<Vec<[u8; 32]>, StoreError>;
    pub async fn store_spending_ucan(&self, context_id: &ContextId, token_id: &str, ucan: &[u8]) -> Result<(), StoreError>;
    pub async fn load_spending_ucan(&self, context_id: &ContextId, token_id: &str) -> Result<Option<Vec<u8>>, StoreError>;
    pub async fn list_spending_ucans(&self, context_id: &ContextId) -> Result<Vec<String>, StoreError>;

    // --- Adapter credentials (identity-private, §19.2.5) ---
    pub async fn store_adapter_credentials(&self, did: &DID, adapter_id: &str, credentials: &[u8]) -> Result<(), StoreError>;
    pub async fn load_adapter_credentials(&self, did: &DID, adapter_id: &str) -> Result<Option<Vec<u8>>, StoreError>;
    pub async fn list_adapter_credentials(&self, did: &DID) -> Result<Vec<String>, StoreError>;

    // --- TLS certificates (§18.6.3) ---
    pub async fn store_tls_certificate(&self, certificate_chain_pem: &str, private_key_pem: &str) -> Result<(), StoreError>;
    pub async fn load_tls_certificate(&self) -> Result<Option<(String, Zeroizing<String>)>, StoreError>;
    pub async fn delete_tls_certificate(&self) -> Result<(), StoreError>;
}
```

Every `ProtocolRepository` method translates to one or two `Storage` trait calls using the key convention from section 17.3. There is no query optimizer, no batch API, no transaction boundary beyond what `delete_prefix` provides. If performance profiling reveals hot paths, batch writes can be added to `Storage` as an optional method with a default implementation that loops (Phase 6).

**Exceptions to `ProtocolRepository` as the single interface.** Two subsystems access `Storage` directly rather than through `ProtocolRepository` domain methods:

1. **MLS bridge (§17.9).** `MlsStorageBridge` accesses raw `Storage` because OpenMLS owns the storage contract and the `StorageProvider` trait dictates serialization format. Wrapping values in `StoredValue` envelopes would break OpenMLS deserialization on read-back.

2. **Identity bootstrap persistence.** `ApplicationNode` reads/writes the `scp/identity` key via `Storage` directly because identity bootstrap is a pre-DID operation — the identity must be loaded before any DID is known, before contexts exist, and before `ProtocolRepository` domain methods can be used (since they are keyed by DID or context_id). This is infrastructure-level metadata, not protocol state. The value is still wrapped in a `StoredValue` version envelope and serialized with MessagePack, consistent with §17.5.

### Module Structure

```
scp-core/src/store/
    mod.rs          # ProtocolRepository struct, StoreError type, re-exports
    context.rs      # Context state, params, membership, sender keys
    event_log.rs    # Event log persistence, tree nodes, roots
    identity.rs     # Identity documents, private state, TOFU, DID cache
    nonce.rs        # UCAN nonce tracking, pruning
    tls.rs          # TLS certificate chain + private key (§18.6.3)
    tools.rs        # Tool registration, sessions
    transport.rs    # Relay scores, key packages
    economy.rs      # Economic policy, payment receipts, spending UCANs, adapter credentials
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

Every value written by `ProtocolRepository` is wrapped in `StoredValue`. On read, `version` is checked before deserializing `data`. This enables lazy migration (section 17.10) without requiring schema-level versioning in the storage backend.

**Context export integrity (signed snapshot).** A portable `ContextExport` (the serialized form produced for backup, migration, or device transfer) carries TWO independent integrity protections, both verified on import before any state is restored:

1. **Event-log Merkle chain** — the serialized event-log entries are hash-chained and the export records the Merkle root; import recomputes and compares it (tamper detection on the event history).
2. **Signed snapshot** — the *entire* embedded context snapshot is bound by an Ed25519 `snapshot_signature`, computed and verified **exactly as specified in §23.16.8 (Signed Context Export)**: Ed25519 over `SHA-256("SCP-CONTEXT-EXPORT-V1:" || scope-tag-byte || JCS(ContextSnapshot))`, where `scope-tag-byte` is the single export-scope discriminant (`0x00` for `Full`, `0x01` for `Public`) placed immediately after the domain separator and before the JCS bytes, and `JCS` is the RFC 8785 canonical-JSON serialization of the whole snapshot. Binding the scope byte into the preimage means a tampered envelope `scope` field fails signature verification by construction (§23.16.8, ADR-050). The export domain separator `"SCP-CONTEXT-EXPORT-V1:"` is deliberately distinct from the §23.16.4 sync-delta separator `"SCP-CONTEXT-SNAPSHOT-V1:"` so that an export signature can never be confused with a sync-delta signature under the same creator key (§9.18.2). The signature is produced by the snapshot's `creator_did` `#active`/`#agent` custody key (ADR-039); on import the verifying key is resolved from `creator_did`, the envelope's `exporter_did` MUST equal `creator_did`, and the signature MUST verify before any state is restored. The signature covers every trusted field the importer restores verbatim — role ceilings, member/suspended capabilities, role assignments, threshold signers and value, governance model configuration, economic policy, consequence rules, read-exclusion list, access-key store, pending ceiling modification, and tool registrations — not only membership and parameters. A subset hash (such as the §23.16.4 sync-delta recipe) would leave those fields forgeable and MUST NOT be used for export. Per-instance anti-abuse and accounting state carried in the snapshot is signed but intentionally wiped or sanitized on import (§23.16.8).

The export format `version` is incremented when this integrity envelope changes (the scope-bound full-snapshot signed construction is native export `version` 4); imports reject any version that is not the current signed format with a dedicated *version* error surfaced as `SCP-CTX-2094`, which is distinct from a signature-verification failure (`SCP-CTX-2093`). See §23.16.8 for the canonical construction and the importer's normative verification and authorization requirements, and §23.17 for the sequence-floor invariants that imports must additionally enforce.

**Encryption at rest** is a platform concern enforced at compile time by the sealed `EncryptedStorage` marker trait.

### EncryptedStorage — Compile-Time Encryption Enforcement

`EncryptedStorage` (defined in `scp-platform/src/encrypted.rs`) is a sealed marker trait — only implementable inside the `scp-platform` crate. External crates can see and require the trait but cannot implement it for their own types. This prevents unencrypted backends from satisfying the bound.

```rust
/// scp-platform/src/encrypted.rs

pub(crate) mod private {
    pub trait Sealed {}
}

pub trait EncryptedStorage: Storage + private::Sealed {}
```

The seal mechanism uses a `pub(crate)` supertrait (`Sealed`) that external code cannot access. Any attempt to implement `EncryptedStorage` outside `scp-platform` fails at compile time. This ensures the encryption invariant is enforced by the type system, not by documentation or convention.

**Production constructors require `EncryptedStorage`.** `ProtocolRepository::new()` is bounded on `EncryptedStorage` (see §17.4). The testing constructor `ProtocolRepository::new_for_testing()` accepts any `Storage` but is gated behind `#[cfg(test)]` and the `allow_unencrypted_storage` feature flag, preventing accidental use in production builds.

**Implementations:**

| Type | Mechanism | Notes |
|------|-----------|-------|
| `SqliteStorage` | Direct impl | SQLCipher provides full-database AES-256 encryption |
| `AppleStorage` | Direct impl | iOS/macOS SQLCipher with Keychain-managed keys |
| `EncryptingAdapter<S>` | Wraps any `Storage` | Per-value AES-256-GCM — for backends without native encryption |
| `Arc<T: EncryptedStorage>` | Blanket impl | Enables shared ownership via `Arc` |

### EncryptingAdapter — Per-Value AES-256-GCM Wrapper

`EncryptingAdapter<S: Storage>` (defined in `scp-platform/src/encrypting_adapter.rs`) wraps any `Storage` implementation with per-value AES-256-GCM encryption, making it satisfy the sealed `EncryptedStorage` bound without requiring the inner backend to encrypt natively.

**Key management:** The adapter is initialized with a 32-byte AES-256 key wrapped in `Zeroizing<[u8; 32]>` (cleared on drop). For ephemeral/FFI usage, the key is generated via `OsRng`. For persistent usage, the key should be derived from identity key material (see §17.6 SQLCipher key derivation).

**Wire format:** Each stored value is:

```
nonce (12 bytes) || ciphertext || tag (16 bytes)
```

- **Nonce:** 12-byte random nonce generated via `OsRng` for each `store()` call (96-bit, AES-256-GCM standard).
- **AAD (Additional Authenticated Data):** The storage key string (UTF-8 bytes). This binds each encrypted value to its key path, preventing relocation attacks (moving a ciphertext from one key to another causes decryption failure).
- **Tag:** 128-bit GCM authentication tag, appended after the ciphertext.

**Key names are NOT encrypted** — they pass through to the inner backend unmodified. The `ProtocolRepository` key convention is deterministic and not secret. Only values are encrypted.

**Usage pattern (matching `scp-node` ephemeral mode):**

```rust
use scp_platform::encrypting_adapter::EncryptingAdapter;
use scp_platform::testing::InMemoryStorage;
use zeroize::Zeroizing;

let mut key = Zeroizing::new([0u8; 32]);
OsRng.fill_bytes(&mut *key);
let encrypted = EncryptingAdapter::new(InMemoryStorage::new(), key);
// `encrypted` implements EncryptedStorage — pass to ProtocolRepository::new().
```

### `allow_unencrypted_storage` Feature Gate

The `allow_unencrypted_storage` feature flag in `scp-core` exposes `ProtocolRepository::new_for_testing()`, which accepts any `Storage` without the `EncryptedStorage` bound. This is intended for:

- **Unit tests** (`#[cfg(test)]`) — crate-internal tests get it automatically.
- **Integration test crates** — enable the feature flag in `[dev-dependencies]`.
- **CI** — test harnesses that need raw `InMemoryStorage` without encryption overhead.

Production code (FFI bridges, application nodes, SDK wrappers) must NOT enable this feature. If a production backend does not natively encrypt, wrap it in `EncryptingAdapter` instead.

The `Storage` trait operates on opaque bytes. Platform-specific encryption happens below:

| Platform | Mechanism | Notes |
|----------|-----------|-------|
| Native (iOS, Android, macOS, Linux, Windows, Python, Node) | `rusqlite` with `bundled-sqlcipher` feature | AES-256 encryption, PBKDF2 with SHA-512 key derivation (256K iterations). Encryption key derived from identity key material stored in platform key custody (Keychain/Keystore). |
| Browser (WASM) | Value-level AES-256-GCM encryption | SQLCipher unavailable in WASM. Each value is encrypted individually before writing to wa-sqlite. Key derivation: the identity's `#0` key is imported into WebCrypto as raw key material, then `HKDF` is used with `salt = SHA-256("SCP-WASM-STORAGE-V1")`, `info = "scp-wasm-storage:" || did` (UTF-8), `hash = SHA-256`, `derivedKeyLength = 256` to produce an AES-256-GCM key. Per-value encryption: 12-byte nonce generated via `crypto.getRandomValues()` for each `store()` call. Stored format: `nonce (12 bytes) \|\| ciphertext \|\| tag (16 bytes)`. The key is stored in memory only (non-extractable WebCrypto key object). AAD (additional authenticated data): the storage key string (UTF-8 bytes), binding each encrypted value to its key path to prevent value relocation attacks. |
| iOS | `NSFileProtectionCompleteUntilFirstUserAuthentication` | Allows background processing while device is locked. Applied to the SQLite database file. |
| Android | TEE-backed key for SQLCipher key derivation | Android Keystore generates the key; SQLCipher uses it for database encryption. StrongBox opt-in only (dramatically slow). |

## 17.6 First-Party Storage Adapters (Client SDK)

| Adapter | Backend | Platform | Good for | Ships in |
|---------|---------|----------|----------|----------|
| `InMemoryStorage` | `HashMap<String, Vec<u8>>` + `RwLock` | All | Testing, CI, short-lived agents | Phase 1 (update for new methods) |
| `SqliteStorage` | `rusqlite` + `bundled-sqlcipher`, WAL mode | Native (all) | **Default production backend** — universal | Phase 2 |
| `FilesystemStorage` | Key -> file path | POSIX systems | Server/CLI, inspectable/debuggable storage | Phase 2 |
| `WasmSqliteStorage` | wa-sqlite (TypeScript) | Browser WASM | Browser default | Phase 4 |

### In-Memory Storage Is Dev/Test-Only

In-memory storage — `InMemoryStorage`, the FFI-layer `BridgeInMemoryStorage`, and `EncryptingAdapter<InMemoryStorage>` — is a development and test affordance only. It MUST NOT be used as a production system-of-record.

In-memory storage loses all state on process restart. For SCP, that state includes MLS group state, identity keys, the event log, and provenance records. Losing it on restart contradicts the durability and provenance tenets directly: a restarted node would silently lose its cryptographic membership, its append-only audit trail, and its identity. Production deployments MUST use a durable, encrypted backend — `SqliteStorage` (SQLCipher) is the default.

### Storage Selection Is Mandatory

Storage selection is mandatory. Constructing an `SCP` without an explicit storage choice is an error (`SCP-STORAGE-8000`); there is no default. The two choices are `{type: in_memory}` (development) and `{type: sqlite, ...}` (production). Bridges that can express this requirement at compile time (e.g. the typed UniFFI `StorageConfig` constructor, the required Swift/Kotlin/TypeScript constructor argument) MUST do so; bridges that cannot (the dynamically-typed PyO3 dict, the JSON-string NAPI factory) MUST reject a missing selection at runtime with `SCP-STORAGE-8000`. No bridge or SDK may expose a zero-argument constructor that silently selects a storage backend on the caller's behalf.

### Storage Selection Fails Closed

When a caller selects a durable storage backend (e.g. `Sqlite`) and the backend cannot be opened — bad path, insufficient permissions, corruption, or a wrong key/passphrase — the bridge or builder layer MUST return an error. Silent fallback to in-memory storage, or to no storage at all, is FORBIDDEN.

In-memory storage is reachable only through an explicit in-memory selection (`{type: "in_memory"}`). It MUST NOT be reachable as a degradation path from a failed durable-backend open. A failed durable open is a terminal error the caller observes, not a condition the system silently recovers from by downgrading durability.

### The Runtime Never Defaults Storage

The runtime core (`scp-runtime`) MUST NOT manufacture or default a storage backend. Storage is supplied by the caller at the bridge or builder layer and threaded into the supervisor as a required (non-optional) parameter. This requirement is enforced by the type system — the supervisor construction surface takes storage as a non-`Option` argument, so there is no code path by which the runtime can run without a caller-supplied backend. The choice of backend (durable vs. in-memory) is made once, at the bridge/builder layer, never silently inside the runtime.

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

**SQLCipher key derivation.** The SQLCipher encryption key is derived from identity key material using HKDF-SHA-256 (RFC 5869), NOT used directly as a signing key:

```
ikm  = identity_key_private_bytes          // 32 bytes, #0 Identity Key from platform key custody
salt = SHA-256("SCP-SQLCIPHER-KEY-V1")     // fixed salt, 32 bytes
info = "scp-sqlcipher:" || did             // DID as UTF-8 bytes — binds key to specific identity
prk  = HKDF-Extract(salt, ikm)            // 32 bytes
okm  = HKDF-Expand(prk, info, 32)         // 32 bytes — SQLCipher PRAGMA key
derived_key = hex_encode(okm)             // 64 hex characters, passed via raw-key syntax (x'..')
```

The `ikm` is the raw private key bytes of the `#0` Identity Key, retrieved from platform key custody (iOS Keychain, Android Keystore, macOS Keychain, or OS keyring). The HKDF domain separation (`"SCP-SQLCIPHER-KEY-V1"`) ensures the derived key is distinct from any signing key, preventing cross-protocol attacks. The DID in the `info` parameter binds the database to a specific identity — databases for different identities on the same device use different encryption keys.

This HKDF-from-identity-key derivation is the **raw-key mode**: the caller supplies 32 bytes of key material (the `#0` identity key bytes) and the SQLCipher PRAGMA key is derived deterministically from them. Raw-key mode is the default and is unchanged by the passphrase mode defined below.

#### Passphrase Key-Derivation Mode

Some SDK callers supply a human-chosen passphrase rather than raw key material (for example, a CLI or desktop deployment with no platform key custody and no `#0` identity key available at database-open time). For these callers, the SQLCipher PRAGMA key MAY instead be derived from a passphrase using **Argon2id**. The caller selects exactly one derivation mode: raw-key (above) or passphrase. The two modes are mutually exclusive — supplying both is a validation error.

Passphrase derivation MUST use the following parameters, which are NORMATIVE and MUST be identical to the platform key-custody Argon2id parameters (§17.8, `FileKeyCustody`):

```
algorithm  = Argon2id
version    = 0x13                              // Argon2 v1.3
m_cost     = 65536                             // 65536 KiB = 64 MiB memory
t_cost     = 3                                 // 3 iterations
p_cost     = 1                                 // parallelism = 1
output_len = 32                                // 32-byte derived key
input      = passphrase (UTF-8 bytes)
salt       = per-database 16-byte salt         // see Salt Persistence below
derived_key = hex_encode(argon2id(...))        // 64 hex characters, passed via raw-key syntax (x'..')
```

A single Argon2id parameterization across the entire codebase is REQUIRED. The passphrase-mode SQLCipher key derivation and the `FileKeyCustody` passphrase-to-wrapping-key derivation MUST share one parameter source; implementations MUST NOT define a second, divergent Argon2id parameter set. The derived 32-byte key feeds the same SQLCipher PRAGMA-key path as raw-key mode (identical `cipher_page_size`, `kdf_iter`, HMAC, and KDF PRAGMAs below).

The passphrase and every intermediate buffer carrying it (and the derived key) MUST be held in zeroizing memory and cleared on drop.

#### Salt Persistence

The Argon2id salt is per-database and persisted, because passphrase derivation MUST be deterministic across process restarts — the same passphrase MUST re-derive the same key, or the database becomes permanently unreadable.

- The salt is generated **once** — 16 bytes from a cryptographically secure RNG — when the database directory is first initialized.
- The salt is persisted to a sidecar file `{dir}/scp.salt`, located **outside** the encrypted `{dir}/scp.db`. The salt is required to derive the key that decrypts the database, so it MUST NOT live inside the encrypted database (that would be a bootstrap deadlock).
- The salt file MUST be written atomically (write to a temporary file, then rename).
- On reopen, the existing `{dir}/scp.salt` is read so the same passphrase deterministically re-derives the same key.

A salt is not secret — it is integrity-relevant only. Its presence and length, however, are load-bearing, so the following conditions MUST fail closed (return an error; the system MUST NOT proceed):

- A missing `{dir}/scp.salt` beside an existing `{dir}/scp.db`. The system MUST NOT regenerate the salt: a fresh salt would derive a different key and permanently brick the existing database.
- A `{dir}/scp.salt` of the wrong length (not 16 bytes).
- A wrong passphrase. SQLCipher rejects the derived key on the first query against the database; the system MUST surface this as a fail-closed error and MUST NOT silently create or open a fresh, empty database.

Only the first-initialization case — no `scp.db` and no `scp.salt` — generates and writes a new salt.

**SQLCipher configuration:**

```rust
// Applied on connection open.
// `derived_key` is the 64-hex-character encoding of the 32-byte derived key
// (raw-key or passphrase mode). It MUST be supplied using SQLCipher's raw-key
// syntax `x'<derived_key>'` (note: `x'..'` inside the SQL string literal), which
// tells SQLCipher to interpret the value as raw key bytes. Plain-quote syntax
// (`'<derived_key>'`) would instead treat the 64 hex characters as a passphrase
// and PBKDF2-stretch them — a redundant second KDF over already-derived key
// material. Raw-key syntax avoids that double-KDF.
conn.execute_batch("
    PRAGMA key = \"x'<derived_key>'\";
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

### 17.7.1 Streaming API

The `BlobStorage` trait provides streaming variants of `store` and `get` for backends that can avoid full in-memory materialization. All streaming methods have default implementations that delegate to their `Vec<u8>` counterparts, so existing adapters work without modification.

**Types:**

- `BlobMetadata` — all `StoredBlob` fields except `blob: Vec<u8>`, plus an optional `content_length: Option<u64>`. Returned by streaming get so metadata is available before the body stream is consumed.
- `BlobBodyStream` — `Pin<Box<dyn Stream<Item = Result<Bytes, StorageError>> + Send>>`. The body of a blob as a stream of chunks.

**Trait methods (with defaults):**

- `store_streaming(routing_id, blob_id, recipient_hint, blob_ttl, content_length: Option<u64>, body: BlobBodyStream) -> Result<BlobMetadata, StorageError>` — Default: collects stream to `Vec<u8>`, delegates to `store()`, drops the blob body from the result.
- `get_streaming(blob_id) -> Result<Option<(BlobMetadata, BlobBodyStream)>, StorageError>` — Default: calls `get()`, splits `StoredBlob` into metadata + single-chunk stream.

**Content length:** `store_streaming` accepts an optional content length hint. Backends MAY use this for pre-allocation or capacity checks. Backends MUST NOT trust it for security decisions — the actual streamed length governs.

**blob_id computation:** For `store_streaming`, the caller provides the `blob_id` (SHA-256 of the complete blob content). The relay computes this incrementally via streaming SHA-256 as it receives the blob over the wire, before calling `store_streaming`. The storage layer does not re-hash.

**Native overrides:** Backends where streaming is materially beneficial (S3, future PostgreSQL large objects) override the defaults. The `S3BlobStore` streams directly to/from S3 using the AWS SDK's `ByteStream` without buffering the full blob.

## 17.8 Platform-Specific Key Custody

Key custody is NOT part of this spec — it is the existing `KeyCustody` trait (ADR-006). Referenced here for completeness of the persistence picture:

| Platform | Key Storage | Key Types | Notes |
|----------|-------------|-----------|-------|
| iOS/macOS | Apple Keychain (generic password items) | Ed25519, X25519 (software-backed) | Secure Enclave only supports P-256; Ed25519 keys are software-backed in Keychain |
| Android | Android Keystore (TEE-backed, API 33+ for Ed25519) | Ed25519, X25519 | StrongBox available but dramatically slow — opt-in only |
| Browser | WebCrypto + IndexedDB (non-extractable CryptoKey) | Ed25519 (Chrome 113+, Firefox 130+, Safari 17+) | Ephemeral in incognito |
| Python/Node/Server | Software keys in SQLCipher-encrypted SQLite | Ed25519, X25519 | No hardware key store on typical servers |
| Testing | `InMemoryKeyCustody` | Ed25519, X25519 | Already defined (ADR-006) |

### FileKeyCustody Argon2id Parameters

The software-key custody backend for non-HSM platforms (`FileKeyCustody`, the universal fallback used by the Python/Node/Server row above) derives an AES-256 wrapping key from a passphrase using Argon2id. Its parameters are the canonical Argon2id parameterization for the codebase and MUST be:

```
algorithm  = Argon2id
version    = 0x13                              // Argon2 v1.3
m_cost     = 65536                             // 65536 KiB = 64 MiB memory
t_cost     = 3                                 // 3 iterations
p_cost     = 1                                 // parallelism = 1
output_len = 32                                // 32-byte derived key
salt       = per-file 16-byte salt             // generated once, persisted with the custody file
```

These are the same parameters the SQLCipher passphrase key-derivation mode (§17.6) MUST use. A single Argon2id parameterization is REQUIRED across the codebase: both the `FileKeyCustody` passphrase-to-wrapping-key derivation and the SQLCipher passphrase-to-PRAGMA-key derivation MUST draw from one shared parameter source. Implementations MUST NOT define a second, divergent Argon2id parameter set.

## 17.9 OpenMLS StorageProvider Bridge

OpenMLS requires a `StorageProvider` trait implementation for persisting MLS group state (tree nodes, key schedules, proposals, etc.). `MlsStorageBridge` wraps `ProtocolRepository` and delegates to the `mls/{context_id}/...` key prefix.

```rust
/// scp-core/src/crypto/mls/storage.rs

pub struct MlsStorageBridge<S: Storage> {
    store: Arc<ProtocolRepository<S>>,
    context_id: ContextId,
}

impl<S: Storage> MlsStorageBridge<S> {
    pub fn new(store: Arc<ProtocolRepository<S>>, context_id: ContextId) -> Self;
}

impl<S: Storage> openmls_traits::storage::StorageProvider for MlsStorageBridge<S> {
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

**Why this bypasses `ProtocolRepository` domain methods.** Every other domain area stores data through typed `ProtocolRepository` methods that apply `StoredValue` version envelopes. The MLS bridge is one of two documented exceptions that access raw `Storage` directly (the other is identity bootstrap persistence — see §17.4). This is intentional:

- **OpenMLS owns the storage contract.** The `StorageProvider` trait dictates what gets stored, key structure, and serialization format. Wrapping values in `StoredValue` envelopes would break OpenMLS deserialization on read-back.
- **The bridge is the domain layer.** It constructs namespaced keys, validates context IDs via `sanitize_key_component`, and handles serialization. ProtocolRepository wrapper methods would be pure indirection.
- **Migration is OpenMLS's concern.** MLS state serialization is governed by the OpenMLS version, not SCP's `StoredValue` versioning. Format changes across OpenMLS upgrades follow OpenMLS's own compatibility guarantees.

### 17.9.1 MLS Crypto State Snapshot

`MlsStorageBridge` (§17.9) implements the OpenMLS `StorageProvider` trait for fine-grained per-item persistence under the `mls/{context_id}/...` key prefix. A complete MLS crypto context also includes state that lives outside the OpenMLS `StorageProvider` contract:

- **Sender keys and sender key store** — per-member symmetric keys for the sender key layer (ADR-001, §23)
- **X25519 wrapping keypair** — HPKE encapsulation key for sender key distribution
- **MLS signer** (`SignatureKeyPair`) — Ed25519 signing credential used by OpenMLS
- **Member wrapping keys** — per-member AES-256 keys for sender key wrapping
- **Sender key epoch** — monotonic counter tracking sender key rotation

Per ADR-049, this state is owned by the per-context actor (`PerContextState.mode`) — encrypted contexts carry an MLS+sender-key variant, broadcast contexts carry a per-author-key variant. The narrow backend traits `MlsBackend` and `HpkeBackend` (architecture.md §2.5.3) provide stateless primitives over this state; state serialization is an inherent concern of the state itself, not the trait.

Two inherent operations on the encrypted-mode state handle snapshot serialization atomically:

- **`export_crypto_state(context_id) -> Vec<u8>`** — Serializes the full crypto state for a context into an opaque `MlsCryptoSnapshot` blob (MessagePack). This includes the OpenMLS in-memory storage entries, the signer, sender keys, wrapping keys, and epoch metadata. Sensitive key material (signer bytes, sender keys, wrapping secret key, MLS storage entries) is zeroized from the intermediate snapshot struct immediately after serialization.

- **`restore_crypto_state(context_id, data) -> Result<()>`** — Deserializes the snapshot blob and reconstructs the full crypto state: rebuilds the `InMemoryMlsProvider` with persisted storage entries, loads the MLS group via `MlsGroup::load`, restores the signer to OpenMLS's key store, reconstructs the sender key store and member wrapping keys, and restores the X25519 wrapping keypair. Intermediate buffers are zeroized after deserialization via `drain()` and explicit `zeroize()` calls.

The snapshot blob is stored in `ContextSnapshot.mls_crypto_state` and persisted alongside the rest of the context state in `context/{context_id}/full_snapshot`. On context restoration, the blob is restored before the per-context actor resumes so that its MLS group and sender keys are available for subsequent encrypt/decrypt operations.

**Relationship to `MlsStorageBridge`.** The blob snapshot is the **sole active** persistence mechanism for MLS crypto state in the current implementation. The actor-local OpenMLS provider uses in-memory storage at runtime; `MlsStorageBridge` (§17.9) remains implemented but is **not wired into the runtime crypto provider path**. It exists as infrastructure for future fine-grained persistence if needed.

- **The blob snapshot** (active) captures the complete crypto provider state atomically — both the OpenMLS-managed portion (group state, tree nodes, key schedules) and the SCP-managed portion (sender keys, wrapping keys, signer) — as a single unit. On restore, it re-populates the in-memory structures that OpenMLS operates against.
- **`MlsStorageBridge`** (not currently instantiated) provides the OpenMLS `StorageProvider` trait implementation for fine-grained, per-item MLS storage. If activated in a future iteration, it would allow OpenMLS to persist individual items incrementally rather than relying on full-state snapshots.

The snapshot approach ensures atomicity: all crypto state is persisted and restored as a single unit. Without it, a crash between persisting MLS state and persisting sender key state would leave the context in an inconsistent state where MLS decryption succeeds but sender key decryption fails (or vice versa).

## 17.10 Migration Strategy

**Lazy on-read migration.** `ProtocolRepository` checks the version envelope on every read:

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

**Key-space migrations** (changing the key convention itself) are rare and handled differently. On startup, `ProtocolRepository` checks a `_meta/schema_version` key. If the key-space version is behind, a one-time startup migration runs before normal operation. Key-space migrations are the only blocking startup operation.

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

Implement the 5 required async methods of the `BlobStorage` trait (`store`, `get`, `query`, `delete`, `purge_expired`). The 2 streaming methods (`store_streaming`, `get_streaming`) have default implementations that delegate to the `Vec<u8>` methods — override them only if your backend benefits from avoiding full materialization (see §17.7.1). Run the `blob_store_conformance!()` macro.

```rust
#[cfg(test)]
blob_store_conformance!(|| MyCustomBlobStore::new(clock.clone()));
```

The conformance suite generates 19 tests: store/retrieve roundtrip, missing blob returns None, TTL expiry, query by routing_id in stored_at order, query with since filter, query with limit, delete removes blob, store returns SHA-256 blob_id, concurrent store + purge safety, purge removes only expired blobs, query for unknown routing_id returns empty, streaming store roundtrip, streaming get roundtrip, full streaming roundtrip, streaming empty body, content_length hint is advisory, streaming get for nonexistent blob, streaming-stored blob findable via query, and streaming get for expired blob.

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

### ProtocolRepository Integration Tests

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
| `mls_group_state_roundtrip` | Create MLS group, persist via `MlsStorageBridge` (§17.9), reload, verify group state matches |
| `mls_state_isolated_per_context` | Two contexts with MLS groups via `MlsStorageBridge`, verify state does not leak between contexts |

## 17.14 Phase Integration

### Phase 1

- `InMemoryStorage` implements all 6 `Storage` methods including `delete_prefix` and `exists`
- Skeleton `ProtocolRepository` with context state, membership, and nonce methods
- `MlsStorageBridge` skeleton (OpenMLS `StorageProvider` implementation)
- `storage_conformance!()` macro covers all 6 methods, ordering, and concurrency
- `InMemoryStorage` passes full conformance suite

### Phase 2

- Full `ProtocolRepository` with all domain methods
- `SqliteStorage` (bundled-sqlcipher, WAL mode)
- `FilesystemStorage`
- `SqliteBlobStore` for relay storage
- `RedbBlobStore` for relay storage
- ADR-008 context lifecycle uses `ProtocolRepository` for state persistence
- ADR-011 event log uses `ProtocolRepository` for Merkle tree persistence
- All new adapters pass their respective conformance suites

### Phase 3

- Python SDK uses `ProtocolRepository` via FFI (SQLite default, auto-configured)
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
- `ProtocolRepository` profiling and hot-path optimization

## 17.15 Per-Context State Persistence

Under the concurrency model in §5.15, each context has a single owning computation responsible for persisting its state. Persistence uses two modes.

### 17.15.1 Coalesced Persist (Default)

A context's state is marked dirty after any mutation that is not explicitly sync-persisted (§17.15.2). A coalescing timer fires at most once per 50 ms per context; when it fires with a dirty state, the full context snapshot is written via the configured persistence backend. This bounds the write rate per context and avoids persisting every incremental change.

The 50 ms window is a normative upper bound on caller-observable rollback (§5.15.3). Implementations MAY persist more aggressively (shorter interval, every-mutation persist); they MUST NOT coalesce beyond 50 ms.

### 17.15.2 Synchronous Persist (Safety-Critical)

Specific operations bypass coalescing and persist inline before the mutation is visible to any observer (observer set defined in §5.15.3). The full list of sync-persisted operations is normative and appears in §5.15.3.

Implementation-level protocol: mutate in-memory state → persist synchronously → only after persist succeeds, surface any outbound effect. On persist failure, roll back the in-memory mutation and return an error. The caller's acknowledgment implies durable commit.

### 17.15.3 Snapshot Schema Versioning

Every context snapshot carries a schema version identifier. Behavior on mismatch:

- **Older than the current runtime's supported minimum:** loader refuses and returns a versioned-load error. No in-place migration; snapshots are rewritten with the current version on next persist.
- **Newer than the current runtime understands** (e.g., a runtime downgrade): loader refuses with the same versioned-load error. Silent data loss or partial reads are forbidden.

Pre-1.0 posture: no deployed state needs to survive schema evolution; neither direction produces a migration path.

## 17.16 Saga Journal

The cross-context saga coordinator (§5.15.4) writes phase transitions to a durable journal, separate from per-context snapshots. The journal is the coordinator's authoritative record across process restarts; per-context saga-state is the participant's authoritative record for evidence content.

### 17.16.1 Required Operations

The journal surface provides three operations:

- **Append a journal entry.** The operation does not return until the entry is durably persisted: any write buffers the backend maintains (OS page cache, application buffer, network replication pipeline) MUST be flushed before the call returns success. Backends that cannot flush durably MUST refuse to be used as a saga journal; construction fails closed. Partial writes MUST be detectable on reload (e.g., length prefix plus checksum). The operation is non-cancellable in practice: callers MUST NOT cancel it mid-flight, and a cancelled append is treated as "state unknown" at restart — the next unresolved-saga scan detects any half-written entry and reconciles.
- **Load unresolved sagas.** Returns the latest entry per saga identifier for sagas **not in a *resolved* terminal state** (`Committed` or `Aborted`). The predicate keys on *resolution*, not on FSM-terminality: `NeedsRepair`, though **FSM-terminal** (the automatic retry machine stops there, §5.15.4), is **not resolved** and IS returned by this scan, so the coordinator re-surfaces it for operator repair at each process start until it is resolved (§17.16.4). A resolved-terminal `Committed`/`Aborted` saga is NOT returned. Used at process start for crash-recovery replay.
- **Mark a saga terminally resolved.** For sagas classified as secret-bearing (§9.4.3), the operation MUST synchronously overwrite the on-disk evidence bytes before returning; it does not wait for the backend's next compaction. The operation is non-cancellable for secret-bearing sagas: if a cancellation occurs before the overwrite completes (e.g., process abort), implementations MUST complete the overwrite on the next process start before the journal is opened for any other use. Secret bytes MUST NOT survive on disk past the next journal open.

**Bounded-cost recovery (normative).** Resolved sagas are compacted: once a saga reaches a resolved-terminal state (`Committed`/`Aborted`), its journal entries SHOULD be removed so they no longer participate in the unresolved-saga scan. The scan's cost — keys listed, values retrieved, and entries decoded at process start — is therefore bounded by the number of sagas that are still UNRESOLVED, not by the number of sagas ever run. An implementation that compacts MUST do so crash-safely: the resolution MUST be durable before any non-terminal entry for that saga is removed, so that an interrupted compaction can never resurrect a stale pre-commit entry as the saga's latest state (a partially-compacted saga either still reads as resolved or is fully absent — never reverts to in-flight). Implementations MAY instead defer compaction and leave earlier entries in place; in that case the scan's per-resolved-saga cost is paid until a later compaction reclaims it. Either is conformant.

Journal entries are append-only per saga identifier while a saga is unresolved: earlier entries of an in-flight saga are not rewritten. (The secret-bearing evidence overwrite above and the compaction of a *resolved* saga are the only writes that touch already-persisted entries, and both occur only at terminal resolution.)

### 17.16.2 Secret-Bearing Entries

Saga classification, commitment construction, bearer handling, and the at-rest-encryption refusal rule are defined in §9.4.3 and apply here without restatement.

### 17.16.3 Key Namespace

Journal entries occupy a dedicated key namespace within the persistence backend. The namespace is distinct from context snapshots and from event log storage; backend operations on the journal namespace do not affect the other surfaces.

### 17.16.4 Crash Recovery

**Startup ordering (normative): restore, then reconcile.** On process start the coordinator performs a SINGLE startup pass: it first restores every persisted context (rehydrating each `Active` context's actor), and only THEN loads the unresolved sagas and reconciles them. Context restore precedes saga reconcile so that every participant a recovery arm must drive — the cross-context caller whose local economy reversal is replayed; the participants a Commit-in-progress re-send targets — is RESIDENT when its arm runs. There is NO separate post-restore sweep within a single process start: reconciliation runs once, after restore, in the same startup pass. (A reconciliation left genuinely undeliverable — see below — is carried to the NEXT process start, whose own restore-then-replay pass re-drives it; that is the only "later sweep," and it is a subsequent restart, not a second pass within one.)

This ordering is sound because every recovery arm that must reach a live actor needs the actor resident, and NO arm requires the inverse (observing a participant *before* it is restored). The caller-reversal arm in particular drives an idempotent reversal that is keyed off the saga's durable `CallerReservationRecord` and consumes that record exactly once (a no-op if the record was already drained, e.g. by a guard that fired pre-crash) — so driving it against a now-resident, freshly-restored caller is safe and correct, not a semantic change. A replay-before-restore ordering would instead force every cross-context caller reversal to miss its live target on the first pass and depend on a separate post-restore sweep that does not exist; restore-first removes that dependency.

For each unresolved saga:

- Pre-Prepare states (no actor committed): discard.
- Prepare-in-progress with one actor already Prepared: abort the Prepared actor (idempotent); discard. **Exception — a cross-context saga whose caller deduction was durably staged (normative, §6.2.4).** For a cross-context tool saga, Prepare-A **durably** persists the caller's velocity/budget/hard-rate-limit deduction **and** its `CallerReservationRecord` **before** the FSM journals the `PreparingB` entry, so a crash can leave a `PreparingA` **or** `PreparingB` journal over a **LIVE durable caller reservation**. For such an entry the recovery does **NOT** unconditionally discard: it reverses the caller's LOCAL economy from the durable `CallerReservationRecord` (the same reversal the live abort performs) and confirms delivery, writing **terminal-`Aborted` only** on a **confirmed reversal** (caller acknowledged `SettledOrAbsent`) **or** a **permanently-deleted caller context**. Because context restore precedes this reconcile (above), the caller is RESIDENT when the reversal is driven, so on the normal startup pass the reversal is delivered in-pass and the entry reaches terminal-`Aborted` with the refund applied. The journal is left **non-terminal** ONLY in the **genuinely-undeliverable** case — the caller context failed to restore, or its persistence existence cannot be confirmed (a transient read error is treated conservatively as "still present," never reaped) — and is then carried to the NEXT process start, whose restore-then-replay pass re-drives it. Marking terminal while a refund is outstanding would strand the durable deduction forever (this scan re-drives only non-terminal journals) — a permanent caller over-charge plus escrow leak. This crash-only path applies to both `PreparingA` and `PreparingB`; it does not alter the live abort path, where the in-process RAII reservation guard remains authoritative. A non-cross-context Prepare-in-progress entry has nothing to reverse and discards as above.
- Commit-in-progress: re-send Commit to all participants; participants deduplicate by saga identifier.
- `NeedsRepair`: surface via a metric (e.g., `saga_repair_needed`); operator retries via a repair command, or the saga is resolved on next process start after the underlying cause is addressed.
- **Corrupt, torn, or undecodable entry (normative).** An entry whose framing fails the integrity check (§17.16.1 length-prefix + checksum) — a torn write, bit-rot, or otherwise undecodable record — is surfaced via the same `saga_repair_needed` metric, SKIPPED for operator repair, and the sweep CONTINUES. A single unrecoverable entry MUST NOT abort recovery of the remaining sagas: the scan recovers every other unresolved saga and never silently falls back to an earlier-seq entry for the corrupt saga (which could resurrect stale pre-commit state). The corrupt saga is neither replayed nor marked resolved; it awaits operator repair.
- **Non-canonical key suffix — key-namespace anomaly (normative).** Distinct from the corrupt-framing case above: a journal entry may be well-framed and fully decodable yet be stored under a NON-canonical key — a key whose trailing seq suffix is not the canonical 20-digit zero-padded decimal sequence (`:020d`, §17) that the append path writes, including a 20-digit-but-out-of-`u64`-range value. This is a key-namespace anomaly, not an "undecodable" record, and it is dangerous precisely because latest-per-saga selection is the lexicographic MAX key per saga: a non-canonical suffix can sort ABOVE every real zero-padded seq and thereby win selection, overriding the canonical latest entry. Such an entry MUST be SKIPPED, flagged via the same `saga_repair_needed` metric, and MUST NEVER win latest-per-saga selection — the same sweep-isolation guarantee as the corrupt-entry case applies: every other unresolved saga is still recovered, the anomalous entry is neither replayed nor marked resolved, and it awaits operator repair. The read path enforces this in parity with the append path, which only ever emits canonical, in-range `:020d` suffixes.

**Permanently-deleted caller (normative).** The ONE case reaped to terminal-`Aborted` rather than carried forward is a caller context PERMANENTLY DELETED from durable persistence: its reservation record died with the context, so there is nothing left to reverse locally and carrying the entry forward would loop forever without resolving. (An external escrow hold staged on a since-deleted context is irrecoverable from journal evidence alone and is settled by operator / external-system reconciliation — see §6.2.4.)
