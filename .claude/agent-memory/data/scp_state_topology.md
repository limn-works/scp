---
name: SCP runtime state topology
description: Complete map of in-memory state domains, their synchronization primitives, and persistence boundaries across the SCP runtime.
type: project
---

State domains (each has its own lock/primitive, its own persistence story):

1. **ContextManager top-level** (`scp-runtime/src/context/manager/mod.rs`):
   - `local_dids: RwLock<HashSet<DID>>` — identity registry (no persistence in CM; identity layer persists separately in `scp-runtime/src/store/identity.rs`).
   - `contexts: Arc<DashMap<String, Arc<tokio::sync::Mutex<PerContextState>>>>` — actually NOT DashMap in current code — it's `Arc<tokio::sync::Mutex<HashMap<String, PerContextState>>>` (mod.rs ~1873). One global async mutex over the whole map. Every context operation takes the map-level mutex, then reads/mutates a single PerContextState.
   - `standing_contexts: Mutex<HashMap<String, DID>>` — lock ordering: `contexts` → `standing_contexts` → `local_dids` (see standing.rs:239-240).
   - Providers (`crypto`, `transport`, `event_log`, `persistence`, `payment_adapter`) are `Arc<dyn …>`.

2. **MlsCryptoProvider** (`scp-runtime/src/crypto/mls/provider.rs`): SEPARATE mutex domain.
   - `contexts: std::sync::Mutex<HashMap<[u8;32], ContextCryptoState>>` — blocking mutex, held across OpenMLS ops. Contains: `mls_group` (ScpMlsGroup), `sender_key`, `sender_key_store`, `sender_key_epoch`, `send_sequence`, `pending_distributions`, `nonce_dedup`, `member_wrapping_keys`, `recv_sequence_tracker`.
   - `broadcast_keys: Mutex<HashMap<[u8;32], SenderKey>>`
   - `wrapping_public_key / wrapping_secret_key: Mutex<…>`
   - `pending_joins: Mutex<Option<PendingJoinState>>` — single-slot, global — serializes joins across ALL contexts.
   - Send path (messaging.rs:310+): drops ContextManager per-context mutex before `crypto.seal`. AEAD nonce uniqueness is enforced by THIS mutex, not the CM mutex.

3. **PerContextState** (mod.rs:1108): 17 fields behind CM's map-level Mutex. Sub-structs: GovernanceState, EpochState (has `grace_store`), AccessControlState, TtlState. Everything else flat. Includes `sequence_tracker`, `reorder_buffer` (100/30s per §9.8.5), `pending_commits`, `commit_fault`.

4. **Transport** (`scp-transport/src/manager.rs` 3212 lines):
   - `relay_assignments: RwLock<HashMap<ContextId, Vec<usize>>>`
   - `reliability_scores: Arc<Mutex<HashMap<String, ReliabilityScore>>>`
   - `dedup_cache: LruCache<BlobId, Instant>` — no lock (field of `&mut self` in some methods? verify — looks like it's NOT wrapped).
   - `active_subscriptions: RwLock<HashMap<usize, Vec<RoutingId>>>`
   - `connection_last_used: Mutex<HashMap<usize, Instant>>`
   - `suppression_tracker: Arc<Mutex<SuppressionTracker>>`
   - `relay_costs: RwLock<HashMap<usize, u64>>`
   - `connection_pool: Arc<ConnectionPool>` — process-wide dedup.
   - Inbound pump: each SDK has its own loop (e.g., napi context.rs:1029 `loop { select! }`) calling `manager.deliver_incoming(&context_id, &envelope.encrypted_blob)`. Cancellation via CancellationToken; active flag via AtomicBool. No structural protocol-layer coupling between transport and CM except through this per-SDK pump.

5. **Storage backends** (`scp-platform/src/`):
   - `InMemoryStorage`: `tokio::sync::Mutex<HashMap<String, Vec<u8>>>` — every op acquires.
   - `FilesystemStorage`: per-file atomic via temp+rename; blocking ops on `spawn_blocking`. NO multi-key atomicity.
   - `SqliteStorage`: `std::sync::Mutex<rusqlite::Connection>`. Single connection, serialized access. No transactions exposed through trait.
   - Keychain/Keystore/IndexedDB: each has its own internal locking and consistency model.
   - `EncryptingAdapter<S>` wraps a Storage and encrypts at rest (AES-256-GCM). Doesn't change atomicity semantics.

6. **Custody backends**: InMemory, File (Argon2id+AES-256-GCM, per-call decrypt via `tokio::sync::Mutex`), SQLite, Apple Keychain, Android Keystore. `KeyCustody` trait is RPITIT (async impl trait) → NOT dyn-compatible. Bridges use concrete type, not Arc<dyn>. This means CM can't hold `Arc<dyn KeyCustody>` — custody ownership currently lives OUTSIDE CM (in FFI-bridge globals / identity registry).

7. **Event log** (`scp-event-log/`): Per-context Merkle tree + tiered storage. Has its own persistence provider (`EventLogPersistence`) and lock discipline. Bridge: `ProtocolRepositoryEventLogBridge`.

8. **Node/Relay**:
   - `ApplicationNode<S>`: `Arc<ProtocolRepository<S>>`, `Arc<http::NodeState>` (contains `broadcast_contexts: RwLock<HashMap>` cert_resolver, relay_url).
   - Relay: `SubscriptionRegistry = Arc<RwLock<HashMap<[u8;32], Vec<SubscriberEntry>>>>` — shared across WS/QUIC/WebTransport transports. `NEXT_OWNER_ID: AtomicU64` for cross-transport unique IDs.

## Persistence call sites

Over 55 call sites of `persist_context_snapshot` / `persist_broadcast_snapshot` scattered across governance.rs (most), messaging.rs (finalize_send), lifecycle.rs, ttl_close.rs, broadcast.rs, trust_recovery.rs. Pattern: take map-level mutex → clone full `PerContextState` → drop lock → call `crypto.export_crypto_state` → blocking-on-async bridge writes single blob. `persist_context_snapshot` also calls `self.crypto.export_crypto_state(&ctx_id_bytes)` out-of-lock, which can race with the MLS provider's internal state (nonce/sequence counters).

## Lock ordering discovered

`contexts` (map-level) → `standing_contexts` → `local_dids` (R).
`local_dids` (R) → `contexts` (from `deliver_incoming`).
Crypto provider's `contexts` mutex is entered while CM map mutex is NOT held.
Crypto provider's `pending_joins` is a global single-slot serializer.

## Inbound receive path torn-read window

`deliver_incoming` (messaging.rs:783) does 4-5 sequential lock acquisitions on the map-level Mutex: phase 1 (read), phase 2 (crypto — no CM lock), phase 3 (`validate_and_drain_timeouts`), phase 4 (`buffer_ahead_message` OR `deliver_message_and_drain_buffered`). Between acquisitions, membership can change, capability can be revoked, context can be closed. Code defensively re-checks. Not atomic across the pipeline.

## Persistence unit mismatch

`ContextSnapshot` is one blob containing 53 fields. `mls_crypto_state` is an opaque inner blob exported by `MlsCryptoProvider.export_crypto_state`. Event log is persisted separately (per-entry). BroadcastContextSnapshot is persisted separately. On crash:
- Event log append already happened → blob write failed → event log shows a message the snapshot doesn't.
- Snapshot persisted → crypto export taken at slightly different time → nonce/sequence counter drift.
- Multi-context mutations (cross-context tool invocation) touch 2 contexts but persistence is per-context.
