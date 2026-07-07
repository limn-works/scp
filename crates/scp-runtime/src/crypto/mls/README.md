# `crypto/mls/` — the MLS subsystem

Every SCP context maps to exactly one MLS (Messaging Layer Security, RFC 9420)
group. This module wraps `OpenMLS` and layers SCP's own concerns on top:
DID-bearing credentials, per-author sender keys, HPKE wrapping-key
distribution, epoch grace windows, and fail-closed commit broadcast. The
single ciphersuite is `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` — no
negotiation (ADR-001).

## The injected-backend shape (ADR-049 §6)

The provider is split so the actor runtime can share stateless primitives and
inject test doubles:

- **`MlsCryptoProvider`** (`provider.rs`) — the concrete
  `ContextCryptoProvider`. It owns the per-context crypto state (lock-free
  `DashMap`s + `ArcSwap` wrapping keys per Decision 12) and orchestrates group
  operations, but delegates every raw MLS/HPKE primitive to two injected
  trait objects:
  - `mls_backend: Arc<dyn MlsBackend>` (`backend.rs`)
  - `hpke_backend: Arc<dyn HpkeBackend>` (`../hpke_backend.rs`)
  Build the production provider with `MlsCryptoProvider::new(local_did)`
  (wires `ProductionMlsBackend` + `ProductionHpkeBackend`); tests inject
  failure-driven mocks via `MlsCryptoProvider::with_backends`.
- **`ProductionMlsBackend`** (`production_backend.rs`) — a stateless struct
  that delegates each primitive to the `group` / `encrypt` / `ratchet` free
  functions. It is byte-identical to the pre-refactor inline `OpenMLS` calls
  by design (the migration must not perturb wire bytes).
- **`MlsBackend` / `HpkeBackend`** are `#[async_trait]`, `Send + Sync`, and
  dyn-compatible so one `Arc<dyn …>` is shared across every context actor.
  This is a hard requirement: actor futures are `tokio::spawn`'d, so the
  primitives they await must produce `Send` futures. See this crate's
  `CLAUDE.md` for the full Send-discipline.

## Storage: `OpenMlsStorageAdapter` (`storage_adapter.rs`)

`OpenMLS`'s own `StorageProvider` is a **sync** trait. The platform `Storage`
trait, meanwhile, uses return-position `impl Trait` and is **not**
dyn-compatible (`Arc<dyn Storage>` will not compile). `OpenMlsStorageAdapter`
resolves both problems:

- It is an `#[async_trait]` keyed blob store (`store` / `retrieve` / `delete`)
  that **is** dyn-compatible, so `Arc<dyn OpenMlsStorageAdapter>` clones into
  every actor's `ActorDeps`.
- `SpawnBlockingStorageAdapter<S>` is the production impl over any concrete
  `S: Storage`. It is erased once per process to the trait object. The name
  signals its role in the sync→async seam: the sync `StorageProvider` bridge
  (`storage.rs`) wraps each adapter call so sync-heavy backends (e.g.
  `rusqlite`) do not pin async worker threads — replacing the old
  `block_in_place` pattern that made `current_thread` runtimes panic.

`storage.rs` is the OpenMLS `StorageProvider` bridge itself (an allow-listed
sync-bridge site in the `block_in_place` ratchet).

## The crypto model at a glance

- **`group.rs`** — group lifecycle: `create_group`, `add_member`,
  `remove_member`, `destroy_group`, key-package generation. Every op advances
  the MLS epoch and emits Commit / Welcome / `GroupInfo` bytes.
- **`credential.rs`** — `ScpCredential`, the DID + UCAN payload carried in the
  MLS `LeafNode`.
- **`encrypt.rs`** — application message seal/open. Membership-tag
  verification, generation-number replay tracking, and forward secrecy are
  enforced by `OpenMLS` internally.
- **`ratchet.rs`** — epoch advancement (Commit processing) and MLS `Update`
  proposals for post-compromise security.
- **`epoch_grace.rs`** — `EpochGraceStore`. When a Commit advances the epoch,
  old-epoch key material is retained briefly so in-flight messages under the
  prior epoch still decrypt.
- **Sender keys** (`sender_keys/`, sibling module) — per-author AES-256-GCM
  keys distributed via HPKE using the X25519 **wrapping key** each member
  publishes in its `LeafNode` `scp_wrapping_key` extension
  (`wrapping_extension.rs`, §9.16.1). The provider holds each identity's
  wrapping keypair in `ArcSwap` so rotation is atomic and old secret material
  is zeroized on last-`Arc` drop.

## §9 fail-closed commit broadcast

An MLS Commit (member removal, content-key rotation, member reset, leave)
mutates **local** group state before it can be broadcast to the group. If the
transport send fails after the local mutation, the epoch has already advanced
locally — silently dropping the broadcast would fork the group. SCP handles
this with a persistent retry queue that fail-closes rather than diverges. The
queue orchestration lives in the context layer (it needs `ActorDeps` transport
+ persistence), not in `crypto/mls/` — the MLS backend only produces the
Commit bytes:

- **`try_broadcast_commit_or_enqueue`** (`context/governance_helpers.rs`) —
  attempts the broadcast; on failure enqueues a `PendingCommit`
  (`context/state.rs`) carrying the serialized Commit bytes, routing ID, the
  logical `CommitOperation`, and retry bookkeeping. Retries use exponential
  backoff (`COMMIT_RETRY_BACKOFFS`), bounded by `MAX_COMMIT_RETRIES` (20),
  `MAX_COMMIT_AGE_SECS` (1 h), and `MAX_PENDING_COMMITS` (50). The queue is
  persisted so retries survive process restart.
- On budget exhaustion the context **fail-closes**: a `CommitFaultMarker` is
  set. While it is set, `check_commit_fault` makes all governance and
  lifecycle mutations return `ContextError::CommitBroadcastFault`.
- **`acknowledge_commit_fault`** (`context/governance_helpers.rs`) is the
  operator escape hatch that clears the marker after intervention.

The `CommitBroadcastPending` / `Succeeded` / `Failed` events are surfaced as
local `ContextEvent`s only — per the ADR-011-amendment exclusion taxonomy they
are per-committer bookkeeping and are **not** appended to the convergent
Merkle event log (§9.9.3).

## Where this sits

`MlsCryptoProvider` is injected into the `Supervisor` at construction and
cloned into each `ContextActor`'s `ActorDeps` (`Arc<MlsCryptoProvider>`), so
handler bodies call `seal` / `open` / `advance_epoch` without reaching back
through the supervisor. See `../../context/README.md` for the actor model and
this crate's `CLAUDE.md` for the injection + Send-discipline rules.
