# `crypto/mls/` — the MLS subsystem

Every SCP context maps to exactly one MLS (Messaging Layer Security, RFC 9420)
group. SCP layers its own concerns on top of `OpenMLS`: DID-bearing
credentials, per-author sender keys, HPKE wrapping-key distribution, epoch
grace windows, and fail-closed commit broadcast. The single ciphersuite is
`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` — no negotiation (ADR-001).

## Where the code lives — sync core vs async bridge (ADR-057)

The **synchronous** MLS state machine — `group`, `encrypt`, `ratchet`,
`credential`, `key_package`, `error`, `wrapping_extension`, `epoch_grace` —
lives in the wasm32-safe [`scp_mls`](../../../../scp-mls) crate, so it can be
shared by both the native node runtime and in-browser SCP clients. Call sites
in `scp-runtime` import those items from `scp_mls` directly — there is no
re-export shim (ADR-057 Amendment; enforced by
`scripts/check-no-shim-reexports.sh`).

This module (`crates/scp-runtime/src/crypto/mls/`) keeps only the **async
durable-storage bridge** — the `tokio`-coupled, node-only pieces:

- `provider.rs` — `NodeMlsFactory`
- `backend.rs` — the `MlsBackend` trait + raw-output types
- `production_backend.rs` — `ProductionMlsBackend`
- `storage.rs` — the OpenMLS `StorageProvider` bridge (`ScpMlsProvider`,
  `MlsStorageBridge`)
- `storage_adapter.rs` — `OpenMlsStorageAdapter` + `SpawnBlockingStorageAdapter`

## The injected-backend shape (ADR-049 §6)

The provider is split so the actor runtime can share stateless primitives and
inject test doubles:

- **`NodeMlsFactory`** (`provider.rs`) — the concrete MLS crypto provider
  (the `ContextCryptoProvider` trait was deleted in ADR-049; the provider is
  now a concrete type held as `Arc<NodeMlsFactory>`). It owns the
  per-context crypto state — a `DashMap` of per-context MLS state, a `DashMap`
  of broadcast sender keys, and each identity's X25519 wrapping keypair in an
  `ArcSwap` for atomic rotation (Decision 12, §9.16.1) — but delegates every
  raw MLS/HPKE primitive to two injected trait objects:
  - `mls_backend: Arc<dyn MlsBackend>` (`backend.rs`)
  - `hpke_backend: Arc<dyn HpkeBackend>` (`../hpke_backend.rs`)
  Build the production provider with `NodeMlsFactory::new(local_did, clock)`
  — `clock` is an `Arc<dyn scp_clock::Clock>` (e.g. `Arc::new(scp_clock::SystemClock)`)
  — which wires `ProductionMlsBackend` + `ProductionHpkeBackend`; tests inject
  failure-driven mocks via `NodeMlsFactory::with_backends`.
- **`ProductionMlsBackend`** (`production_backend.rs`) — a stateless struct
  that delegates each primitive to the `scp_mls` crate's `group` / `encrypt` /
  `ratchet` free functions (e.g. `scp_mls::group::create_group_with_wrapping_key`).
  It wraps those calls exactly, so the async bridge does not perturb the wire
  bytes the sync state machine produces.
- **`MlsBackend`** (`backend.rs`) / **`HpkeBackend`** (`../hpke_backend.rs`)
  are `#[async_trait]`, `Send + Sync`, and dyn-compatible so one `Arc<dyn …>`
  is shared across every context actor. This is a hard requirement: actor
  futures are `tokio::spawn`'d, so the primitives they await must produce
  `Send` futures. See this crate's `CLAUDE.md` for the full Send-discipline.

## Storage: `OpenMlsStorageAdapter` (`storage_adapter.rs`)

`OpenMLS`'s own `StorageProvider` is a **sync** trait. The platform `Storage`
trait, meanwhile, uses return-position `impl Trait` and is **not**
dyn-compatible (`Arc<dyn Storage>` will not compile). `OpenMlsStorageAdapter`
resolves both problems:

- It is an `#[async_trait]` keyed blob store that **is** dyn-compatible, so
  `Arc<dyn OpenMlsStorageAdapter>` clones into every actor's `ActorDeps`.
- `SpawnBlockingStorageAdapter<S>` is the production impl over any concrete
  `S: Storage`. It is erased once per process to the trait object. The name
  signals its role in the sync→async seam: it wraps each storage call so
  sync-heavy backends (e.g. `rusqlite`) do not pin async worker threads —
  replacing the old `block_in_place` pattern that made `current_thread`
  runtimes panic.

`storage.rs` is the OpenMLS `StorageProvider` bridge itself: `MlsStorageBridge`
wraps an `Arc<ProtocolRepository<S>>` + context ID, and `ScpMlsProvider<S>`
presents it to `OpenMLS`. It is an allow-listed `block_in_place` sync-bridge
site in the ratchet (`scripts/check-block-in-place.py`).

## The crypto model at a glance

The sync algorithms below live in the `scp_mls` crate; this module drives them
through the backend traits above.

- **`scp_mls::group`** — group lifecycle: create, add/remove member, destroy,
  key-package generation. Every op advances the MLS epoch and emits Commit /
  Welcome / `GroupInfo` bytes.
- **`scp_mls::credential`** — `ScpCredential`, the DID + UCAN payload carried
  in the MLS `LeafNode`.
- **`scp_mls::encrypt`** — application message seal/open. Membership-tag
  verification, generation-number replay tracking, and forward secrecy are
  enforced by `OpenMLS` internally.
- **`scp_mls::ratchet`** — epoch advancement (Commit processing) and MLS
  `Update` proposals for post-compromise security.
- **`scp_mls::epoch_grace`** — `EpochGraceStore`. When a Commit advances the
  epoch, old-epoch key material is retained briefly so in-flight messages
  under the prior epoch still decrypt.
- **`scp_mls::wrapping_extension`** — the X25519 **wrapping key** each member
  publishes in its `LeafNode` `scp_wrapping_key` extension (§9.16.1).
- **Sender keys** (`crypto/sender_keys/`, sibling runtime module) — per-author
  AES-256-GCM keys distributed via HPKE using each member's published wrapping
  key. Pure types live in `scp_protocol::crypto::sender_keys`; this module
  retains the async `key_protocol`. The provider holds each identity's wrapping
  keypair in `ArcSwap` so rotation is atomic and old secret material is
  zeroized on last-`Arc` drop.

## §9 fail-closed commit broadcast

An MLS Commit (member removal, content-key rotation, member reset, leave)
mutates **local** group state before it can be broadcast to the group. If the
transport send fails after the local mutation, the epoch has already advanced
locally — silently dropping the broadcast would fork the group. SCP handles
this with a persistent retry queue that fail-closes rather than diverges. The
queue orchestration lives in the context layer (it needs `ActorDeps` transport
+ persistence), not in `crypto/mls/` — the MLS backend only produces the
Commit bytes:

- The broadcast is a three-function split (`context/governance_helpers.rs`) so
  the async transport send stays out of the fail-closed Class-S persist closure:
  - **`try_broadcast_commit`** — async, send-only; it touches no
    `PerContextState` and returns `Option<BroadcastFailure>` (`None` on success,
    `Some(..)` carrying the retry payload on transport failure).
  - **`apply_broadcast_failure`** — synchronous; applies that payload by
    enqueuing a `PendingCommit` (`context/state.rs`) carrying the serialized
    Commit bytes, routing ID, the logical `CommitOperation`, and retry
    bookkeeping, or setting the `commit_fault` marker when the queue is full.
    Retries use exponential backoff (`COMMIT_RETRY_BACKOFFS`), bounded by
    `MAX_COMMIT_RETRIES` (20), `MAX_COMMIT_AGE_SECS` (1 h), and
    `MAX_PENDING_COMMITS` (50). The queue is persisted so retries survive
    process restart.
  - **`keep_broadcast_failure`** — async; runs `apply_broadcast_failure` inside
    a `commit_class_s_keep` so the failure bookkeeping fail-closes (persists
    before ack) rather than being lost on a coalesced tick. Only the four
    safety-gated / forward-secrecy sites — `execute_remove_member`,
    `execute_rotate_content_keys`, `leave_context`, `recovery_advance_epoch` —
    fail-close this way; the two best-effort sites (`execute_add_member`,
    `execute_reset_member`) apply the *same* failure value **coalesced** via
    `class_c_view()` (Class-C), not fail-closed — see the context layer +
    `crates/scp-runtime/CLAUDE.md` for the authoritative site list.
- On budget exhaustion the context **fail-closes**: a `CommitFaultMarker` is
  set. While it is set, `check_commit_fault_marker` makes all governance and
  lifecycle mutations return `ContextError::CommitBroadcastFault`.
- **`acknowledge_commit_fault`** (`context/governance_helpers.rs`) is the
  operator escape hatch that clears the marker after intervention.

The `CommitBroadcastPending` / `Succeeded` / `Failed` events are surfaced as
local `ContextEvent`s only — per the ADR-011-amendment exclusion taxonomy they
are per-committer bookkeeping and are **not** appended to the convergent
Merkle event log (§9.9.3).

## Where this sits

`NodeMlsFactory` is injected into the `Supervisor` at construction and
cloned into each `ContextActor`'s `ActorDeps` (`Arc<NodeMlsFactory>`), so
handler bodies call `seal` / `open` / `advance_epoch` without reaching back
through the supervisor. See `../../context/README.md` for the actor model and
this crate's `CLAUDE.md` for the injection + Send-discipline rules.
