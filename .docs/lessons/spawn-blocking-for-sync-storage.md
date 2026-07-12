# `spawn_blocking` for sync storage, not `block_in_place`

## The problem

`OpenMLS`'s `StorageProvider` is a **sync** trait — every method returns
`Result<…, Self::Error>` with no async support. The SCP `Storage` backend underneath it is
async (and, for the production `SqliteStorage`, wraps `rusqlite`, which is itself
blocking). Bridging a sync caller to an async/blocking backend has two shapes, and only one
is safe on a shared runtime:

- **`block_in_place(|| handle.block_on(…))`** — the legacy bridge in
  `crypto/mls/storage.rs`. It **pins the tokio worker thread** for the duration of the call
  and **panics outright on a `current_thread` runtime**. Under load it starves the worker
  pool; under `current_thread` it is a hard crash.
- **`spawn_blocking`** — moves the blocking work to tokio's dedicated blocking pool,
  freeing the async worker. One hop per call at the sync→async seam. This is the ADR-049
  §7 / §153 (Decision 7) direction.

## The seam that is already built

`SpawnBlockingStorageAdapter<S>` (`crypto/mls/storage_adapter.rs`) is the landed adapter.
It implements `OpenMlsStorageAdapter` — a **dyn-compatible** async KV surface
(`store` / `retrieve` / `delete`, `#[async_trait]`-desugared to boxed futures) — over any
`S: scp_platform::traits::Storage`. Dyn-compatibility is the whole point: `Storage` itself
uses RPITIT and so **cannot** be `Arc<dyn Storage>` (the compiler refuses); the adapter
erases to `Arc<dyn OpenMlsStorageAdapter>`, instantiated once per process and cloned into
every actor's `ActorDeps`. The production MLS backend (`crypto/mls/production_backend.rs`,
`ProductionMlsBackend`) drives its group store through this adapter.

The name encodes the role: the sync `OpenMLS` `StorageProvider` bridge built on top of the
adapter wraps **each** adapter call in a single `spawn_blocking`, so a sync-heavy backend
(`SqliteStorage` over `rusqlite`) never pins an async worker when `OpenMLS` reaches for the
KV store. The adapter forwards directly to the already-async `Storage` — the
`spawn_blocking` hop lives at the sync `OpenMLS` seam, not inside the adapter, because an
extra hop there would be redundant for an already-async backend.

## Cost and enforcement

`spawn_blocking` is not free: it is a thread-pool handoff plus a `JoinHandle` await
(`OpenMlsStorageError` carries the join-failure case). It is the right cost for a
genuine sync→async boundary, and the wrong cost for work that is already async — which is
why the adapter does **not** re-wrap. The ban on `block_in_place` / `.block_on(…)` in the
actor-refactor scope is mechanically enforced by `scripts/check-block-in-place.py` (an
AST gate — see `ast-based-ci-enforcement.md`), which opts sites out two ways.
`crypto/mls/storage.rs` — whose sync `OpenMLS` `StorageProvider` bridge (`sync_store` /
`sync_retrieve` / `sync_delete`, ~:201/212/223) is the one place a `block_in_place` is still
genuinely required — is a **wholesale file-scope exclusion** (`EXCLUDED_FILES` in the gate,
alongside the `crates/scp-ffi/**` prefix), *not* an inline directive: it carries no
`// ci-allow`. Individual sites elsewhere opt out with the gate's **inline allow-list
directive** (`// ci-allow: block-on: <reason>`) — e.g. `shutdown_all_contexts_sync`'s FFI
sync-shutdown path; the remaining still-counted sites (`lifecycle_helpers.rs`'s
`flush_all_contexts_sync` pair, `store/trust.rs`, the `outlets_helpers` `_legacy` slack, and
the `scp-node` HTTP handler) are simply **ratchet-baselined** and driven toward zero
(`ratchet/block-in-place-count.json`). At the current commit the `scp-transport`
`provider.rs` / `relay_persistence.rs` bridges are **gone** (count `0` — the `block_in_place`
tokens still in `provider.rs` are doc-comment prose, not calls); the only real
`block_in_place` sites left in this lesson's storage scope are the three in
`crypto/mls/storage.rs`.

## Cross-refs

- `tokio-mutex-blocking-lock-in-runtime.md` — the sibling rule: never `blocking_lock()` a
  `tokio::sync::Mutex` from a runtime thread; the same "don't block the worker" principle.
- `actor-per-context-pattern.md` — the Send-discipline that motivates async provider traits.
- ADR-049 §7 (MLS storage), §153 / Decision 7 (async traits + `block_in_place` deletion).
