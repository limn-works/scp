# ADR-049: Actor-per-Context Concurrency Model

**Status:** Proposed
**Date:** 2026-04-19
**Phase:** Runtime concurrency redesign
**Related:** ADR-034 (WASM Constraints), ADR-046 (Bridge Parity Harness), ADR-047 (Bridge Symmetry Enforcement), ADR-048 (SCP Multi-Instance). Plan: `~/.claude/plans/generic-moseying-lightning.md`.

## Context

SCP's runtime concurrency model today is lock-based: `Arc<DashMap<String, Arc<tokio::sync::Mutex<PerContextState>>>>`, with discipline-enforced lock ordering across 4 lock types and `relock_context` call sites scattered across 8 submodules of `context/manager/`. `MlsCryptoProvider` carries 5 `std::sync::Mutex` fields with no documented order. `pending_joins: Mutex<Option<PendingJoinState>>` is a single global slot serializing all Welcome-processing across every context and identity in the process. 64 `block_in_place` sites across the runtime and transport crates make `current_thread` tokio runtimes infeasible.

Five concurrency defect categories stay open by discipline only:

1. **Lock ordering** — 4 lock types, comment-enforced.
2. **Deadlock** across cross-context operations that grab ≥2 locks.
3. **Generation wiring** — `relock_context` across 8 submodules, a permanent audit burden.
4. **TOCTOU** windows when locks are dropped mid-operation.
5. **Sequence-number rollback** on failed sends — discipline-enforced via `rollback_sequence_number`.

Every new protocol feature risks a deadlock or TOCTOU regression. The `block_in_place` usage breaks `#[tokio::test]` (defaults to `current_thread`) and any FFI embedder that hands SCP a single-threaded runtime. This has been working, but it is the kind of "correct by discipline" foundation that compounds cost over time and is a walking source of future defects.

## Decision

Replace the lock-based model with one tokio task per live context that owns `&mut PerContextState` by move. All state mutation happens inside a command dispatch loop. No interior locks. Cross-context operations go through a supervisor-driven saga coordinator so actors never await each other.

### 1. ContextActor owns state by move

One `tokio::task` per live context. The actor's `run()` loop is a `tokio::select!` with four arms: inbox command dispatch, TTL timer, governance timeout, coalesced-persistence tick. Commands are domain-grouped sub-enums carried by a `ContextCommand` outer enum (Messaging, Lifecycle, Governance, Broadcast, Economy, TrustRecovery, Standing, TtlClose, Tools, Queries, SagaPhase, LifecycleControl). Each carries `oneshot::Sender<Result<T>>` for the reply.

Handler functions take `&mut PerContextState` and `&ActorDeps`, return `Outcome<T> { result, mutated: bool }`. Only handlers that actually mutate state set `mutated: true`; the actor uses this to decide whether to mark the state dirty for coalesced persistence.

`PerContextState` is a discriminated union (`ContextModeState::Encrypted(ContextCryptoState)` or `ContextModeState::Broadcast(BroadcastState)`). Broadcast contexts are full actors with the same command-dispatch shape; only the mode-specific state field differs.

### 2. Supervisor is a plain struct, not an actor

Lookups are on the hot path of every public API call. Making the supervisor an actor would add a mailbox hop to every call. Instead:

- `DashMap<String, ContextActorHandle>` for actor registry
- `ArcSwap<HashMap<String, DID>>` for standing contexts
- `ArcSwap<HashSet<DID>>` for local DIDs
- `DashMap<DID, ArcSwap<WrappingKeyPair>>` for per-identity wrapping keys
- `tokio::sync::Mutex<()>` write-lock serializing all mutations of the above

Read path is lock-free via `DashMap::get` + `ArcSwap::load`. Write path acquires `write_lock` before touching any ArcSwap/DashMap.

Strict hierarchy, no cycles: Supervisor → ContextActor → (KeyPackageStoreActor | KeyCustody | TransportActor). Never ContextActor → ContextActor directly.

### 3. Cross-context saga for atomicity across 2+ actors

Standing-pair creation, cross-context tool invocation, context migration, and broadcast-hosting handshake all cross two actors. Without cross-actor awaiting, they use a supervisor-driven saga with a durable journal:

- **States:** `Initiated → PreparingA → PreparingB → Committing → Committed | Aborting → Aborted | NeedsRepair`
- **Per-actor Prepare** stages the mutation in `PerContextState.saga_pending`; no real state change yet
- **Commit** applies the mutation; duplicate-by-saga-id dedup for retries
- **Abort** drops the staged mutation

Journal is append-only, durable per phase (no coalescing). `SagaJournal::load_unresolved` returns latest-per-saga for startup replay. `mark_resolved(saga_id, terminal, secret_bearing: bool)` synchronously overwrites on-disk evidence for secret-bearing sagas (no waiting for compaction). Backends that cannot provide at-rest encryption (e.g. `FilesystemStorage` default) refuse to host secret-bearing sagas; construction fails closed.

Concurrent sagas against the same actor are **serialized** — at most one `saga_pending` entry per actor. A second Prepare while one is pending returns `SagaRejected { reason: SagaBusy }`. This preserves the "Commit must eventually succeed" property without Commit-time revalidation branches.

**Commit retry policy:** per-phase timeout 30s; Commit retries 3× with 500ms/1s/2s delays, then journals `NeedsRepair` and returns `SagaCommitFailed` to the caller. Operator uses `repair_saga(saga_id)` admin command or process restart to re-drive. No indefinite retry loop, no "log and hope."

### 4. Migration carries a commitment, not a bearer artifact

Migration's `SagaPreparedState` stores `handover_commitment = SHA-256(domain_separator ‖ handover_envelope ‖ nonce)` in the journal, constructed per spec §9.4.3 (16+-byte per-saga-type domain separator, 32-byte OsRng nonce, nonce-reuse forbidden). The actual `CustodyHandover` (bearer artifact) stays in `PerContextState.saga_pending` with `Zeroizing`-wrapped bytes and rolls back on snapshot recovery if the actor crashes. The journal alone cannot replay a migration Commit — crash recovery requires both the journal and the surviving actor-local state.

### 5. `OwnedIdentityDid` via module visibility, not `pub(crate)`

The token that proves an actor owns a given identity is a type declared inside a private `identity_capability` module within `supervisor/`. Constructor is `pub(super)`, only callable from the supervisor module. Handler code in `actor/handlers/` cannot name the constructor's path; the compiler refuses, not CI.

Explicit non-derives: no `Clone`, `Copy`, `Serialize`, `Deserialize`. `#![deny(unsafe_code)]` at the supervisor module prevents unsafe `Send` impls. No public re-export — the type is reachable only as `&OwnedIdentityDid` on `SupervisorHandle` method signatures.

`SupervisorHandle` methods that touch per-identity state take `&OwnedIdentityDid`; there is no method accepting `&DID` and returning identity state. The only identity an actor can read is the one that owns it.

### 6. `ContextCryptoProvider` (26 methods) is deleted; replaced by two narrow traits

The old trait conflated MLS primitives, SCP orchestration, and state management. The replacement:

- **`MlsBackend`** (~10 methods): create_group, add_member_raw, remove_member_raw, encrypt, decrypt, process_commit, advance_epoch, validate_key_package, generate_key_package, join_from_welcome. State flows in as `&mut ScpMlsGroup` parameters; trait owns no state. Mockable for per-primitive error injection.
- **`HpkeBackend`** (~3 methods): seal, unseal, generate_wrapping_keypair. Same shape.

Orchestration (`seal`, `open`, `rotate_sender_key`, `execute_revoke`, etc.) moves to handler functions on `&mut PerContextState`. State management (export/restore crypto state, destroy group, etc.) moves to inherent methods on `PerContextState`. Sender-key AES-GCM is direct calls to `aes-gcm` — not behind a trait, because trivial failure cases don't justify mock overhead and the dangerous failure modes (nonce reuse, missing AAD) are construction defects that no trait catches.

### 7. Async provider traits everywhere, `block_in_place` deleted workspace-wide

All remaining provider traits (`ContextTransportProvider`, `ContextPersistence`, `ContextEventLogProvider`, `EventLogPersistence`, `RelayPersistence`, `RecoveryBackend`, new `OpenMlsStorageAdapter`) become `async` via `#[async_trait]` (dyn-compatible; RPITIT is not). `is_connected` stays sync (reads an `AtomicBool`). All 64 `block_in_place` sites outside the OpenMLS-storage-adapter and FFI sync boundaries are deleted. `SqliteStorage` wraps every `rusqlite` op in `spawn_blocking`. Every transport and storage call inside a handler wraps `tokio::time::timeout(30s, ...)`.

This enables `current_thread` tokio runtimes (test default, FFI embedders), which the prior discipline-enforced `multi_thread` requirement broke.

### 8. `SequenceReservation` RAII

Sequence numbers are reserved by a `SequenceReservation` guard. Rollback fires on `Drop` unless `commit()` is called. Combined with actor-owned state (respawn loads a snapshot that predates any in-flight reservation), sequence monotonicity holds across panics, cancellations, and early `?` returns.

### 9. Persistence: coalesced by default, sync for safety-critical

Default: 50ms write-coalescing per actor. Synchronously persisted (no coalescing) before the mutation is visible to any observer:

- MLS epoch advance, sender-key rotation, event log append (chain integrity)
- `execute_revoke`, **UCAN issuance/attenuation/revocation**, **role assignment/demotion/blocklist updates**, wrapping-key rotation (forward-secrecy class: any downward authorization transition)
- Saga phase transitions in the journal, `saga_pending` Prepare/Commit/Abort transitions in the actor snapshot
- KeyPackage consumption (Welcome idempotency)

Coalesced operations may roll back up to 50ms on actor crash. This is a caller-visible guarantee change from the pre-refactor model (everything was under-lock durable at every caller ack). Documented in release notes. Authorization-state persistence rule, stated as an invariant: **any operation that transitions a member's authorization downward is sync-persisted; rollback would re-grant authority that was meant to be removed.**

### 10. Actor panic recovery

Supervisor `actor_watchdog` catches panics. Log records `actor_kind`, `context_id`, panic count, and `panic_location` from `std::panic::Location`. The panic payload itself is never formatted into the log — Rust panic messages interpolate locals via `format!` and an MLS-encrypt panic could otherwise spill plaintext or key bytes. CI bans `panic!`, `unreachable!`, `unimplemented!`, `todo!`, and `assert*!` outside `#[cfg(test)]` in `crates/scp-runtime/src/context/actor/handlers/`.

Respawn budget: 3 crashes in 60s poisons the context. No infinite respawn loop; operator intervention required to recover.

### 11. `BridgeInstanceCore` lifecycle methods are default trait impls

Per ADR-048, `BridgeInstance` splits into per-bridge concrete structs sharing a `BridgeInstanceCore` trait. This ADR extends `BridgeInstanceCore` with default trait methods for `suspend()`, `resume()`, `shutdown()`. Per-bridge structs override only bridge-specific cleanup hooks (`pre_suspend_hook`, `post_suspend_hook`, etc.). All three non-WASM bridges share one implementation. Cross-bridge consistency check (#1543) extends to verify all bridges use the defaults.

## Rejected alternatives

### Keep `Arc<Mutex<PerContextState>>`, just delete `relock_context`

Closes defect categories (1)-(5) at ~15% of the churn. Rejected because it serves none of the interrelated secondary goals: `current_thread` viability (still needs `block_in_place` elimination), type-system-enforced correctness (the mutex remains a discipline-enforced "don't hold across await" invariant), and future-review-burden reduction (new features still reason about lock ordering and await holding). The full refactor is more work now but pays the one-time cost pre-1.0 when no external state has to survive it.

### Introduce an `IdentityActor` per local DID

Symmetric with per-context actor; would own KeyPackage pool, wrapping keys, recovery state, DID doc cache, etc. Rejected because (a) per-identity state is a grab-bag of orthogonal subsystems with no cross-subsystem invariant that actor-serialization would protect — forcing them into one actor creates a synthetic bottleneck; (b) cozy-fluttering-rose Phase 4 committed petname/handle/scope to per-`SCP` typed fields, and `IdentityActor` would reverse that within 2-3 PRs ("no DOA decisions" violation); (c) the one genuine per-identity mutation hotspot (KP pool) already has its own actor (`KeyPackageStoreActor`). Scattered-with-principled-homes is the chosen approach.

### `RuntimeAdapter` trait abstracting tokio/WASM runtime primitives

Proposed trait with `spawn`, `channel`, `sleep`, `interval` methods, two impls (native/WASM). Rejected because `scp-runtime` remains native-only per ADR-034, the adapter has exactly one real implementation, and WASM consumers continue through `scp-ffi/wasm`'s re-implementation path. Direct `tokio::*` calls are simpler. If a second runtime target ever enters scope, introduction is a mechanical refactor at that point.

### Preserve `ContextManager` as a facade over `Supervisor`

Would avoid churning FFI bridges and SDK bindings. Rejected as a DOA decision (CLAUDE.md "no DOA decisions" tenet): a facade that exists only to avoid migration cost, knowing it needs to go later, is exactly what the tenet forbids. Pre-1.0 with no external users is the cheapest time to pay the churn.

### Keep `ContextCryptoProvider` (26 methods), just redesign method signatures

Fixes state ownership (methods take `&mut ContextCryptoState`) but preserves the level-conflation (orchestration in a "crypto provider" trait). Rejected; orchestration moves to handler functions and the trait splits into the two narrower backends.

### Combine `MlsBackend` + `HpkeBackend` into one trait

Rejected; MLS ops and HPKE ops are independent primitives. Tests may mock one without the other. Keeping them split matches the actual abstraction boundary.

## Consequences

**Positive.** All five defect categories close by construction. `current_thread` tokio becomes viable — tests no longer need to annotate `multi_thread`, FFI embedders can run SCP on host-supplied event loops. New features become "add a command variant plus a handler function"; blast radius for adding a protocol feature collapses from 8-submodule lock-ordering reasoning to one handler file. The `pending_joins` global serialization point is gone. MLS crypto state is per-actor.

**Trade-offs accepted.**

- **50ms coalesced-persistence rollback window on actor crash.** Not a security regression (all authorization-downward operations are sync-persisted), but a behavioral change for participation counters, velocity trackers, and non-critical state. Documented in release notes.
- **`async_trait` heap allocation per trait method call.** Negligible vs MLS crypto operation cost.
- **Per-identity state scattered.** Reader-side discipline required for `Arc<WrappingKeyPair>` (load → use → drop within same poll), enforced by CI.
- **Saga `NeedsRepair` requires operator action.** Runbook `.docs/runbooks/saga-needs-repair.md` documents detection (`saga_repair_needed` metric), inspection, and `repair_saga(saga_id)` admin command.
- **Pre-existing dev-database snapshots do not load.** The schema-version check fails with `ContextError::UnsupportedSnapshotVersion`. No migration code; pre-1.0 has no deployed state to preserve.
- **Test mocks rewritten.** The ~20 existing `impl ContextCryptoProvider` mocks migrate to `MlsBackend` (~10 methods) and/or `HpkeBackend` (~3 methods) — net smaller mock surface per test, more mocks overall because most tests touch both.
- **~13 internal commits.** Large single atomic PR; expected 6–12 full-roster review rounds to double-zero.

**WASM.** Unchanged. `scp-runtime` stays native-only per ADR-034. The actor model does not run in the browser with native parity; `scp-ffi/wasm` continues its re-implementation path.

**Bindings.** Every FFI bridge and language SDK rewires from `ContextManager` (deleted) to `Supervisor` (new). SCP class surface (post-ADR-048) is unchanged — the refactor is internal to `scp-runtime`.

**Dependencies.** Adds `shuttle` (model checker, dev-only) and `tree-sitter-rust` (AST check tooling, dev-only) to the dev-dependencies.

**Performance.** No baseline measured and none required — correctness is the pre-1.0 priority. Expected overhead sources: `Box<dyn Future>` allocation per `async_trait` call, mailbox send+recv+oneshot reply per command, journal write per saga phase transition, `spawn_blocking` hop per SQLite op. No performance tooling is added by this ADR.

## Verification

Executable checks (each must pass on every commit of the implementation series):

```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --features scp-ffi-uniffi/allow_in_memory_custody,scp-ffi/allow_in_memory_custody,scp-ffi-napi/allow_in_memory_custody,scp-core/testing,scp-runtime/testing -- -D warnings
cargo check -p scp-protocol --target wasm32-unknown-unknown
cargo check -p scp-ffi-wasm --target wasm32-unknown-unknown
DYLD_LIBRARY_PATH=$(python3.12 -c "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))") cargo test --workspace
python3.12 scripts/check-protocol-sync.py
bash scripts/check-protocol-deps.sh
python3.12 scripts/check-block-in-place.py
python3.12 scripts/check-block-in-place.py --self-test
bash scripts/check-deleted-primitives.sh
cargo test -p scp-runtime --test persistence_ordering
cargo test -p scp-runtime --test cancel_safety
cargo test -p scp-runtime --test shuttle_actor --features shuttle
```

Plus existing E2E test suites across all four bindings.

Invariants to verify (documented in plan):

1. MLS group state integrity — every MLS op produces the same ciphertext as pre-refactor for the same inputs.
2. Send-sequence monotonicity per sender per context.
3. Receive anti-replay.
4. Merkle event log chain integrity — every `prev_hash` matches across restarts; in-memory never ahead of persisted.
5. Nonce uniqueness (OsRng-generated, never reused).
6. Key zeroization — every secret-byte sequence wrapped in `Zeroizing` for its entire memory lifetime.
7. UCAN validation unchanged.
8. Spec compliance — any ambiguity is a spec gap, update spec first.

## References

- Plan: `~/.claude/plans/generic-moseying-lightning.md` (execution detail, commit ladder, per-binding criteria, CI enforcement, failure modes)
- Spec updates (commit 2): `.docs/specs/05-contexts.md` §5.15, `09-security-model.md` §9.4.1–3, `17-persistence-and-storage.md` §17.15–16, `architecture.md` trait contracts
- Related ADRs: ADR-034 (WASM), ADR-046 (parity), ADR-047 (symmetry), ADR-048 (multi-instance)
- Prior plans superseded: none (this is the first actor-per-context ADR)
