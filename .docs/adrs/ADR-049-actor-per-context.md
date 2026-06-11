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

**Respawn crash-safety invariant.** A context-actor respawn (or any restore from a coalesced snapshot) MUST NOT roll back a security-critical decision already acknowledged to a caller. Every security-critical, monotonic piece of per-context state is in exactly one class:

- **Class S (sync-persisted):** durably persisted synchronously BEFORE the mutating operation returns success (extends the downward-authorization rule above). Required for security state that does NOT survive an actor crash (it lives in the dead actor's `PerContextState`): membership, capability/ceiling state, lifecycle close transition, spending-nonce tracker, executed-proposals set, spending-UCAN revocation set. For these, a persist FAILURE must FAIL-CLOSED (the operation returns an error) — never best-effort-swallow that returns `Ok`.
- **Class M (crash-surviving + max-merge):** state that survives the crash in a supervisor-owned store (the MLS crypto provider `Arc`) is restored by a MONOTONIC MAX-merge of the live pre-crash value with the snapshot — never lowered, never rejected for staleness (spec §23.17.2 **Invariant 2**). Required for per-sender MLS epoch/replay floors. The reject-on-regression policy (spec §23.17.2 **Invariant 3**) applies ONLY to cross-node IMPORT (untrusted peer snapshot).
- **Forbidden — Class C (coalesced-only) for security-critical monotonic state.** Coalesced-only persistence is allowed ONLY for pure liveness/structural state and for explicitly-accepted soft anti-spam state (velocity / earned-capacity), whose ≤50ms rollback relaxes a rate limit briefly and is not an authorization break (documented accepted residual — see §10).
- **Enforcement (two complementary halves).** The invariant is enforced along the two axes a Class-S violation can take — a dropped *field* and a missed *consume site*:
  - **Field round-trip:** the structural test `security_critical_state_is_class_s_or_m_not_coalesced` populates every security-critical Class-S `GovernanceState` field with a sentinel and asserts each survives the real snapshot-build + on-disk serialization round-trip. A new field added to `GovernanceState` but not wired into the snapshot (persist) and restore is dropped by the round-trip and fails CI — catching a field that silently defaults to Class C.
  - **Consume-site fail-closed:** the gate `scripts/check-class-s-fail-closed.sh` scans every spending-nonce consume site (`commit_spending_ucan_nonce` / the shared `enforce_economy` helper / its `enforce_send_economy` / `enforce_join_economy` wrappers) and requires the acknowledging handler to persist fail-closed (`persist_state_fail_closed`) — directly, via an allowlisted pass-through helper, or via a verified persist delegate — before returning success. A new consume site that acknowledges via a best-effort persist fails CI. This is the half that catches the message-send / paid-join misses the field round-trip alone did not (all three paths consume the same nonce through the same helper but are acknowledged by different handlers).
  - The field round-trip does NOT prove every consume site is fail-closed, and the consume-site gate does NOT prove every field round-trips; neither alone is sufficient, and the enforcement claims only what the two together guarantee.

The distinction between Class S and Class M is *where the state lives across the crash*. Class S state is owned by the actor task's `PerContextState`, which is destroyed when the task unwinds — so it is only durable if it was written to the persistence backend before the caller was told the operation succeeded. Class M state (the per-sender epoch/replay floors) lives in the supervisor-owned `MlsCryptoProvider` `Arc`, which a mailbox/handle despawn does NOT tear down — so the live pre-crash floor is still in memory at respawn time and is the authoritative max-merge input, exactly as spec §23.17.2 Invariant 2 prescribes for a node restoring its own snapshot.

### 10. Actor panic recovery

**As-built design.** Each per-context actor is spawned by `Supervisor::spawn_actor_with_watchdog`, which KEEPS the actor task's `JoinHandle` (the pre-watchdog spawn dropped it, silently swallowing panics and wedging the context) and hands it to a detached per-actor watchdog task. The watchdog is started via the free function `spawn_actor_watchdog_task` (NOT an inline `tokio::spawn`) so the watchdog future's `Send` proof resolves outside the opaque `impl Future` scope of the spawn method — the watchdog reaches `respawn_from_snapshot → restore_context → spawn_actor_with_state → spawn_actor_with_watchdog`, a self-referential async cycle the compiler refuses to resolve if the spawn is inline. The watchdog task is deliberately NOT placed on the supervisor timer `JoinSet`; it owns the actor `JoinHandle` directly.

**Panic detection + payload-free logging.** `actor_watchdog` awaits the actor `JoinHandle` and inspects the `JoinError` ONLY via `is_panic()` (a bool). A clean return (`Ok`) or a non-panic `JoinError` (cancellation/abort) is not a crash. A panic records a crash and logs `actor_kind`, `context_id`, `crash_count`, `poisoned`, and `panic_location = "unknown"`. The panic payload itself is NEVER read or formatted (`into_panic()` / `payload()` / `{:?}` on the `JoinError` are forbidden) — Rust panic messages interpolate locals via `format!`, and an MLS-encrypt or key-derivation panic could otherwise spill plaintext or key bytes. `panic_location` is hardcoded `"unknown"`: a process-global "last panic location" store would be racy across threads and multiple supervisors AND a mutable global (forbidden by the `check-no-mutable-globals` gate), so the payload-free floor is chosen deliberately over a racy, possibly-wrong location. CI bans `panic!`, `unreachable!`, `unimplemented!`, `todo!`, and `assert*!` outside `#[cfg(test)]` in `crates/scp-runtime/src/context/actor/handlers/` AND in `crates/scp-runtime/src/context/actor/mod.rs` (the dispatch hub), via `scripts/check-handler-no-panic.sh`. The single allowed exception is the `#[cfg(feature = "testing")]` `TestInducePanic` fault-injection seam in `actor/mod.rs`, which exists solely to exercise the watchdog deterministically and cannot exist in a production build.

**Respawn budget + poison.** 3 crashes within a sliding 60s window poisons the context (the budget is the `CrashWindow` per-context state, keyed in the supervisor's lock-free `crash_windows` `DashMap`). Below the threshold the watchdog respawns from the persisted snapshot via `respawn_from_snapshot`, which reuses the shared `restore_context` primitive to rehydrate the FULL `PerContextState` (governance, MLS crypto, §9.10.4 routing/pseudonym registry, rate-limit). A failed respawn (lost/corrupt snapshot) is itself counted as a crash so a reliably-failing snapshot poisons rather than looping forever, and sets a per-context `last_respawn_failed` flag so a per-context lookup-miss surfaces `ActorCrashed` (SCP-CTX-2135) rather than a misleading `ContextNotRegistered`. Once poisoned, the actor is despawned and stays dormant; `read_context_state` reports `Poisoned` (read from the sticky `crash_windows` flag, since the actor is gone), and any per-context dispatch surfaces `ContextPoisoned` (SCP-CTX-2134). No infinite respawn loop; recovery is operator-driven (`SupervisorHandle::clear_poison`, which clears the window and attempts one respawn) or a process restart (which re-runs `restore_all_contexts`; the poison record is in-memory and does not survive a restart).

**Recovery-surface honesty (mirrors §12a's webhook-deferral disclosure).** `SupervisorHandle::clear_poison` is a Rust-core recovery primitive that is **not yet wired to an FFI/operator-facing surface** — no bridge exports it and no SDK wrapper calls it. The complete, tested end-to-end recovery path available to a deployed node today is therefore a **process restart** (which re-runs `restore_all_contexts` and drops the in-memory poison record). `clear_poison` is exercised by Rust-core tests and is ready for an operator surface to call, but until that surface lands, "operator-driven recovery" in production means restart. This asymmetry is recorded here in the system of record rather than only in code comments, exactly as the §12a webhook-target deferral is.

**Coalesced soft anti-spam residual (accepted).** The per-context `velocity_tracker` (sender velocity, §anti-spam) and `earned_capacity` state are deliberately left on the coalesced (Class C) persistence path, NOT sync-persisted. A crash can roll these back by up to one coalesce interval (≤50ms, ADR §9). The consequence is bounded and accepted: a ≤50ms rollback of velocity/earned-capacity briefly *relaxes* a soft rate limit (a sender that just spent its velocity budget may regain a sliver of it), which is an availability/anti-spam softening, NOT an authorization break — it never re-grants a removed capability, never lowers a replay floor, and never resurrects a revoked token. These are the only security-adjacent fields the crash-safety invariant (§9) classifies as Class C, and the reason is recorded here so a future change does not silently reclassify a true authorization field the same way.

**Standing-context auto-revive residual (BLACK-002, observable, accepted).** A poisoned *standing* context (a deterministic standing-pair id) is auto-revived on the next re-contact: `standing_context` unconditionally `reset_crash_window`s the id (a deliberate recreate is a fresh budget — see *Crash-window hygiene* above), which clears the poison. A peer that can repeatedly trigger re-contact can therefore keep re-arming a context that crashes deterministically, rather than leaving it dormant after the budget is exhausted. This is observable (the revive emits a distinct `tracing::warn!("poisoned standing context auto-revived on re-contact")`) and bounded (each revive still consumes the full 3-crash budget before re-poisoning, so the attacker pays the budget every cycle and cannot achieve an unbounded tight loop). Hardening this into a rate-limited revive (backoff on repeated standing-context poison) is a tracked follow-up; the residual is documented here rather than silently left in code.

**Anti-resurrection precondition.** `respawn_from_snapshot` only respawns an `Active` snapshot. A crash during/after a terminal state (`Closing`/`Closed`/`Expired`/`MigratingOut`/`Tombstoned`) is NOT respawned (mirroring the `state != Active` skip `restore_all_contexts` applies at startup) and is not counted as a crash — a terminal context is the expected end state of a clean close/expire, not a fault to recover. The context is left dormant.

**Crash-window hygiene.** `crash_windows` entries are reaped on a clean (non-poison) shutdown and reset on an explicit (re)create/import/standing-recreate of the same id, so a re-created deterministic id (e.g. a standing-pair id) does not inherit stale crash history or a sticky poison. Poison entries survive a clean despawn (so the dormant-poison signal persists) and are removed only by `clear_poison`, an explicit recreate, or a restart.

**No health-sweep backstop needed.** ADR §10 originally sketched a supervisor health-sweep that would also catch a watchdog task panicking. The as-built watchdog body is panic-free by construction: it only awaits the `JoinHandle`, records crash timestamps into a `DashMap`, logs through `tracing` with payload-free constant-shaped fields (no fallible `format!` over runtime panic data), and calls `respawn_from_snapshot` (which returns typed `Result`, never panics). There is therefore no fallible-formatting or unwrap path in the watchdog that a backstop would protect, so the per-actor `JoinHandle` model carries no health-sweep backstop. If a future change introduces a fallible operation into the watchdog body, a `JoinSet`-based backstop must be added at that time.

**Crash/poison consumer-surfacing boundary (mirrors the §12a webhook-deferral note).** Poison and crash are surfaced to FFI/SDK consumers **via a typed error code on the next per-context operation**, NOT through the cheap cached per-handle state getter. Concretely:

- The watchdog poisons supervisor-side (the sticky `crash_windows` flag) and despawns the actor; it deliberately does **not** reach back into any per-FFI-handle cached `Mutex<ContextState>`. That cache is a best-effort, cheap snapshot taken at the last observed transition — by design it is not a live supervisor read (changing it to one would defeat its O(1), lock-light purpose and add a mailbox round-trip to every `state()` call). After a crash/poison the cached getter may therefore still report the last-known non-terminal state (e.g. `active`); the `Poisoned => "poisoned"` arm in the FFI `state()` mappers is reachable only when a snapshot/restore path actually wrote `Poisoned` into the cache, not on the watchdog poison path.
- The **authoritative** consumer signal is the error code on the next per-context operation: `SCP-CTX-2134` (`ContextPoisoned`) once the budget is exceeded, and `SCP-CTX-2135` (`ActorCrashed`) for the crashed-but-not-yet-poisoned / mid-respawn window (see `Supervisor::lookup_miss_error`). Any per-context dispatch (send, governance, query, …) against a poisoned/crashed context fails closed with these codes. SDKs surface poison/crash by catching these on the operation result, not by polling `state()`.
- Operator recovery is **not** an SDK call: it is `SupervisorHandle::clear_poison` (clear the window + attempt one respawn) or a process restart (re-runs `restore_all_contexts`; the poison record is in-memory and does not survive a restart). The cached `state()` getter remains best-effort and is documented as such at each bridge.

This boundary is the same shape as §12a's webhook-target deferral: the durable, tested signal path (error codes on operations) is complete; the cheap cached getter is intentionally not promoted to a live read, and that asymmetry is recorded here in the system of record rather than only in code comments.

### 11. `BridgeInstanceCore` lifecycle methods are default trait impls

Per ADR-048, `BridgeInstance` splits into per-bridge concrete structs sharing a `BridgeInstanceCore` trait. This ADR extends `BridgeInstanceCore` with default trait methods for `suspend()`, `resume()`, `shutdown()`. Per-bridge structs override only bridge-specific cleanup hooks (`pre_suspend_hook`, `post_suspend_hook`, etc.). All three non-WASM bridges share one implementation. Cross-bridge consistency check (#1543) extends to verify all bridges use the defaults.

### 12. Lock-free read invariant

`tokio::sync::RwLock` and `tokio::sync::Mutex` are FORBIDDEN on read paths — anything that runs more than once per command dispatch. Allowed read primitives are `OnceLock`, `ArcSwap`, `AtomicU64`, `DashMap`, and the actor-owned `&mut PerContextState` borrow.

Empirical justification: OpenSSL issue [#30659](https://github.com/openssl/openssl/issues/30659) ("Analysis of read locks taken while handshaking") measured `RWLOCK_read_lock` at ~67 cycles per acquire even uncontended vs `__atomic_load_n(__ATOMIC_RELAXED)` at ~17 cycles — a 4× hot-path cost. PR [#30670](https://github.com/openssl/openssl/pull/30670) (merged 2026-04-14) applied the TTAS fix; visible gains on `randbytes`, zero gains on `handshake` (rand was 4% of work; contention shifted to other locks). The takeaway: callsite-cost dominates uncontested-acquire frequency, and lock-elimination at one site shifts contention to whichever site is now the next-most-loaded — not necessarily a macro win.

Our `OnceLock<Arc<dyn …>>` for `crypto`/`transport`/`event_log`/`clock`/`key_resolver` is the Rust equivalent of OpenSSL's TTAS pattern. Doc comments on these accessors should name the lineage ("lock-free read per ADR-049 §Decision 12; same pattern as OpenSSL's `__atomic_load_n` TTAS").

Enforced via `crates/scp-runtime/clippy.toml`:

```toml
disallowed-types = [
    { path = "tokio::sync::RwLock", reason = "ADR-049 §Decision 12: forbidden on read paths. Use OnceLock/ArcSwap/AtomicU64/DashMap." },
    { path = "tokio::sync::Mutex",  reason = "ADR-049 §Decision 12: forbidden on read paths. Use ArcSwap+write_lock or Mutex<PerContextState>." },
]
```

Allow-list (sites that legitimately use these primitives):

- Actor-owned `Mutex<PerContextState>` (per-context mailbox holder).
- `Supervisor::write_lock: tokio::sync::Mutex<()>` (write serialization for the ArcSwap+write_lock pattern).
- OpenMLS storage adapter internals (sync upstream trait).
- FFI sync boundaries.

The clippy rule lands in commit 13 of the ADR-049 ladder (Phase 3 of the post-review-round-1 plan); commit 12 already conforms to the rule.

### 12a. Event-channel observer surface

The `Supervisor` owns a `broadcast::Sender<(String, ContextEvent)>` in a `OnceLock` (`event_tx`). `Supervisor::subscribe_events()` is the public, read-only observer surface: it returns `Some(broadcast::Receiver)` when the channel is enabled, `None` otherwise. The per-context actors emit `(context_id, ContextEvent)` onto this sender via `emit_event_into` (payloads stripped of plaintext first — see `strip_event_payload`); the FFI node-startup path subscribes once and drives the outbound webhook dispatcher (spec §12.10.5).

This is lock-free-read-compliant under §Decision 12: `subscribe()` is called **once, at node startup**, not on a per-command read path. The `RwLock`-per-acquire cost that Decision 12 forbids is a hot-path concern — `subscribe_events()` is cold (one call per node), so it does not apply. The emit path itself touches only the `OnceLock`-resident sender (`broadcast::Sender::send` is lock-free for the fast path), consistent with the allowed read primitives.

Production supervisors enable the channel **unconditionally** — each FFI bridge's `build_supervisor` passes `Some(event_tx)`, so `subscribe_events()` always yields a receiver in production. Query/test shims (e.g. `Supervisor::for_query_shim`) may construct a supervisor with no channel; for those `subscribe_events()` returns `None` and observers skip wiring rather than panic. The asymmetry is intentional: the channel exists to feed external sinks (webhooks, SDK listeners), which only matter when a node is actually running.

**Scope of the current wiring.** The subscribe → map → dispatch path is wired end-to-end: a `ContextEvent` emitted by a context actor reaches the `WebhookDispatcher`. What is **not** yet wired in production is the dispatcher's *outbound target registration* — there is no operator-facing surface that registers webhook URLs/signing keys onto the dispatcher's target table. The dispatcher therefore holds zero targets at runtime, and `dispatch_event` is a no-op fan-out until such a surface exists; delivery is end-to-end only once an operator-facing target-registration API drives `WebhookDispatcher::register`. The event *plumbing* is complete and tested; actual outbound delivery is gated on that future operator-config surface. Until it lands, the only consumers exercising the full path are the integration tests, which register targets directly (see `scp-node/tests/webhook_event_wiring.rs`).

### 13. Lock-elimination validation gate (general rule)

Every commit that deletes or splits a serializing primitive needs a Shuttle/stress test under realistic I/O jitter, asserting:

1. Correctness: no deadlock, no stuck mailboxes, sequential equivalence.
2. No other lock now shows >2× the prior acquire count (no whack-a-mole contention shift — see Decision 12's OpenSSL evidence).

Generalizes the OpenMLS shared-storage gate: any commit that deletes the 5 `std::sync::Mutex` fields off `MlsCryptoProvider` or splits the `pending_joins` global slot into per-actor scratchpads triggers this gate. Coverage path: existing `shuttle_actor` test + persistence-ordering tests + new acquire-count threshold instrumentation. The instrumentation lands in commit 13 alongside the `perf_baseline` test.

### 14. Performance regression as a rollback trigger

Pre-merge baseline + post-merge measurement on six operations at N=1/4/16:

- `handshake` (welcome + keypackage + add_member)
- `send_message`
- `deliver_incoming`
- `governance_propose`
- `broadcast_publish`
- `broadcast_subscribe`

A regression of >15% on any (operation, N) pair triggers §Rollback strategy trigger #4. The baseline + post-merge measurement is implemented in `cargo test -p scp-runtime --test perf_baseline`, landing in commit 13 of the ADR-049 ladder (Phase 4 of the post-review-round-1 plan).

Mandatory coverage: BOTH workload classes (crypto-dominated AND protocol-overhead-dominated) AND BOTH read fast path AND write slow path. The handshake path is crypto-dominated; the broadcast publish/subscribe path is overhead-dominated; that pair stresses both classes.

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

### Convert `local_dids` / `standing_contexts` from `ArcSwap` to `tokio::sync::RwLock` for callsite parity

Proposed on the grounds that the rest of the supervisor's mutable state lives behind `tokio::sync::Mutex` (the per-context `Mutex<PerContextState>`), and aligning the read path on `RwLock` would simplify reasoning at the callsites. Rejected on Decision 12 grounds + the OpenSSL evidence underlying it: the per-acquire `RwLock::read()` cost is paid forever at every read; the one-time callsite migration cost to the lock-free `ArcSwap`/`OnceLock` pattern is paid once. The performance-rollback trigger (Decision 14) treats this kind of regression as merge-blocking. Any future proposal to convert hot-path read paths to `RwLock` should be redirected here.

## Consequences

**Positive.** All five defect categories close by construction. `current_thread` tokio becomes viable — tests no longer need to annotate `multi_thread`, FFI embedders can run SCP on host-supplied event loops. New features become "add a command variant plus a handler function"; blast radius for adding a protocol feature collapses from 8-submodule lock-ordering reasoning to one handler file. The `pending_joins` global serialization point is gone. MLS crypto state is per-actor.

**Trade-offs accepted.**

- **50ms coalesced-persistence rollback window on actor crash.** Not a security regression (all authorization-downward operations are sync-persisted), but a behavioral change for participation counters, velocity trackers, and non-critical state. Documented in release notes.
- **`async_trait` heap allocation per trait method call.** Negligible vs MLS crypto operation cost.
- **Per-identity state scattered.** Reader-side discipline required for `Arc<WrappingKeyPair>` (load → use → drop within same poll), enforced by CI.
- **Saga `NeedsRepair` requires operator action.** Detection (`saga_repair_needed` metric), inspection, and `repair_saga(saga_id)` admin command are documented in a runbook that ships with the implementation commits (per the plan's doc-deliverables list), at `.docs/runbooks/saga-needs-repair.md`.
- **Pre-existing dev-database snapshots do not load.** The schema-version check fails with `ContextError::UnsupportedSnapshotVersion`. No migration code; pre-1.0 has no deployed state to preserve.
- **Test infrastructure (as built).** The plan called for the ~20 existing `impl ContextCryptoProvider` mocks to migrate onto the new `MlsBackend`/`HpkeBackend` traits. What was actually built diverges and is recorded here so a fresh agent is not misled:
  - `MockCrypto` and the `ContextCryptoProvider` trait were **deleted outright**, not migrated. There is no per-primitive mock backend in operational use.
  - The runtime binds the **concrete `MlsCryptoProvider`** everywhere, including in tests. Test accommodations are `cfg!(any(test, feature = "testing"))`-gated *inside the concrete provider* (e.g. accepting `did:key`/`did:test` identities and a `None` key-package) rather than swapped in via a mock impl.
  - The fullstack E2E harness was re-wired over the concrete provider plus a shared `KeyExchange` side-channel (commit `12c.9f`) that relays the Welcome/key material between independent nodes' `E2eCryptoProvider`s — there is no in-process mock crypto.
  - The `MlsBackend` injection seam (`with_backends`) exists in the type surface but is **operationally dead**: no production or test path swaps a backend through it; the only coverage is `Arc::ptr_eq` identity asserts proving the seam wires the same instance. It is retained as a future injection point, not an active mock surface. Any future work that needs per-primitive crypto error injection should revive this seam rather than reintroduce a `ContextCryptoProvider`-style omnibus mock.
- **~13 internal commits.** Large single atomic PR; expected 6–12 full-roster review rounds to double-zero.

**WASM.** Unchanged. `scp-runtime` stays native-only per ADR-034. The actor model does not run in the browser with native parity; `scp-ffi/wasm` continues its re-implementation path.

**Bindings.** Every FFI bridge and language SDK rewires from `ContextManager` (deleted) to `Supervisor` (new). SCP class surface (post-ADR-048) is unchanged — the refactor is internal to `scp-runtime`.

**Dependencies.** Adds `shuttle` (model checker, dev-only) and `tree-sitter-rust` (AST check tooling, dev-only) to the dev-dependencies.

**Performance.** Baseline measurement is mandatory per Decision 14 — pre-merge baseline + post-merge measurement on six operations (`handshake`, `send_message`, `deliver_incoming`, `governance_propose`, `broadcast_publish`, `broadcast_subscribe`) at N=1/4/16. A regression of >15% on any (operation, N) pair triggers §Rollback strategy trigger #4. The baseline harness lands as `cargo test -p scp-runtime --test perf_baseline` in commit 13.

Expected overhead sources: `Box<dyn Future>` allocation per `async_trait` call, mailbox send+recv+oneshot reply per command, journal write per saga phase transition, `spawn_blocking` hop per SQLite op. The lock-free read invariant (Decision 12) keeps the hot read paths off the `RwLock::read` cost cliff documented in OpenSSL #30659 (~67 cycles per uncontended acquire vs ~17 for `__atomic_load_n`).

Workload sensitivity: handshake is crypto-dominated (overhead is a small fraction); broadcast publish/subscribe is overhead-dominated (mailbox + journal allocations are visible). The baseline harness covers both classes plus both fast and slow paths.

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

## Follow-ups (sequenced, in the system of record)

These are deferred work items surfaced by the implementation. They are recorded here — not only in commit messages and code comments — so they remain in the system of record.

1. **Spawn-from-Welcome entrypoint.** A Supervisor entrypoint that spawns a per-context `ContextActor` from a *received* Welcome and injects the access/sender keys the joiner picks up while processing it. Without it, a Welcome-joined node has a populated `E2eCryptoProvider` (it can DECRYPT) but no actor-backed send `ContextHandle`, so any send fails closed with "context not found in node's handles" — only the unidirectional path (creator sends, joiner decrypts) works.

   - **Sequencing / ownership.** This is the same gap as, and belongs to, the existing **Welcome-Delivery** effort (relay-mediated Welcome distribution across processes). The actor-spawn-on-Welcome step is the `scp-runtime` half of that work and should land as part of it, not as a standalone change.
   - **Why deferred here.** The actor-per-context refactor deliberately scoped to the creator-side spawn paths (`create_context`, standing-context bootstrap). Adding a join-side spawn path that also threads picked-up keys into a fresh actor is its own design surface (key-injection ordering vs. the actor snapshot model in Decision 1/8/9) and was kept out of this ADR's atomic PR.
   - **Tripwires already in place.** The fullstack bidirectional fail-closed assertions in the Python and TypeScript E2E suites are intentional reverse-tripwires: they assert the *current* one-way contract and will fail the moment joiner-send begins working, forcing them to be rewritten into real bidirectional roundtrips when this entrypoint lands. The PyO3 and NAPI `fullstack_join_from_welcome*` doc comments document the same contract.

## References

- Plan: `~/.claude/plans/generic-moseying-lightning.md` (execution detail, commit ladder, per-binding criteria, CI enforcement, failure modes)
- Spec updates (commit 2): `.docs/specs/05-contexts.md` §5.15, `09-security-model.md` §9.4.1–3, `17-persistence-and-storage.md` §17.15–16, `architecture.md` trait contracts
- Related ADRs: ADR-034 (WASM), ADR-046 (parity), ADR-047 (symmetry), ADR-048 (multi-instance)
- Lock-free read evidence (Decisions 12–14): OpenSSL issue [#30659](https://github.com/openssl/openssl/issues/30659) ("Analysis of read locks taken while handshaking") and PR [#30670](https://github.com/openssl/openssl/pull/30670) (TTAS fix; visible gains on `randbytes`, none on `handshake`).
- Prior plans superseded: none (this is the first actor-per-context ADR)
