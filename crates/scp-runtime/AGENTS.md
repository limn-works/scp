# scp-runtime — agent map

You are modifying SCP's async runtime. This is a map, not a manual: it tells
you where things live and which invariants will bite you. Read the root
`CLAUDE.md` first; it governs. Then read `.docs/adrs/ADR-049-actor-per-context.md`
— every concept below traces to a numbered decision in it.

## The one thing to understand: actor-per-context

One `tokio` task per live context (`ContextActor`), owning its
`PerContextState` by move. No locks on context state. A `Supervisor` (a plain
struct — deliberately not an actor) owns the registry of actor mailboxes and
every provider, and coordinates the one cross-context saga. Handlers mutate
state; the actor decides when to persist.

```
caller → Supervisor::method (lock-free lookup) → ContextActorHandle mailbox
       → ContextActor::run() select! → handlers/<domain>::dispatch
       → &mut ClassSCell (owns PerContextState) → coalesced or fail-closed persist
```

Where it lives:

- `src/context/supervisor/` — `Supervisor` (registry + saga coordinator),
  `SupervisorHandle` (the capability-reduced view actors hold), the saga
  journal, the per-identity key-package actor.
- `src/context/actor/` — `ContextActor` + `run()` loop (`mod.rs`), the
  `ContextCommand` outer enum + 12 sub-enums (`commands.rs`), the mailbox
  wrapper (`handle.rs`), `PerContextState` (`state.rs`), `ClassSCell`
  (`class_s.rs`), `ActorDeps` (`deps.rs`), and `handlers/` (one module per
  command domain).
- `src/context/*_helpers.rs` — the domain logic bodies (governance,
  lifecycle, messaging, trust_recovery, broadcast, …) that handlers call.
- `src/crypto/mls/` — the MLS subsystem (`src/crypto/mls/README.md`).

See `src/context/README.md` for the full `context/` tree.

## Invariant 1 — Class-S (fail-closed) vs Class-C (coalesced) persistence

ADR-049 §9 splits persistence into two classes, and getting this wrong is a
security bug, not a performance one:

- **Class-C (coalesced, best-effort).** Ordinary state. The actor's `run()`
  loop marks state dirty (`Outcome { mutated: true }`) and writes one
  snapshot per coalescing window. A crash can lose the last window; that is
  acceptable for Class-C fields.
- **Class-S (fail-closed).** Security-critical fields — spending-nonce
  consumption, executed-proposals, downward-authorization transitions, saga
  reservation slots. A mutation MUST be durable **before** it is acknowledged
  to the caller: a coalesced ack would let a crash roll back a mutation the
  caller already observed as committed, re-opening a replay / re-spend /
  re-grant window.

This is enforced by the **type system**, not a scanner. `ClassSCell`
(`actor/class_s.rs`) wraps `PerContextState`, exposes `Deref` (reads) but
**no `DerefMut`**, and the Class-S fields are privatized. The only way
to mutate them is through the cell's combinators, each of which persists
fail-closed by construction:

- `commit_class_s_keep` — keep the mutation on persist failure (e.g. a
  consumed replay nonce must not be un-recorded).
- `commit_class_s_restore` — roll back on persist failure.
- `commit_class_s_compensating` / `commit_class_s_keep_compensating` — plus an
  async undo of an external effect (e.g. void an escrow).
- `commit_class_s_then_append` — fail-closed persist followed by a durable
  external append (event log).
- `commit_class_c_best_effort` — the Class-C path; hands out a **field-granular**
  `ClassCMut` view (via `class_c_view()`) that is airtight by construction (it
  holds no whole `&mut PerContextState`, so no Class-S mutation is even
  nameable through it).

If you add a Class-S field or a new persist shape, do it through a combinator.
Do not reintroduce a `state_mut` escape hatch or a source-text scanner — the
retired scanner was non-convergent (a lesson the module doc-comment records).

## Invariant 2 — Send-discipline for provider traits

Actor futures are `tokio::spawn`'d, so **everything the actor awaits must be
`Send`**. That constraint shapes every provider trait:

- MLS/HPKE/storage backends (`MlsBackend`, `HpkeBackend`,
  `OpenMlsStorageAdapter`) are `#[async_trait]` (which desugars to
  `Send`-boxed futures) with a `Send + Sync` supertrait, and are dyn-erased
  as `Arc<dyn …>` so one instance is shared across every actor.
- `scp_platform::Storage` uses return-position `impl Trait` (RPITIT) and is
  therefore **not** dyn-compatible — you cannot write `Arc<dyn Storage>`.
  That is exactly why `OpenMlsStorageAdapter` exists: a dyn-compatible
  `#[async_trait]` wrapper over a concrete `S: Storage`, erased once per
  process. When you need byte-blob storage inside a handler, reach it through
  a bridge that already owns a concrete `Arc<S>` — never try to add
  `dyn Storage` to `ActorDeps`.
- `RecoveryBackend` (`identity/recovery.rs`) is the one `Send`-rule exception:
  it is the SOLE `#[async_trait(?Send)]` provider trait (every other
  ActorDeps-resident provider trait is a plain `Send` `#[async_trait]`). Its
  production impl (`ProductionRecoveryBackend`) `.await`s the supervisor mailbox
  directly. It is driven at the FFI boundary on a single task, never
  `tokio::spawn`'d, so its futures need not be `Send` (ADR-049 Decision 7).

## Invariant 3 — capability reduction (who can reach what)

- Actors hold a `SupervisorHandle`, never `Arc<Supervisor>`. The handle
  exposes no accessor returning a `ContextActorHandle`, so **an actor cannot
  reach a sibling actor** — cross-context work goes through
  `SupervisorHandle::start_saga` (ADR-049 §5). Keep it that way: do not add a
  handle method that hands back an actor handle or the raw supervisor.
- Per-identity operations take `&OwnedIdentityDid`, not `&DID`.
  `OwnedIdentityDid` (`supervisor/identity_capability.rs`) is an unforgeable
  token: its constructor is `pub(super)` and its field is private, so only
  supervisor-module code can mint one for a given DID. `supervisor/mod.rs`
  carries `#![deny(unsafe_code)]` + `#![deny(non_local_definitions)]` (closing
  the body-nested-`impl` forge vector) and a `compile_fail` doctest tripwire.
  Do not weaken those, and do not add a second minter of any form.

## Invariant 4 — no `block_in_place` / `block_on` in the actor scope

ADR-049 removes the sync-bridge pattern that made `current_thread` runtimes
panic. `scripts/check-block-in-place.py` is an AST **ratchet**: each in-scope
file has a baseline count that may only drop. New sites are budget-0 and fail
CI. Genuinely-needed sync→async seams (e.g. the OpenMLS sync `StorageProvider`
bridge in `crypto/mls/storage.rs`) are inline allow-listed. If you find
yourself reaching for `block_in_place`, you almost certainly want
`spawn_blocking` at the seam instead (see `SpawnBlockingStorageAdapter`).

## Adding a new protocol feature — integration checklist

A new runtime capability is not "done" when the core function compiles. Follow
the root `CLAUDE.md` **Integration checklist**: the function must be reachable
from a `Supervisor` method, exported from every applicable FFI bridge, wrapped
in each SDK, asserted in `pipeline_wiring.rs`, and reflected in the SDK
capability matrix. An empty cell means the plan is incomplete. Never edit an
enforcement file (listed in the root `CLAUDE.md`) to make a check pass — fix
the code.

## Pointers

- `.docs/adrs/ADR-049-actor-per-context.md` — the model, every decision.
- `.docs/adrs/ADR-057` — the `scp-mls` extraction (sync MLS state machine
  moved to a wasm32-safe crate shared by node + browser).
- `.docs/lessons/tokio-mutex-blocking-lock-in-runtime.md`,
  `.docs/lessons/lock-free-read-invariant.md` — concurrency lessons.
- `.docs/lessons/ast-gate-checks-definition-not-name-resolution.md` — why the
  Class-S scanner was retired for a type-system guard.
- `src/context/README.md`, `src/crypto/mls/README.md` — module maps.
- `#![warn(missing_docs)]` is crate-wide (`lib.rs`); keep new public items
  documented.
