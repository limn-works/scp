# `context/` — the actor runtime

This module is the heart of `scp-runtime`: the actor-per-context concurrency
model (ADR-049). One `tokio` task per live context owns its state by move; a
`Supervisor` owns the registry of those tasks and every provider. If you are
new here, read `.docs/adrs/ADR-049-actor-per-context.md` and this crate's
`CLAUDE.md`, then use the map below.

## How a command flows

Every public runtime operation is a message to one context's actor:

```
Supervisor::send_message(&handle, …)          // src/context/supervisor/supervisor.rs
  └─ lock-free lookup: actors.get(context_id) // DashMap — no mailbox hop to find the actor
  └─ ContextActorHandle::send(command)         // actor/handle.rs — bounded mpsc, send-with-timeout
        │  (command carries a oneshot::Sender for the reply)
        ▼
ContextActor::run() tokio::select!            // actor/mod.rs
  └─ dispatch(command)  →  handlers::<domain>::dispatch(&mut ClassSCell, &ActorDeps, sub)
        │                                       // actor/handlers/*.rs
        └─ handler body calls the domain logic in ../<domain>_helpers.rs
        └─ mutates PerContextState through the ClassSCell combinators
        └─ returns Outcome { result, mutated } ; reply is sent on the oneshot
  └─ if mutated: mark dirty → coalesced snapshot on the persistence tick
     (Class-S mutations persist fail-closed inline, before the reply)
```

The caller `await`s the oneshot reply, so `Supervisor::method(...).await`
reads like an ordinary async call even though the work happened on the actor
task. Cross-context work never crosses actor-to-actor directly — it goes
through `SupervisorHandle::start_saga` (see the saga coordinator).

## The submodule tree

### `supervisor/` — registry + coordination

- `supervisor.rs` — the `Supervisor` struct. Lock-free reads
  (`DashMap`/`ArcSwap`) behind a single `write_lock` for mutations
  (Decision 2/12). Owns the injected providers (`crypto`, `transport`,
  `event_log`, persistence, clock, `key_resolver`, payment adapter, MLS
  storage) in `OnceLock` slots populated by `with_providers` /
  `with_providers_and_journal`. Hosts the public API surface
  (`create_context`, `send_message`, `restore_on_startup`, …) and the
  cross-context saga FSM.
- `handle.rs` — `SupervisorHandle`, the capability-reduced view actors hold.
  No accessor returns a sibling actor's handle (`start_saga` only).
- `identity_capability.rs` — `OwnedIdentityDid`, the unforgeable per-identity
  token (`pub(in crate::context)` to name, `pub(super)` to mint). The module
  denies `unsafe_code` and `non_local_definitions`.
- `saga_journal.rs` — the durable append-only saga journal trait +
  `ProtocolRepositorySagaJournal` production impl.
- `saga_prepared_state.rs` — the per-actor Prepare-phase staged mutation
  (`SagaPreparedState`).
- `key_package_actor.rs` — the per-identity `KeyPackageStoreActor` (its own
  mailbox), separate from context actors.

### `actor/` — the per-context task

- `mod.rs` — `ContextActor` and its `run()` `select!` loop (inbox / TTL timer
  / governance timeout / coalesced-persistence tick).
- `commands.rs` — the `ContextCommand` outer enum and its 12 domain
  sub-enums (`MessagingCommand`, `LifecycleCommand`, `GovernanceCommand`,
  `BroadcastCommand`, `EconomyCommand`, `TrustRecoveryCommand`,
  `StandingCommand`, `TtlCloseCommand`, `ToolsCommand`, `QueriesCommand`,
  `SagaPhaseMessage`, `LifecycleControlCommand`). Each variant carries its
  reply channel.
- `handle.rs` — `ContextActorHandle`, the caller-side bounded-mailbox wrapper
  (send-with-timeout).
- `class_s.rs` — `ClassSCell`, the fail-closed-persist wrapper around
  `PerContextState` (Class-S vs Class-C; see `CLAUDE.md`).
- `state.rs` — `PerContextState`, the owned per-context payload (identity,
  membership, roles/ceiling, event log, mode-specific state, governance,
  crypto state, …).
- `deps.rs` — `ActorDeps`, the non-state resources moved into the task
  (providers, backends, `SupervisorHandle`, clock, key_resolver, …).
- `sequence.rs` — `SequenceReservation`, the RAII send-sequence guard (rolls
  back on drop, durable on `commit()`).
- `outcome.rs` — `Outcome<T> { result, mutated }`, the handler return type
  that tells the actor when to mark state dirty.
- `handlers/` — one module per command domain (`governance.rs`,
  `lifecycle.rs`, `messaging.rs`, `broadcast.rs`, `economy.rs`,
  `trust_recovery.rs`, `standing.rs`, `ttl_close.rs`, `tools.rs`,
  `queries.rs`, `saga.rs`, `lifecycle_control.rs`). Each exposes a `dispatch`
  taking `(&mut ClassSCell, &ActorDeps, SubCommand) -> Outcome<()>` — Class-S
  mutation flows through the cell's combinators, never a bare
  `&mut PerContextState`.

### `*_helpers.rs` — domain logic bodies

The substance of each domain lives beside the actor, in large helper modules
that the handlers call: `governance_helpers.rs`, `lifecycle_helpers.rs`,
`messaging_helpers.rs`, `trust_recovery_helpers.rs`, `broadcast_helpers.rs`,
`economy_helpers.rs` / `economy_logic.rs`, `queries_helpers.rs`,
`tools_helpers.rs`, `standing_helpers.rs`, `ttl.rs` / `ttl_close_helpers.rs`.
Keeping the bodies here keeps the handler modules thin dispatch shells. The
MLS commit-broadcast retry queue (§9 fail-closed, see
`src/crypto/mls/README.md`) lives in `governance_helpers.rs` +
`state.rs`.

### Supporting modules

- `config.rs` — `ContextConfig` / `ContextCreation`, the flat options object
  behind `Supervisor::create` (ADR-052 construction standard).
- `builder.rs` — the provider trait definitions (`ContextTransportProvider`,
  `ContextEventLogProvider`, and the local/no-op provider impls).
- `providers/` — production provider impls (`MerkleEventLogProvider`,
  the `ProtocolRepository` persistence bridges).
- `export_import.rs`, `persistence.rs`, `key_destruction.rs`, `policy.rs`,
  `app_sandbox.rs`, `governance/`, `tools/` — feature-specific surfaces.
- `mod.rs` — `ContextHandle` (the thread-safe lifecycle handle callers hold)
  and the `test_supervisor` convenience constructor.

## No transitional shim

The ADR-049 handler migration is complete. Every domain handler runs the
owned-state actor shape (`dispatch(&mut ClassSCell, &ActorDeps, sub)`). The
migration-window scaffolding — the `&Supervisor` "shim" dispatch
(`dispatch_from_shim`), the supervisor-shape `handle_*` helpers, and the
`*_legacy` bodies they delegated to — was removed at Phase 2A finalization;
the final `&Supervisor` consumer (the queries shim path) went with it. There
is no second concurrency model to reason about: a command's reply is produced
entirely on the one actor task that owns its context.
