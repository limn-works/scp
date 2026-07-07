# The cross-context saga: prepare / commit / abort over two actors

This lesson is about the *mechanism* — the FSM, its journal, and how a crash is
reconciled. For the *admission* question — "should this even be a saga?" — read
`saga-admission-and-topology-guards.md` first; it is not repeated here.

## One saga survives

There is exactly one cross-context saga in the system: **cross-context tool invocation**
(spec §6.2.4). Three other arms that ADR-049 originally enumerated (custody handover,
standing-pair creation, broadcast hosting) were category errors and were withdrawn — see
the admission lesson. So everything below is written for the single surviving arm: the
caller's economy reservation and the target's tool execution must be **both-or-neither**
across two distinct context-actors.

## The FSM

The coordinator lives on the `Supervisor`; the durable record of *which saga is in which
phase* is `SagaJournal` (`context/supervisor/saga_journal.rs`). The lifecycle is
`SagaState` (same file):

```
Initiated → PreparingA → PreparingB → Committing → Committed
                                    ↘ Aborting  → Aborted
                                    ↘ NeedsRepair
```

`SagaState::is_terminal()` is true only for `Committed` and `Aborted`;
`load_unresolved()` returns the latest entry per **non-terminal** saga, which is what
crash recovery sweeps. `NeedsRepair` is deliberately **not** terminal — a saga that
exhausts its commit-retry budget or lands one-sided parks here and stays visible to the
recovery sweep until an operator resolves it. Operating a saga stuck in `NeedsRepair` is
`.docs/runbooks/saga-needs-repair.md`.

## Two records, one per side of the split

The design deliberately keeps two separate durable records:

- **The journal (supervisor-side, durable).** `JournalEntry` records the `SagaState`, the
  `participants`, and a `Zeroizing<Vec<u8>>` `evidence` blob — public phase metadata only.
  Spec §9.4.3 forbids the journal from holding bearer secrets; no live saga is
  secret-bearing, so the commitment path is dormant. Each entry is length-prefixed +
  CRC32-suffixed so a torn write is detected on load, not replayed.
- **`saga_pending` (actor-side, in-memory).** `SagaPreparedState`
  (`context/supervisor/saga_prepared_state.rs`) holds the full staged evidence an actor
  needs to *apply* the mutation at Commit time; it lives in `PerContextState.saga_pending`
  and is persisted only as part of the actor's coalesced snapshot.

The per-phase handlers run on the participant actors (`context/actor/handlers/saga.rs`):

- **Prepare-A** (`prepare_a`, caller actor) — validates the caller holds `tool:interface`
  and is an allowed caller, **stages** (does not apply) the rate-limit decrement + escrow
  reservation, Class-S sync-persists fail-closed, and replies the `Send` reservation
  handles for the FSM to hold (RAII release on abort).
- **Prepare-B** (`prepare_b`, target actor) — re-runs the full §7 validation *re-bound* to
  the carried `caller_did` + `tool_registration_id` (the confused-deputy defense),
  captures B-controlled provenance, stages the prepared record, Class-S sync-persists
  fail-closed, then replies.
- **Commit** — split `commit_b_reserve` → supervisor executes → `commit_b_settle`
  (B records `ToolInvoked`, signs the receipt, durably captures output keyed by `SagaId`)
  and `commit_a` (A re-acks from the durable witness, settles escrow). Every commit step is
  **idempotent by `SagaId`** — a replayed Commit short-circuits.
- **Abort** (`abort`) — releases the staged reservations, from the live RAII carrier or the
  durable caller-reservation record on the crash-recovery path.
- **Divergence marker** (`emit_divergence_marker`) — on a one-sided `NeedsRepair`, each
  reachable side signs and appends its own marker to its own log.

Prepare-phase rejections carry typed `SCP-SAGA-13xxx` codes (ADR-049 §3a).

## Replay-from-Prepare is what makes crash recovery safe

`saga_prepared_state.rs` states the determinism contract: at Commit time the actor
reconstructs its evidence from `saga_pending` and applies the mutation; **if `saga_pending`
rolled back beyond the prepared state** (e.g. a coalesced-snapshot crash window), Commit
replay fails fast with `SagaCommitFailed` — no half-applied mutation. Combined with the
Class-S fail-closed persist in both Prepare handlers (the caller deduction + reservation
record land durably *before* the FSM appends the `PreparingB` journal entry), this gives
the recovery invariant: a crash never leaves a partial commit — either the durable
prepared state is intact and Commit re-drives idempotently, or it is gone and Commit
refuses. `Supervisor::recover_saga_entry` dispatches each non-terminal state to its
recovery arm on the strict restore-then-replay order enforced by
`Supervisor::restore_on_startup`.

## Cross-refs

- `saga-admission-and-topology-guards.md` — the two guards a saga must pass to exist.
- ADR-049 §3 (saga FSM), §3a (FFI surface + error band), §3b (admission criteria),
  §6.2.4 area; spec §6.2.4 (the surviving arm), §9.4.3 (journal secret handling),
  §17.16 (durable coordinator surface), §17.16.4 (crash-recovery sweep).
- `.docs/runbooks/saga-needs-repair.md` — operating a `NeedsRepair` saga.
