# Runbook: a cross-context saga in `NeedsRepair`

**Scope.** The single cross-context saga — cross-context tool invocation (spec §6.2.4) —
has parked in the `NeedsRepair` state. This runbook covers detecting it, understanding why
restart-driven replay resolves most cases automatically, and recognizing the residual
cases that need a human. For the FSM and phase semantics, see
`.docs/lessons/saga-prepare-commit-abort.md`.

## Symptom

A saga has landed in `SagaState::NeedsRepair` (`context/supervisor/saga_journal.rs`).
`NeedsRepair` is **not** a terminal state — `SagaState::is_terminal()` returns true only
for `Committed` and `Aborted` — so `SagaJournal::load_unresolved()` keeps returning the
entry, and every process restart re-surfaces it until it resolves. A saga reaches
`NeedsRepair` when:

- Commit exhausted its retry budget (the state's own definition), or
- recovery observed a genuinely-unresolvable divergence: a one-sided commit, or a
  participant side that is unreachable (`Supervisor::recover_committing_entry`), or
- an `Aborting` entry whose rollback never completed
  (`Supervisor::recover_saga_entry`, the `Aborting` arm re-resolves to `NeedsRepair`).

## Signal to alert on

Metric: **`scp_saga_repair_needed_total`** (a counter, `crates/scp-runtime/src/metrics.rs`,
emitted by `record_saga_repair_needed`). It increments whenever a saga lands in
`NeedsRepair` **or** when the crash-recovery load sweep skips a corrupt / torn /
undecodable / vanished journal entry (spec §17.16.4). Alert on any increase.

Logs: each increment is paired with a `tracing::error!` carrying `saga_id`. The
distinguishing messages:

- `"saga recovery — NeedsRepair carryover; operator intervention required"`
  (`recover_needs_repair_entry`) — a pre-existing `NeedsRepair` re-surfaced at this restart.
- `"saga recovery — Aborting observed; marked NeedsRepair for operator review"` — a
  rollback that did not finish.
- A `load_unresolved` skip logged from `saga_journal.rs` — a corrupt/torn entry (the CRC32
  + length-prefix check failed); this one is a **storage-integrity** signal, not a stuck
  saga.

Inspect the durable record directly by `saga_id`: journal entries live under the
`saga_journal/{saga_id}/{seq_per_saga}` key namespace, append-only, latest entry wins.

## How restart-driven replay recovers it (the primary path)

There is **no `repair_saga(saga_id)` command** — repair is driven by process restart, not
by a targeted call. On startup the sole recovery entry point is
`Supervisor::restore_on_startup` (`context/supervisor/supervisor.rs`), which runs two sweeps
in the order spec §17.16.4 requires, **restore then reconcile**:

1. `restore_all_contexts` — rehydrate every persisted `Active` context's actor, so every
   participant a recovery arm must drive is resident. (The order is enforced by the type
   system: `replay_unresolved_sagas` requires the `RestoredContexts` witness that
   `restore_all_contexts` returns, so "replay first" does not compile.)
2. `replay_unresolved_sagas` → `recover_saga_entry` per non-terminal entry — **replay from
   Prepare**, idempotent by `SagaId`:
   - a `Committing` entry re-drives the idempotent Commit (**never** re-invoking the tool):
     B re-acks its existing `ToolInvoked` and re-emits the stored output; A re-acks from the
     durable `xctx_committed_invocations` witness. If both sides actually committed, the
     saga resolves to `Committed` — a false `NeedsRepair` clears itself.
   - a `PreparingA`/`PreparingB` entry re-drives the record-keyed caller reversal and
     reaches terminal `Aborted` once the reversal is confirmed delivered.

So the first operator action for most `NeedsRepair` alerts is simply: **confirm a clean
process restart occurred and check whether the entry cleared.** A saga that was really
two-sided-committed or fully compensated resolves without intervention on the next start.

## When a human is actually needed

The entry **stays** `NeedsRepair` across a restart only when replay cannot resolve it:

- a genuinely one-sided commit (one participant committed, the other cannot be made to),
- a participant context that failed to restore or whose persistence existence cannot be
  confirmed (the reversal is left non-terminal, fail-closed, for the next start),
- a non-reconstructible / corrupt journal entry surfaced by the load-sweep skip.

For these, use the durable divergence account: `recover_needs_repair_entry` rehydrates any
`saga_repair_records` carried in the entry's evidence, and each reachable side has appended
its own signed `CrossContextDivergenceMarker` to its own log (the
`emit_divergence_marker` handler). Reconcile from those records — confirm which side
holds the committed effect and which the reservation — and settle the economy manually,
then the entry can be marked resolved. A corrupt-entry skip is a **storage** problem: repair
or restore the backing store before expecting recovery to progress.

## Note

A targeted, no-restart repair command (repair a single `saga_id` without a full
restore-then-replay cycle) is a tracked future enhancement. Until it lands, restart-driven
replay is the mechanism, and the manual reconciliation above is the fallback for the
residual unresolvable cases.
