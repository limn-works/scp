---
name: xctx-saga-624-review-wave1
description: §6.2.4 cross-context tool-invocation saga — review wave-1 fix cluster (Commit-A re-drive, ticket-safe send, receipt verify, crash-surviving nonce-dedup, retryable Commit-B settle) and the FSM/actor/witness architecture
metadata:
  type: project
---

§6.2.4 cross-context tool-invocation saga lives in `crates/scp-runtime/src/context/supervisor/supervisor.rs` (the supervisor-side FSM: `run_saga_fsm`, `dispatch_xctx_commit`, `commit_b_execute_or_replay`, `commit_b_first_execute`, `commit_a_settle`, `recover_saga_entry`/`redrive_xctx_commit_in_progress`) + the per-context actor handlers in `crates/scp-runtime/src/context/actor/handlers/saga.rs` (`prepare_a`/`prepare_b`/`commit_b_reserve`/`commit_b_first_settle`/`commit_a`/`abort`/`emit_divergence_marker`).

**Witness model (the idempotency spine):**
- Target (B) side: `xctx_committed_outputs: HashMap<SagaId, CommittedToolInvocation>` — Class-S, set at Commit-B settle, short-circuits `commit_b_reserve` to `AlreadyCommitted` (re-emit stored receipt+output, NEVER re-invoke).
- Caller (A) side: `xctx_committed_invocations: HashSet<SagaId>` — Class-S, set at Commit-A BEFORE ack; a replayed Commit-A finds it and re-acks no-op (rolls back the handed-back ticket).
- B-side replay/freshness: `xctx_nonce_dedup: NonceDedup` (16-byte nonce → unix-secs, 5-min TTL / 10k cap, in `scp-protocol` `key_protocol_verify.rs`). The ONLY gate against a fresh-SagaId replay of a `CrossContextToolInvoke`.

**ActorHandle::send constraint (load-bearing for FIX 1):** `ContextActorHandle::send<T,F>(cmd_factory)` calls `cmd_factory(tx)` BEFORE `inbox.send(cmd)`. On send failure (mailbox full 30s `SEND_TIMEOUT` / closed) the built `ContextCommand` is dropped INSIDE `send` — the caller never gets it back. So moving a `Box<PreparedAFields>` (holding the `#[must_use]` `ToolEconomyTicket` whose Drop debug-asserts) into the factory and having the send fail drops the ticket UNBALANCED → panic under `--features testing` / escrow leak in release. The inbox is `tokio::sync::mpsc::Sender<ContextCommand>` whose `send` returns the value back in `SendError<T>` — a recover-on-failure send variant is possible.

**Ticket reversal vocabulary** (`tools_helpers.rs` `ToolEconomyTicket`): `void_external_and_consume(payment_adapter)` = void escrow + consume (correct when a leg never landed / owning actor gone); `hold_external_for_repair()` = consume carrier but LEAVE escrow held (NeedsRepair — operation may have partially committed). `commit_tool_economy_ticket` = settle. Dropping un-consumed = debug_assert panic.

**Class-S snapshot pattern:** `ContextSnapshot` (state.rs ~494) carries `saga_pending` / `xctx_committed_outputs` / `xctx_committed_invocations`. Built via `*_snapshot` helpers in `messaging_helpers.rs` (`saga_pending_snapshot`, `xctx_committed_outputs_snapshot`) wired into ~6 snapshot builders (manager_methods, broadcast/ttl_close/trust_recovery helpers, messaging_helpers, supervisor test builder). Restored in `lifecycle_helpers.rs` (~2272). Same-node restore REHYDRATES; cross-node export/import + `strip_snapshot_for_public` DROP to empty (a foreign saga must never drive local replay). `xctx_nonce_dedup` was NOT in the snapshot (reinit empty on restore — the BLACK-624-01 cross-crash replay hole).

**check-class-s-fail-closed.sh** MUTATORS list is additive-only; `prepare_b` records the nonce then `persist_state_fail_closed`, so adding `xctx_nonce_dedup.record(` as a marker is sound (gate still passes). Enforcement files must never be weakened; only ADD coverage.

**Live E2E test harness** in supervisor.rs test module: `xctx_supervisor[_with_event_log]`, `xctx_caller_state`/`xctx_target_state` (members + ToolInterface/ToolInvokeAll caps + registered `XCTX_TOOL`), `spawn_xctx_pair`, constants `XCTX_CALLER/XCTX_TARGET/XCTX_TOOL`, `RecordingEventLog`. Drives `start_cross_context_tool_invocation_saga` over two co-resident actors with a supervisor-side executor. This is where FSM-level regression tests belong; actor-handler unit tests live in `saga.rs` (`build_deps`/`target_state`/`stage_prepared_b`/`mint_tool_ucan`).

**Wave-1 fixes LANDED** (worktree `feat/actor-2c-6.2.4-xctx-saga`, commit `9b68df12b` on top of slice-6 `3e2038d84`; NOT pushed):
- FIX 1: `ContextActorHandle::send_recover_on_failure` (reserve-then-send; returns `Some(Box<ContextCommand>)` on send/timeout failure, `None` on delivered-handler-error). `commit_a_settle` recovers the reservation back into `ctx.prepared_a` on send failure; re-acks from witness via new `CommitACheckWitness` read-only saga phase when `prepared_a` is None (lost-reply recovery).
- FIX 2: `redrive_xctx_commit_in_progress` returns `CommitInProgressResolution::{Committed,NeedsRepair}`; `recover_committing_entry` (extracted from `recover_saga_entry` for line-budget) re-acks A from the witness and `mark_resolved(Committed)` when both sides committed.
- FIX 3: `verify_commit_b_receipt` (assoc fn, no &self) in `dispatch_xctx_commit` before settle; verifies receipt sig against `ctx.target_signing_key.verifying_key()`. New codes SCP-SAGA-13040 (decode) / 13041 (sig). A binds `receipt.output_jcs`.
- FIX 4: `NonceDedup::entries()`/`from_entries()` (scp-protocol, `from_entries` is `const fn`); `ContextSnapshot.xctx_nonce_dedup: HashMap<[u8;16],u64>` `#[serde(default)]`; `xctx_nonce_dedup_snapshot` helper wired into the 4 live builders (messaging/broadcast/ttl_close/trust_recovery/manager) + empty in the 4 strip/default builders (export×2/persistence/supervisor-test/store-context); restore rehydrates via `from_entries`. Gate marker added (additive).
- FIX 5: `CrossContextSagaCtx.executor_output: Option<Vec<u8>>`; `commit_b_first_execute` stashes once, skips executor on retry.
- FIX 6: `commit_b_first_settle` moves slot out up front, re-inserts owned original on append/persist failure; `reprepare_from_receipt` DELETED.

All gates green (class-s/saga-gating/handler-no-panic/error-codes), full CI clippy `-D warnings` exit 0, 1803 lib + 4 named integration suites pass. NOTE: `xctx_supervisor` uses `NoopSagaJournal` — FSM-level journal-resolution can't be asserted via that harness; assert the re-drive RETURN value instead.

See [[lock_free_read_invariant]] [[lesson_actor_boundary_no_key_no_retrieval]] (actor holds NO signing key — target/caller Active Signing Keys are supplied per-call by the FSM).
