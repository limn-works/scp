---
name: scp-out-046-streaming-saga-seal-fsm
description: Architecture review of SCP-OUT-046 streaming-saga seal-phase FSM (ADR-061 seal phase) against ADR-049 actor-per-context invariants — APPROVED
metadata:
  type: project
---

SCP-OUT-046 (branch feat/outlet-xctx-046-seal-fsm, reviewed at HEAD 18f6fd11c) — streaming-saga seal-phase FSM.
**Verdict: APPROVED** (structurally sound, ADR-compliant). Reviewed via 3-dot diff `origin/main...HEAD`
(merge-base bc4464566). NOTE: two-dot `origin/main..HEAD` is misleading — origin/main advanced ~3 weeks
past this branch (docs reorg, supervisor.rs reformat); always use 3-dot for this branch. Also: `cd` into
main repo silently switches away from the worktree — use `git -C <worktree>` for everything.

Invariant verification (ADR-049):
- **Inv 1 (Class-S)**: all durable money/replay state through combinators. `xctx_committed_stream_outputs`
  (new Class-S field) mirrors existing `xctx_committed_outputs` pattern exactly (state.rs + ContextSnapshot
  w/ serde(default)). Handlers: prepare_b_streaming → `commit_class_s_keep_restore_split`; stream_capture_append
  → `commit_class_s_keep` (KEEP = monotonic credit); commit_b_stream_first_settle → `commit_class_s_restore`
  (capture, witness-before-append) then append then rollback via `commit_class_s_keep` — a faithful mirror of
  unary commit_b_first_settle/commit_b_settle_finalize two-combinator decomposition. Fail-closed persist of the
  seal witness is CORRECT: coalesce rollback would re-invoke a non-deterministic LLM on replay (breaks §6.2.4
  determinism). No state_mut escape hatch introduced.
- **Inv 2 (Send)**: off-mailbox seal task is tokio::spawn'd; holds Arc<Supervisor>, Receiver/Sender, escrow_ticket,
  Arc<dyn ContextEventLogProvider>. Compiles → Send-clean.
- **Inv 3 (capability reduction)**: seal task holds Arc<Supervisor> (same as run_saga/run_cross_context_bridge —
  it is supervisor-scope, NOT an actor). Actor handlers only touch own ClassSCell. No actor→sibling path added.
  No re-entrant self-dispatch: seal handler RETURNS StreamSettlement in outcome; off-mailbox task applies it via
  supervisor.settle_outlet_stream_via_actor (separate mailbox message) — explicitly documented deadlock-avoidance.

Phase-1 EXTRACT (open_outlet_stream_phase1, commit 3d0bd0067): clean, behavior-preserving. OutletStreamPhase1 is
a pure data carrier; escrow-ticket arming + fallible-step ordering preserved inside phase1; only reordering is
two side-effect-free Arc::new sink constructions moving to caller (unobservable). Parameterization is clean not
leaky: same-context caller installs both sinks; saga passes settlement_sink=None + no durable invoked-sink (avoids
double-recording B's OutletInvoked, AC5). 7 existing open_outlet_stream tests pass.

FSM structure: streaming driver (start_cross_context_streaming_outlet_invocation_saga @ supervisor.rs:6328) is a
SEPARATE inline FSM, does NOT go through run_saga. Justified — run_saga is block-until-terminal; streaming is
return-receiver-at-Committing + finish off-mailbox (Committed reached in seal task). Shared leaf machinery:
try_reserve_context_set (per-set gating), append_journal, open_outlet_stream_phase1, prepare_b mirror, commit_b
mirror. Committing journaled before receiver return (AC6); slot released at Commit (AC2, ~10 manual drop(reservation)
sites); escrow stays reserved, settled at close (AC3); bounded(=1) outer channel = backpressure.

ADR-049 §3a: per-participant-context-set gating IS implemented (try_reserve_context_set over
Mutex<HashSet<ctx_id>>, saga_participant_context_set) — replaced the supervisor-wide AtomicBool. Remaining
AtomicBools are test scaffolding only. NO start_*_saga FFI export added (in-core only) — correct, §3a defers the
FFI surface until per-set gating + caller_did channel-binding land.

Crash recovery keyless-safe: witness present → idempotent Committed; absent → NeedsRepair + escrow HELD (sweep
refuses to fabricate a signature without a key; key-bearing truncated close is a separate path).

Non-blocking observations (not DOA): (1) FSM journal-sequencing + ~10 manual drop(reservation) sites duplicated
between run_saga and the streaming driver — maintainability tax, keep in lockstep if saga states evolve; (2) AC8
enforcement is a source-text scanner in scp-testing pipeline_wiring.rs (bounds seal fn by next-fn-name string
search) — brittle to refactor, but bounded single-assertion; (3) cross-context live OutletCancel not wired for
streaming (cancel_ack_seq always None; truncation = crash / caller-stops-consuming only) — consistent w/ design,
worth confirming against §6.2.5 scope; (4) A-side CrossContextOutletInvoked is best-effort post-seal (durable
witness is the reconstruction source) — matches unary saga dual-log pattern, "atomic" = B-side atomic.
