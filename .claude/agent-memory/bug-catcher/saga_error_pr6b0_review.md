---
name: saga-error-pr6b0-review
description: PR #116 PR-6b0 typed SagaError for §6.2.4 saga terminal states — CLEAN review, full trace of retry_after_ms propagation + needs_repair classification
metadata:
  type: project
---

# PR-6b0 typed SagaError review (branch chore/116-pr6b0-saga-error, HEAD 4e5d5cfc8)

CLEAN review — no bugs found. Diff e406c15c5..4e5d5cfc8, concentrated in
`crates/scp-runtime/src/context/supervisor/supervisor.rs`.

**Why:** Verifying typed-error refactors that replace FFI message-string
classification needs end-to-end propagation tracing, not just the new enum.

**How to apply:** Reuse these verified facts when re-reviewing this area:

- `saga_code_from_message` (supervisor.rs ~11045): `message.find("SCP-SAGA-")? + PREFIX.len()`
  then `message[start..].chars().take_while(is_ascii_digit).parse::<u16>().ok()`.
  NO panic: prefix is ASCII so `start` is always a char boundary (no multibyte slice panic);
  `start == len` yields empty slice (valid); u16 overflow → `.ok()` None → caller falls back 13067.
  Off-by-one correct.
- `retry_after_ms` propagation: 3 sliding-window saga sites (saga.rs 698/713/808) use
  `Some(retry_after_secs.saturating_mul(1000))` — retry_after_secs is u64, saturating, no overflow.
  3 token-bucket sites (lifecycle/messaging/tools_helpers) use `None`. NO None→Some(0) coercion.
- Actor-boundary survival: PrepareB handler (saga.rs ~877/895) does `reply.send(Err(err))` with the
  FULL ContextError (retry_after_ms intact); the lossy `outcome_error_sketch` is only the local Outcome.
  Shared `outcome::outcome_error_sketch` (outcome.rs 117) was updated to copy retry_after_ms.
  Per-module local `outcome_error_sketch` copies (governance/lifecycle/broadcast/...) drop RateLimited
  into the `other =>` CryptoFailed catch-all, but saga path uses the SHARED one — not a regression.
- needs_repair classification (point 1): `resolve_committed_or_needs_repair` (supervisor.rs ~6700)
  sets `ctx.reached_needs_repair=true` BEFORE returning the mark_resolved error, so run_saga's
  `needs_repair = xctx.is_some_and(|c| c.reached_needs_repair)` is true → lift → NeedsRepair (carries saga_id),
  NOT a false Aborted (which would invite a double-charge retry). On this path `prepared_a` is already
  None (commit_a_settle took() it into the CommitA command), so run_saga tail's reached_needs_repair
  branch is a no-op (no double escrow act). Divergence markers emit ONLY in commit_result Err arm — the
  Ok-arm-then-mark_resolved-fail path never emits them. `xctx.as_deref_mut()` reborrow sound (Ok arm
  returns directly, no later xctx use).
- SagaOutput derive(Clone,PartialEq,Eq): SagaId derives them (saga_journal.rs:78 has pub String tuple),
  Option<Vec<u8>> supports them. Sound.
- Regression test `lift_run_saga_error_mark_resolved_failure_is_needs_repair_not_aborted`: REAL assertion
  (pins same mark_resolved msg → Aborted{13067} when needs_repair=false vs NeedsRepair when true). Tests
  the lift in isolation; does NOT exercise resolve_committed_or_needs_repair setting the flag (acknowledged
  infra gap), but that wiring was verified by reading code.
- start_saga still returns ContextError (`.map_err(|e| e.error)`); only start_cross_context_tool_invocation_saga
  returns SagaError. External tests (actor_saga_coordinator.rs) match ContextError on start_saga — still compiles.
  try_reserve_context_set now returns Err(String contended id); reserve_context_set_or_busy lifts to ActorBusy
  for generic paths, SagaError::Busy for cross-context. No external callers of changed-signature methods.
- SagaError/SagaAbortReason exported from supervisor/mod.rs; codes 13065/13066/13067 documented in sdk-common.md.
