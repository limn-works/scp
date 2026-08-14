---
name: saga121-participant-unavailable
description: Review of fix/121 — transient Prepare-phase ActorBusy typed as SagaAbortReason::ParticipantUnavailable (SCP-SAGA-13068); ALIGNED
metadata:
  type: project
---

# fix/121 ParticipantUnavailable saga terminal @ `124f890eb` (2026-06-30) — ALIGNED

Diff `5a67b771d..HEAD` (11 files). Transient Prepare-phase `ContextError::ActorBusy` in the §6.2.4 xctx tool-invoke saga now lifts to a NEW fieldless unit variant `SagaAbortReason::ParticipantUnavailable` (code `SCP-SAGA-13068`, retryable) instead of permanent `Rejected`/13067. Layers all consistent: ADR-049 §3a, spec §6.2.4, registry sdk-common.md, core supervisor.rs, FFI saga_errors.rs, 4 SDK docstrings.

**Why ALIGNED (0 misalignments):**
- **No taxonomy collision (the load-bearing check).** The participant-context-set OVERLAP gate (`SagaBusy`/13066) is mapped to `SagaError::Busy{contended_context}` at the entry point (supervisor.rs:5638-5645) via `try_reserve_context_set().map_err(...)?` BEFORE `run_saga`. `lift_run_saga_error` (only call site supervisor.rs:5654) ONLY sees `RunSagaError` arising INSIDE the FSM, so its blind `ContextError::ActorBusy(_) => ParticipantUnavailable/13068` arm cannot capture an overlap-gate ActorBusy. The two ActorBusy sources are structurally separate. Matches ADR's "distinct from SagaBusy whose contended_context does not apply."
- **needs_repair short-circuit wins.** Commit-phase ActorBusy (needs_repair==true) → `NeedsRepair` BEFORE the reason match. Explicit test `lift_run_saga_error_actor_busy_with_needs_repair_is_needs_repair_not_aborted`. Prevents mislabeling possible-divergence as clean retryable abort.
- **Honest reachability everywhere.** Closed/terminated inbox = RELIABLY ActorBusy (confirmed: actor handle send maps `Ok(Err(_closed))` arm → ActorBusy). Saturated-but-OPEN mailbox = conditional on future `SEND_TIMEOUT < PHASE_TIMEOUT`; currently races phase timeout → generic abort. Honestly disclosed in spec, ADR, AND core variant rustdoc. No unconditional "mailbox saturated → retryable" overclaim; no "carries retry_after_ms" (ADR says "carries no back-off hint" — matches fieldless variant + FFI `retry_after_ms: None`).
- Rename `MailboxSaturated -> ParticipantUnavailable` complete (0 stragglers).

**Observations (non-blocking, not misalignments):**
1. FFI `SagaErrorKind::Aborted{retry_after_ms}` collapses ParticipantUnavailable + Rejected (both `None`); retryable-vs-permanent recoverable ONLY by string-matching `SCP-SAGA-13068` code. SDK docstrings honestly say "distinguished by the SCP-SAGA-* code." Consistent with ADR taxonomy design + pre-existing RateLimited/Rejected pattern — governed by the ADR, so not a misalignment. A typed retryable boolean would be cleaner but the ADR already made this choice.
2. Unit lift tests feed synthetic message "mailbox full for 30 seconds" while testing the closed/terminated semantics — cosmetic; message string is never parsed (structural variant match). Trivial.

**Gotcha:** review target = worktree `/.claude/worktrees/saga-121/...`, NOT main repo `/Users/alec/Developer/limn/scp/...` (main is on a different/older HEAD — `try_reserve_context_set` there still returns `ContextError::ActorBusy(...(SagaBusy))`; the reviewed branch returns a typed `contended_context`). Reading the main-repo path gives stale line numbers/behavior.
