---
name: saga-mailbox-saturated-13068-cumulative
description: Security review of fix/121 cumulative (afc795ef2) ActorBusy->retryable MailboxSaturated/13068 saga terminal; CLEAN, no findings
metadata:
  type: project
---

# fix/121 MailboxSaturated 13068 cumulative review (afc795ef2 vs 5a67b771d) -- 2026-06-30 -- CLEAN

§6.2.4 xctx-tool saga: Prepare-phase `ContextError::ActorBusy` lifts to retryable fieldless
`SagaAbortReason::MailboxSaturated` (code 13068, surfaced Aborted{retry_after_ms:None}) instead of
permanent Rejected/13067. Files: supervisor.rs lift_run_saga_error + SagaAbortReason enum;
scp-ffi/common/saga_errors.rs decompose (MailboxSaturated|Rejected => retry_after_ms None).

**Why no findings:**
- **No new oracle.** To reach the Prepare-B send where ActorBusy arises, caller MUST pass BOTH
  authorize-before-reserve gates (is_member caller-axis 13050, has_established_tool_interface
  target-axis 13062) at entry BEFORE any reservation. So the recipient of 13068 is already an
  authorized counterparty with an established interface. And `message = error.to_string()` is
  IDENTICAL pre/post change (ActorBusy Display); only reason+code reclassified. Zero new info
  disclosed — the liveness signal was already in the prose message under the old Rejected/13067.
- **No budget bypass.** Relabel is post-hoc in lift_run_saga_error, AFTER run_saga returns — cannot
  retroactively alter budget/escrow. Escrow (prepared_a) voided+consumed unconditionally on clean
  abort (needs_repair=false) in run_saga tail; NeedsRepair held-for-repair branch unaffected.
- **No new DoS.** Label is irrelevant to a malicious caller (could already retry a Rejected). Only
  honest contract-honoring callers change behavior, and they're self-limiting: retry_after_ms=None
  ("apply own conservative back-off", NEVER coerced Some(0)), plus each retry re-runs gates + Prepare-A
  reserve_tool_economy token bucket + §3a per-set reservation (RAII released every terminal).
- **No fabrication / sound closed classification.** 13068 is a hardcoded literal in exactly ONE
  structural match arm `ContextError::ActorBusy(_) =>`. ActorBusy has only 3 production sources
  (handle.rs send: closed inbox / dropped reply / mailbox-full timeout; key_package_actor) — ALL
  genuinely transient → retryable is semantically sound; no permanent condition wears ActorBusy.
- **Commit-phase ActorBusy can't reach the arm.** commit_with_retry exhaustion → Err arm sets
  reached_needs_repair=true → needs_repair=true → short-circuits to NeedsRepair before the abort
  match. Verified run_saga_fsm (~6960-7035) and run_saga tail (~5823).
- **§3a overlap diverted.** try_reserve_context_set contention → `.map_err` to SagaError::Busy/13066
  BEFORE run_saga; never enters lift. Verified supervisor.rs ~5632.

Fieldless variant adds no state/unbounded collection. Tests pin pre-fix mutation (Rejected/13067) and
end-to-end closed-target-mailbox path. POSITIVE: structural variant match (no message parsing),
None-never-Some(0) discipline, authorize-before-reserve ordering.
