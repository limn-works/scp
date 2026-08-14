---
name: issue122-fault-injection-saga-journal
description: Issue #122 fault-injection saga-journal test harness review (branch feat/122, HEAD ce57bdd0d) — ALIGNED w/ 1 stale-doc finding
metadata:
  type: project
---

# Issue #122 fault-injection saga-journal harness @ `ce57bdd0d` (2026-06-30) — ALIGNED (1 minor)

Reviewed `git diff d24b59d33 HEAD` (4 files, pure test code) for `feat/122-fault-injection-saga-journal`. Worktree saga-122.

**Why:** Verify the corrected test harness faithfully tests live §6.2.4 xctx-saga FSM terminal arms and honestly scopes-out the infeasible escrow-held property (pass-1 NEEDS-DISCUSSION on vacuous `voided==0`/`_escrow_held` was resolved-by-correction).

**How to apply:** Questions 1-3 all PASS — verified against production supervisor.rs:
- Err-arm commit-exhaustion → `reached_needs_repair=true` set at supervisor.rs:7003-7005 BEFORE fallible seq-4 NeedsRepair append at :7006 (`?`). Faulting that append still lifts NeedsRepair; durable latest stays Committing (seq-3). Correct.
- Ok-arm `resolve_committed_or_needs_repair` (:6825-6857) sets reached_needs_repair on mark_resolved(Committed) fault, returns Err → lift NeedsRepair NOT Aborted; no re-execute. Correct.
- Self-heal: recover_committing_entry (:6398) → redrive_xctx_commit_in_progress AlreadyCommitted (:6963) → resolve Committed → compact. Correct.
- Scope-out is HONEST+CORRECT: outbound Prepare-A presents NO spending UCAN (saga.rs:488-490, reserve_tool_economy called w/ `None` at :495); free tool ⇒ no external escrow staged ⇒ hold_external_for_repair (supervisor.rs:5803) vs void_external_and_consume (:5814) both yield zero adapter-void calls — distinction genuinely unobservable. Paid policy aborts at Prepare (SCP-ECON-12060), never NeedsRepair. Filed follow-up + honest doc-comment is correct artifact-flow resolution (plan's escrow-held criterion rested on false economy-wiring premise).

**NEW finding from the correction (question 4):** ce57bdd0d removed supervisor.rs as a consumer of `VoidCountingPaymentAdapter` (switched to `None` adapter), leaving handlers/saga.rs:5494 as the SOLE consumer — but the DRY-extraction's "shared across >1 module" rationale/docs were NOT updated and are now FALSE:
- test_support.rs:1 "shared across `#[cfg(test)]` modules"
- test_support.rs:3-4 "Doubles referenced from more than one in-crate test module"
- test_support.rs:21 "Shared by the supervisor saga-FSM tests and the actor saga-handler tests"
- mod.rs:448-449 "shared across more than one in-crate `#[cfg(test)]` module"
Single-fixture single-consumer shared module = mild over-abstraction (simplifier); either move fixture back to saga.rs `mod tests`, or correct all four comments to name the sole consumer. Not a test-correctness defect.

GOTCHA: the Read tool returned STALE line content for supervisor.rs (off vs disk) — `awk`/`grep` from cwd were ground truth. Trust disk over Read for this file.
