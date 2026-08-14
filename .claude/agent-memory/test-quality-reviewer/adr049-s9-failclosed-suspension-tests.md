---
name: adr049-s9-failclosed-suspension-tests
description: ADR-049 §9 RED-CS3 fail-closed capability-suspension persistence tests — what they prove, the verified non-vacuousness chain, and the two real coverage gaps
metadata:
  type: project
---

# ADR-049 §9 (RED-CS3) fail-closed suspension persistence tests

Branch `classs-fix-residual`. Fix: when the consequence engine auto-suspends a member's
capability (`suspended_capabilities`), the suspension OUTCOME must persist FAIL-CLOSED
(durable before ack) so a ≤50ms actor-crash coalesce window can't re-grant the denied cap.

## The four tests (all behavioral, non-vacuous — verified against prod)
- `tool_settle_capture_failure_persists_suspension_fail_closed` (tools_helpers.rs) — CROWN JEWEL.
  Suspension applied IN MEMORY (line 925 `enforce_triggered_consequences`) BEFORE fallible
  `complete_tool_payment` (line 945). Sink is caller-owned `&mut bool` so it survives the
  early `return Err` on capture failure. Dual-arm persist in `settle_tool_economy` caller.
  Would fail on revert to `.await?` (returns AdapterError not PersistenceFailed). VERIFIED.
- `periodic_sweep_suspension_persists_fail_closed` (governance.rs) — distinct handler; pre-fix
  sent `Ok` unconditionally. Asserts reply err + retention + `outcome.mutated`.
- `send_suspension_persists_fail_closed` (governance.rs) — free-path (token=None) upgrade in
  `persist_finalized_send` (messaging_helpers.rs:2316-2322). Requires Active handle transition.
- `receive_suspension_sets_fail_closed_sink` (governance.rs) — WEAKER. Drives
  `deliver_message_and_drain_buffered` via class_c_view, asserts only the `&mut bool` sink is
  OR-set + suspension landed. Does NOT drive the cell-holding `handle_deliver_incoming` boundary
  persist. Receive path's OWN fail-closed persist is UNPROVEN end-to-end.

## Verified non-vacuousness mechanics (good patterns)
- Seed: present member + `member_capabilities` holding `MessagesWrite` + 5 buffered `MessageSent`
  + `MessageVelocity`/threshold-1/`SuspendAccess` rule → `suspend_all` returns `suspended:true`.
- `FailPersistence`/`FailToolPersistence`: persist_context always Err; rest Ok.
- `FailingCaptureAdapter`: authorize+verify_authorization Ok (run BEFORE capture), capture Err —
  reaches the capture-error arm rather than short-circuiting. Correct adapter contract.
- `new_for_test_with_escrow`: sets escrow+policy+deducted_cost so the REAL capture arm runs
  (match at tools_helpers.rs:944). NOT bypassing the path. Sound.
- Assertions match on `PersistenceFailed(_)` VARIANT not message text → refactor-robust.
- ctx id consistency: handler reads `cell.handle.context_id()` = `hex::encode([CTX_BYTE;32])`
  = test ctx_str = event-log storage key. Avoids the silent-drop-to-wrong-context footgun that
  the pre-existing `run_one` unit test documents.

## Coverage gaps found (apply to any §9 suspension-persist review)
1. H10 failure-escalation `suspend_all` path UNTESTED. `process_one_triggered_consequence`
   returns `true` from a SECOND source: `!enforcement.success` escalation
   (governance_logic.rs:329-332 `return true` after `emit_failure_escalation`→`suspend_all`).
   All tests reach suspension via the SUCCESS path only. A broken `return true` there would
   pass every test. Repro: empty `SuspendCapability{capabilities:vec![]}` → success:false →
   escalation.
2. `SuspendCapability` (typed/partial) vs `SuspendAccess` (all) distinction untested. All tests
   use SuspendAccess→suspend_all. `enforce_suspend` (governance_logic.rs:594-604) returns true
   only for non-empty caps, false for empty. The empty-caps NO-OP → must NOT fire fail-closed
   persist (`false`) boundary is the valuable untested case (guards over-eager persist).
3. `discharge_with` governance-execution suspension path — not in this diff; confirm covered
   elsewhere or it's a 5th call site owing the same fail-closed upgrade.

## Good practice to call out
- The weak receive test's doc comment HONESTLY names its own limitation ("persist mechanism
  proven by periodic/send tests above"). Self-documenting scope limits = reinforce this.
- Three high-ROI tests hit three STRUCTURALLY DISTINCT persist call sites (capture dual-arm,
  periodic reply, send free-path) — breadth not redundancy.
