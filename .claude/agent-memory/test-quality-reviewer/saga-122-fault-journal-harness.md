# #122 fault-injectable saga-journal harness (supervisor.rs tests, @c39857b0f)

3 live-FSM tests + FailingSagaJournal/VoidCountingPaymentAdapter doubles. +717 LOC pure test.

## KEY FINDING (BLOCKER) — non-distinguishing escrow-held assertion
- Test `xctx_saga_err_arm_commit_exhaustion_needs_repair_escrow_held` asserts `voided==0` to claim "escrow HELD on NeedsRepair (not auto-voided)". The xctx test tool is FREE (`cost: None`, supervisor.rs:15813 in xctx_target_state) AND xctx_caller_state sets NO economic_policy → Prepare-A stages a ticket with `escrow: None`.
- `void_external_and_consume`/`hold_external_for_repair` (tools_helpers.rs:252,305) only touch the adapter when `escrow.is_some()`. With escrow None, `void` is NEVER called on ANY terminal → `voided==0` holds trivially. Swapping supervisor.rs:5490 `hold_external_for_repair()` → `void_external_and_consume(adapter)` (the exact free-execution regression the test names) keeps it GREEN. Dead/gamed assertion per anti-gaming tenet.
- COVERAGE GAP confirmed: the hold-side with REAL escrow is untested EVERYWHERE. The other `needs_repair_holds_escrow_without_voiding` unit test (supervisor.rs:19494) ALSO uses `new_for_test_no_escrow`. Void-side IS covered: actor-level `reverse_caller_reservation_record_voids_external_escrow` (saga.rs:5451) injects escrow_authorization Some → voided==1.
- `hold_external_for_repair(mut self)` takes NO adapter param → primitive structurally can't void; the only regression vector is the CALL SITE (supervisor.rs:5483-5500) → needs an INTEGRATION test with escrow present, not a primitive unit test.
- FIX FEASIBLE without spending UCAN: escrow staged at tools_helpers.rs:790 whenever `(economic_policy, payment_adapter)` both Some, INDEPENDENT of action_cost; the spending-UCAN gate (line 624) only fires when `action_cost.0 > 0`. So a zero-cost economic_policy on xctx_caller_state + VoidCountingPaymentAdapter (authorize returns Ok) → escrow: Some, no UCAN needed. Then voided==0 on NeedsRepair becomes distinguishing; add contrasting live-FSM abort (voided==1) to prove the adapter is wired into THIS path.

## Tests 2 & 3 — STRONG, mutation-resistant
- Ok-arm (`..._mark_resolved_fault_is_needs_repair_not_aborted`): NeedsRepair + !Aborted + calls==1 + durable Committing. Distinguishing. `!matches!(Aborted)` redundant-but-harmless given NeedsRepair already matched.
- Self-heal (`..._committing_self_heals_to_committed_on_reopen`): load_unresolved empty (compacted) + calls==1 (no re-invoke). Distinguishing.
- Both call drive_xctx_mark_resolved_committed_fault() fresh (drive runs 2×) — isolation>DRY, fine.

## Flakiness — LOW
- Err-arm uses manual `start_paused(true)` current-thread runtime so 500ms/1s/2s commit backoff auto-advances; metric via thread-local `with_local_recorder` (process-global cache poisoned across parallel binary). Tests 2/3 plain #[tokio::test], no timer (commit succeeds first try). Orchestrator confirmed no deadlock, 88/88 pass.

## Minor
- VoidCountingPaymentAdapter DUPLICATED (also in saga.rs actor tests) — shared-helper anti-pattern.
