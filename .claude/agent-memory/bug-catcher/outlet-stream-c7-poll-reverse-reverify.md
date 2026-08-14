---
name: outlet-stream-c7-poll-reverse-reverify
description: C7 re-verify of poll_next GIL test-guard (62891223d) + grant crash-recovery reverse path (66b3fe424) on feat/outlet-streaming-ffi — both CLEAN, empirical hang proven
metadata:
  type: project
---

# C7 poll_next guard + grant-reverse re-verify (branch feat/outlet-streaming-ffi @13c89fabd, worktree scp-wt-ffi)

**Both fixes CLEAN. My prior poll_next MEDIUM is fully resolved.**

## 1. poll_next test-guard (62891223d) — EMPIRICALLY PROVEN
`outlet_stream_live_poll_next_drains_to_terminal_without_gil_deadlock` (e2e_bridge.rs:2280).
Reordered so the FIRST poll_next parks on the live pump BEFORE any grant_credit (default credit window >=1 admits chunk-1 with no grant → poll parks awaiting the Python handler's GIL-reacquire).
- Baseline (tree as-is): PASS 0.06s.
- Reverted ONLY poll_next's allow_threads (outlet_stream.rs:686, left grant/cancel/terminate allow_threads intact) → recompiled → **EXPLICIT_EXIT=124 (hang/timeout)**. Guard is TIGHT: fails exactly when the poll_next fix regresses. Restored (git diff clean).
Why the prior version was a non-guard: grant_credit has its OWN allow_threads → pump buffered both chunks during grant's GIL window → later poll read buffered, never parked.

## 2. grant crash-recovery reverse path (66b3fe424) — concurrency SOUND
reserve_stream_grant_escrow bumps durable record.reserved_escrow (or_insert_with creates on zero-open) ATOMICALLY with budget debit under commit_class_s_compensating (persist-fail snapshot-restores Class-S record + Class-C reverses budget). New reverse_stream_grant_escrow credits budget + un-bumps record in ONE commit_class_s_keep closure (both saturating). request_id threaded bridge→supervisor→command→handler→helper on both legs (same request_id to reserve+reverse in bridge outlet_stream.rs).
Concurrency verified:
- No lock-across-await: `handle.lock().await.apply_credit_grant(...)` guard drops at `;` (returns owned Result) → reverse mailbox await does NOT hold pump handle lock.
- reserve/reverse/settle/reconcile all serialize on the actor mailbox → no data race.
- Atomicity: both legs in ONE keep-closure → no crash window between budget-credit and record-un-bump.
- Reverse always runs on apply-reject; only Errs when actor torn down (budget+record moot). No path where reserve succeeds but reject-reverse is skipped.
- No double-remove/UAF: record via entry/get_mut, `if let Some` guards absence, no RAII grant ticket (so the "double-reverse safe no-op" doc scenario — Drop-guard racing reverse — has no trigger; note: saturating != idempotent, but unreachable).
- settle-races-reverse interleavings all net to `billed` (settle refunds pump ledger not record; reverse credits budget unconditionally, record un-bump skipped-if-removed).

## LOW (very minor, near-unreachable)
Lingering zero-record: open-reserved-0 stream + single grant that REJECTS (record created then un-bumped to 0) → settle's `record_persisted = reserved>0 || cum>0` is false → settle does NOT remove the zero record → lingers in durable class_s.stream_reservations until next restart's reconcile (which refunds 0, clears). No money impact. Near-unreachable in prod (bridge signs internally so no bad-sig; stream-closed reject means settle already ran; replay needs 2 grants where the applied one makes reserved>0). Cosmetic durable-state cleanliness only.

## Regression
- scp-ffi `-E test(outlet_stream)`: 3/3 PASS (features allow_in_memory_custody,testing,outlet-capability-test-grant).
- scp-runtime grant/reconcile/reverse/settle/stream_reserv: 104/104 PASS. Key: grant_debits_incremental_escrow_and_bumps_record, grant_creates_record_when_open_reserved_nothing, grant_reserve_then_reverse_conserves_budget_and_record, grant_then_hard_crash_reconcile_refunds_open_plus_grant, grant_persist_failure_reverses_debit_and_restores_record, clean_settle_clears_recovery_record. No vacuous passes (crash test asserts total_spent==0 + record cleared).

ENV: scp-ffi testing feature pulls scp-core/testing (which pulls scp-runtime/testing) — do NOT pass `scp-ffi/scp-runtime/testing` (E "does not contain this feature"). scp-wt-ffi worktree durable this session.
