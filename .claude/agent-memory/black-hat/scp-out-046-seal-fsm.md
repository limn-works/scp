---
name: scp-out-046-seal-fsm
description: Money/atomicity attack surfaces in SCP-OUT-046 streaming-saga seal-phase FSM (feat/outlet-xctx-046-seal-fsm)
metadata:
  type: project
---

# SCP-OUT-046 streaming-saga seal FSM — money/atomicity findings

Branch feat/outlet-xctx-046-seal-fsm. Core defect: the xctx streaming saga has
NO durable escrow-refund recovery net. Same-context path persists a
`stream_reservations` record (dispatch.rs:2396, gated on `settlement_sink=Some`)
that `reconcile_stream_reservations` sweeps on restore. The xctx saga path opens
with `settlement_sink=None` (supervisor.rs:6648) → that record is NEVER created.

## CRITICAL — seal/settle non-atomicity strands escrow (BLACK-046-1)
The seal (commit_b_stream_first_settle, saga.rs) records the durable witness
`xctx_committed_stream_outputs[saga_id]` + removes the `saga_pending` slot in ONE
Class-S persist, but the actual money move (refund invoker `reserved-billed` +
capture billed + release §7.3.8 counter) is a SEPARATE off-mailbox persist
(`settle_outlet_stream_via_actor`, invoke.rs:5170). Crash/evict/gen-mismatch in
that window:
- witness present ⇒ replay yields `settlement: None` (reemit_committed_stream_settle
  saga.rs; recover_streaming_committing_entry supervisor.rs:7814 resolves Committed
  and applies NO money).
- no stream_reservations record ⇒ reconcile sweep is a no-op.
Result: invoker OVER-charged (reserved-billed never refunded), counter never
released (spend-cap griefing), operator sometimes UNDER-charged (billed never
captured on process crash). Money not conserved.
Three triggers: (a) process crash between the two persists; (b) B evicted →
no-actor fallback (supervisor.rs:11845) captures billed but "refund moot" —
false, debit is durable; (c) Fix-D generation-mismatch (outlets_helpers.rs:1659)
CapturedWithoutMutation, comment relies on the nonexistent reconcile record.
Witness struct comment (saga_prepared_state.rs:711) literally assumes "money
already moved on the first settle" — it hasn't.

## HIGH — dual-log not atomic (BLACK-046-2, attack #5)
B's OutletInvoked appended inside seal; A's CrossContextOutletInvoked recorded
best-effort AFTER seal returns (invoke.rs:5160, "best-effort"). Crash between ⇒
B leaf present, A leaf absent; recovery (witness present) never re-records A.
Roots don't diverge (both use sealed outcome root) but A-leaf can be missing.

## MEDIUM — deliver-then-fold under-charge (attack #3 normal path)
forward_frame (deliver, invoke.rs:5030) precedes StreamCaptureAppend (durable
fold, 5046). If fold fails/crashes, delivered chunk unbilled. Bounded ~1 chunk.

## Verdicts
- #1 double-settle: NO EXPLOIT. Witness idempotency sound (prevents double-move);
  bug is the opposite (first move lost). Overlapping-set sagas each have own
  request_id/slot — no shared reservation.
- #6 slot-release abuse: NO CEILING EXPLOIT. pump_permit (OwnedSemaphorePermit,
  dispatch.rs:2218) is the real node-wide cap, independent of the released
  SagaSetReservation. Residual: long-lived pumps can hold all permits (node-wide,
  economically bounded by escrow). No per-invoker cap.
