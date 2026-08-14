---
name: xctx-saga-preparing-a-recovery-window
description: §6.2.4 cross-context saga — PreparingA crash-recovery arm marks Aborted while a durable caller deduction is outstanding (refund leak)
metadata:
  type: project
---

# §6.2.4 saga: PreparingA recovery arm strands the caller refund

**Where:** `crates/scp-runtime/src/context/supervisor/supervisor.rs`
- `dispatch_full_saga` (~6100): journals `PreparingA` (seq 1, line 6110), THEN `dispatch_prepare_phase(A)` (6113) — which makes the caller actor Class-S **persist the deduction + `CallerReservationRecord`** (`saga.rs` prepare_a, line 476) — THEN journals `PreparingB` (line 6141).
- `recover_saga_entry` `SagaState::Initiated | SagaState::PreparingA` arm (line 5406): UNCONDITIONALLY `mark_resolved(Aborted)` with comment "No remote side-effects yet."

**The window:** supervisor crashes AFTER the PrepareA actor durably persisted the caller deduction+record (per-context snapshot store) but BEFORE the supervisor appends the `PreparingB` journal entry. On restart the journal's latest entry is `PreparingA`; the arm marks Aborted without reversing the durable deduction. No orphan-reservation sweep exists keyed on `xctx_caller_reservations` — recovery is purely journal-driven, and `xctx_caller_reservations` lives in the per-context snapshot (separate store from the saga journal).

**Impact:** permanent silent caller over-charge (budget/velocity/hard-rate-limit) + leaked `CallerReservationRecord` + potentially stranded external escrow. Directly violates the §6.2.4 invariant the whole `PreparingB` machinery enforces: never terminal-Aborted while a caller refund is outstanding.

**Why the rest is clean:** the `PreparingB` arm (`recover_preparing_b_entry`) and live `abort_saga`/`abort_xctx_participants` correctly gate terminal-Aborted on a confirmed `CallerAbortReversal::SettledOrAbsent` and leave the journal non-terminal otherwise. The `PreparingA` arm is the one path that bypasses this — it predates / sits outside the reversal-confirmation design.

**Fix direction:** the `PreparingA` recovery arm must, for a cross-context entry, drive the record-based reversal (`redrive_caller_local_reversal` / the deleted-context reaper) exactly like the `PreparingB` arm, and only mark Aborted on a confirmed `SettledOrAbsent`. Simplest: route `Initiated|PreparingA` xctx entries through the same `recover_preparing_b_entry` reconciliation. (`Initiated` has no deduction yet, so it's safe to keep unconditional, but `PreparingA` is not.)

**No test exists** for a PreparingA-with-durable-deduction crash; PreparingB/Committing are heavily tested.
