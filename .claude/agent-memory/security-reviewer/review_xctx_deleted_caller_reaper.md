---
name: review-xctx-deleted-caller-reaper
description: xctx-saga crash-recovery deleted-context reaper + convergent NTTEST gate audit — CLEAN, guarantees hold
metadata:
  type: project
---

# xctx-saga deleted-caller reaper + convergent Class-S gate (worktree xctx-saga, HEAD d161e8fd9, base 6b7c8b658) — CLEAN 2026-06-19

CLEAN, ZERO findings. Both guarantees hold. Gate PASSES (exit 0, all 42 self-tests). 3 new economic tests pass; scp-runtime --tests compiles clean.

**Why:** Crash-recovery hardening: `recover_preparing_b_entry` extracted from inline; adds (1) corrupt-evidence-but-live-caller reconcile via record-keyed `redrive_caller_local_reversal` (no longer collapses `None`-arm to `SettledOrAbsent`→terminal-Aborted stranding), (2) deleted-context reaper so a permanently-deleted caller's saga reaps instead of looping forever non-terminal.

**How to apply (economic integrity — no NEW over-charge):**
- Reaping (mark terminal-Aborted) fires ONLY inside the `ReversalOutstanding` branch AND ONLY when `caller_context_deleted_from_persistence(caller_hex)==true`.
- That helper returns `Ok(None)`→true (deleted), `Ok(Some)`→false (not-yet-restored, keep non-terminal), `Err`→false (transient, conservative). `persistence_ref()==None`→false.
- KEY SAFETY: `with_providers(persistence=None)` puts NoopContextPersistence in supervisor's OWN field but leaves `helper_persistence` slot EMPTY → `persistence_ref()` returns None → reaper short-circuits false. So Noop's always-`Ok(None)` can NEVER produce a false deletion signal (supervisor.rs ~1276-1302).
- `Ok(None)` is a reliable "deleted, record gone" signal: `xctx_caller_reservations` (the durable CallerReservationRecord) is a FIELD of ContextSnapshot (state.rs:969). Delete context → snapshot gone → record + the deduction obligation both die together. Nothing to strand.
- corrupt-evidence reconcile (participants[0] discriminant) strengthens, no regression: `xctx_caller_hex_from_participants` (len==3 + 64-hex[0]) only reached on PreparingB. ONLY xctx tool-invocation journals PreparingB in production (FSM Initiated→PreparingA→PreparingB; standing/broadcast use other states) — supervisor.rs:6110 sole prod append site; the 3 other appends are in test mod. So broadcast-misclassify concern is unreachable; doc's "harmless no-op" is belt-and-suspenders.
- Reaper applies to BOTH reconstructible (`redrive_xctx_prepare_in_progress`) and corrupt arms via shared ReversalOutstanding gate — consistent, correct.

**How to apply (the gate — convergent NTTEST pure strengthening):**
- `is_column0_item_start` is the SINGLE shared classifier used by BOTH the trailing-test-module DETECTOR (line 877) and the NTTEST vacuum GUARD (line 927). Can't drift.
- Now flags ALL column-0 item resumes after a trailing test mod (closes wave-15 fn-permutation denylist gaps: `mod resumed_prod`, `extern "C" fn`, `make_things!{}`). New self-tests 39/40/41.
- Does NOT false-positive a legit SECOND `#[cfg(test)] mod`: reopening test gate arms `pending_second_test_gate`; following `^mod ` consumed (no HIT). Self-test 42. Inner indented `#[test] fn` never matches (`^`-anchored regexes, no leading-ws allowance).
