---
name: review-xctx-wave15-crash-recovery-terminal-marker
description: §6.2.4 wave-15 crash-recovery PreparingB sweep terminal-marker gating + NTTEST const/unsafe-fn gate hardening — CLEAN, guarantees hold
metadata:
  type: project
---

# §6.2.4 wave-15 crash-recovery terminal-marker symmetry + NTTEST hardening — CLEAN

Worktree `xctx-saga` HEAD `6b7c8b658` (delta `9d168759c..`). 2 files: supervisor.rs (+480/-44), check-class-s-fail-closed.sh (gate). Read-only audit. ZERO findings — all three requested guarantees hold.

**Why:** Closes a replay-before-restore over-charge: the startup `recover_saga_entry` PreparingB arm previously marked terminal-`Aborted` UNCONDITIONALLY, so if `replay_unresolved_sagas` ran before the caller context was restored (lookup miss) the caller's durable Prepare-A LOCAL-economy deduction was never reversed AND could never be (sweep re-drives only NON-terminal journals) → permanent over-charge.

**How to apply (verified facts for future xctx-saga reviews):**
- **Economic integrity CONFIRMED.** `redrive_xctx_prepare_in_progress` now returns `CallerAbortReversal`; caller leg routes through `redrive_caller_local_reversal` (record-based `Abort{None}`), target leg via `abort_target_leg` (orthogonal best-effort). Recovery arm @supervisor.rs:5445-5475 marks terminal ONLY on `SettledOrAbsent`; on `ReversalOutstanding` it `return`s (no journal append → no per-sweep growth) leaving PreparingB for a later sweep. STRUCTURALLY IDENTICAL to live `abort_saga` path @7056-7093.
- **`SettledOrAbsent` = durably reversed, not just enqueued.** `handle.send` awaits the oneshot reply; the actor abort handler @actor/handlers/saga.rs:1878-1893 calls `persist_state_fail_closed` BEFORE acking `Ok(())` — persist failure → `Err` reply → `ReversalOutstanding`. So the verdict is a genuine "delivered + Class-S-persisted" signal.
- **No double-refund.** `Abort{None}` path does `xctx_caller_reservations.remove(saga_id)` FIRST; already-consumed record → `None` → `(false,false)` clean no-op. Record removal persisted before ack. Gen-agnostic `reverse_caller_reservation_record` is correct here (respawn stamps new gen that never matches pre-crash record; gating would skip every real refund).
- **Concern 2 (stuck non-terminal) acceptable.** Leaving PreparingB is strictly better than the over-charge: bounded by count of genuinely-stranded sagas (caller never restored), NOT by sweep count (no re-append). `replay_is_idempotent_after_first_pass` integration test passes.
- **NOTE:** `replay_unresolved_sagas` is `pub async fn` but currently invoked ONLY from tests — not yet auto-wired into production restart. Pre-existing, orthogonal to this change; the in-tree comment ("ordering of context restore vs replay not enforced in-tree") is honest about it. The non-terminal-leave design DEPENDS on that sweep eventually being driven (repeatedly) once wired.
- **NTTEST gate = pure strengthening.** Only removed non-comment line is the old regex, replaced by a SUPERSET (adds `unsafe fn`/`const fn`/`const unsafe`/`unsafe const` alternatives; every prior alt preserved verbatim). `seen_test`/`nontrailing_hit` latch untouched. Fixture 38 + positive assertion added. Gate `bash scripts/check-class-s-fail-closed.sh` PASSES (exit 0, zero self-test failures). Non-exploitable today (forbid(unsafe_code) + const fn can't run state mutation) — vacuum-hardening only.
- **Empirical:** cargo check -p scp-runtime --tests clean; 2 new tests + 17 xctx + 3 crash-recovery integration tests all PASS.

SUPERSEDES the prior wave-14 OVER-CHARGE finding for the import-replace path (`finding_xctx_abort_stale_gen_overcharge.md`) only insofar as the SWEEP terminal-marker race is now closed; that stale-gen live-Abort finding was a different code path.
