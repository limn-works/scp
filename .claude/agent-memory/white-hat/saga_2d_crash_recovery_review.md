# Phase 2D Crash-Recovery Defensive Review (branch feat/2c-saga-dispatch, HEAD a784ca50d, 2026-06-23)

Commit a784ca50d adds `Supervisor::restore_on_startup` = replay_unresolved_sagas() THEN restore_all_contexts() (replay-FIRST). Routed into all 3 persistent bridges. WASM excluded (no journal, safe).

## DOMINANT FINDING (confirms another reviewer's HIGH): I1 liveness MISSING
- §17.16.4 (specs/17-persistence-and-storage.md:966) promises a non-terminal xctx caller-reversal is "left ... so a later sweep re-drives it once the caller context is restored." **That later sweep does NOT exist.** Only caller of replay_unresolved_sagas in prod = restore_on_startup (replay-first). No post-restore re-drive, no periodic reconcile, no respawn hook.
- All re-drive paths (redrive_caller_local_reversal ~7718, redrive_xctx_commit_in_progress ~6021/6106) do `self.lookup(caller_hex)` against RESIDENT actor registry. Replay-first guarantees lookup MISSES (no ctx resident yet) -> ReversalOutstanding -> non-terminal -> stranded across EVERY restart. Permanent caller over-charge + escrow leak — exactly what §17.16.4 says must never happen.

## CORRECT FIX = restore-then-replay (single pass), NOT a second sweep
- Per-case: every arm needing a live actor (xctx PreparingA/B caller reversal; Committing re-send to participants) needs RESTORE-FIRST. No arm requires replay-before-restore.
- Commit's rationale is INVERTED: "a now-resident caller re-driven down live-reversal path changes semantics" — re-driving the resident caller IS the recovery (Abort{None} delivers refund from durable CallerReservationRecord -> SettledOrAbsent -> correct terminal-Aborted).
- Idempotent (I3): Abort{None} record-keyed by SagaId, actor consumes CallerReservationRecord, clean no-op if drained, fresh lookup-by-ctx-id. Live RAII guard died with crash — no race. Safe to drive against resident caller.
- Residual edge under restore-then-replay: Closing/Closed/Expired caller (restore skips) with live reservation -> still stranded. Shrinks stranding set to this narrow case (replay-first strands ALL). Spec must specify: reverse from durable record without resident actor, OR force-rehydrate any ctx owning a live reservation.

## SPEC DEFECT — fix §17.16.4 FIRST (artifact-flow)
- Line 966 "a later sweep re-drives it once the caller context is restored" mandates a non-existent post-restore mechanism AND contradicts the wired replay-before-restore order. Phantom provenance: doc-comments claim §17.16.4 conformance while implementing the opposite. Amend spec to: restore-first, single startup pass, no separate deferred sweep; specify present-but-not-Active reservation disposition.

## TEST/GUARD GAP
- pipeline_wiring guards (restore_on_startup_runs_replay_before_restore, bridge_resume_path_routes_through_restore_on_startup) are source-text find()/fn_body_contains string checks — comment-evadable AND pin the WRONG (replay-first) order.
- ALL behavioral recovery tests (xctx_recovery_supervisor_with_present_contexts ~16495; 17850-18350 suite) deliberately spawn NO actors ("so lookup-misses"). Only the ReversalOutstanding->non-terminal arm is tested. The SettledOrAbsent->terminal DELIVERY arm (refund actually lands) is structurally unreachable + UNTESTED.
- Add behavioral test: real persistence pre-seeded w/ Active caller snapshot + live CallerReservationRecord + PreparingB journal entry -> restore_on_startup -> assert caller resident, load_unresolved empty (terminal), economy actually reversed, outstanding-counter not incremented. Fails under current wiring (would have caught this).

## Well-defended (preserve through fix)
- I2 no-premature-terminal safety: never writes terminal-Aborted while refund outstanding; Err-is-not-deletion conservative reaper (caller_context_deleted_from_persistence ~5923, reaps only on confirmed Ok(None)).
- I4 fold both sweeps behind one method (anti "exported but never called"). Folding is right; only order + missing executor wrong.
- Replay-error short-circuit (? before restore) fails closed.
