---
name: adr049-d7-commit-fault-failclosed
description: ADR-049 D7 PR-3 safety-gate fix — split try_broadcast_commit / apply_broadcast_failure to restore fail-closed commit_fault persist after async transport. CLEAN review.
metadata:
  type: project
---

# ADR-049 D7 commit_fault fail-closed restore (b45f9de5a, branch chore/adr049-d7-transport)

**CLEAN — no real bugs.** Reviewed b45f9de5a (fix) + 167c23078 (doc), base 140786f56, vs main b9ea04f72. `cargo check -p scp-runtime` green (borrow + Send backstop).

Context: PR-3 made ContextTransportProvider async → the MLS-Commit broadcast could no longer live inside the sync `commit_class_s_keep` closure, so PR-3 base hoisted it out and applied `commit_fault`/`pending_commits` COALESCED (≤50ms tick) — a crash window loses the safety gate (silent MLS desync). Fix splits `try_broadcast_commit_or_enqueue` → `try_broadcast_commit` (async, send-only, no state mutation, returns `Option<BroadcastFailure>`) + `apply_broadcast_failure` (sync, applies bookkeeping); caller picks durability class.

Verified:
- **No state mutation in try_broadcast_commit:** takes only `&ActorDeps`/`&str`/`Vec<u8>`/`&CommitOperation`, no `&mut` state. Sound.
- **Apply-exactly-once:** all 6 sites `if let Some(failure)=try_broadcast_commit().await { apply_broadcast_failure(failure) }`; `BroadcastFailure` moved by value once. None-on-success/empty. No double-apply, no dropped failure.
- **Borrow soundness of 2nd commit_class_s_keep:** 3 disjoint fields (state.pending_commits, state.commit_fault, state.receive_buffer) from `view.rest_mut()` — distinct named fields of PerContextState, compiler-accepted, no aliasing. Closure returns Ok(()), `?` propagates PersistenceFailed.
- **MAX_PENDING_COMMITS + marker identical:** queue-full check moved into apply_broadcast_failure, runs against LIVE `&mut pending_commits` at apply time. `failed_at: pending.first_attempt_at` == old `failed_at: now` (first_attempt_at set to same `now` at gov_helpers:5493). retry_count:1, operation identical. No behavior change.
- **Double-persist failure mode:** commit_class_s_keep = keep (no restore on persist fail; messaging_helpers:2787). removal durable (1st keep), commit_fault retained in-memory + PersistenceFailed surfaced via `?`. Matches main keep-direction.
- **Site classification complete (exactly 6 sites, 1:1 with PR-3 base):** FAIL-CLOSED on main→restored: execute_remove_member, execute_rotate_content_keys (gov_helpers), leave_context (lifecycle) — 2nd commit_class_s_keep. BEST-EFFORT on main→unchanged: execute_add_member (was commit_class_c_best_effort), execute_reset_member (takes `view: &mut ClassCMut` param) — coalesced. No missing site; grep of both branches confirms.
- Doc commit 167c23078: accurate (relay_persistence.rs has zero real block_in_place; both matches are doc-comment negations).

**Observation (NOT a bug):** residual non-atomicity — removal persists in 1st keep, commit_fault in 2nd; if broadcast fails AND 2nd persist fails AND crash → removal durable without gate. Strictly BETTER than PR-3 base (needed only a crash in 50ms window), and inherent to async transport (broadcast outcome unknowable at removal-persist time), so two persists unavoidable. Not fixable without reverting async.
