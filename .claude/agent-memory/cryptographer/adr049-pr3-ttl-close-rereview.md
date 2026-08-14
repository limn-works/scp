---
name: adr049-pr3-ttl-close-rereview
description: ADR-049 PR-3 live-timers TTL-close SEC-1 fix re-review (commit 21a93a88e) — 6 findings RESOLVED + one MEDIUM regression in reset_ttl_timer
metadata:
  type: project
---

# ADR-049 PR-3 TTL-close SEC-1 fix re-review (branch feat/adr049-pr3-live-timers, HEAD 21a93a88e)

Fix = `git diff 5752cd50a 21a93a88e` (23 files). Reviewed READ-ONLY.

**Why:** SEC-1/BLACK-P3-001 hostile-relay resurrection + key-leak window; D1 create-window stuck-open; D2 extension-loss; SEC-2 non-terminal disarm; (d) idempotent leaf; B10 real-handle.
**How to apply:** all 6 RESOLVED. Design is sound. One NEW MEDIUM below — flag if PR-3 revisited.

## Verified RESOLVED
- SEC-1: handle_ttl_expiry (ttl_close_helpers.rs:115) = Phase1 apply_ttl_terminal_transition (sync FSM→Expired + key destroy, OUTSIDE timeout) → commit_class_s_keep FAIL-CLOSED persist of Expired (keep-direction, no rollback) → Phase2 finish_ttl_expiry_io INSIDE timeout. on_ttl_tick despawns (return true) ONLY when terminal && result.is_complete() && persist_result.is_ok(); run() Arm2/2b calls on_ttl_tick THEN despawn_actor THEN break. Durable Expired strictly before despawn. commit_class_s_keep (class_s.rs:2792) genuinely fail-closed.
- (d): finish_ttl_expiry_io + finalize_close consult terminal_leaf_exists (event_log_entries tail) before append; Ok(None)|Err(_)→false safe fallback (append under bitmask).
- D1/D2: ContextSnapshot.ttl_remaining_secs → ttl_deadline_secs (ABSOLUTE, #[serde(default)]). Both snapshot builders (manager_methods.rs:268, messaging_helpers.rs:2694) map deadline_unix_secs. restore/import gate handle.params().ttl.is_some(), deadline = ttl_deadline_secs.or_else(convergent_ttl_deadline_secs(creation, params.ttl)). close_context_with_key clears deadline (BUG-1).
- SEC-2: reconcile_timers is_active-gates BOTH ttl_timer + governance; clears on non-Active. on_ttl_tick non-terminal branch nulls ttl_armed_deadline.
- B10: handle_execute_ttl_close + handle_finalize_close both `cell.handle.clone()` (shared ArcSwap), no throwaway ContextHandle::new. ExecuteTtlClose surfaces inner persist/cleanup error.
- Dead-code sweep removed handle_ttl_expiry_with_transport/run_ttl_expiry_with_retries. try_ttl_expiry_cleanup RETAINED but now DELEGATES to apply_ttl_terminal_transition + finish_ttl_expiry_io (tested composition wrapper, not dead dup).
- create-terminal precheck (supervisor.rs ~2701): Ok(Some(terminal))→refuse; Err(read fault)→refuse fail-closed (PersistenceFailed). NO fail-open.

## NEW MEDIUM (regression from pass-1 150bfccd5)
reset_ttl_timer (ttl_close_helpers): `old_dl = deadline_unix_secs.unwrap_or(0); new_dl = old_dl + duration; start_ttl_timer(new_dl)`. On None prior deadline (no-TTL context, params.ttl=None) → new_dl = duration-since-1970 → PAST → reconcile arms sleep(0) → IMMEDIATE expiry (Ephemeral = key destruction). Reachable via unguarded FFI context_reset_ttl_timer on a no-TTL context. governance execute_extend_ttl (governance_helpers.rs:1942) GUARDS `if let Some(deadline)` — bilateral reset does NOT. Pre-fix armed now+duration (future). Fix → immediate expiry. RECOMMEND: mirror the `if let Some(deadline)` guard (no-op / explicit "no TTL to extend" on None). Also FFI doc "spawns a new timer with the given duration" is stale (now extends old+duration).

## LOW/info
- Phase2 leaf append runs even when Phase1 fail-closed persist Err → observable ContextExpired leaf can precede durable Expired snapshot. Self-heals (idempotent re-expiry + check_ttl), no Merkle divergence. Consider gating on persist_result.is_ok().
- Field rename breaks cross-version signed-export digest (JCS changes). No KAT. Acceptable pre-release.
- ttl_expiry_retry: unbounded 5s fixed backoff (vs retired exp-backoff max-5). Intentional fail-closed.

## GOTCHA (process)
Bash cwd resolves to MAIN worktree (/Users/alec/Developer/limn/scp), which was on a DIFFERENT branch (ceiling, 1620de983) NOT containing PR-3. Read tool + working-tree grep gave WRONG-branch content. Must review via `git show 21a93a88e:<file>` / `git diff 5752cd50a 21a93a88e` (commit-pinned). Agent worktree agent-a9a59e51697d57907 is the intended cwd but Bash didn't land there.
