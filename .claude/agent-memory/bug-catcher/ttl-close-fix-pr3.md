# TTL-close FIX commits (PR-3 live-timers, branch feat/adr049-pr3-live-timers, HEAD 21a93a88e)

Reviewed the 4 fix commits on top of 5752cd50a (SEC-1 retry, absolute ttl_deadline_secs,
is_active-gated arm, real-handle Execute/Finalize, dead-code sweep). BUG-1 (stale TTL arm
despawns terminal) IS resolved. Dead-code sweep clean (0 refs to check_ttl/TtlEnforcer).
finalize_close precondition safe (validates Closing before key destruction).

## NEW bugs found by the fix

- **HIGH: Promoted context re-expires on restore/respawn.** `execute_promote_context`
  (governance_helpers.rs:2752, pre-existing) clears `ttl.timer.deadline_unix_secs=None` but
  leaves `params.ttl=Some` and the context Active (`promote_memory_scope` only sets
  memory_scope=Full, mod.rs:149). The NEW restore gate (lifecycle_helpers.rs restore_context
  ~2652 + import_context ~2453) changed from "persisted remaining Some" to
  `params.ttl.is_some()` with fallback `ttl_deadline_secs.or_else(creation+ttl)`. So restore
  re-derives creation+ttl for the promoted (permanent) context → immediate re-expiry
  (creation+ttl is in the past for a long-lived promoted context). Root cause: the D1 fallback
  can't distinguish None=never-armed (create-window, should re-arm) from None=intentionally
  cleared (promoted, should NOT re-arm). OLD code gated on persisted remaining Some → promoted
  stayed un-armed (correct). Fix: on promote also clear params.ttl (or persist a ttl_disarmed
  marker) so the restore gate is false.

- **HIGH: reset_ttl_timer on a context with None deadline → immediate expiry.**
  ttl_close_helpers.rs:306-308 `old_dl = deadline.unwrap_or(0); new_dl = old_dl + new_duration;
  start_ttl_timer(new_dl)`. If deadline is None (no-TTL context, params.ttl=None), new_dl =
  new_duration secs = ~1970 absolute → reconcile arms sleep(0) → context expires immediately
  (+ key destruction/data loss for Ephemeral/Summary). Reachable via public FFI
  context_reset_ttl_timer (napi/uniffi pass deadline_override=None, no guard). ASYMMETRIC with
  execute_extend_ttl (governance_helpers ~1934) which guards `if let Some(deadline)` (no-op on
  None) — confirms reset's unwrap_or(0) is an oversight. Pre-fix reset armed now+duration
  (benign). Regression. Fix: mirror execute_extend_ttl's `if let Some` guard.

## Noted (design tradeoff, MEDIUM)
- SEC-1 retry is rate-bounded (5s) but count-UNBOUNDED: a Full-scope context with a
  permanently-wedged event log retries the STEP_EVENT_LOGGED leaf forever, never despawning
  (keys already fine, terminal state already durable). Actor/task leak; wedge-event-log DoS
  accumulates zombie actors for zero marginal security. ttl_expiry_completed only accumulates,
  reset only by teardown.
