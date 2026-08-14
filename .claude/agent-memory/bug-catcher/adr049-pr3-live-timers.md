# ADR-049 PR3 actor-owned live timers (feat/adr049-pr3-live-timers)

Refactor: TTL + governance timers became ACTOR-OWNED `select!` arms in
`actor/mod.rs` `run()`/`reconcile_timers`. Deleted supervisor `task_set`,
`GovernanceTimeoutTask`, `spawn_ttl_timer`, `FireTimer`, `EvaluateTimeouts`,
`StartTimeoutTask`, `run_ttl_expiry_with_retries`.

## BUG FOUND (HIGH) — stale TTL arm fires on closed/tombstoned contexts
- `reconcile_timers` TTL branch is NOT gated on `is_active` (unlike the
  governance interval which IS). It only re-arms when `deadline != ttl_armed_deadline`.
- Close/tombstone paths removed the old `state.ttl.timer.cancel()` but do NOT
  clear `deadline_unix_secs`: `execute_close_context`,
  `close_context_with_key`, `tombstone_migrated_context`. Only
  `execute_promote_context` (governance_helpers.rs:2756) correctly clears it.
- Result: a TTL-bearing context closed BEFORE its deadline keeps its armed
  one-shot `sleep`. At the original deadline `on_ttl_tick` runs
  `handle_ttl_expiry` → `try_ttl_expiry_cleanup` on a non-Active context →
  hits `_ =>` arm → spurious `ExpiryFailed` event emitted + fanned out.
  Terminal check `matches!(state, Expired|Closed|Tombstoned)` → for
  Closed/Tombstoned returns true → actor DESPAWNS itself. A tombstoned
  (migration-final / anti-replay) or closed context becomes unknown + RE-CREATABLE.
- The close-path comments conflate: they claim `reconcile_timers` clears the
  timers on non-Active, but that's only true for the GOVERNANCE interval, not
  the one-shot TTL arm. Root cause = that conflation.
- Fix: clear `ttl.timer.deadline_unix_secs = None` in the 3 close/tombstone
  paths (symmetric with promote), OR gate the reconcile_timers TTL arm on is_active.
- `handle_shutdown_self_actor` also dropped the cancel but is SAFE because
  Shutdown breaks the run loop (actor exits, arm dropped with task).

## Checked-and-OK (not bugs)
- Removing `run_ttl_expiry_with_retries` is NOT a regression: production actor
  path (FireTimer→handle_ttl_expiry) already used single-attempt
  try_ttl_expiry_cleanup on origin/main; the retry loop was test-only scaffolding.
- Governance interval conversion sound: first tick +60s, MissedTickBehavior::Delay,
  Ok(false) on non-Active nulls interval, reconcile re-arms while Active.
- Cancel-safety of TTL Sleep / governance Interval / persist sleep_until arms: OK.
- Fairness bound (MAX_CONSECUTIVE_INBOX + Arm 5 fall-through): no deadlock, self-heals.
- No lingering live refs to deleted symbols (task_set/tracked_spawn/FireTimer/etc.);
  all remaining are comments. pipeline_wiring.rs changes are comment-only.
