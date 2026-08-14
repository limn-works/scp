---
name: actor-timer-reconcile
description: ADR-049 A3 actor-owned TTL/governance timer arms — reconcile-from-state disarm misses the close/tombstone path (spurious ExpiryFailed)
metadata:
  type: project
---

# Actor-owned timer arms (ADR-049 A3, commit d8d81e33d) review

Refactor moved TTL + governance timeouts from supervisor spawned-tasks to
actor-owned `tokio::select!` arms driven by `reconcile_timers()` (top of
`run()` loop). Timers disarm by nulling `ttl_timer`/`governance_timeout`,
reconciled from owned state each turn.

**Verified-correct fixes:** HANDLER_TIMEOUT wrap on `on_ttl_tick`
(`timeout(HANDLER_TIMEOUT, handle_ttl_expiry)`); TTL-terminal self-despawn
(`despawn_actor(&self.context_id).await` before `break` — write_lock, no
.await held, no deadlock/reentrancy; race-safe because A's two break paths
(TTL-terminal vs claimed-PrepareForReplace) are mutually exclusive and
`bootstrap_spawn_lock`+`contains_key` prevent a concurrent re-register while
A is still in `actors`); fairness guard (`MAX_CONSECUTIVE_INBOX=32` +
`ready(())` fall-through arm5 — arm5 enabled exactly when arm1 disabled so
select! is never all-disabled → no panic; resets counter → no busy-spin).

**REGRESSION FOUND (MEDIUM):** `reconcile_timers` disarms the TTL arm ONLY
when `deadline_unix_secs` changes to None. `execute_promote_context` and
`execute_extend_ttl` rewrite/null the deadline (covered). BUT
`execute_close_context` and `tombstone_migrated_context` (governance_helpers.rs)
do NOT clear `deadline_unix_secs` — their comments only note the governance
interval clears via non-Active. The OLD code called `state.ttl.timer.cancel()`
there (removed in this diff — NOT a no-op). Result: a TTL-scoped context
closed/tombstoned BEFORE its TTL deadline keeps its TTL arm armed; the actor
lingers (close does NOT despawn — deliberate, per read_context_state doc). At
the original deadline `on_ttl_tick`→`try_ttl_expiry_cleanup` hits the `_ =>`
arm (state Closing/Closed/Tombstoned, expects Active/Expired) → emits spurious
`ContextEvent::ExpiryFailed{reason:"context is in Closed state..."}` to
receive_buffer + broadcast tx + `tracing::error!`. Fix: mirror promote —
`view.ttl_mut().timer.deadline_unix_secs = None` in both commit closures.

**LOW:** stale doc on `Supervisor::read_context_state` ("Close / TTL does NOT
despawn the per-context actor") — TTL now DOES despawn after fix #2.

**Pattern:** "reconcile-from-state" disarm silently misses any terminal
transition that doesn't mutate the reconciled key. When replacing an explicit
`cancel()`/side-effect with derive-from-state, enumerate EVERY caller of the
old cancel and confirm each now mutates the derived key.
