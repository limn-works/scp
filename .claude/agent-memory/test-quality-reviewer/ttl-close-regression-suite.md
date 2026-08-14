---
name: ttl-close-regression-suite
description: Assessment of the ADR-049 PR-3 TTL-close regression suite; strong patterns + the belt-and-suspenders masked-gate weakness
metadata:
  type: project
---

ADR-049 PR-3 TTL-close fix (branch feat/adr049-pr3-live-timers, commits 1b7924982..21a93a88e).
Original suite missed all six defects (D1/D2/BUG-1/SEC-1/(d)/SEC-2) because the restore/import
re-arm path had ZERO behavioral coverage.

**Why: the fix moved TTL from relative `check_ttl(created_at, ttl, now)` to absolute convergent
`deadline_unix_secs` persisted as `ttl_deadline_secs`, re-armed on restore via the actor's
reconcile_timers.**

**How to apply:** This suite is a good reference for genuine regression gates — they drive the REAL
`respawn_from_snapshot` path and assert observable state (Active→Expired transitions, despawn,
durable snapshot `.state`/`.ttl_deadline_secs`, event-log leaf counts). Replicate this style.

Good patterns worth replicating:
- Restore tests persist a real snapshot then call `sup.respawn_from_snapshot`, advance paused time
  past the deadline, assert despawn + durable Expired snapshot. Real path, observable outcome.
- SEC-1 tests inject real provider failures (StallingEventLog = `future::pending()`; FlakyEventLog
  fails first append then succeeds) and assert actor stays ALIVE + persists Expired BEFORE teardown.
- `Notify::notify_one` stores a permit, so `timeout(N, recorder.persisted.notified())` under paused
  time fails in bounded VIRTUAL time (auto-advance) instead of hanging — deliberate, not flaky.
- Counter-cases pair every "refuse" gate with an "allow" case (create_after_terminal vs
  create_over_absent) — guards against over-aggressive prechecks.

**Masked-gate weakness (reusable lesson):** `stale_ttl_arm_does_not_fire_on_closed_or_tombstoned`
Part (a) asserts only "actor still resident" after a stale deadline on a terminal context. But the
SEC-1 keep-alive path independently keeps a terminal actor alive: even if the reconcile `is_active`
gate were reverted (arming the tick on a terminal context), the tick would fire → cleanup refuses
the non-Active transition → `has_failures()` → keep-alive retry → NO despawn → test STILL PASSES.
So Part (a) cannot isolate the reconcile-gate regression; it only fails if BOTH the gate AND the
cleanup's non-active refusal are reverted. When two defensive layers both prevent the same
observable, a residency/negative assertion gates neither in isolation. Strengthen by observing the
distinguishing signal (e.g. CapturingEventLog: assert ZERO expiry cleanup attempted on the terminal
context). Part (b) (durable clear of `deadline_unix_secs`) IS a clean isolated gate.

Minor: `key_destruction_failure_keeps_actor_alive_and_retries` injects an EVENT-LOG failure, not a
key-destruction failure (docstring honestly notes MlsCryptoProvider::destroy_* are infallible
DashMap ops). Name is misleading but justification is sound.
