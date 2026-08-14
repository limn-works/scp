---
name: adr049-actor-timer-arms
description: Test coverage gaps in ADR-049 A3 actor-owned TTL/governance timer migration (PR feat/adr049-pr3-live-timers)
metadata:
  type: project
---

# ADR-049 A3: actor-owned timer arms — test coverage profile

PR moves TTL + governance-timeout timers from supervisor `task_set` spawns to
actor-owned `select!` arms in `ContextActor::run()` (`reconcile_timers`,
`on_ttl_tick`, `on_governance_timeout`, fairness bound `MAX_CONSECUTIVE_INBOX`).

**Why:** Three real TTL-restore bugs (D1 create-window stuck-open, D2
extension-loss-on-restore, (d) non-idempotent expiry leaf) reached near-merge and
were NOT caught by existing tests — a test-quality failure.

**How to apply — the coverage holes that let D1/D2/(d) through:**
- The restore/import re-arm path (`restore_context` / `import_context` →
  `dispatch_start_ttl_timer(..., anchor_deadline_to_creation=true)`) is
  ENTIRELY untested with a finite TTL. Existing `restore_with` helper
  (lifecycle_helpers.rs ~3552) only exercises routing/mode validation, never TTL.
- D2 root cause: restore re-arms via `convergent_ttl_deadline_secs(creation, params.ttl)`
  (ttl_close.rs:127) which uses ORIGINAL params.ttl, ignoring any extension —
  a snapshot round-trip test asserting re-armed deadline == extended deadline would catch it.
- The two new behavioral tests (`actor_owned_ttl_arm_fires_and_despawns_self`,
  `actor_owned_governance_interval_fires_and_stops_when_not_active`) arm the
  deadline DIRECTLY on a fresh actor — they never go through restore, so D1/D2 slip.

**Weak/false-confidence assertions found:**
- `actor_owned_governance_interval_fires_and_stops_when_not_active` asserts
  persist-count increments. But `evaluate_governance_timeouts` returns
  `Outcome::ok_mutated(true)` UNCONDITIONALLY (governance.rs:1254), so persist
  fires even when the sweep expires zero proposals. The test proves the interval
  ticks, NOT that a timed-out proposal is actually resolved. The deleted
  `proposal_expires_via_background_task` DID assert real ProposalStatus::Expired —
  net coverage regression on governance consequence.
- pipeline_wiring `actor_owned_timer_arms_reconcile_from_state` is a string-match
  structural test (`fn_body_contains`). Pins the mechanism (run calls
  reconcile_timers, etc.) but passes even with buggy reconcile logic — no behavior.

**Untested new logic:** `reconcile_timers` idempotence guard (`ttl_armed_deadline`
re-arm-only-on-change), fairness bound (MAX_CONSECUTIVE_INBOX starvation),
MissedTickBehavior::Delay no-catch-up-burst, past-deadline restore idempotent re-close (d).
