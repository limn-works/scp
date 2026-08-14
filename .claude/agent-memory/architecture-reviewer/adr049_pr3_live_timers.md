---
name: adr049-pr3-live-timers
description: ADR-049 PR-3 review — TTL + governance timers migrated from supervisor task_set to actor-owned select! arms (finding A3 / Decision-1)
metadata:
  type: project
---

# ADR-049 PR-3: live timers → actor-owned arms (branch feat/adr049-pr3-live-timers, base 0f26442ac)

Migration: TTL-expiry + governance-timeout timers moved from supervisor-driven `task_set` spawns
(that resolved the actor via `lookup` and mailboxed a `FireTimer`/`EvaluateTimeouts` tick) to
ACTOR-OWNED `select!` arms reconciled from owned state inside `ContextActor::run()`.

**Why:** This is EXACTLY what ADR-049 §1 / Decision-1 prescribes verbatim: "run() loop is a
tokio::select! with four arms: inbox command dispatch, TTL timer, governance timeout,
coalesced-persistence tick." The prior state was a half-migrated seam (arms existed as no-op stubs
driven by the legacy supervisor task_set). PR-3 completes it.

**How to apply:** The migration is architecturally clean and ADR-compliant. Verified: `task_set`
field + `task_set_ref` + `tracked_spawn` + `GovernanceTimeoutTask` + `state.governance.timeout_task`
+ `TtlTimer.task/cancel/on_error` + `run_ttl_expiry_with_retries` all fully DELETED with zero live
refs. All callers (finalize_create/restore/import/close/tombstone/promote/extend_ttl/shutdown_all)
updated. pipeline_wiring assertion retargeted (body-scoped) to the new mechanism + negative asserts.

## Key design facts
- `reconcile_timers()` runs at top of every run() turn: TTL one-shot `Sleep` armed from convergent
  `state.ttl.timer.deadline_unix_secs` (re-arm guarded by `ttl_armed_deadline` idempotence cache);
  governance `Interval` (60s, `interval_at(now+60s)`, MissedTickBehavior::Delay) armed while Active.
- `start_ttl_timer` is now a pure SYNC deadline-record (no task). TtlTimer is just
  `{deadline_unix_secs, clock}`.
- `on_ttl_tick` returns bool terminal-signal; on terminal (Expired/Closed/Tombstoned) it calls
  `despawn_actor(&self.context_id)` (self-despawn — internal TTL exit has no external despawner,
  unlike Shutdown/PrepareForReplace) then breaks. `despawn_actor` takes write_lock, no await held — safe.
- New `MAX_CONSECUTIVE_INBOX=32` fairness bound: biased select is inbox-first; counter disables inbox
  arm for one iteration after 32 consecutive dispatches so timer/persist arms get a guaranteed poll.
  Arm 5 fall-through (`future::ready` guarded by counter>=MAX) prevents deadlock. Sound + bounded.

## Findings (none blocking)
1. STALE DOCS: `actor/mod.rs:~124` ContextActor struct doc still says arms "remain no-ops pending
   Phase 2 finalization ... driven by supervisor's timer task_set" — now false (this PR completed it).
   `actor/deps.rs:79` still lists `task_set` as a supervisor field — field was deleted.
2. STALE COMMENT: `on_governance_timeout` (mod.rs) claims "a contended read reports Ok(true) retry
   next tick" — but evaluate_governance_timeouts removed that branch (ArcSwap read can't fail). No
   such case exists.
3. CAPABILITY REDUCTION: `run_ttl_expiry_with_retries` (5 attempts, exp backoff, TtlExpiryFailureCallback)
   deleted → single-shot `handle_ttl_expiry` under 30s HANDLER_TIMEOUT. Architecturally FORCED (a
   multi-second in-actor backoff loop would wedge the single-threaded actor) and cleanup-failure info
   still surfaces via ContextEvent::ExpiryFailed. But: "re-derive on restore re-fires" claim is weak
   for cleanup I/O because Expired snapshots are NOT respawned (anti-resurrection) — a failed
   relay-delete/event-append is effectively not retried until a node restart of an *Active* (failed-
   transition) context. Low severity; ties to cryptographer's TTL-restore-path findings.
4. PROVENANCE: code cites "finding A3" ~40x but A3 is in NO artifact (.docs). Substance is grounded in
   ADR-049 §1/Decision-1 (which IS authoritative), so not phantom-provenance, but the A3 label should
   be added to the ADR or dropped.
5. TEST GAP: new fairness bound (MAX_CONSECUTIVE_INBOX) has no dedicated test. Two good timer tests
   exist (actor_owned_ttl_arm_fires_and_despawns_self, actor_owned_governance_interval_...).
6. MINOR: evaluate_governance_timeouts returns ok_mutated(true) unconditionally on the active path →
   every Active context persists ≥once/60s even with no governance change (matches retired handler
   semantics; not new). Write amplification at scale.

Verdict: APPROVED — ADR-049 A3/Decision-1 compliant, complete, no orphaned wiring. Doc/comment
cleanups + optional fairness test recommended.
