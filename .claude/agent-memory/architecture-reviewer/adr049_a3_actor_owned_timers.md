---
name: adr049-a3-actor-owned-timers
description: ADR-049 finding-A3 PR-3 review — actor-owned TTL/governance timer arms + enforcement retarget; the on_ttl_tick lost-timeout finding
metadata:
  type: project
---

# ADR-049 A3: actor-owned TTL/governance timers (PR-3, HEAD 62f783e62)

> STATUS UPDATE (re-reviewed at HEAD 5752cd50a): the blocking finding below AND both minors are ALL
> RESOLVED. on_ttl_tick now wraps expiry in `tokio::time::timeout(HANDLER_TIMEOUT, expiry)` (best-effort
> warn-and-proceed on elapse). ADR-049 Decision-12 allow-list `task_set` line was deleted. GovernanceTimeoutTask
> + `state.governance.timeout_task` field are fully removed (zero refs), not just dead. See adr049_pr3_live_timers.md.

Retires the intermediate Phase-2A supervisor mailbox-timer driver (`task_set` JoinSet + `FireTimer`/`EvaluateTimeouts`/`StartTimeoutTask` mailbox hops). Makes TTL + governance timers ACTOR-OWNED `select!` arms per Decision-1's literal four-arm mandate (inbox, TTL one-shot `Sleep`, governance 60s `Interval`, persist coalesce). `ContextActor::reconcile_timers()` (actor/mod.rs:550) runs at top of every run() loop turn, re-arms from `state.ttl.timer.deadline_unix_secs` (idempotence-guarded by `ttl_armed_deadline`) and arms governance interval while `Active` (guarded by `is_none()`). Both guards are load-bearing: without them the timers reset every turn and never fire.

**Why:** the mailbox-timer was always scaffold; Decision-1 mandates actor-owned arms. Endpoint is permanent-correct (timers re-derived from persisted convergent deadline on respawn; anti-resurrection respawns only `Active`; `ttl::remaining_secs` made deadline-derived not task-gated so restore re-arm gate stays faithful). Removing `task_set` Mutex = genuine Decision-12 lock reduction (no replacement lock).

**How to apply — the one blocking finding I raised:** `on_ttl_tick` (actor/mod.rs:597) calls `handle_ttl_expiry` UNBOUNDED, dropping the `HANDLER_TIMEOUT`(30s) wrapper the retired `handle_fire_timer` had — while the sibling `handle_execute_ttl_close` (handlers/ttl_close.rs:274) STILL wraps the same fn. `handle_ttl_expiry → try_ttl_expiry_cleanup` has unbounded `transport.delete_published().await` (ttl.rs:889) + `event_log.append_context_event().await` (ttl.rs:900). Since on_ttl_tick runs directly in the select loop, a hung relay/storage wedges the WHOLE actor (no inbox/gov/persist). Violates Decision-7 ("Every transport and storage call inside a handler wraps tokio::time::timeout(30s)"). Fix: wrap on_ttl_tick's call in timeout(HANDLER_TIMEOUT); best-effort on elapse.

Minor: (1) ADR-049 Decision-12 allow-list line 286 still lists the deleted `Supervisor::task_set` Mutex — ADR untouched in diff, must drop it. (2) `GovernanceTimeoutTask::install` + `state.governance.timeout_task` field now effectively dead (only `cancel()`'d, never populated) — simplifier follow-up.

Enforcement retarget `actor_owned_timer_arms_reconcile_from_state` (pipeline_wiring.rs) is SOUND+bounded: positive body-scoped `fn_body_contains` pins real mechanism; 2 negative residue checks are meaningful (verified `task_set_ref` was in supervisor.rs=SUPERVISOR_SRC and `tracked_spawn` was in ttl_close_helpers+governance_helpers which are in the MANAGER_SRC concat — both now 0). Not a denylist.
