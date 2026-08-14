---
name: adr049-pr3-ttl-live-timers
description: Re-review of ADR-049 PR-3 TTL live-timers fixes (BLACK-P3-001/002). Both closed; new findings in retry-path convergence + relay-starved append.
metadata:
  type: project
---

# ADR-049 PR-3 (feat/adr049-pr3-live-timers, HEAD 21a93a88e) TTL re-review

IMPORTANT ENV NOTE: this task ran in a git WORKTREE at
`/Users/alec/Developer/limn/scp/.claude/worktrees/agent-a9a59e51697d57907`.
`cd /Users/alec/Developer/limn/scp` jumps to the MAIN worktree (different
branch/HEAD 1620de983) and reads STALE files. Always use the worktree path
(the Bash tool's default cwd) or absolute worktree paths for Read.

## Verdict
- BLACK-P3-001 (hostile-relay resurrection): CLOSED. Two-phase expiry:
  Phase-1 terminal FSM transition + key destroy + fail-closed `commit_class_s_keep`
  persist of `Expired` runs OUTSIDE any timeout, BEFORE despawn; Phase-2
  relay/event-log I/O inside timeout(30s). Actor despawns only when
  terminal AND is_complete AND persist_result.is_ok (mod.rs on_ttl_tick:812).
  Post-despawn re-create refused by B8 durable-terminal-snapshot precheck.
- BLACK-P3-002 (non-terminal fire disarm): CLOSED. `reconcile_timers`
  (mod.rs:672) runs every loop turn, unconditionally disarms TTL arm when
  FSM != Active. Non-terminal fire drops ttl_armed_deadline.

## NEW findings (introduced by the fix's structure)
- BLACK-P3-003 (MED-HIGH, correctness+relay): retry path stamps ContextExpired
  leaf with local now() not the convergent deadline. ttl_close_helpers.rs:127
  reads timer.deadline_unix_secs; Phase-1 line 157 sets it =None. Retry re-reads
  None -> now(). Divergent leaf timestamp across members (defeats §7.3.1/§9.9.3).
  Reachable by benign transient first-append failure OR hostile relay. Fix:
  re-derive via convergent_ttl_deadline_secs(cell.creation_timestamp_secs, ttl).
- BLACK-P3-004 (MED, relay DoS): finish_ttl_expiry_io (ttl.rs:722-728) awaits
  best-effort relay delete_published INLINE, BEFORE the completeness-critical
  event-log append (line 745), sharing ONE timeout(30s). Hostile relay stalling
  delete_published starves the append -> STEP_EVENT_LOGGED never set -> perpetual
  5s retry (TTL_EXPIRY_RETRY_BACKOFF, no cap), actor never despawns, ContextExpired
  leaf never recorded. Ephemeral/Summary scopes only (needs_key_destruction).
- BLACK-P3-005 (LOW, provenance): ttl_expiry_retry + ttl_expiry_completed are
  actor-runtime only (not in snapshot). Crash mid-retry -> respawn Expired ->
  reconcile disarms ttl_timer (not Active), retry arm None -> append never
  re-driven -> ContextExpired leaf permanently absent. No resurrection.
- OBSERVATION (LOW): standing_context (supervisor.rs:9187) calls
  lifecycle_helpers::create_context DIRECTLY, bypassing the B8 precheck on the
  CreateContext dispatch arm. Tombstone finality NOT enforced for standing
  (deterministic-id) contexts. Scoped to caller's own standing ids (id is
  hash(local,peer)); not arbitrary resurrection. Asymmetric with B8's stated
  Closed/Tombstoned finality goal.
- Liveness residual (accepted): on_ttl_tick deliberately does NOT bound the
  fail-closed local persist; hung trusted storage wedges the actor (fail-closed,
  no resurrection).
