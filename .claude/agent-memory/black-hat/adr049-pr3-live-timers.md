---
name: adr049-pr3-live-timers
description: Attack surfaces in ADR-049 PR-3 actor-owned-timers refactor (feat/adr049-pr3-live-timers)
metadata:
  type: project
---

# ADR-049 PR-3 actor-owned timers — attack surfaces

TTL + governance-timeout timers became actor-owned `select!` arms. Files:
`crates/scp-runtime/src/context/actor/mod.rs` (run loop, reconcile_timers, on_ttl_tick),
`ttl_close_helpers.rs` (handle_ttl_expiry), `supervisor.rs` (despawn_actor:4657, respawn_from_snapshot anti-resurrection gate:4334).

Known trio (being fixed): D1 create-window TTL never fires; D2 restore discards TTL extension; (d) respawn duplicates ContextExpired leaf (non-idempotent).

## NEW: BLACK-P3-001 (HIGH) — hostile-relay TTL-expiry resurrection window
`on_ttl_tick` wraps `handle_ttl_expiry` in `timeout(HANDLER_TIMEOUT=30s)`. The ONLY durable
Expired persist is the LAST line of handle_ttl_expiry (`persist_state_best_effort`), AFTER the
unbounded `transport.delete_published`/`event_log.append` awaits. A malicious relay stalling that
I/O >30s cancels handle_ttl_expiry BEFORE its persist. on_ttl_tick then sets dirty and returns
terminal; run() calls `despawn_actor` (removes registry entry, NO persist) THEN breaks; the
compensating final-drain persist runs AFTER despawn. Crash/restart in that window (or a slow
persistence backend) leaves durable snapshot = stale Active with actor gone → restart's
restore_all_contexts / respawn_from_snapshot reads Active (gate only skips !=Active) → RESURRECTS a
context whose MLS keys + relay ciphertext were already partially destroyed, now past its convergent
deadline → sleep(0) re-expiry → duplicate ContextExpired leaf → Merkle divergence. This reintroduces
the exact window the manual-close path explicitly closed & tested
(`close_to_closing_is_sync_persisted_no_resurrection` supervisor.rs:18135). Fix: persist Expired
fail-closed BEFORE despawn_actor, and do not let HANDLER_TIMEOUT skip the terminal persist.

## NEW: BLACK-P3-002 (MEDIUM) — non-terminal expiry permanently disarms TTL
on_ttl_tick terminal set = {Expired,Closed,Tombstoned}, omits Closing/MigratingOut. If the shared
ContextHandle (ArcSwap) is concurrently moved to MigratingOut/Closing by another task right as
try_ttl_expiry_cleanup runs, the Active→Expired CAS fails, state stays non-terminal, on_ttl_tick
returns false → run() does NOT break → next reconcile: ttl_armed_deadline == deadline_unix_secs
(both unchanged) so ttl_timer stays None (disarmed, not re-armed). If migration aborts back to
Active, context is past-TTL with no armed timer → outlives TTL until deadline changes.

## Trust relaxation
despawn frees the id for fresh CREATE (not resurrect); create path does not consult the durable
Expired snapshot, can overwrite it with fresh Active → defeats anti-resurrection for that id on
future restores. Standing/deterministic ids re-creatable post-expiry (squatting/DoS, not
impersonation — fresh MLS group).

## Resists attack (confirmed sound)
Fairness bound (MAX_CONSECUTIVE_INBOX=32 + Arm5 fall-through) bounds inbox-flood starvation of timer
arms to ~33 turns — NOT indefinite. TTL extension needs unanimous consent (unforgeable). Convergent
deadline re-arm prevents respawn from extending TTL. Governance interval armed via commands (proposal
command wakes inbox→reconcile). MissedTickBehavior::Delay prevents catch-up bursts.
