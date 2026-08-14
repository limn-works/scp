# ADR-049 A3 Actor-Timer Refactor (PR-3) -- 2026-07-10

Base 0f26442a. Moves TTL/governance timers from supervisor task_set (mailbox
FireTimer/EvaluateTimeouts) onto ACTOR-OWNED arms reconciled in
`ContextActor::run()` (crates/scp-runtime/src/context/actor/mod.rs).

## Verdict: 2 MEDIUM, core close/timeout guarantees HOLD across crash+respawn.

### MEDIUM-1: `biased` select starves TTL(arm2)/governance(arm3)/persist(arm4) under inbox load
- actor/mod.rs:271 `biased;` -> arm1 inbox always polled first. Sustained inbox
  traffic to one context delays TTL-close + governance-timeout servicing.
  Fairness relies ONLY on tokio coop-budget yields, not explicit fairness.
  MissedTickBehavior::Delay (line 579) does NOT address this (catch-up only).
- REGRESSION vs old design: old FireTimer/EvaluateTimeouts arrived as arm-1
  commands (FIFO with other cmds, guaranteed turn); now separate lower-prio arms.
- Security consequence: a busy/flooding member can delay their own governance
  demotion/consequence + TTL close while actively sending. Not proven strictly
  indefinite (tokio coop), but code must not rely on that for a security-liveness prop.

### MEDIUM-2: `on_ttl_tick` runs `handle_ttl_expiry` with NO timeout budget
- actor/mod.rs:597-610 calls handle_ttl_expiry directly. Retired `handle_fire_timer`
  wrapped it in `tokio::time::timeout(HANDLER_TIMEOUT=30s)`. Now an unbounded
  await: `transport.delete_published().await` + event_log append inside
  try_ttl_expiry_cleanup (ttl.rs:799) can hang -> whole actor loop blocks
  (no gov sweep, no persist, no shutdown). Recommend re-wrap in HANDLER_TIMEOUT.

### CONFIRMED SOUND (traced):
- Anti-resurrection: restore_all_contexts (lifecycle_helpers.rs:3076) skips
  snapshot.state != Active. Expired/Closed NOT respawned. GOOD.
- Lost-close self-heal: expired-but-Active snapshot -> restore_context:2988 re-arms
  from ttl_remaining=Some(0) -> dispatch_start_ttl_timer -> reconcile arms sleep(0)
  -> re-closes idempotently. GOOD.
- `remaining_secs()` change (ttl.rs:1188) drops is_active() gate: FIX, not risk.
  On actor path task=None so is_active()=false would have returned None ->
  ttl_remaining_secs stored None -> restore drops TTL -> resurrection-forever bug.
  Now deadline-derived: Some(0) for past deadline, stored faithfully (manager_methods.rs:266,
  no >0 gate). Coupled correctly with task removal.
- No new arm-less window: reconcile_timers runs top of EVERY loop turn; every
  deadline change (create/restore/extend via StartTtlTimer/ResetTtlTimer) is a
  command => loop iterates => re-arm. ttl_armed_deadline idempotence guard OK.
- Governance interval: is_none() guard (line ~575) prevents per-turn reset; armed
  only while Active; nulled when sweep returns !Ok(true); Err just delays 60s. OK.
- on_ttl_tick terminal break: try_ttl_expiry_cleanup transitions Active->Expired
  FIRST (ttl.rs:832); partial crypto/relay failure still leaves Expired -> break +
  dirty final-drain persist. GOOD.

### Observation (not a regression):
- If FSM Active->Expired transition itself FAILS, on_ttl_tick returns non-terminal,
  ttl_timer=None, deadline unchanged => NO in-process re-arm; relies on restart
  re-derivation. Matches old one-shot behavior. Stuck-OPEN (safe-ish direction: not
  silent resurrection). reconcile_timers "contended None FSM read" comment is stale
  (handle.state() is ArcSwap, never None).
