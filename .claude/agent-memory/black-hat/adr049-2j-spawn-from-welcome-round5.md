---
name: adr049-2j-spawn-from-welcome-round5
description: Round-5 re-attack of ADR-049 Phase 2J spawn-from-Welcome — BLACK-2J-07 lock-DoS fix verified closed; no new attack
metadata:
  type: project
---

# ADR-049 Phase 2J spawn-from-Welcome — Round-5 verdict (HEAD 1e16634ad)

File: `crates/scp-runtime/src/context/supervisor/supervisor.rs`, fn `spawn_actor_from_welcome` (~10396-10699).

**BLACK-2J-07 (global-lock DoS) CLOSED.** The unbounded `ConfirmConsume` reply-await (processes attacker `welcome_bytes`) is the FIRST stmt inside the `Box::pin(async{})` wrapped by `tokio::time::timeout(LIFECYCLE_TIMEOUT=30s)` at ~10521. On elapse: future dropped → elapse arm `destroy_mls_group`+`delete_context` → `spawn_outcome?` returns → `_bootstrap_guard` (single GLOBAL `bootstrap_spawn_lock`) drops. Lock released ≤30s. Crafted-welcome node-scale DoS bounded.

**Q3 elapse-after-registration UNREACHABLE.** `spawn_actor_with_state`→`spawn_actor_with_watchdog`: ONLY await before `self.actors.insert` (4005) is `write_lock.lock().await` (3999). After insert: sync guard-drop, sync `tokio::spawn`, sync `spawn_actor_watchdog_task`, `Ok(handle)` — NO await. So on the poll where registration happens the inner future returns `Poll::Ready(Ok)` synchronously; timeout returns `Ok`, never takes `Err(_elapsed)`. Rollback cannot nuke a live actor. Verified.

**Q2 rollback-as-weapon CLOSED.** GLOBAL lock held whole body; elapse rollback targets only this join's `context_id`; no concurrent same-id writer possible. Precheck D proved no pre-consume snapshot.

**Q4 05/06 no regression.** Prechecks A (`lookup` 10421) + D (`load_context` 10480) still inside lock; timeout wrap doesn't release lock.

**Residual observations (NOT exploitable, not regressions):**
- Finalization (10683-10696: update_context_gauges / start_governance_timeout_task / dispatch_start_ttl_timer) runs OUTSIDE the timeout but under the global lock (create runs finalize_create INSIDE its timeout). Each does bounded `send_with_timeout` then UNBOUNDED `rx.await` install-reply — but targets the fresh healthy actor, NOT attacker `welcome_bytes`. Lock can be held `30s + finalization`, but finalization is bounded local work. Placement is DELIBERATE+CORRECT (elapse arm is destructive; actor is live). Sound tradeoff.
- On elapse during `ConfirmConsume`, the per-identity KP actor may still churn the enqueued crafted welcome (send already queued) → burns KP + blocks that ONE identity's KP mailbox. Per-identity, not global. Documented "accepted cost as a crash." Timeout CONTAINS it to the KP actor instead of the global lock — improvement, not regression.
