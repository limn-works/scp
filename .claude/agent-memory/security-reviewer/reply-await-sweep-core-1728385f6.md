---
name: reply-await-sweep-core-1728385f6
description: Security verdict on the bounded_reply_await sweep (commit 1728385f6, branch reply-await-sweep-core) — SHIP IT, all wedge dispositions fail-closed
metadata:
  type: project
---

# reply-await bounding sweep (core supervisor) — 1728385f6

Wraps ~61 previously-UNBOUNDED reply-oneshot awaits on the per-context-actor mailbox
in `bounded_reply_await` = `timeout(REPLY_TIMEOUT=2min, rx)` → `Result<T, BoundedReplyError{Dropped,Elapsed}>`.
5 files: actor/handle.rs (helper), actor/mod.rs (re-export), supervisor/handle.rs,
supervisor/supervisor.rs, identity/recovery.rs.

**Why:** a wedged/alive-but-stuck actor (reply sender never dropped) previously pinned
the caller forever. The prior fail-OPEN on `try_consume_hard_rate_limit` (`Err(_) => true`)
was a rate-limit BYPASS on wedge.

**How to apply / VERDICT: SHIP IT.** All disposition directions fail-closed:
- `hard_rate_limit_allow` (supervisor.rs ~15679, const fn): Elapsed→`false` (DENY), Dropped/handler-Err→`true` (no live bucket, legacy pass-through). ONLY security-load-bearing rate-limit gate with a wedge→permissive risk; now correct. Regression-guarded by unit test `hard_rate_limit_wedged_actor_fails_closed`.
- ~18 query folds `Ok(Err(_)) | Err(_) => false/None/Vec::new()`: is_member→false (deny), has_established_outlet_interface→false (deny xctx), needs_reconnect→false (liveness only). All fail-closed; wedge just joins the pre-existing dropped-channel bucket.
- Economy reserve/settle/reverse (reserve_outlet_economy/stream, settle_*, reverse_*, outlet_stream_reserve_grant): wedge→`TransportFailed` (error). Never grants/refunds. Settle handler flips `settled` atomically with money (saga.rs:2544) ⇒ idempotent, no double-settle on retry. reconcile_stream_reservations + settle ticket-reclaim (supervisor.rs:18791) reclaim orphaned holds.
- refund_hard_rate_limit `let _ =` discard on wedge: skips refund = stricter (token stays consumed), matches charge-denies-on-wedge.
- supervisor/handle.rs: Elapsed→ActorBusy (retryable), Dropped→TransportFailed/ContextNotRegistered. TTL-timer install Elapsed→warn+continue (actor re-arms from recorded deadline via reconcile_timers). recovery.rs: Dropped+Elapsed→TransportFailed.
- No secrets/keys in error strings (static fn-name + timeout secs only). No new panic (unwrap_or_else, no unwrap/expect on prod path).

**OBSERVATION (not a finding):** reserve on a 2min-to-∞ slow-but-eventually-succeeds actor
= orphaned hold (debit commits, reply dropped, caller sees TransportFailed, no settle/refund).
NEW narrow window vs prior unbounded wait. Direction is over-HOLD of invoker's OWN budget
(self-disadvantaging, never free-service/double-spend/authz-bypass); reconciliation exists.
Safe from security POV.
