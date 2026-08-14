---
name: bounded-reply-await-130
description: Audit of #130 bounded actor reply-await hardening (branch bound-context-actor-reply-awaits @fe7068808) — found one missed sibling reply-await
metadata:
  type: project
---

# Bounded reply-await hardening (#130) audit

Branch `bound-context-actor-reply-awaits` @ `fe7068808`, mirroring merged #129 (key-package actor `KP_REPLY_TIMEOUT`).

Introduces `REPLY_TIMEOUT = Duration::from_mins(2)` in `context/actor/handle.rs`, exported via `context::actor` alongside `SEND_TIMEOUT`. Bounds the post-enqueue reply-oneshot await (distinct budget from `SEND_TIMEOUT` = mailbox admission). On elapse → retryable `ContextError::ActorBusy("...did not reply within 120 seconds")`. Rationale: a wedged/deadlocked actor never terminates → watchdog never drops the reply sender → bare `rx.await` pins caller forever.

**Named #130 scope COMPLETE + correct**: `send` and `send_recover_on_failure` both wrapped; `send_recover_on_failure` timeout arm keeps recovery slot `None` (avoids escrow double-balance). Docs updated (old "awaited unbounded" rewritten). Deterministic `start_paused` wedge tests added.

**Finding (INCOMPLETE, narrow)**: coder self-expanded the sweep to `supervisor/handle.rs` reply-awaits and bounded 2 of 3 — `dispatch_prepare_for_replace:638` and `dispatch_start_ttl_timer:842` ✓, but **missed `dispatch_recovery_send_notification:324`** (bare `reply_rx.await.map_err(..)?`). That site routes `TrustRecoveryCommand::RecoverySendNotification` through the per-context actor mailbox (`dispatch_via_mailbox`), is load-bearing (result via `?`), production-reachable (trust_recovery_helpers::recovery_notify_contact, spec §9.12). Same wedge class as the two bounded siblings; NOT the deferrable ~100-site `let _ = rx.await` fire-and-forget class in `supervisor.rs` (e.g. `report_degraded_mode:15133`). One-line fix.

**Audit claims verified correct**: `supervisor.rs:15157` (`dispatch_via_mailbox`) genuinely does NOT await a reply (enqueue-only) → correctly left alone. Deferring the ~100 fire-and-forget discards is legit (needs shared helper + structural check). `supervisor/handle.rs` has exactly 3 oneshot reply-awaits (318/324, 615/638, 809/842) — grep pattern: bounded ones read `timeout(REPLY_TIMEOUT, reply_rx).await`, raw `reply_rx.await` only survives at the missed 324.

**Lesson**: when a coder voluntarily expands scope to "sweep all X in file Y", grep file Y for ALL instances of X — a self-expanded sweep that gets N-1 of N is a gap even when the originally-named scope is complete.
