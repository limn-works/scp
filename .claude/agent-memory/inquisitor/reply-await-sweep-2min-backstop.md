---
name: reply-await-sweep-2min-backstop
description: reply-await-sweep-core — uniform 2-min REPLY_TIMEOUT backstop on ~57 supervisor reply-oneshot awaits; SOUND, fail-open rate-limit QUESTION RESOLVED @1728385f6 (Elapsed→deny const fn)
metadata:
  type: project
---

Branch `reply-await-sweep-core` @ c33e7ee35: routes ~57 `Supervisor::dispatch_*` /
recovery reply-oneshot awaits through shared mechanics-only helper `bounded_reply_await`
(actor/handle.rs) = `timeout(REPLY_TIMEOUT=2min, rx)` + classify {Ok(T), Dropped, Elapsed}.
Each caller keeps its OWN disposition inline (typed error / soft-default / discard).

**Verdict: SOUND, one QUESTION.** Do not re-litigate the premise.

**Why the uniform 2-min bound holds (premise: healthy reply ≤30s-bounded upstream):**
- Actor is SEQUENTIAL (`Box::pin(self.dispatch(cmd)).await` in actor/mod.rs run loop) ⇒
  reply-await = queue-wait + handler processing. Both must fit under 2 min.
- Every handler wraps transport/storage in `HANDLER_TIMEOUT=30s`
  (`tokio::time::timeout(HANDLER_TIMEOUT, fut)`) — messaging/lifecycle/economy/governance/
  outlets(25×)/trust_recovery(12×)/standing(9×).
- Bootstrap (Create/Restore/Import) routes via `dispatch_lifecycle_direct`, wraps body in
  `LIFECYCLE_TIMEOUT=30s`. RestoreContext/ImportContext are REJECTED at actor mailbox
  (bootstrap ≠ mailbox); heavy replay is in the direct path, 30s-bounded.
- Custody signing is OUTSIDE the actor: broadcast = reserve(in-mem) → `custody.sign` outside
  → apply(in-mem) (supervisor.rs publish_broadcast_two_phase ~5934). No inline `.sign` in
  outlets/trust_recovery/standing handlers.
- Cross-context saga uses 30s PER-PHASE timers (saga.rs:790, 6830), not one blocking await.
  ⇒ healthy reply ≤~30s; 2min never fires healthy. Queue-stacking to >2min needs multiple
  near-timeout (=degraded) transport calls, where retryable ActorBusy is the correct answer.

**#130's 3 sibling sites (supervisor/handle.rs dispatch_recovery_send_notification /
dispatch_prepare_for_replace / dispatch_start_ttl_timer) converged onto helper:** traced
arm-by-arm = EXACT behavior preservation. Coherence-positive (one mechanics source, kills two
spellings of same timeout+classify). Not churn.

**Deferring saga.rs ~36 awaits: SOUND.** Those are actor's OWN internal work
(persist_state_best_effort, `captured.await` async blocks, sub-handler calls) + 30s xctx phase
timers — NOT external-caller-awaits-mailbox-reply. External-caller-pinned-by-wedged-actor
hazard is FULLY closed by this PR. A naive 2-min bound on a multi-phase saga coordinator future
would WRONGLY abort a healthy-but-slow saga ⇒ not sweeping them is correct, not half-done.

**Behavioral change (hang → return after 2min): 15/16 folds fail-CLOSED** (None/false/
Vec::new = deny/absent = strictly safer than hang). **ONE QUESTION: try_consume_hard_rate_limit
(supervisor.rs:11639)** folds Elapsed into fail-OPEN `true` (=not rate-limited) ⇒ hang→
rate-limit-BYPASS. Mitigations: preserves pre-existing dropped-channel `=> true` contract;
needs sustained 2min wedge; self-defuses (downstream invoke cmd hits same wedged actor, now
also errors). RESIDUAL: cross-context topology (caller-ctx actor wedged, target healthy) could
bypass caller-ctx per-context hard-rate cap for the 2min window. Recommend fail-closed(deny) on
Elapsed specifically while keeping unregistered→true, OR document why fail-open-on-wedge OK for
outlet rate limits.

**QUESTION RESOLVED @ 1728385f6 (`fix(runtime): bound 2 missed reserve reply-awaits + fail-closed
hard-rate-limit on actor wedge`).** Fix extracts a pure `const fn hard_rate_limit_allow(&Result<
Result<bool,ContextError>, BoundedReplyError>) -> bool`: `Ok(Ok(c))=>c`, `Ok(Err(_))|Err(Dropped)
=>true` (no live bucket), `Err(Elapsed)=>false` (wedged-but-alive = DENY). Elapsed no longer
bypasses the cap — closes the cross-context wedge hole. Verdict SOUND, no residual analogous
hazard:
- Dropped→pass vs Elapsed→deny is PRINCIPLED, tracks invariant "pass only when no live per-ctx
  bucket exists." Elapsed = actor alive, bucket exists but unreachable ⇒ defeating a LIVE cap ⇒
  deny. Dropped = actor terminated, in-mem PerContextState bucket gone with it (not durable;
  resets on respawn) ⇒ same as unregistered legacy contract ⇒ nothing to defeat.
- Dropped residual is INERT: attack primitive to induce Dropped (force actor termination) is not
  cheap/available like a wedge (mailbox flood); AND a gone actor fails the reserve path
  (reserve_outlet_economy_via_actor @11863/11911 map ANY BoundedReplyError→TransportFailed,
  fail-closed) so a passed-through rate-limit gate can't grant an invocation. Reserve asymmetry
  (affirmative-needs-success) vs rate-limit (veto-needs-live-bucket) composes correctly.
- No OTHER fail-open-on-wedge fold remains: the ONLY bounded_reply_await fold returning a
  permissive bool on BoundedReplyError was this one. All other ~55 sites map Err→ContextError
  (fail-closed) or discard fire-and-forget (broadcast/refund — refund loss is stricter direction).
  `Ok=>true` arms @8153/13251 are unrelated (persistence/transport, not reply-await; both
  fail-closed on their Err).
- const fn + direct regression test (`hard_rate_limit_wedged_actor_fails_closed`) is the RIGHT
  shape: makes the security disposition unit-testable without wedging a live actor (impractical),
  single source of truth (no inline drift), exhaustive match ⇒ a new BoundedReplyError variant
  forces a compile error at the classifier (can't silently default). Composes with
  bounded_reply_await's own start_paused test (proves a wedge really yields Elapsed).
