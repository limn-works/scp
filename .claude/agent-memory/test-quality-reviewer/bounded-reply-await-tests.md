---
name: bounded-reply-await-tests
description: Gold-standard start_paused virtual-time pattern for testing tokio timeout backstops; and the 4-site DRY/testability gap in context-actor reply-await bounds
metadata:
  type: project
---

# Bounded reply-await tests (context/actor/handle.rs)

Commit `fe7068808` on `bound-context-actor-reply-awaits` added a `REPLY_TIMEOUT`
(2 min) backstop bounding the post-enqueue `rx.await` in `ContextActorHandle::send`
and `send_recover_on_failure`. Mirrors the merged #129 key-package-actor precedent
(`key_package_actor_tests.rs`, `KP_REPLY_TIMEOUT` 1 min).

## Gold-standard deterministic timeout test pattern (REPLICATE THIS)
`#[tokio::test(start_paused = true)]` + buffered mpsc at capacity, receiver held
alive but never drained (`_rx` bound), send a smoke command, then:
- assert the returned error is the reply-timeout `ActorBusy` variant via message
  substring `"did not reply"` (this DISTINGUISHES it from the closed-inbox arm —
  dropping `_rx` would take the "closed" arm; so the substring check is what makes
  it non-vacuous / proves it reached the post-enqueue reply-await path).
- assert `elapsed >= REPLY_TIMEOUT` using `tokio::time::Instant` — this is the
  guard that virtual time ACTUALLY advanced the full budget (vacuous-pass guard).
Why deterministic: buffered send resolves immediately (no park); only the reply
timeout timer is pending → tokio auto-advances virtual time to its deadline. No
real wall-clock wait. Removing the bound → oneshot never resolves → runtime
stalls → test HANGS (not a false pass), so the test has real teeth.

`send_recover_on_failure` variant additionally asserts `recovered.is_none()` —
the escrow-correctness property: a DELIVERED-then-wedged command is NOT
recoverable (actor owns the #[must_use] ticket; `Some` would risk double-balance).

## Residual gap (LOW severity, worth a follow-up)
The same `tokio::time::timeout(REPLY_TIMEOUT, reply_rx)` is copy-pasted at 4 sites:
`send`, `send_recover_on_failure` (actor/handle.rs) AND
`dispatch_prepare_for_replace`, `dispatch_start_ttl_timer` (supervisor/handle.rs).
The two supervisor sites have DISTINCT elapsed-arm behavior:
- prepare_for_replace: fail-closed `ActorBusy` (like send)
- start_ttl_timer: BEST-EFFORT — swallow + `tracing::warn`, no error propagated
Only the two actor-handle sites are directly tested. The supervisor sites are
covered only by the shared-constant pin + "identical pattern" argument; their
divergent elapsed-arm behavior is unverified (justification: live SupervisorHandle
needs a fully-wired Supervisor). Cleaner root-cause fix: extract a
`bounded_reply_await(rx)` helper → DRY the 4 sites, make the seam unit-testable
without a Supervisor, remove the "hard to construct" excuse, and prevent a 5th
site forgetting the bound.

## Minor
`reply_timeout_is_2_minutes` asserts `REPLY_TIMEOUT == Duration::from_mins(2)` —
same token as the constant's own definition; a change-detector pin but tautological
in form. `from_secs(120)` would be a marginally stronger independent-representation pin.
