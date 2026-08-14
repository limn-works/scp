---
name: durability-drain-tests
description: How ADR-049 Class-C durability tests work, and a masking anti-pattern where a later fail-closed persist hides a lost coalesced mutation
metadata:
  type: project
---

# Class-C coalesced-durability regression tests (ADR-049 §Decision 9 / N1)

Location: `crates/scp-runtime/src/context/actor/mod.rs` tests module.

## The property under test
`class_c_view()` mutations perform NO persist at the mutation site. Durability
rides entirely on the handler returning `Outcome::ok_mutated`/`err_mutated`
(sets `self.dirty`), so the run-loop's coalesce tick (Arm-4) or the post-loop
final drain flushes the snapshot. A handler that mutates via `class_c_view()`
but returns `Outcome::ok` (`mutated:false`) silently loses the mutation on a
≤50ms crash. Finding N1 = a caller audit for exactly this bug.

## The GOOD test pattern (deterministic, no race)
`RecordingPersistence` (ArcSwapOption + Notify) records every `persist_context`
snapshot; `last_snapshot()` reads the serialized bytes a respawn rehydrates.
Final-drain test: `send(cmd).await` (reply) → `send_shutdown().await` (ack) →
`actor_task.await` (join guarantees the drain ran before JoinHandle resolves).
Then assert on `last_snapshot().<axis>` — DURABLE state, not live actor state.
Under old `mutated:false` code, dirty stays clear → drain skipped → last_snapshot
== None → first `.expect` panics. `send()` returns the handler REPLY payload
(handle.rs:122), so the first expect also proves the live mutation succeeded.
The Arm-4 tick variant uses `tokio::time::pause()` + `advance()` + a bounded
`timeout(.., persisted.notified())` so a no-op persist regression fails in
bounded VIRTUAL time instead of hanging. Both are deterministic.

## ANTI-PATTERN: fail-closed persist masking a lost coalesced mutation
An integration test that does `class_c_mutation` then later a `Class-S`
fail-closed mutation does NOT guard the Class-C mutation's `mutated` flag,
because the Class-S path re-persists the WHOLE PerContextState (including the
earlier Class-C change) fail-closed. The Class-C mutation lands durably via the
later full-state write regardless of its own `mutated` flag.
Concrete case: `tests/persistence_ordering.rs` drives `test_insert_member`
(Class-C) then `SuspendCapability` (Class-S). It only asserts `committed()` is
Some (create_context alone satisfies that) and `suspended_for(bob)` — never
`snapshot.role_state.members`/`membership` for bob. So it would STILL PASS if
`handle_test_insert_member` reverted to `mutated:false`. Not a valid N1 guard.
Lesson: to guard a coalesced Class-C durability fix, you need an ISOLATED
drain test (mutate → shutdown → assert drained snapshot), never a test where a
subsequent full-state fail-closed persist can re-capture the mutation.

Guarded-unreachable branches (e.g. commit_a replay on generation-match,
saga.rs ~2034): testing requires fabricating impossible FSM state — low ROI.
Prefer a `debug_assert!` on the unreachability precondition over a synthetic
test, so the "guarded" claim is enforced not just documented.
