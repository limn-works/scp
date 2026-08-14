---
name: saga-gating-tests
description: ADR-049 §3a per-participant-context-set saga gating tests — robustness analysis, negative-control proof, and the disjoint-test timing caveat
metadata:
  type: project
---

# Saga gating concurrency tests (actor_saga_concurrent.rs)

Worktree `saga-gating` (HEAD 5e64ee386, re-verified 2026-06-14). Tests the
replacement of supervisor-wide `AtomicBool` saga guard with
per-participant-context-set reservation (`reserved_saga_contexts:
Mutex<HashSet<String>>`, `try_reserve_context_set`, RAII `SagaSetReservation`).

**Why:** Production saga variants are spec-gapped (Prepare returns NotImplemented
instantly), so a real saga reserves+releases in ~0 time — you cannot hold one
"in flight" by racing it. This is the central test-design hazard.

**How the 5 tests handle it (all ROBUST, verified):**
- `disjoint_..._run_concurrently` — two `start_saga` via `tokio::spawn` on
  multi_thread(4). REAL negative control: I collapsed `try_reserve_context_set`
  to a constant token (simulating old AtomicBool) and the test FAILED with
  ActorBusy. So the two spawned start_saga calls genuinely overlap in wall-clock;
  the test discriminates per-set from instance-wide gating. Load-bearing assert =
  ABSENCE of ActorBusy. Caveat: timing-based — can only false-GREEN (if tasks
  serialize) never false-RED (per-set gating cannot reject disjoint sets by
  construction). Acceptable.
- `overlapping_..._reject_busy` — holds set via test-only
  `test_reserve_saga_context_set` (same `try_reserve_context_set` critical
  section, NOT a mock), then `start_saga` overlapping → asserts ActorBusy(SagaBusy),
  then drop(held) + retry → NotImplemented. The drop-then-proceed proves the
  rejection was the reservation, not some other failure. Deterministic, robust.
- `overlap_is_set_membership_across_saga_types` — REWRITTEN (prior version was
  MISLABELED: it used two standing sagas, not a true cross-type cross). Now holds a
  StandingPairCreate reservation and asserts a CrossContextToolInvocation over the
  raw digest collides SagaBusy. NON-TAUTOLOGICAL by construction: both sides compute
  `hex::encode(derive_standing_context_digest(alice,bob))` — held side via production
  `saga_participant_context_set`, test side via `test_standing_pair_context_digest`
  (same production fn). EMPIRICALLY PROVEN: reverting the canonical-key fix (make
  StandingPairCreate reserve `generate_standing_context_id` prefixed display id) →
  test FAILS at line 239 SagaBusy assertion. Gate P5 ALSO catches the same revert
  (defense in depth: test + tripwire).
- `needs_repair_releases_reservation` — uses test-only `TestForceNeedsRepair`
  variant: Prepare succeeds → Committing → `commit_with_retry` exhausts 3 real
  attempts (Commit always Err) → appends NeedsRepair journal → returns error →
  RAII reservation drops. NOT a shortcut — drives the real FSM NeedsRepair arm.
  `start_paused=true` elapses 500ms/1s/2s backoffs in virtual time (suite runs
  in 0.00s). Robust.
- `same_set_sequential_rearm` — 5x same set sequential, each must terminate.
  Robust.

**CI gate `check-saga-gating-granularity.sh --self-test` is REAL (now 5 fixtures):**
(a) `saga_pending_guard: AtomicBool`+fake FFI export must FAIL; (b) correct per-set
gating must PASS; (c) no-gating-at-all must FAIL (absence-only must not pass);
(d) NEW `inflight_guard: AtomicBool` (non-saga*-named bypass) must FAIL — proves the
NEG name match widened to inflight/pending/busy/gate/guard; (e) NEW `saga_x: Mutex<u8>`
(small-scalar Mutex bypass) must FAIL — proves the NEG type list covers
Mutex<u8..usize>. EMPIRICALLY PROVEN plant-and-catch: narrowing NEG_NAME back to
saga-only → (d) fails; removing Mutex<u8> from NEG_TYPE → (e) fails. Gate now also
asserts P4 (try_reserve called in start_saga), P5 (no "standing-" literal /
generate_standing_context_id in extractor), P6 (4 proving test fns exist by name).
In NEVER-WEAKEN list.

**Verdict: SHIP (with 2 non-blocking doc-drift nits in shuttle_actor.rs).** All 5 tests
robust, all 3 negative controls empirically proven (canonical-key revert, instance-wide
serialize, gate name/type narrowing), gate self-test real. 15/15 suite runs clean. All
test-only items #[cfg(any(test, feature="testing"))]-gated. shuttle_actor.rs nits:
header docstring (lines 13-14) still says old "guard admits at most one" model;
Invariant-1 snippet references nonexistent `reserved_saga_contexts_is_empty()` — both
inside ```ignore``` doc, nothing compiles/runs, but a future shuttle author hits a wall.
