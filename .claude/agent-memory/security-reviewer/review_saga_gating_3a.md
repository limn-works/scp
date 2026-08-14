# ADR-049 §3a per-participant-context-set saga gating — re-review (HIGH closed)

Worktree: `.claude/worktrees/saga-gating`, HEAD 5e64ee386 on origin/main ca4f0e012. 8 files.

## Verdict 2026-06-14: SECURITY-CLEAN. Prior HIGH (non-canonical reservation key) CLOSED; MEDIUMs closed.

### The control
Replaces supervisor-wide `AtomicBool` saga guard with `reserved_saga_contexts: Mutex<HashSet<String>>`.
`start_saga` calls `try_reserve_context_set(saga_participant_context_set(input))` — atomic check-disjoint+insert under one
lock acquisition; overlap → typed `ActorBusy(SagaBusy)`; disjoint sets run concurrently. `SagaSetReservation` RAII drop
removes exactly the saga's ids on EVERY terminal (Committed/Aborted/NeedsRepair) AND panic-unwind. NeedsRepair RELEASES
(no instance-wide wedge). Poisoned lock recovered via `into_inner` (no permanent wedge).

### HIGH (canonical key) — verified CLOSED
- `derive_standing_context_digest()` returns raw `[u8;32]`; `generate_standing_context_id()` wraps it `"standing-"+hex`.
- `saga_participant_context_set` for StandingPairCreate reserves `hex::encode(derive_standing_context_digest(..))` (RAW),
  NOT the prefixed actor-registry id. Cross-context/broadcast reserve `hex::encode([u8;32])` of their wire ids.
- Traced collision LIVE: standing digest hex `16c9cb16...` == cross-context `caller_context_id` hex when the cross saga
  names that digest. Cross-probe correctly rejected SagaBusy at same key. Keys are byte-identical.
- Journal provenance (`saga_input_participants`) intentionally separate: StandingPairCreate journals raw DIDs, cross/bcast
  journal hex context ids + DID + tool. Gating vs journal diverge by design; no conflict.
- NO other non-canonical key form: only the standing variant is DID-derived; all others are raw `[u8;32]`.

### Test (MEDIUM mislabel) — CLOSED
`overlap_is_set_membership_across_saga_types` now feeds `test_standing_pair_context_digest(alice,bob)` into a
CrossContextToolInvocation `caller_context_id` while holding the standing-pair reservation → genuinely crosses saga TYPES,
asserts SagaBusy, then drop+rerun asserts NotImplemented (proves rejection WAS the reservation). Would catch a
prefixed-key regression. All 5 tests pass 12/12 runs (one transient FIRST-run fail was build staleness — vanished, isolated
debug confirmed keys equal).

### CI gate (MEDIUM) — CLOSED
`scripts/check-saga-gating-granularity.sh` P5 (`extractor_has_no_standing_prefix`) greps the
`saga_participant_context_set` body for `"standing-` literal OR `generate_standing_context_id` call → fails a FIX-1 regression.
Self-test fixtures (a-e) cover: AtomicBool+FFI-export FAIL, correct PASS, no-gating FAIL, name-bypass FAIL, Mutex<u8>-bypass
FAIL. P1-P6 positive asserts (store, extractor, overlap-reject-in-reserve, start_saga-calls-reserve, no-prefix, tests-exist).
FFI-ordering clause armed (no start_*_saga FFI export yet). Gate + self-test both pass. CI wires self-test BEFORE real check.

### Mutex-across-await soundness
`disallowed_types` allow is sound: `try_reserve_context_set` and `SagaSetReservation::drop` hold the `MutexGuard` only in
sync bodies (lock→contains→insert/remove→drop), never across `.await`. `_reservation` held across the FSM await is the
struct (just `&Mutex` + `Vec<String>`), NOT the guard. clippy -p scp-runtime --features testing -D warnings clean.

### Phase 2C forward obligation (point 6) — DOCUMENTED
supervisor.rs ~4411-4434: reservation becomes attacker-reachable when FFI saga surface ships; malicious participant could
name VICTIM's context id to deny their legit saga (targeted availability attack); Phase 2C MUST authorize initiator over
EACH named context BEFORE try_reserve_context_set. Unreachable today (all variants NotImplemented; in-process callers only).

### Observation (minor, non-blocking)
Shuttle doc pseudocode (`tests/shuttle_actor.rs:65`, inside `#[cfg(shuttle)]` + ````ignore`) references
`sup.reserved_saga_contexts_is_empty()` which does not exist. Illustrative sketch, never compiled. Real shuttle test would
need the accessor added. No security impact.
