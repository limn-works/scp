---
name: saga-gating-granularity-reattack
description: Re-attack of ADR-049 §3a per-participant-context-set saga gating + CI granularity gate (worktree saga-gating, HEAD 7593229d8). Control SOUND; residuals all documented-forward or within gate's honest tripwire limit.
metadata:
  type: project
---

# Saga gating granularity re-attack — CONTROL SOUND

Worktree `saga-gating` HEAD 7593229d8 on origin/main. 8 files. ADR-049 §3a per-participant-context-set saga gating + `scripts/check-saga-gating-granularity.sh`.

**Why:** verifying the control + gate are NOW sound after prior passes closed non-canonical reservation key, name-prefix/unsigned-type gate launderings, signed-atomic gap.
**How to apply:** if asked to re-review or extend this gate, the residuals below are the known boundary — don't re-litigate the in-limit ones.

## Verdict: control is SOUND. Only residuals are documented-forward obligations or the gate's honestly-stated tripwire limit.

## Mechanism (all confirmed correct)
- `reserved_saga_contexts: std::sync::Mutex<HashSet<String>>` (supervisor.rs:603). Sync critical section, never held across await. Poison-recovered via into_inner.
- `try_reserve_context_set` (4518): atomic check-disjoint + insert under one lock; overlap → ActorBusy(SagaBusy). RAII `SagaSetReservation` (7052) Drop = sync lock→remove→unlock.
- `start_saga` (4456) calls extractor then `try_reserve_context_set(&set)?`, awaits FSM inline (NOT spawned) → reservation drops on EVERY terminal + panic-unwind + cancellation.
- `saga_participant_context_set` (7157): StandingPairCreate reserves `hex::encode(derive_standing_context_digest(local,peer))` = RAW digest (canonical, NOT the "standing-"-prefixed registry id). Cross/broadcast reserve hex of each [u8;32]. De-dup via HashSet (no self-conflict).
- `derive_standing_context_digest` + `generate_standing_context_id` now share ONE body (standing_helpers.rs) — prefixed id = "standing-"+hex(same digest). Can't drift.
- 5 integration tests PASS (actor_saga_concurrent.rs): disjoint-concurrent, overlap-busy, cross-saga-type set-membership, NeedsRepair-releases, same-set-rearm.
- Gate self-test rc=0, real check rc=0. Wired in ci.yml (self-test-first ordering).

## Residual 1 (LOW, doc-rot, ACTIONABLE): stale "single atomic bool" in start_saga doc
- supervisor.rs:4409-4416 "# Concurrent saga serialization" still says "serializes sagas supervisor-wide ... single atomic bool ... a second start_saga while one is in flight returns ActorBusy". FALSE — disjoint sets run concurrently now. Contradicts the per-set "Forward obligation" section 20 lines below (4431-4445) and the implementation. Describes exactly the wedge the gate forbids as if current. No runtime effect. Should be corrected so a future reader doesn't "restore" it.

## Residual 2 (gate's HONEST tripwire limit — NOT a new finding)
Negative scan misses instance-wide wedges of obscure TYPE: `RwLock<()>`/`tokio::sync::RwLock<()>`, `Notify`-gate, newtype `struct Gate(AtomicBool)` field `saga_gate: Gate`. Header (lines 20-23) explicitly states this. Caught:
- ALL atomics signed+unsigned (AtomicI8..Isize added prior pass), Semaphore, Mutex<()|bool|u8..usize> — incl. `tokio::sync::Mutex<()>` (regex `.*Mutex<\(\)>` matches despite path prefix), `parking_lot::Mutex<()>`.
- Names: saga|inflight|in_flight|pending|busy|gate|guard prefixes.
- Multi-line field (name\n type) split: missed by line-by-line awk BUT closed by series CI `cargo fmt --check` (rustfmt collapses to single line where gate catches). Defense-in-depth chain, not a hole.

## Residual 3 (subtle, within limit): blocking wedge evades BOTH negative scan AND disjoint test
- `disjoint_participant_sets_run_concurrently` only asserts ABSENCE of ActorBusy. A *blocking* instance-wide guard (latency-serializes, never emits ActorBusy) of an obscure type (RwLock<()>/Notify/newtype — std::sync::Mutex-across-await is independently clippy-banned; tokio::sync::Mutex<()>/Semaphore/atomics ARE negatively scanned) would pass the test while silently serializing disjoint sagas. Requires obscure blocking type = within gate's stated "obscure type" limit. Shuttle scaffold (shuttle_actor.rs) records empty-reservation-store invariant as future check. Exotic; maintainer-mistake-shaped more than attack. Optional hardening: add a latency/non-serialization assertion to the disjoint test.

## Forward obligations (documented, unreachable today — CONFIRMED not silently unfixed)
- **Phase 2C authorization gap** (supervisor.rs:4431-4445): initiator must be authorized over EACH named context BEFORE try_reserve, else attacker reserves victim's context (availability DoS). All 3 SagaInput variants' Prepare dispatch return NotImplemented today; no FFI start_*_saga export exists; start_saga only in-process-reachable. Unreachable until FFI saga surface ships.
- **PR-2D replay-target-context gap** (supervisor.rs:559-586): reserved set NOT rebuilt on restart; journal record for CrossContextToolInvocation omits target_context_id (records {caller,target} only as caller). Naive replay re-reserves {caller} not {caller,target} → target slot free during recovery window. PR-2D must persist target_context_id OR rehydrate full SagaInput + re-derive via saga_participant_context_set. Documented as concrete obligation; replay path itself today only marks journal states, never reserves.
- Canonical-key cross-type match (raw digest vs context_id_bytes("standing-"+hex)): cross-context target_context_id [u8;32] for a standing context — if a Phase 2C caller passes context_id_bytes(standing_string)=SHA256("standing-"+hex) it would NOT equal raw digest and overlap would be MISSED. Forward obligation for Phase 2C wiring; no caller constructs these inputs today (all NotImplemented).

## Bottom line
Control sound. Reservation key canonical (raw digest, single-body derivation). No wedge/leak on terminal/panic/cancellation paths. Gate's honest-tripwire header is accurate (not over-claiming). The 2 forward gaps are documented obligations + unreachable today. Only actionable now: fix the stale 4409-4416 doc-rot.
