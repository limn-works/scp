---
name: saga-gating
description: Per-participant-context-set saga concurrency gating review (feat/actor-2c-saga-gating) — clean, no defects
metadata:
  type: project
---

# Saga gating (ADR-049 §3a) review — CLEAN (2026-06)

Branch `feat/actor-2c-saga-gating` replaced supervisor-wide `AtomicBool` saga
guard with per-participant-context-set gating in
`crates/scp-runtime/src/context/supervisor/supervisor.rs`.

**Why:** the AtomicBool let one stuck saga DoS every unrelated saga; §3a's
block-until-terminal FFI saga surface would expose that wedge to all bindings.

**How to apply:** if reviewing future saga FSM / `start_saga` / reservation
changes, the invariants below must still hold.

## Verified-correct invariants (all held at review time)
1. `try_reserve_context_set`: overlap `.contains` check + whole-set insert are
   in ONE sync `lock()` critical section, no `.await` between → no TOCTOU.
2. `std::sync::Mutex` (banned by `crates/scp-runtime/clippy.toml`
   disallowed-types) guard NEVER held across `.await`. The `SagaSetReservation`
   RAII struct holds only `&Mutex` + `Vec<String>`, NOT a `MutexGuard`, so it's
   safe to carry across awaits in `start_saga`. Drop re-locks synchronously.
   Both `lock()` sites use `unwrap_or_else(PoisonError::into_inner)` (poison-safe,
   no panic-in-Drop).
3. NeedsRepair releases: FSM `run_saga_fsm` NeedsRepair arm returns `Err(err)`
   to `start_saga` → `_reservation` drops → slot freed. Panic-unwind also drops.
   No leak path.
4. Dedup before reserve: `saga_participant_context_set` runs raw ids through a
   HashSet filter so caller==target / host==broadcast reserves ONE slot — no
   self-deadlock.
5. `target_context_id` added to `SagaInput::CrossContextToolInvocation`. ONLY
   construction site outside supervisor.rs is the test (production handler
   `ToolsCommand::InitiateCrossContextToolInvocation` returns
   `reply_saga_deferred`, Phase 2C deferred — does NOT construct the SagaInput).
   `saga_participant_context_set` returns correct sets: standing=derived id,
   tool={caller,target}, broadcast={host,broadcast}.
6. Tests NOT vacuous: `overlapping_participant_sets_reject_busy` holds a real
   reservation via `test_reserve_saga_context_set` (same prod critical section)
   then start_saga overlapping → must be ActorBusy(SagaBusy), release →
   NotImplemented. `needs_repair_releases_reservation` uses
   `start_paused=true` + `TestForceNeedsRepair` (commit always fails) to drive
   real NeedsRepair, then proves a sharing saga reserves.

## Weak (acknowledged, NOT a defect)
- `disjoint_participant_sets_run_concurrently` can't detect a "disjoint sets
  wrongly serialize" bug because the spec-gapped FSM returns NotImplemented
  instantly regardless. Comment at lines 122-126 acknowledges it; the
  overlap test carries the real discrimination. Suite as a whole proves it.

## Verification done
- `cargo test -p scp-runtime --features testing --test actor_saga_concurrent` → 5 pass
- `cargo clippy -p scp-runtime --all-targets --features testing` → clean
- non-testing `cargo build -p scp-runtime` → clean (cfg-gated TestForceNeedsRepair)
- `bash scripts/check-saga-gating-granularity.sh [--self-test]` → both pass
