---
name: saga-gating-per-context-set
description: ADR-049 §3a per-participant-context-set saga gating — the canonical reservation key, the dual-identity standing-context id, and the Phase 2C forward obligations
metadata:
  type: project
---

ADR-049 §3a replaces the supervisor-wide `AtomicBool` saga guard with per-participant-context-set reservation in `crates/scp-runtime/src/context/supervisor/supervisor.rs`.

**Key architectural facts (verified against ADR-049 §3a lines 63-78 and spec §5.15.4/§5.15.8):**
- `reserved_saga_contexts: std::sync::Mutex<HashSet<String>>` holds the union of in-flight reserved context ids. `try_reserve_context_set` does atomic overlap-check + insert under one sync lock; `SagaSetReservation` RAII drop removes the ids on EVERY terminal (Committed/Aborted/NeedsRepair) + panic-unwind. NeedsRepair RELEASES (spec §5.15.4: stuck saga must not wedge unrelated disjoint sagas).
- **Canonical reservation key = raw-digest hex, NOT the `"standing-"`-prefixed display id.** Spec §5.15.8 line 1804: "the 32-byte `derived_context_id` used in saga evidence is the raw digest before prefix and hex." `derive_standing_context_digest()->[u8;32]` in `standing_helpers.rs` is the shared body; `generate_standing_context_id` wraps it with the `"standing-"` prefix for the actor-registry key. This dual identity (registry-id prefixed, gating-key raw) is INTENTIONAL and spec-mandated, not a confusing accident — §5.15.8/§6.2.4(1640)/§5.14.13 require Fixed32 preimage slots carry the raw digest.

**Why `std::sync::Mutex` + `#[allow(clippy::disallowed_types)]` is justified:** the ban in `crates/scp-runtime/clippy.toml:20` targets the await-deadlock hazard. `try_reserve_context_set` and `SagaSetReservation::drop` are both non-async (no `.await`), so the guard is provably never held across a yield. Sound, not a workaround.

**CI gate `scripts/check-saga-gating-granularity.sh`** is in the CLAUDE.md NEVER-WEAKEN list. It is a tripwire (honestly self-described as not un-launderable), with `--self-test` planting 5 fixtures (a-e) that must fail/pass as designed. Negative scan = name×type product (saga/inflight/pending/busy/gate/guard × Atomic*/Semaphore/Mutex<scalar>). Positive P1-P6 assert the machinery present + proving tests exist by name. FFI-ordering clause is armed but vacuous until a `start_*_saga` export lands.

**Phase 2C forward obligations (correctly captured as forward-notes, not scope leak):**
- `SagaInput::CrossContextToolInvocation` gained `target_context_id` for the 2-context gating set. The actor command `InitiateCrossContextToolInvocation` (commands.rs:2115) does NOT carry it — but that handler returns `reply_saga_deferred` and constructs NO SagaInput, so there is zero live wiring. The asymmetry is a Phase 2C obligation, not a present gap.
- start_saga doc carries an explicit Phase-2C authorization forward-note: authorize initiator over each named context BEFORE reserving (else availability attack once FFI is reachable). Today unreachable from attacker input.
- replay_unresolved_sagas (PR-7/2D) must rebuild reservations EXCLUDING NeedsRepair entries. Documented in the `reserved_saga_contexts` field doc.

The shuttle_actor.rs doc-block references `reserved_saga_contexts_is_empty()` (nonexistent) but inside ` ```ignore ` — illustrative prose only, never compiles. Not a gap.

**Verdict on re-review at HEAD 5e64ee386: architecturally sound.** All 5 integration tests pass; CI gate self-test + real check pass; clippy clean with bans active.
