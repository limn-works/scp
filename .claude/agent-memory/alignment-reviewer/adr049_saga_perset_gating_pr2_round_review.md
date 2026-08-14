---
name: adr049-saga-perset-gating-pr2-round-review
description: ADR-049 §3a Phase 2C PR-2 per-participant-context-set saga gating + granularity CI gate — fresh re-pass ALIGNED zero findings (worktree saga-gating HEAD 7593229d8)
metadata:
  type: project
---

# ADR-049 §3a Phase 2C PR-2 — per-set saga gating + granularity CI gate (2026-06-14 fresh re-pass)

Worktree `saga-gating`, HEAD 7593229d8 on origin/main ca4f0e012. 8 files +1283/-120. Master plan = `~/.claude/plans/generic-moseying-lightning.md` (PR-2 = this; user updates plan-done post-merge, NOT a code finding). VERDICT: **ALIGNED, zero findings.** Prior pass also ALIGNED; this pass re-confirmed after: gate NEG_TYPE widened to SIGNED atomics (AtomicI8..Isize) + self-test fixture (f); forward-obligation doc additions (PR-2D replay target-context gap; Phase-2C authorize-before-reserve); shuttle doc reword.

**What the PR does (substance).** Replaces the supervisor-wide `AtomicBool saga_pending_guard` with per-participant-context-set reservation: `reserved_saga_contexts: std::sync::Mutex<HashSet<String>>`. `start_saga` computes `saga_participant_context_set(&input)` and calls `try_reserve_context_set` (atomic overlap-check-then-insert in one sync critical section; `.contains` hit → typed `ActorBusy("...SagaBusy")`; disjoint → insert whole set + return `SagaSetReservation` RAII). Drop releases exactly the reserved ids on EVERY terminal (Committed/Aborted/NeedsRepair) + panic-unwind — so NeedsRepair RELEASES (stuck saga can't wedge disjoint sagas). Poison recovered via `into_inner`.

**Alignment verification (all PASS):**
- **ADR-049 §3a** (ADR-049-actor-per-context.md L71/73/77/78): exact match — SagaBusy only on overlap, disjoint concurrent, NeedsRepair releases, gate must POSITIVELY assert per-set presence AND negatively forbid instance-wide guard of ANY type (predicate = wedge semantics not symbol name). The §3a "hard prerequisite: per-set gating MUST replace AtomicBool before start_*_saga FFI ships" is exactly what this PR + gate enforce.
- **spec §5.15.4** (05-contexts.md L1772): per-participant-context-set serialization, overlap = non-empty intersection ("sharing a single context is sufficient to conflict"), NeedsRepair releases reservation. Exact.
- **spec §5.15.8**: `derived_context_id` = raw 32-byte digest BEFORE "standing-" prefix+hex. PR canonicalizes the gating key to raw-digest hex (`derive_standing_context_digest`), keeps prefixed id as actor-registry key. Refactor is byte-identical (new `generate_standing_context_id` = `format!("standing-{}", hex::encode(derive_standing_context_digest(..)))`; digest fn has same hasher seq as old). 3 standing_helpers + 6 supervisor callers behaviorally unchanged.
- **spec §6.2.4**: names `target_context_id` as real field (wire + journaled `CrossContextToolInvocationPrepared` 8-field projection). PR adds mandatory `target_context_id: [u8;32]` to `SagaInput::CrossContextToolInvocation`. Only struct-LITERAL constructor is the test helper (actor_saga_concurrent.rs:110); all production matches are `{ .. }` destructures or the variant def — no stranded caller (Prepare/Commit spec-gapped per 2C). NOTE: the staged-state struct `CrossContextToolInvocationPrepared` (saga_prepared_state.rs:114) does NOT yet carry target_context_id — that's PR-2C wiring, explicitly named as forward-obligation option (a) in supervisor.rs:569 doc. Not a silent miss.

**KEY DISTINCTION (don't conflate):** `saga_input_participants` (free-form `Vec<String>` journal-provenance list feeding `entry.participants`) is a SIBLING of, NOT the same as, `saga_participant_context_set` (the gating set). The participants-extractor deliberately drops `target_context_id` ("Leave the journal shape UNCHANGED" comment at supervisor.rs:7089) — this does NOT contradict §6.2.4's journaled `CrossContextToolInvocationPrepared` shape (different struct). The PR's supervisor.rs:569 doc flags the resulting REPLAY GAP: journal records only `{caller, caller_did, tool_id}` but gating set is `{caller, target}`, so PR-2D replay MUST either persist target_context_id or rehydrate full SagaInput + re-derive set. Forward obligation captured, accurate.

**CLAUDE.md edit = ADDITIVE only:** adds `check-saga-gating-granularity.sh` to the NEVER-WEAKEN list. No existing entry weakened.

**Gate script = ALLOWED additive hardening (NOT a weakening):** NEG_TYPE widened to signed atomics is broader coverage (legit "ADD NEW assertions/wider coverage" category). Gate self-test (6 fixtures a-f) + real check both PASS. Gate positively asserts P1 reserved_saga_contexts / P2 extractor / P3 overlap-reject-INSIDE-try_reserve / P4 start_saga-calls-reserve / P5 no "standing-" literal in extractor (FIX-1 regression guard) / P6 4 proving tests exist by name; negatively forbids name×type product of instance-wide scalar guards (name-scoped so `spawn_generation: AtomicU64` not flagged; `Mutex<HashSet>` allowed). FFI-ordering clause vacuous-pass-armed (no start_*_saga FFI export exists — verified by grep).

**Forward-obligation docs accurate:** (1) "authorize initiator BEFORE reserving (Phase 2C)" — true: no FFI start_saga export today (grep empty), start_saga in-process-only, all Prepare returns NotImplemented, so reservation not attacker-reachable yet; flags the §availability-attack to close when FFI saga surface ships. (2) replay-gap para matches actual extractor output exactly.

**Shuttle reword accurate:** invariant 1 rewritten from "guard admits ≤1 saga" to "per-set reservation store empty once all sagas terminate; disjoint concurrent; overlap SagaBusy; every terminal releases." Consistent with new design.

**CI run locally:** `clippy -p scp-runtime --all-targets --features scp-runtime/testing -- -D warnings` CLEAN (Mutex disallowed_types allow is sound — sync critical section, provably never held across .await). 5/5 actor_saga_concurrent tests green (incl cross-saga-type overlap + NeedsRepair-release + same-set-rearm). Gate + self-test green.

**TestForceNeedsRepair** test-only SagaInput variant (cfg test/testing): Prepare always Ok → Commit always Err → exhausts retry → NeedsRepair terminal. Only way to drive a real NeedsRepair while 3 prod variants are Prepare-gapped. Exhaustive matches (no wildcard) so adding it forces every match arm to handle it = compile-enforced.

LESSON: when a PR adds a mandatory field to an enum variant that's not yet constructed in prod, confirm the ONLY constructor is the test helper (grep struct-literal `Variant {` vs destructure `Variant { .. }`) — a mandatory field is compile-safe but verify no half-wired prod caller. And distinguish the journal-PROVENANCE extractor (free Vec<String>) from the gating-SET extractor and the staged-state STRUCT — three different shapes, only the last is the §6.2.4 journaled projection.
