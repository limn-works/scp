# ADR-049 §3a per-participant-context-set saga gating + granularity CI gate — FINAL PASS (CLEAN)

Worktree saga-gating, HEAD 228b8146c on origin/main. 8 files. Control SOUND + merge-ready.

## What it replaces
Old supervisor-wide `saga_pending_guard: AtomicBool` (one stuck saga DoS'd every saga) → per-set
`reserved_saga_contexts: std::sync::Mutex<HashSet<String>>`. Saga reserves WHOLE participant
context set atomically; disjoint sets run concurrent, overlap → typed SagaBusy (ActorBusy).

## Re-attacked, all blocked
- Gate `scripts/check-saga-gating-granularity.sh`: real scan PASS, self-test PASS (6 fixtures a-f
  incl signed-atomic + small-scalar-Mutex + name-prefix bypass).
- NEG_PATTERN probe: CAUGHT std/tokio Mutex<()>, Semaphore, AtomicU64/I64; MISS RwLock<()>, Notify,
  newtype `SagaGate`, Mutex<HashSet> (intended allow). The MISSes are EXACTLY the honestly-disclosed
  tripwire limit. Not exploitable as accidental regression: positives P1-P6 force per-set machinery
  PRESENT, so a RwLock<()> wedge would be redundant self-sabotage beside working gating, not a
  rename-laundering of it. The realistic regression (scalar guard under saga-ish name) is fully covered.
- Backstops verified live: `std::sync::Mutex` in crates/scp-runtime/clippy.toml disallowed-types
  (double-covers Mutex<()> wedge); `await_holding_lock = "deny"` at Cargo.toml:102 workspace-level
  (independently denies across-await even though field carries #[allow(disallowed_types)]). Both
  try_reserve_context_set and SagaSetReservation::drop have 0 awaits (verified) — sync critical sections.

## Key/wedge/leak paths — none
- Reserve + release both key off ONE saga_participant_context_set(&input) call; SagaSetReservation.ids
  = context_set.to_vec(), Drop removes exactly its own ids. No key drift, no cross-removal.
- Overlap rejected at reserve → no two live reservations share an id → removal always safe.
- Extractor dedups (caller==target reserves once); HashSet::remove idempotent.
- Canonical key = hex(raw 32B digest). StandingPairCreate reserves
  hex(derive_standing_context_digest(local,peer)) — RAW digest, NOT "standing-"-prefixed registry id.
  New `derive_standing_context_digest` extracted; `generate_standing_context_id` now wraps it —
  byte-identical to old output (same sorted-DID SHA-256 body), so registry keying unchanged.
  P5 gate + `overlap_is_set_membership_across_saga_types` test guard the raw-digest invariant.

## Doc-fix accuracy — correct
start_saga `# Concurrent saga serialization (per participant-context set)` describes per-set / disjoint-
concurrent / overlap-SagaBusy / RAII-release-on-every-terminal-incl-NeedsRepair. Only surviving
"supervisor-wide" is the negation. Zero stale saga_pending_guard/SagaGuardReset refs anywhere.

## Tests green
5/5 actor_saga_concurrent pass: disjoint_concurrent, overlap_busy, cross-type set-membership,
needs_repair_releases_reservation, same_set_sequential_rearm.

## Documented forward obligations (NOT runtime gaps — unreachable until FFI saga surface ships Phase 2C)
1. Authorize initiator over EACH named context BEFORE try_reserve_context_set (else malicious
   participant reserves victim's context = targeted availability attack). Documented in start_saga doc.
2. PR-2D replay must rebuild reservations for non-terminal journal entries EXCLUDING NeedsRepair, and
   must reconstruct FULL {caller,target} set for CrossContextToolInvocation (journal record persists
   only caller — documented concrete gap). FFI ordering clause arms the negative assertion the moment
   any start_*_saga FFI export lands.
