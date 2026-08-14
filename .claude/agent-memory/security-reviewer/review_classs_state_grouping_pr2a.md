# Class-S state grouping refactor (ADR-049 §9 PR2a) — CLEAN

worktree classs-guard HEAD ebb8314f2. Behavior-neutral DATA SPLIT + mirror snapshot only.
14 files / +993/-403. VERIFIED SOUND, zero findings.

## What it does
- 5 PerContextState saga fields → new `ClassSState` sub-struct (saga_pending, xctx_nonce_dedup,
  xctx_committed_outputs, xctx_committed_invocations, xctx_caller_reservations).
- 4 GovernanceState fields → new `GovernanceClassS` (executed_proposals, threshold_signers,
  threshold_value, spending_nonce_tracker).
- Adds `snapshot()`/`restore()` mirror methods on both sub-structs (in-memory round-trip only;
  first prod consumer is later privatization PR, hence `#[allow(dead_code)]`).

## Four verified claims
1. §9.4.3 BEARER BARRIER PRESERVED: saga_prepared_state.rs UNTOUCHED (absent from --stat);
   SagaPreparedState keeps non-derive barrier. ClassSState has NO derive (no Clone/Serialize).
   saga_pending routes through SagaPreparedStateSnapshot mirror in both snapshot paths.
   New `pub const fn saga_pending()` accessor returns read-only &HashMap (no mut, no clone/serialize).
2. ON-DISK ContextSnapshot BYTE-IDENTICAL: ContextSnapshot struct body has ZERO +/- lines
   (awk struct-body extract empty). All snapshot_context/build_snapshot_from_state sites read
   from `class_s.<field>` but write same flat fields with same values. The +field additions in
   state.rs diff are all the NEW in-memory GovernanceClassS/snapshot sub-structs, never ContextSnapshot.
3. GATE NOT WEAKENED: check-class-s-fail-closed.sh --self-test AND real scan both exit 0.
   All 9 live fields stay pub(crate) (moved PerContextState fields actually TIGHTENED pub→pub(crate)).
   Gate markers survive as substrings of lengthened paths (grep -F finds regardless of prefix:
   saga_pending.insert(=9, executed_proposals.insert(=5, threshold_value ==8, etc).
   GovernanceClassS::restore uses `*self = Self {..}` struct-literal → keeps bare `threshold_value =`
   out of pure-rehydration path (correct: rehydration ≠ acknowledged downward-auth transition).
4. NO NEW PANIC: only new panic! is in the new test (wrong saga variant). unwrap_or(u32::MAX) are
   pre-existing infallible saturating conversions, repathed. cargo check -p scp-runtime --lib clean.

## Extras
- import/restore semantics preserved exactly (import drops caller-economy + fresh nonce tracker;
  restore rehydrates all Class-S from snapshot). Only destination struct shape changed.
- Exhaustive-destructure forward-locks (state.rs test + messaging_helpers build_snapshot_from_state)
  updated to nest under sub-structs → silent-field-drop compile-guard intact.

## Method note
- awk struct-body diff extract to prove a serialized struct untouched:
  `git show <sha> -- f | awk '/pub (struct|enum) ContextSnapshot/{p=1} p&&/^[+-]/{print} p&&/^}/{p=0}'`
- grep -F for gate markers works post-repath because markers are method-call/assignment substrings.
