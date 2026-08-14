---
name: review-class-s-guard-foundation-4cf3a9f1f
description: Class-S type-guard FOUNDATION (ClassSCell + 6 view-typed combinators + PR2a data split) merge-readiness review — CLEAN, behavior-neutral
metadata:
  type: project
---

# Class-S type-guard foundation — CLEAN merge-cert (worktree classs-guard, HEAD 4cf3a9f1f)

ADR-049 §9 Class-S fail-closed-persist invariant being moved from source-text gate
(`scripts/check-class-s-fail-closed.sh`) to compile-error-to-violate. This PR is the
FOUNDATION only: scaffolding, no handler migrated, `#[allow(dead_code)]`. Behavior-neutral.

**Why:** source-text scanner is structurally non-convergent (every new `&mut PerContextState`
alias is a fresh evasion). End state = privatize Class-S fields + no DerefMut → only path to
mutate is through a persist-on-commit combinator.

**How to apply:** when the handler-MIGRATION PR lands (combinators get production callers,
`state_mut()` escape hatch + `#[allow(dead_code)]` deleted, fields privatized), re-verify the
gate retirement is sound and no handler acks an un-persisted Class-S mutation.

## Verified CLEAN (all 5 criteria)
- 6 combinators in `crates/scp-runtime/src/context/actor/class_s.rs`: keep(487)/restore(547)/
  compensating(610)/keep_compensating(698)/then_append(778)/class_c_best_effort(841). Every
  Class-S combinator persists fail-closed BEFORE returning Ok; f-reject short-circuits no-persist;
  restore-variants snapshot Class-S sub-structs and roll back on persist-fail; keep-variants
  intentionally retain (un-recording a consumed nonce = unsafe direction). `then_append` persists
  before external append; `AppendOutcomeError.mutated` = true durability-divergence flag.
- Restricted views CANNOT mutate Class-S: ClassCMut(262) exposes only rest_mut/governance_mut/
  split_class_c (none returns &mut ClassSState/&mut GovernanceClassS); only Deref, no DerefMut.
  then_append `after` takes read-only &PerContextState. ClassSCell no DerefMut = compile hook.
  Fields still pub(crate) this PR (read-reachable, no &mut path) — privatization is later PR.
- §9.4.3 bearer barrier: SagaPreparedState (saga_prepared_state.rs:67) NO Clone/Serialize/Debug/
  Display/Deserialize. Mirror snapshot projects saga_pending via sanctioned from_prepared/
  into_prepared (public-field mirror), not derived clone. UCAN bytes NOT in prepared state (only
  proof id) → mirror can't leak bearer material.
- On-disk ContextSnapshot UNCHANGED: struct + serde attrs zero diff. PR2a split moved fields into
  ClassSState/GovernanceClassS sub-structs (still pub(crate)), build_snapshot_from_state/restore
  read field-by-field through lengthened `.class_s.` paths → same flat snapshot fields. New
  ClassSStateSnapshot/GovernanceClassSSnapshot mirrors are in-memory-only round-trip.
- Gate live: `check-class-s-fail-closed.sh --self-test` EXIT 0 (handlers still on state_mut escape
  hatch → source gate remains the guarantee until terminal migration). `check-handler-no-panic.sh`
  EXIT 0. All added unwrap/expect/panic are #[cfg(test)] only. clippy -p scp-runtime clean.
- Build clean; 22 class_s/state tests pass incl class_s_and_governance_class_s_snapshot_restore_
  is_lossless + security_critical_state_is_class_s_or_m_not_coalesced.

Saga handler diff (saga.rs ±154) = pure path-lengthening (state.saga_pending →
state.class_s.saga_pending), no logic change.

NO findings any category.
