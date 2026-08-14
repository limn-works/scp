---
name: review-class-s-typeguard-foundation
description: Class-S type-guard FOUNDATION (ClassSCell + view-typed combinators + ClassSState/GovernanceClassS data split) merge-readiness security review — CLEAN
metadata:
  type: project
---

# Class-S type-guard foundation — SECURITY-CLEAN for merge

Worktree classs-guard HEAD 4cf3a9f1f (branch chore/fuzz-pin-nightly base). ADR-049 §9.
File: crates/scp-runtime/src/context/actor/class_s.rs (1922 L) + data split in
actor/state.rs (ClassSState) + context/state.rs (GovernanceClassS) + saga.rs handler
path-lengthening + mod.rs actor wiring + messaging_helpers snapshot read paths.

**Verdict: sound for merge. Zero weakening.** Behavior-neutral foundation (combinators
`#[allow(dead_code)]`, no handler migrated, saga changes pure `state.X`→`state.class_s.X`).

**Why:** Establishes the compile-time fail-closed-persist boundary (no DerefMut on ClassSCell;
view-typed combinators own persist by construction) replacing the source-text scanner long-term.
**How to apply:** When the LATER privatization/handler-migration PR lands, re-verify combinators
get real production callers + state_mut() escape hatch deleted + fields privatized.

## Verified facts (all live at this HEAD)
1. Every Class-S combinator persists fail-closed BEFORE acking Ok: keep/restore/compensating/
   keep_compensating call persist_state_fail_closed and only return Ok(value) on persist Ok.
   keep = retain mutation on persist-fail (un-recording a nonce reopens replay — correct).
   restore = snapshot Class-S substructs before f, restore on persist-fail. compensating =
   restore THEN async undo external. keep_compensating = keep Class-S, async undo Class-C only.
   then_append = persist, external append, on append-fail restore+re-persist with AppendOutcomeError
   {mutated} DURABILITY-DIVERGENCE flag. best_effort = ClassCMut view, persist_best_effort.
2. Restricted views cannot mutate Class-S: ClassCMut exposes NO class_s_mut/governance_class_s_mut
   (only rest_mut/governance_mut/split_class_c — none reach Class-S mutator). then_append's `after`
   gets READ-ONLY &PerContextState (no &mut → compile error to name class_s_mut). Field privatization
   (later PR) closes the residual pub(crate) Deref-nameability; no &mut PATH exists today.
3. §9.4.3 bearer barrier INTACT: SagaPreparedState enum (saga_prepared_state.rs:67) has NO
   Clone/Serialize/Debug derive (comment :65-66 confirms); file UNCHANGED this PR. snapshot/restore
   route through sanctioned SagaPreparedStateSnapshot mirror (:437, derives Clone/Serialize) via
   from_prepared/into_prepared. NonceTracker (no Clone, holds clock) → snapshot_entries/from_snapshot.
4. On-disk ContextSnapshot format UNCHANGED: build_snapshot_from_state still emits flat
   executed_proposals/threshold_signers/threshold_value/spending_nonce_tracker_state/xctx_* fields;
   only READ paths into state lengthened by .class_s. Exhaustive destructure with struct-literal
   `GovernanceClassS{...}` forces conscious persist decision on any new Class-S field. Mirror snapshot
   types (ClassSStateSnapshot/GovernanceClassSSnapshot) are in-memory round-trip ONLY, not serialized.
5. Gate scripts/check-class-s-fail-closed.sh: --self-test exit 0; real-tree scan exit 0; script
   BYTE-IDENTICAL to origin/main (not weakened). Combinator file's 6 .record() markers all under
   #[cfg(test)]; production markers appear in caller bodies (future migration) where persist covers.
6. No new panic/unwrap/expect in production: 4 hits (state.rs:2059 panic, :474 expect; saga.rs:4633
   expect; +receipt-signs expect) ALL inside #[cfg(test)] mod tests (state.rs mod@1494, saga.rs mod@2061).
7. GovernanceClassS::restore uses struct-literal (not threshold_value= assignment) DELIBERATELY to
   keep the gate's assignment marker out of the rehydration body — documented, correct (mirrors
   restore_context precedent).

## Build/test
cargo build -p scp-runtime --features testing: OK. 22 class_s combinator tests PASS +
lossless snapshot/restore round-trip test PASS. Actor wiring: ContextActor.state:ClassSCell,
dispatch via cell.state_mut() byte-for-byte unchanged handler path; dirty/mutated flow preserved.
