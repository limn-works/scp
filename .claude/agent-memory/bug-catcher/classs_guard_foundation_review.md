---
name: classs-guard-foundation-review
description: Class-S type-guard FOUNDATION review (ClassSCell combinators + ClassSState/GovernanceClassS data split) at HEAD 4cf3a9f1f — CLEAN, merge-ready
metadata:
  type: project
---

# Class-S type-guard FOUNDATION review (HEAD 4cf3a9f1f, branch classs-guard)

Reviewed: crates/scp-runtime/src/context/actor/class_s.rs (ClassSCell + ClassSMut/ClassCMut views + 6 combinators), actor/state.rs (ClassSState + snapshot/restore), context/state.rs (GovernanceClassS + snapshot/restore), on-disk snapshot builder/restore.

**Verdict: CLEAN, merge-ready.** No defects found.

**Why:** (verify all still true before relying)
- 6 combinators' keep/restore directions + AppendOutcomeError.mutated flag in all 4 then_append arms are logically correct (f-reject=false, initial-persist-fail=true/keep, after-fail+repersist-OK=false, after-fail+repersist-fail=true). mutated is DURABILITY-DIVERGENCE not in-mem-changed.
- restore_class_s restores BOTH class_s + governance.class_s = full Class-S scope all snapshotting combinators cover. Total over the subset.
- Async borrows (AsyncFnOnce compensate/on_persist_failure/after) awaited inline; ClassCMut/&PerContextState views + deps borrow ends before return. No use-after-move of snapshot/external.
- Data split lossless: ClassSState/GovernanceClassS snapshot↔restore round-trip through sanctioned mirrors (SagaPreparedStateSnapshot, NonceDedup entries+ttl, NonceTracker snapshot_entries/from_snapshot w/ clock param). NonceDedup is just {seen:HashMap, ttl_secs} — eviction is by-timestamp (min_by_key value), no hidden insertion-order state, so HashMap round-trip is value-stable.
- On-disk format UNCHANGED: build_snapshot_from_state reads new .class_s.*/.governance.class_s.* paths, writes SAME flat ContextSnapshot fields. executed_proposals HashMap<ProposalId,u64>→on-disk HashSet via .keys() is PRE-EXISTING mapping (live form was HashMap before split, only location moved). Restore side (lifecycle_helpers ClassSState literal) writes back into .class_s.*.
- No stale flat field-path refs: crate compiles (fields no longer exist on PerContextState/GovernanceState, so any stale path = build error). All saga_pending/xctx_*/governance Class-S refs go through .class_s. or accessor or are on ContextSnapshot (flat on-disk type).

**Gates:** class_s tests 22/22 pass; broad scp-runtime --lib --features testing 1864 pass; check-class-s-fail-closed.sh --self-test PASSED; clippy -p scp-runtime --all-targets --features testing clean; scp-core+scp-runtime build clean.

**Pattern note:** This is the well-executed inverse of the recurring "documented fix not applied" / "stale field path after rename" patterns. Comprehensive ref update verified by compile + targeted grep of all 9 moved fields. The combinator-name-encodes-rollback-direction design removes the caller-supplied-rollback foot-gun.
