---
name: classs-type-guard-combinators
description: ClassSCell view-typed combinator foundation (ADR-049 §9) — APPROVED merge-readiness review; the misuse-resistance design and the one seam to watch
metadata:
  type: project
---

ClassSCell foundation (`crates/scp-runtime/src/context/actor/class_s.rs`, branch `refactor/classs-type-guard`, commit 4cf3a9f1f) — APPROVED as merge-ready API.

**What it is:** converts the non-convergent source-text invariant "mutate Class-S then persist_fail_closed" (`scripts/check-class-s-fail-closed.sh`) into a by-construction compile-time guarantee. `ClassSCell` owns `PerContextState`, exposes `Deref` only (NO `DerefMut` = the compile hook). Six combinators: `commit_class_s_{keep,restore,compensating,keep_compensating,then_append}` (fail-closed persist) + `commit_class_c_best_effort` (best-effort). Mutation views: `ClassSMut` (has `class_s_mut`/`governance_class_s_mut`), `ClassCMut` (NO Class-S mutator — restricted by design).

**Why the API is sound (the design wins):**
- Rollback is the combinator's OWN `snapshot`/`restore` over the Class-S mirror (`ClassSStateSnapshot` = lossless mirror of all 6 `ClassSState` fields + `GovernanceClassS`), NOT a caller-supplied closure. This removes the real footgun where a caller writes a rollback that undoes the wrong field.
- `keep` vs `restore` is the load-bearing naming axis (survive-persist-failure vs roll-back). Each method doc states the inverse pointer. The keep/restore × no-undo/undo-C grid is enumerated in module docs.
- `ClassCMut` and the `&PerContextState` handed to `_then_append`'s `after` expose no `class_s_mut` → a Class-S transition CANNOT be named there (compile error, not lint).
- `AppendOutcomeError.mutated` is a DURABILITY-DIVERGENCE flag (could durable disagree with returned in-memory?), NOT an "in-memory changed" flag — doc explicitly disclaims the misreading.

**The one seam to watch (non-blocking):** `ClassSMut::rest_mut` and `ClassCMut::rest_mut` share name+signature (`&mut PerContextState`) but different persist guarantees; while Class-S fields stay `pub(crate)`, `ClassSMut::rest_mut` can still REACH Class-S (covered by its fail-closed persist, so not a hole). The named field-privatization follow-on PR is what makes the `ClassCMut` side airtight. Verify privatization lands BEFORE `state_mut` is deleted.

**Honest scoping (don't demand pre-coverage):** the doc claims common-shapes + escape-hatch + 2 documented outliers (prepare_b intra-Class-S keep/restore split → decompose; emit_divergence_marker no-mutation → not a Class-S site), NOT exhaustiveness. `state_mut` (`pub(in crate::context)`) is the explicit migration bridge; 3 production callers exist outside the module = expected. Deleted in terminal migration step. Requiring full pre-coverage would violate the repo's over-engineering guidance (CLAUDE.md line 189).

Tests: every combinator has success / persist-fail / f-rejects; `_then_append` adds initial-persist-fail, after-fail+repersist-OK (mutated=false), after-fail+repersist-FAIL (mutated=true).

Related: this is the ADR-049 storage/actor ladder work (see [[pr1744_pseudonym_routing_rehome]] is unrelated; the actor refactor is the broader context).
