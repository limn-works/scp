---
name: class-s-derefmut-guard
description: ADR-049 §9 — compile-time guard (assert_not_impl_any DerefMut) locking Class-S view airtightness; HEAD d973f179a APPROVED
metadata:
  type: project
---

HEAD d973f179a (branch refactor/classs-type-guard, test-only commit) adds a compile-time regression guard locking the field-granular view airtightness. See [[project_classcmut_field_granular]] and [[project_class_s_combinator_taxonomy]].

**What it adds (13 lines, 4 files):** three `static_assertions::assert_not_impl_any!(…: core::ops::DerefMut)` under `#[cfg(test)]` at class_s.rs:1002-1004 for `ClassCMut`, `GovernanceClassCMut`, `ClassSCell`. Dev-dep `static_assertions = "1.1"` wired at workspace `[workspace.dependencies]` + scp-runtime `[dev-dependencies]` (`{ workspace = true }`) + Cargo.lock. NOT previously in the repo.

**Why APPROVED (zero findings):** The guard asserts the EXACT load-bearing property the field-granular design rests on — "no `&mut` path to a Class-S-containing struct on a non-fail-closed path." A future `impl DerefMut` would silently re-open that path (`&mut *view`), bypassing the field-granular accessors. So this is closing the one hole the type system would otherwise leave open, NOT weaker re-checking of an already-sound property — on the right side of CLAUDE.md's non-convergent-enforcement guard. Positive/bounded ("trait absent"), no "next spelling" to chase — opposite of the source-text scanner it helps retire.

**ClassSMut correctly EXCLUDED from the guard set:** it is constructed ONLY inside the 5 fail-closed-persisting combinators (every `ClassSMut::new` at 614/676/748/833/917 is immediately followed by `persist_state_fail_closed`), so a DerefMut on it would be covered by the persist. Guarding it would assert a property the design doesn't depend on. Omission is principled.

**ClassSCell: !DerefMut is the highest-value assertion** — the cell owns PerContextState; "mutation only through combinators" depends on it having Deref but no DerefMut (it IS the compile-time hook, class_s.rs:536-545). The `state_mut()` escape hatch (`pub(in crate::context)`) is a NAMED/greppable/scheduled-for-deletion method — categorically different from an implicit DerefMut coercion; guard targets the implicit re-opening, doesn't pretend to close the known hatch.

**Verification:** `cargo check -p scp-runtime --tests` clean (assertions hold today → true regression guard, not already-red). Dev-dep is `#[cfg(test)]`-only → zero weight on shipped artifact/FFI/SDK. Precedent: supervisor/mod.rs:70-75 already uses a compile_fail doctest for a trait-shape invariant; ADR-049 §5 ran this playbook for OwnedIdentityDid. ADR-049 §9 still names scripts/check-class-s-fail-closed.sh (ADR lines 166-174) — amendment correctly deferred to terminal gate-deletion step. Scanner byte-identical to this commit's parent (branch-vs-commit: two-dot main...HEAD is huge = whole actor branch; THIS commit's stat = 4 files +13 lines). Nothing precludes terminal state_mut deletion + privatization (no field-visibility/prod-path changes).
