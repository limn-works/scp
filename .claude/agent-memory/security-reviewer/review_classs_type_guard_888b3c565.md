---
name: review-classs-type-guard-888b3c565
description: CLEAN security review of ClassCMut/GovernanceClassCMut field-granular refactor (ADR-049 §9 Class-S fail-closed); branch refactor/classs-type-guard HEAD 888b3c565
metadata:
  type: project
---

# Class-S type-guard refactor — CLEAN (no findings any category)

Worktree `classs-guard`, branch `refactor/classs-type-guard`, HEAD `888b3c565` ("refactor(actor): best-effort views hold field-granular refs, not whole &mut"). Single-file commit: `crates/scp-runtime/src/context/actor/class_s.rs` only (+254/-135). Large two-dot diff vs origin/main is UNRELATED event-log work the branch is behind on — ignore it; review only the one commit.

**Why:** ADR-049 §9 Class-S fail-closed persistence invariant. `ClassSCell` owns `PerContextState`; mutation only through combinators handing a closure a view. `ClassSMut`=fail-closed-persist view (may reach Class-S). `ClassCMut`/`GovernanceClassCMut`=best-effort/compensation views (NO fail-closed persist) → must have NO `&mut` path to `state.class_s.*` or `state.governance.class_s.*`. This commit converts those two views from holding a whole `&mut PerContextState`/`&mut GovernanceState` to holding FIELD-GRANULAR refs, so a whole-bucket accessor (e.g. `rest_mut -> &mut PerContextState`) becomes uncompilable by construction (nothing of that type to return) rather than a documented prohibition.

**How to apply / verified facts (re-check if revisiting):**
- `ClassCMut` (class_s.rs:313) destructures `PerContextState` in `new` (:500): `&mut` to members/receive_buffer/role_state/checkpoint_events_since; `&` (shared) to `membership` and `class_s: &'a ClassSState` (:328); `GovernanceClassCMut` sub-view for governance. NEW shared `class_s: &ClassSState` is `&` read-only; sole accessor `class_s(&self)->&ClassSState` (:555), NO `&mut` counterpart; no `unsafe` in file so no &→&mut coercion. Whole-state `Deref` REMOVED.
- `GovernanceClassCMut` (:360) destructures `GovernanceState` in `new` (:387) binding only 5 Class-C fields; `..` DISCARDS the rest including `governance.class_s: GovernanceClassS` (real field @ state.rs:1156) — never bound to any ref. `governance_class_c_mut -> &mut GovernanceClassCMut<'a>` (:529) returns &mut to sub-view, which holds no Class-S ref → no transitive &mut path. `split_class_c` (:576) reborrows already-disjoint fields; class_s not in split.
- `ClassSMut` (:192) + all 6 combinators UNCHANGED, still persist_state_fail_closed (best-effort path = persist_state_best_effort). `ClassSMut::new`/`ClassSCell::new` const-fn constructor-locked.
- Behaviour-neutral: views `#[allow(dead_code)]`, no prod callers; `cargo check -p scp-runtime` clean; 26 class_s unit tests pass; no panic/unwrap/expect outside `#[cfg(test)]`.
- Gate `scripts/check-class-s-fail-closed.sh` UNTOUCHED by commit, byte-identical to origin/main (blob `5f660191`), runs exit 0.
- §9.4.3 bearer barrier: NO Clone/Serialize/Debug added to any saga/nonce bearer type. Diff REMOVES the now-moot `Deref` impls on the two C-views + their `assert_not_impl_any!(…: DerefMut)` guards (correct — no Deref ⇒ can't misuse DerefMut); KEEPS load-bearing `assert_not_impl_any!(ClassSCell: DerefMut)` (:1119).
- POSITIVE pattern: documented-prohibition → structural-impossibility via destructure-once-into-disjoint-refs; matches "enforce mechanically via type system" tenet; avoids weaker re-check of what types now enforce.
