---
name: classs-cell-invariant-pr1
description: Adversarial assessment of ClassSCell (ADR-049 §9 Class-S fail-closed persist as compile error) — what migration PRs MUST close
metadata:
  type: project
---

# ClassSCell Class-S fail-closed compile-enforcement — adversarial assessment

File: crates/scp-runtime/src/context/actor/class_s.rs (PR1 scaffolding, commit 5c50015f8).
Goal: make "mutate Class-S field then fail-closed persist" a COMPILE error to violate, retiring the non-convergent awk gate (`scripts/check-class-s-fail-closed.sh`).

**Why:** Deref-only (no DerefMut) cell owns PerContextState. Reads via Deref; mutation only via combinators that persist. Eventual end state = private fields + state_mut() escape hatch removed.

**How to apply:** when reviewing the MIGRATION PRs (not PR1), verify each hole below is closed. PR1 itself is fine as scaffolding.

## Empirically proven (rustc compile probes in isolated worktree)

1. **Deref-only blocks `&mut *cell`** — confirmed E0596 without DerefMut. Direct-aliasing axis CLOSED.

2. **Module-visibility paradox — the core finding.** class_s, state, handlers are SIBLING modules under actor. Combinator closures (`f`) are written in HANDLERS, not class_s. So:
   - Fields private-to-`state` module ⇒ handler closures can't name them ⇒ `commit_class_s` ITSELF breaks (proven E0616). So the plan CANNOT be "fields private to state module" while closures live in handlers.
   - Therefore migration must either (a) `pub(in crate::context::actor)` the fields so all siblings name them, or (b) move mutators to `&mut self` methods on PerContextState.

3. **`commit_best_effort` is a PERMANENT bypass** (proven both for pub(in) fields AND for method-only mutation). It vends a raw `&mut PerContextState`. As long as ANY Class-S mutator is reachable from `&mut PerContextState` (public field OR `&mut self` method), best_effort's closure reaches it with only BEST-EFFORT persist. Privatizing fields does NOT close it — just changes spelling `state.field=x` → `state.method()`. MIGRATION MUST: make best_effort unable to reach Class-S state — e.g. split Class-S fields into a sub-struct best_effort's closure can't touch, or give best_effort a closure param type that only exposes Class-C fields.

4. **`into_inner()` is a bypass** — `pub(crate)`, consumes self, returns owned PerContextState. Any scp-runtime code can `into_inner()` → mutate detached state → drop or re-`new()` (also pub(crate) const fn) → NO persist. MIGRATION MUST: restrict to a real ownership-handoff seam (e.g. return a token type that forces a persist/snapshot, or narrow visibility to the single drain/replace caller).

5. **Deref + interior mutability = latent reopen.** If any Class-S field type EVER gains RefCell/Cell/Mutex/RwLock/Atomic*, Deref (shared &) mutates it with ZERO persist (proven). CURRENTLY CLOSED: NonceDedup = HashMap+u64 (&mut methods); saga_prepared_state types have no interior mutability. Standing fragility — add a gate/test forbidding interior-mutable Class-S field types.

## Verdict
Design is SOUND on the direct `&mut`/DerefMut axis. NOT yet sound until migration closes: commit_best_effort (permanent bypass, the most important), into_inner, and adds an interior-mutability guard. The escape hatch state_mut() is expected PR1 artifact, not a flaw.
