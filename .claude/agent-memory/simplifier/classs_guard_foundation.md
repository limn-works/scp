---
name: classs-guard-foundation
description: class_s.rs ClassSCell combinator foundation (ADR-049 §9) — what "minimal" means here; why the coverage/migration-scope doc earns its place
metadata:
  type: project
---

`crates/scp-runtime/src/context/actor/class_s.rs` is the compile-time replacement for the source-text `check-class-s-fail-closed.sh` scanner: `ClassSCell` owns `PerContextState`, has `Deref` but NO `DerefMut`, so the ONLY mutation path is through combinators that persist by construction. This retires a non-convergent denylist gate via the type system — exactly the CLAUDE.md "enforce mechanically / prefer type system over AST gate" direction.

The foundation is 6 combinators + 2 views + a data split, and it is appropriately minimal:
- 5 Class-S-capable combinators span a real 2x2 grid (keep/restore x no-C-undo / C-or-external-undo): `_keep`, `_restore`, `_keep_compensating`, `_compensating`, plus `_then_append` for the one extra post-persist external-append shape. `commit_class_c_best_effort` covers Class-C.
- Each maps to a distinct rollback discipline that recurs in handlers — not speculative. Rollback strategy is encoded in the combinator NAME against snapshot/restore mirrors, removing the caller-supplied-rollback foot-gun.
- 2 views (`ClassSMut` / `ClassCMut`) differ by which slice of state they expose `&mut`; `ClassCMut` has no `class_s_mut`. `ClassCSplit` exists only because `ConsequenceStateSplit` needs 5 disjoint borrows.

**Why:** A future reviewer may flag the combinator count or the long doc as over-engineering. It is not. The grid is minimal-spanning, and the foundation is deliberately behaviour-neutral scaffolding (`#[allow(dead_code)]`, handlers still on the `state_mut` escape hatch).

**How to apply:** The "Combinator coverage & migration scope" doc section (added @4cf3a9f1f, ~43 lines) is "why"-focused and NON-redundant with per-combinator docs: per-combinator docs say what each combinator DOES; the coverage section says what the set deliberately does NOT cover and how outliers are handled at migration. Both cited outliers are REAL: `prepare_b` (handlers/saga.rs ~L799) genuinely keeps `xctx_nonce_dedup` while restoring `saga_pending` (intra-Class-S field split no single combinator expresses); `emit_divergence_marker` (~L1974) takes `state: &PerContextState` (read-only) so it provably mutates no Class-S — "append-then-persist of unchanged state." Verify cited example sites still exist before re-approving. Related: [[project_class_s_gate_selftest]].
