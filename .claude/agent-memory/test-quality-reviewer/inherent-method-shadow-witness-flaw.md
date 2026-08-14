# Inherent-method-shadowing compile witnesses are UNSOUND for `&mut self` GROW guards

Context: ADR-049 §9 Class-S (`crates/scp-runtime/src/context/actor/class_s.rs`),
commit b23509123. Tests `role_view_grow_resolves_to_trait` and
`best_effort_view_has_no_whole_mut_accessor` use a trait with a zero-arg
`fn x(&self) -> Witness` shim, calling `view.x()` and binding to `Witness`,
claiming that ADDING an inherent `x` would shadow the trait (inherent preferred)
and break compilation = negative guard for "no GROW accessor exists."

## The flaw (empirically verified in /tmp scratch crate)
Rust method resolution picks a candidate by RECEIVER applicability via the
autoref/autoderef step order: `&self` (shared) candidates are tried BEFORE
`&mut self`. Inherent-vs-trait preference only applies WITHIN the same receiver
adjustment.

- Inherent `fn x(&self) -> Different` (same receiver, zero-arg) → SHADOWS, breaks
  build. Guard works.
- Inherent `fn x(&mut self, arg)` (the REALISTIC GROW shape) → does NOT shadow.
  The `&self` trait candidate is found first; trait method fills it; call compiles;
  guard SILENTLY PASSES (evaded).
- Inherent `fn x(&mut self) -> Different` zero-arg → also does NOT shadow (evaded).

Every realistic GROW / whole-`&mut` accessor takes `&mut self` (you cannot grow
through `&self`). Real targets here: `suspend_all(&mut self, member_did)`,
`rest_mut(&mut self) -> &mut PerContextState`, `role_state_mut(&mut self) -> &mut`.
ALL would evade these witnesses. The guard is theater against its own threat.

The `require(ConsequenceRoleStateMut::suspend_all)` POSITIVE half is sound (catches
deletion) — but that is NOT the negative guarantee the commit claims.

## Lesson
A coupled-negative compile witness via trait-method shadowing only works when the
hostile method has the SAME receiver+arity as the trait shim. For `&mut self`
mutators the shim must be `&mut self` too — but then `assert_not_impl_any!` or a
genuinely typed call is cleaner. Treat "inherent shadows trait" claims skeptically:
verify with a scratch crate using the EXACT realistic hostile signature, not a
convenient zero-arg `&self` one.
