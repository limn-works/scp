# A Mechanical Check Earns Its Keep Only Against an Attacker Who Cannot Edit the Check

## The rules

1. **Before building a source-text check, ask whether its own threat model can defeat it.**
   When the only attacker the check constrains is an insider with commit access, and that
   insider can equally edit the check, its self-test, or its CI wiring, the check adds zero
   security over the type system plus code review. It is maintenance cost presented as
   defense in depth.
2. **Prefer the compiler.** Make the forbidden thing uncompilable: a private field, a
   restricted constructor, no `DerefMut`, a `#![deny(...)]` module lint. The compiler is
   sound, it converges, and it does not rot as the language grammar grows.
3. **A gate may check a definition, never use-site name resolution.** A gate can soundly
   assert facts about how one item is defined: its visibility, its fields, its closed set of
   constructors, the item kinds a file may hold. A gate that asks "does this argument at this
   call site resolve to the trusted binding?" is reimplementing name resolution in an AST
   walker, and every review pass will find one more binding form that rebinds the name.
4. **A gate is a positive whitelist that fails closed.** It enumerates the permitted shapes
   and rejects everything else by kind. A denylist of forbidden spellings never closes.
5. **A second, weaker check of a property something else already proves soundly has negative
   value.** Ask what already proves the property — the compiler, `cargo tree`, a
   cryptographic check — and add a gate only for a residual that nothing else expresses.
6. **Review-pass count is a convergence signal.** More than about three passes that each find
   a new spelling of the same bypass means the approach is wrong. The merge-blocking bar for
   a defense-in-depth gate is a compiling counterexample that evades it, not a theoretical
   spelling that does not compile.

## Where these rules came from

- A tree-sitter scanner over `OwnedIdentityDid` (ADR-049 §5) grew past 6,000 lines across
  about 17 review passes chasing shadowed-binding spellings at the one site that mints the
  token, and was deleted. The Class-S fail-closed source-text gate reached 4,354 lines
  chasing mutation spellings before a type-shape design in `ClassSCell` replaced it.
- Two integration tests parsed their own `Cargo.toml` to prove that no non-dev edge enables
  `scp-identity/testing`. Each review round found another manifest spelling. Both readers
  were deleted, because `scripts/check-shipped-feature-graph.sh` already resolves the
  shipped feature set with `cargo tree` and rejects the feature whatever spelling enables it.

## How `OwnedIdentityDid` is held today

`OwnedIdentityDid` (`crates/scp-runtime/src/context/supervisor/identity_capability.rs`)
proves that an actor's identity owns the actor. Three layers hold it, with different reach:

- **Type system, against all outsiders.** The `did` field is private and the minting
  constructor `issue_for_actor` is `pub(super)`, so code outside the supervisor module can
  hold or borrow a token and cannot construct one.
- **Module lints, against the insider move review misses most.**
  `#![deny(non_local_definitions)]` in `supervisor/mod.rs` makes a second minter hidden as an
  `impl` block inside a function body a compile error, and `#![deny(unsafe_code)]` blocks
  `transmute` fabrication.
- **Code review, against every other insider edit.** A new constructor, a second top-level
  `impl`, a widened visibility, or an added derive all compile. The file is small, so each
  shows as a visible diff.

## Traps in type-shape enforcement

These come from the Class-S migration (ADR-049 §9).

- **The perimeter is the view constructors.** A best-effort view that binds a Class-S field
  by name gets `&` only because of the destination field type; changing `&'a` to `&'a mut`
  in one place re-arms mutation. Guard each such field with a `compile_fail` doctest, not
  with a text scanner over the constructors.
- **A `Drop` guard with `debug_assert!` does nothing in release builds.** Move semantics are
  the real backstop: a consuming `commit(self)` makes double-commit a type error.
- **Couple the obligation to the mutation.** A mutator that returns a `bool` the caller must
  turn into a persist obligation lets a caller mutate and forget. Take the obligation sink as
  a required parameter and arm it inside the mutator.
- **State a structural guarantee for the view that lacks the accessor, never globally.**
  "The best-effort view has no grow accessor" is a compile-time fact. "Growth happens only
  through the consequence view" is false when a `pub` method reaches the same mutation, and
  that sentence stops a reviewer from looking for the persist that makes the other path safe.
- **A method-resolution witness is not a negative guarantee.** A test that relies on "an
  inherent method beats a trait method" to detect an added method misses any added method
  whose receiver or arity makes it non-viable at the witness call site, such as an
  `&mut self` method with arguments. An injected `fn suspend_all(&mut self, did)` compiled
  with every such witness green. `assert_not_impl_any!` over a trait is a real negative
  check; coupling over inherent-versus-trait resolution is not.
