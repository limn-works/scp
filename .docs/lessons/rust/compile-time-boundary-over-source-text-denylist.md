# Compile-time type-shape enforcement beats a source-text denylist — but the perimeter moves to the view destructures

**Evergreen lesson — ADR-049 §9 Class-S fail-closed migration (2026-06).**

## The principle

A security invariant of the form "field X may only be mutated on path Y" should be enforced by making the wrong thing **uncompilable**, not by a CI script that greps the source for forbidden spellings. A source-text denylist (`grep`/awk over an open mutation-method grammar) is **non-convergent**: every new way to spell the mutation is a fresh evasion, so the gate grows without bound and never closes. The Class-S gate reached **4354 lines** chasing spellings before it was retired.

## What replaced it (the convergent design)

To enforce "every Class-S mutation is paired with a fail-closed persist":
- The owner type (`ClassSCell`) has **no `DerefMut`** and **no whole-`&mut` escape hatch** (`assert_not_impl_any!(ClassSCell: DerefMut)`), so a handler cannot reach `&mut PerContextState`.
- The Class-S fields are **privatized**; the only `&mut` views are issued by persist combinators (each performs/owes a fail-closed persist) or a deferred-persist linear token (`#[must_use]` + move-consuming `commit`).
- The **best-effort path gets field-granular views that hold NO whole `&mut`** and only a shared `&` to Class-S — so a Class-S mutation off the fail-closed path is a **compile error by construction**, independent of field visibility.
- A residual the type system genuinely can't catch (one sanctioned no-persist method) is held by a **bounded positive-allowlist** tripwire test — NOT a denylist. A new no-persist mutator trips it.

## The non-obvious trap: the perimeter is the destructures

The "airtight by construction" guarantee depends on each view's `new`/`from_state` **destructure binding every Class-S-containing field to the `..` rest or a shared `&` — never `&mut`.** A field bound *by name* is downgraded to `&` only by the destination field *type*: a one-token edit (`&'a` → `&'a mut`) silently re-arms a Class-S `&mut`, and a whitelist tripwire that scans only the owner `impl` block sees nothing. **The structural guarantee's perimeter is the view constructors, and they need their own mechanical guard.** The right guard is a `compile_fail` doctest per fragile field (NOT extending the text scanner to the constructors — that reintroduces the denylist).

## Related corollaries from the same migration

- **Linear-handle Drop guards are debug-only.** `#[must_use]` + `Drop`-`debug_assert!` is a no-op in release and is silenced by `let _x =`. The real backstop is **move semantics** (a consuming `commit` makes double-commit/swallow a type error); pair it with drop-path tests so CI's debug-assertions fire, an `assert_not_impl_any!(Token: Clone)`, and a metered release-mode signal.
- **Dual-use fields defeat a per-field split.** A field mutated on both a fail-closed path (downward-auth) and a best-effort path (e.g. consequence-engine auto-suspension) can't be cleanly privatized per-field. Fail-close the *rare outcome* write (keep the hot evaluation coalesced), or split the field at the sub-struct level — don't leave it reachable best-effort, because a coalesce-window crash that loses a suspension is a downward-authorization rollback.

See `.docs/lessons/ast-gate-checks-definition-not-name-resolution.md` (related: prefer compiler enforcement over AST/text gates) and ADR-049 §9.
