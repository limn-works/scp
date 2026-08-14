# OwnedIdentityDid gate (check-owned-identity-did.py) — Pass 4 BYPASS FOUND

Target: `scripts/check-owned-identity-did.py` (positive-whitelist frozen-shape gate)
asserting `crates/scp-runtime/src/context/supervisor/identity_capability.rs`.

## CONFIRMED COMPILING BYPASS (BLACK-G02): nested-in-method-body inherent impl

Put a SECOND inherent `impl OwnedIdentityDid { pub(in crate::context) fn forge_for_handler(arbitrary: DID) -> Self { Self { did: arbitrary } } }`
INSIDE the body of an allowlisted method (e.g. `reissue`).

Rust fact: an inherent impl nested in a fn body is NOT scoped to the fn —
rustc applies it globally (only a `non_local_definitions` WARNING, compiles
clean). So `forge_for_handler` is a caller-chosen arbitrary-DID minter callable
from `crate::context::actor::handlers` → full cross-identity isolation defeat.

Why the gate misses it (all three structural checks blind):
- A1 walks ONLY `root.children` → sees one top-level impl (the nested one is
  buried in a method body, not a module-level item).
- A3 walks ONLY the outer impl's direct `declaration_list` children → sees the
  three valid methods; never recurses into method bodies.
- A4 walks the whole tree for `struct_expression` but EXEMPTS any literal whose
  lexical span lies inside an allowlisted method body. The nested impl's
  `Self { did: arbitrary }` is inside `reissue`'s body span → exempted.
- A0 `has_error` is FALSE (perfectly valid parse).

Triad verified (worktree p4-bh @ c5c145caa):
- gate exit 0 (PASSED)
- `cargo check -p scp-runtime` clean (warnings only: non_local_definitions, dead_code)
- handler-reachability proof: `OwnedIdentityDid::forge_for_handler(DID("did:evil:attacker"))`
  added to handlers/queries.rs compiled with NO errors (then reverted).

## FIX DIRECTION
The gate's "method BODY semantics are out of charter" line is too generous: it
treats the whole body as opaque, but an inherent `impl` (item, not body
semantics) nested in a body is a DEFINITION-shape escape. Fix: extend A3/A4 to
reject any `impl_item` (and any other item kind that can introduce a minter —
`function_item` of the type, etc.) appearing ANYWHERE in the file via `_walk`,
not just at module level / impl-declaration-list level. I.e. "exactly one
`impl OwnedIdentityDid` in the ENTIRE tree", and reject any nested impl_item.
This stays definition-side (still no use-site/mint-arg analysis).

## What I ruled out (resisted attack)
- top-level macro_invocation `m!();` parses as expression_statement / m!{} as
  macro_invocation — both rejected by A1 catch-all.
- extern block = foreign_mod_item, union = union_item, const block = const_item
  — all rejected by A1 catch-all.
- raw-ident struct/attr names (`r#OwnedIdentityDid`, `r#derive`) → normalize to
  different string, rejected; also not real forgeries (rustc treats r#derive≠derive).
- cfg_attr(...) smuggling derive → attr named `cfg_attr`, not in allowlist → rejected.
- nested impl inside test mod → cfg(test), compiled out of prod, not reachable.
- nested impl inside a top-level const block → const_item rejected at A1.
