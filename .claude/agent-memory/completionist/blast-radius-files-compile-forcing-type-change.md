---
name: blast-radius-files-compile-forcing-type-change
description: When a PRD story removes a default type param / deletes a constructor (compile-forcing change), its files[] almost always under-enumerates the real caller set — grep every call site yourself.
metadata:
  type: feedback
---

When a story does a **compile-forcing type change** — removing a default type parameter
(e.g. `DidDht<D = InMemoryDhtClient>` → `DidDht<D>`) and deleting `impl Default` / `fn new()` —
EVERY caller of the deleted API is in the blast radius, including test files and sibling
bridge files. The story's `files[]` (and its "Blast radius (all in files[])" claim) routinely
omits some.

**Why:** ADR-062 SCP-CAPINJECT-001 removed `DidDht::new()` + the default type param but its
`files[]` listed only `napi/src/identity.rs`, not `napi/src/scp.rs` (which had 6 production
`DidDht::new()` sites), and listed zero of the ~8 test files that call `DidDht::new()`
(`scp-ffi/tests/e2e_bridge.rs`, `scp-testing/tests/integration/*.rs`,
`scp-runtime/tests/identity_config_cross_path.rs`, napi `discovery.rs`/`context.rs`/`ucan.rs`
test mods, `scp-ffi/src/discovery.rs` test mod). An AC required `cargo test --workspace` exit 0
AND `grep 'pub fn new()' == 0` — mutually satisfiable only if every caller is migrated, so the
omitted files ARE in scope.

**How to apply:** For any story deleting/renaming a widely-used symbol, run
`grep -rn 'Symbol::method\|bare Symbol' crates --include=*.rs`, classify each site prod vs test
(find nearest preceding `#[cfg(test)]`/`mod tests`), and diff the full set against `files[]`.
Missing prod file = definite compile break = INCOMPLETE. Missing test files that call the
deleted API also break `cargo test --workspace`. Feature unification restores a gated *type*
across a workspace build, but never restores a *deleted fn* — don't let "workspace unification"
excuse a missing `fn new()` caller. See [[feature-gating-blast-radius]].
