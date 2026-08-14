# Gate: scripts/check-no-shim-reexports.sh (ADR-057 T1)

Bans `pub use scp_clock|scp_crypto|scp_did|scp_mls ::` outside the owning crate + scp-core facade.
Runs in ci.yml `protocol-deps` job (needs: check-draft = UNCONDITIONAL, in required `ci` aggregation). Good wiring.

## Coverage gaps (confirmed empirically, split-primitives branch @033a12d4c)
- **BLIND SPOT (MEDIUM):** grep target `crates/*/src/` (line 51) is a single-level glob — does NOT recurse into
  `crates/scp-ffi/{common,uniffi,napi,napi-test-stubs}/src/`. Those trees have ~257 live scp_did/scp_mls/etc imports.
  Even the CANONICAL `pub use scp_did::X` shim in a bridge sub-crate passes. Gate header claims "anywhere" — false.
  Fix (coverage-expanding, closed): recurse all of `crates/` via `find`/`grep -r crates/ --include=*.rs`.
- **Single-spelling denylist (LOW, do NOT chase — anti-denylist rule):** evaded by `pub use ::scp_did::`,
  `pub use scp_did as x`, `pub type X = scp_did::Y`, alias-launder (`use scp_did::T as U; pub use U;`),
  Cargo package-rename (`dep = { package = "scp-did" }` + `pub use dep::`).
- `pub(crate) use` exclusion is CORRECT (cross-crate shim requires `pub`; pub(crate) not importable cross-crate).

Property is HYGIENE not security — real invariants (wasm-safety, acyclicity, banned deps) enforced soundly by
rustc + wasm32 job + check-protocol-deps. So best-effort tripwire is defensible, but ADR overstates as fully "enforced."
No live shim currently hides in blind spots (verified). Release.yml publish order topo-valid (runtime→media is dev-dep).
