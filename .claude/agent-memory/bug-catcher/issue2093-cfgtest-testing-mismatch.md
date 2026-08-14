---
name: issue2093-cfgtest-testing-mismatch
description: scp-runtime has many #[cfg(test)]-only test modules that use testing-feature-gated surface; #2093 fix (a5755bcdd) gated only 1 of 6+; all masked by dev-dep
metadata:
  type: project
---

# scp-runtime `#[cfg(test)]` modules using `testing`-feature surface (issue #2093)

**Class of latent defect:** scp-runtime unit-test modules gated ONLY `#[cfg(test)]` call
surface gated behind the crate's `testing` feature — `scp_platform::testing::InMemoryKeyCustody`
(scp-platform/lib.rs:67 `#[cfg(feature="testing")]`) and `Supervisor::seed_peer_pseudonym`
(`#[cfg(feature="testing")]`). Under test-on/testing-off this is E0599/E0432.

**Why it never fires in practice (the mask):** scp-runtime dev-deps `scp-testing`
(Cargo.toml:116), which depends on `scp-core {testing}` (scp-testing/Cargo.toml:20),
and `scp-core/testing = ["scp-runtime/testing"]` (scp-core/Cargo.toml:16). Cargo feature
unification pulls dev-dep features into the lib-under-test, so `scp-runtime/testing` is
ALWAYS on for any `cargo test -p scp-runtime` / `--all-targets`. Verified empirically:
plain `cargo test -p scp-runtime --lib --no-run` (no `--features`) yields a binary with
all 32 `spawn_from_welcome_tests::*` tests present. Coverage NOT lost by the #2093 fix.

**Fix a5755bcdd gated only ONE instance** (spawn_from_welcome_tests.rs via inner
`#![cfg(feature="testing")]`). The SAME testing-ungated `#[cfg(test)]` pattern remains in
≥5 siblings in the same crate:
- context/supervisor/supervisor.rs:25679 (inline `mod tests` @15744-30030, `#[cfg(test)]` only)
- crypto/agent_binding_tests.rs:20
- crypto/mls/wrapping_extension_runtime_tests.rs:57,138
- crypto/mls/two_party_test_support.rs:40
- context/agent_binding_pipeline_tests.rs:764 (seed_peer_pseudonym)

So the commit's stated goal "make `cargo build -p scp-runtime --all-targets` compile under
testing-off" is NOT achieved crate-wide; 5+ files still E0599 in that hypothetical.
LOW severity: not a regression, not reachable (mask). Directional nit: the per-file
`#![cfg(feature=testing)]` converts a would-be LOUD E0599 into SILENT test-vanishing if the
mask ever breaks; the 5 un-gated siblings fail loud instead.

## REVISED FIX 9095edfd1 (branch fix/2093-spawn-welcome-cfg-gate) — CLEAN, 0 defects
Reverts the per-file gate (both test files now byte-identical to origin/main; net diff vs
main = ONLY lib.rs) and adds ONE crate-level tripwire at scp-runtime/src/lib.rs:24:
`#[cfg(all(test, not(feature="testing")))] compile_error!(...)`. This is the RIGHT fix — one
loud, non-enumerating site covering all 6+ modules; no silent test-vanish.
Verified empirically (worktree scp-wt-2093, resolver="2"):
- cfg logic correct on all 4 axes: (a) normal `cargo build -p scp-runtime` compiles clean
  (cfg(test) off → silent; resolver2 also keeps dev-dep `testing` de-unified in non-test build);
  (b/c) `cargo test -p scp-runtime --lib --no-run` compiles clean (dev-dep mask keeps testing ON
  → not(testing) false → silent, no E0599); (d) only test+testing-off trips.
- Non-vacuity PROVEN via minimal rustc repro: `rustc --test` w/ feature off → "compile_error"
  fires; plain `rustc` (no --test) → does NOT fire. `compile_error!` in item position + outer
  `#[cfg]` is valid Rust (std macro, expansion-time).
- cfg(test) for a crate-level lib.rs item is set ONLY when rustc compiles the lib's OWN unit-test
  harness (--test) — NOT for examples/benches/integration-tests (lib compiled normally there).
  That is EXACTLY the compilation where the E0599 modules live → perfect alignment, no spurious
  fire/miss under --all-targets.
- No real green CI/dev lane broken: testing is always satisfied when scp-runtime's test target
  builds today (dev-dep scp-testing→scp-core{testing}→scp-runtime/testing).
- Minor (not a defect): in the severed-mask hypothetical, compile_error (expansion) AND E0599
  (typeck) both surface, but the clear message is guaranteed present — as intended.
