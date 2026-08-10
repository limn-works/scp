---
name: project-2028-2029-welcome-ceiling-followups
description: Testing traps hit while fixing the #2028/#2029 Welcome-seam branch — the cfg-disabled persistence integration file, and why production `cfg!(testing)` branches are untestable in the CI lane
metadata:
  type: project
---

Two repo-level testing facts that cost real time on the `fix/2028-f5-welcome-join-ceiling`
branch. Both are still true as of 2026-08-08; re-verify before relying on them.

**1. `crates/scp-testing/tests/integration/persistence.rs` is dead.** Its first
non-comment line is `#![cfg(any())]` (ADR-049 §15 deleted `ContextCryptoProvider`;
the file was gated off pending rewire). It is a registered `[[test]]` target in
`crates/scp-testing/Cargo.toml`, so `cargo test -p scp-testing --test persistence`
compiles and reports "running 0 tests" — it looks live. Its contents do not even
type-check (e.g. `persistence.load_context(id).unwrap()` on an `#[async_trait]`
method). Do NOT add restore/persistence regressions there. Live homes:
`crates/scp-runtime/src/context/supervisor/supervisor.rs` `mod tests`
(`MapPersistence` + `import_test_snapshot` + `supervisor_with_clock_and_persistence`)
and `crates/scp-testing/tests/integration/persistence_advanced.rs`.

**Why:** a dead-but-registered test target reads as coverage that does not exist,
and a regression written into it silently never runs.

**How to apply:** before adding a test to any `crates/scp-testing/tests/integration/*.rs`,
check the file head for `#![cfg(any())]`, and confirm the target actually runs your
test by name.

**2. A production branch guarded by `cfg!(any(test, feature = "testing"))` cannot be
exercised by the workspace test lane.** CI's nextest command enables
`scp-runtime/testing` (and the other `*/testing` features) workspace-wide, so those
`cfg!` checks are TRUE in every test build — the production-only arm is unreachable
from any test. `execute_add_member` and `execute_reset_member` both have this shape
for their "no MLS KeyPackage in production" refusal.

**Why:** writing a test for the production refusal is wasted effort; the mutation
signal has to come from an UNCONDITIONAL sibling branch instead.

**How to apply:** to make such a guard mutation-testable, assert on a branch that is
not cfg-gated — e.g. the KeyPackage credential-DID binding, which fires for
`Some(bytes)` regardless of features. A deleted guard then changes the error variant
or lets the operation succeed, which a test can see.

Related: [[feedback-worktree-absolute-path]], [[feedback-read-tool-stale-verify-with-awk]]
