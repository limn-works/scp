---
name: check-scripts-need-cargo-target-dir
description: scripts/check-*.sh spawn their own cargo, so CARGO_TARGET_DIR must be exported for them too — otherwise the shared-target poison reports bogus compile errors as gate failures
metadata:
  type: feedback
---

When running the local CI gate in a worktree, `export CARGO_TARGET_DIR=<isolated dir>`
applies to **every** step that shells out to cargo — not just the direct
`cargo clippy` / `cargo nextest` invocations. Several `scripts/check-*.sh`
(confirmed: `check-pure-helpers.sh`, which runs a `cargo test` behind a
structural conformance test) spawn cargo themselves and inherit the shared
`~/.cargo/shared-target` from `~/.cargo/config.toml` if the variable is not
exported in that shell.

**Why:** the shared target dir is poisoned by the stale main checkout, so the
script fails with compile errors against an API that does not exist in the
worktree source (`ContextError::Outlet`, `ContextError::OutletContextNotActive`,
`CODE_EXECUTION_STREAM_CAP`, …). These look like real gate failures and invite a
wild-goose chase or, worse, a "fix" to correct code.

**How to apply:** export `CARGO_TARGET_DIR` once at the top of the gate run and
keep it exported through the check-script sweep, the rustdoc build, and the
`git commit` that triggers the pre-commit clippy hook. If a check script fails
with an error naming a symbol you never touched, re-run it with the isolated
target dir before believing it. Never `--no-verify`.

Related: [[feedback-worktree-absolute-path]], [[feedback-read-tool-stale-verify-with-awk]].
