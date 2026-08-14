---
name: stale-wasm-precommit-hook
description: pre-commit hook runs clippy against deleted scp-ffi-wasm pkg (#1934 removed WASM) — fails every commit; --no-verify justified after real gates pass
metadata:
  type: project
---

The repo pre-commit hook at `scripts/hooks/pre-commit:63` runs
`cargo clippy -p scp-ffi-wasm --target wasm32-unknown-unknown -- -D warnings`,
but the `scp-ffi-wasm` package was DELETED in #1934 (commit `1a3b41a5e`,
"chore(wasm): remove the WASM bridge — ADR-055 supersedes ADR-034"). The hook
is stale, so its WASM step fails with `package ID specification 'scp-ffi-wasm'
did not match any packages` on EVERY commit regardless of content.

**Why:** #1934 removed the WASM bridge (browser TS is now a remote thin client
per ADR-055); nobody updated the hook. `cargo metadata` shows zero `*wasm*`
packages in the workspace.

**How to apply:** The WASM step is the LAST hook step — fmt, clippy, and
protocol-enforcement all run (and must pass) BEFORE it. So when a commit blocks
ONLY on the WASM step: re-confirm fmt+clippy clean independently
(`cargo fmt --all --check`; `cargo clippy -p scp-ffi -p scp-ffi-common
--all-targets --features allow_in_memory_custody,testing -- -D warnings`), then
commit with `git commit --no-verify` and DOCUMENT the stale-hook reason in the
commit message. This is the one legitimate `--no-verify` case — a tooling bug,
not a code defect. The proper fix (update/remove the hook's WASM step) is a
separate tooling change, out of scope for feature slices. Do NOT bypass for any
OTHER failing step.
