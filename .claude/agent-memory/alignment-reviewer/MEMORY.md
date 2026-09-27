# Alignment Reviewer Memory

- [Two-dot diff on a stale branch shows phantom deletions](feedback_two_dot_diff_stale_base_trap.md) — confirm the merge base and read the three-dot diff before flagging any deletion.

## Checks that found real misalignment in past reviews
- **Verify against the plan text, not the branch name or PR title.** A branch named for a demolition had shipped only the additive half. Count what the plan says to remove: for the SDK façade, the `#[pyfunction]`, `#[napi]`, and `#[uniffi::export]` free-function counts.
- **When a planning document conflicts with a later binding decision, check that the code followed the binding one.** An execution plan said to convert `ArcSwap` to `tokio` locks; a later architecture decision rejected that, and the correct implementation kept `ArcSwap`.
- **A test file outside the build graph compiles clean because it is never built.** Cargo auto-discovers only `tests/*.rs` and `tests/*/main.rs`, so a file under `crates/scp-testing/tests/integration/` compiles only when a `[[test]]` entry in `Cargo.toml` or a `mod` declaration in a compiled entry point names it; one unnamed file held 19 references to deleted symbols. For a "keep and rewire" item, confirm the target is registered.
- **`#[allow(dead_code)]` on a field that is clearly used is usually stale.** Remove the annotation and run clippy to find out.
- **A rewrite updates the code and the adjacent rustdoc but leaves a second comment block elsewhere in the same function describing the old model,** and a mechanical sweep of markdown links misses prose such as "attached manager" or "shim". Grep the retired term across the whole file.
- **A spec reclassification is usually missed in the API-surface summary,** which restates the property in passing far from the section the editor changed. Grep the whole spec file for the property and the type name.
- **A Python wrapper that calls a bridge function that does not exist still imports cleanly** (attribute lookup happens at call time). Check each wrapper call against the bridge's module registration.
- **A mock-based "integration" test validates SDK logic only.** Check what the mock replaces before crediting a story whose acceptance criterion is end-to-end.
- **ADR pseudocode drifts from implementation** in method names, dependency versions, and artifact IDs; verify the code, then decide which side is wrong under the one-way artifact flow.
