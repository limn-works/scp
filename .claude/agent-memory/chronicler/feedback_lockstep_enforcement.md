---
name: Lockstep enforcement of bridge matrix and WASM ratchet
description: When promoting or demoting wasm_required entries, edit bridge-aliases.json and WASM_REQUIRED_OPERATIONS atomically — a test enforces equality
type: feedback
---

When extending the bridge-symmetry matrix's `wasm_required` entries, edit both `scripts/bridge-aliases.json` AND `WASM_REQUIRED_OPERATIONS` in `crates/scp-testing/tests/integration/ffi_conformance.rs` atomically in the same commit.

**Why:** The `aliases_json_is_in_sync_with_parity_operations` test in `ffi_conformance.rs` asserts that the set of ops with `"wasm_required": true` in the JSON matrix equals the `WASM_REQUIRED_OPERATIONS` Rust constant. Editing one without the other breaks the test and silently weakens enforcement — the JSON and the constant are a single logical artifact split across two files for tooling reasons. PR #1703 (Batch 2 of #1543, 2026-04-25) promoted 33 ops in lockstep and validated the pattern.

**How to apply:** Any PR that adds, removes, or flips a `wasm_required:true` entry MUST include both edits. Workflow: flip the JSON value, add (or remove) the op name in the Rust array, run the conformance test until green. If only one of the two appears in the diff, the PR is incomplete — request the missing edit before merge. The lesson in `.docs/lessons/cross-bridge-canonical-naming.md` documents this under "Lockstep enforcement: matrix and ratchet must move together."
