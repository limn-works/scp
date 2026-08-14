---
name: wasm-cut-slice5-review
description: Slice 5 (chore/cut-wasm-stray-refs) WASM-bridge removal completeness review — INCOMPLETE, ~300 stray doc-comment refs remain
metadata:
  type: project
---

# WASM bridge removal (ADR-055) — Slice 5 stray-ref review

Reviewed branch `chore/cut-wasm-stray-refs` worktree `.claude/worktrees/cut-wasm-5`
@ `d9d8b8504` (commits `23653e2b5` + `d9d8b8504`). **Verdict: INCOMPLETE.**

**Why:** ADR-055 deletes the WASM FFI bridge (browser → remote thin client).
The crate/build/CI/gate-fixture/capability-matrix/TS-SDK-runtime surface is CLEAN.
But Slice 5's commit `23653e2b5` ("remove stray scp-ffi-wasm references in code
doc-comments") was a PARTIAL pass — it edited ~13 files but left the SAME CLASS of
reference ("the WASM bridge does X / native↔WASM parity / non-WASM bridges /
PyO3·NAPI·UniFFI·WASM 4-bridge enumeration") in ~300 lines across the live surface.
Files it DID edit (`consequence.rs`, `system_actors.rs`, `payload.rs`) still have
WASM refs left → proves misses, not deliberate LEGIT-REMAIN.

**How to apply (where the misses live, for a re-check):**
- `crates/scp-ffi/common/` — UNTOUCHED by slice; ~70 stray lines incl. Cargo.toml
  package `description` listing "(PyO3, napi-rs, UniFFI, WASM)" + "four FFI bridges"
  comment + all `*.rs` "non-WASM bridges"/"Not available for WASM" docs +
  `validate.rs:33` cites deleted `ScpWasmError`.
- `scp-protocol/src/trust/consequence.rs` (12 lines left), `context/mod.rs`, others.
- `scp-event-log/` (~22 lines, "native↔WASM parity/unification").
- `scp-runtime/` (~40 lines; `export_import.rs:74` `WASM_EXPORT_VERSION` + test
  `..._matches_wasm`; ttl/governance/mls/provider).
- Surviving bridges `scp-ffi/src`(PyO3)/`napi`/`uniffi/bridge.rs` + `scp-ffi/CLAUDE.md:125`.
- SDK docs: Swift `ScpBindings.swift`, python `scp_sdk/server.py:17`, parity
  `seed_operations.py`/swift+kotlin runners (note: `node_bridge_runner.ts` is LEGIT —
  correctly says "removed per ADR-055").
- DEV-FACING (highest user impact): `bindings/typescript/README.md:5,46` ("Dual-target
  browser WASM"), `scaffolds/typescript-web/*` + `templates/chat/typescript/*` (browser
  scaffolds importing a WASM backend the NAPI-only SDK no longer has → broken-by-
  construction), `docs/examples/typescript/README.md:65` (cites deleted
  `crates/scp-ffi/wasm/`), `docs/guides/sdk-quickstart.md`, `README.md:66`,
  `GETTING-STARTED.md:97,105`.
- `.docs/specs/09,10,11,25` normative remnants belong to Slice-4 / PR #1945 (the
  in-branch docs commit `29b87c8a5` cleaned 05/17/18/23 but not these).

**LEGIT-REMAIN (do not touch):** scp-protocol wasm32 compat check (ci.yml
`wasm-protocol`, `.cargo/config.toml` getrandom_backend, `.mise.toml`);
`scp-transport/src/webtransport/*` + `webtransport-wasm` feature (surviving transport);
`node_bridge_runner.ts` ("removed per ADR-055"); historical `.docs/adrs|lessons|audits|
planning-sessions` + `.claude/agent-memory|agents`; `specs/05:192` WASM deployment-
artifact hashing (a compiled binary, not the bridge).

Fix convention (already used by the slice in its partial edits): drop the WASM
enumeration / reword "non-WASM bridges" → "all FFI bridges", "native↔WASM parity" →
"byte-identical across all honest members".
