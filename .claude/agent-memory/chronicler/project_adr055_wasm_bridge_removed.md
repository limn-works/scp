---
name: adr055-wasm-bridge-removed
description: WASM bridge fully removed on main (ADR-055 supersedes ADR-034); TS SDK is napi-only — there are now THREE FFI bridges, not four
metadata:
  type: project
---

The WASM bridge was fully removed from `main`. `ADR-055 supersedes ADR-034`.

- Commits: `1a3b41a5e` ("remove the WASM bridge — Slice 1 foundation, ADR-055 supersedes ADR-034", #1934) and `9f4062693` ("make TypeScript SDK NAPI-only; remove in-browser WASM backend", #1942).
- `crates/scp-ffi/wasm/src/` is gone (only generated `pkg-node/` build artifacts linger). `bindings/typescript/src/internal/wasm.ts` is gone. No `real-wasm` test file.
- TS SDK is napi-only: `BRIDGE_TARGET = "native"` in `bindings/typescript/src/internal/bridge.ts`; `wrapBridgeErrors` wraps only the native factory.

**Why:** ADR-034 (WASM constrained re-impl) was retired; the in-browser backend was dropped.

**How to apply:** There are now THREE FFI bridges — PyO3, NAPI, UniFFI — NOT four. When reviewing new ADRs/specs/PRDs, flag any "all four bridges", "NAPI/WASM serde projection", references to `crates/scp-ffi/wasm/src/*`, `internal/wasm.ts`, `real-wasm` tests, or "WASM native-only (ADR-034)" as STALE. Cite ADR-055. Many of my older memories that say "WASM N/A (no Supervisor, ADR-034)" are now superseded — WASM doesn't exist at all.

This caused a finding cluster on branch `c3c-ts-work` (ADR-057 + SCP-302/SCP-303 + pipeline_wiring.rs:159 were authored against the pre-removal four-bridge worldview).
