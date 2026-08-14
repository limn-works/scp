---
name: sdk-failclosed-parity-614f0eb17
description: API review of fix/sdk-coverage-fail-closed-and-parity @614f0eb17 — TS ucanValidate/eventLogQuery now wrapped, ADR-053 PreRotationCustodyProvider interface, trust.ts classification
metadata:
  type: project
---

# fix/sdk-coverage-fail-closed-and-parity @614f0eb17 — APPROVED

HEAD commit wraps the last two TS SCP methods (`ucanValidate`, `eventLogQuery`) in `mapBridgeError`, completing the uniform typed-error surface. All 203 throwing async methods in scp.ts now route through `mapBridgeError`; 0 async native-touching methods unwrapped (verified by AST-ish scan).

**Load-bearing contract:** trust.ts `evaluateTrust` classifies UCAN/context failures by regex `^\[SCP-PERM-\d+\]` / `^\[SCP-CTX-\d+\]` on `error.message`. `mapBridgeError` preserves the bridge message VERBATIM in `.message` (only re-types the class), so prefix classification + PERM-3030 re-raise survive the wrapping. Tests assert `message).toBe(message)` verbatim — locks the contract.

**Cross-binding error-surface architecture (intentional divergence, NOT a defect):**
- Python: typed errors raised at the PyO3 BRIDGE layer (native raises `_scp_core.UcanError`/`ContextError`); SDK `ucan_validate`/`event_log_query` are bare delegations, no try/except.
- TypeScript: NAPI/WASM throw plain `Error` w/ bracketed code string → typed at SDK WRAPPER layer via `mapBridgeError`.
- Both reach typed `ScpError` subclasses; different layer, same observable surface.

**Minor doc inaccuracy (non-blocking):** trust.ts comments say classification "mirrors the Python port's code-based dispatch" — Python's PRIMARY dispatch is actually `except bridge.UcanError`/`except ContextError` (instanceof), with code-prefix check ONLY for the PERM-3030 re-raise. Behaviorally equivalent; comment overstates the structural parallel.

**ADR-053 PreRotationCustodyProvider** (now a STANDALONE file `.docs/adrs/ADR-053-pre-rotation-custody-substrate-isolation.md`, no longer `## ADR-053` in phase-N): 4-method flat interface (`generate`, `public_key`, `import_seed_bytes`, `consume`), no typestate, per-binding casing table locked. Agent-first compliant. Separate-provider-not-new-methods is the structural mechanism enforcing spec §9.7.4.1 §3 substrate isolation. Handle single-use invariant enforced adapter-side in Rust (`CallbackPreRotationCustody` invalidates after consume regardless of foreign success). Status: Proposed (3 open questions: WASM scope, backend floor, spec clause).

`__classifyUcanError`/`__extractCoreError` exported from trust.ts for tests but NOT re-exported from index.ts — internal, fine.
