---
name: pr1867-trust-ucan-parity
description: Security review of PR #1867 — TS/Python trust Layer-1 UCAN classification, WASM error-code parity, att[0]-only limitation, test-env gate
metadata:
  type: project
---

PR #1867 (`fix/sdk-coverage-fail-closed-and-parity`, HEAD `205966ced`) security review — PASSED, no CRITICAL/HIGH/MEDIUM.

**Why:** SDK coverage gate fail-closed + cross-SDK trust-layer parity. Reverted the broken multi-att AND-intersection (commit `8909092eb`) back to att[0]-only.

**How to apply (security-relevant invariants to preserve on future trust/UCAN changes):**

- **att[0]-only Layer 1 is deliberate, documented.** `evaluateLayer1` (TS `bindings/typescript/src/trust.ts`) and Python equivalent validate only `att[0].with`. Multi-att AND-intersection is BROKEN because each `ucanValidate` call consumes the nonce → att[1..] always `NonceReused`. Residual risk (documented): out-of-ceiling `att[1]` yields `withinCeiling: true`. Acceptable because SCP production mints single-att tokens, and `evaluateTrust` is an inputs-provider not an authorizer (per-op authority needs direct `scp.ucanValidate(handle, token, caller-uri)`). Documented in `.docs/lessons/ucan-validate-needs-real-capability-uri.md` §Multi-att limitation.

- **PERM-3001 closed allowlist (fail-closed).** `validateOneCapUri` absorbs ONLY `^\[SCP-PERM-3001\]`; re-throws PERM-3000 (WASM mgr), PERM-3030 (handle-affinity), and any future code. Correct direction. PERM-3001 is the one code every UcanError variant maps to.

- **`ucan_error_code` (`crates/scp-ffi/common/src/ucan_errors.rs`) is the single-point-of-change UCAN→code map for ALL 4 bridges.** Exhaustive match, NO wildcard (only `_ =>` mentions are in comments warning against it). New UcanError variant = compile error until classified. WASM `validate_tool_ucan_wasm` was fixed in this PR to route through it (was dropping code as `None`).

- **Test-env gate (`bindings/typescript/src/internal/test-guard.ts`) is sound:** reads process.env ONCE at module load (frozen `_IS_TEST_ENVIRONMENT`), `Object.hasOwn` blocks prototype-pollution, fail-closed. Primary boundary = tsup DCE + package.json exports map; env guard is defense-in-depth.

- **`mapBridgeError` (errors.ts) re-types by `[SCP-CAT-NNNN]` prefix, preserves message verbatim** (prefix stays at position 0). Both NAPI+WASM use `[{code}] permission error: {message}` for Permission variant (errors.ts:208 comment slightly oversimplifies WASM format but logic is correct).
