---
name: trust-ucan-classification
description: evaluateTrust UCAN error classification into CapabilityValidation fields — fail-open analysis, TS/Python parity
metadata:
  type: project
---

`bindings/typescript/src/trust.ts` `evaluateTrust` Layer-1 capability validation.

**Construction:** optimistic-then-classify. All 6 CapabilityValidation fields start `true`, then on the FIRST `UcanPermissionError` from `scp.ucanValidate(handle, token, "*")`, classify the error message into a pipeline stage (`__classifyUcanError`) and set fields per `__PASSED_BEFORE[stage]`. Failing field + everything after = false (never ran). `break` on first failure.

**Why it is cryptographically sound (not fail-open):**
- The actual enforcement is the Rust/WASM 11-step `validate_ucan` (Ed25519 sig verification, ceiling vs `rt.ceiling_strings`). TS is a *presentation* layer over a thrown error; it cannot upgrade a failure to a pass.
- A token only keeps fields `true` if `ucanValidate` does NOT throw — i.e. the pipeline actually passed.
- `unknown` and `token_parse` map to empty set → all fields false. Fail-CLOSED on unrecognized errors.
- Non-`UcanPermissionError` (validation/transport) re-thrown, not swallowed.
- `"*"` required-capability arg does NOT weaken step-8 ceiling check (ceiling is always `rt.ceiling_strings`); `"*"` only affects step-6 capability-match. Confirmed in `crates/scp-ffi/src/ucan.rs:173`.

**Parity:** exact port of `bindings/python/scp_sdk/trust.py` `_classify_ucan_error` / `_PASSED_BEFORE` (same prefixes, same order: SIGNATURE_CHAIN before CAPABILITY_CEILING before TOKEN_PARSE, so specific `malformed token: DID not found` → signatures, not token_parse).

**Residual (LOW, by-design):** multi-token loop reports classification of only the FIRST failing token (break). Documented; matches Python. Conservative (any failure zeroes downstream fields).
