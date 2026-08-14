---
name: perm-code-allowlist-vs-typecatch-parity
description: Why TS trust Layer-1 absorbs PERM-3001 by message-prefix while Python catches UcanError by type — correct-per-bridge, not a parity bug
metadata:
  type: project
---

PR #1867 (`fix/sdk-coverage-fail-closed-and-parity`) Layer-1 trust signal: TS `evaluateLayer1`/`validateOneCapUri` absorbs ONLY `[SCP-PERM-3001]` (message-prefix regex) and re-throws all other codes; Python `evaluate_trust` catches `bridge.UcanError` BY TYPE then explicitly re-raises only `[SCP-PERM-3030]`. These look asymmetric but are correct on each SDK's reachable surface.

**Why:**
- `crates/scp-ffi/common/src/ucan_errors.rs::ucan_error_code` maps EVERY `UcanError` variant → `PERM_3001` (exhaustive match, deliberate; planned future splits TokenExpired→3007, TokenRevoked→3008 held back). So on the native validate path only PERM-3001 + PERM-3030 surface.
- PERM-3000 ("generic permission") has active producers ONLY in the WASM bridge (`crates/scp-ffi/wasm/src/ucan.rs`, `manager.rs`). TS reaches WASM via fallback; Python NEVER uses WASM. So PERM-3000 is reachable in TS (correctly re-thrown — manager failure ≠ a UCAN self-consistency verdict) and unreachable in Python.
- In PyO3, `error.rs::From<ContextError>` routes ALL `SCP-PERM-*` codes from `PermissionDenied(msg)` → `ScpPyError::UcanError` → Python `UcanPermissionError`. So Python's type-catch catches 3000/3001/3030 alike; the explicit 3030 re-raise is the only manual guard needed.

**How to apply:** Do NOT flag this as a cross-SDK parity defect. The closed-allowlist (TS) is the more robust long-term shape: a future PERM-code split would be correctly re-thrown by TS but SILENTLY ABSORBED by Python's type-catch. That is a latent Python fragility worth a one-line note in `trust.py` IF/WHEN the ucan_errors split lands. Message preservation: `errors.ts::mapBridgeError` keeps `.message` verbatim (extracts code only for class selection), so prefix-based re-classification in trust.ts is sound. See [[ts-python-trust-parity]], [[sdk_failclosed_parity_614f0eb17]].

**Latent API misuse gap (LOW):** `CapabilityValidation.withinCeiling===true` means token self-consistency vs its OWN declared `att[i].with`, NOT authority-for-action. Distinction lives only in doc prose on `evaluateLayer1`/`evaluate_trust`; field naming invites misread. Authority path = call `scp.ucanValidate(handle, token, uri)` directly. Follow-up candidate: field rename or `selfConsistencyOnly` marker.
