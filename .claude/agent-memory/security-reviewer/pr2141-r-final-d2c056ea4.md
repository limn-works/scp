---
name: pr2141-r-final-d2c056ea4
description: PR #2141 fix/sdk-coverage-fail-closed-and-parity @ d2c056ea4 — final security pass, CLEAN (0 CRITICAL/HIGH/MEDIUM)
metadata:
  type: project
---

# PR #2141 @ d2c056ea4 (2026-08-01) — SECURE, 0 blocking

Delta since prior rounds = commits a20eb5314, 28623a226, 95bf99be4, 40a7a8eca, 76bbeabfc, e9adb42a2, d2c056ea4. Diff-vs-main includes large merge-base noise (scp-client-wasm/scp-mls/scp-platform/scp-runtime store refactors) OUT of this PR's scope; reviewed only the SDK error/gate slice.

**Why clean (all 5 security-focus questions answered):**
- `_coded_bridge_error` MOVED trust.py→errors.py; regex now ANCHORED `^\s*\[(SCP-[A-Z]+-\d+)\]` (was unanchored `\[(SCP-...)\]`). New message-strip `raw_msg[match.end():].lstrip()` avoids double-bracket via ScpError.__str__; code=None → _default_code SCP-UNKNOWN-0000 (never "[None]").
- TS `mapBridgeError` anchor+SCP-literal `^\s*\[(SCP-[A-Z]+-\d+)\]` (was BROAD `[A-Z]+-[A-Z]+-\d+`). Class-selection driven by anchor-extracted `code`, not body → body-injected `[SCP-PERM-3001]` can't masquerade. `instanceof ScpError` passthrough (no downgrade); generic ScpError fallback (no misclassify). Bridges emit code at pos 0 (napi/pyo3 Display) → zero legit-code loss.
- 5 identity key-mut methods + contextSend/governancePropose/outletInvoke/ucanValidate migrated to getBridge(this) → wrapBridgeErrors Proxy (native.rs:2127) applies mapBridgeError to sync throw + async reject; handles NOT deep-proxied (sync return passthrough). outlets.py `_translate_bridge_error` (code-omitting) DELETED → `_coded_bridge_error` at 4 sites (strict improvement).
- Coverage gate: `_extract_python_*` now excludes `_`-prefixed names (private/dunder) — MONOTONIC fail-closed (shrinks symbol set → only more failures). Grep-verified ZERO ALIASES target a `_`-symbol → no legit symbol dropped. Bridge/register ALIAS comment change honest: matrix now ts=True, `bridgeRegister` matched by domain_camel auto-candidate (stricter, requires the TS symbol). New scripts/test_check_sdk_coverage.py = comprehensive fail-closed self-test (unmatched-true, missing-sdk-key, all-exempted-none-verified, malformed-json all assert FAIL).
- No leak: bridge Display = UCAN/context diagnostics, no key bytes/secrets. Codes are caller-branchable by design. No NEW info beyond prior str(exc)/error.message.
- test-guard.ts `__setBridgeForTests` fail-closed frozen (`_IS_TEST_ENVIRONMENT` at module load, Object.hasOwn defeats proto-pollution, runtime env-mutation can't flip); contained 4 layers (not re-exported, exports-map blocks deep import, files:[dist/], DCE). NODE_ENV=development allowance local-only.
- `except Exception as exc: raise _coded_bridge_error(exc) from exc` never swallows: CancelledError is BaseException (not caught) → cancellation propagates. `__exit__/__aexit__` `del exc_type,exc,tb` returns None → exceptions NOT suppressed.

**INFO only (non-security):** Py strips `[code]` prefix from stored .message; TS keeps it inline. Cosmetic cross-SDK inconsistency, no leak/injection. contextMemberCount `?? 0` masks bridge null→0 (display only, membership is cryptographic). economy_verify_payment_receipts unwrapped (docstring warns check valid/all_valid not ok).
