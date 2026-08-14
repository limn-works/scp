---
name: pr1867-valid-absorb-ucan-option-3ea854ff3
description: PR #1867 @3ea854ff3 crypto review — VALID-* absorption + validate_tool_ucan_wasm Option-drop; APPROVE no blocking, 1 LOW stale Python lesson-doc example
metadata:
  type: project
---

# PR #1867 fix/sdk-coverage-fail-closed-and-parity @3ea854ff3

Crypto review (5 questions). VERDICT: SOUND / APPROVE, no blocking crypto findings. One LOW doc-accuracy defect.

**Why:** branch hardens trust Layer 1 fail-closed + cross-bridge UCAN error parity.
**How to apply:** if revisited, the absorption logic is closed-allowlist correct; only the lesson-doc Python snippet needs fixing.

## Findings
1. `validate_tool_ucan_wasm` return `Option<&'static str>` → `&'static str` (tools.rs drops `code.unwrap_or(PERM_3000)`). 11-step pipeline INTACT — `run_validate_ucan` still calls `validate_ucan(token, cap, &mut ctx)?` at ucan.rs:381 unchanged; diff only changed error-mapping String→UcanError so all branches route through `ucan_error_code` → PERM-3001 (was: non-parse branches returned None→PERM_3000). Net: stricter/consistent classification, no pipeline change. SOUND.

2. VALID-* absorption in `validateOneCapUri`/`evaluateLayer1` (trust.ts) → all-false. Cannot avoid sig verification: VALID-* is a FAIL-CLOSED (all-false) verdict; a PASSING verdict is only producible via `null` return = `scp.ucanValidate` SUCCESS = full 11-step incl Ed25519 sig. `validate_ucan` pipeline NEVER emits VALID-* (only UcanError→PERM); VALID-* is exclusively the NAPI boundary `validate_capability_uri` rejection (empty/>1024/control/HTML-special) at napi/ucan.rs:202, BEFORE parse_ucan(209) + with_context/validate_ucan(237-263). SOUND. TS+Python in lockstep (py trust.py:866-881 same VALID-* → all-false, else raise).

3. lesson doc `.docs/lessons/ucan-validate-needs-real-capability-uri.md`: TS side CORRECT (line 19 `__extractFirstCapabilityUri`, `string | null`). **LOW**: Python example lines 26-31 STALE — shows `_extract_all_capability_uris` (plural, list, `cap_uris[0]`) but actual code = `_extract_first_capability_uri` returning `str | None` (trust.py:155/826). Doc-only.

4. `ucan_error_code` (common/ucan_errors.rs): exhaustive match, NO wildcard, UNCHANGED by PR. SOUND.

5. Nonce: VALID-* fires at NAPI boundary BEFORE nonce tracker reached → nonce NOT consumed on absorbed VALID-*. WASM writeback `ucan_record_nonce` (ucan.rs:387) guarded by `validated_nonce.is_some()` (set only in record()/step9) — unchanged. Nonce-at-step9-before-revocation(10)/expiry(11) is PRE-EXISTING single-call semantic, NOT altered by PR.
