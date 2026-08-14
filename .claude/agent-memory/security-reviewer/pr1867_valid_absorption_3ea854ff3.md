---
name: pr1867-valid-absorption-3ea854ff3
description: PR#1867 VALID-* absorption + WASM &'static str + py evaluate_trust root export review at HEAD 3ea854ff3 — security SOUND but 3 real test/lint failures on branch
metadata:
  type: project
---

# PR#1867 fix/sdk-coverage-fail-closed-and-parity @ 3ea854ff3 (2026-06-23)

3 reviewed commits: 1861c3691 (extractFirst rename + py evaluate_trust root export), 785aaf560 (WASM Option<code>→&'static str), 3ea854ff3 (VALID-* absorb in evaluateLayer1).

## Security verdict: SOUND, no privilege gain
- `validateOneCapUri` (trust.ts:450) absorbs `/^\[SCP-VALID-/` → ALL_LAYER1_FIELDS_FALSE. Sound: within ucanValidate path the ONLY VALID emitters are boundary validators validate_ucan_token + validate_capability_uri (both VALID_7000, NAPI ucan.rs:201-202 / WASM ucan.rs:415-420), both = "structurally invalid input grants nothing". All POST-parse pipeline errors map to PERM-3001 via ucan_error_code (never VALID). Folding to all-false = fail-closed, all-false is most-restrictive verdict → no privilege gain. `[SCP-VALID-` at msg position 0 (NAPI Display `[{code}] validation error:`). ucanValidate wraps mapBridgeError (scp.ts:2390) which preserves message verbatim — prefix intact.
- Closed allowlist intact: PERM-3001 absorbed+classified; VALID-* absorbed all-false; PERM-3000/PERM-3030/everything else `throw error` (trust.ts:493).
- Py evaluate_trust (trust.py:848-887): `except bridge.UcanError` FIRST (PERM-3030 startswith re-raise @866-867; others classify); `except Exception` SECOND (only `[SCP-VALID-` → _set_all_false @879; else `raise` @887). PERM-3030 maps to ScpPyError::UcanError (error.rs:730-741) → caught by first handler → re-raised. SOUND.
- ucan_error_code (common/ucan_errors.rs:48): `pub const fn -> &'static str`, EXHAUSTIVE match all UcanError variants, NO wildcard (`_ =>` only in comments). Test `every_mapped_variant_currently_routes_to_perm_3001` passes.
- validate_tool_ucan_wasm (wasm/ucan.rs:562): `Result<(),(String,&'static str)>`, all 3 branches bind code from ucan_error_code (&'static str). tools.rs call sites (513/622/731) destructure (msg,code)+code.to_owned(); dead unwrap_or(PERM_3000) removed. WASM clippy clean.

## BLOCKING: branch does NOT pass full test suite (Q6 premise FALSE)
3 genuine Python failures at HEAD (557 passed, 11 failed, 43 env errors from unbuilt _scp_core):
1. **test_sdk_parity_additions.py::test_evaluate_trust_reraises_perm_3030 FAILS (DID NOT RAISE).** Test passes `capability_tokens=["token.a.b"]` — but _extract_first_capability_uri("token.a.b")=None → evaluate_trust short-circuits all-false at trust.py:843-847 BEFORE the bridge call, so the PERM-3030 side_effect never fires. Regression: test was added at 2b449e8e2 when loop called ucan_validate(...,"*") directly (no extraction); the att[0] extraction refactor (culminating in IN-SCOPE rename 1861c3691) broke it. PERM-3030 re-raise CODE is correct but now UNTESTED in Python. FIX: use _make_mock_token() (real extractable token) like test_trust.py does.
2. **test_falsy_optionals.py lint guard FAILS.** trust.py:180 `first = att[0] if att else None` — falsy IfExp on bare name `att` flagged by check-python-falsy-optionals.py. Line is in IN-SCOPE _extract_first_capability_uri (1861c3691). FIX: add `# falsy-ok: empty list and absent are equivalent` or use explicit length check.
3. **test_ucan_conformance.py::test_operational_errors_classify_as_unknown FAILS.** _REVOCATION_PREFIXES gained "revocation unauthorized:"/"revocation failed:" (commit 62bbf8e41, NOT in 3 reviewed commits) → now classify as 'revoked' not 'unknown'. Pre-existing vs the 3 commits but present on branch HEAD.

TS: trust.test.ts 61/61 pass. Full TS suite 24 fails = ALL IdentityAttestation/transportConnect (need unbuilt .node addon, environmental). WASM clippy clean. ucan_errors test passes.

LESSON: when an extraction/short-circuit guard is added upstream of a bridge call, any test that drives the bridge via side_effect with a token that fails extraction goes silently dead (or DID-NOT-RAISE). Re-run the FULL suite, not just the new tests.
