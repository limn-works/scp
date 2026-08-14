---
name: pr1867-sdk-trust-parity
description: Black-hat findings on PR #1867 SDK trust evaluation Layer 1 multi-att + PERM-3001 allowlist
metadata:
  type: project
---

# PR #1867 — SDK coverage fail-closed + trust parity

Branch `fix/sdk-coverage-fail-closed-and-parity`, HEAD c0bee8d22. TS `bindings/typescript/src/trust.ts`, Python `bindings/python/scp_sdk/trust.py`.

## KEY FACT: ceiling step only checks the passed-in capability
`crates/scp-protocol/src/crypto/ucan/validate.rs:591` — step 8 runs `verify_ceiling_compliance(std::slice::from_ref(required_capability), ...)`. It checks ONLY the single capUri passed to `ucan_validate`, NOT the token's full `att` array. Step 6 (`check_capability_match`) only verifies att INCLUDES required_cap. So the SDK's per-att loop is the ONLY thing enforcing ceiling over all att entries. This makes `__extractAllCapabilityUris` load-bearing for authorization.

## FINDING (MEDIUM): cross-att fail-fast masks later att ceiling violations
`evaluateLayer1` (TS) / `_evaluate_layer1` (Py) break on the FIRST failing att URI. Pipeline order is ceiling(8) BEFORE expiry(11)/nonce(9)/revocation(10). If att[0] is in-ceiling but fails at a LATER stage (expired/revoked/nonce), the loop narrows on att[0] and NEVER checks att[1]. If att[1] is out-of-ceiling, `withinCeiling` is reported TRUE (from att[0]'s narrowing) — masking att[1]'s ceiling violation. This defeats the exact guarantee the PR added (att[1] ceiling test at trust.test.ts:499 only passes because att[0] fully succeeds). Fix: don't fail-fast across att entries — validate ALL att URIs and AND-merge the narrowed results (intersection of passed sets), or at minimum continue checking remaining att even after a non-ceiling failure.

## CONFIRMED SOUND
- PERM-3001 allowlist: ALL UcanError variants map to PERM_3001 (ucan_errors.rs exhaustive match), incl InvalidCapabilityUri. NAPI parse failure for "*" explicitly sets code PERM_3001 (napi/src/ucan.rs:215). So "*"/unparseable → absorbed → all-false. Correct.
- PERM-3030 (handle-affinity) + PERM-3000 (WASM mgr) now re-thrown both SDKs. Tested.
- Empty-string `with`: Python `isinstance(...,str) and entry["with"]` excludes "" (verified). TS `.filter(uri !== "")` excludes "". Both correct.
- SDK/bridge base64 divergence is fail-closed: bridge re-parses own att for step-6 inclusion; SDK-passed URI not in bridge att → step 6 rejects. Not exploitable.
- Coverage gate: total_ops==0 floor guard + all-exempted check (≥1 SDK must be statically verified) — closed positive verification, resists "all exempt = fake coverage".

## FINDING (LOW/INFO): non-UCAN error aborts evaluateTrust
att[i].with with HTML-special char (<,>,&,",') or >1024 chars passes `__extractAllCapabilityUris` but fails FFI `validate_capability_uri` → SCP-VALID-7xxx → re-thrown (not absorbed). Attacker-supplied token makes evaluateTrust THROW instead of fail-closed all-false. This is INTENTIONAL + TESTED (trust.test.ts:621 asserts SCP-VALID propagates). Fail-safe (no false trust granted), but a batch caller can have one malformed token abort the batch. Documented contract; note only.
