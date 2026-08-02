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

## fix/sdk-coverage-fail-closed-and-parity (d70c3c272) — APPROVED
- **PERM-3030 re-raise**: trust.py:770 `error_msg.startswith("[SCP-PERM-3030]")` + trust.ts:461 `/^\[SCP-PERM-3030\]/.test(msg)`. BOTH ANCHORED to message start (`^` / startswith) — cannot be spoofed by attacker-controlled error body mid-string. Direction safe: a match RAISES (fail-closed), never grants. Placed after UcanError filter (py) / `^\[SCP-PERM-\d+\]` prefix filter (ts:457, non-PERM re-thrown). SOUND.
- **Citation fix §3.2.1→§9.12**: DidRotationEvent-distribution doc-comments on migrate/identity_migrate/rotation_event_json (DID-CHANGING) moved from "§3.2.1 step 4b"→"§9.12, ADR-003 §4b". CORRECT: 03-identity.md §3.2.1 step 4 is TRANSFER-attestation-chain (4a/4b = re-sign attestations), NOT rotation-event distribution. Authoritative = 09-security-model.md §9.12 (619/645/1157) + ADR-003 §4b (phase-1.md:375 migrate_identity returns DidRotationEvent). wasm identity_execute_custody_migration (DID-PRESERVING) correctly RETAINS §3.2.1; rotate_key retains §3.2.1 ADR-003 §4a.
- **BridgeTrustLevel**: TS `type = 0|1|2|3` mirrors Rust enum (provenance.rs:43-67): ShadowBridged=0/ClaimedBridged=1/NativeBridged=2/NativeNative=3. TS evaluateTrust→NAPI bridge_evaluate_trust→Rust evaluate_trust_level (provenance.rs:228). NativeNative=3 ONLY when `!is_bridged && is_native_transport` — no accidental over-grant. SOUND.
- **provider.rs**: comments-only (zero non-comment +/- lines verified). Stale "default impl/override" trait language removed (inherent methods post-ADR-049, no crypto-trait indirection) + ContextManager→actor/supervisor rename. open() genuinely defers sig verify to receive handler via key_resolver. No logic change.
