---
name: adr055-ucan-evaluate-optional-capability
description: ADR-055 / spec §7.2.4 / SCP-302 — evaluate_ucan optional required_capability (None=intrinsic), structured CapabilityValidation across FFI; SOUND review on branch c3c-ts
metadata:
  type: project
---

# ADR-055 ucan_evaluate optional-capability + structured CapabilityValidation (branch c3c-ts) — SOUND

Reviewed branch `c3c-ts` (worktree agent-a1400c1b005b502a3) 2026-06-27. APPROVE, no blocking findings.

**Why:** SCP-302/C3c made UCAN trust evaluation return a structured per-stage `CapabilityValidation` (six bools: tokens_valid, signatures_valid, within_ceiling, nonce_valid, not_revoked, time_bounds_valid) consumed directly by SDKs instead of reverse-engineering failure stage from error prose.

**How to apply:** When reviewing UCAN trust/capability changes, the load-bearing facts are:

- Core `evaluate_ucan` (crates/scp-protocol/src/crypto/ucan/validate.rs ~779-891): `required_capability: Option<&CapabilityUri>`. ONLY `check_capability_match` (step 6, line ~836) is gated by `if let Some(required)`. Every other step (sig/chain/issuer/aud/keyscope/catA/atten/ceiling/nonce/revoke/expiry) runs unconditionally. `None` = intrinsic-validity. Fail-closed: starts NONE (all false), each bool set true ONLY after its stage passes, every failure does `return result` (strict short-circuit). `None` can never flip false→true. `within_ceiling` (step 8) is over token's OWN att set, independent of challenge.
- `validate_ucan` (the throwing GATE) UNCHANGED — keeps mandatory capability, records nonce via &mut ctx. `evaluate_ucan` is read-only (check_replay only, never record) — safe to call repeatedly; recording in a trust probe would be a self-revocation/DoS vector.
- Deleted error-prose parsing in trust.py (_classify_ucan_error, _PASSED_BEFORE, 6 prefix tables) + deleted test_ucan_conformance.py — net security WIN (prose reword no longer silently misclassifies). Correct deletion: test's subject (prefix tables) no longer exists.
- SDK trust (trust.py evaluate_trust, scp.ts evaluateTrust) pass subject_did/subjectDid as PRESENTING AGENT + None/null capability + AND-combine (`&=`/`&&=`) per-token from all-true identity. Audience binding is SECURITY-LOAD-BEARING: omitting presenting agent makes native bridges default to token's own aud → tautology aud==aud → trust inflation (token for Alice inflates Bob). Subject-as-presenting-agent closes it.
- All 4 bridges (pyo3/napi/uniffi/wasm) route to shared core evaluate_ucan — ENFORCED by pipeline_wiring.rs `*_ucan_evaluate_routes_to_core_evaluate_ucan` (fn_body_contains "evaluate_ucan("). WASM run_evaluate_ucan does NOT reimplement (ADR-034 reuses scp-protocol algos directly). Empty-string→None coercion uniform across all 4: `.filter(|c| !c.trim().is_empty())`.

**INFORMATIONAL (not blocking):** no-presenting-agent DEFAULT diverges by bridge — native defaults to token's own aud (tautology); WASM defaults to handle.creatorDid (stricter). Root cause: WASM `expected_aud_did` is a required (non-Option) wasm-bindgen param (ADR-034 constraint). NOT exploitable: SDK trust path ALWAYS passes subjectDid explicitly so the default is never used there. Could doc the divergence in bridge comments.

Test coverage: 3 Rust integration tests (none_valid_all_true / none_out_of_ceiling_fail_closed / none_vs_some grant-match contrast) in crates/scp-runtime/tests/ucan_validate_integration.rs + TS real-wasm/e2e-cross-bridge (NAPI-mint→WASM-eval w/ member.did as aud).
