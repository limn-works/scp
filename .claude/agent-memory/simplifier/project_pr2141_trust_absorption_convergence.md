---
name: pr2141-trust-absorption-convergence
description: PR #2141 (fix/sdk-coverage-fail-closed-and-parity) trust-absorption machinery is bounded/convergent, NOT a non-convergence BLOCKER
metadata:
  type: project
---

PR #2141 trust-classification review (R2B3, branch `fix/sdk-coverage-fail-closed-and-parity`). The Layer-1 UCAN-absorption apparatus is CONVERGENT/bounded — do NOT re-flag as a non-convergence BLOCKER in future rounds.

Key artifacts and verdicts:
- `_PIPELINE_ABSORBED_CODES` (Python frozenset) / `PIPELINE_ABSORBED_CODE_PREFIX` (TS single string) = positive allowlist of codes to ABSORB (all else re-raises, fail-closed). Closed-by-construction, one element today ([SCP-PERM-3001]). NOT a denylist chasing spellings.
- `WasmValidateError{Ucan(UcanError), Context(String)}` enum in wasm/src/ucan.rs = idiomatic 2-variant sum type replacing stringly-typed `Result<(),String>`; restores WASM/NAPI parity (Context→CTX_2023, Ucan→PERM_3001). A simplification, not new abstraction.
- `_CONTEXT_ID_RE` + hoisted pre-flight in evaluate_trust = raises ValidationError before token loop so a bad context_id isn't swallowed by the loop's `[SCP-VALID-*]` all-false absorption. Bounded positive whitelist. Partial redundancy w/ Rust validate_context_id but changes semantics (raise vs absorb) + covers no-tokens path.
- `TestPipelineAbsorbedCodesSync` (Py) + "ucan_errors.rs pipeline code sync" (TS) regex-parse ucan_errors.rs/error_codes.rs asserting every emitted code is in the absorbed set. Bounded (superset check), fail-safe (over-match direction), fails loud. Guards cross-language drift rustc CANNOT catch (exhaustive match forces Rust decision, not SDK allowlist update). Justified.

Ucan_errors.rs `ucan_error_code` is an exhaustive match (all variants → PERM_3001 today; PERM_3007/3008 splits documented-but-held-back pending same-change test updates).

Low-priority open notes (not blockers): (1) frozenset vs single-string asymmetry across Py/TS is a mild consistency wart; (2) `_CONTEXT_ID_RE` has no coupling test to Rust MAX_CONTEXT_ID_LEN=256/charset — deliberate (adding one = more machinery).

R7 verification (HEAD 5d118e1a2): NO BLOCKER. Sole substantive delta since R4 is commit 5d118e1a2 anchoring `_CODES_RETURN_RE` from `codes::(\w+)` to `=>\s*\{?\s*codes::(\w+)` in test_ucan_conformance.py. This is CONVERGENT — it REMOVES a false match (over-broad regex matched a doc-comment `codes::PERM_3009` at ucan_errors.rs:114 with no error_codes.rs const → hard-fail) and a test-assert `assert_eq!(…, codes::PERM_3001)` at line 172. Now matches only match-arm return positions (inline `=> codes::X` + block `=> { codes::X }`), the closed set of Rust match-arm return forms. NOT a "one more spelling" denylist expansion — the opposite: precision fix on a bounded parser. `assert emitted_const_names` still fail-safe if structure changes. trust.py evaluate_trust absorption logic unchanged since R4. Minor non-blocking residual (pre-existing): a hypothetical multi-statement block arm `=> { stmt; codes::X }` (codes:: not immediately after `{`) would be missed = under-coverage, but no such arm exists (all inline today) and the runtime all_variants_route_to_perm_3001 test is a secondary value-correctness guard.

R4 final verification (HEAD 7c7af56b6): CLEAN, no new machinery since R2B3 — delta is net-negative. Swift `TrustEvaluation.init(from:)` ×2 flipped Layer-1 fields true→false (fail-closed parity fix, correctness not machinery); removed redundant 6-variant `ucan_errors.rs` subset test (simplification, superset test already covers all 28); rest are doc/comment honesty fixes (phantom Swift method sigs, "exhaustive"→"representative" table label, ensure_ascii=False JSON re-serialize). SCP-302 story is PROPORTIONATE: tracks the single genuine att[0]-only ceiling gap (multi-att needs one nonce-once `ucan_validate_all_att` bridge op), well-formed machine-verifiable ACs, cites real spec §7.2.1 step 8. No non-convergent "one more spelling" pattern anywhere. Not a BLOCKER.
