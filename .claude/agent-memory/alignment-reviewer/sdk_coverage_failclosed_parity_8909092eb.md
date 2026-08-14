---
name: sdk-coverage-failclosed-parity-8909092eb
description: PR #1867 fix/sdk-coverage-fail-closed-and-parity @ 8909092eb — multi-att AND-intersect alignment review; ONE blocking doc/code mismatch (Python docstring stale att[0])
metadata:
  type: project
---

## PR #1867 @ 8909092eb (2026-06-23) — NEEDS DISCUSSION, 1 blocking doc/code mismatch

Branch `fix/sdk-coverage-fail-closed-and-parity` vs base `1f1ea7cd2`. Multi-att AND-intersection of UCAN capability verdicts in TS + Python `evaluate_trust`/`evaluateTrust`.

**Spec faithfulness (checks 1-5): ALIGNED.**
- Multi-att AND-intersect: validating EACH `att[i].with` separately via ucanValidate and AND-intersecting per-field verdicts is MORE spec-faithful than att[0]-only. Spec §7.2.1 step 8 ceiling validates one required_capability per call; iterating all att entries = stricter (a token passes only if ALL declared URIs are within ceiling). No spec violation.
- Layer-1 contract: `evaluateTrust` measures token SELF-CONSISTENCY (token's own declared caps), NOT "authorizes action X". TS JSDoc states this explicitly + correctly. Sketch §SCP.Trust.evaluate Layer-1 has tokensValid/signaturesValid/withinCeiling/notRevoked; impl adds nonceValid+timeBoundsValid (faithful to the 11-step pipeline, superset not contradiction).
- UcanPermissionError canonical: matches taxonomy. phase-3.md/phase-4.md ADR text updated PermissionError→UcanPermissionError. Deprecated TS `PermissionError` alias DELETED. Python errors.py docstrings intentionally note avoiding shadowing Python builtin PermissionError — correct.
- PERM_3001 parity: `crates/scp-ffi/common/src/ucan_errors.rs` exhaustive match — EVERY UcanError variant → PERM_3001. WASM ucan.rs now routes parse/capability failures through `ucan_error_code` (was hardcoded), non-parse → PERM_3000 fallback in tools.rs callers. Brings WASM into cross-bridge parity. Closed-allowlist absorb (only PERM_3001; re-throw PERM_3000/PERM_3030) is architecture-faithful.
- ADR-053 (check 6): Status Proposed, docs-only (grep confirms NO PreRotationCustodyProvider/CallbackPreRotationCustody/import_seed_bytes code). Artifact-flow compliant: design fixed in ADR + cites spec §9.7.4.1 §3/§4/§5 BEFORE code. Compliant.

**BLOCKING: Python `evaluate_trust` docstring (bindings/python/scp_sdk/trust.py:779-786) STALE.** Still says "Layer 1 validates each token against its FIRST declared capability URI (att[0]['with'])" and "Multi-att ceiling validation ... is NOT yet implemented" — but the CODE now does full multi-att AND-intersection (lines 838-895). TS JSDoc was correctly updated; Python was not. Direct doc-vs-code contradiction AND TS/Python doc divergence (check 2 fails on docs). Fix: rewrite the Python docstring paragraph to match TS `evaluateTrust` JSDoc (validates ALL att[i].with, AND-intersects). LESSON: when commit 935298ba3 reverted then 8909092eb re-applied multi-att, the Python prose docstring was left at the reverted state.

See [[feedback_two_dot_diff_stale_base_trap]].
