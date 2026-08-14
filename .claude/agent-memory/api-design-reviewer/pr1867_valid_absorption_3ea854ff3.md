---
name: pr1867-valid-absorption-3ea854ff3
description: PR#1867 final state @3ea854ff3 — APPROVED; VALID-* absorption + extractFirst rename + WASM Option-drop; lone follow-up = lift VALID-* into public docstring
metadata:
  type: project
---

PR #1867 (`fix/sdk-coverage-fail-closed-and-parity`) HEAD `3ea854ff3`. APPROVED, no blockers. Supersedes [[perm_code_allowlist_vs_typecatch_parity]] and [[pr1867_final_65eba404b]] — later commits.

**Three changes reviewed this round:**
1. `validateOneCapUri` 3-arm error handling (trust.ts): PERM-3001→classify+narrow, `[SCP-VALID-*]`→all-false fail-closed, else→re-throw. Closed allowlist, well-commented. Python mirror: same VALID-* arm added to evaluate_trust as `except Exception` startswith `[SCP-VALID-`.
2. `__extractFirstCapabilityUri` rename: `string[]|null` → `string|null`. Name now matches att[0]-only behavior (multi-att reverted earlier — bridge can't validate all URIs w/ single nonce consume). Old plural names purged. Python `_extract_first_capability_uri`.
3. WASM `validate_tool_ucan_wasm` sig: `Result<(),(String,Option<&'static str>)>` → `Result<(),(String,&'static str)>`. `run_validate_ucan` now returns typed `UcanError` not String. Removes per-callsite `unwrap_or(PERM_3000)`; all branches now PERM_3001 via exhaustive `ucan_error_code`. **Internal crate-local helper — zero external impact** (3 callers all in tools.rs, not #[wasm_bindgen]). Behavioral consequence intended: WASM tool-invoke pipeline failures now PERM-3001 (was PERM-3000) = parity fix. `use error_codes as codes` stays live (SCP-VALID-* paths).

**Lone follow-up (O1, MED, non-blocking):** VALID-* fail-closed absorption documented ONLY in private `validateOneCapUri`/`evaluateLayer1` — NOT in public `evaluateTrust`/`evaluate_trust` JSDoc/docstring. It's a security-relevant guarantee (commit msg: caller catching throws w/ trusted default would be exposed). Lift one sentence into both public docstrings.

**Carried/positive:** `withinCeiling` field-name footgun (Layer-1 = token self-consistency vs token's own att[0].with, NOT authority-for-action) — doc-mitigated, no rename. TS↔Python `Context` handle vs `context_id` string divergence correctly justified in JSDoc (NAPI/WASM need handle, PyO3 resolves by id). `evaluate_trust`/`bridge_evaluate_trust` (Py) ↔ `evaluateTrust`/`bridgeEvaluateTrust` (TS) disambiguation symmetric, both in __all__/index.

**LATENT (O3):** Python distinguishes PERM-3030 from 3001 via startswith INSIDE a `bridge.UcanError` type-catch; TS via regex allowlist OUTSIDE catch. Both correct today (all UcanError→3001). If a future variant splits onto a new PERM code, Python type-catch silently absorbs it; TS allowlist re-throws. Note in trust.py if a new PERM code lands.
