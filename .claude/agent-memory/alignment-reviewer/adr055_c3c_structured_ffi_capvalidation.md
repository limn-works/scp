---
name: adr055-c3c-structured-ffi-capvalidation
description: ADR-055/§7.2.4/SCP-302 C3c review — structured CapabilityValidation crosses FFI, SDKs consume typed not prose, diagnostic challenge cap optional. ALIGNED, 1 cosmetic PRD AC wording.
metadata:
  type: project
---

# C3c structured-FFI capability/trust validation (ADR-055, §7.2.4, PRD SCP-302) — branch c3c-ts @ 3e9ec3a22 (2026-06-27) — ALIGNED

Part of PR #1867 rebuild ("structured data crosses FFI; SDKs never parse prose"). Reviewed read-only in worktree. Verdict ALIGNED, 0 blocking/material, cosmetic notes only.

## What shipped + verification
- **Core**: `evaluate_ucan` (validate.rs:782) now `required_capability: Option<&CapabilityUri>` (intrinsic-validity diagnostic mode when None — skips ONLY step-6 grant-match; every other stage incl. all-att ceiling step-8 still runs → fail-closed). Gate `validate_ucan` (validate.rs:547) keeps MANDATORY `&CapabilityUri` — NOT weakened. Integration tests prove None-all-true-parity, None-still-enforces-ceiling, None-vs-Some-for-ungranted-cap.
- **All 4 bridges symmetric**: PyO3/NAPI/WASM/UniFFI `ucan_evaluate` cap → `Option<String>`, empty/whitespace coerced via `.filter(|c| !c.trim().is_empty())`, pass `Option<&CapabilityUri>` (`.as_ref()`) to core, return structured 6-bool record (camelCase NAPI/WASM serde; CapabilityValidationRecord UniFFI). WASM correctly DELEGATES to scp_protocol (UCAN validate is pure protocol, no Supervisor → ADR-034 OK).
- **Python SDK**: trust.py has ZERO of 9 forbidden prose-parser symbols (_classify_ucan_error etc.). evaluate_trust (trust.py:656) calls `ucan_evaluate(ctx, token, None, subject_did)` — None cap (intrinsic, no `*`), subject_did as presenting agent (fixes audience tautology aud==aud). AND-combines 6 bools; empty token set = all-false (fail-closed). `discover()`/`verify_payment_receipts()` parity wrappers real.
- **TS SDK**: evaluateTrust (scp.ts:2289) byte-parallel to Python — `this.ucanEvaluate(handle, token, null, subjectDid)` (scp.ts:2328). `ucanEvaluate` declared bridge.ts:331, impl native.ts:997 + wasm.ts:1429, surfaced scp.ts:1955. CapabilityValidation 6-camelCase iface types.ts; `allValid` DERIVED free fn (types.ts, not stored 7th field) mirrors Python all_valid. bridgeRegister = MODULE-LEVEL export bindings/typescript/src/bridge.ts:79 (takes explicit scp arg, ADR-048 multi-instance) re-exported index.ts — matches PRD desc.
- **Chokepoint**: single `mapBridgeError` (errors.ts:265) keyed on `[SCP-CAT-NNNN]` CODE regex, idempotent (passes already-typed ScpError through — the "preserve typed errors" fix). `wrapBridgeErrors` Proxy (internal/bridge.ts:778) wraps BOTH bridge factories. Zero prose `.message`/.includes branching in trust paths. (rethrowEconomyFailClosed wasm.ts:687 keys on CODE not prose, economy path not trust, unchanged by this diff.)
- Matrix: cells flip true, stale C3c exemptions removed, Kotlin/Swift kept non-imminent. check-sdk-coverage.py adds ("UCAN","evaluate") alias, exits 0. validate-prd.py passes (13 files/371 stories). New lesson sdk-consume-structured-ffi-results-not-error-prose.md (mock-fidelity corollary).

## Findings (non-blocking)
1. **PRD AC4 cosmetic name imprecision**: AC4 + action item say TS public wrappers `rotateKey/addAgentKey/rotateAgentKey/removeAgentKey/migrate` "on the SCP class". Actual SCP-class methods are `identityRotateKey/identityAddAgentKey/identityRotateAgentKey/identityRemoveAgentKey/identityMigrate` (scp.ts:739-800, `identity` prefix = class idiom); the bare names are the underlying HANDLE methods. Code correct+idiomatic; only AC wording names handle-method spelling. Coverage gate passes via matrix aliases. Optional: reword AC4.
2. AC3 names native.ts/wasm.ts as mapping sites; real design centralizes in one mapBridgeError fn + Proxy — OVER-satisfies intent. AC text more literal than architecture.

## Lessons
- test_ucan_conformance.py deletion (613 lines) is CORRECT removal (tested the deleted prose-prefix machinery), not lost coverage — replacement moved to test_trust.py + test_real_ffi.py, expanded to real bridge. ALWAYS check what a deleted test FILE was testing before flagging lost coverage.
- Real-addon `.skip` calls (real-napi:112/real-wasm:194) are availability GUARDS (fire only when addon not installed), not gated-out assertions — correct pattern; the evaluate tests run in the `else` branch.
- "optional arg" core change: verify the SIBLING gate stays mandatory (here validate_ucan) — the security property is the gate/diagnostic asymmetry, not the field itself.
