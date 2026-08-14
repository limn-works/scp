---
name: pr2141-r2delta-closed-allowlist-wasm-routing-76d95fba3
description: PR #2141 "Round 2" delta review @ 76d95fba3 (9 commits past R27's 22ac39777) — closed-allowlist absorption, WASM CTX-2023 routing, browser base64url, Python private-symbol filter; ALIGNED
metadata:
  type: project
---

# PR #2141 Round-2 delta @ 76d95fba3 (fix/sdk-coverage-fail-closed-and-parity, /tmp/scp-review-r25, 2026-07-15) — ALIGNED

Delta = 9 commits past R27 ([[pr2141_r27_lessons_and_clippy_22ac39777]]). ADR-053 + trust-parity settled in R26/R27, NOT touched here. 11 files, +667/-51.

**Why:** finishing SDK-coverage-fail-closed + Layer-1 parity branch for merge.

**All 6 review checks ALIGNED. Verified against code:**
- Layer-1 self-consistency framing (trust.py/trust.ts docstrings: "measures self-consistency vs att[0], NOT authorization; call scp.ucanValidate(handle,token,uri) for authority") matches spec §7.2.1 11-step Tier-1 — SDK validates token against its OWN att[0].with, no caller-supplied target. Honest, no overclaim.
- Python closed allowlist (411112b8f): denylist "absorb-all-UcanError-except-3030" → `_PIPELINE_ABSORBED_CODES = frozenset({"[SCP-PERM-3001]"})`, `if not any(startswith(code)): raise`. Fail-closed-correct direction. REACHABLE: PyO3 ScpPyError Display = `[{code}] permission error: {message}` (error.rs:158) and ucan_error_code emits ONLY PERM_3001 for ALL UcanError variants (ucan_errors.rs:55-93 verified) — so startswith("[SCP-PERM-3001]") matches real bridge errors; PERM-3030/CTX-2023/unknowns re-raise.
- WASM CTX-2023 routing (8a1764172, ucan.rs): new `WasmValidateError{Ucan,Context}` enum splits with_manager state faults (→CTX_2023) from pipeline faults (→PERM_3001). NAPI parity claim SUBSTANTIATED: NAPI ensure_registered emits codes::CTX_2023 (runtime.rs:1541 etc.). CTX_2023="SCP-CTX-2023" (error_codes.rs:267) + ScpWasmError::Context variant (error.rs:56) both exist. Previously state faults wrongly wore PERM-3001 → silently absorbed by trust.ts → false all-false. Fix restores parity.
- Browser base64url (a3c0e6efb): `__decodeBase64UrlToUtf8` feature-detects Buffer, atob+TextDecoder fallback, normalizes base64url→base64+pad. Test deletes globalThis.Buffer, asserts undefined (precondition guards non-configurable-Buffer false-green), exercises atob path. Genuine.
- Python private-symbol filter (adfe9c710, check-sdk-coverage.py): excludes `_`-prefixed names/classes from extracted symbol set. SAFE: grep shows ZERO ALIASES entries reference underscore-prefixed symbols → won't break coverage. Fail-closed direction (can't claim coverage via private helper).
- TS direction-pinning table (31c78ddeb): honestly scoped ("hand-copied, guards TS classifier internal stability, NOT cross-lang drift; see test_ucan_conformance.py for Rust→TS lockstep"). errors.ts `^`-anchored code regex (Fix 4) safe given bridge contract (code always leading token).

**LOW/OBS (non-blocking):**
- OBS-1 (only substantive finding): the code-sync gates (`TestPipelineAbsorbedCodesSync::test_every_emitted_code_is_absorbed` + TS "every code...absorbed") are ONE-DIRECTIONAL. They enforce completeness (every ucan_error_code-emitted code ∈ allowlist) but NOT minimality (allowlist ⊆ emitted). A future fail-OPEN regression — someone ADDS "[SCP-CTX-2023]" to `_PIPELINE_ABSORBED_CODES`, re-laundering infra faults into all-false verdicts — passes both gates. Currently harmless (allowlist == exactly {PERM-3001}). Suggest adding an assertion that every absorbed code is ALSO emitted by ucan_error_code (bidirectional coupling). Primary protection stays human review of the small constant.
- OBS-2 (pre-existing, now documented): __PASSED_BEFORE groups step-6 cap-match into "ceiling" while step-7 attenuation is "signatures" — a step-6 failure infers "signatures passed" though step-7 runs after step-6. New lesson honestly flags fixed-ordering fragility. Not introduced here.
- Nit: lesson's "parity with TS extractor which requires export keyword" is imprecise — TS exports some `__`-prefixed names (`__extractFirstCapabilityUri`); Python filter is name-based/stricter than TS export-based. Framing only; direction correct.

**VERDICT: ALIGNED.** Zero misalignments in delta; one non-blocking bidirectional-guard suggestion (OBS-1).
