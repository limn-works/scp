---
name: pr2141-r25-batch3
description: PR#2141 SDK coverage/trust R2-batch3 black-hat re-attack — all 5 probed areas resistant
metadata:
  type: project
---

# PR#2141 fix/sdk-coverage-fail-closed-and-parity — R2 Batch 3 (post-fix)

Re-attacked at /tmp/scp-review-r25. All Round-1/2-batch-1/2 fixes verified. NO NEW exploitable vector.

**Why:** Fresh adversarial pass requested on current state after fixes (WASM WasmValidateError enum, Python closed allowlist + fullmatch + ValidationError pre-flight, TS PIPELINE_ABSORBED_CODE_PREFIX, private-symbol coverage filter, mapBridgeError ^-anchor).

**How to apply:** These 5 areas are closed; do not re-litigate. Focus future passes elsewhere.

1. **Python `_CONTEXT_ID_RE.fullmatch`** (trust.py:476,888): byte-exact w/ Rust validate_context_id. Rust uses `value.len()` (BYTES, max 256); Python `{1,256}` (chars) — but char class `[a-zA-Z0-9_-]` is ASCII-only so chars==bytes. Char ranges are codepoint ranges (no Unicode/fullwidth-digit collision). fullmatch rejects trailing-\n. AND it's defense-in-depth: bridge ucan_validate re-validates, so even a divergence = no bypass. RESISTANT.
2. **ValidationError pre-flight** (trust.py:888): raised BEFORE the token loop and BEFORE Layer-2. ValidationError is direct ScpError subclass (errors.py:97), NOT ContextError → Layer-2 `except ContextError` cannot catch it. ScpError.__init__ accepts `code` kwarg. Propagates fail-closed. RESISTANT.
3. **tools.rs CTX vs Permission routing** (wasm/tools.rs:517,638,762): `if code==codes::CTX_2023 {Context} else {Permission}`. Producer (ucan.rs:508,629) sets `code: error_codes::CTX_2023` for Context faults via SAME constant → constant change moves both in lockstep (neither hardcodes literal). ucan_error_code (common/ucan_errors.rs) is exhaustive, every arm→PERM_3001, NO `_=>`, never returns CTX_2023 → Ucan branch can't misroute. Also: code string preserved verbatim in both branches; trust.ts keys off code-string not JS class; tool_invoke path isn't fed through Layer-1 absorption anyway. RESISTANT.
4. **Coverage gate + ALIASES** (check-sdk-coverage.py): SDK_PATHS glob src-only (scp_sdk/, src/, Sources/SCP/) — tests/ EXCLUDED so no test-helper name collision. Python extractor now excludes `_`-prefixed (parity w/ TS `export`). Match = ALIASES table OR domain-prefixed exact variant; suffix/substring matching removed. Residual = inherent name-existence≠wired limit + mis-pointed-ALIAS (documented R25-2), not NEW. RESISTANT for "unexposed op passes."
5. **Layer-1 trust verdict consumer**: grep confirms NO codebase consumer gates access control on CapabilityValidation fields — produced only by evaluate_trust/evaluateLayer1, returned in TrustEvaluation, advisory. Real enforcement = bridge ucan_validate raise/no-raise (binary, unaffected by classification). Misclassification only reshuffles partial-pass FAILURE diagnostics; fully-True verdict requires ucan_validate to actually succeed crypto. RESISTANT.

**Classification robustness (_classify_ucan_error / __classifyUcanError):** startswith on core=_extract_core_error(msg). Pipeline returns FIRST failure only, so core always starts with the REAL failing step's literal. Attacker controls content AFTER the leading literal (embedded DIDs/URIs), not the prefix. Cannot escalate early-fail→late-step (which would set more fields True). Embedded "] permission error: "/em-dash injection can only TRUNCATE core earlier, not change leading token. TS extractCoreError (indexOf first) == Python split(...,1)[1]; both strip first em-dash — parity-exact.

**TS/Python asymmetry (NOT a gap):** TS evaluateTrust takes a Context HANDLE (context.contextId from established handle), Python takes raw context_id string (PyO3 dispatches by id). TS needs no context_id pre-flight because id comes from a validated handle, not attacker string.

**Persistent/latent (previously documented, not new):** R25-1 closed-allowlist couples to all→PERM_3001 invariant (PERM-3007/3008 split will need prefix SET; fail-closed re-throw meanwhile). R25-3 within_ceiling att[0]-only over-report (BLACK-053 OBS-1).
