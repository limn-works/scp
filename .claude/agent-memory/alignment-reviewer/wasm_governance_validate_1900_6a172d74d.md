---
name: wasm-governance-validate-1900-6a172d74d
description: WASM governance-model string validation (reject unknown) @ 6a172d74d (#1900 PR-1, #1877 convergence) — ALIGNED; reject-aliases is correct end state
metadata:
  type: project
---

# WASM governance-model validation @ `6a172d74d` (#1900 PR-1) — ALIGNED

Single-file change (crates/scp-ffi/wasm/src/manager.rs, +213/-1). Adds `validate_governance_model` rejecting unknown governance strings with VALID_7005, gating both create_context (:1621) and import_context (:6904). Closes fail-open: WASM stores RAW governance string (:413,:1779) and re-parses in `governance_quorum` (:4912) whose `_ =>` arm maps any unrecognized model → single_admin auto-execute. Typo ("threshhold") silently became single-admin auto-approve. Verdict ALIGNED, 0 findings.

**Key decision assessed: reject legacy aliases `multisig`/`token_voting` vs accept+normalize.** REJECT is correct, arguably the end state not just temporary.
- **Why:** Native `parse_governance` (crates/scp-ffi/common/src/context_params.rs:186) does NOT store the alias string — it maps to typed `GovernanceModel` enum immediately; `"multisig"` ceases to exist (and falls back to SingleAdmin when no signers). Native quorum = from typed enum, never re-parsed string. So "normalize matches native acceptance" is FALSE: native never round-trips the alias either. Normalize-in-WASM would store a DIFFERENT string ("threshold") AND still not match native's enum — a lossy 2nd translation.
- Aliases `multisig`/`token_voting` are OUT OF SPEC. ADR-031/phase-6.md:2326 = exactly 4 models (SingleAdmin/Threshold/Majority/Unanimity). Native's own comments call them "legacy UniFFI Multisig/TokenVoting backward-compat." Per no-backcompat-pre-release stance, a NEW WASM path replicating a legacy alias = importing debt the spec never asked for. WASM declining to grow the alias is MORE spec-faithful.
- Safety: accepting alias WITHOUT normalize re-opens the `_ =>` fail-open (WASM quorum only knows threshold/majority/unanimity). Reject avoids both fail-open and lossy translation.

**Other gates:**
- VALID_7005 correct: error_codes.rs:691-700 explicitly designates 7005 ("invalid field value") for "enum-like string mismatches (unknown custody type/transport mode)." Native `parse_governance` returns bare String error (NO code) — no native code to match, but WASM taxonomy points unambiguously at 7005.
- Both create+import correct: import = untrusted snapshot; Ed25519 sig authenticates ORIGIN not WELL-FORMEDNESS. Mirrors native `import_context` (crates/scp-runtime/src/context/lifecycle_helpers.rs:1721) belt-and-suspenders (re-validates ceiling/consequence/mode on in-memory path). Native gets gov well-formedness FREE from typed enum (serde rejects unknown variants); WASM carries raw string → genuinely NEEDS the belt.
- Cross-bridge import not broken: WASM export snapshot governance is own String, explicitly "NOT byte-parity with native ContextSnapshot" (:503); ADR-050 cross-family export = not byte-parity. WASM import deserializes own WasmContextExportSnapshot, not native wire. No SDK/test emits aliases to WASM bridge (only new doc-comment + negative test).

**PR-2 forward-pointer (non-blocking):** when typed governance engine adopted on WASM, raw-string repr (:413) + quorum string re-parse collapse into typed enum → `_ =>` arm + validate_governance_model both subsumed by serde/type enforcement (as native today). Don't leave validator as permanent redundant belt over a future type guarantee.

**Reusable pattern:** when assessing "WASM should match native's acceptance for convergence" — check what native STORES, not what it ACCEPTS. Native often normalizes-to-typed-enum at parse, so accepting alias X ≠ storing X. WASM storing a raw string is the ADR-034 divergence that forces string-validation belts native gets free from its enum.
