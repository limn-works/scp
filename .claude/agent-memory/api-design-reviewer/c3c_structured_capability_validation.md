---
name: c3c-structured-capability-validation
description: ADR-055 structured CapabilityValidation across FFI + ucan_evaluate optional-capability diagnostic; branch c3c-ts review APPROVED
metadata:
  type: project
---

# C3c Structured Capability/Trust Validation (ADR-055, spec §7.2.4)

Reviewed branch `c3c-ts` (commits 7138de9fc..abccade38). Verdict: APPROVED (no blocking, 4 hardening suggestions).

**Why:** ADR-055 retires the prose-parsing antipattern where Python `trust.py` reconstructed which UCAN check failed by string-matching `[SCP-PERM-3001]` error messages. The structured `CapabilityValidation` (six bools: tokens_valid, signatures_valid, within_ceiling, nonce_valid, not_revoked, time_bounds_valid) already crossed the FFI at every layer; C3c made SDKs consume it. The prose-parsing also masked a multi-attestation nonce bug (mocks emitted unconditional prose).

**How to apply (durable facts for future C3c/trust reviews):**
- Field set + meaning identical across ALL bindings; only casing differs: snake_case in core/PyO3/UniFFI `CapabilityValidationRecord`, camelCase via `#[napi(object)]` auto-conversion (NAPI) and `#[serde(rename_all="camelCase")]` (WASM). This is sanctioned per-SDK idiom, NOT a divergence.
- `evaluate_ucan(token, required_capability: Option<&CapabilityUri>, ctx)` — capability OPTIONAL on the read-only DIAGNOSTIC; MANDATORY on the enforcing gate `validate_ucan` (kept mandatory at all 4 bridges). The only behavior change is `if let Some(required) = required_capability { check_capability_match() }`. `within_ceiling` (step 8, all-attestation) is independent of the challenge — fail-closed proven: omission never flips a bool false→true.
- All 4 bridges treat empty/whitespace capability as absent: `.filter(|c| !c.trim().is_empty())` before parsing. Uniform.
- TS `wrapBridgeErrors` (internal/bridge.ts) = the ADR-055 §4 single error chokepoint: Proxy maps raw FFI errors → typed ScpError at one site, does NOT deep-proxy returned handles (preserves handle-affinity). Python uses its `_bridge`/`BRIDGE_ERROR_MAP` seam instead — per-SDK idiom OK.

**Hardening suggestions made (not yet done):**
1. Add `all_valid()`/`allValid` derived accessor on the record (pure AND of six) — every consumer hand-rolls the six-way AND today (evaluate_trust does it twice per SDK). Misuse-resistance: a single field check (esp. `tokens_valid`) can be misread as "valid".
2. Python `SCP.ucan_evaluate` annotated `-> Any` (import-cycle dodge) but actually returns `trust.CapabilityValidation` — weaker than TS `-> Promise<CapabilityValidation>`. Use forward-ref/TYPE_CHECKING import.
3. `within_ceiling: true` means BOTH grant-match+ceiling (challenge mode) OR ceiling-only (intrinsic mode); record doesn't carry which mode produced it — only interpretable with call-site knowledge.
4. evaluate_trust "no tokens" → all-false is indistinguishable from "all tokens failed step 1"; consider `CapabilityValidation | None`.

Six-bools-vs-enum: bools are CORRECT here — a diagnostic reports WHICH stages passed (product type), an enum would reintroduce the lossy projection ADR-055 retires. Short-circuit ordering means a true late field (e.g. time_bounds_valid) implies all earlier passed.
