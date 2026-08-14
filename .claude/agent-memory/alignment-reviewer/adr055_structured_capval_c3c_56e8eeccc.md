---
name: adr055-structured-capval-c3c-56e8eeccc
description: ADR-055 structured CapabilityValidation across FFI + optional diagnostic challenge (C3c SCP-302) review @ branch c3c-ts head 56e8eeccc — ALIGNED, 2 minor findings
metadata:
  type: project
---

# ADR-055 Structured Capability/Trust Validation + C3c SDK rebuild @ `56e8eeccc` (branch c3c-ts, 2026-06-27) — ALIGNED, 2 minor

Reviewed `git diff origin/main...HEAD` (32 files, +2329/-1443). SCP-302 (PRD main.json, 371 stories) is the SOLE governing story.

**Premise (root cause, confirmed):** old `trust.py:762` called the throwing GATE `instance.ucan_validate(ctx, token, "*")` with a `*` sentinel the real bridge rejects + reverse-engineered per-check breakdown by string-matching error prose (`_classify_ucan_error`, six `*_PREFIXES` tuples). PR #1867 rebuild premise = "structured data crosses FFI, SDKs never parse prose." This is that rebuild's C3c slice.

**Artifact flow CORRECT (specs/ADR/PRD govern code):** commit order = ADR `48908917d` → PRD `7138de9fc` → SDK code `8404b/e97c` → core+bridge optional `56e8eeccc`. ADR-055 lives in `phase-2.md:1936` (by subject, like ADR-032/042/052/053, not by number). §7.2.4 added to `07-trust-validation-and-capabilities.md`. NO phantom provenance — the optional-capability decision is explicitly written: ADR-055 Decision-2a, Consequences ("One narrow core change"), Rejected-Alt-2, and §7.2.4 table + "challenge mandatory for gate, OPTIONAL for diagnostic".

**Core change verified:** `evaluate_ucan` (validate.rs:782) `required_capability: Option<&CapabilityUri>`; step-6 `check_capability_match` gated `if let Some(required)`. Gate `validate_ucan` (validate.rs:547) keeps MANDATORY `&CapabilityUri` — UNCHANGED, fail-closed preserved. All 4 bridges (PyO3/NAPI/WASM/UniFFI) make `capability` Option + empty-string→None filter + doc "gate keeps mandatory". `None` stays fail-closed: every other stage runs, `within_ceiling` (step 8 all-att ceiling) independent of challenge — integration tests prove `None`+out-of-ceiling → `within_ceiling:false`, `None`+valid → all-true, nonce read-only idempotent.

**SCP-302 ACs all met:** #1 prose apparatus = 0 occurrences (9 symbols gone). #2 `evaluateTrust` (scp.ts:2279) + `CapabilityValidation` 6 camelCase bools (types.ts:795). #3 single chokepoint. #4 TS Identity wrappers + Python discover/verify_payment_receipts. #5 matrix flips TS/Py true, C3c-imminent exemptions removed, Kotlin/Swift keep non-imminent exemption citing Decision-5; check-sdk-coverage.py exit 0; validate-prd exit 0. #6 nonce-state mocks (gate records / diagnostic doesn't), real-napi/wasm evaluate unskipped, multi-token AND.

**FINDINGS (2 minor, neither blocking):**
1. **Broken provenance:** `bindings/typescript/tests/trust.test.ts:18` cites "`.docs/adrs/phase-5.md` ADR-055" — ADR-055 is in `phase-2.md`. Fix: change phase-5→phase-2 (CLAUDE.md "broken provenance is a bug").
2. **PRD internal contradiction:** SCP-302 `details.outOfScope` says "The bridge ucan_evaluate op, the Rust core evaluate_ucan / CapabilityValidation, and the throwing gate ucan_validate already exist and are NOT modified by this story" — but this branch's commit `56e8eeccc` (the SCP-302 work) DOES modify core `evaluate_ucan` + all 4 bridges (Option change). ADR-055 Consequences correctly calls it "One narrow core change"; the PRD outOfScope text just wasn't updated to match. Fix: amend SCP-302 outOfScope to scope-IN the narrow optional-capability core/bridge change (or move it to a sibling story), so the story doesn't disclaim its own diff.

**Non-finding clarified:** AC #4 says "TypeScript public bridgeRegister wrapper exists ON THE SCP class" but `bridgeRegister` is a module-level export in `bindings/typescript/src/bridge.ts:79` (re-exported index.ts:124). This is CORRECT per TS SDK free-function idiom (ADR-048/#1549 façade-deletion); AC wording "on the SCP class" is imprecise but matrix cell `Bridge.register typescript:true` is the operative check and passes.

VERDICT: ALIGNED. No DOA, no scope creep, gate/diagnostic separation is a sound security property (not ergonomics).
