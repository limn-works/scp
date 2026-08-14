---
name: adr055-structured-capability-validation-ffi
description: ADR-055 + §7.2.4 review (2026-06-26, commit 48908917d) — structured CapabilityValidation crosses FFI; SDKs consume typed result not prose. ALIGNED, 0 blocking.
metadata:
  type: project
---

# ADR-055 / §7.2.4 Structured Capability Validation Across FFI — ALIGNED (2026-06-26)

Branch `docs/adr-structured-capability-validation-ffi` @ `48908917d`. Docs-only diff: phase-2.md +62 (ADR-055), spec 07 +25 (§7.2.4). Verdict ALIGNED, 0 blocking, 0 material.

**Why:** Legit upstream provenance record for the C3c SDK rebuild (artifact flow respected). Structured op already exists at core+4 bridges (capability matrix `UCAN.evaluate` line 1309 = bridge-present/SDK-pending, exemptions name "C3c SDK-parity follow-up"). ADR records the CONSUMPTION CONTRACT (consume typed CapabilityValidation, never parse prose; gate vs diagnostic stay distinct; error typing via `[SCP-CAT-NNNN]` one chokepoint; per-SDK idiom) — NOT a new op. "No core change" claim verified.

**How to apply / verified facts:**
- `evaluate_ucan` (validate.rs:745) read-only `check_replay` (827), returns 6-bool CapabilityValidation, never throws — matches §7.2.4 table EXACTLY (tokens_valid=step1, signatures_valid=steps2-7 whole chain, within_ceiling=step8, nonce_valid=step9 read-only, not_revoked=step10, time_bounds_valid=step11; strictly ordered short-circuit).
- `validate_ucan` (validate.rs:545) 11-step throwing gate, `check_and_record` records nonce (611). Both run same checks.
- §7.2.4 "signatures_valid covers WHOLE chain not leaf" matches code (parent expiry/revoke inside verify_delegation_chain at step 3, folded into signatures stage).
- Cited problem is REAL: `trust.py` 155-243 reconstructs 6 fields via `startswith("[SCP-PERM-3001] permission error: ...")` + `_PASSED_BEFORE` lossy short-circuit map. Nonce-mock-masking claim plausible.
- ADR-055 numbering UNIQUE (1 `## ADR-055` header, phase-2.md only; ADR-054 + ADR-051 exist, 056 unused). Sits in phase-2 by SUBJECT (§7.2 capability surface) per same convention as 032/035/042/052/053 — self-documented in the Note.
- Coheres with §7.2.1 Tier-1 11-step, §7.2.2 Tier-2 cache, ADR-009 (nonce), ADR-016 (11-step), ADR-039 (Category-A in signatures_valid), just-merged §5.3.1.1 ceiling (within_ceiling). No contradiction found in .docs.
- NO Goal #2 / C3c / ADR-055 PRD story exists (author flagged correctly). ADR+§7.2.4 is sufficient upstream provenance to AUTHORIZE the C3c code, but prd.md MANDATORY rule still requires a PRD story before the code lands (stories reference ADR+spec — both now exist, so the story is writable). This is the one open item: ADR/spec are NECESSARY-and-now-present, a PRD story is still REQUIRED by repo convention before C3c code.

**Minor (informational only):** none material. ADR Consequences correctly scope Python+TS wrappers to C3c, Kotlin/Swift "tracked separately" (UniFFI bridge already exports CapabilityValidationRecord). No DOA — typed 6-field record is closed-by-construction; gate/diagnostic split is a security property (avoids nonce-burn DoS), permanent.
