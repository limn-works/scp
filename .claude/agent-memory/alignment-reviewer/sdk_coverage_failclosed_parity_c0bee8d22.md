---
name: sdk-coverage-failclosed-parity-c0bee8d22
description: PR #1867 spec-alignment review of trust multi-att validation + PermissionError rename at HEAD c0bee8d22 — ALIGNED, 1 LOW
metadata:
  type: project
---

# PR #1867 fix/sdk-coverage-fail-closed-and-parity @ c0bee8d22 (2026-06-22) — ALIGNED, 1 LOW

**Why:** Asked 5 spec-alignment questions on trust.ts/trust.py multi-att validation, evaluateLayer1 self-consistency framing, and PermissionError→UcanPermissionError rename.
**How to apply:** merge-base==origin/main was 1f1ea7cd2 (origin/main had advanced to a632c731a — review diff 1f1ea7cd2..c0bee8d22 explicitly, not the moving tip).

Key findings (all verified against spec text, not memory):
- **Multi-att validation = ALIGNED, improvement.** Spec 07 §7.2.1 step 7 ("EACH delegation narrows") + step 8 (ceiling) make every att entry subject to ceiling — checking only att[0] would let att[1] smuggle a ceiling violation past withinCeiling:true. SDK now validates ALL att[i].with. Spec is silent on SDK-side per-att iteration; fail-closed (null/[]→all-false) fills a spec GAP safely.
- **CapabilityValidation field count = pre-existing drift, NOT introduced here.** sketch.md `SCP.Trust.evaluate` defines 4 fields (tokensValid/signaturesValid/withinCeiling/notRevoked). Both SDKs ship 6 (adds nonceValid=step9, timeBoundsValid=step11). The 6 fields are MORE faithful to the 11-step pipeline than the sketch. Python already had all 6 on main (verified `git show 1f1ea7cd2:.../trust.py`); this PR only brings TS to parity. **OBS-1 (LOW): sketch.md should be reconciled to 6 fields** per artifact-flow invariant.
- **Self-consistency framing = ALIGNED.** doc-comment "is token valid/signed/in-ceiling/unexpired" vs "does it authorize action X" matches §7.2.3 (token-validity) vs step-6 caller-supplied required-capability. aud-binding deferred to upstream issuance = consistent with step-5.
- **PermissionError removal = no spec contract broken.** Specs don't name SDK exception classes. sdk-common.md ALREADY had Python=UcanPermissionError; rename converges TS to it (strengthens cross-SDK shape parity tenet). Pre-release, no users → remove alias not deprecate. PRD main.json + ADR-022 phase-4.md updated in lockstep (downstream artifacts, flow respected).
- **sdk-common.md/phase-4.md = correct.** Canonical UcanPermissionError both langs with shadowing rationale (builtins.PermissionError / global PermissionError).

Positives: Layer-2 behavioral record now 0-not-computed with comment (honest: aggregate queries unexposed over bridge) vs prior fabricated contexts_participated=1. PERM-3001 closed-allowlist absorption (TS) + PERM-3030 re-raise (Python) = sound positive-whitelist shape.
OBS-2 (INFO): TS __extractAllCapabilityUris lacks isinstance(entry,dict) guard that Python has; converges on well-formed payloads, both fail-closed.

Verdict ALIGNED. Only follow-up = OBS-1 sketch.md 4→6 field reconciliation (LOW, doc-sync).
