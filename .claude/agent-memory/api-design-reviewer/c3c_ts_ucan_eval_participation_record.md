---
name: c3c-ts-ucan-eval-participation-record
description: c3c-ts branch review — ucan_evaluate optional-capability + typed participation_record across PyO3/NAPI/UniFFI + Py/TS SDKs; NEEDS REVISION on cross-SDK input/fallback divergences
metadata:
  type: project
---

Branch `c3c-ts` (worktree agent-a1400c1b005b502a3), `git diff origin/main...HEAD`. WASM removed; native only.

**Verdict: NEEDS REVISION** (cross-SDK consistency vs Agent-first identical-shape tenet).

Two features:
- (A) `ucan_evaluate`: `capability` now `Option`/optional across all 3 bridges (PyO3 `Option<&str>`, NAPI/UniFFI `Option<String>`) + both SDKs (`capability=None` / `string|null`); empty/whitespace→None normalized in all 3 bridges; `evaluate_ucan(required_capability: Option<&CapabilityUri>)` skips step-6 grant-match in None mode (intrinsic-validity); fail-closed preserved (None never flips a bool true). `all_valid`/`allValid` SDK accessor collapses 6 bools (Py property, TS free fn — per-lang idiom). Good.
- (B) typed `participation_record`: 11 fields. Output `ParticipationFacts` projection IDENTICAL across 3 bridges + both SDKs (field-by-field verified; NAPI i64 vs PyO3/UniFFI u64 = correct per-bridge idiom). Both SDKs unify dev-facing name on `BehavioralRecord` (bridge types ParticipationRecord/NapiParticipationRecord/ParticipationRecordView still diverge but are internal). Error-code chokepoint now converged: CTX_2000 (compute), VALID_7059 (parse/validate) across all 3 (PyO3 explicit CTX_2000 w/ comment — resolves prior R2/R3 divergence). `tool_invocation_count_anchored` + `attestation_count` verifier-relative both clearly named+documented at every surface (not silently-misleading 0). attestation_count default reads persistent store (not auto-zero) — mitigates footgun.

**Findings (all cross-SDK; the OUTPUT shape itself is sound):**
1. MED — input divergence: TS `participationRecord(...,cachedAttestationsJson: string="[]")` raw JSON string vs Python `cached_attestations: list[dict]|None`. TS caller gets zero schema guidance (footgun); violates identical-shape+idiomatic tenet. Fix: TS accept typed array, stringify internally.
2. MED — empty-log fallback diverges: Python `evaluate_trust`→`behavioral_record=None` (Optional field); TS `evaluateTrust`→zeroed `BehavioralRecord` (REQUIRED non-null field). Different shape+type; can't write identical handling. (field NAMES match: behavioral_record↔behavioralRecord.)
3. MED — TS swallows empty-log via `/event log is empty/i` regex on error MESSAGE PROSE — brittle, contradicts THIS PR's own new lesson `consume-structured-ffi-results-not-error-prose.md`/ADR-053. Python swallows ALL ContextError (broad, not prose). Root: empty-log collapses into generic CTX_2000 w/ detail only in prose. Fix: distinct structured code for empty-event-log; align both SDKs on same predicate+result shape.
4. LOW — Python `SCP.participation_record` annotated `-> Any` while sibling `SCP.ucan_evaluate` is `-> CapabilityValidation` (via TYPE_CHECKING). Add BehavioralRecord to TYPE_CHECKING block, annotate `-> BehavioralRecord`.

Good defensive doc: ucan_evaluate WARNING that presenting_agent_did=None → aud==aud self-check tautology (trust inflation); both SDK trust paths pass subject_did.
