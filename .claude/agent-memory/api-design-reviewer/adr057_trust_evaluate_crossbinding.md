---
name: adr057-trust-evaluate-crossbinding
description: ADR-057 structured trust/UCAN evaluate cross-binding API review — evaluate_trust Python arg-order footgun, CachedAttestation casing split
metadata:
  type: project
---

# ADR-057 trust/UCAN evaluate cross-binding API review (branch c3c / ADR-057, 2026-06-30)

Reviewed `ucanEvaluate` (diagnostic, optional cap) vs `ucanValidate` (gate, mandatory cap),
`evaluateTrust`, `participationRecord`, `CapabilityValidation`(6-bool+allValid),
`BehavioralRecord`(12-field), `AttestationSummary`(4-field), `CachedAttestation(Envelope)`
across Python/TS/Swift/Kotlin. Verdict NEEDS REVISION.

**Big win this PR:** Layer-1 now reads the bridge's structured `CapabilityValidation`
(NapiCapabilityValidation / PyCapabilityValidation / CapabilityValidationRecord) — the old
Python `_classify_ucan_error` error-PROSE parsing is gone. Layer-2 is computed ONCE in Rust
(`Supervisor::participation_record`); all four RECEIVE the 12-field record. This kills the
PR #1867 prose-classification + client-side-aggregation divergence class by construction.
`presenting_agent_did` is fail-closed required at all three bridges (UniFFI types it `String`;
PyO3/NAPI type it `Option` but runtime-reject None/empty) and required (non-optional) at all
four SDK surfaces; arg order consistent: (handle|context_id, token, presentingAgentDid, capability?, proofTokens?).

**BLOCKER — Python `SCP.evaluate_trust` reverses the first two args vs siblings.**
- Python: `evaluate_trust(subject_did, context_id, ...)` — subject FIRST, context SECOND, both `str`.
- TS/Swift/Kotlin: `evaluateTrust(handle, subjectDid, ...)` — context-handle FIRST, subject SECOND.
- Also internally inconsistent: Python's own `participation_record(context_id, subject_did)` is context-FIRST.
- Both Python args are strings → swapping them is SILENT (no type error, wrong result). Worst-case
  agent-authorability footgun. Fix: make Python `evaluate_trust(context_id, subject_did, ...)`.

**Root cause of the handle-vs-string split:** PyO3 bridge is context_id-STRING-keyed; UniFFI/NAPI are
opaque-HANDLE-keyed. So Swift/Kt/TS `evaluateTrust` take a handle and resolve `handle.contextId()`
as the label (authoritative); Python takes a context_id string and echoes it (caller-asserted).
Same split already exists for `ucanEvaluate`/`ucanValidate` (handle vs context_id). Per-SDK idiom,
acceptable — but the arg-ORDER reversal is not.

**MODERATE — CachedAttestation(Envelope) field-name casing is 2/2 split.**
Py + TS expose serde snake_case to the developer (attestation_type, issued_at, verified_at, ttl_secs…);
Swift + Kotlin expose camelCase with CodingKeys/buildJsonObject mapping to snake on the wire. TS using
snake_case fields is un-idiomatic for TS and diverges from Swift/Kt. "Identical shape" tenet partially broken
for this input DTO.

**MINOR:** `allValid` is a free fn in TS `allValid(cv)` vs accessor `cv.allValid` elsewhere (TS interface
can't carry methods — idiomatic). Python keeps module-level `scp_sdk.evaluate_trust(scp, subject, context)`
exported alongside the new `SCP.evaluate_trust` method (different arity) — mild discoverability collision.
Swift/Kt/TS mix handle (ucanEvaluate) + context_id-string (participationRecord) addressing within the trust module.

All four document `all_valid`/`allValid` as DIAGNOSTIC-NEVER-AUTHORIZATION; TrustEvaluation shape matches
(no vestigial Layer-4 fields; 4-field AttestationSummary; 12-field BehavioralRecord identical).
