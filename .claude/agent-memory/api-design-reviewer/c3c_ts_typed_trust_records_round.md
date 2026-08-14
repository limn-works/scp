---
name: c3c-ts-typed-trust-records-round
description: c3c-ts trust SDK review — typed BehavioralRecord/CapabilityValidation/CachedAttestation cross-SDK; APPROVED, one MED reversed-input-asymmetry
metadata:
  type: project
---

Branch `c3c-ts` (worktree agent-a1400c1b005b502a3), tip a19aa5352. Review of typed `ucan_evaluate`→CapabilityValidation + `participation_record`→BehavioralRecord across PyO3/NAPI/UniFFI + Python/TS SDKs. WASM removed (3 bridges).

VERDICT: APPROVED. The recent fixes converged the OUTPUT side fully.

Verified SOUND:
- BehavioralRecord = 12 fields IDENTICAL across Py dataclass + TS interface + 3 bridge records (NapiParticipationRecord `#[napi(object)]`→camelCase, UniFFI ParticipationRecordView, PyParticipationRecord), incl. new `attestation_count_anchored` (always false, §7.4 credential-layer) and `tool_invocation_count_anchored` (false until ADR-051). NAPI uses i64 (JS number, lossless), Py/UniFFI u64 — correct per-bridge int idiom.
- Empty-log: BOTH SDKs build the SAME 12-field zeroed record (subjectDid set, all else 0/false/"") AND branch on STRUCTURED code `SCP-CTX-2076` (NO_PARTICIPATION_FACTS_CODE), never prose. All 3 bridges map `ContextError::NoParticipationFacts`→CTX_2076 (TrustError::EmptyEventLog→NoParticipationFacts in supervisor.rs:9779). This fully closes the prior-round ADR-053 prose-branching finding.
- TS CachedAttestation/CachedAttestationEnvelope input now matches Rust serde wire EXACTLY: DID `#[serde(transparent)]`→string; AttestationType unit-enum→string; RevocationStatus ext-tagged→`unknown` (string|object); signature serde_bytes→`number[]`; Duration→`{secs,nanos}`; CachedAttestation={attestation,verified_at,ttl_secs}. snake_case fields (correct — JSON.stringify'd straight to wire, like Py json.dumps).
- ucan_evaluate optional capability None(Py)/null(TS) consistent; subject passed as presenting-agent in BOTH (avoids aud==aud tautology, matches FFI fail-closed fix 07b10818a).
- Python SCP.participation_record + module fn both `-> BehavioralRecord` (prior `-> Any` resolved).

REMAINING findings (non-blocking):
- MED (REVERSED asymmetry): Python `cached_attestations: list[dict[str,Any]]` is now the UNTYPED side; TS has full typed envelope. Python author gets zero type guidance for ~12 snake_case wire keys → fails Agent-first "correct from type signature" bar TS now meets. Fix: add Python CachedAttestation/AttestationEnvelope dataclass-or-TypedDict (idiomatic, satisfies per-sdk-idiom). Note: list[dict] IS consistent w/ Python's own aggregate_trust_input convention.
- LOW doc drift: TS scp.ts ~2393 comment says core "return EmptyEventLog" but SDK catches ContextError code CTX-2076 (mapped from NoParticipationFacts); Py comment correct. Align.
- LOW call-site shape: `all_valid` = Py property vs TS free fn `allValid(v)` — idiomatically justified (TS interface can't host methods).
- LOW (pre-existing): TS evaluateTrust(handle,...) resolves canonical ctxid from handle; Py evaluate_trust(scp,subject,context_id) uses string directly — handle-pattern divergence, outside this change.
