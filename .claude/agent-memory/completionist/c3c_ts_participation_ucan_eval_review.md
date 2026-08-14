---
name: c3c-ts-participation-ucan-eval-review
description: c3c-ts branch (ADR-057 ucan_evaluate + §7.3.2 participation_record) across 3 native bridges + Py/TS SDKs, post-WASM-removal; re-verify @fcd7ee1d7 INCOMPLETE on 2 minor parity/spec items
metadata:
  type: project
---

RE-VERIFY @fcd7ee1d7 (2026-06-29, founder-MemberJoined-leaf HEAD, newer than a19aa5352):
verdict INCOMPLETE on TWO minor residual findings (no SCP-302/303 AC unmet; all 6 task
items + both validators pass). The core wiring (below) re-confirmed PASS at this HEAD.
1. TS public-surface parity gap: `CachedAttestation`/`CachedAttestationEnvelope` (types.ts
   :961/:925, consumed by public `participationRecord` wrapper scp.ts:2496) are OMITTED from
   the curated `export type {...} from "./types"` block (index.ts:232-274 — lists 40+ incl
   BehavioralRecord/CapabilityValidation/ParticipationFact but NOT these two); package.json
   exports only `.` (no `./types` subpath). Python exports both (__init__.py:198-199). A TS
   consumer cannot import the named input type for `cachedAttestations`. Mitigated by TS
   structural typing; NOT required by any written AC. Fix = add 2 names to index.ts block.
2. Spec-internal drift §7.3.2.1: `ParticipationFact` category prose (~lines 219-225) uses
   stale field spellings (`participation_duration_seconds`, `.len()` forms) vs the flat
   `ParticipationProfile` struct (~242-258, `*_secs`/u64 eleven-field) in the SAME section.
   Code (ParticipationFacts) matches the struct; fix the spec prose (one-way flow).
NON-FINDINGS confirmed: challenge_results verify-on-ingest IS in code (trust_store.rs:254 →
challenge.rs:786 verify_challenge_verification), grounded in ADR-017/§7.3.3 (trust-aggregation
input, NOT a participation_record fact) → ONE correct ingest path (attestations have 2);
"both paths" in the brief applies to attestations only. Founder duration now non-zero via a
founder MemberJoined leaf appended at context creation (builder.rs:927-950, convergent
creation ts) + tests (builder.rs:1141 nonzero-duration; e2e_bridge.rs:502 stream =
ContextCreated+MemberJoined). participation_record matrix kotlin/swift exemptions match
SCP-303 AC11 verbatim ("UniFFI exports ParticipationRecordView"). attestation_count_anchored
const-false = faithful documented flag, not a stub.

--- prior pass (HEAD a19aa5352) below: verdict COMPLETE ---
Review of branch `c3c-ts` (worktree agent-a1400c1b005b502a3, HEAD a19aa5352), 2026-06-29.
Verdict: COMPLETE.

Scope: two ops, native-only (WASM removed; worktree CLAUDE.md confirms "3 targets").
- `ucan_evaluate` (ADR-057 §7.2.4): read-only structured diagnostic counterpart to
  throwing gate `ucan_validate`. Core `evaluate_ucan` (validate.rs:780). NO runtime/Supervisor
  method by design — bridges call core directly via trait adapters (same as the gate);
  pipeline_wiring asserts bridge→core, not bridge→supervisor. Matrix op name = `evaluate`
  (capability[11]); py/ts true, swift/kotlin false WITH ADR-057 Decision-5 exemptions.
- `participation_record` (§7.3.2): core `compute_participation_record` + `ParticipationFacts`
  (the unsigned SDK-facing flattening) → `Supervisor::participation_record` (supervisor.rs:9728)
  → PyO3 participation_record / NAPI participationRecord / UniFFI participation_record →
  Python scp.py:1859 + TS scp.ts:2472. Matrix py/ts true, swift/kotlin false WITH exemptions.

Key facts verified:
- `attestation_count_anchored` (NEW field) lives on `ParticipationFacts` (core
  participation.rs:202, const ATTESTATION_COUNT_ANCHORED=false) + all 3 typed bridge records
  (pyo3 trust.rs:535, napi trust.rs:88, uniffi bridge.rs:1716) + both SDK shapes (py
  trust.py:216, ts types.ts:908 BehavioralRecord). NOT on the signed `ParticipationProfile`
  wire struct — correct: spec §7.3.2.1 profile only carries tool_invocation_count_anchored.
  Both anchored flags are legitimately constant-false (spec says attestation_count never
  Merkle-anchored; tool_invocation false until ADR-051) — NOT placeholder stubs.
- All 6 leaf facts sourced from event log (target_did/subject_did keying via
  scp_event_log::payload::project_payload); attestation_count sourced from
  credential layer. Bridges thread verified attestations (NOT empty) via
  scp_ffi_common::trust_store::verified_attestations (verify-on-ingest: verify_and_cache
  before count). Both halves complete: verified_attestations + populate_and_aggregate agree
  by construction (same cache/resolver/clock).
- CTX_2076 ("SCP-CTX-2076", empty-log/NoParticipationFacts) defined ONCE
  (error_codes.rs:357), mapped in all 3 bridges (pyo3 error.rs:459+trust.rs:660, napi
  error.rs:276+trust.rs:486, uniffi bridge.rs:1167+14919), branched by both SDKs
  (py trust.py:46/761/803, ts scp.ts:59/2410) — folds empty log → zeroed record.
- ADR renumber clean: this branch's ADR-055→ADR-057 (commit 51d9ba98f). ADR-057 lives in
  phase-2.md:1961 (by subject, not number). The OTHER ADR-055 (WASM removal) lives in
  phase-4.md — PRD ADR-055 refs are all WASM-removal context, not this work. No stray.
- Phantom provenance FIXED not introduced: old spec said attestation_count counts
  `AttestationPublished` events — no such EventType exists in code. Diff corrects spec to
  credential-layer sourcing across §7.3.2, §7.3.2.1, ADR-051, §9 security-model,
  00-open-questions — all internally consistent (attestation = credential-layer artifact).
- pipeline_wiring: 7 assertions (3 ucan_evaluate→core evaluate_ucan; Supervisor→core +
  3 bridges→Supervisor for participation_record). ffi_conformance ADD: event_log_query
  project_payload parity (expanding coverage, not weakening).
- validate-prd.py PASS (exit 0, 369 stories); check-sdk-coverage.py PASS (exit 0, 0 errors).

Note for future: matrix has TWO `evaluate_trust` entries (capability[4] kotlin=false
"only aggregate_trust_input" exemption; capability[17] all-true). Distinct capability
sections, both pass coverage. Pre-existing structure, not this change set.
