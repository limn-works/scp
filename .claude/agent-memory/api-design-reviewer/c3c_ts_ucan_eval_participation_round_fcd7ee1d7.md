---
name: c3c-ts-ucan-eval-participation-fcd7ee1d7
description: c3c-ts round @fcd7ee1d7 — ucan_evaluate/participation_record typed across Py+TS; required presenting_agent_did reorder + typed CachedAttestation converged; 1 MED evaluateTrust mislabel footgun
metadata:
  type: project
---

c3c-ts worktree HEAD @fcd7ee1d7 (WASM removed; 3 native bridges + Py/TS SDKs). NEEDS REVISION, 1 MEDIUM blocker.

**CONVERGED (evidence both SDKs):**
- Required `presenting_agent_did` + reorder IDENTICAL both SDKs. `ucan_evaluate`=(ctx/handle, token, presentingAgentDid REQUIRED, capability?, proof?) — PA before optional capability. `ucan_validate`=(ctx/handle, token, capability, pa, proof?). Native WIRE order identical across bridges `(ctx,token,capability,pa,proof)` (PyO3 call scp.py; NAPI call internal/native.ts); both SDKs reorder public evaluate identically. Fail-closed real+symmetric (bridge rejects empty PA; no aud==aud default).
- Typed `CachedAttestation`/`CachedAttestationEnvelope` at PARITY: Py TypedDict (total=False envelope) ⟷ TS interface, both serde snake_case wire (not SDK camelCase), pass-through json.dumps/JSON.stringify. Field sets match Rust serde.
- BehavioralRecord 12 fields IDENTICAL modulo casing incl attestation_count_anchored + tool_invocation_count_anchored. Empty-log: BOTH branch on structured code SCP-CTX-2076 (never prose) → all-zeroed record (Py BehavioralRecord(subject_did=) defaults / TS explicit zero literal), re-raise everything else.
- CapabilityValidation 6 bools both, populated via SINGLE shared projection (structured_to_capability_validation / toCapabilityValidation) so no field silently dropped. Py prose-classification machinery (_classify_ucan_error, _PASSED_BEFORE, prefix tuples) fully DELETED. Single error chokepoint both: Py _coded_bridge_error / TS wrapBridgeErrors Proxy.
- Py return types fixed: ucan_evaluate -> CapabilityValidation, participation_record -> BehavioralRecord (prior `-> Any` LOW findings CLOSED).

**MEDIUM (blocker, NEW this diff, TS-only):** SCP.evaluateTrust(scp.ts) takes BOTH a context `handle` AND a separate `contextId` string. Layer1 vs handle; Layer2 vs `resolvedContextId = handle.contextId ?? contextId`; but RETURNS bare `contextId` label. handle for ctx-A + contextId="B" → computed-for-A, labeled-B silent lie. Root cause intra-TS addressing split: ucanEvaluate is HANDLE-keyed, participationRecord is STRING-keyed (Python keys BOTH uniformly by context_id string → mismatch structurally impossible). Fix: return contextId:resolvedContextId (min) OR unify TS addressing model (both handle or both string) to match Py.

**LOW/OBS:** all_valid (Py dataclass property) vs allValid(v) (TS free fn — TS interface data-only) call-shape asymmetry; CachedAttestationEnvelope.evidence loosely typed Py dict[str,Any] vs precise TS object; Py ucan_validate -> Any vs TS Promise<void> (→ None); capability/PA relative order swapped between evaluate vs validate (forced required-after-optional, symmetric+documented); internal Bridge.ucanEvaluate marks PA optional (wire-shaped) vs public required.

Supersedes prior round [[c3c_ts_typed_trust_records_round]] (which flagged REVERSED asymmetry Py untyped list[dict] input — NOW typed, CLOSED) and [[c3c_ts_ucan_eval_participation_record]].
