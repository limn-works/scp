---
name: c3c-ts-behavioralrecord-divergence
description: c3c-ts review — CapabilityValidation/ucanEvaluate surface APPROVED across 4 bindings, but Python BehavioralRecord field shape diverges from TS + spec (BLOCKING)
metadata:
  type: project
---

Branch `c3c-ts` review (structured CapabilityValidation + optional-capability ucanEvaluate). Verdict NEEDS REVISION, one blocking item.

APPROVED portion (sound, consistent, evidence from both SDKs):
- `CapabilityValidation` six bools identical Py/TS (casing only): tokens_valid/signatures_valid/within_ceiling/nonce_valid/not_revoked/time_bounds_valid. Order + types match.
- `all_valid` (Py property) ↔ `allValid(v)` (TS free fn) parallel; correct happy-path AND collapse; steers consumers, prevents silent field omission on new stage.
- Six bools (not enum) is correct: independent non-mutually-exclusive axes, conjunction not state-choice — "enums over booleans" tenet targets mutually-exclusive choices, N/A here.
- Optional `capability` uniform across all 4 bridges (PyO3 Option<&str>, NAPI/UniFFI/WASM Option<String>), same empty/whitespace→absent `.filter(|c| !c.trim().is_empty())` + `.transpose()` optional-parse.
- Diagnostic vs gate well-distinguished; presenting_agent_did WARNING doc-blocks (aud==aud tautology → trust inflation) excellent + consistent; WASM correctly REQUIRES expected_aud_did instead of defaulting.
- Py return types as precise as TS (TYPE_CHECKING import + `from __future__ import annotations` avoids trust.py circular import).
- `toCapabilityValidation` (TS internal/bridge.ts) pins six-field projection in ONE place across native+WASM; `wrapBridgeErrors` Proxy single error chokepoint (async/sync preserved, handles not deep-proxied for affinity).
- Deletion of Py `_classify_ucan_error`/`_PASSED_BEFORE` prose-classification = correct (spec §7.2.4 forbids prose reverse-engineering).

BLOCKING: Python `BehavioralRecord` (trust.py:127) diverges from TS `BehavioralRecord` (types.ts:858) AND from spec §7.2.4 authoritative names (07-trust...md lines 219-221, 243-246).
- TS (matches spec): participationCount, participationDurationSeconds, toolInvocations, governanceActionsBy, governanceActionsAgainst.
- Py (wrong): contexts_participated, total_duration, governance_actions_against, tool_invocations, role_history, endorsement_accuracy — MISSING governance_actions_by; wrong names (contexts_participated vs participation_count; total_duration vs participation_duration_secs).
- toolInvocations MAP itself WAS converged (dict[str,int]↔Record<string,number>, "ToolInvoked" bucket) — but enclosing record + population logic were not. Py evaluate_trust sets contexts_participated=1 + no governance counts; TS sets participationCount=rawEvents.length + counts GovernanceActionExecuted/GovernanceActionAgainst.
- Fix: rename Py fields to spec/TS, add governance_actions_by, converge population.

How to apply: when re-reviewing c3c-ts, confirm Python BehavioralRecord aligned to spec field names + governance counts populated. The CapabilityValidation/ucanEvaluate surface itself needs no further changes.
