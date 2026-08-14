# c3c-ts (ADR-055) structured UCAN CapabilityValidation review

Branch c3c-ts: optional `capability` (Option<&CapabilityUri>) for `evaluate_ucan`; structured CapabilityValidation across 4 bridges; SDK trust consumers.

## Findings
- **MEDIUM — SCP.evaluateTrust reads event.payload but SCP.eventLogQuery returns raw NAPI shape (payloadJson string, no `payload`).** scp.ts:2365 `event.payload?.toolId` always undefined → toolInvocations always bucket under literal "ToolInvoked"; tool-id aggregation dead on real NAPI. The CORRECT transform exists only in internal/native.ts:1149 (Bridge.eventLogQuery parses payloadJson→payload), but SCP.evaluateTrust uses SCP.eventLogQuery (scp.ts:2038) which returns raw. Also NAPI manager-entries path sets payload_json={"hash":...} (no toolId at all). The `as readonly Event[]` cast is unsound.
- **LOW (test) — tautological mock in trust.test.ts:409** "builds Layer-2 behavioral record from ToolInvoked events": mock eventLogQuery returns events with `payload:{toolId}` (object), a shape real NAPI NEVER returns (it returns payloadJson string). Test asserts toolInvocations={calculator:2} which can't happen against real bridge. real-napi.test.ts only asserts behavioralRecord toBeDefined() — never asserts toolInvocations content. So the payload bug is masked.

## CLEAN (verified correct)
- Core evaluate_ucan Option<&CapabilityUri>: step-6 grant-match skipped on None; within_ceiling (step 8) independent; fail-closed preserved; docs accurate.
- All 4 bridges: empty/whitespace capability coerced to None via filter(|c| !c.trim().is_empty()); parse via map+transpose; pass required_cap.as_ref(). Consistent.
- NAPI NapiCapabilityValidation #[napi(object)] auto-camelCases tokens_valid→tokensValid; TS reads camelCase. WASM serde rename_all=camelCase, JSON.parse'd to JS object; TS reads camelCase. Both correct.
- Python evaluate_trust: passes subject_did as presenting_agent (fixes audience tautology aud==aud); &= AND-combine correct; None capability = intrinsic mode. ucan_evaluate arg order correct (context_id, token, None, subject_did) vs PyO3 sig.
- Python Layer-2 buckets by event_type only (no payload dep) — NOT affected by payload bug.
- mapBridgeError pass-through: `if (error instanceof ScpError) return error` avoids downgrading typed errors to SCP-UNKNOWN-0000; doesn't mask raw errors. wrapBridgeErrors proxy: maps sync throw + async rejection, preserves handle identity (no deep-proxy). Correct.
- Deleted test_ucan_conformance.py (613 lines): only tested removed _classify_ucan_error/_PASSED_BEFORE/_extract_core_error. Justified deletion, not dropped assertions.
- Python event_log_query takes dict {"actor_did":...}; TS EventFilter uses actorDid, NAPI accepts both actor_did|actorDid. Correct.
- all_valid / allValid accessors: correct 6-way AND, mirror each other.
