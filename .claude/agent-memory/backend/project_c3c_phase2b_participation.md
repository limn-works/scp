---
name: project-c3c-phase2b-participation
description: c3c Phase 2B — surface subject_did through 3 native bridges + reconcile stale Rust-core compute_participation_record + attestation_count credential-layer feasibility
metadata:
  type: project
---

STATUS: COMPLETE + PUSHED to c3c-ts (012bba8f5..d1fec867b), 2026-06-29. 6 commits: b4c0cf9c2 (3-bridge subject_did projection + tests), 01eb5a655 (compute_participation_record reconcile + credential-layer attestation_count), 779ad8422 (doc fix + empty-action_type test), bb066a519 (NAPI test CI-gating fix + governance single-decode), bd9740394 (decode-once consolidation), d1fec867b (undecodable-subject test). Double-zero reached (3 full review rounds + 2 confirmation reviews). LESSON: a NAPI test gated on `scp-ffi-napi/testing` (the crate's OWN feature) was SILENTLY excluded from CI — Cargo features don't flow in reverse; CI passes scp-core/testing which does NOT enable scp-ffi-napi/testing. Fix = gate on `allow_in_memory_custody` (CI enables it; test_append_event_log resolves via scp-core/testing→scp-runtime/testing transitively). ALSO: a reviewer false-positived a "stale AttestationPublished spec line" — spec was already correct (only mention at line 192 = the correct negation "There is no AttestationPublished event type"); ALWAYS verify a reviewer's cited line numbers against actual HEAD before acting. Task-3 outcome below stands: path (a) implemented; Phase 2C needs NEW FFI attestation-fetch wiring.

Phase 2B of participation-facts (branch c3c-ts-work, push target c3c-ts). Builds on Phase 2A which added `EventPayloadProjection { target_did, subject_did }` + `project_payload` in `crates/scp-event-log/src/payload.rs` (decodes RoleAssigned/MemberJoined/MemberLeft subject_did, GovernanceActionExecuted/AccessRevoked target_did).

**Three native bridges — projection pattern (mirror Phase-1 target_did exactly):**
- PyO3 `crates/scp-ffi/src/event_log.rs`: manager path `query_manager_entries` (~258-267) + storage fallback `query_storage_fallback` (~426-433). Pattern: `if let Some(x)=projection.target_did { payload_json["target_did"]=String(x) }`.
- NAPI `crates/scp-ffi/napi/src/event_log.rs`: manager path only (~149-158); NO typed-event storage fallback.
- UniFFI `crates/scp-ffi/uniffi/src/bridge.rs`: manager path (~12797-12809) + UCAN-state fallback (~12892-12904, gated on `payload_value.as_object_mut()`).
- Phase-1 positive test lives in: PyO3 `tests/e2e_bridge.rs::event_log_query_projects_governance_target_did_from_storage`; UniFFI `bridge.rs::event_log_query_projects_governance_target_did`; NAPI only has a NEGATIVE omission test in `context.rs::event_log_query_manager_path_omits_target_did_for_non_target_event`.

**Task 3 KEY ARCHITECTURE FINDING (attestation_count):**
`compute_participation_record` (crates/scp-protocol/src/trust/participation.rs) is consumed by MANY callers. Only `aggregate.rs::aggregate_trust_input` has the attestation cache (`AttestationCache<S>`) in scope — and it ALREADY computes `verified_attestations` separately (step 2) via `ctx.cache.get_verified_attestations(...)` but does NOT pass them into the participation record. The proposer-eligibility callers (governance_helpers.rs ~3567, invoke.rs ~836, lifecycle_logic.rs ~262, messaging_helpers.rs ~2031) do NOT have the cache and only read `participation_count`. So attestation_count CAN be sourced cleanly in aggregate.rs (count verified, non-revoked attestations) but NOT at proposer-eligibility sites — those don't need it.

**Why:** locked semantics say attestation_count = credential-layer (count of subject's accessible/valid endorsements), NEVER from event log. The old code faked it with `ToolVerified` events (`attestation_history`) — a stopgap to DROP.

**How to apply:** Switch compute_participation_record off legacy variants (GovernanceAction→GovernanceActionExecuted, ContextCreated→ChildContextCreated, drop ToolVerified attestation stopgap) and decode subject/target via project_payload (positional MessagePack) not ad-hoc JSON. EventType enum (crates/scp-event-log/src/lib.rs) still HAS legacy GovernanceAction(143)/ContextCreated(114)/ToolVerified(138) variants alongside canonical GovernanceActionExecuted(227)/ChildContextCreated(263)/RoleAssigned(126)/MemberJoined(122)/MemberLeft(124)/AccessRevoked(341). Update consumer test crates/scp-runtime/tests/participation_event_log.rs (uses legacy raw-DID-bytes payloads). NEVER touch WASM (being removed by another agent).
