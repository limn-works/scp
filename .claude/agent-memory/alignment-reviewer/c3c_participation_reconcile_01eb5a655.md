---
name: c3c-participation-reconcile-01eb5a655
description: C3C participation-record §7.3.2 reconcile (canonical leaves + credential-layer attestation_count) review — ALIGNED, 1 LOW doc finding
metadata:
  type: project
---

# C3C participation reconcile @ b4c0cf9c2 + 01eb5a655 (branch c3c-ts-work) — 2026-06-29 — ALIGNED

Reviewed two commits for §7.3.2/§7.3.2.1 alignment. Spec was already reconciled upstream in 012bba8f5 (spec edits out of scope). WASM being removed — ignored.

- **b4c0cf9c2** feat(ffi): project subject_did through PyO3/NAPI/UniFFI event_log_query (alongside existing target_did), all via single shared `scp_event_log::payload::project_payload`; key omitted on None.
- **01eb5a655** refactor(trust): reconcile compute_participation_record to canonical leaves + credential-layer attestation_count.

**All 7 locked semantics verified EXACT** (participation.rs / aggregate.rs / payload.rs):
- governance_actions_against = GovernanceActionExecuted, projected target_did==subject, adverse-filtered (participation.rs:191-204; ADVERSE_ACTION_TYPES positive closed allowlist :360, H18 defense)
- governance_actions_by = actor_did==subject (177-186)
- role_progression = RoleAssigned projected subject_did==subject (206-217)
- participation_duration = MemberJoined/MemberLeft interval walk on projected subject_did, rejoin sums, still-joined→latest_event_ts−joined (224-260)
- context_creation_count = ChildContextCreated if actor==subject (220-222) — correctly NOT legacy ContextCreated
- tool_invocation_count = local ToolInvoked, anchored=false (170-173, 970); flag in signed preimage (signable_bytes:592)
- attestation_count = credential layer ONLY: credential_attestation_history filters accessible_attestations by subject + RevocationStatus::Active (291-303); profile = attestation_history.len() (973). NEVER event log.

**Key wiring**: aggregate_trust_input (aggregate.rs:334-382) calls get_verified_attestations FIRST (TTL re-verify, drops revoked), then threads into compute_participation_record as accessible_attestations. Verifier-relative; lifecycle/proposer callers pass empty slice → count 0 (spec-correct).

**project_payload grounds the two-field model** (payload.rs:355-377): GovernanceActionExecuted/AccessRevoked→target_did; RoleAssigned/MemberJoined/MemberLeft→subject_did. All 3 bridges surface both, byte-identical. Per-bridge positive tests pin RoleAssigned surfaces subject_did and NOT target_did (UniFFI bridge.rs:16919-16921).

**ONLY finding (LOW, doc-only)**: participation.rs:85 field doc says "Number of `ContextCreated` events" but field computes from ChildContextCreated (a DISTINCT, still-existing EventType — self-creation of this context vs child-creation). Comment misnames leaf; code correct; test comment at :1420 already says ChildContextCreated. Phantom-provenance-in-comment class. Fix: rename to ChildContextCreated.

Verdict ALIGNED, 0 blocking/0 material/1 LOW. No leftover legacy semantics (no actor-keyed "against", no event-sourced attestation count, no legacy ContextCreated match arm).
