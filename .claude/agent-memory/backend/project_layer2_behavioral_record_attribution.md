---
name: project-layer2-behavioral-record-attribution
description: Layer-2 behavioral-record participation-fact computation — which of the 7 spec facts are honestly attributable from event-log leaves TODAY vs blocked by missing subject-DID on leaf / missing EventType variant
metadata:
  type: project
---

Computing the spec §7.3.2 participation record (`.docs/specs/07-trust-validation-and-capabilities.md`) in both SDKs from `event_log_query`. Phase 1 (commits 385824ed2/e92e7db23/475022815 on branch c3c-ts-work) added `scp_event_log::payload::project_payload` exposing `target_did` for `GovernanceActionExecuted`/`AccessRevoked`. Phase 2 = compute the facts in TS `scp.ts evaluateTrust` + Python `trust.py evaluate_trust`.

**Why:** the old SDK code was broken — TS branched on non-existent `GovernanceActionAgainst` EventType (dead, always 0), set participationCount=rawEvents.length (self-inflatable), hardcoded duration=0; Python hardcoded contexts_participated=1.

**How to apply — attribution matrix of the 7 facts (verified by reading runtime emit sites):**
1. `participation_duration_secs` (MemberJoined/MemberLeft). Leaf carries `actor_did` + `timestamp`. SUBJECT-on-leaf is path-dependent: self-join/leave (`lifecycle_helpers.rs:985/362`) and broadcast subscribe/unsub (`broadcast_helpers.rs:120/193`) set actor_did = the member (CORRECT). BUT governance add/remove (`governance_helpers.rs:1233/1364` via `execute_add_member`/`execute_remove_member`, dispatch `:4090/4105`) set actor_did = the ADMIN executor; the affected member is param `did`, NOT on the leaf. So admin-driven membership is mis-attributed.
2. `governance_actions_against` = GovernanceActionExecuted where projected `target_did==subject`. FULLY computable today (Phase-1 projection). The one clean subject-keyed fact.
3. `governance_actions_by` = GovernanceActionExecuted where `actor_did==subject`. Computable today.
4. `tool_invocation_count` = ToolInvoked. ADR-051 interim-EXCLUDES ToolInvoked from the canonical Merkle log (`crates/scp-event-log/src/lib.rs:415`; built-not-appended at `crates/scp-runtime/src/context/tools/invoke.rs:197`). `event_log_query` does NOT return intra-context ToolInvoked. MUST set count=0, `tool_invocation_count_anchored=false`, cite ADR-051. Becomes real+anchored under ADR-051 causal-DAG count.
5. `context_creation_count` = ChildContextCreated where `actor_did==subject`. Leaf actor_did = creator (`governance_helpers.rs:1926`). Computable today.
6. `role_progression_count` = RoleAssigned where `subject_did==subject`. ONLY production emit = `execute_change_role` (`governance_helpers.rs:1417`) with actor_did=ADMIN executor, EMPTY payload, subject `did` NOT on leaf. NOT computable until a subject DID is added to the RoleAssigned payload+projection.
7. `attestation_count` = AttestationPublished. **No such EventType variant exists** — closed enum in lib.rs; the only `AttestationPublished` mention in the whole repo is the one spec line §7.3.2 step 2 (verified by grep). No attestation event is ever appended. NOT computable; spec references a phantom event.

**Canonical struct shape** = core `scp_protocol::trust::participation::ParticipationProfile` (8 facts incl `_anchored`); SDK BehavioralRecord should mirror it. `ParticipationFact` enum (participation.rs:363) already has all 7 categories.

**Bridge facts:** `event_log_query(ctx, filter=None)` returns ALL events (filter optional; do NOT pass actor_did filter — against-counts need subject as TARGET). PyO3 returns event.payload as a Python DICT; NAPI/UniFFI return `payload_json` (JSON string, snake actor_did); WASM returns `payloadJson` (JSON string, camel actorDid). target_did lives inside the payload obj in all 4.

**ARTIFACT-FLOW BLOCKER (escalated to Alec):** facts 6 (role_progression) + 7 (attestation) cannot be honestly computed without upstream changes — fact 7 needs a NEW EventType variant + emit site (spec names a phantom event), fact 1's governance-path mis-attribution + fact 6 need subject DID added to leaf payloads (RoleAssigned, governance MemberJoined/MemberLeft). Adding DID fields to convergent Merkle leaves ripples through native↔WASM equivocation parity (§9.9.3). Per CLAUDE.md "code reveals spec is wrong → fix spec first." Do NOT fake/hardcode these — carry honest neutral value + flag, or fix the spec+runtime. See [[project-eventlog-committer-assigned-timestamp]].
