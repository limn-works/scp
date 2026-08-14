---
name: c3c-participation-facts-keying-779ad8422
description: ALIGNED review of c3c-ts-work 012bba8f5..779ad8422 — 7 participation facts keyed per §7.3.2; attestation_count credential-layer; subject_did through 3 native FFI bridges
metadata:
  type: project
---

# c3c-ts-work participation-facts reconciliation @ 779ad8422 (2026-06-29) — ALIGNED

Range `012bba8f5..HEAD` (3 commits: b4c0cf9c2 FFI subject_did, 01eb5a655 canonical-leaf reconcile + credential attestation_count, 779ad8422 doc fix + empty-action_type test). Spec 07 §7.3.2/§7.3.2.1/§7.4 unchanged in range (correct — spec edits out of scope). Verdict ALIGNED, 0 blocking.

**All 7 facts keyed exactly per spec** (compute_participation_record in crates/scp-protocol/src/trust/participation.rs):
- governance_actions_against: GovernanceActionExecuted, projected target_did==subject, adverse-filtered (ADVERSE_ACTION_TYPES whitelist; empty/undecodable action_type = conservatively adverse, H18). ✓
- governance_actions_by: actor_did==subject. ✓
- role_progression_count: RoleAssigned, projected subject_did==subject (NOT assigning admin). ✓
- participation_duration_secs: MemberJoined/MemberLeft intervals keyed on projected subject_did; rejoin sums; still-open→latest_event_ts−lastjoin. ✓
- context_creation_count: ChildContextCreated && is_subject (actor==subject). ✓
- tool_invocation_count: ToolInvoked && is_subject; tool_invocation_count_anchored hardcoded false (ADR-051). ✓
- attestation_count: credential-layer via credential_attestation_history(accessible_attestations) — filtered subject + RevocationStatus::Active; = attestation_history.len(); NEVER event log. ✓

**Key reconciliation (legacy → canonical):** old code keyed legacy untyped `EventType::GovernanceAction`→`GovernanceActionExecuted`; `ContextCreated`→`ChildContextCreated`; dropped `ToolVerified`→attestation_history; attestation now credential-sourced. project_payload (crates/scp-event-log/src/payload.rs) is the SINGLE shared decoder: GovernanceActionExecuted/AccessRevoked→target_did; RoleAssigned/MemberJoined/MemberLeft→subject_did; empty string→None.

**FFI: subject_did through all 3 native bridges** via shared project_payload — PyO3 (src/event_log.rs manager+fallback), NAPI (napi/src/event_log.rs), UniFFI (uniffi/src/bridge.rs, refactored fallback to both keys). WASM ignored per scope.

**Wiring intact end-to-end:** production append sites emit subject-bearing payloads via append_membership_change_leaf(actor, subject, role) — governance_helpers.rs:1237 admin-driven join passes actor_did≠did(subject), the exact case actor-keying would break. aggregate_trust_input (aggregate.rs) threads get_verified_attestations (TTL+revocation-checked) into record. Runtime gating callers (governance/lifecycle/messaging/tools-invoke) pass &[] for accessible_attestations — documented verifier-relative count-0, NOT a stub. Supervisor::test_append_event_log is #[cfg(test/testing)]-gated.

**Findings:** LOW residual spec self-contradiction (out-of-scope to fix here): §7.3.2:158,161 algorithm step still says attestation_count = "Count of events with type AttestationPublished where actor_did==target_did" but (a) NO AttestationPublished EventType exists, (b) §7.3.2.1:193 says attestation_history.len(), (c) §7.3.2:224,250 + task endorse credential-layer. Code correctly follows the credential-layer reading. Flag for a future spec patch to delete the AttestationPublished algorithm line.
