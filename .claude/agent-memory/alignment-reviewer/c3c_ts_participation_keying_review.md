---
name: c3c-ts-participation-keying-review
description: ALIGNED review of branch c3c-ts-work (012bba8f5..HEAD) — 7 participation facts keyed per spec §7.3.2; attestation_count credential-layer; subject_did/target_did projected through 3 native FFI bridges
metadata:
  type: project
---

# c3c-ts-work participation-keying review (2026-06-29) — ALIGNED

Range `012bba8f5..HEAD` (4 commits): b4c0cf9c2 (FFI subject_did projection) / 01eb5a655 (canonical leaves + credential-layer attestation_count) / 779ad8422 (doc fix ContextCreated→ChildContextCreated + empty-action_type test) / bb066a519 (CI-gate fix + decode-governance-once).

Spec: `.docs/specs/07-trust-validation-and-capabilities.md` §7.3.2 / §7.3.2.1 / §7.4.

**Why:** Verified all 7 participation facts keyed exactly per §7.3.2 step-2; verified prior reviewer's "AttestationPublished at lines 158/161" claim.

**How to apply:** All 7 facts CORRECT in `crates/scp-protocol/src/trust/participation.rs` (compute_participation_record + record_governance_action + credential_attestation_history + produce_participation_profile) and `aggregate.rs` (aggregate_trust_input):
- gov_against: GovernanceActionExecuted/AccessRevoked → `target_did`, adverse-filtered (ADVERSE_ACTION_TYPES H18; empty action_type = conservatively adverse). Aligned in SPIRIT with §7.3.2:174 "warnings, role demotions, ejections."
- gov_by: actor_did==subject. role_progression: RoleAssigned projected subject_did==subject. duration: MemberJoined/MemberLeft on projected subject_did, sum-on-rejoin, still-joined→latest-event-ts. context_creation: ChildContextCreated if is_subject. tool_invocation: ToolInvoked actor==subject, anchored=false always. attestation_count = attestation_history.len() filtered subject-match + RevocationStatus::Active, NEVER from event log.
- Keying routed through shared `scp-event-log/src/payload.rs::project_payload`: Gov/AccessRevoked→target_did, RoleAssigned/MemberJoined/MemberLeft→subject_did. 3 native bridges (PyO3 src/event_log.rs, NAPI napi/src/event_log.rs, UniFFI uniffi/src/bridge.rs) project subject_did via same decoder, byte-identical, key-omitted-on-None. WASM excluded (correct).

**PRIOR REVIEWER CLAIM REFUTED:** spec has exactly ONE "AttestationPublished" mention (line 192), the CORRECT negation "There is no AttestationPublished event type." No stale assertion. No EventType::AttestationPublished variant exists (grep count 0). NO spec fix needed.

GOTCHA: EventType enum has BOTH `ContextCreated` (variant) AND `ChildContextCreated` (variant) — distinct. Spec wants ChildContextCreated; code counts ChildContextCreated; 779ad8422 fixed a stale doc that said ContextCreated. Real semantic divergence, now resolved.

LEGACY CLEANUP confirmed: runtime test `participation_event_log.rs` flipped attestation_history.len() 1→0 (old test counted a "tool verify" event as attestation — the pre-unification event-log-sourced semantic, now credential-layer-only).

Runtime gating callers (governance_helpers/lifecycle_logic/messaging_helpers/tools/invoke) pass `&[]` accessible_attestations — spec-correct (verifier-relative, count 0, "producer without cache access"), justified by comments, NOT stubs.

Verdict: ALIGNED, 0 findings.
