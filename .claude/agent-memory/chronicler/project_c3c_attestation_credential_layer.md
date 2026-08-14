---
name: c3c-attestation-credential-layer
description: c3c-ts branch amendment (916d1be23/03d0eca8c) — attestation_count is credential-layer not a context event; downstream impl + PRD still source it from event log
metadata:
  type: project
---

LOCKED decision (branch c3c-ts, commits 916d1be23 + 03d0eca8c, 2026-06-28): attestations are credential-layer (DID-doc/relay-blob/TrustProtocolRepository cache, §7.4), NEVER context-log events. `attestation_count` is on-demand, verifier-relative, non-Merkle-anchored. role/membership leaves (`RoleAssigned`, `MemberJoined`/`MemberLeft`) gain `subject_did` in their EventPayload for participation-fact attribution. No EventType variant added/removed (no `AttestationPublished`/`AttestationRevoked`).

**Why:** the equal-count/equal-root equivocation test (§9.9.3) is only sound over convergent leaves; attestations are verifier-relative so they were never convergent — keeping them in the log enumeration was a latent bug. Attribution must follow the affected member (subject), not the governance actor (admin) who executes admin-driven joins/role-changes.

**How to apply:** the SPEC/ADR amendment itself (4 files: spec 07, spec 09, phase-2 ADR-011, ADR-051) is internally consistent and cross-refs all resolve. BUT downstream artifacts diverge and need follow-up before this can be called done:
1. `crates/scp-protocol/src/trust/participation.rs` — `attestation_history` is populated by scanning the event log for `EventType::ToolVerified` ("attestation-adjacent activity"). Directly contradicts the locked decision. `attestation_count = attestation_history.len()` therefore counts a context event, not credential-layer endorsements.
2. `crates/scp-runtime/tests/participation_event_log.rs:386` asserts `attestation_history.len()==1` from a ToolVerified event — codifies the wrong sourcing.
3. PRD `.docs/prds/main.json` (SCP story ~line 3544/3579) defines ParticipationRecord with `attestation_history` and likely AC sourcing it from the log.
4. `.docs/specs/00-open-questions.md:30` "Resolved" text still lists attestations among the 7 fact categories computed from event-log slices.

Per artifact-flow invariant, the spec is now authoritative; code is downstream and must be fixed to compute attestation_count from the credential layer (envelope-sig + revocation-status filtered), not the event log.

Minor doc nits in the amendment (non-blocking):
- ADR-011 EventType variant is `GovernanceAction` (legacy) + `GovernanceActionExecuted`; spec §7.3.2 step-2 uses `GovernanceActionExecuted`. Both exist in the enum — consistent, not a bug.
- §7.3.2 prose bullet (line 177) still lists "Attestation history" among facts "derivable from context event logs" — the lead-in sentence ("derivable from context event logs") is now slightly inaccurate for the attestation bullet specifically (it's credential-layer). Precision nit.
