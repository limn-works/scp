---
name: c3c-attestation-credential-layer-amendment
description: Review of c3c-ts commits 916d1be23/03d0eca8c — attestation removed from convergent-log requirement (SOUND for equivocation) but ADR-011 subject_did leaf-payload claim is spec-ahead-of-code (phantom provenance)
metadata:
  type: project
---

# Attestation-as-credential-layer amendment (branch c3c-ts, commits 916d1be23 + 03d0eca8c)

Human decision (locked, do NOT relitigate): attestations are credential-layer (DID-doc entries, relay blobs, TrustProtocolRepository cache; §7.4), revocable, selectively presented — NEVER context-event-log Merkle leaves.

## Crypto soundness verdict: SOUND on the equivocation question (items 1-3)
- §9.9.3 equal-count/equal-root equivocation test is UNAFFECTED by removing "attestation" from the convergent-log enumeration. Verified: NO `AttestationPublished`/`AttestationRevoked` EventType variant exists (grep of phase-2.md EventType enum + crates/scp-event-log/src/lib.rs). `AttestationRevoked` exists ONLY as a `TrustError` variant, never EventType. Attestations were NEVER appended to the canonical log → the removed mention was aspirational/phantom. Removal is purely corrective; nothing in the equivocation argument depends on attestations being convergent.
- Added clarifier (attestations verified by own envelope sig + revocation status per §7.4.4, not Merkle-anchoring) is cryptographically accurate.
- attestation_count as credential-layer / on-demand / verifier-relative / NON-Merkle fact (while other 6 facts stay Merkle-anchored) introduces no soundness problem — participation aggregate is unsigned local computation anyway; only per-context ParticipationProfile (§7.3.2.1) is signed and its attestation_count was always a self-reported field, not Merkle-proven.

## CRITICAL finding (item 4): ADR-011 subject_did leaf-payload claim is SPEC-AHEAD-OF-CODE
- ADR-011 amendment text claims: `RoleAssigned` carries `RoleAssignedPayload { subject_did, role }`; `MemberJoined`/`MemberLeft` carry `{ subject_did, role_name }`; project_payload surfaces subject_did.
- REALITY on origin/c3c-ts: payload.rs has NO RoleAssignedPayload, NO membership-change payload, NO `subject_did` field. `project_payload` handles ONLY GovernanceActionExecuted + AccessRevoked, projecting a field named `target_did` (Option<String>). EventPayloadProjection has only `target_did`.
- Emit sites: governance_helpers.rs MemberJoined/MemberLeft/RoleAssigned call `append_context_event(...actor_did...)` → builder.rs default passes `EventPayload::default()` (EMPTY). So these are empty-payload leaves carrying only actor_did (= the ADMIN for admin-driven actions, NOT the affected member). The spec's participation-attribution fix (attribute to affected member via subject_did) is NOT implemented.
- Naming mismatch: spec says `subject_did`; code says `target_did`.
- Artifact-flow violation (CLAUDE.md INVARIANT): spec/ADR documents implementation that does not exist on this branch. The "one-way pre-release leaf-preimage bump" / "old empty-payload leaves project subject_did=None" narrative describes a future state as if current.

## Branch topology gotcha
- Working dir was on `c3c-ts-work` (HEAD 1620de983) — the 5 review commits live on `origin/c3c-ts`, NOT an ancestor of the checked-out branch. Had to `git show origin/c3c-ts:...` to read the real reviewed state. Always verify the commits are ancestors of HEAD before reading working tree.
