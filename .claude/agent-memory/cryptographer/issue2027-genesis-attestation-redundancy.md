---
name: issue2027-genesis-attestation-redundancy
description: Is #2027 GenesisAttestation redundant with the 0xFF02 MLS group-context extension? Verdict GENUINELY-NEEDED, not redundant, and extend-0xFF02 (option b) does NOT substitute.
metadata:
  type: project
---

# #2027 GenesisAttestation vs 0xFF02 — redundancy verdict (origin/main 093c5afca)

VERDICT: (c) GENUINELY-NEEDED. Not redundant with MLS-authenticated 0xFF02; and option (b) "just extend 0xFF02 to a full-ContextParams hash and drop the separate signature" is WRONG — the creator-DID signature is independently required as the authorship anchor.

**Why:** SCP deliberately splits genesis-param authentication into TWO anchors (spec §5.12.3.1 step 4 / §05-contexts.md line 1281, EXPLICIT):
- `0xFF02` (scp-mls group_context ext, `ScpContextExtension` in scp-protocol/src/context/group_context_extension.rs) is MLS-key-schedule-committed but commits only a SUBSET: context_id, creator_did (rule 8), context_mode, governance_policy_hash, ceiling_policy, ceiling_hash, parent lineage. It is set by "whoever created the group" → cross-checkable, NOT self-authenticating of creator authorship.
- A creator-DID Ed25519 signature authenticates the FULL genesis ContextParams — including the fields 0xFF02 does NOT commit: roles, ttl, memory_scope, economic_policy(.payee), consequence_rules, outlets. Today (SingleAdmin only) this is `InvitationBundle.signature` over `invitation_bundle_signing_hash` which includes `genesis_params_hash = SHA-256(JCS(context_params))` (scp-protocol/src/context/invitation_bundle.rs; runtime verifies at supervisor.rs:13570 `bundle.verify(&creator_vk)`, creator_vk resolved from bundle.creator_did #active).

Spec's own reasoning (line 1281): "the bundle signature alone proves only that the SIGNER authored the bundle, not that the signer is the group's real creator/admin ... which is why the creator identity is anchored in the MLS-committed extension, not the signature." → NEITHER half alone suffices. Anchoring creator authorship needs BOTH (a) a signature under the creator DID's key AND (b) rule-8 cross-check vs 0xFF02. An attacker CAN set 0xFF02.creator_did=X in a group they created (0xFF02 is just committed data); the distinguishing factor is they can't produce a signature under X's key.

**The governed gap #2027 closes:** governed contexts (Threshold/Majority/Unanimity) execute AddMember post-quorum by a KEYLESS actor — NO creator key at execution → the invite-time bundle signature CANNOT be produced (today governed returns InvalidState/RequiresGovernanceApproval; ADR-049 line 493, matrix line 235). GenesisAttestation = creator signs full genesis params ONCE at creation (key present then), standalone artifact verifiable by any later joiner. Governed bundle assembled by keyless actor from: GenesisAttestation (non-0xFF02 params) + 0xFF02 (governance voter-set/ceiling/creator, MLS) + GovernanceApprovalCertificate (quorum SignedVotes authenticate the ADD decision, NOT the params). Clean separation: certificate authorizes membership change; GenesisAttestation authors params; 0xFF02 anchors identity+enforcement subset.

**Why option (b) fails:** extending 0xFF02 to full params gives "immutable genesis params of THIS group" but still not "creator DID X attests them" — MLS credential/GroupInfo sigs at a later epoch are by the (ephemeral, non-creator) committer, KeyPackage attestation is context-agnostic (binds leaf keys↔DID, does NOT sign params/context_id), and a late joiner cannot verify the genesis committer's DID from current state. So you'd STILL need a creator-DID signature. Extending 0xFF02 = redundant re-commit of the enforcement subset + pure-declaration fields that have nothing to enforce against, and removes nothing.

**For SingleAdmin, GenesisAttestation is a REFACTOR not new security** (unifies bundle-inline sig → one standalone authenticator). The NEW capability is strictly the governed/deferred path.

Q4 (operative params source): joiner installs FULL params from `InvitationBundle.context_params` (the "authenticated authority source"), authenticated by creator sig; `verify_scp_context_binding` (lifecycle_helpers.rs:2063) cross-checks only the 0xFF02 SUBSET vs the joined MLS group. Operative full params come from the signed bundle, NOT MLS state.
