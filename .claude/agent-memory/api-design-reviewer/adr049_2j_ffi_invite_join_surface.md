---
name: adr049-2j-ffi-invite-join-surface
description: API review of ADR-049 2J invite/join FFI slice (SealedInvitation, InviteMemberOutcome) — cross-binding consistency findings
metadata:
  type: project
---

# ADR-049 Phase 2J FFI invite/join surface review (branch feat/adr049-2j-ffi-slice, HEAD cef1c681d)

Reviewed the new public surface across all 4 SDKs + 3 bridges + runtime supervisor.invite_member.

**Verdict: NEEDS REVISION.** Two must-fix; three moderate; several observations.

Key findings (reusable patterns):
- **Re-box footgun (MAJOR):** invite_member `Sealed` outcome carries only (enc, ciphertext, delivered) — NOT context_id/creator_did. But `context_join_from_welcome` consumes a `SealedInvitation`(context_id, creator_did, enc, ciphertext). Every SDK ships identical hand-assembly boilerplate in its example (the tell). Runtime already has both values (supervisor.rs:10560 takes context_id + creator identity). Fix: Sealed should carry a ready-to-use SealedInvitation + delivered. This is the biggest agent-authorability miss.
- **Ceiling precondition doc-parity (MAJOR):** invite routes through propose_governance_action_checked → checks `governance:propose` (supervisor.rs:10626) + SingleAdmin-admin. ONLY Kotlin (Scp.kt:833-835) documents the ceiling requirement; Python/TS/Swift say only "unauthorized inviter". Discoverability footgun on default-ceiling contexts.
- **RequiresGovernanceApproval is a no-op-as-success (MODERATE):** non-SingleAdmin governance returns RequiresGovernanceApproval{proposal_id:None} but does NOTHING (supervisor.rs:10594-10600 "not yet implemented"). Success indistinguishable from no-op; proposal_id always None.
- **Naming collision (MODERATE):** `Sealed` (invite output variant) vs `SealedInvitation` (join input type) — both "Sealed*", overlapping-but-different fields.

Consistent (good): SealedInvitation 4-field shape identical across all 4 (modulo case/bytes-type). InviteMemberOutcome variant names + field presence + success-not-error identical; discrimination differs per-idiom (Python isinstance / TS kind-string / Swift+Kotlin native sum type) — correct.

Cross-binding divergences that are PRE-EXISTING / whole-SDK axis (not this slice's defect):
- inviter identity: Swift/Kotlin `identity: Identity` vs Python/TS `creator_did`/`owning_did: string`. SDK-wide uniffi-vs-string convention; slice conforms.
- context_create `mode`: NAPI capitalized "Encrypted"/"Broadcast" (default+returned) vs PyO3 lowercase-only "encrypted"/"broadcast" (context.rs:495). Real inconsistency, predates slice, matters because invite needs an Encrypted context.
- reserve_key_package: Python positional `tuple[str,bytes]` vs TS/Swift/Kotlin named `ReservedKeyPackage{reservationId,keyPackagePublic}`.
