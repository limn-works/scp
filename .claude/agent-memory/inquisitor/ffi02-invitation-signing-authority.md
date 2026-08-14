---
name: ffi02-invitation-signing-authority
description: FFI-02 signed InvitationBundle — what the creator signature must cover; why economic_policy/tools/consequence_rules are excluded from §5.7 structural metadata; the 0xFF01 root-cause divergence
metadata:
  type: project
---

# FFI-02 InvitationBundle signature scope — authority model per field

Interrogated 2026-07 on branch `feat/adr049-2j-spawn-from-welcome`. Question: for a signed
§5.12.3 InvitationBundle closing FFI-02, what must the creator signature cover, given the joiner's
`build_welcome_joiner_state` (supervisor.rs:10676) + `fresh_governance_state` (state.rs:1820) build
ENFORCEABLE economic/consequence authority from raw `WelcomeJoinRequest.params`?

**Why:** black-hat BLACK-2J10-002/003 flagged joiner enforcing authority from unauthenticated params.
**How to apply:** when reviewing the FFI-02 signing decision, the real gap is signed-artifact vs
enforced-artifact divergence + an unimplemented MLS binding — not the §5.7 visibility split.

## Findings
- **economic_policy** — deliberately OPERATIONAL in §5.7 (payee sensitive). But ENFORCED: joiner
  installs `params.economic_policy` → `message_pricing`; payee IS the payment target (§19 flow step 3
  `adapter.authorize(payer, payee, …)`), max_total is payer-SDK-enforced. Forged payee = real redirect.
  Consent guard = §19.3 hard rule (no auto-accept for paid contexts). MetadataSnapshot carries only an
  `Option<String>` summary — signing the snapshot does NOT authenticate the enforced `EconomicPolicy`.
- **consequence_rules** — §7.3.7 says "visible in context metadata before opt-in" but StructuralMetadata
  AND OperationalMetadata OMIT it entirely (spec-internal contradiction). Enforced (RevokeAccess gated on
  `allow_automatic_access_revocation`, params.rs:629/801). Unsigned + unbound. Real gap.
- **tools** — authenticated by a DIFFERENT mechanism (governed §6.2 registration + §7.7 provenance).
  Joiner does NOT enforce `params.tools`: both create+join set registered_tools/tool_interfaces=Vec::new().
  Tool ACCESS is bounded by the SIGNED ceiling (`tool:invoke:*`) + §5.12.2 no-auto-accept-for-tool-bearing.
  Latent completeness bug: initial `params.tools` silently dropped (comment "beyond initial ContextParams.tools").

## Root-cause divergence (upstream of the signing decision)
§5.13.3 mandatory `ScpContextExtension` (0xFF01) binding `governance_policy_hash`+`ceiling_hash` into the
MLS group_context is NOT IMPLEMENTED. 0xFF01 is instead assigned to `SCP_WRAPPING_KEY_EXTENSION_TYPE`
(crypto/mls/wrapping_extension.rs:36) — an ID collision. Validation rules §5.13.3(1,3,4,7) unenforced, so
the joiner has NO second (cryptographic) verification path and trusts params blindly for ALL fields,
including ceiling/governance that the spec assumed were group-identity-bound.

## Recommendation
Signing the lossy MetadataSnapshot ≠ authenticating the enforced full ContextParams. Either (A) sign the
full genesis ContextParams the joiner enforces (add EconomicPolicy struct + consequence_rules), OR (B)
re-derive economic/consequence from authenticated in-context state after join. Since spawn-from-Welcome is
the FIRST join of a NEW context (first-writer-wins enforced), genesis has no prior state ⇒ (A) is the
pragmatic close, but MUST also implement 0xFF01 so ceiling/governance cross-check the group identity, not
just a signature from the same inviter. Visibility (§5.7 structural/operational) is orthogonal to
authentication — a MemberOnly field can still be creator-signed inside the encrypted bundle.
