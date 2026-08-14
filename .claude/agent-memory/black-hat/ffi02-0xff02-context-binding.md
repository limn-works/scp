---
name: ffi02-0xff02-context-binding
description: Residual gaps in the §5.13.3 0xFF02 context-params MLS binding meant to close FFI-02 (Welcome-joiner authority forgery)
metadata:
  type: project
---

# FFI-02 / §5.13.3 0xFF02 binding — residual attack surface

Branch `feat/adr049-2j-ffi-slice`. Spec uses 0xFF01 in text but CODE uses **0xFF02**
(spec §5.13.3 not updated to match — provenance drift). Extension =
`SHA-256(RFC8785-JCS(governance))` + `SHA-256(JCS(ceiling))` + ceiling_policy + mode +
context_id + parent lineage. Verify on join/import/restore via
`verify_scp_context_binding` (lifecycle_helpers.rs:1752) → `ScpContextExtension::verify_against`
(scp-protocol/src/context/group_context_extension.rs:333).

## Confirmed residual gaps (binding covers a NARROW subset of authority)

1. **HEADLINE — SingleAdmin admin-principal NOT bound.** `GovernanceModel::SingleAdmin`
   is a unit variant → `SHA-256(JCS(SingleAdmin))` is CONSTANT regardless of who the admin
   is. The admin = `creator_did`, which on the join path is UNTRUSTED caller input
   (`WelcomeJoinRequest.creator_did`, supervisor.rs:1021) passed straight into
   `build_welcome_joiner_state` → `create_governance_engine(&SingleAdmin, creator_did)` →
   `SingleAdminEngine::new(creator_did)` (state.rs:1781). NO cross-check that creator_did is
   even a member of the joined MLS group. A member-inviter (Mallory) sets creator_did=herself;
   extension check PASSES; victim installs Mallory as SingleAdmin. Full governance hijack of
   joiner's view. This is exactly the FFI-02 class ("creator=admin from unverified params")
   the fix claimed to close.

2. **economic_policy unbound** — payee DID/costs caller-chosen → financial redirection.
3. **tools unbound** — attacker-chosen tool registrations in joiner's context.
4. **consequence_rules/consequence_config unbound** — punitive automation (RevokeAccess).
5. **ttl unbound** (used at supervisor.rs:10844) — lifecycle split-brain.
6. **roles, memory_scope, counterparty_policy, metadata_visibility, sybil_policy,
   max_chain_depth, session_cap** all unbound — stored in handle.params(), used downstream.
   Only governance-model-shape + ceiling + mode + ceiling_policy are hashed.

7. **Child lineage NEVER committed in prod.** create path (builder.rs:859) always calls
   `for_root` — no `for_child`/`for_child_from_parents` call anywhere in production runtime.
   §5.13.3's core "unforgeable parent lineage" claim is unwired.

8. **verify_against does NOT re-verify parent_governance_hash** (structural-only, by design
   comment) and never compares extension's parent_context_ids to any expected lineage. Spec
   rule 5's hash-match is not enforced on join.

9. **Mid-epoch 0xFF02 rewrite (equivocation-lite)** — 0xFF02 deliberately kept OUT of
   RequiredCapabilities (context_extension.rs:51-55); no scp-mls rejection of inbound
   GroupContextExtensions proposals. A malicious member could commit a GCE proposal rewriting
   governance/ceiling; existing members don't re-verify (authority cached at join), future
   joiners bind the new value → governance split. Contingent on OpenMLS accepting the GCE
   proposal (RFC 9420 §12.1.6 permits it). Needs a confirming test.

## What genuinely resists
- Threshold/Majority/Unanimity bind their signer/voter DIDs (in the model → hashed).
- JCS+SHA-256 collision-resistant; canonicalization sound (KAT-pinned bytes + digest).
- rule-1: absent/malformed 0xFF02 → Err/Ok(None) → rejected fail-closed on join.
- Import is signature-anchored to creator_did (== exporter), so its admin IS authenticated;
  import skips binding only when mls_crypto_state empty (keyless/needs-reconnect).
- MLS folds group_context into key schedule → no cross-member equivocation WITHIN an epoch.
- Verify runs BEFORE install/build/persist/spawn; rejection leaves nothing half-installed.

## Root cause / fix direction
Spec §5.13.3 ScpContextExtension only defines governance+ceiling+lineage+mode hashes. Per
artifact-flow, closing gaps 1-6 requires SPEC change (add creator/admin DID binding + a
full-params hash, or commit creator_did into the extension). Gap 1 is fixable now by
cross-checking creator_did against the MLS ratchet-tree leaf credentials at join.
