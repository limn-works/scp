---
name: invite-member-structural-rebuild
description: Crypto review of invite_member routed through actor governance gate + single-raw-key collapse + staged_key_packages + add-commit broadcast (branch feat/adr049-2j-ffi-slice, HEAD 648d4d2fa)
metadata:
  type: project
---

# invite_member structural rebuild — crypto review (648d4d2fa, off 1bc5d3aa3)

SOUND overall. Routes invite_member member-add through actor governance (propose_governance_action(AddMember) -> execute_add_member), collapses the FFI `sign` closure into ONE raw `&ed25519_dalek::SigningKey` used for BOTH the governance admin self-vote AND the InvitationBundle signature.

## Single-raw-key collapse — SOUND (hardest item)
Three distinct domain separators, disjoint preimages, no cross-protocol confusion:
- proposal id: SHA-256("SCP-PROPOSAL-V1:" ...) — not signed, just an id
- admin self-vote: Ed25519 over SHA-256("SCP-VOTE-V1:" || proposal_id(32) || len||voter_did || len||vote_json || ts)  (governance/mod.rs sign_vote)
- bundle: Ed25519 over SHA-256("SCP-INVITATION-BUNDLE-V1:" || len||context_id || len||creator_did || 5x Fixed32 JCS hashes) (invitation_bundle.rs:212)
Key↔DID binding is ENFORCED by governance: SingleAdminEngine::propose (mod.rs:1569) signs admin self-vote with the raw key then verify_vote against key_resolver(proposer, Active) — a key that isn't creator_did's #active fails InvalidSignature. Same key signs bundle with bundle.creator_did=creator_did. So bundle.creator_did == governance-authorized proposer == admin == 0xFF02-committed creator (joiner-verified). Attacker supplying victim_did+attacker_key => verify_vote fails => Err. Non-admin => NotAdmin => Err. Collapse genuinely REMOVES the two-input divergence class (proposal-signed-A / bundle-claiming-B).

## Commit broadcast fix — SOUND
execute_add_member (governance_helpers.rs:1229) now calls try_broadcast_commit_or_enqueue with commit_for_broadcast=add_output.commit_bytes.clone() (the Commit, NOT Welcome) + CommitOperation::AddMember{target_did}. Parity with remove(1373)/reset(2356). try_broadcast only transport.send_message()s (or enqueues on failure) — does NOT self-apply, so admin (already at epoch N+1 from add_member) doesn't double-apply. Add path adds an is_empty() guard remove lacks (safer). No epoch hazard vs buffered WelcomeGenerated (disjoint recipient sets).

## staged_key_packages — SOUND (public KPs)
DashMap<([u8;32],String),Vec<u8>> keyed (context_id, invitee_did). stage overwrites; add_member(None) remove()s exactly-once; unstage on ALL non-success paths (propose Err / voting-None / unexpected Some). KPs are public. No cross-invitee leak (did in key). LOW: unstage-on-voting-defer means when the (currently UNBUILT) voting approve->execute path lands, the staged KP is already gone — execute_add_member(None) will find nothing. Documented out-of-scope but latent.

## BLACK-2J10-001-R — STILL CLOSED
Diff doesn't touch 0xFF02 creator_did commit or joiner verify_against. Only added LIFECYCLE_TIMEOUT around the 2 custody awaits (bootstrap-DoS fix) + Zeroizing on bundle_wire in spawn_actor_from_welcome. Test N regression intact.

## Zeroization — GOOD
InvitationKeyMaterial is #[derive(ZeroizeOnDrop)] (context_metadata_key zeroes when bundle drops). `wire` now Zeroizing. spawn bundle_wire now Zeroizing. Key crosses mailbox as SigningKeyBytes(Zeroizing<[u8;32]>) (commands.rs:534). No key logged.

## Residual (pre-existing, not regressions)
- Ghost-leaf: MLS add + role_state + Commit broadcast are irreversible and happen BEFORE the fallible bundle seal/HPKE/deliver on caller task. Delivery failure => member in group who never gets Welcome. Broadcast now makes existing members actually advance epoch (more correct than before). Memory-tracked follow-up.
- No explicit test for SingleAdmin non-admin (NotAdmin) reject path of invite_member (M3 covers voting-defer only).
