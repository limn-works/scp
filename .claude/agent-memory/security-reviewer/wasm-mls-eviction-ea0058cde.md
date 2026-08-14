---
name: wasm-mls-eviction-ea0058cde
description: Security review of WASM governance RemoveMember MLS-eviction fix (branch fix/wasm-governance-mls-eviction, commit ea0058cde) -- found HIGH fail-open ordering bug
metadata:
  type: project
---

# WASM governance MLS eviction (commit ea0058cde) -- 2026-06-23

Branch `fix/wasm-governance-mls-eviction`. Adds WASM MLS eviction on governance RemoveMember
(mirrors native execute_remove_member in governance_helpers.rs ~1231-1356).

**Why:** previously WASM removed member from governance state but did ZERO MLS work; evicted
member kept group key schedule and could still decrypt. Fix evicts from MLS + drops/rotates sender key.

**How to apply:** the crypto primitives are correct (governance_remove_from_group / remove_sender_key /
rotate_sender_key in crypto/state.rs; remove_member_by_did + leaf_index_for_did in crypto/group.rs).
The security test in state.rs (evicted_member_cannot_decrypt_after_removal_and_rotation) is a real
3-party crypto proof. commit hex returned is public MLS MlsMessageOut -- no private material. Leaf
parity (empty payload, executor actor_did, convergent timestamp, MemberLeft-before-Executed) is correct.

## FINDING (HIGH) -- fail-OPEN ordering inversion in dispatch_remove_member (manager.rs ~3457-3497)
- WASM order: `ctx.members.remove(did)` FIRST (manager.rs ~3459), broadcast author cleanup, THEN
  MLS eviction `crypto.governance_remove_from_group(did)?` (~3486).
- Native order: MLS removal FIRST (hard boundary), all crypto fail-close, THEN strip membership;
  whole closure wrapped in commit_class_s_keep (fail-closed KEEP direction).
- On the `?` error path (MLS eviction fails -- group destroyed OR DID not in MLS tree = native↔WASM
  divergence, the EXACT documented trigger): member is ALREADY gone from ctx.members but STILL in MLS
  group, sender key NOT dropped, NOT rotated. Member removed from governance but can STILL DECRYPT.
- Rollback in execute_governance_action (~3173) only does `ctx.executed_proposals.remove(proposal_id)`
  -- does NOT restore ctx.members, does NOT undo broadcast block_author. No snapshot/restore anywhere.
- This reintroduces the very vuln the PR fixes, on the error path. FIX: reorder -- do MLS eviction +
  sender-key drop/rotate BEFORE ctx.members.remove (match native), so a crypto failure leaves member
  fully in place (fail-closed keep). Or snapshot+restore member entry on error.

## Non-findings (verified safe)
- commit hex = public MLS message, no key material.
- leaf_index_for_did first-match on duplicate DID = parity with native find_leaf_index_by_did.
- no-match returns RemoveMemberFailed (not swallowed) -- correct, surfaces loudly.
- documented no-ops (access-key store / routing registry / HPKE pending queue) genuinely absent in WASM.
