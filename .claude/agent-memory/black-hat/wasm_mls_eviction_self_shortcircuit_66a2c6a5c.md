---
name: wasm-mls-eviction-self-shortcircuit-66a2c6a5c
description: Re-attack of WASM gov RemoveMember at 66a2c6a5c (self-DID short-circuit + own-leaf skip, dup-leaf parity) — CLEAN, no exploitable divergence after genuine probing
metadata:
  type: project
---

# WASM gov RemoveMember self-DID short-circuit (commit 66a2c6a5c) — CLEAN convergence result

Builds on b98c5b1a9 (MLS eviction) + f761c7d2b (own-leaf skip). 66a2c6a5c ADDS the second native mechanism: `remove_member_by_did` now ALSO short-circuits `if self.own_did()? == member_did { return Ok(Vec::new()) }` BEFORE the leaf scan (group.rs:347), mirroring native provider.rs:1041. `own_did()` (group.rs:203) derives the local DID from the committer's OWN leaf via `own_leaf_index()` (no stored field — correct for creator leaf-0 AND Welcome-joined non-zero leaf). This closes the dup-DID-OWN-leaf case f761c7d2b left latent: a SECOND leaf carrying the local DID is no longer resolved/evicted (short-circuit returns first), matching native (evicts neither).

## Why: native oracle (verified file:line)
- provider.rs:1041 self short-circuit `member_did == self.local_did` → RemoveMemberOutput::default() (empty).
- provider.rs:1060 own-index skip in scan `if member.index == own_index { continue }`.
- governance_helpers.rs:1231 execute_remove_member: membership.contains → crypto.remove_member FIRST (hard boundary) → remove_member_sender_key → rotate_sender_key → strip membership/role_state/access/peer_registry → emit MemberLeft buffer → broadcast commit → THEN append_context_event(MemberLeft, actor_did=executor, ts) → checkpoint++. finalize appends GovernanceActionExecuted AFTER.
- builder.rs:187 append_context_event uses EventPayload::default() (EMPTY payload).
- event_log.rs:74 native runtime `append` builds Event{signature: Vec::new(), ...} → append_unsigned_event. WASM manager.rs:489 append_log_event builds the IDENTICAL Event (empty sig, same seq via event_count, same prev_hash) → same append_unsigned_event. Leaf preimage includes signature (tree.rs:278) but BOTH are empty-sig at runtime → tree::root converges.

## Probes run (all PASS, reverted zero-diff)
1. Welcome-joined member (non-zero own leaf) as committer evicts creator at leaf 0 → own-leaf skip uses ACTUAL own_index not hardcoded 0; self still no-op. PROVES "do NOT hardcode 0" claim.
2. Dup-DID NON-self (two "dave" leaves) → remove-by-did evicts ONE per call (break-on-first parity), epoch +1 each, both eventually evictable.
3. 41-member group middle eviction → no panic, epoch +1, self still no-op.
4. FULL E2E through real execute_governance_action on ENCRYPTED ctx w/ real Bob MLS leaf → non-empty hex commit, epoch +1, Bob removed, EXACTLY 1 empty MemberLeft(actor=executor, ts=convergent created_at) + 1 GovActionExecuted(same ts), MemberLeft precedes Executed.
- All 379 WASM lib tests + 8 cross_impl conformance tests GREEN.

## Attack surfaces CHECKED and HELD
- Partial-leaf divergence on wrapper: `parse_proposal_id_bytes(proposal_id)?` runs AFTER dispatch appends MemberLeft in success branch (manager.rs:~3192). UNREACHABLE-with-failure: all gov bridge entry points validate via validate_proposal_id_hex at boundary (context.rs:752/823/...), AND propose path re-parses at 4380 BEFORE auto-execute. Belt-and-suspenders redundancy, not a bug. No path appends MemberLeft then fails before GovActionExecuted.
- Rollback (manager.rs:3171) only removes executed_proposals on dispatch Err; dispatch_remove_member fails ONLY at MLS-eviction step (before any strip/leaf) → no leaf to roll back. Fail-closed-KEEP: member stays in ctx.members, NO MemberLeft (existing test proves).
- Evicted member decryption: state.rs test evicted_member_cannot_decrypt_after_removal_and_rotation PROVES Bob's stale state can't decrypt post-eviction (epoch advance is the lockout); Carol (remaining) can.
- own_did() decode failure → RemoveMemberFailed (fail-closed); destroyed group → GroupDestroyed propagates.
- commit-hex weaponization: documented at all 3 layers (context.rs/wasm.ts/scp.ts) — WASM has NO auto-broadcast (ADR-034); caller MUST relay or MLS forks. Honest liveness-gap disclosure, NOT a security hole (committer's local durable log identical to native).

## Orthogonal pre-existing (NOT this change, NOT a regression)
- Consequence dispatch (manager.rs:~3247) uses local crate::time::now_secs() — the documented #1861 consequence-window limit (Slice 3). RemoveMember itself appends only MemberLeft+GovActionExecuted, both convergent-ts.
- Native auto-broadcasts eviction commit (try_broadcast_commit_or_enqueue) vs WASM manual-relay — transport asymmetry, ADR-034, not tree::root divergence.
- Conformance KAT still HAND-REPLAY (does not invoke execute_remove_member; scp-runtime test crate can't dep scp-ffi-wasm cdylib). Pre-existing structural gap; both real paths (native gov tests + WASM dispatch tests) read+match independently.

## VERDICT: no CRIT/HIGH/MED/LOW found after genuine effort. Self-removal parity is sound via BOTH mechanisms; all RemoveMember variants (normal/self/creator/missing-leaf/dup-DID-self/dup-DID-nonself/non-zero-own-leaf-committer/large-group) converge. CLEAN — valid convergence-check outcome.
