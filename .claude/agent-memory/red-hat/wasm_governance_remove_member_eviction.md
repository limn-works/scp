---
name: wasm-governance-remove-member-eviction
description: Red-team assessment of WASM governance RemoveMember MLS-eviction fix (commit 97c351df9, fix/wasm fail-closed MLS eviction). Core crypto property holds; residual chains are bridge-state desync + commit-distribution + sender-key non-distribution, all bounded.
metadata:
  type: project
---

# WASM Governance RemoveMember MLS Eviction (commit 97c351df9)

Branch `fix(wasm): fail-closed ordering for MLS eviction + accurate sender-key docs`. Files: crypto/group.rs (leaf_index_for_did + remove_member_by_did), crypto/state.rs (governance_remove_from_group/_sender_key/_rotate_sender_key + eviction security test), manager.rs (dispatch_remove_member ~3450-3557, execute_governance_action ~3078, fail-closed test ~9601), wasm_conformance.rs (mirror-model tests only).

Native oracle: crates/scp-runtime/src/context/governance_helpers.rs execute_remove_member ~1231-1356.

## VERDICT: Core eviction property HOLDS. No CRITICAL/HIGH. Diff is well-constructed, fail-closed ordering is correct.

## WASM architecture facts (load-bearing)
- WASM governance is SINGLE-BRIDGE execution. The quorum-crossing VOTER (or SingleAdmin proposer) runs execute_governance_action → dispatch_remove_member on THEIR bridge ONLY (manager.rs:4620 approve path; :4391 auto-execute). That one bridge generates the MLS commit (group.rs remove_members + merge_pending_commit:171) and strips its own ctx.members.
- There is NO inbound governance-application path on WASM. No process_commit/apply_commit binding. Remaining members learn the removal ONLY by: (a) feeding the eviction commit hex through context_decrypt_message → decrypt_message → mls_group.decrypt → decrypt_protocol_message → merge_staged_commit (group.rs:395), which advances MLS epoch but DOES NOT touch ctx.members; (b) independently running their own vote→execute (which would generate a DIFFERENT, conflicting MLS commit).
- Commit distribution is JS's job: dispatch_remove_member returns {commit: hex} (manager.rs:3552). Native instead self-distributes via deps.transport.send_message with retry/enqueue (try_broadcast_commit_or_enqueue:5028 — note: NO durable leaf appended, buffer-only events). This is THE structural divergence.
- WASM sender_key_store is NEVER populated outside tests; encrypt_message never attaches/wraps the sender key. Layer-1 double-encryption is effectively non-functional cross-member in prod WASM. Pre-existing; the eviction property rests entirely on MLS layer-2 epoch advance (correct). Docs in state.rs:166-176 + manager.rs:3493-3503 are accurate.
- WASM does NOT track access_key_store or peer_registry (no such fields) — native's strip of those has no WASM counterpart, so not a divergence.

## Native vs WASM RemoveMember cleanup divergence
Native strips: membership, role_state.{members,assignments,member_capabilities}, access_key_store, peer_registry(pseudonym). WASM strips: members (+broadcast author block). WASM LEAVES stale suspended_capabilities[did] entry (LOW — member gone from members so all member_has_capability checks fail-fast at manager.rs:539 regardless). Leaf parity OK: both emit MemberLeft + GovernanceActionExecuted (2 leaves), byte-convergent (empty payload, executor actor_did, proposal.created_at timestamp).

## Chains (all bounded)
- RED-EVICT-1 (LOW, by-design): committer-only ctx.members strip → bridge-membership desync on remaining members. NOT a key-access bypass: enforcement that matters is MLS epoch (crypto), proven by state.rs eviction test. Bridge ctx.members is per-client local view; a remaining member's stale view only over-grants capabilities to the removed member IN THAT CLIENT'S LOCAL CHECKS, but the removed member is cryptographically mute/deaf (stale epoch) so cannot send/read regardless. Native's receive-side strip is cleaner but the security boundary is crypto, not the bridge map.
- RED-EVICT-2 (LOW/MED, liveness not confidentiality): JS-driven commit distribution. If JS never relays the commit, remaining members stay at old epoch and the removed member is NOT evicted from THEIR view — but the committer already advanced epoch and can no longer be decrypted by stragglers either. Worst case = group split / DoS / failure-to-evict, NOT removed-member-retains-access on a member who DID process the commit. Removed member gains nothing they didn't already have; cannot forge the commit. Native's self-distribution+retry is more robust. This is the real residual to flag.
- RED-EVICT-3 (NON-ISSUE): evicted member declines to process own commit. Crypto test (state.rs:398-407) proves stale state cannot decrypt new-epoch ciphertext. Holds.
- RED-EVICT-4 (orthogonal, pre-existing): sender-key non-redistribution. Does NOT become exploitable here; MLS epoch advance is the lockout. Docs accurate.

## Controls that hold
Fail-closed-keep ordering (MLS evict FIRST, strip only on success; manager.rs:3507-3520 + test :9601); retry-safe (no partial strip on error); leaf-count/byte parity; merge_pending_commit on committer; epoch advance proven to deny stale decrypt.
