---
name: wasm-mls-eviction
description: Crypto review of fix/wasm-governance-mls-eviction (ea0058cde) — WASM bridge now cryptographically evicts removed governance members from MLS group
metadata:
  type: project
---

# WASM Governance MLS Eviction (branch fix/wasm-governance-mls-eviction @ ea0058cde)

Fixes a real security hole: WASM `dispatch_remove_member` previously did ZERO MLS work — removed member kept the group key schedule and could decrypt. Now evicts.

**Why:** native↔WASM parity (ADR-049, §9.9.3) + close the WASM eviction gap.
**How to apply:** when reviewing follow-ups, the construction is SOUND; the open items below are doc-accuracy + a pre-existing sender-key-distribution gap, not security regressions.

## Verified SOUND
- group.rs `leaf_index_for_did`: faithful mirror of native `find_leaf_index_by_did` (wrapping_extension.rs:192). First-match scan, BasicCredential→WasmScpCredential decode, DID-string compare. DID is MLS-authenticated (signed into LeafNode) so no impersonation. Native returns Err on miss; WASM Ok(None)→RemoveMemberFailed. Both fail-loud.
- `remove_member` (pre-existing) merges pending commit locally (committer adopts new epoch) and returns the PRE-merge commit for relay distribution. Correct OpenMLS. Test proves epoch+1 and evicted stale state can't decrypt new-epoch ct.
- Ordering matches native execute_remove_member (governance_helpers.rs:1255-1353): remove_member(MLS) → remove_member_sender_key → rotate_sender_key → emit/push MemberLeft buffer → durable append(MemberLeft, actor=executor, ts, EMPTY payload).
- Rotation: SenderKey = [u8;32] Zeroize+ZeroizeOnDrop (sender_keys/mod.rs:66). generate_sender_key uses OsRng.fill_bytes (WASM→getrandom/js→crypto.getRandomValues CSPRNG). governance_rotate_sender_key explicit zeroize()+regenerate. governance_remove_sender_key drops stored key (ZeroizeOnDrop).
- MERKLE CONVERGENCE confirmed: both native append_context_event (EventPayload::default()=data:[]) and WASM append_log_event(...,b"",...) build a scp_event_log::Event with identical fields and call the SAME shared leaf_hash/append_unsigned_event. MemberLeft is a stable EventType variant. Both stamp actor_did=EXECUTOR (= tracked proposal.proposer for the direct-execute path: native execute_governance_action executor_did.unwrap_or(&proposal.proposer_did) gov.rs:694 None; WASM context_execute_governance resolves proposer). timestamp=proposal.created_at (NOT now()). Byte-identical preimage by construction.
- KAT not tautological: native half drives REAL appends in execute_remove_member order (conformance.rs cross_impl_remove_member_leaf_is_empty_and_precedes_executed — PASSES); WASM half drives REAL execute_governance_action path. Each pins empty-payload + executor-actor + created_at-ts + MemberLeft<Executed ordering. Root-byte parity structurally guaranteed by shared crate + §25 KAT (vectors 32/33) anchor.
- cargo check --target wasm32-unknown-unknown -p scp-ffi-wasm: clean.

## FINDINGS (non-blocking, LOW)
1. **Doc-comment inaccuracy** (state.rs:163-167; manager.rs:3479-3483): claims "rotated local_sender_key ships with the next encrypt_message (lazy redistribution)". FALSE — encrypt_message (state.rs:68-88) emits ONLY the double-ciphertext; it does NOT attach/ship local_sender_key. No sender-key distribution path exists in the WASM bridge for MLS contexts (sender_key_store populated only by broadcast open_broadcast_key + tests).
2. **"genuine no-op, not a stub" overstated**: native maintains HPKE pending-redistribution queue (drain_and_deliver_sender_keys) and actively delivers rotated keys. WASM delivers nothing. PRE-EXISTING gap (sender layer never wired for cross-member key delivery on WASM), not introduced here.
   - Security goal still HOLDS: evicted member is locked out by MLS layer-2 eviction (epoch advance) regardless of sender key — sender-key rotation is defense-in-depth. Test proves Bob can't decrypt even with old sender key.
   - But remaining-member post-rotation sender-layer decryption depends on a distribution mechanism that doesn't exist in the bridge. Liveness concern for double-encryption on WASM generally; flag if WASM encrypted-context messaging is exercised E2E.

## Duplicate-DID note (shared, not a regression)
WASM dispatch_add_member governance member map is DID-keyed (dedup). But MLS leaves are established on the separate join/KeyPackage flow; same DID joining twice → two leaves, leaf_index_for_did evicts only first. Identical to native. Not this PR's concern.

## Open task #205 (orthogonal)
native proposer vs WASM executor consequence-subject divergence is the quorum-approval path; this PR's direct-execute MemberLeft leaf converges (both = proposer).
