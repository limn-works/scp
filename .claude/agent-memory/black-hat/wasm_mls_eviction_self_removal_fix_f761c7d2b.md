---
name: wasm-mls-eviction-self-removal-fix-f761c7d2b
description: WASM RemoveMember self-removal fix (f761c7d2b) — own-leaf-skip RESOLVES prior MED FINDING-1; sound. 1 LOW latent cross-impl dup-DID-self epoch divergence; conformance KAT still hand-replay (not real cross-exec)
metadata:
  type: project
---

# WASM RemoveMember self-removal fix (commit f761c7d2b, on top of b98c5b1a9)

Adds own-leaf skip to WASM `leaf_index_for_did` (group.rs ~224): `let own_index = g.own_leaf_index(); for member { if member.index==own_index {continue} ...}`. This RESOLVES the MED FINDING-1 from [[wasm-mls-eviction-b98c5b1a9]] (self-removal previously hit CannotRemoveSelf → Err → member KEPT, 0 MemberLeft, diverging from native's strip+2-leaf). Now own-DID lookup → None → `remove_member_by_did` Ok(empty) no-op → dispatch PROCEEDS to strip + append MemberLeft+GovernanceActionExecuted. Mirrors native two-funnel (provider.rs:1041 `member_did==self.local_did` short-circuit + 1060 own-index skip).

## VERDICT: sound. Could not break the self-removal fix. No CRIT/HIGH/MED introduced.
PROVEN by probes (all ran on host target, reverted clean):
- Self-removal at non-zero leaf: Bob joins via Welcome (leaf 1), own_leaf_index()=1 (NOT hardcoded 0), own DID → None → empty no-op. Correct.
- Creator-removal by another: Bob (leaf 1) removes creator Alice (leaf 0) → resolves leaf 0, commit non-empty (368B), epoch advances, Alice evicted. Own-leaf skip is keyed to LOCAL committer, does NOT accidentally shield the creator from removal-by-others. Correct.
- Fail-closed-keep on genuine MLS error (destroyed group) → Err → member kept, no leaf. Correct.
- Encrypted decryption-after-removal: evicted member's stale state cannot decrypt post-eviction (epoch advance is the lockout); remaining member can. Verified via state.rs `evicted_member_cannot_decrypt_after_removal_and_rotation`.
- Leaf SET parity: native `execute_remove_member` (governance_helpers.rs:1348) appends EXACTLY one MemberLeft; the RoleAssigned at 1401 belongs to `execute_change_role`, a different helper. WASM = one MemberLeft + wrapper GovernanceActionExecuted. Counts/order/payload/actor_did/timestamp match.

## FINDING (LOW, latent cross-impl divergence, NOT a regression, NOT WASM-reachable) — duplicate-DID self-removal advances epoch on WASM, no-op on native
PROVEN via probe `PROBE_dup_self_did_resolves_non_own_leaf`: add a 2nd MLS leaf whose credential DID == creator's own DID (dup leaf at index 1). Then `leaf_index_for_did(own_did)` skips ONLY own leaf 0, then RESOLVES the dup leaf 1 → `remove_member_by_did(own_did)` EVICTS leaf 1 (commit_len=370, epoch 1→2). Native's `member_did==self.local_did` short-circuit (provider.rs:1041) returns empty BEFORE the scan → no eviction, epoch unchanged. => WASM advances MLS epoch, native does not → divergent commit + MLS group fork in a heterogeneous group.
WHY LOW / not practically exploitable:
- The dup-DID-own-leaf precondition is NOT reachable via the WASM surface: WASM has NO admin admit path (`mls_group.add_member` with externally-supplied key package exists only in tests; the bridge exports only the JOINER side `generate_key_package_for_did`/`join_context_encrypted`). WASM-only groups can never mint a 2nd leaf carrying the local DID.
- Native admit (`add_member`, provider.rs:909) binds credential DID == owner_did but does NOT forbid owner_did == an existing member/creator DID, so a pathological governance AddMember{did=creator_did, matching KP} could mint the dup leaf in a heterogeneous (native-admin + WASM-holder) group. Deeply contrived; durable event-log tree::root still CONVERGES (MemberLeft/GovernanceActionExecuted leaves identical) — only MLS epoch/commit diverges.
- FIX (defense-in-depth + exact native parity): WASM should add native's explicit self-DID short-circuit (`if member_did == local_did { return Ok(empty) }`) BEFORE the leaf scan, instead of relying solely on own-leaf skip. WASM has no `local_did` field on WasmCryptoState today, so this needs the own-credential DID threaded in — but the structural exposure is bounded by the no-admit-path immunity.

## RESIDUAL (unchanged from prior pass) — conformance KAT is a HAND-REPLAY, not real cross-execution
`cross_impl_remove_member_leaf...` and `cross_impl_self_removal_leaf...` (wasm_conformance.rs) EXPLICITLY do NOT invoke `execute_remove_member`/`dispatch_remove_member` — they manually `append_context_event(MemberLeft)` then `append_context_event_with_payload(GovernanceActionExecuted)` and assert the replayed oracle. Documented reason: scp-runtime test crate can't dev-depend on the scp-ffi-wasm cdylib. CONSEQUENCE: a divergence in the real WASM dispatch leaf SET vs the real native helper leaf SET would NOT be mechanically caught — convergence rests on the two crates' independent unit tests asserting the same invariants by hand. This is a pre-existing structural test-coverage gap (own bridge-vs-bridge KAT impossible without a shared harness), not introduced by this commit. Both impls' real paths were read and match; the gap is the absence of a mechanical cross-check.

Probes: detached worktree /tmp/scp-mls-bh3 @ f761c7d2b, added PROBE_* to group.rs tests, ran on host target, reverted clean (git status clean confirmed).
