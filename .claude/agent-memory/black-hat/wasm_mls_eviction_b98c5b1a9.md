---
name: wasm-mls-eviction-b98c5b1a9
description: WASM governance RemoveMember MLS-eviction fix (b98c5b1a9) — strict security improvement; 1 MED self-removal cross-impl divergence; duplicate-leaf exposure shared w/ native (not a regression)
metadata:
  type: project
---

# WASM governance RemoveMember MLS eviction (commit b98c5b1a9)

Adds real MLS eviction to WASM `dispatch_remove_member` (was a pure governance-strip no-op pre-commit). New: `leaf_index_for_did` + `remove_member_by_did` (group.rs), `governance_remove_from_group`/`remove_sender_key`/`rotate_sender_key` (state.rs), threaded `executor_did`+`timestamp_secs` into dispatch, durable empty-payload MemberLeft leaf + commit hex return.

## VERDICT: strict security improvement. No CRITICAL/HIGH introduced.
Pre-commit WASM (`git show origin/main:...manager.rs` dispatch_remove_member) did ZERO MLS work — `ctx.members.remove(did)` + buffer event only. Every removed member STAYED in the MLS group and kept decrypting, AND no durable MemberLeft leaf was appended (count 0 vs native 1 = pre-existing §9.9.3 divergence). This commit fixes BOTH. The "previous error-on-missing-leaf behaviour" the review prompt hypothesised never existed.

## Missing-leaf no-op: NOT exploitable as described. Faithfully mirrors native.
`remove_member_by_did` returns Ok(empty) when DID has no leaf; dispatch proceeds to strip+leaf. Native `provider.rs:1077` does the identical `RemoveMemberOutput::default()` no-op. In the self-consistent WASM flow, governance DID == credential DID (joiner's `generate_key_package_for_join(ctx, member_did)` embeds member_did; same did used for membership insert). No WASM admin-side "add remote key package" manager method exists, so attacker can't inject a credential-DID≠governance-DID leaf through the WASM surface.

## FINDING 1 (MEDIUM, cross-impl divergence) — self-removal via governance
WASM `leaf_index_for_did` does NOT skip own leaf (native `provider.rs:1060` `if member.index==own_index{continue}` + `member_did==self.local_did` early empty no-op at 1041). PROVEN via probe: removing the creator's own DID via dispatch →
`Err(Crypto CRYPTO-4011 "The Commit tried to remove self from the group. This is not possible.")`, MemberLeft count=0, creator KEPT.
Native for the same proposal: empty-commit no-op → strips creator → appends MemberLeft + GovernanceActionExecuted. => 2-leaf count + root divergence + divergent membership. FAILS CLOSED in WASM (member kept in BOTH gov+MLS — consistent, no decryption hole) but breaks §9.9.3 convergence (the commit's own stated invariant). Reachable: creator/admin voted out, or the doc-cited "local member under a different DID in multi-identity env". UNCOVERED by KAT (cross_impl_remove_member_leaf... is a hand-replay, no self-target case). FIX: WASM should treat own-leaf/local-did removal as an empty-commit no-op like native (return Ok(Vec::new()) when leaf_index_for_did resolves own leaf), then strip+leaf.

## FINDING 2 (LOW, pre-existing, NOT a regression) — duplicate-DID two leaves
OpenMLS allows 2 distinct leaves with identical credential DID (probe: both add_member calls Ok). leaf_index_for_did returns FIRST match only (break). After one remove-by-did, DID STILL resolves to leaf 2, member count stays 2 → that holder keeps decrypting. Native shares this exactly (same break-on-first scan, add_member doesn't reject dup DID — member_did only used for wrapping-key map). Crypto-layer property shared by both impls; not introduced here. Only reachable if dup leaves can be minted (no WASM admin-add path today).

## What held (genuine effort, could not break):
- Fail-closed ordering CORRECT: existence-check-without-remove → MLS evict via `?` (Err before any strip) → ctx.members.remove only after. No gov-stripped-but-still-in-MLS window.
- Genuine MLS error (destroyed group) → Err → keep (test remove_member_keeps_governance_state_when_mls_eviction_fails verified).
- sender-key remove/rotate made infallible in WASM = justified (WasmCryptoState is borrowed &mut, no DashMap lookup that can fail; native fallibility is only the get_mut().ok_or). WASM lacks member_wrapping_keys/recv_sequence_tracker fields (structural, not a bug).
- Leaf bytes byte-identical: empty payload, executor actor_did (not removed DID), convergent timestamp_secs=proposal.created_at (never now()), MemberLeft before GovernanceActionExecuted, exactly-one-each counts. append_log_event matches native append_context_event(EventPayload::default()).
- Rotate-on-no-op path matches native (both rotate even on missing-leaf empty commit).
- TS/context.rs docs honestly disclose the WASM no-auto-broadcast relay obligation + silent-fork risk (ADR-034 no internal transport).

Probes: detached worktree /tmp/scp-mls-bh2, added bh_probe_* to group.rs tests + self-removal probe to manager test, ran on host target, reverted clean.
