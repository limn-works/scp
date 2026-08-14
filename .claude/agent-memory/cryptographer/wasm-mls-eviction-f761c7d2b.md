---
name: wasm-mls-eviction-f761c7d2b
description: Review of fix/wasm-governance-mls-eviction @f761c7d2b (self-removal MLS no-op parity — own-leaf skip) — SOUND, no blocking, APPROVE
metadata:
  type: project
---

# WASM governance MLS-eviction — branch fix/wasm-governance-mls-eviction @f761c7d2b

VERDICT: SOUND, no blocking findings. APPROVE. Supersedes @b98c5b1a9 (wasm-mls-eviction-b98c5b1a9.md). This pass reviews the SINGLE incremental commit f761c7d2b "self-removal MLS no-op parity (skip own leaf)" on top of the already-approved b98c5b1a9.

## Incremental change (b98c5b1a9..f761c7d2b)
ONLY production-logic change is 3 lines in `leaf_index_for_did` (group.rs): `let own_index = g.own_leaf_index();` + `if member.index == own_index { continue; }`. Everything else = tests + doc-comments.
- group.rs: own-leaf skip in scan + 1 new unit test `remove_member_by_did_is_noop_for_self_did` + existing test updated (alice's OWN DID now resolves to None).
- manager.rs: 1 new dispatch test `remove_member_self_did_encrypted_empty_commit_strips_and_appends_leaf` (test-only).
- wasm_conformance.rs: 1 new KAT `cross_impl_self_removal_leaf_is_empty_and_precedes_executed` (test-only).
- NO TS / context.rs changes in this commit (those were b98c5b1a9 doc-only).

## Self-removal correctness (verified against native provider.rs:1030-1108)
Native has TWO mechanisms: (1) self-DID short-circuit `if member_did == self.local_did { return RemoveMemberOutput::default() }` at provider.rs:1041; (2) own-index skip `if member.index == own_index { continue; }` in scan at 1053-1062. WASM COLLAPSES both into the own-index skip alone → own-DID lookup returns Ok(None) → `remove_member_by_did` returns empty commit Ok(Vec::new()) → dispatch PROCEEDS to strip membership + append MemberLeft. Byte-identical outcome to native self-removal.
- WASM crypto state does NOT store local_did (no `local_did`/`own_did` field in WasmCryptoState — state.rs); own leaf identified purely via OpenMLS `own_leaf_index()`. The own leaf's credential.did == creator_did (set at create_group). So own-index skip == native own-index skip.
- Collapse is SAFE: the only case where native's short-circuit and own-index skip could diverge is a DUPLICATE-DID group (committer's own leaf claims DID-X AND another leaf claims DID-X). That requires duplicate DIDs, which governance ctx.members (DID-keyed HashMap) structurally prevents. DID-in-BasicCredential is not MLS-authenticated (pre-existing, not a regression). Not reachable on live path.
- Without the skip: OpenMLS rejects remove_member(own_index) with CannotRemoveSelf → dispatch fails closed → member KEPT with ZERO leaves where native appends TWO → §9.9.3 tree::root divergence. The skip closes exactly this.

## Carried-forward SOUND (unchanged from b98c5b1a9, re-verified)
- Fail-closed ordering in dispatch_remove_member (manager.rs:3450): existence-check (no remove) → MLS evict FIRST via governance_remove_from_group `?` (genuine MLS err → Err, member STILL present, no leaf) → remove_sender_key → rotate_sender_key → THEN strip ctx.members + suspended_capabilities + read_exclusion_list → block_author → buffer event → append MemberLeft(executor_did, b"", timestamp_secs). GovernanceActionExecuted appended by wrapper after.
- remove_member (group.rs:158): remove_members + merge_pending_commit advances epoch, drops member from key schedule; returned commit is what remaining members ratchet on.
- remove_member_by_did (group.rs:265): leaf_index_for_did(did)? propagates GroupDestroyed via `?`; None→empty no-op; Some→remove_member.
- Sender-key §9.16.4: governance_rotate_sender_key eagerly local_sender_key.zeroize() THEN = generate_sender_key() (OsRng.fill_bytes, sender_keys/mod.rs:107, CSPRNG, SHARED native+wasm). governance_remove_sender_key drops via SenderKey ZeroizeOnDrop.
- Merkle convergence: MemberLeft leaf empty payload, actor=executor, ts=committer-assigned; precedes GovernanceActionExecuted, exactly-one-each. Both impls use SAME shared scp_event_log::payload::encode_payload over GovernanceActionExecutedPayload{target_did, action_type}. WASM producer = encode_governance_action_executed_payload (manager.rs); conformance fixture = gov_action_executed_payload_bytes — both call shared encoder. Non-tautological.
- Self-removal KAT replays native's two shared appends (MemberLeft via append_context_event, GovernanceActionExecuted via shared payload producer); WASM real-path covered by the dispatch test driving REAL dispatch_remove_member on a REAL encrypted ctx (WasmCryptoState::new_for_context) — pins empty commit + member stripped + F5 cleaned + MemberLeft(empty,executor,ts).

## Verification run (worktree wasm-mls-evict, HEAD f761c7d2b)
- cargo test -p scp-ffi-wasm --lib remove_member: 10 passed (incl 2 new self-removal tests).
- evicted_member_cannot_decrypt_after_removal_and_rotation: 1 passed.
- cargo test -p scp-runtime --test wasm_conformance --features testing -- remove_member self_removal: 3 passed (incl new cross_impl_self_removal KAT).
- cargo clippy -p scp-ffi-wasm --lib --target wasm32-unknown-unknown: clean.
- Enforcement files in diff: NONE. TS/context.rs non-comment diff: EMPTY.
