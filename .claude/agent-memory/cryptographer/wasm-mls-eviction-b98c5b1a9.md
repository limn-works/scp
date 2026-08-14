---
name: wasm-mls-eviction-b98c5b1a9
description: Final review of fix/wasm-governance-mls-eviction @b98c5b1a9 (native-parity missing-leaf no-op + F5 per-DID cleanup + F8 exact-count + relay-commit docs) — SOUND, no blocking, APPROVE
metadata:
  type: project
---

# WASM governance MLS-eviction — branch fix/wasm-governance-mls-eviction @b98c5b1a9

VERDICT: SOUND, no blocking findings. APPROVE. Supersedes @97c351df9 (wasm-mls-eviction-97c351df9.md). This pass reviews the native-parity-no-op + F5/F8 hardening commit b98c5b1a9.

## What changed since 97c351df9
- **Missing-leaf semantics FLIPPED**: was fail-LOUD (`RemoveMemberFailed` error); now NO-OP returning empty commit `Ok(Vec::new())` + console.warn. This now MATCHES native `MlsCryptoProvider::remove_member` (provider.rs:1077-1084), which returns `RemoveMemberOutput::default()` (empty commit) when the DID has no MLS leaf. Verified native parity by reading provider.rs:1030-1108. The crypto layer is NOT authoritative for membership; governance is. A member in ctx.members but never MLS-added is removed from membership regardless, and there is no key schedule to advance ⇒ cryptographically safe.
- **Genuine MLS errors still fail-closed**: `remove_member_by_did` → `leaf_index_for_did(member_did)?` propagates `GroupDestroyed` (group is None, group.rs:200) via `?`; `Ok(None)` is the no-op. A leaf that IS found but whose remove/commit-serialization fails returns `RemoveMemberFailed`. Both propagate as `Err`, dispatch returns Err with member STILL present + no MemberLeft leaf (no decrypt-after-removal window). New test `remove_member_by_did_errors_on_destroyed_group` + `remove_member_keeps_governance_state_when_mls_eviction_fails` (forces err via `crypto.mls_group.destroy()`).
- **F5 NEW per-DID cleanup** (manager.rs ~3534): dispatch now also strips `ctx.suspended_capabilities.remove(did)` + `ctx.read_exclusion_list.remove(did)` — the WASM-local mirror of native `execute_remove_member`'s strip of `role_state.members`/`assignments`/`member_capabilities` + `access_key_store.remove` + `peer_registry.remove` (governance_helpers.rs:1295-1307). Closes a stale-desync foothold: a DID re-admitted under the same string would otherwise inherit a phantom suspension/read-exclusion. Real defense-in-depth improvement. Parity comment is HONEST (verified against native).
- **F8 NEW exact-count**: real-path WASM KAT now asserts `==1` MemberLeft AND `==1` GovernanceActionExecuted (manager.rs:9592+) — guards a duplicate-append from silently diverging cross-platform `tree::root` (find/position would tolerate dupes).

## Verified SOUND
- MLS eviction (encrypted path): leaf_index_for_did scans members, decodes BasicCredential→WasmScpCredential, matches .did, returns FIRST match (group.rs:196-210) — byte-identical scan to native (provider.rs:1059-1070, same first-match/dup-DID property; DID-in-BasicCredential is NOT MLS-authenticated, pre-existing, governance ctx.members(DID-keyed) prevents dup — NOT a regression). remove_member → remove_members + merge_pending_commit advances epoch + drops member from key schedule; returned commit (hex) is what remaining members ratchet on. New test `remove_member_encrypted_path_returns_decodable_commit_hex` adds a REAL 2nd MLS leaf (Bob) and proves non-empty decodable commit + Bob no longer resolves to a leaf.
- Sender-key rotation §9.16.4 (UNCHANGED, still sound): governance_rotate_sender_key eagerly `local_sender_key.zeroize()` THEN `= generate_sender_key()` (CSPRNG OsRng/getrandom-js; SenderKey: Zeroize+ZeroizeOnDrop). governance_remove_sender_key drops evicted member's stored key (zeroized on drop). Order in dispatch: evict → remove evicted's key → rotate local key.
- ★ MERKLE CONVERGENCE: WASM `ctx.append_log_event(EventType::MemberLeft, executor_did, b"", timestamp_secs)` → shared scp_event_log append_unsigned_event; byte-identical to native `append_context_event(EventType::MemberLeft, actor_did=CommitMeta.actor_did=executor, ts=proposal.created_at)` with EventPayload::default() (empty). Precedes GovernanceActionExecuted both sides. Target DID lives in buffer event ONLY, never the durable leaf (§9.9.3).
- ★ Conformance KAT now HONEST: `cross_impl_remove_member_leaf_is_empty_and_precedes_executed` doc no longer claims it "drives native's REAL appends" — it now correctly states it REPLAYS the two appends (via the SAME shared `append_context_event` + `gov_action_executed_payload_bytes` producers native uses) and does NOT invoke execute_remove_member (scp-runtime test crate can't dev-dep the wasm cdylib + helper is behind actor machinery). Native real-path ordering covered by native gov tests; WASM real-path covered by 5 dispatch tests driving execute_governance_action by-id. Not a tautology on the WASM side.
- Broadcast/crypto.is_none() path: empty commit, block_author cleanup runs, MemberLeft leaf still appended (`remove_member_broadcast_path_empty_commit_still_appends_leaf`).
- Doc accuracy CONFIRMED: encrypt_message (state.rs:68) emits ONLY double-ciphertext (sender-layer then MLS), never attaches rotated key. Honest sender-key-redistribution gap doc'd (manager.rs:3500-3510). Native-vs-WASM broadcast asymmetry doc'd in context.rs/scp.ts/wasm.ts — native auto-broadcasts via try_broadcast_commit_or_enqueue (governance_helpers.rs:1319); WASM has no internal transport (ADR-034), caller MUST relay the hex commit or the group silently forks. Accurate.

## Verification run (worktree wasm-mls-evict, HEAD b98c5b1a9)
- cargo test -p scp-ffi-wasm --lib remove_member: 8 passed (serde-roundtrip, broadcast-empty-leaf, real-path-empty-before-executed, destroyed-group-errors, keeps-state-on-fail, noop-for-non-member, no-leaf-removed-cleanly, encrypted-decodable-hex)
- evicted_member_cannot_decrypt_after_removal_and_rotation: 1 passed
- cross_impl_remove_member_leaf_is_empty_and_precedes_executed (conformance): 1 passed
- cargo clippy -p scp-ffi-wasm --target wasm32 (lib): clean. (--all-targets fails on scp_identity test-only dep — pre-existing/expected, not a wasm runtime dep.)
- bun run check (TS): passes (doc-comment-only TS changes).
- No enforcement files touched.
