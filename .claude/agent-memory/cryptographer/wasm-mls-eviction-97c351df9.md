---
name: wasm-mls-eviction-97c351df9
description: Final review of fix/wasm-governance-mls-eviction @97c351df9 (fail-closed ordering + accurate sender-key docs) — SOUND, no blocking findings
metadata:
  type: project
---

# WASM governance MLS-eviction — branch fix/wasm-governance-mls-eviction @97c351df9

VERDICT: SOUND, no blocking findings. APPROVE. Supersedes prior pass (wasm-mls-eviction.md) which reviewed an earlier commit ea0058cde; this is the fail-closed-ordering + doc-accuracy hardening pass.

**Why:** The prior pass flagged (a) docs falsely claiming encrypt_message ships the rotated sender key and (b) no sender-key distribution path. Both are now corrected: docs at crypto/state.rs:160-176 + manager.rs dispatch_remove_member comment are ACCURATE — encrypt_message (state.rs:68-88) emits ONLY the double-ciphertext, never attaches local_sender_key; docs correctly scope the eviction property to the MLS epoch advance (layer-2 lockout) independent of sender-key redistribution.

**How to apply:** This is the production WASM eviction path. Treat the leaf-byte parity invariants (empty payload, actor=executor, ts=proposal.created_at, MemberLeft-before-GovernanceActionExecuted, shared scp_event_log preimage) as load-bearing for cross-platform §9.9.3 Merkle root convergence.

## Verified SOUND
- MLS eviction: leaf_index_for_did (group.rs) scans members, decodes BasicCredential→WasmScpCredential, matches .did, returns first leaf; remove_member_by_did delegates to remove_member → merge_pending_commit advances epoch + drops member from key schedule; returned commit is what remaining members ratchet on. KAT leaf_index_for_did_resolves_added_member_and_remove_by_did_evicts passes.
- Credential matching: DID-in-BasicCredential is NOT MLS-authenticated (BasicCredential = opaque bytes; OpenMLS validates leaf SIG against leaf signature_key but does not bind DID↔key). Duplicate-DID would evict only first leaf. PRE-EXISTING property of BasicCredential model, IDENTICAL on native (find_leaf_index_by_did also first-match); governance ctx.members(DID-keyed)+add-driven-by-governance prevents dup. NOT a regression. Doc comment correctly notes "MLS does not key its tree by DID".
- Sender-key rotation (§9.16.4): governance_rotate_sender_key eagerly self.local_sender_key.zeroize() THEN = generate_sender_key() (OsRng.fill_bytes via getrandom-js; SenderKey: Zeroize+ZeroizeOnDrop). governance_remove_sender_key drops evicted member's stored key (zeroized on drop). SOUND.
- ★ MERKLE CONVERGENCE: native execute_remove_member (governance_helpers.rs:1231) appends MemberLeft via append_context_event(ctx, EventType::MemberLeft, actor_did=CommitMeta.actor_did=executor, timestamp_secs=proposal.created_at) → non-payload variant → EventPayload::default() (empty) → ContextLog::append → scp_event_log::tree::append_unsigned_event (SHARED preimage). WASM dispatch_remove_member appends ctx.append_log_event(EventType::MemberLeft, executor_did, b"", timestamp_secs) → append_unsigned_event (SAME shared path). Byte-identical: event_type, actor=executor, ts=created_at, payload=empty, prev_hash/sequence derived from log state. MemberLeft precedes GovernanceActionExecuted (dispatch appends MemberLeft @3548 inside dispatch_governance_action called @3170; GovernanceActionExecuted appended @3219 AFTER on success). NOTE: the runtime event log was MIGRATED to RFC-6962 scp_event_log path (finding_runtime_eventlog_not_rfc6962.md unification LANDED) — providers/event_log.rs now uses EventType + tree::append_unsigned_event + tree::root, NOT the old SCP-EXPORT-ENTRY hash-chain.
- Fail-closed-keep ordering: dispatch_remove_member does existence-check (no remove) → MLS eviction FIRST (governance_remove_from_group → CRYPTO_4011 on miss) → only THEN strip ctx.members. On crypto err returns Err with member STILL present + no MemberLeft leaf. Caller rollback (@3174) only removes executed_proposals, never ctx.members. No decryption-after-removal window.
- KAT non-tautology: cross_impl_remove_member_leaf_is_empty_and_precedes_executed (native, conformance) PASSES — drives REAL MerkleEventLogProvider appends, pins empty payload + actor=executor + MemberLeft<Executed order. WASM half remove_member_appends_empty_member_left_leaf_before_executed_wasm drives REAL execute_governance_action (crypto:None no-op-commit branch), pins payload-empty/actor=executor/ts=created_at(1_700_600_700)/ordering. Security KAT evicted_member_cannot_decrypt_after_removal_and_rotation (3-member Alice/Bob/Carol) proves Bob stuck-epoch AEAD-fails post-eviction + Carol still decrypts. Fail-closed KAT uses crypto:Some single-leaf to force real RemoveMemberFailed. GovernanceActionExecutedPayload uses SHARED scp_event_log::payload encoder both sides (only matters for Executed leaf; MemberLeft is empty).
- Honest residual (documented, NOT a finding): WASM has NO cross-member sender-key distribution for encrypted MLS contexts — rotated key never reaches remaining members on subsequent encrypt_message (conformance test hands key directly). Eviction property holds via MLS epoch advance regardless. Pre-existing + orthogonal.

## Verification run
- cargo check -p scp-ffi-wasm --target wasm32: clean
- cargo clippy -p scp-ffi-wasm --target wasm32 -D warnings: clean
- cargo test -p scp-ffi-wasm --lib (host): 367 passed (incl all 5 new: leaf_index/remove_by_did/empty-leaf/fail-closed-keep/evicted-cannot-decrypt)
- cargo test -p scp-runtime --features testing --test wasm_conformance cross_impl_remove_member...: 1 passed
- WASM wasm32 test target cannot run (no harness + scp_identity not a wasm dep) — expected; tests validate on host + conformance harness.
