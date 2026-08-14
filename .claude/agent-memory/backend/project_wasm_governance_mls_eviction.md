---
name: project-wasm-governance-mls-eviction
description: WASM governance RemoveMember did ZERO MLS work (removed member kept group key, could still decrypt); fix mirrors native execute_remove_member — MLS remove + sender-key cut/rotate + durable MemberLeft leaf before GovernanceActionExecuted
metadata:
  type: project
---

WASM governance `RemoveMember` security fix (branch fix/wasm-governance-mls-eviction off origin/main @0a87e4ac2).

**Bug:** `crates/scp-ffi/wasm/src/manager.rs` `dispatch_remove_member` (~3431) removed a member from governance state but did ZERO MLS work — removed member kept the MLS group key schedule and could still decrypt. Native (`crates/scp-runtime/src/context/governance_helpers.rs` `execute_remove_member` ~1231) removes from MLS FIRST (hard boundary), then `remove_member_sender_key`, then `rotate_sender_key`, then appends a durable `MemberLeft` leaf.

**Native MemberLeft leaf (the convergence-critical KAT target):**
- `append_context_event(EventType::MemberLeft, actor_did, timestamp_secs)` → `EventPayload::default()` = EMPTY payload (`builder.rs:187`).
- **actor_did = executor_did (committing member), NOT the target did.** Sourced from `CommitMeta.actor_did` = `executor_did.as_ref()` (`dispatch_governance_action` 4290-4303; `ts = proposal.created_at`). TRAP: the task plan literally said `append_log_event(EventType::MemberLeft, did, ...)` using the TARGET did — that DIVERGES from native. Must use executor_did + proposal_created_at to match byte-for-byte.
- Leaf ordering: MemberLeft is appended INSIDE the commit closure (before the closure returns); GovernanceActionExecuted leaf is appended by `finalize_governance_action` AFTER dispatch. So MemberLeft precedes GovernanceActionExecuted.

**WASM wrapper:** `execute_governance_action` (3078) is the SOLE caller of `dispatch_governance_action` (3264) — threading a `timestamp_secs` param is clean/safe. Wrapper already appends GovernanceActionExecuted leaf with `proposal_created_at` + `executor_did` AFTER dispatch (3209). So append MemberLeft inside dispatch (before that) with executor_did+proposal_created_at.

**Key APIs:**
- group.rs: `remove_member(&LeafNodeIndex)` (158); `members()` via `group.as_ref()`; leaf-index-by-did mirror = `wrapping_extension.rs:192-205` (`BasicCredential::try_from(member.credential.clone())` → `ScpCredential::from_bytes(basic.identity())` → `cred.did == target` → `member.index`). credential.rs: `WasmScpCredential::from_bytes` (114), field `did` (58).
- SenderKey (scp-protocol/src/crypto/sender_keys/mod.rs:66): derives Zeroize+ZeroizeOnDrop; `from_bytes([u8;32])`, `as_bytes()`. Map clear/drop zeroizes; `.zeroize()` for in-place.
- `append_log_event(EventType, actor_did:&str, payload:&[u8], timestamp_secs:u64)` (manager.rs:489) — NEVER pass now_secs (489-488 doc: breaks Merkle convergence).
- Error: `ScpWasmError::Crypto{message,code}`; `codes::CRYPTO_4011` ("MLS proposal error") for MLS remove failure. `codes = scp_ffi_common::error_codes`. hex: `crate::runtime::encode_hex`.
- crypto field: `PerContextState.crypto: Option<WasmCryptoState>` (364). None branch (broadcast/unencrypted) → commit = Vec::new() (native non-MLS no-op).

**Cross-impl KAT:** `crates/scp-runtime/tests/wasm_conformance.rs`. Pattern = `cross_impl_governance_proposal_vote_leaf_is_empty` (2346, empty-payload via real `MerkleEventLogProvider` + `append_context_event`) + `cross_impl_governance_action_executed_leaf_bytes` (2266). Add: native MemberLeft leaf empty-payload + MemberLeft-before-GovernanceActionExecuted ordering. Test crate CANNOT link wasm32 (split-KAT convention: native asserts here, WASM asserts in its own crate against same pinned bytes).

**No exact event-COUNT assertion for RemoveMember exists on origin/main** (the genuine-execute test 9296 uses ChangeRole + counts only GovernanceActionExecuted). So no +1 bump needed.

`make_bare_per_context_state` (1268) sets crypto:None → manager-level test hits the no-MLS branch. Real MLS security proof (stale member can't decrypt) lives in state.rs WasmCryptoState 3-member harness (Alice/Bob/Carol; OpenMLS can't self-decrypt so Carol verifies Alice's sends).
