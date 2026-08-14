---
name: wasm-mls-eviction-66a2c6a5c
description: WASM governance MLS-eviction security fix @66a2c6a5c (branch fix/wasm-governance-mls-eviction) — fresh independent crypto review, SOUND, APPROVE, no blocking findings
metadata:
  type: project
---

# WASM MLS eviction @66a2c6a5c — SOUND, APPROVE, no blocking findings

Branch `fix/wasm-governance-mls-eviction`, HEAD 66a2c6a5c. Fresh independent review (supersedes prior @f761c7d2b notes — same logical change, different commit). Diff: group.rs +492, state.rs +259, manager.rs +675, context.rs +13 (doc), wasm_conformance.rs +228, TS scp.ts/wasm.ts (DOC-ONLY).

**Why SOUND:**
- **MLS eviction**: `remove_member_by_did` → `leaf_index_for_did` (decode BasicCredential→WasmScpCredential, match did) → `remove_member(leaf)` → merge_pending_commit advances epoch, drops member from key schedule. Security proof test `evicted_member_cannot_decrypt_after_removal_and_rotation` (3-member Alice/Bob/Carol): Bob's stale state CANNOT decrypt post-eviction (new-epoch AEAD fails), Carol still can. PASSES.
- **Self-removal parity (BOTH native mechanisms)**: (1) self-DID short-circuit `own_did()? == member_did → Ok(vec![])` BEFORE scan = native provider.rs:1041; (2) own-leaf skip `member.index == own_index continue` in leaf_index_for_did = native provider.rs:1060. own_did derived from own-leaf credential (no stored field) — correct for creator (leaf 0) AND Welcome-joiner (non-zero leaf), tested both. Dup-DID tree: short-circuit returns before resolving non-own dup leaf → evicts NEITHER (matches native). Without skip, OpenMLS CannotRemoveSelf → fail-closed → 0 leaves where native appends 2 → §9.9.3 divergence.
- **Fail-closed**: GroupDestroyed + genuine commit-serialize-fail on a FOUND leaf propagate as Err; member STAYS in ctx.members + NO MemberLeft leaf (test `remove_member_keeps_governance_state_when_mls_eviction_fails`). Missing-leaf = NO-OP empty commit (native parity), proceeds to strip+append. Ordering: MLS-evict FIRST, strip members AFTER → no decrypt-after-removal window.
- **Sender-key §9.16.4**: SenderKey is Zeroize+ZeroizeOnDrop. `governance_rotate_sender_key` eager .zeroize() then = generate_sender_key() (OsRng.fill_bytes, CSPRNG via getrandom/js). `governance_remove_sender_key` drops removed key (ZeroizeOnDrop).
- **★ MERKLE CONVERGENCE**: MemberLeft leaf byte-identical native↔WASM. Native `MerkleEventLogProvider::append` (event_log.rs:74-99) and WASM `append_log_event` (manager.rs:489-519) BOTH: sequence=event_count, prev_hash=last-leaf-or-GENESIS, SAME field order, signature=Vec::new(), shared `scp_event_log::tree::append_unsigned_event` + `leaf_hash`. Native MemberLeft via append_context_event = EventPayload::default() (empty); WASM passes b"" → EventPayload{data:vec![]} (empty). actor_did=executor (native CommitMeta.actor_did; WASM executor_did param), ts=proposal.created_at (NOT now()). MemberLeft appended in dispatch BEFORE wrapper appends GovernanceActionExecuted (only on Ok). Exactly one each.
- **DID matching**: same as native (did from signed MLS leaf credential; cannot forge victim DID without their key going through add path). Dup-DID handled by short-circuit.

**KAT non-tautology assessment**: conformance KATs (cross_impl_remove_member / cross_impl_self_removal) REPLAY native append sequence (call append_context_event directly), do NOT invoke either execute_remove_member or WASM dispatch — honestly disclosed in test docs (scp-runtime test crate can't dev-dep scp-ffi-wasm cdylib). NON-tautological WASM-side proof = manager.rs test `remove_member_appends_empty_member_left_leaf_before_executed_wasm` drives REAL execute_governance_action, pins empty payload + executor actor_did + ts=created_at + exactly-one-each + ordering. Combined the parity claim holds; NO single test byte-compares roots across both impls (acceptable given the cdylib constraint).

**Residual (NON-blocking, pre-existing, well-documented)**: WASM returns commit hex but caller MUST relay it (ADR-034 no internal transport); native auto-broadcasts. No enforcement that caller relays → silent MLS fork if dropped. Documented thoroughly in scp.ts/wasm.ts/context.rs doc-comments. Not introduced by this PR. Same class as prior reviews.

**Verification**: 379 wasm lib tests pass (incl security proof); 3 conformance removal KATs pass; wasm32 lib clippy clean; NO enforcement files touched; TS diff is doc-only.
