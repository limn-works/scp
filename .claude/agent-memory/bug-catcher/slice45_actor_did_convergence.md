---
name: slice45-actor-did-convergence
description: Review of fix/leaf-actor-did-convergence (native↔WASM Merkle leaf actor_did + accept/reject convergence, §9.9.3). CLEAN.
metadata:
  type: project
---

# fix/leaf-actor-did-convergence review (2026-06, base b5b0eb02c, top 501a44f6a)

CLEAN review — no defects found. Native↔WASM Merkle event-log leaf convergence (§9.9.3).

**Why:** Convergence-critical: honest members at equal event_count must derive byte-identical roots. Native minting a leaf where WASM rejects = equivocation false-positive.

**How to apply:** When reviewing further slices in this series (Tasks #205 consequence-subject, #206 per-action leaf parity), the verified-correct baseline established here:

- System-leaf sentinels hoisted to `scp_event_log::system_actors`: SYSTEM_TIMER_ACTOR="system:timer", SYSTEM_CLOSE_ACTOR="system:close", SYSTEM_SAGA_ACTOR="system:saga", SYSTEM_CONSEQUENCE_ACTOR="system". Both bridges reference consts (convergent by construction).
- Native has EXACTLY 7 per-action ceiling gates (`ceiling.contains(&Capability::X)`): MemberBan×4 (execute_suspend_member, execute_revoke, execute_restore_access, inline SuspendAccess), ToolRegister×1 (execute_register_tool), ChildContextCreate×1 (execute_create_child_context L1689), ToolInterface×1 (execute_establish_tool_interface L1977). WASM `dispatch_ceiling_capability` mirrors exactly: member:ban / tool:register / context_child:create / tool:interface; all other variants → None. EXHAUSTIVE match, no wildcard (compile-enforced).
- Ceiling string forms verified against `Capability::ucan_capability_name()`: ChildContextCreate → "context_child:create" (underscore, 3-seg via ucan_resource_action), ToolInterface → "tool:interface" (2-seg unchanged). WASM `capability_to_ucan_format` correctly converts "context:child:create"→"context_child:create". Default ceiling (native default_ceiling == WASM build_ceiling_strings empty-input) excludes all 4 gated caps → both reject on default ceiling.
- Executor stamping: quorum→voter_did, auto/direct→proposer_did. Native finalize_governance_action + dispatch_governance_action both use executor_did. Consequence SUBJECT remains proposer_did (NOT executor) — Task #205 is the pending divergence, deliberately out of scope.
- Replay: WASM_PROPOSAL_TTL_MS now 14d = native EXECUTED_PROPOSALS_TTL_SECS (14*24*60*60). status==Approved precondition + executed_proposals replay guard prevent double-execute and zero-execute.
- Rollback: on dispatch failure, execute removes executed_proposals marker; propose/vote callers remove resolved + reinsert pending_snapshot (captured post-vote, preserves approval). GovernanceVoteCast leaf is NOT rolled back — matches native (event appends non-transactional).
- TTL deadline math: WASM close_leaf_secs + expiry_leaf_secs both = creation.saturating_add(ttl) (None→now_secs). = native deadline_unix_secs (creation+ttl). ExtendTtl saturating_add on both. Algebraically equal incl. extension.
- KATs in consequence.rs cross_impl_leaf_parity are NOT tautological: reconstruct from independent shared scp_event_log primitives + non-vacuity controls (assert_ne pre-fix bytes diverge). Native side has matching governance_integration.rs tests driving real Supervisor + MerkleEventLogProvider.

**Pre-existing (NOT this diff, latent):** WASM `execute_governance_action` dispatches on the caller-supplied `action` param, NOT `proposal.action` (native uses proposal.action only). Direct-FFI path could execute action Y while stamping proposal P's timestamp/proposer. Old signature already took `action` separately — pre-existing shape, not introduced here. Worth flagging if direct-execute FFI surface is hardened later.
