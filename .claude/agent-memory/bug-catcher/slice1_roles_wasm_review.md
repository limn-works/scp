---
name: slice1-roles-wasm-review
description: Bug sweep of slice1-roles WASM ContextRoleState adoption (manager.rs/consequence.rs, HEAD cde3c1002) — CLEAN, one LOW latent note
metadata:
  type: project
---

# slice1-roles WASM ContextRoleState adoption review (HEAD cde3c1002)

Scope: crates/scp-ffi/wasm/src/{manager.rs,consequence.rs}. Read authoritative via `git show HEAD:` (Read tool serves stale on this worktree). 126 manager + 31 consequence tests pass on native target.

## Verdict: CLEAN. No actionable bugs.

Verified solid:
- **Membership rollbacks** (dispatch_add_member, join_context_membership_only, subscribe_broadcast, join_context_encrypted): all conditional-on-novelty, no split-brain. add_member only evicts if `!member_was_present`/`!seq_was_present`. encrypted-join Welcome-failure rollback strips members+assignments+member_capabilities+suspensions+seq (matches leave_context teardown minus side-effects). No gone-from-members-but-retains-caps window.
- **restore_capabilities** operates only on suspended_capabilities map (independent of member_capabilities), so calling it AFTER member_capabilities.remove(did) is fine. All callers clone suspended set into Vec first → no borrow-invalidation.
- **dispatch_remove_member**: MLS eviction FIRST (hard boundary), strip+MemberLeft leaf only after crypto succeeds. Fail-closed-keep proven by test. No-MLS-leaf = no-op empty commit, proceeds to strip (native parity).
- **TransferAdmin**: reject-non-member-before-mutate; demote-all-admins-to-member then promote-new; built-in roles always in role_definitions (ContextRoleState::new) so system_assign_role("member"/"admin") infallible → no partial-demote split. creator_did never touched.
- **ModifyCeiling**: set_ceiling-only, no member_capabilities refresh (stale-on-ceiling-change = native parity); widening does NOT un-suspend (closes BLACK-CEIL-01).
- **send/publish messages:write gate**: single suspension-aware member_has_capability(MessagesWrite) check closes both read-only-role and suspended-write facets.
- **Export/import determinism**: ALL HashSet fields in ContextRoleState (members, member_capabilities, suspended_capabilities, role_definitions→RoleDefinition.capabilities, ceiling→CapabilityCeiling.capabilities) use `#[serde(with=serde_sorted_set[_map])]`. canonicalize_snapshot_sets handles the non-role_state Vecs (read_exclusion, revoked_tokens, seen_nonces_v3, executed_proposals, broadcast block lists). JCS handles object-key order. Vec fields (tokens, att) roundtrip in order. Producer+verifier both sort identically → signatures reproducible. import restores role_state VERBATIM (no recompute). exporter_did==creator_did enforced; Ed25519 verify_strict; version gate fails-closed.
- New tests (leave_context trio, join_context success, remove_member nonmember) non-vacuous, drive production handlers, assert exact leaf-count/ordering/actor_did/timestamp.

## LOW latent note (NOT reachable in production, do not file)
execute_governance_action: if dispatch returns Ok but the subsequent `parse_proposal_id_bytes(proposal_id)?` (manager.rs ~3586) errored, you'd get partial execution (member already removed + MemberLeft leaf appended in dispatch_remove_member, but no GovernanceActionExecuted leaf, executed_proposals NOT rolled back since we're in the is_ok branch). UNREACHABLE because propose_governance_action validates proposal_id via parse_proposal_id_bytes BEFORE tracking (line 4923), and only tracked/approved proposals reach execute. Would become reachable if a future path inserts a pending/resolved proposal with an unvalidated string id. Defensive fix if ever wanted: parse proposal_id_bytes once up-front in execute before dispatch.

## Intentional documented divergences (NOT bugs)
- Per-author message sequence POST-increment from base 0 (first msg seq=0) vs native PRE-increment (seq=1). Documented, ADR-050 out-of-byte-parity scope, increment direction convergence deferred.
- Per-action EventType leaves (AdminTransferred, CeilingModified) not emitted by WASM — deferred to per-action-leaf-parity workstream (ignored wasm_native_full_governance_eventtype_parity_pending test).
- join_context_encrypted consumes pending_key_packages entry, NOT restored on Welcome-failure rollback (caller must regenerate key package). Acceptable.
- ChangeRole/AddMember broadcast add_author/block_author errors swallowed (`let _ =`), fails closed (can't publish), native parity.
