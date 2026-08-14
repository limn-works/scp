---
name: wasm-1877-slice1-join-rollback-530752ac5
description: #1877 Slice 1 WASM ContextRoleState adoption + fail-closed join_context_encrypted rollback (530752ac5) security review — CLEAN, 1 LOW observation
metadata:
  type: project
---

# WASM #1877 Slice 1 + join rollback (530752ac5) — 2026-06-24

Branch wasm/1877-slice1-adopt-context-role-state @ 530752ac5 atop origin/main f37372b25.
3-dot diff = ONLY crates/scp-ffi/wasm/src/{manager.rs,consequence.rs}.

**VERDICT: CLEAN. No actionable security/authorization defects. 1 LOW observation (orphan event-log leaf, benign).**

**Why:** This commit + prior Slice-1 work migrated WASM PerContextState to the SHARED
`scp_protocol::context::roles::ContextRoleState` (members/assignments/member_capabilities/
ceiling/suspended_capabilities) — same type native uses.

## F1 phantom-member leak CLOSED (verified)
- `join_context` (manager.rs ~1822) adds EXACTLY: role_state.members, member_sequence_numbers[did]=0,
  system_assign_role("member") which writes assignments + member_capabilities, plus a MemberJoined
  buffer event + a MemberJoined event-log leaf.
- F1 rollback (manager.rs ~2289-2316) on join_from_welcome Err strips: members, assignments,
  member_capabilities, suspended (via suspended_for→restore_capabilities, no-op when None — safe),
  member_sequence_numbers. Returns CRYPTO_4021.
- ALL membership/authz queries derive from role_state.members / assignments / member_capabilities
  (is_member, member_count, member_dids, member_role, member_has_capability, members_contains, export).
  Rollback empties all → phantom fully absent. CANNOT panic (HashMap/HashSet removes infallible;
  suspended_for None-guarded; require_active_context_mut re-borrow correct).
- No OTHER reachable error after the inner join: the only post-join statements are
  require_active_context_mut + ctx.crypto=Some(...) (infallible).

## LOW observation (benign, not actionable)
Rollback intentionally does NOT remove the MemberJoined buffer event or the MemberJoined event-log
leaf (as-if-never-joined: must NOT emit MemberLeft). Leftover leaf is LOCAL-ONLY:
- export_context (manager.rs ~6282) builds member list from role_state.members ONLY; event-log
  leaves are NOT serialized into the snapshot → no cross-context leak on export.
- import_context (manager.rs ~6698) rebuilds membership from snap.members (explicit list), NOT by
  replaying the log → orphan leaf never reconstitutes membership.
- Joiner never entered MLS group, so no native peer shares/compares this leaf; convergent-equivocation
  invariant only bites on a SUCCESSFUL join. Pure local provenance hygiene, not authz/leak.

## F2 TransferAdmin atomicity (manager.rs ~3973) — correct
Capture old_admin_prior_role BEFORE mutation → demote old → promote new → on promote Err restore
old's prior role (creator_did not yet mutated, no restore needed) + return err → on success set
creator_did. No zero-admin vacancy. Self-transfer (old==new) net no-op. Old-admin-not-member →
prior_role None, restore skipped. Unreachable today (built-in roles infallible) but uniform.

## Unchanged gates — NO regression (final commit hunks: 1860 comment, 2271 F1, 3978 F2, 5433 comment, 11040 test)
- §5.3.1.1 ceiling grammar: create (1568), ModifyCeiling (3573/3681), import (validate_imported_ceiling_strings ~6770) untouched.
- messages:write positive role-grant + suspension gate: send_message (2028-2047), publish_broadcast (5508-5521) untouched.
- #1886 role validation on consequence path: apply_assign_role→system_assign_role (consequence.rs) validates role_definitions+ceiling, returns false on undefined → enforce_triggered escalates to SuspendAll. Intact.
- Import authz: Ed25519 sig verify + per-field validate_imported_did/string + ceiling grammar + ceiling-checked system_assign_role per member. Intact.

GOTCHA: native has no `join_context_encrypted` (WASM-bridge-specific join-then-crypto ordering;
native joins as a RESULT of processing Welcome). Rollback is a WASM-local concern.
