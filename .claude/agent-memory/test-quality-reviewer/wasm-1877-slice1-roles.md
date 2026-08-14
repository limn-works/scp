---
name: wasm-1877-slice1-roles
description: Test-hardening review of WASM #1877 slice-1 role-state adoption (CTX_2015 assertions, AddMember rollback, export/import round-trip, subscribe-rollback dead code)
metadata:
  type: project
---

# WASM #1877 slice-1 role-state test hardening (commit 177d35b13)

Reviewed the 3 requested test hardenings in `crates/scp-ffi/wasm/src/manager.rs`. Suite is solid; one observation worth keeping.

**Why:** map_role_error unconditionally returns ScpWasmError::Context{code: CTX_2015} for ALL RoleError variants (RoleNotFound, OutOfCeiling, MemberNotInContext). So asserting CTX_2015 confirms "a role error happened" but does NOT distinguish RoleNotFound from other role errors. Acceptable here because the only reachable role error in these tests is RoleNotFound, but the assertion is weaker than the comment claims ("the RoleNotFound code" — there is no RoleNotFound-specific code).

**How to apply:**
- AddMember rollback test: `member_role == None` assertion is VACUOUS w.r.t. rollback (system_assign_role returns RoleNotFound at step 2 BEFORE writing `assignments`, so member_role is None regardless of rollback). The `test_member_sequence_number == None` assertion is the GENUINE rollback proof (seed inserted before system_assign_role).
- `subscribe_broadcast` rollback (added by THIS commit) is effectively DEAD/unreachable: role is hardcoded "subscriber" (always seeded by ContextRoleState::new → no RoleNotFound); builtin_subscriber intersects MessagesRead with ceiling → empty role validates fine → no OutOfCeiling; member inserted immediately before → no MemberNotInContext. No test exists and none can be written without contriving impossible state. Untestable-because-unreachable, not a true coverage gap.
- export/import round-trip test is fully non-vacuous: real Ed25519+HMAC signed envelope, import genuinely reconstructs role/sequence/suspensions; moderator genuinely grants messages:write (verified builtin_moderator) so the suspension assertion truly tests suspension not a role gap.
- Identity registry is thread_local (per-test-thread). Round-trip test relies on src+dst managers sharing the thread-local registry on the same test thread. cleanup before+after is adequate.

# ModifyCeiling convergence regression (commit eb276450e)
- WASM `dispatch_modify_ceiling` now calls `role_state.set_ceiling` ONLY (matching native `apply_pending_ceiling_modification`); the eager per-member `system_assign_role` refresh was REMOVED. `set_ceiling_and_refresh` is now `#[cfg(test)]`-only scaffolding (used by `manager_with_governed_context`, `test_insert_ceiling`); `builtin_roles`/`builtin_broadcast_roles` imports gated `#[cfg(test)]`.
- Security bug fixed: on a ceiling WIDEN, the old refresh recomputed a SuspendAccess'd member's `member_capabilities` to include the new cap, but `prune_suspensions_to_role_grants` is SHRINK-only so the suspended set never gained it → member silently regained authority.
- Regression test `test_wasm_suspended_member_stays_suspended_across_ceiling_widen` (manager.rs ~9694): VERIFIED non-vacuous. Asserts (a) ceiling WAS widened (set_ceiling ran), (b) suspended member does NOT gain messages:write, (c) stays suspended for messages:read. Goes through REAL production dispatch (SuspendAccess + ModifyCeiling via dispatch_governance_action). Counterfactual CONFIRMED via shared-type semantics (suspend_all snapshots effective caps pre-widen; member_has_capability checks suspension-set first): under old refresh, assert (b) FAILS. Coder's mutation claim is correct. Test setup seeds `member:ban` because SuspendAccess is ceiling-gated on member:ban (dispatch_ceiling_capability); ModifyCeiling is NOT ceiling-gated.
- 114/114 manager::tests pass; no flakiness (deterministic, WasmClock, fixed DIDs).

# Slice-1 suite completeness (commit eb276450e)
- messages:write gate: read_only_role_member_cannot_send_message / write_granting_role_member_can_send_message / suspended_write_member_cannot_send_message / publish_broadcast_enforces_write_role_grant_and_suspension — all non-vacuous, assert distinct error messages + seq-number side effects. SOLID.
- #1886 undefined-role: change_role_to_undefined_role_is_rejected_wasm + add_member_with_undefined_role_is_rejected_wasm + change_role_to_defined_role_succeeds_wasm (positive guard). Honestly document CTX_2015 generic-code limitation. AddMember rollback proof = sequence-number==None (load-bearing); member_role==None is supplementary.
- export/import round-trip: export_import_roundtrip_preserves_role_state_model_wasm — role+suspension+seq, pre-roundtrip sanity asserts. SOLID.
- membership rollback: join_context_encrypted_rolls_back_membership_on_welcome_failure (no orphan leaf + no phantom buffer event) + ..._appends_one_member_joined_leaf_on_success + self-removal/broadcast empty-commit leaf tests. SOLID.
- GAP (LOW): TransferAdmin has only `serde_roundtrip_transfer_admin` (wire shape). The handler (manager.rs ~4081) has real demote-old/promote-new/update-creator_did logic + documented-unreachable rollback, but NO behavioral test asserts the role swap + creator_did update. Closes by: a test that TransferAdmins to an existing member and asserts old admin→member, new admin→admin, creator_did updated.
- GAP (ACCEPTABLE/native-parity): a ceiling NARROW leaving member_capabilities stale (lazy-narrow) is UNTESTED. This is native-parity + the deferred two-phase governed-ceiling slice; acceptable to leave untested per the deferred-slice boundary. Would be nice-to-have: assert a narrow leaves a member's stale cap until next assignment, matching native.
