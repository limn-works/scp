---
name: wasm-1877-role-state-rebase
description: CLEAN review of #1877 slice 1 (WASM adopts shared ContextRoleState) rebased onto #1884 ceiling-grammar; manager.rs + consequence.rs
metadata:
  type: project
---

# #1877 Slice 1 — WASM adopts shared ContextRoleState (rebase onto #1884)

CLEAN review (HEAD 848557957, three-dot diff = manager.rs + consequence.rs ONLY). 394 wasm-ffi lib tests pass; wasm32 cargo check clean.

**Why:** Verify the rebase reconciliation that deleted `ValidatedCeilingStrings` newtype + `capability_to_ucan_format`, added `validate_ceiling_capabilities`/`validate_imported_ceiling_strings` + fallible `set_ceiling_and_refresh`, and replaced the flat WASM model (`members: HashMap<MemberEntry>`, `ceiling_strings`, `suspended_capabilities`, `creator_did`) with the shared `scp_protocol::context::roles::ContextRoleState` + a separate `member_sequence_numbers` map.

**How to apply / verified facts:**
- `set_ceiling_and_refresh` is fail-closed: `set_ceiling()?` validates+installs whole replacement BEFORE touching role_definitions/member_caps; on Err the prior ceiling/roles/caps are unchanged. The "discarded system_assign_role result is always Ok" claim holds — WASM NEVER inserts custom role definitions (only builtin_roles + builtin_broadcast_roles rebuilt), and builtins intersect with ceiling so validate_role_definition can't fail; assignments are drawn from live `assignments` so MemberNotInContext can't fire.
- Custom roles can never be successfully assigned (system_assign_role rejects RoleNotFound), so no member ever holds a non-builtin role — the refresh assumption is sound.
- ModifyCeiling SHRINK + suspended member: system_assign_role's prune_suspensions_to_role_grants drops suspensions for caps the new (intersected) role no longer grants. Fail-safe (member also loses the cap via ceiling). Matches native.
- send_message + publish_broadcast positive gate (`member_has_capability(did, MessagesWrite)`) is suspension-aware (shared type checks suspended set first). All production broadcast-author registration paths (create=creator-admin, AddMember role=author, ChangeRole→author) seed the author as a write-granting member, so the new positive gate is NOT a regression — it's tighter-but-correct.
- member_sequence_numbers seeded on ALL add paths (create/join/add_member/subscribe/import/test_insert_member) and dropped on ALL remove paths; send's `.entry().or_insert(0)` is defensive.
- RemoveMember/leave clear assignments+member_capabilities+suspensions(via restore_capabilities)+seq+read_exclusion — goes one step beyond native (native leaves suspended_capabilities). No re-admit phantom-state foothold.
- Import: validate_imported_ceiling_strings (UCAN-form) runs BEFORE lossy ucan_string_to_capability parse (closes BLACK-005 non-canonical colon-form built-in). role_state rebuilt from snapshot (creator auto-admin cleared then rebuilt purely from snap.members), suspensions restored AFTER assignment so prune runs on empty set.
- ucan_string_to_capability = Capability::new round-trips compound builtins (bridging:*→Bridging, tool_invoke:*→ToolInvokeAll, context_child:create→ChildContextCreate, tool_invoke:<id>→ToolInvoke(id)) — verified by test_wasm_ucan_string_to_capability_roundtrips_compound_builtins.
- consequence.rs apply_assign_role now returns false on undefined role (#1886); shared enforce_triggered escalates `false`→suspend_all (consequence.rs:1304/1312) — fail-safe tightening.
- No production unwrap/expect/panic introduced (only #[cfg(test)] make_bare_per_context_state .expect; unreachable! arms are sound exhaustive guards).
- Non-actionable pre-existing: SuspendCapability/SuspendAccess/RevokeAccess don't membership-check before suspending; harmless (export only emits suspensions for current members; non-members can't send). NOT introduced by this rebase.

**GOTCHA for future reviews of this worktree:** the harness Read tool returned STALE content for manager.rs (showed deleted `ctx.members` / `capability_to_ucan_format` code that is NOT in HEAD). `git diff HEAD -- file` was empty and grep count was 0. ALWAYS verify suspicious manager.rs regions via `git show HEAD:...` here, not the Read tool.
