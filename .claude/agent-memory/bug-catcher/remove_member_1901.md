# #1901 ContextRoleState::remove_member (commit 139e35aae) — CLEAN

Shared `ContextRoleState::remove_member(&mut self, &str) -> bool` clears all 4 per-DID
maps (members/assignments/member_capabilities/suspended_capabilities); returns
members.remove() bool. Verified:
- Struct has exactly 4 per-DID maps; role_definitions keyed by role-name (not per-DID,
  correctly NOT touched). No missed map. No borrow issue, no must_use, no name collision
  (membership.remove_member is a different type MembershipState).
- Native execute_remove_member (governance_helpers ~1316) + leave_context
  (lifecycle_helpers ~333): repoint preserves members/assignments/member_capabilities,
  ADDS suspended_capabilities; access_key_store.remove + peer_registry.remove stay inline;
  read_exclusion_list.remove NEWLY added (mirrors execute_restore_access@1078). Both inside
  commit_class_s_keep. leave_context not-found guard on membership.remove_member (-> bool
  on role_state correctly unused).
- WASM 3 sites: leave_context(2367), join_context_encrypted rollback(2809),
  dispatch_remove_member(4498). restore_capabilities dance replaced; removed_role captured
  BEFORE remove_member (used for broadcast-author cleanup@4520); member_sequence_numbers +
  read_exclusion_list kept inline. restore_capabilities still used@4668(unban) — no dead
  import. WASM read_exclusion_list is HashSet<String> (pre-existing divergence from native
  HashSet<DID>; both .remove typecheck in-crate).
- Tests non-vacuous: native clears_suspension/clears_read_exclusion/readmit_regression +
  WASM readmit. member_has_capability checks suspension first, so readmit→true genuinely
  proves no phantom suspension. 1.1s tokio sleep = legit fix for compute_proposal_id
  seconds-granularity duplicate-id rejection (§5.9 replay), deterministic, not flaky.
- Edit-tool-no-op concern (governance/lifecycle/05-contexts re-applied via heredoc):
  committed state verified CORRECT and COMPLETE via git show.

No bugs. Sound.
