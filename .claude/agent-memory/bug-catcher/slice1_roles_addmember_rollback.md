# Slice1-roles: conditional add-member rollback review (dcb3beb25, 2026-06-24)

VERDICT: fix correct + complete. No actionable bugs found in the slice.

## The fix
`dispatch_add_member` (wasm/manager.rs ~3880) now captures `member_was_present`/`seq_was_present`
BEFORE the insert + `or_insert(0)`, and on `system_assign_role` failure only removes what THIS
call added. Prevents split-brain (existing member dropped from `members`+seq but keeping
`assignments`/`member_capabilities` → membership-gone yet caps retained).

KEY CORRECTNESS PROOF: `ContextRoleState::system_assign_role` (scp-protocol/roles.rs:1731)
validates in order: (1) member-in-context, (2) role exists, (2a) `validate_role_definition`
ceiling check — ALL before step 4 mutates assignments/member_capabilities. So a failed re-add
of an existing member leaves assignments/caps untouched → conditional rollback keeps them fully
intact. `member_has_capability` (roles.rs:1544) reads member_capabilities NOT members, so under
the OLD bug caps survived while membership vanished — exactly the split-brain.

4-case matrix all correct. `or_insert(0)` vs `seq_was_present`: an existing member always had a
seq entry (test_insert_member/join seed it) → seq_was_present=true → seq not removed. Coherent.

## All other membership-mutation paths traced — NONE has the bug class
- `join_context_membership_only` (~1810): already-joined guard CTX_2013 before insert →
  unconditional rollback only reachable for NEW members. Safe.
- `subscribe_broadcast` (~5575): guarded by `!members.contains`. Safe.
- `dispatch_reset_member` (~4710): member-exists guard, re-assigns SAME defined role, seq reset
  AFTER success. Safe.
- `dispatch_change_role` (~3843): member-exists guard, system_assign_role validates pre-mutate.
- `dispatch_remove_member` (~3957): MLS-first hard boundary, returns Err while member fully
  present; on success does COMPLETE strip (members+assignments+caps+suspensions+seq+read_excl).
- `leave_context` (~1949): membership-gated, complete strip.
- `join_context_encrypted` join_from_welcome rollback (~2363): COMPLETE strip; only reachable
  for new member (upstream already-joined guard). Correctly unconditional+full (it inserted full
  assignments/caps that must be undone) — NOT contradictory with add_member's conditional pattern.
- TransferAdmin (~4147): membership guard pre-mutate; demote-all-admins then promote; built-in
  roles can't fail. Theoretical no-admin window unreachable by construction; matches native.

## Native convergence
native execute_add_member (governance_helpers.rs:1148): inserts members + system_assign_role,
on failure returns early WITHOUT rollback (best-effort, coalesce-window acceptable ADR-049 §9);
on SUCCESS emits MemberJoined UNCONDITIONALLY even for re-add. WASM's unconditional MemberJoined
on success therefore CONVERGES with native (not a spurious-event bug). WASM is STRICTER than
native in failure case (rolls back genuinely-new member; native keeps it) — benign, both
acceptable per §9.

## Tests (all pass on native; verified `cargo test -p scp-ffi-wasm`)
- add_member_existing_member_bad_role_does_not_evict_wasm: bug-detecting asserts are (b)
  is_member + (d) test_member_sequence_number==Some(0) — both flip under old unconditional
  rollback. (c) member_has_capability would still pass under bug (caps survive) but doesn't mask
  (b)/(d). Mutation-sensitive, through production propose_governance_action path.
- add_member_with_defined_role_succeeds...: real dispatch success path; asserts exactly 1
  MemberJoined.
- enforce_triggered_assign_role_undefined_role_escalates_to_suspend_all: apply_assign_role→
  system_assign_role rejects undefined role→false→enforce_triggered escalates to suspend_all,
  mints ConsequenceEnforcementFailed + ConsequenceEscalatedToSuspendAll (consequence.rs:1306).
  Asserts role unchanged, caps fully suspended, exactly 1 escalation leaf. Non-vacuous.
