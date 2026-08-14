---
name: wasm-slice1-roles-addmember-review
description: Review of dcb3beb25 (slice1-roles) — conditional add-member rollback fix + 3 tests; suite SOLID; only real gap is leave_context (zero tests)
metadata:
  type: project
---

# WASM slice1-roles — commit dcb3beb25 (conditional add-member rollback + 3 tests)

HEAD dcb3beb25 review verdict: **SHIP**. All three new tests are non-vacuous and go through the PRODUCTION dispatch path.

**Why the regression test is sound:** `dispatch_ceiling_capability(AddMember)` returns `None` (manager.rs ~3331) so the AddMember rejection comes from `dispatch_add_member`'s `system_assign_role` role-validation, not the ceiling gate — the path under test. `member_has_capability` reads `assignments`/`member_capabilities` (independent of `role_state.members` and `member_sequence_numbers`), so the OLD unconditional `members.remove`/`member_sequence_numbers.remove` was genuinely observable as RED (split-brain: caps retained, membership gone). The fix captures `member_was_present`/`seq_was_present` before the inserts and only undoes novelty.

**Production-path proof:** `propose_governance_action` (required==0 single_admin auto-execute) → `execute_governance_action` → `dispatch_governance_action` → `dispatch_add_member`. Creator has governance:propose via creator=admin in `make_bare_per_context_state` (ContextRoleState::new auto-assigns admin).

**Consequence test** uses the REAL shared `enforce_triggered` from `scp_protocol::trust::consequence` via production `WasmConsequenceDispatcher`; `apply_assign_role`→`role_state_system_assign_role` validates role. Non-vacuous: asserts role unchanged + cap denied + exactly-one ConsequenceEscalatedToSuspendAll leaf delta (leaves_before captured).

**Self-validating role assumptions:** tests assert `moderator`/`member` grants `messages:read` BEFORE the bad operation, so if the built-in role weren't valid the test fails at setup, not silently passes.

## Membership-mutation coverage matrix (this slice)
- AddMember: success (new) ✓ + failure-new-rollback (add_member_with_undefined_role_is_rejected) ✓ + failure-existing-no-evict ✓ NOW
- RemoveMember: rich success coverage (mls/no-mls/broadcast/self/empty-commit) ✓; NOT-FOUND (CTX_2015) rejection has NO dedicated test (low value — simple guard)
- ChangeRole: success ✓ + failure-state-unchanged ✓
- join_context_encrypted: success ✓ + welcome-failure-rollback ✓
- TransferAdmin: to-member demote/promote+creator_did-invariance ✓ + to-nonmember reject ✓
- **join_context (NON-encrypted): NO success/rollback behavioral test** (only rejects_paid_context) — GAP
- **leave_context: ZERO tests** — biggest GAP. Mutates members/assignments/member_capabilities/suspensions/seq/broadcast/crypto, emits MemberLeft leaf, auto-closes. now_secs() works on native (SystemTime fallback in time.rs cfg(not wasm32)), so it IS testable — absence is a real gap, not a platform constraint.

## Flakiness
None. Fresh WasmContextManager::new() per test (no globals), distinct context_ids, no thread_local identity registry usage (no signed export), no wall-clock assertions.

## Closing tests for the two real gaps
- `leave_context_strips_all_member_state_and_emits_member_left_wasm` (success: removed from members, caps stripped, seq deleted, MemberLeft leaf, last-member auto-close to "closing")
- `leave_context_nonmember_is_rejected_wasm` (CTX_2015, no mutation)
- (lower value) `remove_member_nonmember_is_rejected_wasm` (dispatch_remove_member CTX_2015)
- (lower value) `join_context_succeeds_adds_member_wasm`
