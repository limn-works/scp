# slice1-roles WASM slice review (HEAD a56fd0e31)

## FINDING (HIGH, data corruption / privilege retention)
`dispatch_add_member` (manager.rs ~3861) lacks the already-member guard that
`dispatch_change_role`/`dispatch_remove_member`/TransferAdmin/subscribe/join all
have. It unconditionally `members.insert(did)` + `member_sequence_numbers.entry().or_insert(0)`,
then on `system_assign_role` failure (undefined/out-of-ceiling role — RoleNotFound
reachable, role is caller-supplied) rolls back with `members.remove(did)` +
`member_sequence_numbers.remove(did)`.

For an ALREADY-PRESENT member M: insert/or_insert are no-ops, assign fails,
rollback EVICTS the pre-existing M from `members` and deletes M's seq counter,
but leaves `assignments`/`member_capabilities` intact (rollback doesn't touch them,
and system_assign_role errors BEFORE its own step-4 insert).

Result: M absent from `members` (is_member/member_count/member_dids say gone) but
present in assignments (member_role returns old role) and member_capabilities.
`ContextRoleState::member_has_capability` keys ONLY off member_capabilities (no
membership check) → M retains messages:write etc. despite not being a member.

Reachability: AddMember{did: existing_member, role: undefined} flows from
propose/execute straight to dispatch_add_member; NO upstream already-member guard.

Native parity: native `execute_add_member` (governance_helpers.rs:1148) does
members_mut().insert + system_assign_role and returns Err WITHOUT removing on
failure (coalesce-window-rollback acceptable). So native does NOT corrupt M.
WASM's eager `members.remove` is the divergence.

Fix: add `if ctx.role_state.members.contains(did)` already-member guard at the top
of dispatch_add_member (reject, matching native CTX_2015 semantics), OR make
rollback conditional on `members.insert` having returned true (genuinely new).
Existing test `add_member_with_undefined_role_is_rejected_wasm` only covers NEW
member — already-member case untested.

## CLEAN areas verified
- export/import: ContextRoleState sets use serde_sorted_set/_map codecs; sidecar
  member_sequence_numbers in signed digest; verbatim single-signer model sound;
  no panic on desynced sidecar (all access via .entry/.get). Tests non-vacuous.
- send/publish messages:write gate: suspension-aware, distinct suspended-vs-not-granted.
- TransferAdmin: demote-all (owned Vec, no borrow conflict) then promote; idempotent.
- join/join_encrypted/subscribe rollbacks: guarded by membership check first, clean.
- consequence.rs: delegates to shared ContextRoleState; clean.
- import validation fails closed; no crafted-input panics.
