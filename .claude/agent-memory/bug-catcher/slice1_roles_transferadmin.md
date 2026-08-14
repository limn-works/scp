# Slice1-roles TransferAdmin convergence review (d05e8ad7d, 2026-06-24)

WASM TransferAdmin handler (manager.rs dispatch_governance_action_ext ~4055) rewritten to
match native execute_transfer_admin (governance_helpers.rs:1828). Reviewed READ-ONLY.

## Verdict: NO actionable bugs found. Convergence is correct.

Key verified facts (reusable for future WASM role reviews):
- WASM PerContextState.role_state IS the shared scp_protocol::context::roles::ContextRoleState
  (not a WASM-local reimpl). So system_assign_role semantics are identical to native.
- ContextRoleState::new ALWAYS inserts builtin "admin"+"member" role defs; builtin_admin =
  ceiling.capabilities.clone() (exactly ceiling), builtin_member = filtered-to-ceiling. So
  system_assign_role(member, "admin"/"member") CANNOT fail validate_role_definition (caps ⊆ ceiling)
  and CANNOT RoleNotFound. With the members.contains guard, all 3 failure modes are unreachable →
  "no rollback needed" claim is SOUND.
- demote-all-admins loop collects current_admins into owned Vec<String> first (releases iter borrow),
  then mutates. No mutate-while-borrowed. new_admin-already-admin case: demoted in loop then re-promoted
  → net exactly one admin. Never zero/two admins.
- Dropping creator_did write is CORRECT and load-bearing: creator_did is read at export HMAC (6475),
  export signing (6486/6687 resolves signer key from creator_did), exporter_did (6507), import check
  (6611 exporter_did==creator_did), UCAN state (3115), operator_did (4714). Old code relocated creator_did
  onto new_admin → corrupted export signing. Keeping it = original creator is consistent everywhere.
- Both new tests go through production propose_governance_action → single_admin (required==0) → auto-execute →
  dispatch_governance_action_ext. Mutation-sensitive (assert role transitions + creator_did invariant). Pass.
- make_bare_per_context_state is pub(crate) NON-cfg-gated but ALL callers are inside `#[cfg(test)] mod tests`
  (line 7638). NOT a production path. Minor cleanliness (could be #[cfg(test)]), not a bug.

## Sibling slice commits also checked (clean):
- ModifyCeiling (eb276450e): converged to set_ceiling-only; removed eager refresh that un-suspended a
  SuspendAccess member on ceiling widen (real security fix). set_ceiling_and_refresh + builtin_roles imports
  now #[cfg(test)]. Non-test build compiles.
- join_context_membership_only (d96c38c0d): rollback rolls back BOTH members + member_sequence_numbers
  atomically; system_assign_role returns before its inserts on error so no orphan assignments entry.
- Encrypted-join: MemberJoined leaf deferred until after MLS welcome (no orphan leaf on welcome failure).

## Build/test evidence
- `cargo check -p scp-ffi-wasm --target wasm32-unknown-unknown` clean (non-test build OK).
- `cargo test -p scp-ffi-wasm --lib transfer_admin` → 3 passed.
