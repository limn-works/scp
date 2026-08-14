# #1877 Slice 1 — subscribe rollback + role-state tests (commit 177d35b13)

Reviewed final fix commit on `wasm/1877-slice1-adopt-context-role-state`. NO actionable bugs.

## Verified-correct facts (reusable)
- WASM `member_sequence_numbers` and `role_state.members` are kept in lockstep at
  EVERY add/remove site (join_context 1858/1859, leave_context 1914, dispatch_add_member
  3738/3746, remove 3870, subscribe 5341/5350). Invariant: DID in seq-map IFF in members.
  So subscribe-rollback `.remove()` only erases what it just inserted (guarded by
  `if !members.contains`).
- `ContextRoleState::new` ALWAYS registers builtin_roles + builtin_broadcast_roles
  (incl. "subscriber"), so subscriber role always exists in role_definitions.
- `builtin_subscriber`/`builtin_moderator` INTERSECT desired caps with ceiling, so a
  built-in role's caps are ceiling-subset by construction → `system_assign_role` ceiling
  check (validate_role_definition) cannot fail for a built-in role.
- `system_assign_role` validates member-present + role-found + ceiling BEFORE mutating
  self → error return leaves role_state internals untouched.
- => subscribe rollback for "subscriber" is effectively UNREACHABLE defensive code
  (fail-closed, correct). The non-rolled-back `bc.subscribe()` registration on the
  error path is therefore NOT a live bug (latent only — would orphan a subscriber if
  the subscriber role were ever undefined, which it can't be).

## Test review
- export_import_roundtrip_preserves_role_state_model_wasm: exercises REAL
  export_context→import_context (sign/JCS/verify). Suspension restored via
  snap.suspended_capabilities (import line ~6701). Moderator grants MessagesWrite so
  suspending messages:write is meaningful, not a no-op. cleanup_identity_registry()
  bookends thread-local registry (start+end) — no cross-test pollution. Member DID
  unregistered is fine (import only verifies exporter/creator key).
- test_member_sequence_number: #[cfg(test)], reads correct map.
- All panic!/expect/index in added lines are inside #[cfg(test)].

## Results
- `cargo test -p scp-ffi-wasm`: 395 passed, 0 failed. New tests pass.
- `cargo clippy -p scp-ffi-wasm --all-targets`: clean.
