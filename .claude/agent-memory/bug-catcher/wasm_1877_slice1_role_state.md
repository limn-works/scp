# WASM #1877 Slice 1 — adopt shared ContextRoleState (commit c65552c9e)

CLEAN review. WASM PerContextState replaced flat role model (members:HashMap<MemberEntry>,
ceiling_strings, suspended_capabilities, creator_did) with scp_protocol ContextRoleState +
member_sequence_numbers:HashMap<String,u64> (MLS counter carved out). Verified at the REAL
target commit c65552c9e (parent a81c15f6e), NOT the worktree HEAD.

## ENVIRONMENT TRAP (cost ~10 tool calls)
The worktree /Users/alec/.../slice1-roles was checked out on the WRONG branch
(recovered/pyo3-inmem-did-resolver-dht-20260624, HEAD e8683f79a) at review time, with an OLD
flat-model roles.rs/manager.rs. `git log -1` reported c65552c9e but `git rev-parse HEAD` gave
e8683f79a. ALWAYS `git rev-parse HEAD` to confirm; if it differs from the target SHA, review the
target commit directly via `git show <sha>:path` and a `git worktree add --detach <sha>` for
build/test. roles.rs differs hugely between the two branches (target has ceiling()/set_ceiling()/
suspended_for()/system_assign_role() methods; the wrong branch's roles.rs has only free fns).

## Verified correct
- Compiles clean on wasm32-unknown-unknown; 382 native lib tests pass; clippy -D warnings clean
  (both `--target wasm32` lib and native --all-targets).
- member_sequence_numbers lifecycle COMPLETE: seeded on create/join/add/subscribe/reset/import +
  test_insert_member; incremented in send_message AND publish_broadcast (both via entry().or_insert(0)
  after a membership-contains guard, matching old get_mut-or-err); dropped on leave/remove/add-rollback;
  round-trips through export (get().copied().unwrap_or(0)) and import (verbatim).
- ucan_string_to_capability: only tool_invoke: and context_child: are compound (underscore) resources;
  all others are single-segment colon form identical in both encodings, so Capability::new(rest) is
  correct. dispatch_ceiling_capability static strings (member:ban/tool:register/context_child:create/
  tool:interface) all map correctly. Round-trips with ucan_capability_name on export/import.
- #1886 fix: system_assign_role validates role against role_definitions AND
  validate_role_definition(ceiling) at mint time. ChangeRole/AddMember/TransferAdmin/ResetMember/
  consequence AssignRole all route through it; undefined/out-of-ceiling rejected. AddMember rolls back
  members+sequence insert on failure (fail-closed atomicity). Error mapping via map_role_error ->
  CTX_2015 / CTX_2032; consequence apply_assign_role returns is_ok() -> false (escalates to SuspendAll).
- suspend_all semantics change: governance SuspendAccess now uses role_state.suspend_all (copies
  member_capabilities only) vs old whole-ceiling; functionally equivalent for enforcement (member only
  ever had role caps); CapabilitiesSuspended event uses vec![] (all) so no wire divergence. Consequence
  apply_suspend_all still iterates ceiling_strings_pub ∩ member_has_capability.
- Import: ContextRoleState::new(creator,creator,...) then context_id corrected BEFORE member loop, then
  members/assignments/member_capabilities cleared and rebuilt purely from snapshot (handles
  creator-left). Suspensions applied AFTER role assignment (so prune in system_assign_role is a no-op
  on them — correct). Minted tokens get corrected context_id.
- make_bare_per_context_state .expect() is #[cfg(test)] + infallible (empty ceiling, no custom roles).
  WasmClock falls back to SystemTime on native (time.rs), so test-target token minting needs no JS.

## Latent fragilities (NOT bugs — documented invariants hold)
- set_ceiling_and_refresh swallows system_assign_role errors via `let _ =`. Safe ONLY because WASM
  assigns built-in role names only, and builtins are rebuilt within the new ceiling before the loop, so
  validate_role_definition can't fail. If WASM ever assigns a custom role, a ceiling shrink would leave
  STALE member_capabilities (insert skipped). Guard: WASM-only-builtins invariant.
- export suspended_capabilities iterates role_state.members only (old code iterated the raw map). Safe
  because suspensions are always keyed to members and cleaned on removal (restore_capabilities). A
  suspension on a non-member would be dropped on export — but no path leaves one.
