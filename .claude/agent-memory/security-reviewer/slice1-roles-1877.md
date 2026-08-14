# #1877 Slice 1 — WASM adopts shared ContextRoleState (post-PR#1884 rebase)

Branch `wasm/1877-slice1-adopt-context-role-state`, HEAD 848557957 atop origin/main.
Diff = manager.rs + consequence.rs only. Reviewed 2026-06-24. ZERO actionable findings.

## What changed (architecture)
- DELETED the WASM-local `ValidatedCeilingStrings` newtype + flat reimpl
  (`members: HashMap<String,MemberEntry>`, `ceiling_strings: HashSet<String>`,
  flat `suspended_capabilities`, hardcoded role resolver).
- PerContextState now holds `role_state: ContextRoleState` (shared scp_protocol type,
  same as native runtime). Ceiling lives in `role_state.ceiling()` (typed CapabilityCeiling).

## §5.3.1.1 enforcement (all 4 points intact, fail-closed, route through scp_protocol grammar)
- Grammar is NOT reimplemented in WASM — delegates to scp_protocol::context::roles:
  `Capability::validate_as_ceiling_entry` (colon/enum form) and `validate_ucan_ceiling_string`
  (UCAN form). Single source of truth.
- create_context (~1634): parse colon → `validate_ceiling_capabilities(&parsed)?` BEFORE
  mutation → CapabilityCeiling::new → ContextRoleState::new (defense-in-depth re-validate).
- ModifyCeiling dispatch_modify_ceiling (~3528): `validate_ceiling_capabilities(new_ceiling)?`
  BEFORE require_active_context_mut → set_ceiling_and_refresh → `.map_err(ceiling_validation_error)?`
  (NOT swallowed). Test asserts prior ceiling == before on reject (true fail-closed).
- set_ceiling_and_refresh (~814): `role_state.set_ceiling(ceiling)?` FIRST (error propagated
  before any role-def/member-cap mutation). `system_assign_role` discards (`let _ =`) justified
  (built-in roles re-inserted+intersected w/ ceiling, members live → always Ok).
- import_context (~6646): `validate_imported_ceiling_strings(&snap.ceiling_strings)?` BEFORE
  the lossy `ucan_string_to_capability` parse — this ORDER is load-bearing (BLACK-005): the
  parse would canonicalize a colon-form built-in `tool:invoke:*` and silently accept it.

## Write gate (2 sites, suspension-aware, intact post-rebase)
- send_message (~2007) + publish_broadcast (~5386): positive
  `role_state.member_has_capability(did, &Capability::MessagesWrite)` check.
  member_has_capability checks suspension FIRST (scp_protocol roles.rs:1544) → single check
  closes both read-only-role AND suspended-write. Distinct error msg per facet.

## #1886 role routing
- ChangeRole (dispatch_change_role ~3686) + AddMember (~3734) + consequence apply_assign_role
  → ALL route through `system_assign_role`, which enforces `validate_role_definition(role_def,
  ceiling)` (every cap within ceiling) + RoleNotFound on undefined. Fail-closed via `?`.
  AddMember rolls back membership insert on assignment failure (atomic).
- consequence apply_assign_role returns false on reject → shared enforce_triggered escalates
  to SuspendAll (no silent free-form-role acceptance like old code).

## Import trust model (correct)
- Signature authenticates ORIGIN (creator), not well-formedness. Malformed ceiling REJECTED
  (string grammar). Escalated role / dropped suspension = creator's own authority over their
  context; importer voluntarily adopts. Roles ceiling-bounded by system_assign_role. Bogus
  suspended cap (parses to Custom) is inert (suspension only removes, never grants).

## No new panic/leak
- ucan_string_to_capability = Capability::new (total, never panics; unknown→Custom).
- Production expect/unwrap: only #[cfg(test)] (make_bare_per_context_state ~1443).
- `unreachable!()` arms (3979/4164/4271/4418) = pre-existing exhaustive-match-split dispatch
  pattern (compile-checked routing), not this slice.

## Verified
- cargo clippy --target wasm32 -p scp-ffi-wasm: clean (forced rebuild).
- cargo test -p scp-ffi-wasm --lib: 394 passed. Dedicated tests for every enforcement point
  (create/modify reject malformed, import accept-canonical/reject-malformed, write-grant+suspension,
  undefined-role reject, ceiling-paths-converge, cross_impl out-of-ceiling rejected).

## GOTCHA (recurring, cost me 3 tool calls)
- Bash relative paths `crates/...` resolve against MAIN worktree (/Users/alec/Developer/limn/scp),
  NOT the slice1 worktree — cwd resets between calls. Read tool used the correct absolute slice1
  path. ALWAYS use absolute slice1 paths in Bash, or --manifest-path. grep showing `role_state`
  field while Read showed `ValidatedCeilingStrings` was the tell (main has the new merged code;
  slice1 has its own).
