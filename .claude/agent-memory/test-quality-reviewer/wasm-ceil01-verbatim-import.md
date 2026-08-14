# WASM BLACK-CEIL-01: verbatim ContextRoleState import (commit f319ca863)

WASM `import_context` now restores `role_state: ContextRoleState` VERBATIM (matches native
`lifecycle_helpers::import_context`) instead of rebuilding `member_capabilities` via
`ContextRoleState::new(imported_ceiling)` + per-member `system_assign_role`.

## The bug the regression test guards (mutation-verified RED)
Old import called `ContextRoleState::new(ctx, creator, imported_ceiling, ...)` which DERIVES
built-in role defs FROM THE CEILING (`builtin_roles(&ceiling)`). So after a governed ceiling
WIDEN, `role_definitions["admin"]` = whole widened ceiling, and re-running
`system_assign_role(member,"admin")` regranted `member_capabilities` the widened cap. The
restored suspended set (captured pre-widen) did NOT contain the new cap, so
`member_has_capability(new_cap)` flipped false->true. Fix: verbatim restore, no recompute.

### Mutation-verify caveat (IMPORTANT for future reviews)
A NAIVE mutation (just re-run `system_assign_role` per member on the verbatim role_state) does
NOT reproduce the bug — `dispatch_modify_ceiling` does not rebuild `role_definitions`, so admin's
def stays stale and reassign yields the stale caps. To reproduce the bug you MUST rebuild via
`ContextRoleState::new(verbatim.ceiling())` (re-derives builtins from ceiling) THEN reassign.
Lesson: faithful mutation-verification requires the ACTUAL deleted code path, not an approximation.

## Test quality verdict: SOLID
- `import_does_not_un_suspend_capability_widened_after_suspension` — routes through PRODUCTION
  `dispatch_governance_action(ModifyCeiling/SuspendAccess)`, NOT the masking test helpers
  `set_ceiling_and_refresh`/`test_insert_ceiling` (those recompute and hide the bug). Asserts
  pre-export `!has(write)` AND post-import `!has(write)`. Mutation-verified RED.
- `test_wasm_import_rejects_malformed_ceiling_on_deserialize` — `serde_json::from_slice` is FIRST
  op in `deserialize_and_verify_envelope`, so `{"Custom":"a:b:c"}` hits `CapabilityCeilingRaw::try_from`
  -> `validate_entries` -> CTX_2032 BEFORE exporter_did bind / signature (CTX_2093). Empty sig in
  test would otherwise yield CTX_2093, so asserting CTX_2032 genuinely proves deserialize-layer.
- `import_preserves_assignment_tokens_verbatim` / `import_round_trips_role_state_verbatim` — both
  mutation-RED under recompute (tokens re-minted, nnc differs). role_state derives PartialEq/Eq so
  the verbatim eq covers ALL fields (members, assignments+tokens, member_caps, suspended, role_defs,
  ceiling, creator_did). member_sequence_numbers sidecar round-trip asserted in
  `export_import_roundtrip_preserves_role_state_model_wasm` (EXPECTED_SEQ=7).
- `snapshot_digest_changes_when_suspended_capabilities_tampered` — re-expressed to tamper via
  `role_state.restore_capabilities`; non-vacuous (base seeds the suspension via snapshot_with_sets).

## Removed-test coverage: NOT lost
`test_wasm_import_ceiling_validation_accepts_canonical_rejects_malformed` tested the deleted
string-level validator rejecting non-canonical COLON-form built-ins (`tool:invoke:*`). Moot now:
ceiling is typed `Capability` enums on the wire; built-ins serialize as variants (canonical by
construction), only `Custom(s)` can be malformed, and `validate_entries` rejects it. The
no-colon/stray-wildcard/multi-colon Custom shapes are still covered at the write path by
`test_wasm_modify_ceiling_rejects_malformed_entry`. (NOTE: task prompt claimed BOTH ceiling-string
tests were removed; `test_wasm_ceiling_paths_converge_on_canonical_form` was only MODIFIED in place.)

## Flakiness: LOW
thread_local IDENTITY_REGISTRY cleaned up at start+end of each test (defensive bracketing; thread
reuse self-heals via leading cleanup). Token nnc randomness captured pre-export, asserted preserved
verbatim — deterministic within a run, not a flakiness source. All 401 lib tests green, clippy clean.
