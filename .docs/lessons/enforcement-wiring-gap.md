# Enforcement Functions Must Be Wired Into Their Call Sites

**Rule**: When a security enforcement function exists in one module, verify it is actually *called* at every invocation point that requires it. The existence of a check function does not imply it is used. Audit callers, not definitions.

**Context**: Three spec requirements had partial or absent enforcement in the SCP codebase:

1. **Chain depth limit** (spec 6.2): `check_chain_depth` existed in `provenance/attach.rs` with `DEFAULT_MAX_CHAIN_DEPTH = 3` (now 8 per ADR-043) and 34 tests, but was never called from `invoke_cross_context` in `outlets/interface.rs`. Cross-context outlet calls could chain indefinitely.

2. **Per-caller session cap** (spec 6.2.1): The spec requires a cap (now default 1000, context-configurable via `ContextParams::session_cap` per ADR-043) per calling context, but `create_session` in `outlets/session.rs` had no cap enforcement at all. Any caller could exhaust sessions.

3. **Schema specificity floor** (spec 6.2): The spec requires minimum 2 distinct fields in outlet schemas to prevent degenerate broad-schema outlets, but `register_outlet` in `outlets/registry.rs` only checked structural validity (is-an-object, has-type-field), not field count.

**Fix**: Wired `chain_depth` enforcement into `invoke_cross_context`, added `count_by_source` and cap check to `create_session`, added `validate_specificity_floor` to `schema.rs` and wired it into `register_outlet` and `update_outlet`.

**Lesson**: Spec audits must trace requirements end-to-end from spec text through to the exact enforcement point in code. A common failure mode is: the spec says X, a helper function for X exists, the story for X is marked "done" -- but the helper is never called at the point where it matters. Grep for callers of enforcement functions, not just their definitions. PRD acceptance criteria that don't explicitly name enforcement points allow this gap to persist.
