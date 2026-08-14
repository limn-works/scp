---
name: classs-compile-boundary
description: ADR-049 §9 Class-S compile-time boundary on branch classs-finalize — the role_state_mut hole that lets best-effort views mutate Class-S ceiling/suspended_capabilities with no fail-closed persist
metadata:
  type: project
---

# ADR-049 §9 Class-S Compile-Time Boundary (branch classs-finalize)

File: `crates/scp-runtime/src/context/actor/class_s.rs`

## CONFIRMED HOLE: ClassCMut::role_state_mut() reaches Class-S downward-auth fields

**Why:** ADR-049 §9 (line 153 of ADR-049-actor-per-context.md) classifies "capability/ceiling state"
as Class-S (sync-persisted, fail-closed). `execute_modify_ceiling` / `execute_suspend_member` are
downward-auth arms (line 173) that MUST persist fail-closed. That state lives in
`ContextRoleState.{ceiling, suspended_capabilities}` (both `pub` fields, scp-protocol roles.rs).

The best-effort view `ClassCMut` exposes `role_state_mut() -> &mut ContextRoleState` (line ~1482),
which hands out the WHOLE `&mut ContextRoleState`, reaching ceiling + suspended_capabilities with
NO fail-closed persist. PROVEN: `cell.class_c_view(); view.role_state_mut().ceiling.capabilities.clear()`
COMPILES and RUNS. The ADR (line 165) claims "a Class-S mutation through a best-effort path is itself
a compile error" — FALSE for ceiling/suspended_capabilities.

Author ACKNOWLEDGES this inline (lines 1471-1481): "this whole-&mut accessor can reach those...
a §9 bypass... slated for deletion once all callers move to role_state_class_c_mut." So it's a
documented-but-LIVE residual. role_state_mut has ~8 production callers (lifecycle_helpers,
tools_helpers, queries_helpers, governance_helpers). The restricted replacement
`role_state_class_c_mut()` (returns RoleStateClassCMut with shared & to ceiling/suspended) exists
but isn't yet the only path.

**How to apply:** The compile boundary is NOT complete while role_state_mut exists. Fix = delete
role_state_mut, migrate all callers to role_state_class_c_mut, route ceiling/suspension mutations
through a fail-closed combinator.

## What HOLDS (verified by compile/test):
- ClassCMut.class_s() returns &ClassSState (shared) — `&mut view.class_s().X` = E0596 compile error.
- GovernanceClassCMut has NO class_s / revoked_spending_ucan_cids fields (left to `..` rest) — E0609.
- Tripwire (class_s_no_persist_mutator_whitelist_is_bounded) correctly TRIPS on a best-effort-on-
  Class-S mutator added to impl ClassSCell (persist_state_best_effort is NOT a §9 marker). Confirmed.
- Tripwire MISSES marker-on-unreachable-branch — but this is a DOCUMENTED limitation (INFO).
- No DerefMut on ClassSCell (static_assertions guard). #![forbid(unsafe_code)] crate-wide.

## Method: apply `git diff --cached HEAD` from target worktree into a detached worktree at the
staged HEAD, then probe by writing exploit fns and `cargo build -p scp-runtime --tests`.
MembershipClassCMut similarly restricts member-removal (downward-auth) — verify it has no whole &mut.
