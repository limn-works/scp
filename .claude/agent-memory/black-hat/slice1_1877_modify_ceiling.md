---
name: slice1-1877-modify-ceiling
description: PR #1877 Slice 1 WASM ModifyCeiling convergence — live path clean, but WASM import path still un-suspends (BLACK-CEIL-01)
metadata:
  type: project
---

# #1877 Slice 1 — WASM ModifyCeiling → set_ceiling-only (commit eb276450e)

Slice removed the per-member `system_assign_role` refresh from WASM `dispatch_modify_ceiling`; now validate (§5.3.1.1) → `set_ceiling` only, matching native `apply_pending_ceiling_modification`. `set_ceiling_and_refresh` + `builtin_roles`/`builtin_broadcast_roles` imports are now `#[cfg(test)]` (prod wasm32 build clean, no dead-code leak).

## Live path: CLEAN (5 probes)
- Un-suspend via ModifyCeiling widen: NO (probe1/2 + existing regression test).
- ModifyCeiling+ResetMember / ChangeRole→admin: NO un-suspension — WASM never rebuilds built-in `role_definitions` on widen, so re-assign uses STALE role_def (no new cap); suspended set prune is SHRINK-only so suspension retained.
- ModifyCeiling NARROW: per-action governance gate reads LIVE `ctx.role_state.ceiling()` → SuspendAccess correctly REJECTED (PERM-3000) after narrow.
- Role round-trip un-suspension (suspend-all → ChangeRole observer drops cap from suspended set → back to member regrants) = real but DOCUMENTED prune semantic in shared scp-protocol `prune_suspensions_to_role_grants`; native-parity, NOT a WASM finding.

## BLACK-CEIL-01 (HIGH) — export/import un-suspends, WASM-SPECIFIC
- File: `crates/scp-ffi/wasm/src/manager.rs` import_context ~line 6905 (`system_assign_role` per member).
- WASM `WasmContextExportSnapshot` (struct ~line 7470) carries member ROLE NAME + `suspended_capabilities` but NOT `member_capabilities`. Import recomputes `member_capabilities` via `system_assign_role` against the imported (current/widened) ceiling — i.e. the SAME refresh the slice deleted from ModifyCeiling.
- Attack: SuspendAccess a member (suspended set = pre-widen caps), production ModifyCeiling widen (member_capabilities stays stale, suspended set lacks new cap), export, import → import recomputes member_capabilities to include new cap; suspended set (restored) lacks it → `member_has_capability(new_cap)`=true. Suspended member regains the widened cap. PROBE5 confirmed: write=false pre-export, write=TRUE post-import.
- NOT native-parity: native `ContextRoleState` serializes member_capabilities + suspended_capabilities (roles.rs ~1404/1425); native import carries `role_state` VERBATIM (lifecycle_helpers.rs lines 2074, 2637 `role_state: ...snapshot.role_state`). Native preserves stale member_capabilities → no un-suspension. WASM snapshot is lossy and reconstructs via refresh.
- Same bug CLASS the slice fixed for ModifyCeiling; survives on the lossy WASM import path. The commit msg claims "the un-suspension bug disappears" — true only for the live path.
- Fix direction: WASM export snapshot should carry `member_capabilities` per member and import should restore it verbatim (parity with native), OR import must re-apply suspensions AFTER computing member_capabilities in a way that re-suspends caps that were under SuspendAccess. The current "restore suspended set after assign" doesn't help because the widened cap was never IN the suspended snapshot.
