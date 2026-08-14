---
name: wasm-1877-modify-ceiling-converge-eb276450e
description: WASM #1877 slice-1 final commit eb276450e — ModifyCeiling converged to native (set_ceiling only); removed eager refresh; SECURITY CLEAR
metadata:
  type: project
---

# WASM #1877 Slice 1 — ModifyCeiling converge-to-native (HEAD eb276450e) — 2026-06-24 — CLEAR

Branch `wasm/1877-slice1-adopt-context-role-state`, worktree `.claude/worktrees/slice1-roles`. Diff = manager.rs + consequence.rs only (3-dot).

**The fix (eb276450e):** `dispatch_modify_ceiling` now does `validate_ceiling_capabilities` (§5.3.1.1, BEFORE mutation, fail-closed) → governed-policy check → `ctx.role_state.set_ceiling(...)` ONLY. Removed the prior `set_ceiling_and_refresh` (which rebuilt built-in roles + re-ran `system_assign_role` per member to recompute `member_capabilities`).

**Why it was a real bug (intended fix, CONFIRMED):** on a governed ceiling WIDEN, the eager refresh recomputed a SuspendAccess'd member's `member_capabilities` to include the new cap, while `prune_suspensions_to_role_grants` is SHRINK-only (retain) — the suspended set never gained the new cap. Net: `member_has_capability` returned true → suspended member silently regained authority. Removing the refresh closes it.

**Native parity VERIFIED:** native `apply_pending_ceiling_modification` (governance_helpers.rs:455) calls `state.role_state.set_ceiling(...)` ONLY (+ clears pending). Shared `ContextRoleState::set_ceiling` (roles.rs:1687) validates entries then `self.ceiling = ceiling` — does NOT touch member_capabilities or suspended_capabilities. `member_has_capability` (roles.rs:1544) checks suspended set FIRST. So WASM now byte-matches native.

**Flip side (ceiling NARROW no longer eagerly revokes member caps) = NATIVE PARITY, not a WASM-specific regression.** Native set_ceiling doesn't touch member_capabilities either; full two-phase governed-ceiling member-cap semantics is the DEFERRED slice (CeilingModificationPending / notification window). WASM matching native here is convergence, NOT a slice-1 blocker. The per-action CEILING gate in dispatch_governance_action still gates future governance actions on the live (narrowed) ceiling, so a narrow does constrain new governance immediately; only the stale member_capabilities snapshot lags — exactly as native.

**Regression test** `test_wasm_suspended_member_stays_suspended_across_ceiling_widen` (manager.rs ~9671) PASSES and proves it for the right reasons: admin member snapshot {messages:read, member:ban} → SuspendAccess copies into suspended set → widen adds messages:write via set_ceiling only → assert !has(messages:write) (never entered member_capabilities, no refresh) AND !has(messages:read) (still suspended). No residual un-suspension path.

**set_ceiling_and_refresh** now `#[cfg(test)]` (def @817), only callers are test_insert_ceiling (#[cfg(test)] @1024) + manager_with_governed_context (mod tests @9576). builtin_roles/builtin_broadcast_roles imports gated #[cfg(test)]. Zero production callers — verified by grep.

**Other gates intact:** §5.3.1.1 validation still pre-mutation; import path uses validate_imported_ceiling_strings (UCAN-form, BLACK-005 pre-parse); send-gate (member_has_capability MessagesWrite, suspension-aware) unchanged; #1886 (system_assign_role role-exists check) unchanged; membership-add rollbacks unchanged; TransferAdmin atomic.

**Verification run:** wasm lib clippy CLEAN (lib target). `--all-targets` wasm32 fails in identity.rs (scp_identity unresolved) — PRE-EXISTING + OUT OF SCOPE: identity.rs not in slice diff, scp-identity is `cfg(not(wasm32))`-gated so its tests aren't meant to build under wasm32. Host `cargo test -p scp-ffi-wasm --lib` = 398 pass (was 397 + new test). `cargo test -p scp-runtime --test wasm_conformance --features testing` = 57 pass / 1 pre-existing unrelated ignore (broad EventType-leaf parity).

No new untrusted-input/panic/leak. NO ACTIONABLE FINDINGS.
