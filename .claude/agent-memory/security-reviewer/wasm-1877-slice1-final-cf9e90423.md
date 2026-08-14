---
name: wasm-1877-slice1-final-cf9e90423
description: Security review of WASM #1877 Slice 1 final (PerContextState adopts shared ContextRoleState) — CLEAN, no actionable findings
metadata:
  type: project
---

# WASM #1877 Slice 1 FINAL (branch wasm/1877-slice1-adopt-context-role-state, HEAD cf9e90423 atop origin/main f37372b25)

Reviewed 2026-06-24. Diff = manager.rs + consequence.rs ONLY (3-dot verified). clippy wasm32 clean (0 warn); 397 wasm bridge tests pass; 57 wasm_conformance pass (1 pre-existing ignore = full governance EventType leaf parity, unrelated).

**VERDICT: CLEAN — no actionable security/authorization findings.**

Why sound:
- §5.3.1.1 fail-closed at all 3 paths. Create: `validate_ceiling_capabilities(parsed)` BEFORE `ContextRoleState::new` (which re-validates, defense-in-depth); empty→`default_ceiling()`. ModifyCeiling: `validate_ceiling_capabilities` before mutation, then `set_ceiling_and_refresh` (shared `set_ceiling` validates whole replacement, leaves prior unchanged on err). Import: `validate_imported_ceiling_strings` (UCAN-form) runs BEFORE lossy `ucan_string_to_capability` parse — closes BLACK-005 (colon-form built-in like `tool:invoke:*` would canonicalize+accept otherwise).
- send/publish gate: positive `role_state.member_has_capability(did, &Capability::MessagesWrite)` — suspension-aware (shared type checks suspended set first). Replaces old negative suspension-only check. observer/subscriber (read-only) rejected; suspended-write rejected. Both send_message and publish_broadcast.
- #1886: ALL role-assign paths go through inherent `ContextRoleState::system_assign_role` (roles.rs:1731), which DOES enforce ceiling via `validate_role_definition` step 2a (UNLIKE the free fn at 2066 and the older method at 1085 which don't — but WASM calls the inherent one on `self.role_state`). RoleNotFound/CapabilityOutsideCeiling → reject. WASM never installs custom role_definitions, so AddMember/ChangeRole/import with a custom role name → RoleNotFound → fail-closed.
- Membership-add atomicity uniform: join/join_encrypted/add/subscribe/transfer all insert member+seq then rollback BOTH on role-assign err. join_context_membership_only appends NO leaf; join_context appends leaf AFTER membership commits; join_context_encrypted defers buffer-event+leaf until AFTER join_from_welcome Ok (REACHABLE rollback strips members/assignments/member_capabilities/suspensions/seq on Welcome err → no phantom member, no orphan leaf). Matches native adder-path leaf-last ordering.
- Import integrity: Ed25519 sig over JCS + exporter==creator binding + fail-closed empty-sig, verified BEFORE state reconstruction. role_state rebuilt purely from snap (clear() then re-insert) so creator-not-listed snapshot doesn't leave phantom admin. Suspensions restored AFTER all system_assign_role calls (so not pruned away).
- set_ceiling_and_refresh `let _ =` discard genuinely infallible: only built-in roles rebuilt-by-intersection; members only hold built-in roles; did from live assignments.

Minor non-issues (NOT findings): import `suspend_capabilities` for a non-member DID from attacker snapshot creates an inert dangling entry (bounded by size-validated snapshot, member_has_capability returns false anyway) — hygiene only.

GOTCHA confirmed again: harness Read served STALE roles.rs (main version, ~1200 lines) — worktree HEAD version is ~4300 lines with inherent ContextRoleState methods (ceiling/set_ceiling/suspended_for/system_assign_role at 1657-1731). Use `git show HEAD:<path>`.
