# WASM slice1 — drop redundant ceiling validator (f8b6e11c1) — 2026-06-24 — CLEAN / no §5.3.1.1 regression

Worktree `.claude/worktrees/slice1-roles`, HEAD f8b6e11c1. Read tool serves STALE manager.rs here — use `git show HEAD:`.

Commit deletes WASM-side `validate_ceiling_capabilities` (looped `cap.validate_as_ceiling_entry()`) on create+modify, relying on shared `ContextRoleState` enforcement. Verified redundant + no bypass:

- **Equivalence**: deleted validator == `CapabilityCeiling::validate_entries` (roles.rs:632) which loops the SAME `cap.validate_as_ceiling_entry()?`. Closed grammar, not a denylist. Removal sound.
- **Create** (manager.rs ~1599): ceiling built `CapabilityCeiling::new(map(Capability::new))`, passed to `ContextRoleState::new` whose FIRST line is `ceiling.validate_entries()?` (roles.rs:1457) BEFORE struct construct/store. Malformed → `RoleError::InvalidCeilingCategory(ce)` → new match arm (manager.rs:1689) destructures → `ceiling_validation_error(ce)` → SCP-VALID-7000. `RoleError::InvalidCeilingCategory(#[from] CeilingEntryError)` at roles.rs:1340. No parse→validate gap.
- **Modify** (manager.rs:3669): `set_ceiling` (roles.rs:1687) validates WHOLE replacement BEFORE `self.ceiling = ceiling` — fail-closed-before-mutation, prior ceiling intact on err. active+governed guards reject-first. `map_err(ceiling_validation_error)` → SCP-VALID-7000.
- **Scope**: diff fully scoped to comment/validator-delete/2 call-sites/error-arm/additive tests. NO authz/import/suspension/subscribe LOGIC touched.
- **subscribe_broadcast tests** (additive) match real impl (manager.rs:5513): non-broadcast `ok_or_else` rejects BEFORE mutation; membership-add atomic (insert member+seq, system_assign_role, rollback BOTH on err — no orphan); idempotent via `!members.contains`. No split-brain.

VERDICT: clean. Same reject surface SCP-VALID-7000 across create/modify/import; native-parity convergence.
