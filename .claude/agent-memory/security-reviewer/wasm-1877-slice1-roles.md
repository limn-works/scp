---
name: wasm-1877-slice1-roles
description: Security audit of WASM #1877 Slice 1 — PerContextState adopts shared ContextRoleState (manager.rs + consequence.rs). CLEAN.
metadata:
  type: project
---

# WASM #1877 Slice 1 — ContextRoleState adoption (branch wasm/1877-slice1-adopt-context-role-state, HEAD a131bf62a)

Audited 2026-06-24. Two files: manager.rs, consequence.rs (crates/scp-ffi/wasm/src/).
Verdict: CLEAN — no actionable defects. 395/395 tests pass, wasm32 clippy clean.

Slice replaces WASM's flat role model with shared scp_protocol ContextRoleState (same type native uses). Authz now enforced by construction.

Verified-correct patterns:
- §5.3.1.1 fail-closed at create/ModifyCeiling/import. Import: validate_imported_ceiling_strings on UCAN strings BEFORE lossy parse (closes BLACK-005 colon-form bypass). set_ceiling_and_refresh fail-closed (set_ceiling err returns before rebuild).
- Send/publish write gate (~2029, ~5418): single positive member_has_capability(MessagesWrite), suspension-aware. Both sites identical. No bypass.
- #1886: no path assigns role without system_assign_role (enforces ceiling step 2a + role-in-definitions). All paths fail-closed.
- 3 rollbacks (join 1866, add_member 3750, subscribe 5353): on system_assign_role Err remove members+seq. No partial authz.
- Import envelope: length-bound → version gate (rejects unsigned <v4) → JCS recanon BEFORE reconstruction → exporter==creator → Ed25519. Escalation/dropped-suspension needs creator key = trust model. anti-replay ts clamped; creation_ts verbatim (signed). Suspensions restored AFTER role assign.

Observations (unreachable asymmetries, non-blocking):
- subscribe_broadcast: bc.subscribe() before membership-add; subscriber-role assign failure wouldn't roll back broadcast subscriber entry. Unreachable.
- TransferAdmin (~3950): old admin demoted before new promoted; promotion failure leaves no admin. Unreachable (admin=full ceiling).
- map_role_error formats RoleError with caller DIDs/role names — no secret leak.
