---
name: changerole-orchestration-b800910c7
description: First #1877 ChangeRole orchestration unification (native+WASM via scp-protocol orchestrate_change_role); refactor faithful BUT WASM assign_role lacks native's role-definition/ceiling validation → undefined/out-of-ceiling role = cross-bridge Merkle divergence (amplifies pre-existing 1-leaf to 2-leaf)
metadata:
  type: project
---

# ChangeRole orchestration unification (b800910c7, first #1877 slice)

**Provenance:** branch over origin/main. Adds `scp_protocol::context::orchestration::{orchestrate_change_role, ContextStateMut, ContextStateView}`. Native `execute_change_role` (governance_helpers.rs:1480) + WASM ChangeRole arm (manager.rs:3413) both route through it. WASM newly appends the previously-missing `RoleAssigned` durable leaf.

## What is CLEAN (genuinely verified)
- **Native byte-identity**: old code called `append_context_event` (→ `append_event` w/ `EventPayload::default()`); new calls `append_context_event_with_payload(EventPayload::default())`. Same `append_event`, same empty payload. Checkpoint counter `+=1` preserved (now in `append_leaf` hook). Persist-fail-closed rides `commit_class_s_keep` inside `assign_role` (native `persist_fail_closed` = no-op); ordering assign→persist→leaf preserved.
- **WASM active-check faithful**: switched `require_active_context_mut`→`require_context_mut` so orchestration's `is_active` (`state=="active"`) does the check; `inactive_error` reproduces EXACT CTX_2013 msg/code of old path. Native `require_active` (state.rs:1997) also strict `==Active`. Convergent.
- **Ordering**: both bridges append RoleAssigned during dispatch_governance_action, THEN GovernanceActionExecuted in finalize (native gov_helpers 5034 vs 5065; WASM manager 3272 vs 3320). Matches RemoveMember's MemberLeft-before-Executed pattern. WASM 2-leaf reference test (consequence.rs native_reference_change_role_two_leaf_root) is correct.
- Existing `cross_impl_role_assigned_leaf_bytes_wasm` test uses built-in role "observer" → never exercises the gap below.

## THE FINDING (MEDIUM, cross-bridge Merkle divergence; amplified-not-created)
- Native `assign_role` → `roles::system_assign_role` (roles.rs:1375) REJECTS when `new_role` not in `role_definitions` (RoleNotFound, l.1387) OR role caps exceed ceiling (validate_role_definition, l.1392).
- **WASM `assign_role` (manager.rs:1293) does ZERO validation** — just `member.role = new_role`. WASM `PerContextState` has NO `role_definitions` map; `member_has_capability` hardcodes built-in roles. Accepts ANY string.
- `propose` (governance/mod.rs:1548 SingleAdmin) does NOT validate `new_role` — arbitrary String, immediately Approved. Validation deferred to execute = native-only.
- **Result**: an approved `ChangeRole{new_role:"ghost-superuser"}` (undefined OR out-of-ceiling custom role): native aborts whole execute, 0 leaves, role unchanged; WASM succeeds, 2 leaves (RoleAssigned+GovernanceActionExecuted), member.role set. Divergent tree::root + role state + leaf count = §9.9.3 equivocation / stealth fork.
- **PROVEN** by probe (added blackhat_wasm_accepts_undefined_role to consequence.rs, ran, reverted): `execute result = true; RoleAssigned leaves = 1; GovernanceActionExecuted leaves = 1; total = 2`. Native rejection structurally certain via l.1387 `?`.
- **Pre-existing vs new**: pre-PR WASM ChangeRole arm (origin/main manager.rs:3314) also no-validation but appended ONLY GovernanceActionExecuted (1-leaf divergence already existed). This PR adds the 2nd divergent leaf (RoleAssigned). So PR AMPLIFIES (1→2 leaf divergence) but doesn't create root-divergence-from-nothing. Real root cause = WASM has no role-definition/ceiling model for ChangeRole; the shared orchestration's `assign_role` trait hook lets each bridge keep its own (asymmetric) validation.
- **Fix direction**: either (a) move role-existence + ceiling validation INTO the shared orchestration (before assign_role) so both bridges reject identically — requires exposing role_definitions/ceiling via ContextStateView; or (b) validate new_role at propose time on every bridge. The orchestration was the chance to unify this and it stopped at the leaf, not the validation.
