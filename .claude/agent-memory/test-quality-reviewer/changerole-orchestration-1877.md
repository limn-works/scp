---
name: changerole-orchestration-1877
description: Test patterns and gaps from the #1877 ChangeRole shared-orchestration convergence slice (cross-bridge leaf parity)
metadata:
  type: project
---

# ChangeRole shared orchestration (#1877 first convergence slice)

`orchestrate_change_role` in `crates/scp-protocol/src/context/orchestration/mod.rs` is a generic sync
body over `ContextStateMut`. Native binds it in `governance_helpers.rs` (`NativeChangeRoleState`,
assign+persist atomic via `commit_class_s_keep`), WASM binds it in `manager.rs`
(`WasmChangeRoleState`, persist=no-op). WASM now appends the previously-missing RoleAssigned leaf.

**Why:** historically each bridge re-transcribed the ChangeRole sequence → divergent Merkle leaves →
false-positive §9.9.3 equivocation. Shared body guarantees ordering+leaf equal by construction.

**How to apply (cross-bridge leaf-parity test review checklist):**
- The leaf-byte KAT is SPLIT: native fixture (`wasm_conformance.rs cross_impl_*`) + WASM real-path
  (`scp-ffi/wasm/src/consequence.rs cross_impl_*_wasm`). Split is forced — scp-runtime test crate
  can't dev-depend on the scp-ffi-wasm cdylib. Each side drives its OWN producer against the same
  known answer. This is the standard pattern; the native "replay" KAT (replays appends, doesn't
  invoke the real helper) is HONEST iff it documents the crate-dep reason AND points to where the
  real path is covered (governance_integration.rs for native).
- Good non-vacuity convention here: every leaf-stamp KAT pairs the parity `assert_eq` on the root
  with an `assert_ne` against the PRE-FIX shape (caller-stamp, local-now, target-DID, empty sentinel).
  Demand this pairing.
- RECURRING GAP in WASM real-path leaf KATs: they `.find()` the leaf and assert its fields but omit
  the `==1` leaf-count and ordering asserts that the native replay + mock tests DO have. Always check
  the real-path test pins exactly-one-leaf and RoleAssigned-before-GovernanceActionExecuted.
- GAP: bridge-binding reject paths (is_active / has_member → CTX_2013 / CTX_2015) are tested only via
  the scp-protocol MOCK, not at the WASM/native binding. The manager.rs ChangeRole arm deliberately
  switched `require_active_context_mut` → `require_context_mut` so the shared body owns the active
  check; nothing tests the WASM context actually rejects (not mutates) when state != "active".
- `ContextStateView::event_count` is a trait method with NO production caller — only the orchestration
  mod-test reads it. Flag as over-engineering: delete or wire into the count assertions.
- `make_bare_per_context_state` defaults state="active" — so is_active passes but the reject branch
  is never hit on the WASM real path.
