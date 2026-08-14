---
name: wasm-1877-slice1-roles
description: Review of wasm/1877-slice1 ContextRoleState adoption — clean, no actionable bugs. ModifyCeiling native-convergence verified.
metadata:
  type: project
---

# wasm/1877-slice1-adopt-context-role-state review (HEAD eb276450e)

Reviewed 2026-06-24. Branch migrates WASM `PerContextState` from flat `suspended_capabilities` map + `MemberEntry.role` strings to the shared `scp_protocol::context::roles::ContextRoleState` (8 commits). Final commit converges WASM `ModifyCeiling` to native (`set_ceiling` only, no per-member refresh).

**Verdict: NO actionable bugs found.** Production wasm32 build + host clippy (lib+tests) clean. 398 tests pass.

**Why:** the historical bug-density patterns in this codebase did NOT recur here:
- `dispatch_modify_ceiling`: validate-before-mutate, `set_ceiling` Result propagated via map_err (fail-closed), governed-only gate. Matches native `apply_pending_ceiling_modification` (governance_helpers.rs:455 — set_ceiling ONLY + pending-clear + CeilingModified leaf).
- `set_ceiling_and_refresh` + `builtin_roles`/`builtin_broadcast_roles` imports now `#[cfg(test)]`; both callers (`test_insert_ceiling`, `manager_with_governed_context`) test-gated. Production build confirms no leak (would be compile error).
- Regression test `test_wasm_suspended_member_stays_suspended_across_ceiling_widen` is MUTATION-VERIFIED: reverting to `set_ceiling_and_refresh` makes it FAIL at the exact bug-fix assertion (manager.rs:9770). Non-vacuous.
- Encrypted-join rollback (530752ac5) + MemberJoined leaf-deferral (d96c38c0d): correct. Rollback strips members/assignments/member_capabilities/seq + restores suspensions; leaf deferred until after MLS welcome (native adder-path ordering). Consumed pending_key_package NOT re-inserted on failure — CORRECT (RFC 9420 one-time-use key packages; re-insert would be reuse vuln).
- Send-gate (b3acdbaa5): positive suspension-aware `member_has_capability(MessagesWrite)` on send + broadcast paths — genuine fail-to-revoke fix (read-only roles + suspended writers now blocked).
- import_context: ContextRoleState::new Result propagated; clears auto-derived creator membership, rebuilds from snapshot, system_assign_role error-propagated, THEN re-applies suspensions (correct order — after assign, which prunes).
- All `unwrap`/`expect`/`panic` in diff are `#[cfg(test)]`-only. Two production `ContextRoleState::new` callers (create ~1733, import ~6884) both map_err(...)?.

**Known scoped gap (NOT a bug, explicitly deferred):** WASM ModifyCeiling is single-phase immediate-write and emits NO CeilingModified event-log leaf, where native is two-phase (notification window) + emits a leaf. Pre-existing (old ceiling_strings path emitted none either). Commit defers two-phase to a separate slice.

**Lint gotcha:** `cargo clippy -p scp-ffi-wasm --target wasm32-unknown-unknown --all-targets` FAILS (proptest/zbase32 dev-deps + JsError Display unavailable on wasm32 test target). This is EXPECTED — WASM tests run on host. Correct lint = wasm32 WITHOUT --all-targets, OR host WITH --all-targets. Both clean here.
