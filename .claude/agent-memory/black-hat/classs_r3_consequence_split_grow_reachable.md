---
name: classs-r3-consequence-split-grow-reachable
description: ADR-049 §9 Class-S r3 (commit beddb1c70) — the BLACK-CS-03 "structural GROW confinement" claim is FALSE; consequence_split() (GROW view) is reachable from best-effort class_c_view() with zero fail-closed persists. Compile boundary itself holds.
metadata:
  type: project
---

# Class-S r3 (commit beddb1c70, class_s.rs) — confinement is convention, boundary holds

File: crates/scp-runtime/src/context/actor/class_s.rs (6403 lines). All 5 probes COMPILED+RAN in worktree classs-r3-bh, reverted to zero-diff.

## HEADLINE (HIGH, latent): BLACK-CS-03 structural GROW confinement is FALSE
- `consequence_split()` is a method on `ClassCMut` (the BEST-EFFORT view), class_s.rs:2260. It returns `ConsequenceStateSplit` whose `role_state: pub(crate) ConsequenceRoleStateMut` (1765) exposes the downward-auth GROW `suspend_capabilities`/`suspend_all` (1426/1439).
- `class_c_view()` (2807) hands out `ClassCMut` and does NO persist (coalesce-only).
- PROVEN (PROBE A): `cell.class_c_view().consequence_split().role_state.suspend_all(victim)` GROWs `suspended_capabilities` with persist_calls==baseline (0 fail-closed). spy-counted.
- The doc at 1327-1331 claims "a best-effort caller CANNOT call suspend_capabilities/suspend_all because the method does not exist on the type it holds." FALSE — the best-effort view HANDS OUT the type that has those methods.
- REAL safety = the `downward_auth`/`suspension_applied` BOOLEAN FLAG threaded by hand from `enforce_triggered_consequences` → `persist_finalized_send(.., downward_auth_applied)` (messaging_helpers.rs:2169/2291; upgrades free-path None=> from best_effort to persist_state_fail_closed at 2323). Convention, not structure. A NEW caller that calls consequence_split().suspend_* and forgets the flag silently loses the GROW on a ≤50ms coalesce-window crash — no compile error, no tripwire. (This is the SAME residual class as RED-CS3, re-opened by relying on flag discipline instead of the claimed structural confinement.)

## PROBE B (MEDIUM, latent structural-permissibility): member_capabilities SHRINK no-persist
- `RoleStateClassCMut::member_capabilities_mut()` (1220) on best-effort view hands out whole `&mut HashMap`. PROVEN: best-effort `.remove(victim)` revokes (member_has_capability=false) with 0 fail-closed persist. A crash re-grants. Production revokes via system_assign_role (flag-persisted), so latent; but the view STRUCTURALLY permits a non-persisted revocation. member_capabilities is a named §9 downward-auth field; defense argues it's a derived cache (authoritative deny = suspended_capabilities GROW), which is directionally true.

## PROBE C (MODERATE gap in tripwire's STATED guarantee): type-alias evades one-block counter
- `find_inherent_impl_blocks` scans LITERAL text "ClassSCell". PROVEN production-scope `type BlackhatAlias = ClassSCell; impl BlackhatAlias { fn blackhat_evil(&mut self){ self.state.class_s.saga_pending.clear(); } }` COMPILES (full private-field access) AND the tripwire `class_s_no_persist_mutator_whitelist_is_bounded` STILL PASSES (count stays 1, evil never enumerated). Type alias is a plausible accidental/refactor pattern, so it defeats the honest-contributor speed-bump the tripwire claims to be. NOT a CRITICAL break: tripwire doc explicitly disclaims adversarial scope ("anyone who can add a mutator can edit KNOWN_SAFE/delete the test").

## WHAT HOLDS (load-bearing compile boundary — SOUND)
- PROBE D: SharedClassS read-only wrapper holds. `view.class_s().saga_pending.clear()` → E0596 cannot borrow & as mutable. No &mut accessor, no DerefMut (assert_not_impl_any), forbid(unsafe_code) blocks ptr-cast. Re-arming = 3 central edits.
- assert_not_impl_any!(ClassSCell: DerefMut) + no state_mut → no whole &mut via cell.
- ClassCMut exposes role_state ONLY via restricted role_state_class_c_mut() (no whole &mut role_state accessor); whole &mut ContextRoleState only via ClassSMut::rest_mut() (fail-closed combinator).
- PROBE 7: ceiling_mut/capabilities_mut are #[cfg(any(test, feature="testing"))]. `cargo tree -p scp-node` shows scp-protocol "default" only (NOT testing) → NOT reachable in production. set_ceiling is pub but needs whole &mut ContextRoleState (only via rest_mut, fail-closed).
- PROBE 6: clear_committed_reservation_idempotent (only no-persist Class-S mutator, allowlisted) justification SOUND — only after xctx_committed_invocations.contains witness (saga.rs:1919-1949), removal rebuilt-irrelevant on respawn.
- PROBE 5: ClassSCommitToken commit/discharge_with take `mut self` by value (no double-commit), not Clone/Copy (asserted). Residual: release-build drop-without-commit silently loses owed persist (mutation already applied in begin_class_s); only telemetry (tracing::error + metric) fires, debug_assert no-op. Documented runtime-discipline residual, LOW.

## BOTTOM LINE
The compile BOUNDARY (no whole &mut to Class-S on best-effort path; SharedClassS; no DerefMut) is genuinely sound. The GROW-direction CONFINEMENT is NOT structural — it's a return-flag convention, and the doc overstates it as structural. New-caller hazard is real and latent.
