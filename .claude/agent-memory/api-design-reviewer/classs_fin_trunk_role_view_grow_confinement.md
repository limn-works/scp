---
name: classs-fin-trunk-role-view-grow-confinement
description: ADR-049 §9 Class-S fail-closed role-view API review (class_s.rs + roles.rs class_c_parts seam); GROW-confinement is per-surface not absolute; bool-flag coupling for GROW persist
metadata:
  type: project
---

Branch `classs-fin-trunk` @ `beddb1c70`. Review of the crate-private §9 view family
(`ClassSMut`/`ClassCMut`/`RoleStateClassCMut`/`ConsequenceRoleStateMut`/splits/`ClassSCommitToken`)
in `crates/scp-runtime/src/context/actor/class_s.rs` + the cross-crate seam
`ContextRoleState::class_c_parts() -> ContextRoleClassCParts` in `crates/scp-protocol/src/context/roles.rs`.

**Why:** Evaluating whether the API makes the §9-safe path the path of least resistance.

**Key structural facts (verified):**
- The "GROW lives ONLY on `ConsequenceRoleStateMut`" claim is true ONLY on the best-effort
  `ClassCMut`/`ClassCSplit` surface. On the fail-closed `ClassSMut` surface, `rest_mut()` hands
  out a whole `&mut PerContextState`; `PerContextState.role_state` is `pub` (state.rs:1080) and
  `ContextRoleState::suspend_capabilities`/`suspend_all`/`system_assign_role` are `pub` inherent
  (roles.rs ~1031/1061/1153). So GROW callers in governance_helpers.rs:809,4352 reach GROW via
  `view.rest_mut().role_state.suspend_*` — bypassing the view entirely. That is §9-SAFE (it is
  inside a fail-closed combinator) but means the real invariant is "GROW-with-no-fail-closed-persist
  is uncompilable," NOT "GROW only exists on one type." Several doc comments overstate it as the latter.
- GROW→persist coupling on the consequence path is by CONVENTION: `enforce_triggered_consequences`
  returns `#[must_use] bool` (downward_auth_applied); caller OR-accumulates and calls
  `persist_state_fail_closed` (governance.rs:851, messaging.rs:368). The `#[must_use]` mitigates
  drop-the-flag, but a contributor who calls `split.role_state.suspend_all()` DIRECTLY on a
  `ConsequenceStateSplit` gets NO token/bool tying it to a persist. Contrast `ClassSCommitToken`
  (must_use + Drop + no Clone) used for the governance-execution Class-S path — the role GROW path
  has no equivalent linear obligation.
- `class_c_parts()` seam: bare `pub &mut` fields (members/assignments/member_capabilities/
  role_definitions/suspended_capabilities all `&mut`) + `pub system_assign_role` + `pub
  prune_suspensions_to_role_grants` on `ContextRoleClassCParts`. Both runtime views forward to it;
  `suspended_capabilities` exposed as bare `&mut` here is what each view then re-narrows. The seam
  itself is permissive — the narrowing happens downstream in scp-runtime, not at the seam.

**Verdict given:** APPROVED with observations (no §9-breaking misuse found; the airtight-by-
construction best-effort path holds). Recommended (non-blocking): (1) doc-accuracy fixes for the
"ONLY on ConsequenceRoleStateMut" overclaim; (2) consider a must-use token for consequence GROW
parity with ClassSCommitToken; (3) consider accessor-shaping the `suspended_capabilities` field on
`ContextRoleClassCParts`.

**Reference design** (see [[classs_cell_field_granular_views]]): same review lineage, prior PR.
