---
name: classs-fin-trunk-seam-review
description: ADR-049 §9 Class-S cross-crate protocol seam (roles.rs class_c_parts / inherent GROW methods) defense-in-depth assessment, branch classs-fin-trunk @beddb1c70
metadata:
  type: project
---

ADR-049 §9 Class-S fail-closed persistence. Branch classs-fin-trunk @beddb1c70.

**Why:** Replaces deleted 4354-line awk denylist with compile-time/type enforcement (ClassSCell no whole &mut, SharedClassS no DerefMut, move-consuming ClassSCommitToken, two role views).

**Key architectural finding — TWO production GROW paths, not one:**
1. Consequence engine → `ConsequenceRoleStateMut` (type-confined; view only exists inside `ConsequenceStateSplit`). GROW methods reimplemented locally over `&mut suspended_capabilities` (class_s.rs:1426/1439), NOT delegating to inherent.
2. Governance helpers (execute_revoke, execute_suspend_member, execute_change_role, admin_transfer, SuspendAccess, remove_member, leave) → `ClassSMut::rest_mut()` → whole `&mut ContextRoleState` → **INHERENT** `ContextRoleState::suspend_capabilities`/`suspend_all`/`system_assign_role` (roles.rs:1031/1061/1153). governance_helpers.rs:809,892,914,1392,1834,1841,4352.

**Therefore:** the inherent pub GROW methods CANNOT be made pub(crate) — path 2 needs them cross-crate. Confinement for path 2 = `rest_mut()` exists ONLY on `ClassSMut` (fail-closed view), NOT on `ClassCMut`. That IS type-level (ClassCMut holds field-granular refs + SharedClassS, no whole &mut). The "GROW lives only on consequence view" doc claim is INCOMPLETE — omits path 2.

**The seam gap (real but bounded):** `class_c_parts()` pub + `ContextRoleClassCParts` has pub `&mut suspended_capabilities` + pub `&mut member_capabilities` + pub `system_assign_role`. Plus inherent `suspend_capabilities`/`suspend_all` pub. A hypothetical NEW scp-runtime caller holding bare `&mut ContextRoleState` (obtainable via rest_mut, or class_c_parts) could GROW-suspend or shrink member_capabilities directly without going through a view. Confinement is CALL-SITE CONVENTION for the whole-&mut path, not type. All CURRENT call sites are correctly inside commit_class_s_keep — verified each.

**Verified all current GROW/shrink callers ARE fail-closed:** every .suspend_capabilities/.suspend_all/system_assign_role/member_capabilities.remove on the downward path is inside commit_class_s_keep closure via rest_mut(). supervisor.rs:14904 + member_capabilities.entry direct writes are #[cfg(feature=testing)].

**Type-level fix that does NOT break view constructors:** views call `parts.system_assign_role(...)` and `ContextRoleClassCParts` field mutation — they consume the PARTS struct, NOT inherent ContextRoleState methods. So: making inherent `suspend_capabilities`/`suspend_all` pub(crate) would break path 2 (governance helpers call them on whole role_state). The real lever = the rest_mut() asymmetry already enforces it. The residual is the bare pub `ContextRoleClassCParts` fields letting a future caller bypass even the view. Hardening = seal the parts struct (private fields + sealed constructor in roles.rs, accessors that mirror the view discipline) OR a #[non_exhaustive]+private-field token. But this is DEFENSE-IN-DEPTH not must-fix: path 2 already proves whole-&mut GROW is a sanctioned pattern gated by rest_mut(), so sealing parts doesn't close the whole-&mut path, only the parts-destructure path.

**Verdict:** Sound as-is with honest-disclosure caveat (doc claim "GROW only on consequence view" is wrong — must acknowledge path 2). Hardening opportunities are P2.
