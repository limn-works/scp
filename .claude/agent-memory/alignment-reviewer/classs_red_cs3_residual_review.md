---
name: classs-red-cs3-residual-review
description: ADR-049 §9 RED-CS3 consequence-suspension fail-close review (branch classs-fix-residual, base 272c4d079) — behavioral close VERIFIED, but a "never touches downward-auth pair" over-claim repeated in ADR + 3 code docs
metadata:
  type: project
---

# ADR-049 §9 RED-CS3 Consequence-Suspension Fail-Close (branch classs-fix-residual, base 272c4d079) — NEEDS DISCUSSION, 1 MED phantom-provenance over-claim (repeated x4)

Reviewed UNCOMMITTED worktree changes closing the §9 BEHAVIORAL hole where the consequence ENGINE auto-suspended a member (`suspended_capabilities` write) through a coalesced/best-effort persist — a ≤50ms crash lost the suspension and re-granted a denied capability.

## What is CORRECT (verified end-to-end against code)
- `enforce_triggered_consequences` now returns `#[must_use] bool` = `true` iff a capability suspension was applied. Doc (governance_logic.rs:191-205) is accurate. `dispatch_enforcement_action` sets `suspended` correctly: SuspendCapability(non-empty)/SuspendAccess=true, AssignRole/empty-suspend=false; H10 failure-escalation path returns true (suspend_all always applied).
- ALL FOUR cell-holding consequence sites persist FAIL-CLOSED when flag true: send (finalize_send→persist_finalized_send msg_helpers.rs:2316-2322), receive (handle_deliver_incoming messaging.rs:363-370, threads suspension_sink through whole receive cascade), tool-settle (tools_helpers.rs:1279-1283), periodic sweep (governance.rs:849-853). finalize_governance_action path covered by enclosing ClassSCommitToken::discharge_with (gov_helpers.rs:4700-4741) — accurate.
- Governance-INITIATED writes (execute_suspend_member:768, apply_pending_ceiling_modification:455, execute_modify_ceiling:1505) all route through commit_class_s_keep (fail-closed). Accurate.
- A REAL behavioral fail-closed test added: `periodic_sweep_suspension_persists_fail_closed` (governance.rs:1436) drives the actual handler with a `FailPersistence` provider, asserts reply=PersistenceFailed AND suspension RETAINED in memory (keep-direction). Not a string-search decoy.
- Behavioral-CLOSED vs structural-disclosed distinction is honestly drawn: the whole-`&mut ContextRoleState` still NAMEABLE via role_state_mut/split_class_c/from_state (compile-time boundary NOT extended to the dual-use pair, blocked by cross-crate destructure constraint — accurate). No "fully closed" over-claim of the STRUCTURAL surface.
- No issue numbers in code. ADR change touches ONLY the "Known residual" bullet; §9 invariant itself unchanged → artifact-flow honored (code→ADR residual disclosure of a security strengthening, invariant flows top-down).
- "pure-read/clone callers migrated to role_state()/role_state_class_c_mut()" — accurate; only 2 remaining role_state_mut production sites are the system_assign_role sites (lifecycle join + execute_add_member).

## THE FINDING (MED — phantom provenance, repeated 4x)
Claim: the remaining role_state_mut callers (system_assign_role) "mutate ONLY structural fields — never the downward-auth pair" / "never `ceiling` / `suspended_capabilities`".
This is FACTUALLY FALSE. `system_assign_role` (scp-protocol roles.rs:1101) calls `prune_suspensions_to_role_grants` (roles.rs:996) which DOES mutate `suspended_capabilities` (`retain` + remove-if-empty). The code author KNEW this — the in-code comment at governance_helpers.rs:1152-1159 is honest ("prunes `suspended_capabilities` (a downward-auth field)... best-effort BY DESIGN... NOT strengthened to fail-closed"). The over-claim CONTRADICTS the author's own accurate comment.
WHY IT'S STILL SAFE (the carve-out the ADR should DESCRIBE, not deny): prune only SHRINKS the suspended set (drops suspensions for caps the new role no longer grants). A coalesce-window rollback RESTORES dropped entries = re-suspends = re-NARROWS authority — never re-grants. The dangerous direction is GROW (suspend_capabilities/suspend_all extend/insert — roles.rs:948/976), which is exactly what IS fail-closed. The real safety argument is DIRECTIONAL ASYMMETRY (shrink-on-prune is rollback-safe), not "the field is never touched."
Locations (all need the same correction — replace "never touches the pair" with "the only mutation is the shrink-only suspension PRUNE, which is rollback-safe because a coalesce rollback can only re-suspend, never re-grant"):
1. ADR-049 §9 line 166 ("which mutate ONLY structural fields — never the downward-auth pair")
2. class_s.rs:204 (module "Known residual": "which mutate ONLY structural fields, never the downward-auth pair")
3. class_s.rs:1578-1579 (role_state_mut accessor doc: "mutate ONLY structural fields ... never `ceiling` / `suspended_capabilities`")
4. governance_logic.rs:554-556 (enforce_assign_role / AssignRole arm comment: "AssignRole mutates only Class-C structural role state — never `suspended_capabilities`"; returns suspended:false — SAFE because shrink-only, but comment is false)

LESSON: when a doc says a path "never touches field X" but a called helper DOES touch X in a benign direction, the honest framing is "touches X only in the rollback-safe direction," not "never." A flat "never" is phantom provenance even when the behavior is safe — and here the author's OWN adjacent code comment already contradicted the ADR/module-doc "never." Cross-check: read the leaf helper (system_assign_role → prune_suspensions_to_role_grants) and the field-mutation direction (retain/remove = shrink-safe vs extend/insert = grow-dangerous), don't trust the summary verb.
