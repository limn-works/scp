---
name: review-classs-red-cs3-consequence-suspension
description: ADR-049 §9 RED-CS3 — consequence-engine auto-suspension now persists fail-closed-before-ack; CLEAN, one doc-NIT
metadata:
  type: project
---

# RED-CS3 Class-S consequence-suspension fail-closed fix — CLEAN

Worktree `classs-fix-residual`, branch `classs-fix-residual`, base `272c4d079`. Uncommitted working-tree review. scp-runtime compiles; new fail-closed test + consequence suite + whitelist tripwire all PASS.

**The fix:** `enforce_triggered_consequences` now `#[must_use] -> bool` (`governance_logic.rs`); `true` iff a `suspended_capabilities` mutation (`suspend_capabilities`/`suspend_all`, incl H10 `emit_failure_escalation` which `return true`). New `EnforcementOutcome{success,suspended}` from `dispatch_enforcement_action`. Flag threaded through receive cascade via `&mut bool suspension_sink`. Each cell-holding consequence site persists fail-closed (`persist_state_fail_closed`, keep-direction) when set: send `persist_finalized_send` free-path upgrade, receive `handle_deliver_incoming`, tools `settle_tool_economy`, periodic `handle_evaluate_periodic_consequences_actor`. Governance-exec path rides existing `ClassSCommitToken::discharge_with`.

**Verified all 6 concerns CLEAN:**
- Keep-direction is STRUCTURAL: `persist_state_fail_closed` takes `&PerContextState` (shared) → cannot roll back; returns `PersistenceFailed`, never swallows. Receive handler keeps fail-closed persist even on error/timeout reply path.
- `enforce_suspend` returns false ONLY on empty caps (true no-op) → flag precise, no silent best-effort suspension.
- All production writers of `suspended_capabilities`/`ceiling`: consequence-engine (flagged+fail-closed) OR `commit_class_s_keep` (gov_helpers 478/805/888/910/1056/4342). All other `.ceiling=`/`suspend_all` hits are `#[cfg(test)]` (lifecycle 3662, supervisor 14903/15342/15394, saga 3019). broadcast 275 / messaging 1822 are READS.

**SAFE CARVE-OUT (concern 5):** `system_assign_role` (roles.rs:1144) DOES mutate `suspended_capabilities` via `prune_suspensions_to_role_grants` — ADR prose "role_state_mut callers mutate ONLY structural fields, never the downward-auth pair" is LITERALLY FALSE. But safe: (a) the 2 best-effort `role_state_mut()` callers (lifecycle 1130 join, gov_helpers 1162 execute_add_member) operate on BRAND-NEW members (members.insert precedes), so prune is a guaranteed no-op; (b) consequence `AssignRole` path (`suspended:false`→best-effort) prunes an existing suspension ONLY in the SAME coalesced persist unit as the demotion (`member_capabilities.insert` + prune in one `system_assign_role` call), so a crash rolls BOTH back atomically — `member_has_capability(C)` identical pre/post-crash (post: orig role grants C AND C re-suspended). No re-grant window.

**ONLY FINDING (LOW/NIT, doc-only):** tighten the "never the downward-auth pair" prose in ADR-049 §9, class_s.rs:204-205, class_s.rs:1577-1583 to acknowledge prune is a no-op on new-member adds and rolls back atomically on the consequence AssignRole path. Code correct; justification overstated. NOT a security defect.

Fields `ceiling`/`suspended_capabilities` stay `pub` (cross-crate `RoleStateClassCMut::new` destructure constraint) — behavioral guarantee upheld; remaining residual is STRUCTURAL (compile boundary doesn't forbid NAMING) and correctly disclosed, not claimed closed.
