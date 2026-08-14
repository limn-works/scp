---
name: classs-consequence-assignrole-gap
description: RED-CS3b — consequence-engine AssignRole demotion rides best-effort coalesce (member_capabilities downward-auth rollback); the c815017d7 fix closed only the suspended_capabilities half
metadata:
  type: project
---

# RED-CS3b: Consequence-engine AssignRole-demotion downward-auth rollback (branch classs-fin-trunk)

Commit c815017d7 ("fail-close consequence-engine suspension") closed RED-CS3 for `suspended_capabilities` (suspend half) by threading a `suspension_applied`/`suspension_sink` bool from `enforce_triggered_consequences` to fail-closed persists at every cell-holding caller (messaging.rs:366, tools_helpers.rs:1328, governance.rs:849, finalize_send persist_finalized_send:2317, finalize_governance_action via token). That plumbing is EXHAUSTIVE across send / inbound-deliver / buffered-drain (run_buffered_post_delivery returns flag) / timeout-drain (validate_and_drain_timeouts) / force-drain (buffer_ahead_message) / tool-settle / governance-sweep. Verified complete.

**THE GAP**: `enforce_triggered_consequences` only sets the flag for GROW of `suspended_capabilities`. The `EnforcementOutcome { success, suspended }` (governance_logic.rs:499) marks `ConsequenceAction::AssignRole` as `suspended: false` (dispatch_enforcement_action:571-574). But AssignRole → `system_assign_role` (roles.rs) REPLACES `member_capabilities` with the new role's grant set — a DEMOTION (admin→observer) is a genuine downward-auth transition. `member_has_capability` gates on BOTH `suspended_capabilities` AND `member_capabilities` (roles.rs). `role_state: ContextRoleState` is a SNAPSHOT field (state.rs:603) restored from snapshot, NOT re-derived from event log. So a consequence rule with action AssignRole (reachable: consequence.rs:402, aggregate.rs:1179) that demotes a member, on the free-send or inbound-delivery path, sets suspension_applied=false → skips the fail-closed persist → rides best-effort ≤50ms coalesce. Crash in window → restore re-grants the PRE-demotion (higher) member_capabilities.

The fix's justification (governance_logic.rs:558-575) only reasons about the suspended_capabilities SHRINK-prune ("rollback can only re-suspend, never re-grant"), and ignores the member_capabilities REPLACEMENT, which CAN re-grant on rollback.

Project's OWN stated invariant (supervisor.rs:13808): "§9 mandates that any downward-auth transition (member removal, capability/access revocation, ROLE DEMOTION) is SYNC-persisted." Governance-initiated demotion (execute_revoke/execute_remove_member) IS sync-persisted. Consequence-engine AssignRole demotion is NOT. Same bug class as RED-CS3, member_capabilities half.

**FIX**: make `dispatch_enforcement_action`'s AssignRole arm return `suspended: true` when the new role's capability set is a strict subset of the member's current `member_capabilities` (demotion), OR unconditionally true for AssignRole (simplest, sound — a coalesce-loss of a promotion is harmless upward, so over-persisting promotions costs only a rare fail-closed persist). Rename the `suspended` field to `downward_auth` to capture both fields. Tripwire/compile-boundary does NOT cover this (role_state structural residual reach, no gate).

## Confirmed dead-ends / not-regressed this branch
- RED-CS1 (spending nonce deferred persist): burn in begin_class_s_conditional mutates cell-owned state BEFORE any await; survives handler-future drop; all abort paths take()+commit() fail-closed; timeout-drop collapses to standard ≤50ms coalesce residual. LOW, not regressed.
- RED-CS2 (saga double-settle): unchanged, still gated by durable xctx witness.
- RED-CS4 (governance executor spoofing): unchanged.
- Governance path consequence-suspension: finalize_governance_action runs inside token.discharge_with (governance_helpers.rs:4903) = single fail-closed persist; `let _ = suspension_applied` at 4741 is correct (token persists it).
