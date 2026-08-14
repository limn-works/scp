# Class-S RED-CS3 downward-auth durability fix (branch classs-fix-residual) — CLEAN

Closes ADR-049 §9 behavioral hole: consequence-engine auto-suspension of `ContextRoleState.suspended_capabilities` (GROW direction) rode only coalesced/best-effort persist → a ≤50ms actor crash lost the suspension and re-granted a denied capability (suspension is NOT re-derived on respawn).

## Fix shape (all verified sound)
- `enforce_triggered_consequences` now `#[must_use] -> bool` (true iff a GROW suspension applied: `SuspendCapability` non-empty / `SuspendAccess` / H10 `SuspendAll` escalation). `EnforcementOutcome{success,suspended}` splits the signals.
- 5 production consequence callers persist the applied suspension FAIL-CLOSED before ack:
  - send: `finalize_send` binds `suspension_applied` once, `persist_finalized_send` upgrades free-path `None=>` from best-effort to `persist_state_fail_closed?`; paid path covered by token commit.
  - receive: `handle_deliver_incoming` owns `&mut suspension_applied`, threaded through deliver_incoming→validate_and_drain_timeouts / deliver_message_and_drain_buffered / run_buffered_post_delivery (all `*sink |=`); persists fail-closed after view drops.
  - tool-settle: `settle_tool_economy_capture` takes `&mut bool` SINK (not return value) so the obligation SURVIVES the payment-capture early `return Err`; `settle_tool_economy` persists fail-closed on BOTH Ok+Err arms; error-precedence = PersistenceFailed over capture err, chains cause.
  - periodic sweep: `handle_evaluate_periodic_consequences_actor` OR-accumulates, persists fail-closed.
  - governance-execution (`finalize_governance_action`): already covered by `execute_governance_action`'s `token.discharge_with` (single fail-closed persist last). Both success + dispatch-error arms discharge.

## Attacks attempted, all BLOCKED
1. Second fallible-op-between-suspend-and-persist: tool-settle was the one; now Ok+Err both persist. `create_and_broadcast_checkpoint_if_due` returns `()` (no `?`), can't short-circuit send. No others.
2. Flag-made-false: all sites `|=` (no `=` clobber, no dropped branch). Timeout arm in handle_deliver_incoming is moot — deliver_incoming is sync `pub fn` (no await yield), can't be interrupted mid-flag-set; flag checked even on Err(_elapsed).
3. Best-effort SHRINK (`prune_suspensions_to_role_grants` via system_assign_role / `restore_capabilities`): SHRINK rollback only RE-SUSPENDS (safe); prune + member_capabilities replacement roll back in lockstep (same persist). Never a re-grant. The 2 system_assign_role callers are member ADD/JOIN (no prior suspension → no-op).
4. Ceiling writers: all 4 production (apply_pending_ceiling_modification, execute_modify_ceiling, execute_suspend_member, SuspendAccess suspend_all) route through `commit_class_s_keep`. All other ceiling/suspend writers (supervisor.rs 13850/14903/15342/15394, lifecycle 3662, saga 3019) are #[cfg(test)].
5. DoS/info-leak: receive-path consequence targets the SENDER but persist is LOCAL; surfaced err goes to local deliver caller not sender. "Wedge" requires victim storage ALSO failing (pre-existing availability), and suspension targets the attacker = self-defeating. Tool-settle chained err = invoker's own payment err to invoker = no leak. Intended fail-closed semantics, not a new vector.

## Tests PROVEN non-vacuous (detached worktree, reverted each fix → test FAILS)
- `tool_settle_capture_failure_persists_suspension_fail_closed`: revert dual-arm→`.await?`+best-effort → FAILS (surfaces PermissionDenied capture err instead of PersistenceFailed).
- `periodic_sweep_suspension_persists_fail_closed`: revert sweep→best-effort+Ok → FAILS (Ok instead of PersistenceFailed).
- `send_suspension_persists_fail_closed`: revert free-path→best-effort → FAILS.
- `receive_suspension_sets_fail_closed_sink`: revert in-order `*sink |=`→`let _=` → FAILS (sink stays false).
All 4 pass with fix in place; whitelist tripwire + field round-trip gate still green.

## Residual (disclosed, not a hole)
STRUCTURAL only: `ContextRoleState.ceiling`/`suspended_capabilities` still `pub` + nameable via whole `&mut` (ClassCMut::role_state_mut, ClassCSplit.role_state) — blocked by cross-crate pub(in) constraint on RoleStateClassCMut::new destructure (struct in scp-protocol, view in scp-runtime). Behavioral guarantee closed; whitelist tripwire scans only `impl ClassSCell` so doesn't cover these. Snapshot persists `role_state: state.role_state.clone()` (suspended_capabilities round-trips).
