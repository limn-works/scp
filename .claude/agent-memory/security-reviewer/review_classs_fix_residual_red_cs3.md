# RED-CS3: Class-S downward-auth fail-closed (worktree classs-fix-residual)

Branch `classs-fix-residual`, base 272c4d079. ADR-049 §9 fix making consequence-engine
auto-suspension (`suspended_capabilities` GROW) persist FAIL-CLOSED before ack across all
4 cell-holding consequence sites. VERDICT: CLEAN, no security issue, all claims verified vs live code.

## Enumeration of every production writer of the dual-use ContextRoleState pair
GROW (dangerous, must-be-fail-closed):
- governance_logic.rs:532/602/649 (consequence engine SuspendAccess/SuspendCapability/H10 suspend_all) → returns flag, cell-holding caller persists fail-closed
- governance_helpers.rs:805 execute_suspend_member → commit_class_s_keep (FC)
- governance_helpers.rs:888/910 execute_revoke → commit_class_s_keep (FC)
- governance_helpers.rs:4342 SuspendAccess gov action → commit_class_s_keep (FC)
SHRINK (directionally safe, no FC obligation):
- governance_helpers.rs:1056 restore → commit_class_s_keep anyway (strictly safer)
- system_assign_role → prune_suspensions_to_role_grants (roles.rs:996, retain/remove ONLY; never grows). callers lifecycle_helpers.rs:1130 / governance_helpers.rs:1164 are member ADD/JOIN, prune is no-op there. member_capabilities replaced in lockstep → rollback re-suspends+re-grants together, never leaves un-denied.
ceiling GROW: only governance_helpers.rs:478 apply_pending_ceiling_modification → commit_class_s_keep (FC). lifecycle_helpers.rs:3662 is TEST.
Direct-field grep: only suspended_capabilities mutations are in roles.rs SHRINK methods. No uncovered best-effort GROW writer.

## Key verified mechanisms
- enforce_triggered_consequences now `-> bool` + `#[must_use]`; OR-accumulated. All 6 prod call sites route flag to a sink/persist. run_buffered_post_delivery also `-> bool #[must_use]`, all 4 prod sites `*sink |=`.
- TOOL-SETTLE (the subtle one): settle_tool_economy_capture (tools_helpers.rs:925) OR-sets caller-owned `&mut bool` sink ATOMICALLY with the in-memory suspension, BEFORE the fallible capture (944-972). Capture-fail `return Err`(970) reverses ONLY Class-C economy (budget/velocity/rate-limit), NOT the suspension. Caller settle_tool_economy (1287-1348) persists FC on BOTH Ok+Err arms. No early-return strands obligation. Error precedence: PersistenceFailed surfaced OVER capture err, capture cause preserved in msg (1336-1339) — no mask.
- KEEP-DIRECTION: persist_state_fail_closed (messaging_helpers.rs:2403) snapshots in-memory (retains suspension), returns PersistenceFailed, NEVER rolls back. Safe direction (in-mem more restrictive than disk).
- NO REGRESSION: spending-nonce token path (persist_finalized_send Some(t)) unchanged; suspension_applied only affects free None arm; paid path covered by token's full-snapshot commit (no double-persist/double-revert). On token-commit fail op returns Err (not acked). Convergence/§9.9.3 untouched (only OUTCOME fail-closed, EVALUATION stays coalesced).
- `pub` ceiling/suspended_capabilities = disclosed STRUCTURAL residual (cross-crate pub(in) can't admit RoleStateClassCMut::new destructure). No behavioral weakening; prose honestly does NOT claim compile-time closure for the pair.

## Observations (non-actionable)
- OBS-1: SuspendAccess/H10 return suspended:true unconditionally but suspend_all is no-op when member has no caps → benign over-persist (safe over-approx, never a missed persist).
- OBS-2 positive: caller-owned &mut bool sink (not return-value) is the correct design to survive the `?` early-return; #[must_use] backstops dropped signal.
- OBS-3: 4 fail-closed tests (failing persistence provider, assert PersistenceFailed + suspension retained). Receive-path test asserts sink reaches cell boundary.
