# #1877 Slice 1 — WASM adopts shared ContextRoleState (manager.rs + consequence.rs)

Branch wasm/1877-slice1-adopt-context-role-state @cf9e90423. Reviewed full 3-dot diff. Compiles clean (wasm32) + 397 lib tests pass.

## Key architectural facts
- WASM `PerContextState` now holds shared `scp_protocol::context::roles::ContextRoleState` (members/assignments/member_capabilities/ceiling/suspended_capabilities) + a separate `member_sequence_numbers: HashMap<String,u64>` (MLS seq, NOT role state).
- `ContextRoleState` has TWO impl blocks in roles.rs: first (suspend_all/suspend_capabilities/restore_capabilities/member_has_capability/prune) and a second ADR-049 §9 block (ceiling/set_ceiling/ceiling_mut/suspended_for/system_assign_role METHOD/class_c_parts). The method `system_assign_role` validates member-in-ctx + role-in-defs + ceiling, REPLACES member_capabilities, prunes suspensions to role grants.
- `suspend_all` = REPLACE suspended set with current member_capabilities (insert, not extend).
- builtin roles (member/moderator/author/observer/subscriber) do NOT include GovernanceVote; only admin (whole ceiling) does. Matches old WASM behavior (voting eligibility admin-only via member_has_capability) — NOT a regression.
- member_has_capability is EXACT-match (no wildcard expansion); ToolInvokeAll does not satisfy ToolInvoke("calc"). Matches native + old WASM. Tool-specific auth lives in UCAN layer.

## FINDING (MEDIUM) — suspend_all un-suspension on governed ceiling widen
`set_ceiling_and_refresh` (ModifyCeiling path) re-runs `system_assign_role` for every member, which prunes suspensions to new-role grants. A `SuspendAccess`'d (fully suspended) member whose context then gets a governed ModifyCeiling WIDENING the ceiling regains the newly-added caps: suspend_all only captured the OLD member_capabilities; prune only removes, never adds, so newly-granted caps are unsuspended. Native `apply_pending_ceiling_modification` (governance_helpers.rs:455) calls ONLY set_ceiling — no refresh/reassign — so native keeps the member fully blocked. Real divergence + security-relevant un-suspension. Narrow (requires governed widen on actively-suspended member).

## NON-FINDINGS (verified safe)
- ModifyCeiling immediate-apply vs native two-phase deferral (NOTIFICATION window): documented intentional, pre-existing, separate slice. Not introduced here.
- TransferAdmin rollback: latent suspension-loss on demote-then-rollback (prune drops, restore doesn't re-add) BUT dead code today (builtin member/admin assign infallible w/ populated ceiling). Note only.
- All rollbacks (join/add/subscribe/transferadmin/encrypted-join) verified: members + member_sequence_numbers rolled back together.
- suspended_for(&)→collect-owned→restore_capabilities(&mut) borrow pattern: NLL-safe, compiles.
- export/import round-trip: role/suspension/seq preserved; suspensions restored AFTER assign loop (not pruned); members.clear() before rebuild prevents phantom creator. Test passes.
- No production unwrap/expect/panic; all in #[cfg(test)] helpers or mod tests.
- encrypted-join leaf deferred to post-MLS-success (native Phase 5 ordering) with full membership rollback on Welcome failure — verified by 2 new tests (rollback + happy-path-exactly-one-leaf).
