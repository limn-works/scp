---
name: wasm-slice1-roles-review
description: WASM slice1-roles test suite review (manager.rs + consequence.rs) — strong suite, 2 real gaps (TransferAdmin behavior + seq overflow), found native divergences
metadata:
  type: project
---

# WASM slice1-roles role-state test review (HEAD 4babda7ba)

Reviewed `crates/scp-ffi/wasm/src/manager.rs` #[cfg(test)] (lines 7654-11937) + `consequence.rs`. Read authoritative via `git show HEAD:...` (Read tool serves STALE in this worktree).

## Verdict: solid suite, REVISE for 2 gaps. Both gaps are ALSO production divergences from native, not just test holes.

## GAP 1 (HIGH): RESOLVED at d05e8ad7d. Handler rewritten to match native execute_transfer_admin (reject non-member before mutate w/ CTX_2015, demote ALL admins, promote new_admin, NEVER touch creator_did; rollback block removed as obsolete). Two new tests through PRODUCTION propose_governance_action (single_admin auto-execute): `transfer_admin_to_member_demotes_old_promotes_new_wasm` (manager.rs:10461 — asserts new=admin, old=member, creator_did UNCHANGED ×2) + `transfer_admin_to_nonmember_is_rejected_wasm` (10522 — Err CTX_2015, old admin intact, creator_did unchanged). EMPIRICALLY non-vacuous: reverted handler to OLD in scratch worktree → both FAIL (happy-path catches creator_did=zmember vs zcreator; reject catches silent Ok). Residual OBSERVATION (not a gap, behavior locked by single-admin case): no explicit multi-admin-demote-all or idempotent-new-admin-already-admin test — native loop demotes-all-then-promote handles both, single-admin tests adequately lock the convergent shape. AdminTransferred event-log leaf still NOT minted by WASM (native does) — separately-tracked deferred leaf-parity workstream, real native↔WASM leaf-count divergence.

## GAP 2 (MED): per-member sequence increment uses raw `*seq_entry += 1` at manager.rs:2093 (send_message) and 5615 (publish_broadcast). Native uses saturating_add everywhere (messaging_helpers.rs:3033/3144, governance_helpers.rs:615). At u64::MAX → panic(debug)/wrap(release). Fix prod to saturating_add + add test seeding seq=u64::MAX then send, assert stays MAX (no panic/wrap).

## What's SOLID (replicate these patterns):
- Role/membership/governance tests go through PRODUCTION dispatch: dispatch_governance_action, propose_governance_action, execute_governance_action, send_message, publish_broadcast, export_context, import_context. NOT via set_ceiling_and_refresh (that helper used only in manager_with_governed_context SETUP, action-under-test is real dispatch).
- #1886 undefined-role: change_role + add_member both covered (manager.rs:10375,10475) with load-bearing rollback proof (seq seeded-before-fallible-assign → None proves rollback, with explicit comment why member_role==None alone is insufficient).
- Suspended-stays-suspended across ceiling widen: in-memory (9723) AND export/import roundtrip (10638) — BLACK-CEIL-01.
- Verbatim role_state roundtrip via derived PartialEq (10797); assignment tokens verbatim no-remint (10730).
- Membership rollback: remove_member empty-leaf-before-executed (11211), encrypted-join rollback on welcome failure (11514) checks member/seq/role/leaf-count/buffer all rolled back; positive one-leaf-on-success (11629) with REAL MLS.
- Deserialize-rejection: CTX_2094 newer/older version (8307/8332), CTX_2032 malformed ceiling (9438) — correctly distinguished from sig-failure CTX_2093.
- Digest determinism uses FIXED nonces ("nonce-1"), not random → not flaky. snapshot_digest_invariant_under_set_insertion_order (8897) good.
- Identity registry thread_local flakiness MITIGATED: cleanup_identity_registry() at START and END of all 4 export tests; register_identity_with_agent_key uses OsRng → unique DIDs, no same-thread collision.

## Minor: CTX_2015 generic-code asserts are defensible (comments explain RoleNotFound is only reachable role-error in setup). Forgery tests (direct_execute_*) assert no GovernanceActionExecuted leaf minted — good state-change-absence proof.
