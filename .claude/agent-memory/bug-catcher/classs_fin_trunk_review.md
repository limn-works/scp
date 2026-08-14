---
name: classs-fin-trunk-review
description: ADR-049 §9 Class-S migration review (classs-fin-trunk) — deferred-persist token, view combinators, borrow splits all sound; only LOW comment defects
metadata:
  type: project
---

# ADR-049 §9 Class-S migration review (branch classs-fin-trunk, 2026-06)

Reviewed the ~26-commit refactor that routed all `PerContextState` mutation through
typed views and deleted `state_mut()`. Conclusion: NO real bugs found after deep scrutiny.

**Why:** the soundness backbone is the destructuring `let PerContextState { .. }` in
`ClassCMut::new` / `ClassCSplit::from_state` (class_s.rs) — Rust's borrow checker
guarantees field-disjointness, so the disjoint-borrow structs (`EconomyPreCheckBorrows`,
`CommitBroadcastBorrows`, `economy_pre_check_borrows`, `detection_borrows`) cannot alias.
`cargo check -p scp-runtime --features testing` passes → aliasing is impossible.

**How to apply:** when re-reviewing this area, focus on these verified-correct invariants:
- `ClassSCommitToken` (#[must_use]+Drop) discharged EXACTLY once on every terminal path
  in send_message, join_context, execute_governance_action, prepare_b. All use `.take()`
  then `return` — no fallthrough double-take, no leak.
- `commit_class_s_keep` (fail-closed keep), `_restore`, `_keep_compensating`,
  `_keep_restore_split` all persist once; f-reject runs NO persist/compensation.
- Persist direction preserved vs origin/main: apply_pending_ceiling_modification stayed
  fail-closed (commit_class_s_keep); apply_pending_economic_policy_change stayed
  best-effort (Class-C); leave/close member-removal fail-closed; send/join nonce deferred.
- NonceDedup::is_replayed_read replicates the TTL filter exactly (expired ≠ replay);
  eviction hoisted into prepare_b KEEP closure preserves evict→decide→record net effect.
- post_join_bookkeeping narrowed to participation_cache — body never touched budget;
  the "records budget spend" doc was already stale on main (enforce_join_economy does it).
- clear_committed_reservation_idempotent: no-persist Class-S remove is SAFE — caller
  checks xctx_committed_invocations.contains() first; straggler rebuilt-irrelevant on respawn.
- The 4354-line awk denylist (check-class-s-fail-closed.sh) replaced by a BOUNDED
  positive-allowlist test (class_s_no_persist_mutator_whitelist_is_bounded) + compile-time
  no-DerefMut guard. Strengthening, not weakening. Honestly documents its limits.

**LOW findings (comment-only, both pre-existing on main, not introduced here):**
- saga.rs module-doc on run_prepare_b_checks (~line 999-1004 new / 880-883 on main) claims
  the inbound-rate consume "stays consumed even if a LATER check rejects" and "precedes the
  freshness/chain-depth checks deliberately" — FALSE. Code consumes LAST (after all 6
  read-only checks pass). Stale on main too; carried forward.
- lifecycle_logic.rs post_join_bookkeeping doc "records budget spend" — body only inserts
  participation_cache. Stale on main too.
