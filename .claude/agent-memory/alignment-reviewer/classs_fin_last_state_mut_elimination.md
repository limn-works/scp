---
name: classs-fin-last-state-mut-elimination
description: ADR-049 §9 Class-S migration — eliminate last state_mut() callers in context/ (worktree classs-fin-last, parent f36b09462); ALIGNED zero findings
metadata:
  type: project
---

# Class-S `state_mut()` elimination (worktree classs-fin-last, parent f36b09462) — ALIGNED, ZERO findings

Tightly-scoped ADR-049 §9 step. SOLE goal: drive the last `ClassSCell::state_mut()` callers out of `crates/scp-runtime/src/context/` so the grep `\.state_mut()` (excl `fn state_mut`) returns EMPTY — VERIFIED empty. Next step deletes `state_mut()` + privatizes Class-S fields (compile-enforces fail-closed). `state_mut()` def retained at class_s.rs:1847 now marked `#[allow(dead_code)]` with a comment scoping it to the final atomic deletion — correct.

**Why:** code-only invariant (Class-S persist must be fail-closed) becomes COMPILE-ENFORCED once the whole-state `&mut` escape hatch is gone.

**How to apply:** mechanism = narrow fns onto field-granular `ClassCMut`/`GovernanceClassCMut`/`MembershipClassCMut` views (best-effort/coalesced for Class-C, run-loop persists on `mutated`); route Class-S mutation + fail-closed persist through the sanctioned combinators / `&*cell` SHARED reads. Boundary held everywhere:
- `finalize_send`/`persist_finalized_send`: sig migrated `&mut PerContextState` → `&mut ClassSCell`. Paid (token) path → `t.commit(cell,…)` = fail-closed persist via `&*cell`. Free path → `persist_state_best_effort(cell,…)` = best-effort. Class-C mutations via `class_c_view()`. PRESERVED, no downgrade/strengthen.
- `deliver_incoming`/`validate_and_drain_timeouts`/`deliver_checkpoint_message`: sig → `&mut ClassCMut` (handler `DeliverIncoming` now threads `cell.class_c_view()` not `cell.state_mut()`). Receive cascade is all Class-C.
- send-path payment split into `authorize_send_payment_prepare` (sync `&*cell` shared read → owned `OwnedAuthInputs`) + async `authorize_paid_action_hold` (cell free across await — `ClassSCell` !Sync). capture split same way. Class-S never crosses an await.

**Dead-code deletions are IN-SCOPE, not creep:** `create_checkpoint_if_due` (bare-fields, gated) and `compare_remote_checkpoint_bare` were the send/receive-path bare-state callers at parent messaging_helpers.rs:2067/1470 — deleted BECAUSE those callers migrated to the view siblings (`create_checkpoint_if_due_view` send-path; pre-existing `compare_remote_checkpoint` view receive-path). NOT pre-existing dead code. `_bare`'s `record_equivocation_if_fresh` body is byte-equivalent to the view path's inlined `divergence_is_fresh`+`emit_equivocation_alert` — no behavior change. The tracing `debug!`↔`info!` swap follows fn semantics (periodic=debug, forced-final-close=info), matches parent.

New airtight-by-construction helpers verified: `ClassCMut::from_state` (cell-free bridge = `ClassCSplit::from_state` counterpart, delegates to `new`'s single disjoint destructure — no whole `&mut PerContextState`/`&mut GovernanceState`/`&mut ClassSState`); `CommitBroadcastBorrows` struct (3 disjoint Class-C `&mut`: pending_commits/commit_fault/receive_buffer) replaces whole `&mut state` param on `try_broadcast_commit_or_enqueue`; `rollback_economy_ticket_inline` → `_view` (takes `GovernanceClassCMut`, sequential field accessors, all 3 reversed fields Class-C). `member_has_capability`/`member_dids`/`drain_timed_out_gaps`/`commit_broadcast_borrows` view accessors added — pure or field-disjoint.

Enforcement: pipeline_wiring.rs `b3_checkpoint_generation_wired` assertion `create_checkpoint_if_due` → `create_checkpoint_if_due_view(` (trailing `(` blocks renamed-sibling substring match) = COVERAGE-TIGHTENING, allowed. Test PASSES. Class-S straggler test re-seeds via new `seed_caller_reservation_for_test` (routes through `commit_class_s_restore` sanctioned combinator instead of `state_mut()` escape) + asserts the clears add ZERO persists vs post-seed snapshot — correct.

GATES (run in worktree): `cargo clippy -p scp-runtime --all-targets --features scp-runtime/testing -- -D warnings` CLEAN; targeted tests green (class_s 43, finalize_send rollback, restore-reconcile, clear_committed_reservation, b3_checkpoint_generation_wired). PerContextState import still used (shared `&` reads + remaining bare-state helpers execute_remove_member/execute_rotate_content_keys which use inline CommitBroadcastBorrows) → no unused-import CI break.

LESSON: for a "delete the last X callers" step, the deletion of bare-state SIBLING fns is in-scope when those fns were the migrated callers (confirm via `git show PARENT:file | grep` that the parent had a LIVE caller). Verify the replacement view-fn is behaviorally byte-equivalent (compare the freshness/dedup core), and that an enforcement-test token rename is a TIGHTENING (trailing `(`, names the real entry) not a weakening.
