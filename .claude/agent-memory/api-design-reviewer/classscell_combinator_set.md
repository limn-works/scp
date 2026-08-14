---
name: classscell-combinator-set
description: ClassSCell 6-combinator set (ADR-049 §9 Class-S fail-closed) coverage gap — split-Class-S (keep one field, restore another) is not expressible
metadata:
  type: project
---

ClassSCell (`crates/scp-runtime/src/context/actor/class_s.rs`) is the typed wrapper retiring the source-text gate `scripts/check-class-s-fail-closed.sh` by making Class-S fail-closed-persist a compile error to violate. No `DerefMut`; mutation only via combinators; temporary `state_mut()` escape hatch (1 caller in actor/mod.rs) to be deleted once all handlers migrate. Terminal goal: NO site forced onto state_mut.

6 combinators as of 5f57fad71: `commit_class_s_keep` (keep all Class-S), `_restore` (snapshot+restore whole Class-S), `_compensating` (restore Class-S + async ClassCMut comp), `_keep_compensating` (NEW — keep all Class-S + async ClassCMut comp; for reserve_tool_economy keep-nonce/reverse-budget), `_then_append` (persist then external event-log append, restore+re-persist on append fail → AppendOutcomeError.mutated divergence flag), `commit_class_c_best_effort` (renamed from commit_best_effort).

**Why (gap found):** `ClassSState::snapshot/restore` (state.rs:938/962) is ALL-OR-NOTHING across its 5 fields (saga_pending, xctx_nonce_dedup, xctx_committed_outputs, xctx_committed_invocations, xctx_caller_reservations). The `prepare_b` handler (saga.rs:823 record nonce + 842 insert saga_pending; 852 persist-fail branch) needs a SPLIT: KEEP xctx_nonce_dedup (un-recording re-opens replay window) but RESTORE saga_pending (stale slot re-stages a saga). Both are in ClassSState. No combinator expresses this: _restore/_compensating un-record the nonce (unsafe); _keep/_keep_compensating keep the stale saga_pending and their ClassCMut hook structurally cannot reach saga_pending. → that one site is forced back to state_mut, contradicting the terminal goal.

**How to apply:** When reviewing further ClassSCell work, the missing 7th shape is "split Class-S commit" — needs either field-granular snapshot/restore or a combinator whose keep-direction hook can still restore a NAMED Class-S field. Verify reserve_tool_economy (tools_helpers.rs ~617-667) maps to _keep_compensating (it does — nonce consume kept, budget/velocity/hard_rate_limit reversed). commit_b_first_settle (saga.rs ~1437) and commit_a_first_settle (~1669) map to _then_append. Abort (~1947) and rate-limit consume (~440/472) map to _keep.
