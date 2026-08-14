---
name: saga-prepare-a-besteffort-2094
description: Retro review of #2094 (21b29ea1f) — prepare_a reject-path persist fail_closed->best_effort; SAFE, no Class-S regression
metadata:
  type: project
---

# #2094 (21b29ea1f) prepare_a reject-path persist best-effort — SAFE, ZERO findings

Squash-merge on origin/main (parent 8bcbc3cae). saga.rs prepare_a: two
`let _ = persist_state_fail_closed(&*cell, deps, &hex).await;` reject sites →
`persist_state_best_effort(...).await;`. Retro review (skipped roster).

**Behavior is byte-identical.** Both helpers (messaging_helpers.rs) build the
SAME whole-state snapshot via `build_snapshot_for_persist` + `persist_context`,
and BOTH fire `record_persistence_failure` on error. Only diff: fail_closed
returns Err, best_effort returns (). Original used `let _ =` → error ALREADY
discarded. So no error-propagation was ever in play here.

**Fail-closed's whole purpose = never ack SUCCESS on unpersisted Class-S.** At
BOTH sites: `reply.send(Err(..))` + `return Outcome::err_mutated(..)` — TERMINAL,
no success acked. So fail-closed vs best-effort is immaterial by construction.

**Site 1 (consume_outbound_interface_rate_limit reject):** reserve_tool_economy
has NOT run. Only validate_outbound_caller (read-only via `&*cell` Deref) +
§6.2.0.2 window consume via `class_c_view()` (non-persisting view, structurally
CANNOT touch governance.class_s). Class-C only; RateLimited case = window not
even incremented.

**Site 2 (reserve_tool_economy Err):** verified all failure returns in
tools_helpers.rs reserve_tool_economy:
- hard_rate try_consume fail / pre_check Err / missing-UCAN: velocity rollback +
  hard_rate refund, Class-C net-zero, no Class-S.
- combinator `f`-reject (validate ucan / budget / nonce-commit-fail): combinator
  does NOT persist; velocity+budget reversed inline; nonce NOT net-consumed;
  outer arm refunds hard_rate. Class-C net-zero, Class-S clean.
- combinator PERSIST-failure: on_persist_failure reverses budget+velocity, KEEPS
  nonce consumed — but nonce DURABILITY is the combinator's OWN fail-closed
  `commit_class_s_keep_compensating` responsibility (already attempted+failed),
  NOT site-2's.
- escrow authorize_tool_payment Err: nonce consumed AND already durably persisted
  by the SUCCESSFUL combinator persist; only Class-C budget/velocity reversed
  after (rides coalesce; over-charge respawn-corrects, conservative direction).

Conclusion: in NO case does the site-2 persist bear responsibility for landing a
Class-S mutation. Every Class-S write is fail-closed-persisted by
reserve_tool_economy's internal combinator upstream. Site-2 persist only ever
carries Class-C residuals (window increment, budget/velocity reversals).

**Untouched (confirmed):** genuine Class-S fail-closed persists elsewhere in
saga.rs — success-path commit_class_s_restore (step 5), commit_class_s_keep,
cross-context settle `persist_snapshot_fail_closed` (origin/main line 2585) — NOT
in the diff. record_persistence_failure observability preserved (best_effort L2545).

GOTCHA: local HEAD (1620de983) was BEHIND origin/main; must review via
`git show origin/main:...`. On parent 8bcbc3cae the helpers are already ASYNC
(sync-fn-returning-future for !Send discipline, ADR-049 Decision 7).
