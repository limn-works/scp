---
name: red-cs3-suspension-failclosed-review
description: Review of classs-fix-residual branch — RED-CS3 consequence-suspension fail-closed persist threading; clean, no bugs found
metadata:
  type: project
---

# RED-CS3 suspension fail-closed persist review (branch classs-fix-residual, base 272c4d079)

Threaded a "suspension applied" downward-auth signal out of `enforce_triggered_consequences` (governance_logic.rs) so cell-holding callers persist an auto-suspension FAIL-CLOSED before acking (closes ADR-049 §9 RED-CS3 behavioral hole: ≤50ms coalesce-window crash re-granting a denied capability).

**Why:** consequence-engine auto-suspension wrote `ContextRoleState.suspended_capabilities` through best-effort coalesced persist; a crash lost it (not re-derived on respawn).

**How to apply:** This pattern is the canonical "fail-closed flag threaded to cell boundary" shape. Two propagation shapes coexist and are BOTH correct here: (a) `#[must_use] -> bool` OR-accumulated (`|=`); (b) caller-owned `&mut bool` sink threaded through receive cascade + tool-settle (sink survives the `?` early-return on payment-capture Err — a return-value flag would be stranded).

## Verdict: NO BUGS. Clean across all 6 hunt areas.
- Compiles clean (`cargo check`/`test --no-run`), clippy `-D warnings` clean, all 4 new tests pass and are non-vacuous (verified each drives a real SuspendAccess + real persist; the capture-failure test asserts `PersistenceFailed` which only surfaces if the dual-arm Err-path persist runs — would fail if reverted).
- tool-settle: `cell.class_c_view()` is moved by-value into `settle_tool_economy_capture` (param `mut view: ClassCMut<'_>`), dropped at its `.await` return, so `&mut cell` is free for `persist_state_fail_closed` after. Persist runs on BOTH Ok/Err arms. Error precedence `match capture_result { Ok=>persist_err, Err(c)=>PersistenceFailed(format!(... {c})) }` correct, no double-wrap, cause preserved.
- `finalize_governance_action` is the ONE site that discards the flag via `let _ = suspension_applied;` — VERIFIED CORRECT: its sole caller (governance_helpers.rs:4904) runs it inside `token.discharge_with(...)` which performs the single fail-closed persist the ClassSCommitToken owed. No best-effort caller exists.
- `finalize_send` `suspension_applied` is bound exactly once (unconditional `{}` block tail). handle_deliver_incoming: view scope closes before persist; persist is OUTSIDE the `tokio::time::timeout` future; `outcome` (mutated flag) returned unchanged so Ok-deliver+failed-persist surfaces Err via reply while staying mutated.
- All `enforce_triggered_consequences` / `run_buffered_post_delivery` call sites honor `#[must_use]` (OR-accumulated, assigned as block tail, or `let _suspended =` in tests).
- New `ToolEconomyTicket::new_for_test_with_escrow` sound: capture-failure path sets `consumed=true` so Drop guard doesn't trip.
- ADR-049 doc updated to match (artifact-flow respected, residual disclosed honestly — structural residual remains because `ContextRoleState.ceiling`/`suspended_capabilities` are `pub` cross-crate; behavioral hole closed).
