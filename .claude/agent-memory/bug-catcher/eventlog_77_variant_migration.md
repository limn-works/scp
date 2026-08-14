---
name: eventlog-77-variant-migration
description: e068a70d4 EventType 75->77 saga integration review — clean except 2 stale "75" comments; convergence chain verified
metadata:
  type: project
---

Reviewed commit e068a70d4 (feat(event-log): typed CrossContext* variants + #1849 saga append migration, Phase-2).

**Why:** Integration of #1849 cross-context saga onto Phase-2 typed event log. +2 EventType tags (76 CrossContextToolInvoked, 77 CrossContextDivergenceMarker), 3 saga append migrations to typed EventType+timestamp_secs, new committed_timestamp_secs threaded through EmitDivergenceMarker cmd + DivergenceMarkerPlan 4-tuple.

**How to apply:** Commit is behaviorally sound. Convergence chain verified end-to-end: prepared.recorded_timestamp_ms (B's clock, set once at Prepare-B, saga.rs:818) -> build_signed_receipt sets receipt.timestamp_ms (saga.rs:1571) -> Commit-B ToolInvoked leaf uses receipt.timestamp_ms/1000 (saga.rs:1501) -> Commit-A CrossContextToolInvoked reads forwarded receipt timestamp_ms/1000 (cross_context_invoked_leaf) -> divergence marker uses supervisor prepared_b.recorded_timestamp_ms/1000 (supervisor.rs:7125). All three resolve to same value. No ms/s swap, no off-by-1000, no clock-read divergence, marker NOT default/0.

**finalize_send test rewrite is LEGIT** (not a masking weakening): current finalize_send (messaging_helpers.rs:1742) only emits local ContextEvent::MessageSent via emit_event_into (in-memory), no durable append_context_event for MessageSent (M12/ADR-051 §6 exclusion). So failing event-log append no longer fails a plain non-spending/non-broadcast send and there's no append-failure rollback. New asserts (is_ok + next reservation=2) match real behavior. Test has no consequence rules so FailingAppendEventLog never invoked.

CountingEventLog idempotency test still genuinely asserts EXACTLY-ONE ToolInvoked: string starts_with("ToolInvoked:") -> event_type==EventType::ToolInvoked is strictly MORE precise, CommitB only appends ToolInvoked (not CrossContext*), no cross-count risk.

PaymentReceipt anchored:false test fix legit — field lies OUTSIDE signed payload (adapter.rs:282), false=canonical default.

**ONLY findings (LOW, comment-only):** 2 stale "75" comments the migration missed, both 2 lines above correctly-updated ;77] arrays:
- pruning.rs:1140 "The full closed EventType taxonomy (75 variants)" — array below is [(EventType,bool); 77]
- wasm_conformance.rs:1475 banner "closed 75-variant injection" — test below updated to 77
No compile/test impact. RECURRING: bulk count migrations update assertions/array-lengths but miss prose comments stating the count. Grep ALL "75"/old-count occurrences including comments.
