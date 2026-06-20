---
name: eventlog-phase2-substrate-swap-final
description: ALIGNED final-state review of Phase-2 event-log substrate swap at HEAD 16a2cd42b (ADR-051 + ADR-011 amendment); 5 architect items all met, honest deferrals
metadata:
  type: project
---

# Phase-2 Event-Log Substrate Swap @ `16a2cd42b` — ALIGNED (double-zero gating)

Worktree `agent-aaf1b56ed9b9a3581`. Diff vs origin/main ~7900+/3028-. Reviewed as alignment final state.

**Verdict: ALIGNED.** 0 blocking, 0 material. All 5 architect items met; deferrals honest; no scope-creep into Phase 3+; no DOA decisions; no phantom provenance.

**Why:** This is the convergent-only canonical Merkle log swap. ADR-051 (causal-DAG app-event ordering, clockless — velocity=local throttle, suspension=governance commit where execution IS record) + phase-2.md ADR-011 amendment (2-category exclusion taxonomy) govern; all code/spec flows DOWN.

**How to apply (the 5 items verified):**
1. trait `&str`→`EventType` atomic: `EventType` gains `Copy`; `event_type.clone()`→`event_type` in evaluate_consequence_rules.
2. provider onto `scp_event_log::EventLog`: providers/event_log.rs `log: EventLog::new(...)`, `tree::root(&log.log)` as checkpoint root. `state.merkle_tree` twin GONE.
3. PyO3/NAPI bridge-local logs deleted (delegated).
4. checkpoint+proofs+export-root onto `tree::root`: export_import.rs signed `snapshot.event_log_merkle_root = tree::root` (RFC 6962, not hash-chain head). Final commit also REMOVED redundant unsigned `ContextExport.merkle_root` envelope mirror (sole authoritative = signed field; no remaining consumer — verified) + renamed `verify_merkle_chain`→`recompute_event_log_root`.
5. `MessageReceived`/`EquivocationDetected`/`PseudonymAnnounced` Merkle appends removed — grep for `EventType::MessageReceived`/`EquivocationDetected` append sites = 0; only `ContextEvent::*` buffer notifications remain (correct). `PseudonymAnnounced` removed from EventType enum (76→75); lib.rs:282 comment explains.

**Taxonomy 76→75 fully coherent:** enum=75 variants (counted), closed-set test renamed `..._at_75_distinct_variants`, Vector 32 (25-test-vectors.md) says 75, pruning.rs EXPECTED comment 75, lib.rs rustdoc 75. The prior "76→75 doc nit" is FIXED.

**Prior-memory residuals NOW FIXED on this branch:** (a) phase-2.md "(causal-DAG ... + median clock)" self-contradiction GONE — all median/quorum/beacon confined to ADR-051 REJECTED-alternatives. (b) 19-economic-governance.md:594 `paymentHistory` now qualified ("per-payee ContextEvents in interim; convergent Merkle leaves under ADR-051").

**Shared convergence function (final commit headline):** `scp_protocol::trust::consequence::merge_consequence_events` — Source-1 (durable log, convergent events ONLY) + Source-2 (buffer, `MessageSent` ONLY since excluded from durable log). WASM `merged_consequence_events` + native `event_log_entries_for_consequences` both delegate. CONVERGENCE INVARIANT doc explains why double-counting convergent events would break §9.9.3. WASM overrides `append_durable_consequence_leaf`; conformance test pins byte-identical leaf labels (`trigger_kind_str`/`consequence_action_type`). `is_convergent_trigger` gate: WarningCount/Custom=durable, MessageVelocity/ToolRateExceeded=non-durable.

**`anchored` field (ADR-051 §6):** `tool_invocation_count_anchored: bool` wired Rust(participation.rs, in SIGNED preimage — test pins flip changes sig)/Python(trust.py)/TS(types.ts), `false` interim. payment_receipts ring BOUNDED (economy_helpers.rs:242 pop_front at DEFAULT_BUFFER_CAPACITY).

**Honest deferrals (both `#[ignore]`'d, panic/assert bodies, NO issue#refs in code per feedback_no_issue_refs_in_code):**
- cross-member replication (#1845): eventlog_convergence.rs:331 `two_real_members_converge_pending_cross_member_replication` — convergence tests hand-feed identical committer-assigned timestamps.
- WASM ~40-emit gap (#1846): wasm_conformance.rs:2454 `wasm_native_full_governance_eventtype_parity_pending` — panics; RoleAssigned/AccessRevoked/SpendApproved/migration/TTL/threshold/proposal families not yet WASM-appended = Phase 3+, correctly NOT pulled in.

GOTCHA: review target = worktree file, not main. Diff is large but governance/messaging helper bulk is substrate-swap mechanical (committer-assigned timestamp threading), not scope-creep.
