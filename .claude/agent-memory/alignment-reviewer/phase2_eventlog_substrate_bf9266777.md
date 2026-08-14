---
name: phase2-eventlog-substrate-review
description: Phase-2 event-log substrate swap review at HEAD bf9266777 — ALIGNED, 1 trivial nit
metadata:
  type: project
---

# Phase 2 — Event-Log Substrate Swap Review (2026-06-19) — ALIGNED

**Branch HEAD** `bf9266777`, merge-base `f55ff949e`. ~7825/-2747 across 99 files.

**Verdict: ALIGNED** — 0 blocking, 0 material, 1 trivial doc nit.

The architect's 5 finalized Phase-2 items all complete, no scope-creep, no incompleteness:
1. trait `&str`→`EventType` ATOMIC: `append_event(... event_type: EventType ...)` (providers/event_log.rs:671); 139 `EventType::` usages in runtime context, 0 string-literal type args in prod.
2. `MerkleEventLogProvider` onto `scp_event_log::EventLog` unsigned (`tree::append_unsigned_event`, `signature: vec![]`) matching WASM model.
3. Bridge convergence: `SCP-EXPORT-ENTRY:` hash-chain GONE (0 hits); WASM manager.rs byte-parity for convergent leaves via shared payload producers; excluded per-author events not appended.
4. checkpoint+proofs+export-root on `tree::root`; `state.merkle_tree`/`MerkleTree` twin = 0 refs in runtime. export root via `tree::root` (export_import.rs:485,506).
5. `MessageReceived`/`EquivocationDetected`/`PseudonymAnnounced` Merkle appends REMOVED — now ContextEvent-buffer only.

**Taxonomy = 75 variants** (lib.rs:109). MessageSent/ToolInvoked/PaymentReceived/PaymentCaptureFailed RETAINED as variants (ADR-051 end-state) but not appended now.

**ONLY NIT:** `crates/scp-event-log/src/pruning.rs:1127` comment "76 variants" but array below is `[(EventType, bool); 75]` (75 entries + .len() assert). Code correct, prose stale from 76→75 PseudonymAnnounced removal. Fix: 76→75.

**Honesty of deferrals — exemplary:**
- WASM ~40-event emit gap: `wasm_native_full_governance_eventtype_parity_pending` (wasm_conformance.rs:2458) is `#[ignore]`d + PANICS if run, enumerates unappended types, labels "dedicated effort". Canonical honest-deferral.
- `anchored`/`tool_invocation_count_anchored: bool` real, signed-preimage-bound (participation.rs:558, tests 1676/1694), default false, propagated to Python trust.py + TS types.ts.
- No `#NNNN` issue refs in source.

**Convergence enforced not just asserted:** negative-control tests (eventlog_convergence.rs:160/228/288) prove per-author/per-payee/per-member-local appends BREAK convergence. `is_convergent_trigger` gate (consequence.rs) fail-safe-excludes velocity/rate from durable leaves; `convergent_consequence_timestamp` derives from triggering event's created_at not local now().

**frontierRoot/SCP-CHECKPOINT-V2 correctly NOT implemented** (0 hits checkpoint.rs) — that's ADR-051 step-2 / Phase 3+.

**Both prior-review residuals RESOLVED on this HEAD:** "median clock" only in ADR-051 REJECTED-alts now; paymentHistory 19:594 now qualified "per-payee ContextEvents interim; convergent Merkle leaves under ADR-051". (See [[adr051_clockless_reframe_review]], [[adr051_causal_dag_review]].)

ADR-051 = step-1 (unification/exclusion) is THIS phase; step-2 (causal DAG + frontierRoot) is a separate forward program (Phase 3+: #1845 cross-member replication, #1846 WASM emit parity, #1847 missing appends, #1535).
