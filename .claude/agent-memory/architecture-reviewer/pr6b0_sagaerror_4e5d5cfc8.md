---
name: pr6b0-sagaerror-4e5d5cfc8
description: PR-6b0 typed SagaError re-squash @ 4e5d5cfc8 (parent e406c15c5, after dead-command delete #1907) — APPROVED, substance identical to b6a7b49d0
metadata:
  type: project
---

PR-6b0 typed SagaError @ **4e5d5cfc8** (HEAD), parent **e406c15c5** ("delete dead InitiateCrossContextToolInvocation command + stale deferred docs #1907"). APPROVED.

**Re-squash, no new substance vs [[pr6b0-sagaerror-b6a7b49d0]]** — same parent SHA, folds the same deltas (typed SagaError lift, Ok-arm resolve_committed_or_needs_repair, escrow-ordering, Clone/Eq derives). HEAD-1 is the dead-command-delete PR (already reviewed as [[pr105-pr6a-delete-dead-xctx-command]]).

**Re-verified against governing artifacts this pass:**
- ADR-049 §3a line 90 terminal mapping is 1:1: Committed⇒Ok; Aborted⇒SagaAborted(RateLimited carrying retry_after_ms | Rejected); NeedsRepair⇒SagaNeedsRepair carrying SagaId; saga-busy⇒SagaBusy. Implementation matches exactly.
- spec §6.2.4 line 319 "Committed⇒both records; Aborted⇒neither" — the literal contract the Aborted variant doc claims, and the justification for resolve_committed_or_needs_repair lifting a both-committed-but-marker-write-failed saga to NeedsRepair NOT Aborted (Aborted would invite double-charge retry with fresh SagaId).
- spec §6.2.4 line 335 NeedsRepair escrow-reserved semantics — run_saga tail (supervisor.rs:5682-5709) implements it: reached_needs_repair ⇒ hold_external_for_repair (NOT auto-void); else void_external_and_consume. §5.15.4 ref for Busy correct.

**Ok-arm escrow no-op confirmed (supervisor.rs:6694-6745 + 5682-5709):** resolve_committed_or_needs_repair sets ctx.reached_needs_repair=true on mark_resolved(Committed) failure; on that path prepared_a already None (consumed by Commit-A settle), so tail's `if ctx.reached_needs_repair { if let Some(r)=prepared_a.take() }` is genuine no-op — no false escrow-hold, no divergence-marker emission (markers live only in run_saga_fsm commit-exhausted Err arm at 6889+). Escrow-ordering fix at 6889 (reached_needs_repair=true BEFORE fallible append_journal(NeedsRepair).await?) intact — first stmt in Err arm, no fallible op before it.

**Derives sound:** SagaOutput{SagaId(String), Option<Vec<u8>>×2} + SagaError/SagaAbortReason{String/u16/SagaId/Option<u64>} all Eq-capable, no floats. Clone/PartialEq/Eq additive on public re-export.

**Codes 13065(NeedsRepair)/13066(Busy)/13067(generic) registered** in sdk-common.md table; 13050/13062 hardcoded fast-fail (caller/target authorize-before-reserve); saga_code_from_message parse-once-at-boundary seam (#120 tracks structural FSM-carried code), 13067 generic fallback for prefix-less aborts (timeout/journal-IO) — must NOT synthesize 13050 for an auth failure that never occurred (test pins this). Producer still DARK (no FFI export yet, ADR-049 §3a deferred). pipeline-wiring/check-error-codes unaffected (core-only).

NIT carried from [[pr6b0-sagaerror-408c3079b-deltas]]: PR-prose "parity with ContextError" re Clone/Eq is false (ContextError derives only Debug+thiserror) but harmless — derive itself is required/correct.
