---
name: pr6b0-typed-sagaerror-review
description: PR-6b0 typed SagaError for §6.2.4 saga terminal states — architecture review, APPROVED, re-verified at ba3ef1f5a
metadata:
  type: project
---

# PR-6b0 typed SagaError — APPROVED

Dedicated `SagaError{Aborted/NeedsRepair/Busy}` + `SagaAbortReason{RateLimited{retry_after_ms:Option<u64>}, Rejected}` returned by `start_cross_context_tool_invocation_saga` (was ContextError). ContextError→SagaError lift at the PUBLIC boundary only.

**Option B (dedicated enum) CORRECT** vs widening 50+-variant ContextError: makes §6.2.4 terminal space the TYPE, compels exhaustive bridge match (ADR-049 §3a). Maps cleanly: Committed⇒Ok(SagaOutput); Aborted⇒neither side committed (carries SCP-SAGA-13xxx code + structured reason); NeedsRepair⇒commit-retry exhausted (carries durable SagaId = operator-repair handle, 13065); Busy⇒participant-set overlap (13066, §5.15.4).

**run_saga refactor SOUND.** Caller-minted SagaId threaded as 1st param (both start_saga and cross-context mint `SagaId::new()` at caller; cross-context clones so NeedsRepair carries the REAL durable id and Ok path's SagaOutput.saga_id is provably the SAME). Private `RunSagaError{error: ContextError, needs_repair: bool}`; run_saga_fsm untouched (FSM contract stays ContextError internally). `reached_needs_repair` is a PRE-EXISTING xctx field set ONLY at supervisor.rs:6832 inside FSM Err arm (Commit-retry-exhausted, after append_journal(NeedsRepair)) ⟹ invariant `needs_repair=true ⟹ fsm_result=Err` airtight (Ok arm computes needs_repair but discards it). Boundary lift only on public xctx method; start_saga preserves ContextError via `.map_err(|e| e.error)`.

**retry_after_ms: Option<u64> right shape, exhaustive.** Sliding-window (saga.rs ×3 SCP-SAGA-13023/13024/13026) → `Some(retry_after_secs.saturating_mul(1000))`; token-bucket hard limits (join/send/tool_invoke helpers) → `None` (no exact refill instant). outcome.rs:120 round-trip clone preserves field. `None` propagated, NEVER coerced to Some(0) (0 would read "retry immediately" → re-trip hard limit) — explicit test `lift_run_saga_error_propagates_token_bucket_none_backoff`. FFI bridges (uniffi/napi/pyo3 error.rs) use `CE::RateLimited{..}` wildcard — no update needed.

**reserve_context_set_or_busy split coherent.** try_reserve_context_set now returns bare contended-id `String` (read structurally); reserve_context_set_or_busy wraps into ContextError::ActorBusy(SagaBusy) for generic/test paths; cross-context renders SagaError::Busy directly. Each caller mints its own typed error without string-reconstructing the id.

**Re-exports correct.** supervisor/mod.rs adds `pub use supervisor::{SagaAbortReason, SagaError, ...}`. `supervisor` is `pub mod` so reachable via `scp_runtime::context::supervisor::SagaError`. NOT re-exported from scp-core/runtime lib facade — but 0 production callers (only tests + doc-comments reference start_cross_context...) ⟹ signature change non-breaking, **producer DARK**. SagaId is Clone (clone() in lift sound). SagaAbortReason derives PartialEq+Eq (FFI-comparable); SagaError can't (thiserror::Error). Right granularity.

13065/13066 registered in sdk-common.md (+2 this PR). check-error-codes.sh PASS.

**OBS:** saga_code_from_message uses first-match `.find("SCP-SAGA-")` then take_while ascii_digit; safe today — all 63 FSM rejects embed code at message PREFIX, no production message double-embeds the prefix (only a doc comment does). Lift parses ONCE at boundary (proportionate vs 63-site per-variant-code refactor). u16 overflow → None → generic 13050 fallback.

## Re-verified @ ba3ef1f5a (rebase of 7955003da; range e406c15c5..HEAD)
Substance UNCHANGED; APPROVED again. Live re-run: clippy clean (scp-runtime+scp-protocol+core+media); 4 new unit tests PASS + 76 saga lib tests; actor_saga_coordinator 10/10 + actor_saga_concurrent 5/5 PASS (features testing[,saga-witness-test-mint]); check-error-codes.sh PASS (2331 codes). All findings above re-confirmed against current diff.

## Full roster pass-3 @ ba3ef1f5a — UNANIMOUS APPROVED/ALIGNED/zero-findings
architecture + simplifier + alignment + security + api-design all clean, no net-new blockers. Value-adds beyond the structural pass:
- **alignment** range-diff vs prior 7955003da: the SOLE material delta (retry_after_ms u64→Option<u64>, lift unwrap_or(0)→*retry_after_ms) FIXES A REAL DEFECT — prior rustdoc falsely claimed token-bucket never reaches a saga abort; reachable path is tools_helpers.rs:545 → saga.rs:482 prepare_a→reserve_tool_economy Err → FSM → lift. Old Some(0) read "retry immediately" → re-trip hard limit. ba3ef1f5a strictly better than prior approval, not just a rebase.
- **security** cleared the new typed surface for LEAKAGE: 0 FFI bridges consume SagaError/SagaAbortReason/retry_after_ms (CE::RateLimited{..} rest-patterns); every field already present in prior string error (no new datum); saga_id = server-minted CSPRNG UUIDv4, caller can't influence (no saga_id in CrossContextToolInvocationRequest); retry_after_ms server-authoritative reporting-only, no enforcement/DoS-amplification change; saga_code_from_message panic-free on core-internal (never attacker-supplied) string (start = find(PREFIX)?+len always char boundary, ASCII prefix).
- **simplifier** churn proportionate (~2/3 of 532 lines = tests + required doc updates); RunSagaError/saga_id-threading/reserve split each least-structure for a real constraint; saga_code_from_message bounded/single-sited/closed-by-construction, no non-convergence signal.

## api-design OBS (non-blocking, NOT a defect): non-uniform `code` accessor
`code: u16` lives ONLY on SagaError::Aborted (it multiplexes many inner reject codes 13013/13023/13050/13062/…). NeedsRepair(13065)/Busy(13066) encode their code only in #[error(...)] Display string, no field → a bridge hardcodes 13065/13066 in those arms (one-to-one variant=code, no discriminant to carry). DEFENSIBLE per api-design's own triage; carrying a const field on single-code variants = ceremony. FUTURE option if a bridge wants one call site: `fn code(&self)->u16` inherent method (not required this PR).

## FORWARD OBLIGATION for the dark FFI producer (when bridge lands)
When a bridge eventually surfaces retry_after_ms: None it MUST map to the language's genuine absence (Python None, TS undefined/null, Swift/Kotlin nil) — NEVER a 0/-1 sentinel, or the hard-limit re-trip bug re-enters at the SDK layer. This is the None-never-coerced-to-0 core discipline projected to the binding layer. Producer is currently DARK (0 prod callers) so unenforceable here — flag at bridge-wiring review.
