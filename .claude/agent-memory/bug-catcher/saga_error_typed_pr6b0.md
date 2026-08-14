---
name: saga-error-typed-pr6b0
description: Review of typed SagaError enum for §6.2.4 cross-context saga terminal states (branch chore/116-pr6b0-saga-error, HEAD 6a42b210c) — CLEAN
metadata:
  type: project
---

# PR-6b0 typed SagaError review (CLEAN, 2026-06-27)

Branch `chore/116-pr6b0-saga-error`, HEAD `6a42b210c`. Reviewed READ-ONLY.

**Why:** Adds `SagaError {Aborted{reason:SagaAbortReason,code:u16,message}, NeedsRepair{saga_id,message}, Busy{contended_context,message}}` as the typed terminal space for `start_cross_context_tool_invocation_saga`; `ContextError::RateLimited` gains `retry_after_ms: Option<u64>`.

**How to apply:** No bugs found. Verified:
- `try_reserve_context_set` returns `Result<_, SagaReserveReject{contended_context, actor_busy}>`; lock spans check+insert (TOCTOU-free, `significant_drop_tightening`). Generic `start_saga`/test path `.map_err(|r| r.actor_busy)` preserves exact `ContextError::ActorBusy(...SagaBusy)` message — `actor_saga_coordinator.rs:260` still passes. xctx path reads `r.contended_context` structurally; building-then-discarding `actor_busy` on xctx is a cold-path waste, not a bug.
- saga_id now minted at the boundary (start_saga / xctx entry) and threaded into `run_saga`→`run_saga_fsm`; same id for journal, SagaOutput, and NeedsRepair repair handle. Previously minted inside run_saga (unavailable on err path) — fixed.
- `resolve_committed_or_needs_repair` (Ok-arm helper): sets `reached_needs_repair=true` BEFORE returning mark_resolved(Committed) failure → lifts to NeedsRepair not false Aborted (prevents double-charge retry). `prepared_a` is already None here (consumed by commit_a_settle:7422 on successful Commit-A), so run_saga tail's take() is a no-op. Holds.
- `saga_code_from_message`: `message[start..]` start is post-ASCII-prefix → char boundary, no multibyte panic; empty/overflow digits → parse Err → None → fallback 13067. All SCP-SAGA codes ≤13099 (u16 safe).
- `retry_after_ms`: None never coerced to Some(0) (verified lifecycle/messaging/tools all None; saga.rs all `Some(secs.saturating_mul(1000))` — no `*1000` overflow). reason classified by error VARIANT not message.
- All `ContextError::RateLimited` construction sites updated; all match sites use `{ .. }` (FFI bridges, saga tests) — forward-compatible. `start_cross_context_tool_invocation_saga` only referenced in docs/tests, no production FFI caller breaks on return-type change.
