---
name: pr6b0-saga-error-review
description: CLEAN review of PR chore/116-pr6b0-saga-error (typed SagaError + RateLimited.retry_after_ms + saga-gating gate hardening), HEAD 3630e578d
metadata:
  type: project
---

# PR 6b0 — typed SagaError + retry_after_ms + gate hardening (CLEAN)

Branch chore/116-pr6b0-saga-error, HEAD 3630e578d. Reviewed 2026-06-28. NO bugs found.

Verified invariants (if a later PR touches these):
- lift_run_saga_error (supervisor.rs:5601): needs_repair short-circuits to NeedsRepair BEFORE abort classification. retry_after_ms copied via *retry_after_ms (None stays None, never Some(0)).
- resolve_committed_or_needs_repair Ok-arm mark_resolved failure sets ctx.reached_needs_repair=true + returns Err -> read at 5719 -> RunSagaError{needs_repair:true} -> lift->NeedsRepair. prepared_a already None after Commit-A settle, no double-consume at 5691.
- saga_code_from_message (11046): take_while ascii_digit + parse::<u16>().ok() -> no panic/overflow; empty/overflow->None->unwrap_or(13067).
- 3 token-bucket sites: retry_after_ms None (correct). 3 sliding-window sites (saga.rs 704/720/814): Some(secs.saturating_mul(1000)) - no wrap.
- SagaReserveReject reshape: check+insert atomic under single std::sync::Mutex guard (no .await) - TOCTOU-free. Both fields consumed. SagaSetReservation::Drop removes only own ids; live reservations always disjoint.
- outcome.rs:120 deep-clone preserves retry_after_ms.

Gate hardening (check-saga-gating-granularity.sh P3): VERIFIED. sed 's://.*$::' strips comment tails; prod try_reserve_context_set body has NO // inside string literals. Tokens survive in live code: .contains(, ContextError::ActorBusy(, (SagaBusy) string literal at 5799, return Err(SagaReserveReject {. ERE return[[:space:]]+Err\( matches. Directly tested has_overlap_reject_in_reserve: gutted->REJECTED, prod->ACCEPTED. --self-test exit 0, real scan exit 0.

Latent gate fragility (NOT current bug): sed would mis-strip a // inside a future string literal (URL "https://...") in that fn body. None today.

NOTE: gate CLI entry (691) ignores positional args - always scans hardcoded prod path. Test fixtures via internal run_check; BSD head -n -1 unsupported on macOS.
