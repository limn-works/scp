---
name: outlet-2196-active-gate-audit
description: "#2196 fail-closed ContextState::Active gate before outlet escrow debit + error-taxonomy fix — SHIP verdict, money path verified"
metadata:
  type: project
---

# #2196 outlet Active-gate + error-taxonomy audit (branch fix/outlet-2196-active-gate @68eeadbd1, base fa28f925c)

VERDICT: SHIP. Money path sound. No bypass found.

**Why:** closes a real runtime-layer money hole — reserve_outlet_stream_economy / reserve_outlet_economy / reserve_stream_grant_escrow historically gated rate/velocity/membership/funds but NOT context lifecycle. A Closing/Expired/MigratingOut context could take new spend if no FFI bridge guard caught it first (direct runtime/saga callers bypass the bridge). Now `ensure_context_active` (outlets_helpers.rs:597) is the FIRST predicate on all 3 reserves.

**How to apply — verified facts (SCP outlet money model):**
- All escrow debit = budget_tracker.record_spend. Prod callers: helpers:906 (reserve_outlet_economy), :1297 (reserve_stream), :1476 (grant) — ALL 3 gated. invoke.rs:409/859 record_spend only fires with economy=Some; prod invoke_outlet caller (dispatch.rs:2353) passes economy=None; unary reserves via #1. economy_logic.rs:484 = message-send path, separate, out of #2196 scope.
- Gate reads handle.state() = live Arc<ArcSwap<ContextState>> load (mod.rs:171) — authoritative, never lags. "Lagging cache" in comments = the SEPARATE FFI-side read_context_state, not this.
- TOCTOU: transitions CAN land off-actor via FFI finalize (context_finalize_close_on, mod.rs:186). Gate→debit window (reserve's own .await) collapses to the pre-existing mid-stream-teardown case: escrow ticket Drop refunds / settlement sink settles. Benign, reconciled, NOT weakened by #2196. Gate closes the common already-Closing case.
- Reserve runs FIRST in open_outlet_stream_phase1 (supervisor:12589), BEFORE admission + escrow_ticket arming. ContextNotActive rejection touches ZERO money state → no strand, no double-refund, exactly-once intact.
- Caller-axis streaming saga: NO caller-side escrow debit (money is B-side/target only, supervisor:6543 reserves on &target_hex). Caller bridge guard (OUTLET_6010) is a policy gate not a money gate — asymmetry sound. Unary saga caller (prepare_a, saga.rs:683) DOES reserve on caller → now gated.
- Error taxonomy: CODE_PROTOCOL_SESSION→RetryPolicy::Never; CODE_TRANSPORT_FAULT→WithBackoff (retryable). Pre-fix `let _ = err` collapsed permanent failures into retryable transport band. Fix routes ContextNotActive→6101/Never. Correct.
- SCP_OUTLET_6080_MARKER single-sourced (helpers:2898 only). No other error can spoof into ContextNotActive classification; current_state = ContextState enum (no injection, no embedded ": "). rsplit(": ").next() extraction cosmetic-only.
- FFI bridge guards (napi/uniffi/pyo3) diff = COMMENTS ONLY; both-axis checks intact.

**Minor observations (non-blocking):**
- Creating→Active is the one non-monotonic lifecycle edge; a reserve racing during Creating gets Never (arguably too strong for a client that retries post-activation). Matches existing SESSION path; client-ordering error not money bug. LOW.
- reserve_stream_grant_escrow gate sits before the zero-cost/zero-grant early return — stricter than needed (zero grant moves no money) but correct/harmless.
