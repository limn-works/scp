---
name: outlet-stream-pyo3-bridge-c7-eb75ce608
description: Security review of C7 PyO3 outlet-streaming FFI bridge (outlet_stream.rs, eb75ce608/a96940ecf) — GIL-deadlock HIGH, grant-escrow=0 safe-fail, terminate auth-by-assertion
metadata:
  type: project
---

# C7 PyO3 outlet-streaming FFI bridge (feat/outlet-streaming-ffi eb75ce608, a96940ecf)

File: crates/scp-ffi/src/outlet_stream.rs (947 lines) + runtime.rs registry field.

## HIGH — poll_next holds the GIL across block_on(recv) → deadlock vs Python outlet handler
outlet_stream_poll_next (outlet_stream.rs:585, 846) is a PyO3 `&self` method with NO `py: Python`
param and NO `py.allow_threads` — holds the GIL across `rt.block_on(receiver.recv())` which parks
UNBOUNDED until the pump emits a chunk. The streaming executor is a SEPARATE `tokio::spawn` task
(invoke.rs:3456 run_streaming_executor_task); it calls BridgeStreamExecutor.run → the registered
handler, which for real handlers is a Python callable wrapped in `Python::with_gil` (mcp.rs:2317).
Deadlock: poll_next holds GIL waiting for chunk; pump thread blocks on with_gil waiting for GIL.
Freezes the WHOLE interpreter (all threads). Untested: e2e test (e2e_bridge.rs:2170) admits "a
member-backed live stream is not constructible at the bridge boundary" — only tests the reject path
(SCP-OUTLET-6160) + poll on bogus handle (immediate None). No-handler echo path (handler=None) never
touches GIL, so the deadlock is invisible in tests. Same GIL issue on grant/cancel/terminate block_on
(bounded, lower risk). Fix: `py.allow_threads(|| rt.block_on(...))` in poll_next (+ others).

## grant-escrow=0 (reserved_top_up=Amount(0)) — SAFE-FAIL, not a fund hole (author's rating largely correct, comment imprecise)
outlet_stream_grant_credit passes Amount(0) (outlet_stream.rs:642). Verified: outlet_stream_reserve_grant
/ outlet_stream_reverse_spend DO NOT EXIST (only reserve_outlet_stream_economy_via_actor open-time).
So 0 is the only safe option (nonzero would extend escrow ceiling w/o budget debit = strictly worse).
Money conservation backstop is NOT `billed ≤ reserved` — it's the max_calls caveat ceiling
(CreditTracker.max_billable / effective_max_billable_chunks) + settle-time cap
`billed_amount = min(billed, cost_per_chunk × billed_count)` (outlets_helpers.rs:1409-1413). Operator
paid exactly for delivered chunks (never unfunded); invoker charged only for delivered, bounded by
their own validated-UCAN max_calls + their own SIGNED grants. RESIDUAL (MED/LOW): grant extends the
credit window (replenish_clamped) WITHOUT a budget check/debit, and escrow.reserved is not extended,
so at settle refund=reserved−billed floors at 0 and MemberBudgetTracker.total_spent UNDER-records
actual payment when billing exceeds the open-time estimate → per-member context BUDGET-CAP under-
enforcement (payment adapter can capture beyond the recorded budget hold, up to cost×max_calls). Author
comment "grant relaxes backpressure WITHIN the already-escrowed budget; never raises the ceiling" is
imprecise: the grant DOES raise the effective billing ceiling (credit window), billing CAN exceed the
escrowed hold; what's preserved is fund-safety via the caveat cap, not the escrow bound.

## LOW — terminate authorization is by unauthenticated assertion (asymmetry vs grant/cancel)
authorized_control (outlet_stream.rs:319) rejects caller_did != pinned invoker_did. For grant the real
gate is the invoker SIGNATURE (grant_with_identity under pinned invoker_pk) — caller_did = defense-in-
depth. For cancel, caller_did drives resolve_stream_signer (needs custody possession) + runtime self-
verify — load-bearing + crypto-backed. For TERMINATE (outlet_stream.rs:698) the SOLE gate is the string
check: terminate_with_error uses the operator signer pinned at OPEN, no fresh caller signature. Since
invoker_did is public and the only other secret is the handle_id (request_id hex, returned only to the
opener), a co-resident local identity that learns a handle_id can terminate a peer's stream (availability
only; billing still settles for delivered chunks). Acceptable under co-resident single-tenant threat
model but the module doc frames CRITICAL #1 as a real boundary for all three — for terminate it isn't.

## LOW/MED — registry leak not bounded by admission caps
StreamEntry evicted ONLY on poll_next(None) / cancel / terminate. Admission counters (per-invoker/origin/
outlet from ContextParams) are released by the pump at TERMINAL-chunk emission (release_stream_admission),
independent of registry eviction. So a caller that opens streams, lets them terminate, and never drains
(poll_next) leaks StreamEntry (2 Arc<Mutex> + strings) unbounded — admission cap does NOT bound it. No TTL
reaper; cleared only on instance shutdown (shutdown_hook clears registry). Self-inflicted under single-
tenant, but unbounded per-instance growth. Consider a drained/terminal-age reaper.

## Clean
Input handling: all caller bytes via serde_json::from_slice + <[u8;N]>::try_from with map_err — no
unwrap/expect/panic on caller data (grant, chunk_bytes, operator_pk, caveats_binding, request_id).
poll_next clones receiver Arc OUT of DashMap before block_on (no ref across await); split control/data
locks so parked poll_next never blocks control plane. CRITICAL #3 sound: bridge never supplies next_seq;
apply_outlet_cancel_signed reads runtime cursor. Custody-backed signer keeps key out of address space;
StreamSignerError maps to bounded category (no key/preimage leak). Closed-set TerminateReason::from_slug
+ code-must-match guard. Per-instance registry (no globals). No secrets logged.
