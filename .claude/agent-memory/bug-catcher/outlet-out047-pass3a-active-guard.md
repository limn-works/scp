---
name: outlet-out047-pass3a-active-guard
description: SCP-OUT-047 pass-3a streaming-saga active-state guard (f69650ab8) — PyO3 authoritative & correct, but NAPI/UniFFI read stale cached handle.state → load-bearing gap NOT closed for Closing state
metadata:
  type: project
---

# SCP-OUT-047 pass-3a active-state guard (f69650ab8, branch feat/outlet-xctx-047-streaming-saga-ffi)

The xctx streaming-saga OPEN is money-moving; runtime reserve path
(`open_outlet_stream_phase1` supervisor.rs:12454 → `reserve_outlet_stream_economy_via_actor`
→ handler outlets.rs:509) has NO ContextState::Active gate (verified — reserve handler
delegates straight to reserve, no state check; actor outlets dispatch has no state gate).
So the bridge guard is genuinely the SOLE barrier (commit's LOAD-BEARING claim TRUE).

## PyO3 guard — CORRECT & robust
outlet_stream.rs:1222-1243. Reads `supervisor.read_context_state(ctx)` (supervisor.rs:10505,
returns Option, None for unknown, Some(Poisoned) for poisoned) for BOTH caller (6010) +
target (6011); `!matches!(_, Some(Active))` → fail-closed for None/Closing/Expired/etc.
Before principal-binding + saga drive. block_on mirrors existing local_mls_epoch/saga idiom
(off asyncio.to_thread, not in tokio ctx). Test drives REAL CloseContext path. Seams gated
(`#[cfg(any(test,testing,allow_in_memory_custody))]` impl block). All good.

## RESOLVED @d3bce8c16 (confirmed 2026-08-01) — Closing money-gap CLOSED on all 3 bridges
NAPI outlet_streaming_saga_open_on + UniFFI outlet_streaming_saga_open_impl now read
`supervisor.read_context_state(id).await` (NAPI via crate::runtime::supervisor(bi)?, UniFFI via
bi.context_manager_or_error()?) for BOTH caller+target, reject `!matches!(_, Some(Active))` with
6010/6011 BEFORE principal-binding+saga drive. Identical to PyO3. read_context_state dispatches to
the live actor (alive during Closing) → Some(Closing) → rejected; cache no longer consulted. No
lock-across-await (lookup clones+drops DashMap ref then awaits oneshot). set_state_for_test seam
DELETED from napi/context.rs. Tests rewritten: drive REAL CloseContext via supervisor dispatch
(cache stays Active, authoritative→Closed/None), assert_ne! precondition, non-vacuous (fail vs old
cache-read). CTX_2040→CTX_2001 alignment at UCAN-registry miss correct (export-fault stays 2040).
NOTE: unary xctx saga guard likely still has the same staleness (pre-existing, not sole-barrier there).

## ORIGINAL FINDING (now fixed) — NAPI/UniFFI read STALE cached handle.state
NAPI outlet_stream.rs:1158-1179 reads `source_handle.state()?` (cached Mutex<ContextState>);
UniFFI outlet_stream.rs:1194+ reads `handle.state.lock().await`. This cache is NEVER synced
to Closing (grep: no `= ContextState::Closing` in either bridge's prod code — only tests).
NAPI never syncs Expired at all. context_finalize_close_on (napi context.rs:4275) transitions
the CORE handle to Closing but leaves the FFI handle.state = Active until Closed at 4308 AFTER
async finalize completes.

CONCRETE HARM: context with close PROPOSED (Closing) but not finalized → actor ALIVE, members
intact, runtime state=Closing, read_context_state→Some(Closing). FFI cached handle.state still
reads Active → guard PASSES → saga reserve DEBITS ESCROW on a Closing context. PyO3 blocks it
(6011/6010). So "load-bearing gap closed on all 3 bridges" is TRUE only for PyO3.

Autonomous TTL-Expired case is mostly self-mitigating: actor loop mod.rs:430 Arm-2 fires the
one-shot ttl_timer → on_ttl_tick → despawn_actor → subsequent reserve hits missing actor →
fails (no debit, but wrong/uninformative error on NAPI/UniFFI vs clean 6011/6010 on PyO3).

FIX (local): NAPI/UniFFI open should call supervisor.read_context_state(context_id) for both
contexts (like PyO3), not the cached handle.state. FIX (root, DOA-quality): gate the runtime
reserve path on Active fail-closed → demotes all bridge guards to defense-in-depth. NOTE:
pre-existing pattern — unary xctx saga guard has the SAME staleness; elevated to sole-barrier
by this commit for streaming.

## LOW — UniFFI CTX_2040→CTX_2001 alignment incomplete
resolve_context_active_signing_key_by_id (uniffi outlet_stream.rs): custody-miss aligned to
2001 (1126) but "not found in UCAN registry" (1114) + "export failed" (1136) still CTX_2040.
Different error class than the hosted-identity rejection the commit aligned; not a regression.
