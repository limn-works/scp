---
name: out047-streaming-saga-ffi-final-verdict
description: SCP-OUT-047 fresh-eyes final review (branch feat/outlet-xctx-047-streaming-saga-ffi, HEAD b1d28ef08) — cross-context streaming-saga FFI surface across PyO3/NAPI/UniFFI. VERDICT SHIP, no blocker.
metadata:
  type: project
---

# SCP-OUT-047 streaming-saga FFI — final verdict: SHIP (no ship-blocker)

Money-moving FFI surface (escrow reserve/settle + key-bearing recover) → 3 native bridges → 4 SDKs.
True delta = merge-base(11f62b8)..HEAD: 38 files, ~7608+/47- (clean additive).

## Verified sound
- **Active-state gate** (OUTLET_6010 caller / OUTLET_6011 target) present on ALL 3 bridges, BOTH axes,
  BEFORE caller-principal binding and saga drive → before any escrow debit. Load-bearing (runtime saga
  path has NO active-gate; FFI gate is the sole barrier, documented PyO3 1201-1221). Fail-closed on None actor.
- **Open money path**: no fallible step between saga Ok (money moving, seal task spawned) and infallible
  DashMap register (PyO3 1454-1471). No stranding. saga_id unique → no overwrite.
- **Recover** (PyO3 1560 / NAPI 1546 / UniFFI 1536) structurally identical all 3: hosted-identity gate
  (CTX_2001) → registry lookup → invoker gate SCP-PERM-3001 (entry LEFT INTACT on reject) → target key
  resolved per-call from custody AFTER both gates → drive → evict on success. UniFFI uses
  identity_custody_registry().contains_key (== PyO3/NAPI identity_registry_contains).
- **Double-settle foreclosed at runtime**: recover_streaming_saga_truncated_close (supervisor.rs 6905,
  PRE-EXISTING SCP-OUT-046, not in diff) → settle_outlet_stream_via_actor(Some(saga_id)) atomic `settled`
  flag → None on replay (6969-6973). Plus FFI eviction-on-success. Recover callable on healthy live saga
  is SAFE by this runtime invariant (no FFI-side race guard, intentional).
- **Security ordering** identical+correct: descriptor built runtime-side from phase1.params (bridge passes
  NONE from caller), caveats recomputed runtime-side from validated UCAN (mismatch rejected), request_id
  freshly minted, key per-call from custody (ADR-006, never envelope-asserted).
- **poll_next**: possession of saga_id = read capability (single-consumer channel), no per-poll principal;
  terminal chunk returned THEN evicted (no leak); unknown id = distinct no_active_saga_err (never None).

## status:done honesty — legit, not theater
- AC8 layered-coverage amendment VERIFIED: runtime xctx_streaming_saga_truncated_close_ac7 (supervisor.rs
  32410) drives REAL crashed multi-chunk saga (PrefixThenBlockExecutor 5 chunks+wedge), asserts exec-once
  (32570) + escrow settles at prefix billed_count (32651). FFI auth tests real (e2e_bridge 2006/2033/2068:
  unhosted/unknown/hosted-non-invoker; last asserts entry NOT evicted). Isolation-boundary claim TRUE
  (spawn_actor_with_state = pub(in crate::context)). Non-blocking-open test real (2692). pipeline_wiring
  out047 assertions real (2181 open, 2205 recover; ac8 seal-once 3384).
- WASM fence REAL: grep outlet_streaming_saga in wasm crates = empty. Matrix rows mark node-delegated w/ rationale.
- Test seams insert_test_streaming_saga_entry cfg(any(test, feature="testing")) on impl block, ALL 3 bridges
  — NOT shipping prod, not exported (not #[pymethods]/#[uniffi::export]).
- check-sdk-coverage.py + bridge-aliases.json additions purely ADDITIVE (canonical→bridge aliases), no
  enforcement weakened. supervisor.rs +24 = cfg-gated test_saga_journal_state accessor only.
- SDK wrappers (TS verified): StreamingSagaHandle stops on terminal-flagged chunk OR null; faithful.

## Non-blocking findings (ranked)
1. LOW/process — **branch DIVERGED from origin/main** (merge-base 11f62b8, NOT fast-forward; prompt's
   "0 behind" is wrong). `git diff origin/main..HEAD` shows a PHANTOM 783-line credentials.rs deletion
   that is NOT part of the feature (merge-base..HEAD touches zero credentials.rs). REBASE onto origin/main
   before opening PR so the PR diff = true additive delta and CI runs vs real base.
2. LOW/naming — recover documented "crash-recovery" but authorizes+routes off the IN-MEMORY per-instance
   registry (target_context_id, invoker_did). A true process crash wipes that registry → recover returns
   no_active_saga_err. So this FFI surface is in-SESSION reconnect/repair (seal stalled while process
   alive), NOT cross-restart crash recovery (which needs a durable-journal operator path). Fail-closed,
   no security hole; naming slightly oversells reach.
3. INFO — deferred follow-ups (runtime-native active-gate; cancellation-orphan double-escrow) are honestly
   pre-existing/systemic, NOT new holes: FFI active-gate closes the practical hole (all money callers go
   through FFI); cross-context saga has NO live cancel (cancel_ack_ceiling=u64::MAX, documented PyO3 1527).
