---
name: outlet-slice3-completeness-audit
description: Adversarial completeness/stub/money-gap audit of outlet streaming-saga slice 3 (SCP-OUT-036/044/045/046/047/048/049) on scp-wt-049 (586782036) + scp-wt-048 (8d5da1912). Verdict + findings.
metadata:
  type: project
---

# Outlet streaming-saga slice-3 completeness audit (2026-08-02)

Trees: `scp-wt-049` (feat/outlet-xctx-049-conformance, 586782036) = base(044-047)+conformance;
`scp-wt-048` (feat/outlet-xctx-048-wasm-session, 8d5da1912) = base(044-047)+wasm session.
Tool→outlet rename landed (dir is `outlets/` now, not `tools/`). Money core files:
`outlets_helpers.rs` (reserve L1106, settle L1631, reconcile L2056), `outlets/dispatch.rs`
(cancel-ack L995-1218, StreamSettlement/panic-guard L1915, bridge pump), `outlets/invoke.rs`
(run_cross_context_bridge L4578, run_streaming_saga_seal_task L4858), `actor/handlers/saga.rs`
(commit_b_stream_first_settle L2591), `stream_settlement_adapter.rs`.

## VERDICT: SHIP WITH CONDITIONS. Money core genuinely sound. No new CRITICAL/HIGH found.
Two money gaps already TRACKED (confirmed): **#2196** (no ContextState::Active gate in runtime
reserve path — same-context + unary share it; 047 closed xctx via 3 bridge guards) and **#2197**
(lazy-open cancellation can orphan/double-reserve a streaming saga across SDK handles).

## Verified sound (personal read, not agent-trusted)
- **Over-billing capped**: settle caps captured amount at `cost_per_chunk × billed_count`
  (outlets_helpers.rs:1732-1736); overflow → 0 (capture nothing). `min` only reduces.
- **cancel_ack_seq forgery closed** (§5.4.5:547): sourced from runtime `next_emission_seq`, never
  caller. Native `apply_outlet_cancel_signed` reads live cursor+signs internally; verbatim path
  cross-checks `cancel.next_seq == next_emission_seq`. `current_next_emission_seq` (dispatch.rs:910).
- **xctx double-refund foreclosed**: durable `settled` flag flipped in SAME Class-S persist as money
  move; authoritative PRE-commit read returns AlreadySettled (outlets_helpers.rs:1704-1719). Actor
  serializes settles.
- **Seal exactly-once**: `commit_b_stream_first_settle` uses `commit_class_s_restore` (saga.rs:2617)
  = RESTORE-on-persist-failure → witness discarded on failure → seal returns Err → ticket Drop is
  sole refund. Seal Ok → ticket.consume() + witness durable → recovery drives deferred settle once.
  Two escrow arms mutually exclusive (consume-on-Ok / drop-on-Err).
- **Panic path**: PumpEscrowGuard Drop settles from ledger, `pump_exited` double-settle guard.
- **Cross-context bridge complete** (not stub): bounded retained snapshot (anti-OOM), operator-sig
  verify vs pinned descriptor, fault probe, schema validation, terminal-guarantee synthesis.
- **Gap detector keys on chunk.sequence** (correct, not tautological) in all 4 full SDKs; 044/045
  base_sequence/ForwardedStreamFrame reversal fully clean (zero prod residue).
- **048 wasm**: prior HIGH/DOA cancel defect RESOLVED by REMOVING browser cancel surface (Option-A,
  cb5cb44d4) — no caller-supplied next_seq path left. R4-1..R4-4 all real. Wasm fence intact.

## New findings (all LOW/MEDIUM, none blocking)
1. **MED — error masking (dispatch.rs:2301)**: streaming-open `invoke_outlet` sync failures (incl
   "context not active", schema-invalid — PERMANENT) are `let _ = err`-discarded and remapped to
   `AdmissionRateLimited{SLUG_TRANSPORT_RATE_LIMITED}` (RETRYABLE). Client retries a permanent
   failure. Wrong error class. Likely same root as #2196.
2. **LOW/provenance — dead cross-context cancel plane**: `apply_outlet_cancel_verbatim`
   (dispatch.rs:1179) `#[allow(dead_code)]`, ZERO callers repo-wide. The cross-context signed-cancel
   forwarding plane is absent; xctx cancellation degrades to channel-drop backpressure. Spec-SANCTIONED
   (§6.2.5 no live cross-ctx cancel; §5.4.5:515 carve-out #2204; seal task cancel_ack_seq:None honestly
   scope-documented invoke.rs:5077-5086) — but the dead primitive's deferral cites "a later chunk" /
   "SCP-OUT-047 action item", not a numbered PRD story. Get it a tracking ID.
3. **LOW/defense-in-depth (046 agent LOW-2)**: exactly-once escrow on seal-Err vs witness-absent
   recovery is non-overlapping ONLY because ed25519 signing is infallible on a resident actor today
   (13044 PreimageConstruction unreachable under §9.10.3 256KB bound). A future transient signing error
   on a resident actor → seal-Err drop(ticket) + later key-bearing reseal = DOUBLE REFUND. Add invariant
   note at invoke.rs:5201-5214 or a "sealed-but-unsigned/do-not-drop" marker.
4. **LOW/doc — "atomic dual-log" overclaim** (046 story): A's CrossContextOutletInvoked leaf is
   best-effort post-money-move (invoke.rs:5135), not jointly atomic with B's. Safe (recovery re-records +
   §9.9.3 (count,root) dedup) but story wording overclaims.
5. **LOW — dead computation** dispatch.rs:2162 `let _ = open_error_to_slug(open_err)` (call+discard).
6. **LOW — 048**: `close()`/`dispose()` are client-local only (no node escrow release; reclamation via
   credit-stall/timeout — ADR-057 sanctioned, docs honest); `executionTimeMs` lossy u64→number display-only.
7. **LOW/arch boundary**: typescript-wasm has NO streaming drain/gap-detector (ADR-034 constraint).

8. **MED — #2197 scope is incomplete (NEW)**: #2197 names only Swift Task{}/Python to_thread/TS
   memoized-promise. **Kotlin (`OutletsStreaming.kt:794`) exhibits the identical lazy-open double-reserve**
   and is omitted. Worse: UniFFI saga-open offloads via a DETACHED `crate::runtime().spawn(...).await`
   (uniffi/outlet_stream.rs:1654) — cancelling the Swift/Kotlin await does NOT drop the Rust open future,
   which runs to completion (inserts StreamingSagaEntry, reserves escrow). So #2197's fix cannot rely on
   future-drop cancellation; needs explicit open-in-flight/abandonment reconciliation (surface reserved
   saga_id even on abandonment). Widen #2197 to all 4 SDKs + record the detached-spawn constraint.

## FFI parity (047): FULLY POPULATED matrix — open/poll_next/recover_truncated_close × {PyO3,UniFFI,NAPI}
× {py,ts,swift,kotlin}; WASM fenced (ADR-057/048, documented). ffi_conformance ratchet 106→109. Two
real (non-#[ignore]) pipeline_wiring assertions. No money-field narrowing across boundary. Zero-sentinel
OpenStreamParams authoritatively overwritten by open_outlet_stream_phase1 (supervisor.rs:12666-12684).

## Stub sweep: CLEAN. Zero todo!/unimplemented!/unreachable!/panic! in non-test paths. All
unwrap/expect confined to #[cfg(test)]. No hardcoded zero manifest roots (the [0u8;32] hits are the
documented empty-stream sentinel + unary no-manifest sentinel invoke.rs:777, both honest).
