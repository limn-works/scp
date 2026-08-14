---
name: outlet-group4-streaming-money-audit
description: Whole-outlet Group-4 audit (SCP-OUT-032..039 same-context streaming + base economy) @ worktree scp-wt-audit / origin main d5de8b153. Verdict SHIP per story. Money core sound; 2 doc/provenance conditions on 039.
metadata:
  type: project
---

# Outlet Group-4 (SCP-OUT-032..039) streaming + economy audit

Worktree `/Users/alec/Developer/limn/scp-wt-audit` @ `d5de8b153` (origin/main). Read-only.
Builds on chunk-3 economic RE-REVIEW (see [outlet-streaming-chunk3-economic-audit.md]) — all 3 prior
findings stayed resolved; current HEAD is much later and consistent.

## Per-story verdicts
- 032 protocol types + preimages: SHIP. caveats_binding/chunk-sig/credit preimages byte-exact,
  len_be32 uniform (`update_with_len_prefix`), final JCS field length-prefixed (collision closed).
  @type-first JCS ordering sound.
- 033 executor→mpsc: SHIP. Pump `run_stream_pump_v2` (dispatch.rs:2721) — terminal guarantee via
  `pending_terminate` drained at loop top → signed synthetic terminal; timeout/panic/stall/cancel/
  revocation all route there; `PumpEscrowGuard` Drop refunds on panic. No dropped-chunk/lost-terminal.
- 034 credit+billing: SHIP (money core). CreditTracker (stream.rs:259) grant() verifies sig under
  pinned identity (cross-stream/epoch replay foreclosed), replay-check-first, `replenish_clamped` to
  max_billable ceiling. Per-chunk gate (invoke.rs:2572) + accrual + record_billed_emission share ONE
  `is_billable_chunk` predicate under ONE lock; manifest ingests only forwarded chunks → escrow ledger
  and manifest can't disagree. Settlement (dispatch.rs:3356) anchors BOTH event + receipt to
  manifest-derived count (`anchor_settlement_receipt_to_manifest`, overflow→0, capped at reserved,
  billed+refund==reserved). Grant top-up (dispatch.rs:950 apply_credit_grant): pump_exited gate first,
  debit→apply→reverse via supervisor.outlet_stream_reserve_grant (outlets_helpers.rs:1366 checked_mul
  EscrowOverflow + InsufficientFunds before debit). Self-mismatch → AuditAnomaly, never dropped. 7
  ContextParams present; base_cost_scale/outlet_error_buffer_max_secs correctly ABSENT (042d pending).
- 035 one-event-at-close: SHIP. Single emission at settlement (dispatch.rs:3341). chunks_billed
  verification honest split: same-context appender only has event → event-local `<=` backstop (can't
  re-derive without sequence, doc admits it); FULL re-derive on cross-context Sequence path
  (append_outlet_invoked_verified, invoke.rs:4465) → ChunksBilledMismatch wire-reject. Same-context
  producer writes manifest_reference directly so can't lie vs own manifest.
- 036 cross-context bridge: SHIP. Zero-escrow gate (invoke.rs:4291 cross_context_economy_gate) rejects
  on EITHER registration.cost.amount>0 OR cost_per_chunk>0 (split-source bypass closed). Bridge
  (invoke.rs:4578): OOM cap MAX_CROSS_CONTEXT_STREAM_CHUNKS=1<<20; verify against PINNED descriptor
  never bridge-supplied (verify_forwarded_chunk); aggregate_schema on End else output_schema; operator
  sig preserved end-to-end (synth terminals all-zero sig, real chunks fwd verbatim); terminal guarantee.
- 037 4-bridge FFI: SHIP (subagent-verified matrix). CRITICAL#1 (caller_did==pinned invoker_did →
  SCP-PERM-3001) enforced with real byte-compare in all 3 native bridges; CRITICAL#3 (no caller
  next_seq; runtime derives from emission cursor) real; no SDK signs (custody). MIN_PARITY_OPERATIONS
  floor real (109, ratcheted from 106). WASM = 2 predicates by ADR-057 fence (the extra 2 sign/preimage
  fns are OUT-048 scope, not a gap).
- 038 SDK control-plane: SHIP (subagent). single invoke verb, Credit newtype (0/neg/≥2^32 → InvalidGrant;
  Swift/Kotlin reject neg/overflow at compile via UInt32/UInt), StreamAlreadyClosed guard, SDK never
  signs (passes Credit.value; bridge signs via custody). All 4 langs.
- 039 vectors: SHIP-WITH-CONDITIONS (subagent). 7 vectors genuine (sequence_gap really skips seq 2;
  credit_stall window=1 no grant); runtime replays live via ScriptedExecutor, terminal codes
  FRAMEWORK-derived not read from JSON; per-SDK gap-detection REAL in all 4 (drain detects hole →
  signs cancel → StreamGap 6131, no scripted cancel-ack); WASM wire-integrity 30 chunks. CONDITIONS
  (doc/provenance only, not gaming): (1) story files-list names nonexistent
  crates/scp-ffi/napi/tests/outlet_stream_vectors_real.rs — actual tests inline at napi/src/outlet_stream/tests.rs;
  (2) AC[4] "driven through each of 4 bridges" only literal for single-shot vectors — multi_chunk/
  error_recoverable/credit_stall proven at runtime tiers + wire-integrity, not live bridge drain
  (UniFFI has no live drive, seam is pub(crate)). Architectural constraint, documented.

## Residual LOWs (non-blocking, carried from chunk-3 or new)
- Open-reject compensating counter releases (dispatch.rs:1507/1532/1537 `let _ = store.release`)
  swallow release failure → over-consumes invoker's OWN max_calls/cumulative counter. Self-scoped,
  fail-safe (no operator loss, no free service). Same class as chunk-3 hard-rate-token LOW.
- Settlement is fire-and-forget (stream_settlement_adapter.rs:148 warn+swallow on dispatch fail);
  money conservation still holds via durable stream_reservations record → reconcile refunds on restart.
- 037 minor: PyO3 sources durable monotonic_seq via shared helper; NAPI/UniFFI via
  protocol_repository.next_stream_credit_seq — both crash-safe, doc implies single helper (cosmetic).

## No production stubs/panics/unwraps in the money path. All panic!/unwrap hits are #[cfg(test)].
## No AC falsely depends on pending 040-043: same-context PaymentReceipt is §19.15.5 (existing), NOT
   the pending cross-context SCP-XCTX-STREAM-RECEIPT-V1 (043).
