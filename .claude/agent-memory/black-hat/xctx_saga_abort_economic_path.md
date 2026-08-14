---
name: xctx-saga-abort-economic-path
description: Re-attack of §6.2.4 cross-context saga abort/economic path + check-class-s-fail-closed gate cutoff fix (wave-14, commit 9d168759c). 3 prior HIGHs fixed; this pass found them robust.
metadata:
  type: project
---

# §6.2.4 Cross-Context Saga Abort/Economic Path — Wave-14 Re-attack (commit 9d168759c)

Files: `crates/scp-runtime/src/context/actor/handlers/saga.rs` (prepare_a, abort, commit_a),
`crates/scp-runtime/src/context/supervisor/supervisor.rs` (abort_xctx_participants,
redrive_caller_local_reversal, abort_saga), `crates/scp-runtime/src/context/tools_helpers.rs`
(void_external_and_consume, reverse_caller_reservation_record, rollback_tool_economy_generation_checked),
`scripts/check-class-s-fail-closed.sh`.

## Economic double/zero-reverse — ALL RESIST
- **Local economy (budget/velocity/hard-rate-limit) reversed EXACTLY ONCE on every abort terminal path.**
  - prepare_a lost-reply (saga.rs:508) calls ONLY `void_external_and_consume` (voids escrow + consumes
    `#[must_use]` ticket; does NOT touch `state.governance` local). Leaves durable record. Local reversed
    later by the abort's record path = once total.
  - abort `Some` gen-MATCH: carrier reverses local, removes record. gen-MISMATCH: carrier voids escrow only
    (`carrier_ran=false`), FALLS THROUGH to `reverse_caller_reservation_record` (reverses local once from
    record), removes record. abort `None` (crash sweep): reverses local from record once, removes.
  - Record is the single-consume token: removed on every terminal caller path (abort Some/None, commit_a
    first + replay). A 2nd abort/sweep finds no record → no-op. No await between get+remove in the actor
    (single-threaded owned `&mut state`), so no interleave.
- **Ticket balanced exactly once** in prepare_a lost-reply (only `ToolEconomyTicket` has the Drop guard;
  `ToolEconomyReservation` is `#[must_use]` lint only — partial-move of `.ticket` drops the rest cleanly).
- **Zero-reverse hole closed**: `abort_saga` (supervisor.rs:7023) early-`return Ok(())` on
  `ReversalOutstanding` WITHOUT `mark_resolved(Aborted)` — journal stays `PreparingB` for the §17.16.4 sweep.
  Terminal-Aborted is NEVER written while local reversal is pending.
- **Wrong-context steering**: redrive uses `caller_hex = hex(ctx.caller_context_id)` (bound to the saga's
  caller); actor reverses by `record.actor_did` keyed in ITS OWN `xctx_caller_reservations[saga_id]`. A
  victim ctx has no record under the attacker's SagaId → no-op. Resistant.
- **Escrow double/triple-void** (carrier void + record void, sometimes + supervisor recover void): all on the
  SAME `PaymentAuthorization`, idempotent by adapter contract (pre-existing assumption the carrier path
  already relied on — not a regression).

## Gate cutoff fix (check-class-s-fail-closed.sh) — un-blinds ~10k lines, correctly
- Root cause: column-0 `#[cfg(any(test,feature="testing"))]` at supervisor.rs:207 decorates `impl SagaInput`
  (a production-compiled testing item), NOT a `mod`. Old raw-line cutoff treated it as "skip rest of file",
  silently blinding ~10k production saga lines (real trailing `mod tests` is at 10265).
- Fix: cutoff now look-aheads from the gate to the first column-0 item; fires ONLY for `mod`-form. Verified
  scan_file now inspects 189 fns in supervisor.rs INCLUDING abort_xctx_participants(7121), abort_saga,
  redrive_caller_local_reversal. saga.rs: all 5 marker fns (prepare_a/prepare_b/commit_b_first_settle/
  commit_a/abort) in FC set. Gate = 0 HITs / 0 GOVHITs. No real best-effort Class-S mutation hides in the
  un-blinded region.
- NTTEST structural assertion: a `mod`-form test gate followed by a column-0 production item emits NTTEST
  (fail-loud). Verified catches: plain `fn`, `pub(crate) fn`, attribute-then-`fn`, `const fn`+later-`fn`,
  `macro_rules!`+later-`fn`. Interspersed testing-`impl` (the 207 shape) correctly does NOT false-cutoff and
  still HITs an unsatisfied mutation below it.

## Residual (defense-in-depth, NOT exploitable here)
- **NTTEST regex misses a bare `unsafe fn` resumption** (matches `unsafe impl` but not `unsafe fn`): a lone
  `unsafe fn` after a test mod is skipped with NO NTTEST. DEAD in practice — `scp-runtime/src/lib.rs:21` has
  `#![forbid(unsafe_code)]`, so `unsafe fn` cannot compile in the scan dir. Fix is cheap (add `unsafe[ ]+fn`
  alt) if defense-in-depth desired.
- **fn-detection (line 858) misses column-0 `const fn`** (governance_logic.rs:308, supervisor.rs:10073 etc.):
  never scanned. DEAD — const context cannot perform a runtime `state.x.insert()` Class-S mutation.
- Gate checks PRESENCE of `persist_state_fail_closed` in a fn body, not that it COVERS the mutation's
  success-ack (coarse). Pre-existing design limitation, not a wave-14 regression.

## Tests (all green): abort_a_side_gen_mismatch_reverses_local_from_record,
prepare_a_lost_reply_balances_ticket_and_keeps_record, abort_a_side_persists_caller_refund,
reverse_caller_reservation_record_voids_external_escrow,
rollback_generation_checked_voids_external_not_local_on_mismatch + all 74 saga lib tests.
