---
name: review-xctx-saga-abort-reversal-445542b95
description: §6.2.4 cross-context saga abort/reversal economic-integrity audit — exactly-once caller refund holds; ONE MEDIUM dead Class-S gate marker (multi-line insert chain never matches per-line awk scanner)
metadata:
  type: project
---

# §6.2.4 xctx-saga abort/reversal economic-integrity audit (worktree xctx-saga, branch feat/actor-2c-6.2.4-xctx-saga, HEAD 445542b95)

Scope: supervisor.rs 6987-7307 (abort_saga / abort_xctx_participants / redrive_caller_local_reversal), tools_helpers.rs reverse_caller_reservation_record + void_external_and_consume, saga.rs abort handler + commit_a + prepare_a insert/remove, check-class-s-fail-closed.sh MUTATORS.

## VERDICT: exactly-once reversal guarantee HOLDS across all 5 abort sub-paths. ONE MEDIUM enforcement-gate finding (dead marker), not a live over/double-charge.

### Q1 over-charge / double-refund — HOLDS
- Carrier-vs-record mutual exclusion: live abort = `Some(reservation)` reverses via generation-checked carrier ticket rollback THEN removes durable record WITHOUT re-reversing; crash abort = `None` reverses FROM record (generation-checked local + always-void escrow). carrier present ⟺ Some ⟺ record-reversal-NOT-run. Never double-reversed.
- abort_saga refuses to write terminal `Aborted` marker unless caller_reversal == SettledOrAbsent; any ReversalOutstanding leaves journal non-terminal (PreparingB) so §17.16.4 sweep re-drives Abort{None}. So a skipped/failed refund never gets sealed as "fully compensated" → no permanent over-charge.
- 5 sub-paths all correct: (a) delivered Abort{Some} Ok → fully compensated; (b) send-fail+recovered cmd → void+consume escrow, inline redrive Abort{None} from record; (c) redrive also fails → ReversalOutstanding (journal stays non-terminal); (d) delivered-but-handler-error Err((_,None)) → ReversalOutstanding (handler may have failed before durable persist; sweep idempotently re-drives); (e) despawned-actor (lookup miss) → void+consume escrow, ReversalOutstanding for respawn+sweep.
- Commit-A consumes the record in the SAME Class-S snapshot as the commit witness (re-stash on persist failure), so a settled saga has no straggler record for a spurious abort to reverse. Replay Commit-A is generation-checked + witness-idempotent.

### Q3 escrow double-void safety — HOLDS
- `void_external_and_consume` (tools_helpers.rs:221) + `reverse_caller_reservation_record` escrow void (tools_helpers.rs:371-380) BOTH rely on adapter void being idempotent across recovery re-drives (explicitly documented contract). `#[must_use]` ToolEconomyTicket + ToolEconomyReservation drop-guards: send-fail uses send_recover_on_failure (NOT plain send) so the ticket is never dropped inside the send; recovered ticket is void_external_and_consume'd (sets consumed=true) exactly once; despawn arm voids+consumes once. Carrier-void + record-driven re-void hit the SAME PaymentAuthorization but void is idempotent → safe.

### Q2 MEDIUM (enforcement gate, not live charge): dead Class-S marker for the Prepare-A insert
- scripts/check-class-s-fail-closed.sh MUTATORS token `xctx_caller_reservations.insert(` is matched LINE-BY-LINE via awk `index(normalize_assign(line), marr[mi])`. There is NO line-join / continuation accumulation (in_block only handles block comments).
- The real insert (saga.rs:461-463) is a 3-line method chain: `state` / `.xctx_caller_reservations` / `.insert(saga_id.clone(), record);`. No single physical line contains the contiguous token → marker NEVER fires (empirically verified with awk).
- prepare_a still PASSES the gate, but only because it independently persist_state_fail_closed (line 476) → fn_failclosed=1. The coverage is COINCIDENTAL. A future refactor that moves the insert into a non-fail-closing helper would NOT be caught by this marker. Self-test fixtures (send_message/reserve_tool_economy/suspend_access) never exercise a multi-line insert chain, so the dead marker is unnoticed.
- FIX options: (1) make the awk scanner join method-chain continuations before matching (robust, also future-proofs other multi-line markers), or (2) match on the bare-substring `xctx_caller_reservations` (drop `.insert(` precision — but then .remove sites also match, which the gate intentionally excludes), or (3) add a self-test fixture with the multi-line chain form that asserts the marker fires. Substantive economic correctness is unaffected — this is enforcement defense-in-depth only.
