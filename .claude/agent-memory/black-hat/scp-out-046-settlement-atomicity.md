---
name: scp-out-046-settlement-atomicity
description: SCP-OUT-046 streaming-saga settlement atomicity — fix verdict + residual concurrent-double-settle hole
metadata:
  type: project
---

# SCP-OUT-046 settlement-atomicity (branch feat/outlet-xctx-046-seal-fsm)

Original CRITICAL (BLACK-046-1): witness persisted before money moved off-mailbox; crash strands invoker refund + §7.3.8 counter.

## Fix delta 18f6fd11c..HEAD (4 commits). Verdict: crash-in-window CLOSED, but RESIDUAL concurrent hole.

### CLOSED (verified)
- Money+`settled` flag are atomic: ONE `commit_class_s_keep` closure moves money (release+refund+record-remove) AND flips `xctx_committed_stream_outputs[sid].settled=true`. `outlets_helpers.rs` ~1791-1820. Crash can't leave money-moved-but-flag-unset nor flag-set-but-money-unmoved.
- Same-context path unchanged: `witness_saga_id=None` (stream_settlement_adapter.rs:142). None path = original Fix-D behavior. No regression.
- Widened replies (StreamSettleApplication{receipt,applied}, StreamWitnessRecoveryStatus) read correctly; seal task only resolves Committed when applied==true (invoke.rs:5232-5276).
- BLACK-046-2 (A-leaf) + BLACK-046-3 (capture_broke terminal, commit f716e323a) addressed.

### RESIDUAL CRITICAL — concurrent double-settle (money conservation broken)
Settle handler `settle_outlet_stream` is NOT self-idempotent: money move at outlets_helpers.rs:1794-1810 runs UNCONDITIONALLY when witness present; `w.settled` is SET (1815-1819) but never CHECKED to gate the money move. Idempotency rests ONLY on the recovery-READ gate (saga.rs `stream_settle_check_witness` rebuilds settlement iff !settled) — a SEPARATE mailbox round-trip from the settle-apply → TOCTOU.

Two concurrent settles against matching generation both apply → double reverse_spend (invoker over-refunded), double AmountCumulative release (§7.3.8 cap over-credited), double external capture. Money conservation broken across 3 ledgers.

Reachability:
- `replay_unresolved_sagas` (supervisor.rs:7336) has NO concurrent-invocation guard; `recover_streaming_committing_entry` (7800) has NO per-saga lock; no journal in-flight claim.
- Production trigger `resume()` (bridge_instance.rs:2544 → restore_all_persisted_contexts:2547; core resume:1144) has NO single-flight guard. Mobile (UniFFI/NAPI) calls it on EVERY foreground.
- Two overlapping resumes → two sweeps → both read settled=false → both settle. OR one resume racing a live seal task (invoke.rs:5236) that inserted witness settled=false but hasn't settled yet.
- Both CheckWitness reads complete BEFORE either settle (each sweep reads-then-acts), so FIFO mailbox does NOT save it — both reads see settled=false, guaranteed.

Fix test only covers SEQUENTIAL double-recovery (2nd sweep sees settled=true, no-op). Misses concurrent case.

ROOT FIX: gate the money move on `!w.settled` INSIDE the commit closure (check-and-act atomic in one Class-S persist), so N concurrent settles move money exactly once. Then the flag is a real guard, not just a recovery-read hint.
