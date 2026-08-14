---
name: scp-out-046-fixpass-pass2
description: PASS-2 re-review of SCP-OUT-046 streaming-saga seal-FSM fix-pass (4 blockers) — all FIXED, COMPLETE @324037d76
metadata:
  type: project
---

PASS-2 re-review of the SCP-OUT-046 fix-pass. Branch feat/outlet-xctx-046-seal-fsm,
worktree agent-ae545b67bf399eb19, delta 18f6fd11c..HEAD (4 commits). VERDICT: COMPLETE —
all 4 review blockers genuinely fixed (not string-gamed), 047 amendment faithful, all 9
OUT-046 ACs still pass, no new stub/deferral, no enforcement file touched.

**Why:** re-verify a fix-pass that addressed CRITICAL/HIGH review blockers on the durable
streaming-saga settlement path before merge.

**How to apply:** if re-touched, the load-bearing invariant is the durable `settled: bool`
flag on `CommittedStreamingOutletInvocation` (saga_prepared_state.rs) flipped in the SAME
Class-S persist as the money move (outlets_helpers.rs settle_outlet_stream commit closure).
That atomicity is the xctx double-refund guard (xctx path runs settlement_sink=None, no
stream_reservations reconcile net). Do not decouple the flag from the money persist.

Per-blocker FIXED table:
- (a) CRITICAL settlement-atomicity: FIXED. Witness carries settled=false + 11 rebuild
  fields copied from prepared slot at seal; settle_outlet_stream(_via_actor) take
  witness_saga_id, flip settled=true atomically with refund+counter-release; gen-mismatch
  AND no-actor branches DEFER entirely (no capture) for witness-bearing settle; seal task
  settles against outcome.generation (dead settlement_generation param fully removed) and
  only resolves Committed when applied; keyless recover_streaming_committing_entry →
  complete_unsettled_streaming_saga completes money move when present&!settled, idempotent
  when settled. NEW behavioral test xctx_streaming_crash_after_witness_before_settle_
  recovers_exactly_once dispatches seal handler directly (reproduces the seal→settle crash
  window), asserts money HELD in window, gen-mismatch settle DEFERS, keyless recovery
  refunds+captures EXACTLY once (captured==1, invoked==1), 2nd recovery no-op. REAL test.
- (b) dead reassembled Vec removed: FIXED. run_streaming_saga_seal_task keeps only
  last_sequence: Option<u64>; forward_bridge_terminal returns Some(chunk) instead of
  pushing into a Vec; A-side leaf recorded from SEALED outcome not a buffer. Fold-in synths
  terminal on capture_broke path (outer_open stays true — B-side fault, terminal guarantee
  preserved).
- (c) fabricated SCP-OUT-047 citation: FIXED. supervisor.rs:6796/7798 recovery-deferral
  comments re-pointed from "deferred to SCP-OUT-047" → ADR-049 §3a (general FFI-surface
  deferral authority; concrete driver now an AC of 047). Remaining SCP-OUT-047 refs in
  invoke.rs are legit (047 = the FFI consumer/caller seam). §3a + forward obligation exist
  (ADR-049:76/88).
- (d) A-side dual-log recovery reconstruction: FIXED. stream_settle_check_witness rebuilds
  a_event (CommitBStreamSettleOutcome) from witness receipt; complete_unsettled_streaming_
  saga calls record_streaming_saga_a_event on recovery. Best-effort/convergent/dedup-able;
  omitted if receipt won't re-serialize (honest).

047 amendment (upstream .docs/prds/outlet.json edit): FAITHFUL, not over-scoped. Adds AC#6
(recover_streaming_saga_truncated_close FFI-reconnect driver + caller_did binding),
machine-verifiable (grep target + test), cites real headings (§5.4.5, §5.4.5 CRITICAL #1,
§3a forward obligation, SCP-OUT-046 #136). Correctly homes the recovery-driver obligation
in the FFI-streaming-saga-surface story (pending). validate-prd PASS (437 stories).

Verification: cargo test -p scp-runtime --features testing --lib = 2207 passed/0 failed/1
ignored (ignored=scpid golden-value print, unrelated pre-existing); 4 streaming_saga +
serde round-trip + 12 settlement-adapter tests green; clippy clean; ZERO enforcement files
in delta (reply-type widening bool→StreamWitnessRecoveryStatus is scp-runtime-internal
SagaPhaseMessage, no FFI/matrix/pipeline obligation).

LOW obs (not a gap, not blocking): witness-present+unsettled where target is PERMANENTLY
evicted before any resident-sweep → saga stays Committing, refund HELD-not-credited. Fail-
closed (money held, never lost/double-spent), strictly better than pre-fix (which stranded
100% of crash-window refunds), inherent to actor-resident recovery (same posture as witness
-absent NeedsRepair). Code is honest ("left Committing for the next sweep"); not documented
as a terminal stranding case the way witness-absent is — a doc-nit at most.
