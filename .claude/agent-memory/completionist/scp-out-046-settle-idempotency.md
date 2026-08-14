---
name: scp-out-046-settle-idempotency
description: How the xctx streaming-saga settle idempotency gate stays sound (actor serialization + sync closure), and how the recovery-status enum maps the old struct
metadata:
  type: project
---

SCP-OUT-046 pass-2 fix (branch feat/outlet-xctx-046-seal-fsm) added a settle
idempotency gate + a recovery-status enum refactor. Verified COMPLETE (pass-3).

**Why the concurrent-double-settle gate is sound** (the load-bearing claim):
`settle_outlet_stream`'s `settled`-flag read+set lives INSIDE the
`commit_class_s_keep` closure. `commit_class_s_keep` (class_s.rs ~2792) runs the
closure `f` SYNCHRONOUSLY (`let value = f(...)?;` then `persist(...).await`) — the
in-memory flag flip + money move complete before any await. The per-context actor
mailbox serializes every `SettleOutletStream` message, and both `settle_outlet_
stream_via_actor` calls dispatch separate mailbox messages. So the first settle
flips `settled=true` synchronously; the second observes it and returns
`Ok(true)` → `StreamSettleOutcome::Settled(None)` → `StreamSettleApplication{
applied:true, receipt:None}` (handlers/outlets.rs ~423). No money moves twice.

**Why the new test is non-vacuous:** both concurrent settles pass the IDENTICAL
rebuilt settlement + MATCHING generation, so `should_release`/`refund` (derived
from the settlement, constant) are true for both, and the generation-mismatch
defer branch is NOT hit. The ONLY thing preventing a double refund/capture is the
`settled` gate — so `captured==1` and budget-exact assertions genuinely fail
without it.

**Recovery-status enum mapping** (StreamWitnessRecoveryStatus, commands.rs ~3195):
old struct{present,settled,generation,settlement,a_event} → enum
Absent | Settled | Unsettled{generation,settlement,a_event}. Map: None→Absent,
Some+settled→Settled, Some+!settled→Unsettled. Permanent-eviction + send-failure
both →Absent (NeedsRepair, escrow held) = old present:false. The dropped
"settlement couldn't be rebuilt" defensive branch was already unreachable —
`rebuild_stream_settlement` (handlers/saga.rs ~2513) returns a non-Option
StreamSettlement (infallible).

**How to apply:** when re-reviewing this area, the gate's soundness rests on
(1) closure sync execution in commit_class_s_keep and (2) actor mailbox
serialization — if either changes, the idempotency guarantee breaks. The enum's
exhaustive match in supervisor.rs recover_streaming_committing_entry (~7848) is
the recovery decision point.
