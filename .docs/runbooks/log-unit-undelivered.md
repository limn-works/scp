# Runbook: `scp_log_unit_undelivered_total` is non-zero

**Scope.** Code outside a context's actor hands an event-log record to that actor, which
queues it as a pending log unit (spec 17 §17.3 "Event log write failures"). When the hand-off
fails on a background path that has no caller to return the error to, the runtime increments
`scp_log_unit_undelivered_total` and writes an error log. This runbook
covers what a non-zero value means and how to repair the context's log.

## Signal

`scp_log_unit_undelivered_total` (`crates/scp-runtime/src/metrics.rs`,
`record_log_unit_undelivered`) counts every failed hand-off. The counter carries no labels,
so read the paired error log. The first two paths below name the context in the log; the third names no context, so match it by time against the streams that closed during a shutdown. Any increase means a context's log is missing
a record of an operation that the context performed: the operation completed, and the log
holds no record of it.

Three paths increment the counter. Each path writes its own error message:

| Path | Error log | Missing record |
|------|---------------|----------------|
| The cross-context bridge, after a cross-context stream ends (`send_cross_context_a_unit`, `context/outlets/invoke.rs`) | `log unit was not queued; the context's log lacks this record`, with `record` set to `cross-context bridge A-side OutletInvoked` | The `OutletInvoked` record in the receiving context A's log |
| The streaming close sink (`ActorOutletInvokedEventSink`, `context/outlets/stream_settlement_adapter.rs`) | `log unit was not queued; the context's log lacks this record`, with `record` set to `streaming OutletInvokedEvent` | The stream's close record in the hosting context's log |
| A streaming close hand-off that never ran because the Supervisor was gone or refused the task (`spawn_supervisor_op` in `context/outlets/stream_settlement_adapter.rs`, counted through `SinkHandoff::OutletInvokedEventAppend`) | `streaming sink: ... operation not run`, with `operation` set to `streaming OutletInvokedEvent append` | The stream's close record in the hosting context's log |

A streaming saga's A-side record increments this counter only when A's context is deleted.
While A's context exists, a failed hand-off leaves the saga in `Committing`, and the saga
recovery sweep re-sends the record on the next sweep and restart. When A's context is deleted
from persistence, the record has no log to land in: the sweep resolves the saga, increments
the counter once, and logs `streaming saga recovery — the caller context is deleted`.
`saga-needs-repair.md` covers a saga that does not resolve.

## Cause

A hand-off that never ran (the third path) sent nothing. The first two paths send the record
to the actor once and do not retry, and the send ends in one of two ways:

- **The unit was not queued.** The counter counts only this outcome, and the error log's
  `error` field begins `log unit not queued:` followed by the reason:
  - **The Supervisor or the context's actor is gone.** A shutdown that started during the
    stream, or a context that despawned before the stream ended, leaves no actor to queue
    the record.
  - **The actor's mailbox stayed full** for the whole send timeout, so the command never
    reached the actor (`ActorBusy`).
  - **The actor refused the unit.** Its leaf did not plan, or the context state store failed
    and the actor could not store the unit (`PersistenceFailed`).
- **The reply was lost.** The actor took the command, but its reply was dropped or did not
  arrive within the reply bound, so the unit may have been queued. The runtime logs this at
  warn level, with `log unit delivered, outcome unknown:` in the `error` field, and does not
  increment the counter. Check whether the context's log holds the record before you treat
  it as missing.

## Repair

No path re-sends a record that this counter counted. The record stays missing until an
operator acts.

1. Find each paired error log and note the context ID it names, or, for a hand-off that
   never ran, the streams that closed at that time.
2. Fix the cause. For a refused persist, repair the context state store before anything
   else, because every later queued record in that context fails the same way. For a gone
   actor, confirm that the context restored after the restart.
3. Reconcile the missing record from the record the other side holds. For the
   cross-context bridge, the target context B's log holds its own record of the same
   invocation. For a streaming close,
   the stream's settlement in the hosting context is the remaining account of the stream.
4. Record the gap in the incident: the context's log stays one record short, and every
   member that replays that log sees the same gap.

## Related

- Spec 17 §17.3 "Event log write failures": the pending log unit protocol.
- `saga-needs-repair.md`: a cross-context saga that recovery cannot resolve.
