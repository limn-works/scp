# Class-S KEEP closure return is discarded on persist Err (SCP-OUT-046)

`ClassSCell::commit_class_s_keep(deps, ctx, closure)` runs
`persist_state_fail_closed(..).map(|()| value)` — it maps the closure's return
value ONLY on `Ok`. On a persist FAILURE (KEEP semantics: in-memory mutation is
kept, run-loop retries the durable write) the closure's returned value is
DISCARDED and the caller sees `Err`.

**Rule:** NEVER encode a control-flow decision (e.g. an "already settled, skip
external side-effect" bool) in the closure's return value if that decision must
survive a persist failure. The bug in OUT-046 pass-2: the in-closure `settled`
gate returned `Ok(true)`; on persist `Err` the `true` was lost, `already_settled`
stayed false, and the external (non-transactional) payment capture re-ran →
double-bill (the xctx streaming saga runs with `settlement_sink = None`, so there
is NO `stream_reservations` reconcile net to dedup the capture).

**Fix (pass-3, commit 2c3b2408c) — verified correct:** an AUTHORITATIVE
PRE-COMMIT read of the durable flag through the cell `Deref`, BEFORE the commit
block, returning a distinct `StreamSettleOutcome::AlreadySettled` (applied:true,
no receipt, `Outcome::ok` unmutated). Actor-serialization makes the pre-commit
read authoritative for concurrent same-process double-settles; the payment
adapter idempotency key (`idempotency_key = request_id`, stable across crash via
`rebuild_stream_settlement` copying the durable witness `request_id`) is the
second layer that closes the cross-process crash window. Two-layer exactly-once:
flag = concurrent guard, key = crash guard.

**Recovery generation note:** crash recovery passes B's CURRENT generation
(`stream_settle_check_witness` reports `cell.generation`; supervisor.rs ~6893
passes `outcome.generation`), so the re-driven first settle matches generation
and does NOT defer-loop. The pre-commit read is placed before the
generation-mismatch check — safe, because it only fires on `settled==true`
(money durably moved once), which is valid to observe regardless of instance
generation (the witness is B's own durable Class-S state).
