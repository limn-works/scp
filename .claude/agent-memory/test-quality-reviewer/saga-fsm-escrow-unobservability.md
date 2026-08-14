---
name: saga-fsm-escrow-unobservability
description: Why hold-vs-void escrow coverage is infeasible on the live §6.2.4 xctx saga FSM path in pure test code (scp-runtime)
metadata:
  type: project
---

# §6.2.4 xctx saga: caller-side escrow is ALWAYS None on the live FSM path

On the live cross-context tool-invocation saga (§6.2.4), the caller-side external
escrow hold is always absent, so any FSM test asserting hold-vs-void (`voided==0`
vs `voided==1`) on a NeedsRepair/Aborted terminal is trivially true and
non-distinguishing. Verified against production (commit ce57bdd0d era):

- Prepare-A hardcodes `spending_ucan = None`: `reserve_tool_economy(cell, deps, …, None, …)` at `actor/handlers/saga.rs:482` (outbound leg presents no spending UCAN by design).
- `cost > 0 && spending_ucan.is_none()` → `Err("SCP-ECON-12060")` → Prepare-A FAILS → saga **Aborts at Prepare, never reaches NeedsRepair** (`tools_helpers.rs:624-631`).
- `cost == 0` (free tools, e.g. the `{a:1,b:2}` calculator harness uses) → **no escrow staged** (`tools_helpers.rs:652-655`).

Net: every reachable NeedsRepair terminal on this path has escrow `None`. A
`voided==1` positive control is equally unreachable. Making it distinguishing
needs a production test-seam that injects a non-empty `escrow_authorization` into
a live Prepare-A reservation — out of pure-test-code scope; correctly deferred to
a filed follow-up issue in #122.

**How to apply:** When reviewing the escrow-seam follow-up, expect a production
test-seam (not a pure-test mock) injecting a live reservation escrow, then a
`voided==0` (held) assertion on the NeedsRepair terminal with a `voided==1`
positive control elsewhere. The held-not-voided property IS already tested at the
actor-helper layer: `actor/handlers/saga.rs:5483-5518`
(`reverse_caller_reservation_record` with `escrow_authorization: Some(...)`,
asserting `voided == 1`) — that is the genuine consumer of
`VoidCountingPaymentAdapter`.

## Harness patterns worth replicating (#122)
- `start_paused(true)` manual current-thread runtime so the 500ms/1s/2s commit
  back-off auto-advances deterministically (no wall-clock sleep). Actor message
  passing wakes via wakers, not timers.
- Thread-local metrics via `metrics::with_local_recorder(&DebuggingRecorder…)` to
  dodge the poisoned process-global metrics cache under the parallel test binary.
- `FailingSagaJournal` wrapping the PRODUCTION `ProtocolRepositorySagaJournal` so
  post-fault on-disk bytes are byte-for-byte production shape; fault keyed on
  `SagaState` (robust to seq renumbering), not seq number.
- Strongest assertion: faulting the seq-4 NeedsRepair append yet still returning
  NeedsRepair + durable entry stays Committing — proves `reached_needs_repair` is
  set BEFORE the fallible append (reorder = test fails).

## Recurring finding: extraction charter vs single consumer
`context/test_support.rs` charter = "doubles referenced from MORE THAN ONE test
module." After the #122 honest-naming correction, `VoidCountingPaymentAdapter`
has exactly one consumer (saga.rs) yet three doc-comments still claim "shared by
two modules" (mod.rs:449, test_support.rs:3-4 and :15). When a correction removes
a second consumer, re-check the extraction's "shared" justification and its docs.
