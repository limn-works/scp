---
name: outlet-streaming-chunk3-economic-audit
description: Economic + resource-safety attack audit of chunk-3 outlet-streaming actor wiring (reserve→pump→settle bracket), worktree scp-wt-streaming, range 355f50a8c~1..c166ba953. 3 real findings + what holds.
metadata:
  type: project
---

# Outlet-streaming chunk-3 (reserve→pump→settle) economic audit

Range `355f50a8c~1..c166ba953` in worktree `/Users/alec/Developer/limn/scp-wt-streaming`.
Key files: `supervisor/supervisor.rs` (open_outlet_stream orchestrator + admission registry),
`outlets_helpers.rs` (reserve_outlet_stream_economy L1109, settle_outlet_stream L1359,
reverse_stream_escrow L1526), `outlets/stream_settlement_adapter.rs` (sinks),
`actor/handlers/outlets.rs` (handle_settle_outlet_stream L333), `outlets/dispatch.rs`
(open_stream_session L2010, StreamEscrowTicket L163, PumpEscrowGuard L1863),
`outlets/stream.rs` (StreamAdmissionTracker L1159).

## Real findings
1. **HIGH — respawn drops the billing capture (free rendered service).** `settle_outlet_stream`
   (outlets_helpers.rs L1365) returns `Dropped` on generation mismatch BEFORE the receipt
   capture. The no-actor teardown path (`settle_outlet_stream_via_actor`, supervisor.rs L400)
   DOES capture billed_amount against the open-time snapshot. Asymmetry: full teardown → billed;
   despawn+respawn (new gen actor) → capture DROPPED → invoker never billed for delivered chunks.
   Capture doesn't touch owned state (goes to supervisor payment adapter vs snapshot), so it could
   safely run on mismatch like the no-actor path. Fix: on gen-mismatch skip release/refund but STILL
   capture vs snapshot. Attacker induces via crash→respawn (or any import-replace) mid-stream.
2. **HIGH — per-origin-invoker admission cap is per-context, spec mandates operator-scope.**
   `outlet_stream_admission_for(context_id)` keys trackers by context_id (supervisor.rs L184).
   Spec `.docs/specs/05-contexts.md:448` is explicit: per_origin_invoker "tracked at operator scope,
   not per-context, so a caller cannot fan out across a cluster of interfaces hosted by the same
   operator to bypass the per-context limit." stream.rs L1210 doc even claims the tracker is "shared
   across every context they host" — but the wiring gives each context its own counter. One origin
   gets per_origin cap (default 16) PER context → fan out across ~256 contexts → exhaust node pump
   semaphore (4096) → deny streaming to all contexts. The exact spec-named DoS is unforeclosed.
3. **MEDIUM (DOA-risk) — base_sequence orphaned/leaked every open.** reserve allocates
   `base_sequence` via `next_sequence_number` (durably advances per-sender roster counter,
   Class-C persisted). `open_outlet_stream` never threads it into the returned StreamSessionHandle
   (no slot) and never rolls it back on `open_stream_session` rejection — so it's orphaned on BOTH
   success and failure. StreamEconomyReservation doc (outlets_helpers.rs L519-524) FALSELY promises
   "on ANY open-time failure after allocation it is rolled back via rollback_sequence_number" — only
   true for reserve-INTERNAL rejections, not post-reserve pump failures. Every open burns a sequence
   number no chunk uses → gaps; escalates to HIGH once transport lands if receiver enforces gap-free
   per-sender ordering.

## What holds (and why)
- **Double-refund foreclosed.** All `open_stream_session` rejection paths return BEFORE
  `spawn_pump_task` (dispatch.rs L2069-2267), so settlement_sink never fires on Err; escrow_ticket
  Drop is sole refund on failure, `consume()` disarms it on success. Exactly one refund fires.
- **Counter over-release foreclosed.** unspent_release = saturating(reserved − billed_count×cost);
  bounded by reserved (the CAS amount). release() saturates. max_calls/rate_window NOT released
  (correct — call was made / time-based). Only over-reserved AmountCumulative unspent is returned.
- **Cancel-ack billing escape foreclosed** (pre-existing pump): compute_chunks_billed_ref bills
  data chunks with seq ≤ cancel_ack_seq; pump sets cancel_ack_seq at current emit pos, so
  already-delivered chunks are billed. billed_count is metered by trusted pump, not invoker-controlled.
- **Escrow protected on reserve-then-abandon.** escrow_ticket Drop fully reverses reserved_escrow
  (saturating reverse_spend). Minor LOW: hard-rate token + velocity tick consumed at reserve are
  NOT rolled back on pump-failure (only on reserve-internal reject) — self-scoped (attacker
  rate-limits themselves), fail-safe, but inconsistent with reserve's own rollback discipline.
- **Pump permit** held for exact pump lifetime, released on return/terminal/cancel-ack/panic
  (bound as owned permit in spawned task, dispatch.rs L1947). Teardown terminates pump → releases.

## RE-REVIEW verdict (range c166ba953..941c81d97, Fix-A/B/C/D) — RESOLVED (2026-07-13)
All 3 prior findings resolved; no new HIGH/MED regression.
- **#1 RESOLVED** — mismatch settle now `CapturedWithoutMutation(Some(receipt))`: captures §19.15.5
  receipt vs OPEN-TIME snapshot.policy (not live), no owned mutation. billed_amount is Fix-B
  manifest-anchored (settlement.billed_amount = manifest_billed_amount) + re-capped cost×count in settle.
- **#2 RESOLVED** — new operator-scoped `OriginAdmissionTracker` (single Supervisor instance, keyed by
  origin_did, self-removes at zero). Lock order fixed: per-ctx `admission` FIRST, origin leaf SECOND at
  all 3 sites (gate/release/pump-close). Origin=innermost leaf → no deadlock, no lost-update. Tests prove
  16-total-across-4-contexts + release frees capacity.
- **#3 RESOLVED** — Fix-A deleted base_sequence alloc+field+all rollback_sequence_number; explicit
  MembershipState::contains gate instead. Allocate-at-consumption deferred to transport chunk.
- **Double-refund FORECLOSED** all interleavings: clean settle clears record in SAME commit as
  release/refund (→sweep no-op); mismatch never touches state/record (→sweep sole releaser); exactly one
  of {clean,mismatch} fires per stream (gen ==/!= at single terminal); sweep idempotent under KEEP fail
  (refund+clear one commit, lost in-mem re-runs from durable). Escrow-ticket-Drop vs record CANNOT co-occur:
  record persist is strictly AFTER last fallible op in open_stream_session (only infallible chan+spawn→Ok),
  ticket.consume() immediately follows Ok (supervisor.rs L11238-11249) with no intervening fallible code.
- **Wrong-context sweep FORECLOSED doubly**: strip_snapshot_for_public zeroes stream_reservations +
  import_context starts fresh → ONLY same-node restore_context rehydrates own durable records vs own state.
- **Residual LOW**: open-time leak window (escrow-debit/counter-reserve → record-persist, ~1-2 mailbox
  commits) strands invoker's OWN reserve on a crash-in-window. Fail-safe, no attacker profit, strictly
  better than pre-fix (whole-stream window). Harden: fold record insert into Step-5.5 counter-reserve commit.
- **LOW doc bug**: outlets_helpers.rs:1339 stale doc-comment still says mismatch "DROPPED silently —
  [StreamSettleOutcome::Dropped]" (removed variant, broken intra-doc link, OPPOSITE of current capture).
  CI cargo doc has no -D warnings → warning not hard-fail. Fix trivially.
- **OBSERVATION**: crash-survived case over-refunds INTERNAL budget_tracker (nets 0) while external receipt
  still bills B — sweep can't recover billed from open-time record. Conservative/favors-user, receipt is
  authoritative money artifact. Not free service. Acceptable.
