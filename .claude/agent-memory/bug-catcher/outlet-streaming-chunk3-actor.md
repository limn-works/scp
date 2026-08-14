---
name: outlet-streaming-chunk3-actor
description: Bug review of outlet-streaming chunk 3 (reserve→pump→settle bracket) on the actor architecture — base_sequence leak + generation-guard escrow/counter leak
metadata:
  type: project
---

# outlet-streaming chunk 3a-3e (feat/outlet-streaming-runtime, 355f50a8c~1..c166ba953)

Same-context outlet streaming wired onto the actor arch. `Supervisor::open_outlet_stream`
(supervisor.rs:10970) = reserve (mailbox) → off-mailbox pump (`dispatch::open_stream_session`)
→ settle (mailbox via `ActorStreamSettlementSink`). dispatch.rs is PRE-EXISTING infra (not in diff).

**Why:** review for money/capacity leaks, races, crashes.

**How to apply — findings (most severe first):**
- **MEDIUM base_sequence leak on open-failure.** `reserve_outlet_stream_economy`
  (outlets_helpers.rs:1158) allocates `base_sequence` via `MembershipState::next_sequence_number`
  (the SHARED per-sender message send-sequence). On reserve-internal failures it rolls back, but
  once reserve returns Ok and the PUMP rejects, `open_outlet_stream`'s Err arm (supervisor.rs:11141)
  only `drop(escrow_ticket)` — NEVER rolls back base_sequence. Burns a sequence number on every
  failed open (admission cap, pump-cap-exhausted, caveat-post-input, counter-exhausted). Durably
  persisted on paid streams (rides the escrow `commit_class_s_keep_compensating`). Creates §9.8.5
  sequence gaps → receiver force-close. Naive LIFO `rollback_sequence_number` (saturating_sub) is
  UNSOUND to add because the off-mailbox window lets the actor advance the counter via other sends.
  Fix: defer allocation to the transport chunk that consumes it. Contradicts reserve's own doc
  ("rolled back on ANY open-time failure after allocation"). Also unconsumed even on success this
  chunk (known gap b).
- **MEDIUM generation-guard drop leaks durable escrow + counter reserve.** `settle_outlet_stream`
  (outlets_helpers.rs:1365) DROPS on `generation != cell.generation` touching nothing — comment
  says "no external escrow to void". But the §5.4.5 open-time hold is a DURABLE budget-tracker debit
  (persisted at reserve) + the §7.3.8 AmountCumulative counter reserve (persisted by
  ReserveStreamCaveatCounter). On actor crash+respawn-from-snapshot (gen G→G+1) WHILE the off-mailbox
  pump SURVIVES (separate task, own Arc<Supervisor>), the settlement lands with old gen → dropped →
  unspent escrow never refunded (money leak) + unspent counter never released (capacity leak) + no
  receipt captured. Unary/saga paths compensate (void external escrow / CallerReservationRecord);
  streaming has NO recovery record. Inherent generation-guard tradeoff (can't distinguish
  import-replace from same-context-restore) but streaming lacks compensation.
- **LOW test-gap correction.** Prompt claimed "no e2e test" — FALSE. supervisor.rs:27320
  `open_outlet_stream_reserve_pump_settle_end_to_end` drives open→grant→drain→cancel→close→receipt
  (in-process, live actor). Real gaps: FAILURE-path coverage (open-reject → escrow ticket refund +
  base_sequence) and FFI-bridge integration.

**Verified SOUND (not bugs):** escrow-refund-from-Drop captures `Handle` at construction (open runs
on runtime) so Drop never calls `Handle::current()`; double-settle guarded by `PumpEscrowGuard.settled`
+ `pump_exited` lock (single fire); counter unspent-release happens ONCE (settle_outlet_stream only,
not also via adapter.release at close); reverse_spend/release saturate (double-refund safe);
reap_stream_admission keeps live-pump Arc alive + skips respawn transient despawn; get-or-create
admission uses sync std RwLock (no lock-across-await); ContextError→OpenStreamRejection reverse-map
never turns a failure into success (worst case imprecise slug, still Err + ticket refund).
