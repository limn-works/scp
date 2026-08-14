# Event-log convergence: PaymentReceived/per-author exclusion (b3d354279, 3e667ef48)

Branch reviewed Jun 2026. Wave B core + WASM parity for ADR-051 §6 / phase-2.md ADR-011 exclusion taxonomy.

## What changed
- `complete_paid_action` (economy_helpers.rs): dropped durable `EventType::PaymentReceived` append; now emits local `ContextEvent::PaymentReceived` + pushes into new `PerContextState.payment_receipts: Vec<PaymentReceipt>`. Dropped `payer_did` param (both callers capture_send_payment/capture_join_payment updated; member_did/sender_did still used on failure path).
- `payment_history` (receipt.rs): now takes `&[PaymentReceipt]` instead of scanning `&[Event]`. Wired QueriesCommand::PaymentHistory → Supervisor::payment_history through actor mailbox.
- WASM manager.rs: removed MessageSent (send+broadcast) and ToolInvoked durable appends; push_event local emits KEPT. invoke_tool dropped identity_did param.
- WASM consequence.rs: new `merged_consequence_events` = faithful port of native `event_log_entries_for_consequences` (governance_logic.rs:689). Same constants, same dedup/skew/cap logic.

## Findings (no CRITICAL/HIGH)
- **payment_receipts unbounded Vec, no eviction (MEDIUM)** — while receive_buffer is bounded (DEFAULT_BUFFER_CAPACITY=1000, ring eviction). Long-lived high-payment context grows unbounded in actor memory. Old durable path was also unbounded BUT checkpointed; in-memory Vec is not. Also never persisted to ProtocolRepository::store_payment_receipt (which is dead code, tests-only, both before+after).
- **Supervisor::payment_history wired but UNREACHABLE (LOW)** — no ContextManager method / FFI export / SDK surface calls it. Doc references `SCP.Economy.paymentHistory(context)` which does not exist. Pre-existing gap (old free fn also had no prod caller), but new mailbox plumbing added still-dead.
- **receipt.anchored excluded from signature, no trust-consumer yet (LOW/latent)** — field always false, no production reader. When a future consumer gates on anchored it MUST derive from Merkle/local state, never the unsigned wire field.
- **ToolRateExceeded consequence now dead in BOTH native+WASM (by design, NOT a bug)** — ToolInvoked no longer in durable log nor receive buffer (no ContextEvent arm). Matches native (settle_tool_economy_capture feeds no ToolInvoked). Acknowledged by is_convergent_trigger + tool_invocation_count_anchored=false. Re-activates under ADR-051.

## Verified clean
- All 16 PaymentReceipt sites set anchored. All PerContextState constructors init payment_receipts.
- participation signable_bytes: anchored byte inserted at fixed pos, capacity+1, sig-binding tests real. WASM uses SHARED ParticipationProfile (no drift).
- WASM merged_consequence_events: saturating arithmetic throughout, no panic/borrow issues, single-threaded (no lock-across-await). Bounds match native.
- clippy clean: scp-protocol+scp-runtime (testing) and scp-ffi-wasm (wasm32) both -D warnings clean.
- Tests non-vacuous: cross_impl_per_author_leaf_would_break_convergence is a real negative control.
