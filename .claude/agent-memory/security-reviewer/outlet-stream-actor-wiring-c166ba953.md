---
name: outlet-stream-actor-wiring-c166ba953
description: Security review of chunk-3 outlet-streaming actor wiring (reserve→pump→settle bracket), commits 355f50a8c..c166ba953 on scp-wt-streaming
metadata:
  type: project
---

# Outlet-streaming chunk-3 actor wiring (355f50a8c~1..c166ba953) — 2026-07-13

## FIX DELTA re-review c166ba953..941c81d97 (Fix-A/B/C/D) — 2026-07-13 — VERDICT: SECURE
- F5 RESOLVED: escrow ticket (`StreamEscrowTicket::new`) armed IMMEDIATELY after reserve Ok in
  open_outlet_stream (supervisor.rs ~11158), BEFORE the fallible build_stream_post_input_hook `?`.
  Consume on pump-Ok, drop→refund on pump-Err. Explicit comment documents the ordering.
- F6 RESOLVED: reverse_stream_escrow_via_actor / settle_outlet_stream_via_actor /
  dispatch_outlets_command / reconcile_stream_reservations_via_actor / outlet_stream_origin_admission
  ALL `pub(in crate::context)`. Only open_outlet_stream is `pub`. scp-ffi + bindings grep for
  open_outlet_stream/Persist/Reconcile/reverse/settle/dispatch = EMPTY. Whole surface internal.
- NEW cmds PersistStreamReservation (fired ONLY from ActorStreamSettlementSink::persist_reservation
  → open_stream_session pump path) + ReconcileStreamReservations (fired ONLY from
  reconcile_stream_reservations_via_actor → lifecycle_helpers.rs:3172 restore_context). No untrusted
  caller. Attacker can't forge (not FFI, pub(in crate::context)).
- CROSS-CONTEXT: reconcile_stream_reservations (outlets_helpers.rs:1638) operates PURELY on passed
  cell.class_s.stream_reservations, refunds state.governance.budget_tracker (own, keyed invoker_did),
  releases state.class_s.caveat_counters (own, keyed ucan_cid). ZERO cross-context ref. Records
  stripped from PUBLIC export (export_import.rs:816 stream_reservations=HashMap::new()) so foreign node
  can't drive local refund. Full private migration carries debit+record together → balanced release.
  reverse_spend/release SATURATE → benign double-release = no-op. NO cross-context corruption vector.
- Fix-C OriginAdmissionTracker = per-Supervisor instance field (supervisor.rs:1515, init in ::new:1765),
  NOT a process global. Keyed per origin_invoker_did (BTreeMap). try_admit middle tier rejects only when
  THAT origin's own count>=cap → one origin denies only ITSELF; admission returns static slug only (no
  count leak, no cross-origin data).
- Fix-D capture-on-mismatch + all new logs (supervisor/lifecycle/dispatch 505/514/822/2308/2336/2350):
  context_id, hex request_id/receipt_id, generations, invoker's OWN billed amount, err string. tracing
  operator-log ONLY, never returned to caller (returns CapturedWithoutMutation). No keys/cross-context.
- Residual (NOT a Fix-D regression): settle double-fire idempotency obs from prior review still stands
  (release/refund legs saturate but re-apply; only capture deduped). Generation guard protects
  wrong-instance not double-fire on same instance.



Reviewed the 5 new OutletsCommand variants (ReserveOutletStreamEconomy, ReserveStreamCaveatCounter,
ReleaseStreamCaveatCounter, ReverseStreamEscrow, SettleOutletStream) + open_outlet_stream orchestrator
+ pump semaphore + admission registry + Drop-guard escrow refund.

**Verdict:** No CRITICAL/HIGH. Command surface is INTERNAL (scp-ffi grep empty; open_outlet_stream has
only a test caller — not FFI-wired yet). 3 MEDIUM (all defense/robustness, none externally reachable in
this chunk).

**Why:** How to apply — when the later FFI/transport wiring chunk lands, re-review these:
- MED-1 (real, manifests today): reserve allocates `base_sequence` via
  `MembershipState::next_sequence_number` (SHARED counter with message send path —
  messaging_helpers.rs:1069 + broadcast_helpers.rs:494; receiver does §9.8.5 gap detection +
  SequenceGapDetected + reorder-buffer stall). The reserve's OWN doc says "on ANY open-time failure
  after allocation it is rolled back" and the reserve does roll back on its internal failures. But
  `open_outlet_stream` (supervisor.rs ~730-745) does NOT roll back the sequence on `open_stream_session`
  Err (admission full / estimate / caveat / pump saturated / capability-denied at invoke_outlet Step 5 /
  counter exhausted) — only escrow is refunded (ticket Drop). No off-mailbox sequence-rollback command
  exists. → every downstream-rejected open permanently advances the shared per-sender counter → gaps in
  that sender's real messages → receiver stalls + spurious gap events. Self-limited (attacker's own
  sender seq), economically safe. Fix: add a rollback-sequence command fired on the Err arm, or defer
  seq allocation until pump commit.
- MED-2 (latent/robustness): escrow debited in reserve (Phase 1) but StreamEscrowTicket not armed until
  ~6 lines later; the ONLY intervening fallible `?` is `build_stream_post_input_hook` (open_outlet_stream
  line ~673), whose Err branch (counter-bearing caveat + no store) is unreachable because store is always
  Some. If ever reachable / another `?` added between reserve and ticket-arm, escrow (AND sequence) strand
  with no refund. Fix: construct escrow_ticket immediately after reserve Ok.
- MED-3 (hardening): `reverse_stream_escrow_via_actor` / `settle_outlet_stream_via_actor` /
  `dispatch_outlets_command` are `pub` on Supervisor; OutletsCommand is `pub` with pub fields.
  `reverse_stream_escrow_via_actor(ctx, attacker_did, HUGE)` is a direct spent-capacity refund primitive
  (reverse_spend reduces total_spent → raises remaining). Not reachable now (no FFI ref), but tighten to
  pub(in crate::context) and ensure FFI wires only open_outlet_stream, never the raw reverse/settle/dispatch.

**SOUND (cite these as passing gates):**
- Drop-guard fire-once: `StreamEscrowTicket::consume(self)` sets consumed; Drop refunds iff
  !consumed && reserved>0. Ok→consume (no refund), Err→drop→refund. Mutually exclusive by construction
  (settlement_sink fires only when pump spawned Ok = when ticket consumed). reverse_spend saturates so
  double-refund is a no-op anyway. Refund via `self.runtime.spawn` (Handle captured at construction, NOT
  Handle::current() at Drop) — correctly avoids off-runtime-Drop panic.
- Confused-deputy: SettleOutletStream carries reservation.generation (captured in sink), compared to live
  actor generation; mismatch DROPS (no external escrow to void). Correct.
- Caps survive crash-respawn: reap_stream_admission called ONLY at permanent teardown (remove path,
  shutdown_all_contexts, handle_ttl_expiry if state_transitioned, finalize_close) — NOT at despawn. So a
  malicious member can't reset per-context admission by forcing crash-respawn. No leak (reaped at all 4
  permanent sites, twin of remove_context_floors). Pump semaphore per-instance (not global), clamped [1,65536].
- Admission gate (Step 1) + pump permit (Step 3.5) both BEFORE expensive invoke_outlet (Step 5). Counter
  CAS is LAST gate (Step 5.5, after permit + invoke Ok) = R4 HIGH-2 preserved (rejected open burns no
  counter). Admission increment atomic under tracker write lock; concurrent opens serialize; no TOCTOU.
- Reserve check-and-debit atomic (serial actor mailbox). All reserve reject paths refund hard-rate +
  rollback velocity + rollback sequence + reverse budget (compensating persist). Tests cover all.
- No info disclosure: reserve→OpenStreamRejection reverse-map carries only static slugs (no amounts/balance);
  PaymentCaptureFailed + settle logs carry context_id, request_id/receipt_id (hex ids), invoker's own
  amounts, err strings — operator-log only, never returned to caller (caller gets Settled(None)); counter-CAS
  denial log explicitly omits UCAN/input. No key material anywhere.

**Observation:** settle_outlet_stream is NOT idempotent against a double-fire on the same instance — the
release/refund legs saturate but re-apply; only capture is deduped (request_id idempotency key). Relies on
pump's exactly-once settle contract (chunk 2b). Generation guard protects wrong-instance, not double-fire.
