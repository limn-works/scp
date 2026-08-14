# SCP-OUT-046 streaming-saga seal FSM (ADR-061) — review notes

Branch feat/outlet-xctx-046-seal-fsm. Files: outlets/invoke.rs (run_streaming_saga_seal_task,
record_streaming_saga_a_event), actor/handlers/saga.rs (prepare_b_streaming, stream_capture_append,
commit_b_stream_settle + first_settle + finalize), supervisor.rs (recover_streaming_committing_entry,
recover_streaming_saga_truncated_close, streaming_saga_target_hex, settle_outlet_stream_via_actor).

## FINDING (HIGH, narrow trigger) — saga escrow refund/counter-release stranded on mid-stream actor respawn
- Normal seal task (invoke.rs:5172) applies StreamSettlement via settle_outlet_stream_via_actor
  using `settlement_generation` = RESERVE-TIME gen (econ_reservation.generation, supervisor.rs:6696).
- settle_outlet_stream (outlets_helpers.rs:1659) drops the settlement (CapturedWithoutMutation, no
  owned-state mutation) when generation != cell.generation — the Fix-D confused-deputy guard.
- The non-saga pump path tolerates this drop because open_stream_session persists a `stream_reservations`
  record (dispatch.rs:2396, gated on `settlement_sink.is_some()`) that the restore-time
  reconcile_stream_reservations sweep refunds. BUT the SAGA path calls open_stream_session with
  settlement_sink = None (supervisor.rs:6648) → NO stream_reservations record → NO reconcile net.
- Scenario: B's actor despawns+respawns mid-stream (suspend/resume, import-replace, evict+reload) while
  the off-mailbox seal task survives; saga_pending slot restored from snapshot; seal succeeds on new gen
  G1 (witness present, slot cleared) → escrow_ticket.consume() (invoke.rs:5142, no drop-refund) →
  settle with reserve-time G0 != G1 → dropped. Refund (reserved-billed) never returned to budget hold;
  §7.3.8 cumulative counter unspent-release never applied. Permanent over-charge, no recovery path.
- Recovery path (recover_streaming_saga_truncated_close, supervisor.rs:6888) correctly uses
  outcome.generation (CURRENT) so it APPLIES. The normal seal task should do the same. Fix: pass
  outcome.generation to settle_outlet_stream_via_actor in the seal task (matches recovery; still
  protects against import-replace-AFTER-seal since seal-time gen != a later different-context gen), OR
  register a Fix-D stream_reservations record for the saga path.

## Verified CLEAN
- Discriminant streaming_saga_target_hex (supervisor.rs:7751): 2 raw-64-hex participants + empty
  evidence. Unary xctx journals 3-elem triple [caller_hex, caller_did(has colons), outlet_reg] with
  non-empty evidence; TestForceNeedsRepair 1-elem. No collision. Sound.
- into_prepared rehydration (saga_prepared_state.rs:555/604): all fields incl frontier + new
  SCP-OUT-046 ledger fields copied; test asserts root/billed_count/leaf_count survive. Seal recomputes
  billed = cost_per_chunk × frontier.billed_count() (not stored billed) so stale field can't corrupt.
- Replay short-circuit (commit_b_stream_settle): witness get() first → reemit with settlement:None
  (no double money-move); else first_settle removes slot + inserts witness. Idempotent.
- Class-S: first_settle uses commit_class_s_restore (witness rolled back on persist fail), finalize
  append-fail rolls witness back + re-stages slot via commit_class_s_keep. No state_mut escape.
- Send-discipline: seal task tokio::spawn'd; all awaits Send (compiler-enforced).
- Bounded(=1) outer channel: backpressure intended; slot already dropped at Commit-transition
  (supervisor.rs:6728) so backpressure doesn't hold the concurrency slot. No deadlock (seal only sends
  to B mailbox AFTER forward succeeds; off-mailbox so no re-entrancy).

## LOW / pre-existing pattern
- commit_b_stream_settle_finalize (saga.rs:879): if persist-1 (witness durable) OK, OutletInvoked
  append fails, AND rollback persist-2 (KEEP) fails, then crash before coalesce retry → durable witness
  present but no OutletInvoked event + hold reversed (seal Err → drop ticket). Recovery resolves
  Committed on witness, missing B-side dual-log leaf + un-billed service. Narrow multi-failure window;
  mirrors unary commit_b_settle_finalize design. Invoker-favorable direction.
