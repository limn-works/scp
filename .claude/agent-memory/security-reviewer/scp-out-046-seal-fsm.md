# SCP-OUT-046 Streaming-Saga Seal FSM — Security Review (2026-07-15)

Branch `feat/outlet-xctx-046-seal-fsm` HEAD 18f6fd11c. Verdict: **NO BLOCKING
SECURITY ISSUES.** 1 MEDIUM robustness observation (fail-closed direction) + 1
minor defense-in-depth note.

Key files: actor/handlers/saga.rs (prepare_b_streaming 2137, stream_capture_append
2276, commit_b_stream_settle 2420, commit_b_stream_first_settle 2510, finalize 2702,
build_signed_stream_receipt 2806), outlets/invoke.rs (verify_forwarded_chunk 4233,
run_streaming_saga_seal_task 4914), supervisor/supervisor.rs (streaming driver
6329, recover_streaming_saga_truncated_close 6818, recover_streaming_committing_entry
7779, settle_outlet_stream_via_actor 11837).

## CLEAN (verified)
- **Signing key never persisted.** SigningKeyBytes = `zeroize::Zeroizing<[u8;32]>`
  (commands.rs:614); ed25519-dalek has `zeroize` feature (root Cargo.toml:41) so
  reconstructed SigningKey zeroizes on drop. Durable structs
  CommittedStreamingOutletInvocation (saga_prepared_state.rs:697) and
  CrossContextStreamingOutletInvocationPrepared (:315) carry NO key field
  (field-by-field checked). Key lives only in transient CommitBStreamSettle msg +
  seal-task memory. No key in logs/errors (grep of new + tracing lines empty).
  ContextCommand / SagaPhaseMessage do NOT derive Debug → no {:?} byte leak.
- **Fail-closed keyless recovery.** recover_streaming_committing_entry: witness
  absent → NeedsRepair + escrow HELD (never voided/settled). Send-error /
  actor-not-resident default to false → NeedsRepair. Honest-absent, not a
  nullifier. Aligned w/ §6.2.4 anti-free-execution (memory #1970).
- **Authz gates.** Streaming driver runs is_member (gate1 13050) +
  has_established_outlet_interface (gate2 13062) BEFORE reserving; caveat_binding
  threaded through open_outlet_stream_phase1 → §7.3.8 counter CAS; caller_source_role
  resolved supervisor-side (not envelope-asserted).
- **Chunk verify-before-bill.** verify_forwarded_chunk (pinned descriptor:
  request_id + operator sig) at invoke.rs:4968 gates BEFORE forward_frame (5030)
  AND before StreamCaptureAppend fold (5048) which drives billing. Forged/foreign
  chunk → Authorization terminal, never folded/billed.
- **Replay idempotent.** xctx_committed_stream_outputs witness; replay reemits
  stored receipt verbatim (no re-sign) + settlement:None (no re-settle). Witness
  inserted before OutletInvoked append inside same commit_class_s_restore closure;
  append-failure rolls back witness + re-stages slot. Actor mailbox serializes →
  no TOCTOU. Recovery guards on witness.
- **Saga escrow separation.** Saga runs settlement_sink=None → dispatch.rs:2396
  guard skips persist_reservation → NO StreamReservationRecord → ReconcileStreamReservations
  restore-sweep never touches saga escrow → no double-refund. Saga's own durable
  prepared slot is sole settlement source.

## MEDIUM observation (fail-closed direction — over-hold, not under-charge)
Settlement application is OFF-mailbox AFTER the seal commits (witness present).
If settle_outlet_stream_via_actor fails OR is dropped by the confused-deputy
generation guard (normal seal task passes RESERVE-time generation; a B respawn
between escrow-reserve and seal → generation mismatch → settlement DROPPED), the
refund/counter-release is not applied and NOT reconciled: witness-present makes
recover_streaming_committing_entry resolve Committed without re-settling, and the
saga path writes no StreamReservationRecord so ReconcileStreamReservations no-ops.
The reassuring log ("crash-recovery sweep reconciles the durable reserve",
invoke.rs ~5175) overstates the net for the saga path. Blast radius: invoker's
unspent `refund` stranded/over-held. Direction is fail-closed (never under-charge,
never free execution, never key leak). Robustness/money-correctness, not auth/inj/secrets.

## Minor: SigningKeyBytes has no custom redacting Debug (relies on no enclosing
enum deriving Debug). Pre-existing (predates this diff, shared w/ SendMessage).
Defense-in-depth: add redacting Debug to be robust vs a future derive.
