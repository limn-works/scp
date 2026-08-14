# §6.2.4 Cross-Context Tool-Invocation Saga — bug-catcher findings (Jun 2026, branch feat/actor-2c-6.2.4-xctx-saga)

Files: crates/scp-runtime/src/context/actor/handlers/saga.rs (3040L), supervisor/supervisor.rs (saga FSM),
actor/handle.rs (send/send_recover_on_failure), tools_helpers.rs (ToolEconomyTicket/Reservation Drop guards).

## HIGH — abort_xctx_participants caller-side uses plain `send`, leaks/panics ticket on send failure
supervisor.rs:6601. abort_xctx_participants moves the Prepare-A reservation (PreparedAFields → ToolEconomyReservation
→ ToolEconomyTicket, consumed=false, #[must_use] Drop guard that debug_assert!(false) under --features testing) into
a boxed CommitA... no, Abort command, then sends via plain `caller.send()`. On a full/closed mailbox, handle.rs::send
(lines 130-143) DROPS the built command (and the ticket) — unbalanced → debug_assert panic in CI, escrow leak in
release. This is the EXACT bug class commit_a_settle was fixed for (it uses send_recover_on_failure). Fix: use
send_recover_on_failure in abort_xctx_participants and on send failure extract+void_external_and_consume the ticket.

## HIGH — abort() + commit_a() replay branch call rollback_tool_economy directly (no generation check)
saga.rs:1395 (abort handler), saga.rs:1291 (commit_a idempotency-replay branch). Both call rollback_tool_economy()
which unconditionally writes velocity_tracker.rollback / budget_tracker.reverse_spend / hard_rate_limit.refund to THIS
actor's state — with NO generation check. The happy-path commit_a settle uses settle_tool_economy (tools_helpers.rs:970)
which rejects on generation mismatch and only voids EXTERNAL escrow. Actors can crash+respawn mid-saga (respawn budget
path is independent of the saga context-set gating reservation, which only serializes overlapping sagas). A respawn
between Prepare-A and the abort/replayed-CommitA lands the old-gen reservation on a new-gen instance → confused-deputy
refund to WRONG context instance. This is exactly what `generation` was introduced to prevent (ToolEconomyReservation
field doc, tools_helpers.rs:310-317). Fix: route abort/replay rollbacks through a generation-checked helper.

## MEDIUM — Commit-B persist-retry double-appends ToolInvoked (idempotency claim false on retry)
saga.rs:1146 (commit_b_first_settle append) + provider event_log.rs:755 (plain unconditional append, no event-id dedup).
Sequence: first settle appends ToolInvoked(N) → insert capture → persist_state_fail_closed FAILS → rollback removes
capture + re-inserts staged slot (but event-log append is a SEPARATE provider, NOT rolled back). FSM retries Commit
→ reserve sees staged slot, no capture → ReadyToExecute → commit_b_first_execute re-sends settle with stashed output
(no re-invoke ✓) → commit_b_first_settle re-appends ToolInvoked(N+1) DUPLICATE. Doc at saga.rs:1133-1134 claims the
SagaId-stable event id makes the append idempotent — TRUE only for the AlreadyCommitted short-circuit, FALSE on the
persist-failure retry. Commit-A is SAFE (its retry goes through witness path, not re-append). Fix: make the append
idempotent by event-id at the provider, OR append AFTER the capture+persist lands (reorder so a persist failure never
leaves an orphan ToolInvoked).

## MEDIUM — crash-recovery NeedsRepair (one-sided commit) emits no divergence marker / no supervisor repair record
supervisor.rs:5293-5311 recover_committing_entry NeedsRepair arm. When redrive_commit_a_witness returns Ok(false)
(B committed, A witness absent = genuine one-sided commit / repudiation case), the recovery path only appends a
NeedsRepair journal entry — it does NOT emit CrossContextDivergenceMarkers (no signing keys post-crash; they're
per-call from the live initiator) and does NOT write saga_repair_records. §6.2.4 "Dual event-log recording" mandates
durable audit of one-sided commits. Likely best-achievable post-crash (keys gone), but the supervisor repair journal
SHOULD at least record it. Weaker audit guarantee than the live FSM path. Flag for design confirmation.

## VERIFIED CORRECT (no bug)
- handle.rs send_recover_on_failure: reserve()-then-permit.send() is cancel-safe; never strands a built command. Good.
- Class-S snapshot round-trip: saga_pending/xctx_committed_outputs/xctx_committed_invocations/xctx_nonce_dedup all
  snapshot (messaging_helpers.rs:2122-2126) + rehydrate (lifecycle_helpers.rs:2272-2299) + cross-node export/import
  DROPS them (export_import.rs:824-829,1017-1022). NonceDedup from_entries/entries round-trip sound.
- commit_a_settle witness re-drive: reservation-present → send_recover_on_failure (recovers ticket on send fail);
  prepared_a==None → witness path (no false NeedsRepair). Idempotent, ticket-safe. Good.
- divergence_marker_plan committed_side=Target only when committed_b_tool_invoked_event_id.is_some(). Correct (B-before-A).
- No &PerContextState held across .await in saga handlers (commit_b_first_settle + emit_divergence_marker are sync fns).
- NeedsRepair escrow held (hold_external_for_repair, not voided) — run_saga tail reached_needs_repair branch. Correct.
