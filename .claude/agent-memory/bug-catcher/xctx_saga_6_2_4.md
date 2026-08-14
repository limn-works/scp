# §6.2.4 Cross-Context Tool Invocation Saga (feat/actor-2c-6.2.4-xctx-saga)

## Architecture
- Prepare-A (caller actor): persists velocity/budget/hard-rate-limit deductions into PerContextState (durable), returns `PreparedAFields`/`ToolEconomyReservation` (RAII `#[must_use]` ticket) held ONLY in supervisor in-memory `ctx.prepared_a`. External escrow held by payment adapter. NOTHING staged into caller `saga_pending`.
- Prepare-B (target actor): stages `CrossContextToolInvocationPrepared` into `saga_pending`; records nonce in `xctx_nonce_dedup`.
- Ticket safety: caller-side Commit-A + Abort use `send_recover_on_failure` (handle.rs) which reserves mailbox slot BEFORE building command, returns un-delivered command on send failure for ticket recovery. Sound.
- Abort persist: `local_rollback_ran || had_slot` → persist; skip only on no-op mismatch+no-slot. Correct.
- NonceDedup TTL: SAGA_NONCE_DEDUP_TTL_SECS = 600s, strictly > skew (300s) per BLACK-XCTX-01. Seeded at all 3 prod construction sites + debug_assert. Correct.
- Commit-A/Commit-B: witness+persist BEFORE event-log append (no orphan on persist-failure-retry). Correct.

## FINDING (HIGH): PreparingB crash recovery never refunds caller Prepare-A deductions/escrow
- run_saga_fsm journals PreparingB (seq 2) AFTER Prepare-A persisted caller deductions + holds external escrow.
- Crash after PreparingB journal → recover_saga_entry PreparingB arm → redrive_xctx_prepare_in_progress sends Abort(reservation=None) to caller actor.
- abort handler with reservation=None: local_rollback_ran=false; had_slot=false (caller has NO saga_pending slot — only target does). → clean no-op, NO refund, NO external escrow void.
- Result: durable over-charge of caller velocity/budget/hard-rate-limit + leaked external escrow on a path that is supposed to be a CLEAN abort (not NeedsRepair/operator).
- Contrast live path: abort_xctx_participants takes ctx.prepared_a (carrier still in mem) → Abort(Some) → refund+persist. Crash lost the carrier; evidence (CrossContextToolInvocationPrepared) carries provenance NOT the ticket; no saga-keyed durable caller reservation record exists.
- Fix: Prepare-A must record a durable saga-keyed refund descriptor on the caller actor (escrow handle + velocity/budget/hard-rate-limit token amounts) so Abort(None) can reverse it; OR evidence-based recovery must reconstruct and drive a real refund. Same invariant the abort doc (lines 1607-1610) protects in the live path.
