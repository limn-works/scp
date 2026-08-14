# classs-fin-last — ClassSCell state_mut elimination refactor (ADR-049 §9)

Pure refactor narrowing last `state_mut()` callers onto field-granular `ClassCMut` views. Parent f36b09462. Reviewed full `git diff` + verified against source.

## Finding (LOW) — gate-reorder error-precedence change — FIXED (re-review Jun 2026)
RESOLVED: current diff restores legacy order. `require_active` + `check_commit_fault_marker`
now run in a dedicated `{}` block (msg_helpers.rs ~872-877) BEFORE the signer-None match
(~887-897). Comment explicitly documents "matching the legacy ordering". No precedence flip remains.

ORIGINAL finding (now historical):
`send_message` moved `require_active` + `check_commit_fault_marker` from BEFORE the
signer-None check to AFTER it (they now live inside the `velocity_token` view block;
the signer `let signer = match signing_key {...}` precedes that block).
- OLD order: require_active → check_commit_fault → signer-None → capability → hard_rate_limit.
- NEW order: signer-None → require_active → check_commit_fault → capability → hard_rate_limit.
- Observable ONLY on a doubly-invalid call (signing_key=None AND closed/faulted ctx):
  error flips from ContextClosed/CommitBroadcastFault → CryptoFailed("signing key required for send").
- All three are pure non-mutating early-return gates (no state write), so NO
  state-ordering/aliasing change — purely which Err wins. No test pins it.
- Pattern: re-bucketing independent early-return gates into a different lexical block
  silently reorders error precedence. Prompt said "NO behavior should change" → flag.

## Verified equivalent (no bug)
- `split_class_c()` == `ConsequenceStateSplit::from_state(state)`: both build the same
  5-field `ClassCSplit` (governance ClassC view, role_state &mut, membership &,
  receive_buffer &mut, checkpoint_events_since &mut). ConsequenceStateSplit is a type alias.
- `RoleStateClassCMut::member_has_capability` is char-for-char `ContextRoleState::member_has_capability`
  (suspension check first→false, then member_capabilities). View aliases real fields.
- `try_broadcast_commit_or_enqueue`: `emit(state,...)` inlined to
  `emit_event_into(receive_buffer,...,deps.event_tx.as_ref())` — `emit` IS exactly that.
  CommitBroadcastBorrows carries the 3 disjoint fields it touches; semantics identical.
- `rollback_economy_ticket_inline_view` reverses same 3 governance fields (velocity, hard_rate_limit
  refund-if-flagged, budget reverse-if-cost) as old inline `rollback_economy_ticket_inline(&mut state.governance)`.
- `create_checkpoint_if_due_view` == `create_checkpoint_if_due` (50-event / 600s / events>0 gates,
  reset 0/now, push+drain MAX_RETAINED_CHECKPOINTS). Reads counters into locals before build; no interleave.
- `compare_remote_checkpoint(view)` == `compare_remote_checkpoint_bare`: bare's
  `record_equivocation_if_fresh` is literally `if divergence_is_fresh {emit_equivocation_alert}`.
- capture split: new inlines `surface_paid_action_receipt` = `emit_payment_received_event` then
  `record_payment_receipt`; error path only from `capture_and_verify_paid_action` — same as old `complete_paid_action`.
- authorize split: `authorize_send_payment_prepare`(→prepare) + `authorize_paid_action_hold` ==
  old `authorize_paid_action` (prepare-None→Ok(None)→auth=None). prepare reads only governance/membership.

## Fail-closed token (CRITICAL invariant) — CLEAN
ClassSCommitToken has Drop guard `debug_assert!(false)` on unconsumed drop. All 8 send_message
terminal paths commit-or-take the token: pre-economy gates return before token exists; enforce_send_economy
Err arm issued no token; 3 discharge_send_abort + lone-member no-op + authorize-hold-err + phase2-err all
`.take()`+commit; finalize_send receives `.take()` and owns its commit via persist_finalized_send.
Order preserved: nonce persist FIRST (keep-direction) THEN Class-C economy reversal.

## Sequence rollback — no double-revert (CLEAN)
finalize_send owns sequence rollback on its error exits (require_active-fail + persist_finalized_send
token-commit-fail, both gated `!is_broadcast`). send_message's finalize-error handler rolls back ONLY
the economy ticket (+void escrow), NOT the sequence — matches the documented round-5 regression fix.
PseudonymRegistryEmpty rolls its OWN reserved sequence before discharge_send_abort (which is sequence-agnostic).

## Deliver cascade — CLEAN
handle_deliver_incoming switched from cell.state_mut() to cell.class_c_view(); deliver_incoming is sync,
wrapped in timeout (pre-existing, can't fire mid-poll). Persist still driven by run loop on Outcome::ok_mutated.
Compiles clean (`cargo check -p scp-runtime --features testing`).
