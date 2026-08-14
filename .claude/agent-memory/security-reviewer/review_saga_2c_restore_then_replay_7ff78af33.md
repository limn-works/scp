# §17.16.4 restore-then-replay recovery reorder — CLEAN (fix re-review)

worktree saga-2c, branch feat/2c-saga-dispatch, HEAD 7ff78af33 (Phase 2D / ADR-049).
Re-review of the fix for a prior HIGH (durable caller over-charge) + MEDIUM (error-code band).
VERDICT: CLEAN, zero findings any severity. Both prior findings correctly closed, no new vuln.

## What changed
- `Supervisor::restore_on_startup` (supervisor.rs:7909-7913) REORDERED from replay-before-restore
  to RESTORE-THEN-REPLAY: `restore_all_contexts().await?` (fail-closed `?`) THEN
  `replay_unresolved_sagas().await?`. Crashed xctx caller is now RESIDENT when its record-keyed
  reversal is driven → refund delivered, entry terminal-Aborted. Prior order missed the
  not-yet-resident caller → ReversalOutstanding → non-terminal "for a later sweep that doesn't
  exist" (replay called once, replay-first) → permanent over-charge + escrow leak.
- Spec §17.16.4 (17-persistence-and-storage.md) amended FIRST (artifact-flow) to restore-then-replay.
- Error codes SCP-SAGA-13003/4/5 → 13100/1/2, new 13100-13199 broadcast-hosting sub-block in
  sdk-common.md (reserved moved to 13200-13999), 3 rows registered. hosting_handshake.rs:75/79/87.

## Why CLEAN (the 4 verification axes)
1. ECONOMIC INTEGRITY / no new authz: recovery is purely COMPENSATING (Abort{None}/refund), never
   grants authority. Live RAII guard died with crash → record-keyed reversal idempotent (consumes
   durable CallerReservationRecord exactly once, no-op if drained). Restoring first only makes caller
   resident so refund lands. No double-spend path. New unit gate
   restore_on_startup_xctx_caller_reversal_delivered_entry_terminal proves token refunded to full
   burst + record consumed (red-hat PoC inverted).
2. FAIL-CLOSED: restore `?` short-circuits before any saga touched; orphan stays unresolved, carried
   to next process start. Integration test restore_on_startup_fails_closed_when_restore_leg_errors
   pins post.len()==1 + PersistenceFailed surfaces.
3. CONSERVATIVE REAP: caller_context_deleted_from_persistence (supervisor.rs:5936) reaps ONLY on
   Ok(None) (confirmed absent); Err(_) → treated still-present (false, logged), no backend → false.
   Never reaps on a guess → never strands AND never falsely-terminal. Spec text agrees.
4. SIGNING UNCHANGED: hosting_handshake diff = error-code strings + doc-comments only; every
   h.update() preimage call + test vector byte-identical. 26 tests pass incl tamper-each-field.
   New `# Verification scope` doc-comments = DEFENSIVE (verify is sig-only; caller must
   validate/clamp + Prepare-B lifetime ceiling — closes over-trust confused-deputy footgun).

## Gate hardening (additive, permitted enforcement-file expansion)
- extract_fn_body (scp-testing pipeline_wiring.rs:184-258) now blanks //-comment text + string-literal
  CONTENTS (order-preserving, delimiters kept) so contains()/find() can't false-pass on commented/
  stringized tokens. Ordering assertion flipped to restore_pos<replay_pos. Governance forgery
  assertion rebound from blanked error-string "not tracked" to code construct
  (get_proposal(proposal_id)+ok_or_else+PermissionDenied). Escape handling (prev_char!='\\') intact;
  final break on non-string } so escape state irrelevant there.
- FFI bridge_instance.rs: genuine recovery faults → warn, expected ephemeral NotInitialized/
  PersistenceFailed no-ops → debug. error=%e is server-side operator tracing, NOT remote-surfaced =
  not a leak. Catch-all still logs-and-continues (best-effort rehydration).

## Verified live
scp-runtime lib 1921 pass (incl both new gates); pipeline_wiring 2 pass (ordering+bridge-routing);
hosting_handshake 26 pass; check-error-codes.sh PASSED (2300 occ); grep SCP-SAGA-13003/4/5 = 0
dangling; RawBytes16 in hosting_handshake = 0 (remaining hits in cross_context_saga.rs = different
untouched file, own convention).
