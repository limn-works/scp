# §6.2.4 xctx saga FINAL CERT wave-25 (HEAD 11fe5ecba) — CLEAN, no exploitable break, gate honest

Branch feat/actor-2c-6.2.4-xctx-saga. Diff base origin/main. Isolated worktree xctx-blackhat (detached).

## SCOPE NARROWING (key fact)
- `crates/scp-protocol/.../cross_context_saga.rs` AND `crates/scp-runtime/.../actor/handlers/saga.rs`
  are UNCHANGED since wave-15 base 6b7c8b658 (git diff 6b7c8b658..11fe5ecba = 0 lines each).
  ALL prior certifications of those files (receipt-forgery resistance, exactly-once, confused-deputy,
  abort economic single-consume record, replay/nonce-dedup) HOLD VERBATIM — see xctx_saga_6_2_4*.md,
  xctx_saga_abort_economic_path.md.
- Waves 16-25 touched ONLY supervisor.rs (crash recovery) + scripts/check-class-s-fail-closed.sh.

## ECONOMIC SURFACE (A) — RESISTS. No exploitable break.
- WAVE-23 FIX (the real new econ surface): `recover_saga_entry` split `Initiated | PreparingA`.
  - `Initiated` arm: marks terminal-Aborted unconditionally. SAFE — FSM journals Initiated(seq0,6146)
    BEFORE PreparingA append(seq1,6154) BEFORE dispatch_prepare_phase(A); Prepare-A durable deduction
    only runs after seq1, so an Initiated-latest journal can have NO durable record. Correct.
  - `PreparingA` arm: NOW routes to `recover_preparing_b_entry` (was unconditional-Aborted = permanent
    over-charge). Prepare-A durably stages caller deduction + CallerReservationRecord between seq1 and
    the PreparingB append(seq2,6185). PreparingA evidence is ALWAYS &[] (only prod append site 6154
    uses &[]), so reconstruct_xctx_prepared→None → participant-keyed redrive_caller_local_reversal.
    Resident caller + record ⇒ Abort{None} reverses LOCAL from record + consumes record, persist-before-
    ack, THEN terminal-Aborted. Non-resident/persist-fail ⇒ ReversalOutstanding ⇒ left NON-terminal for
    next-startup sweep. Deleted caller ⇒ reaped terminal (record died w/ snapshot). Tests pass.
  - Crash-window where PreparingA journaled but Prepare-A NOT yet durably staged: redrive sends
    Abort{None} to resident actor, handler finds no record → (false,false) no-op → Ok ⇒ SettledOrAbsent
    ⇒ terminal-Aborted. Correct (nothing deducted).
- PERSIST-FAIL DIVERGENCE probed: actor abort persist-fail at saga.rs:1886 leaves in-mem reversed but
  durable still deducted; returns Err ⇒ supervisor ReversalOutstanding ⇒ non-terminal. NO double-sweep
  within one live-actor lifetime exists in prod (replay_unresolved_sagas is STARTUP-ONLY, no periodic
  re-drive), so the in-mem divergence can't be falsely confirmed before a restart. Persist-before-ack
  honored. RESISTS.
- BROADCAST MISCLASSIFICATION (PreparingA spec-gapped Standing/Broadcast crash): broadcast participants
  `[hex(host),hex(broadcast),subscriber_did]` are len-3 + hex[0] ⇒ xctx_caller_hex_from_participants
  classifies as xctx ⇒ redrive Abort{None} vs host. HARMLESS: broadcast Prepare-A returns NotImplemented
  (stages nothing), so host has no record + no saga_pending[saga_id] ⇒ no-op ⇒ terminal-Aborted = CORRECT
  outcome for a spec-gapped saga. Doc-claim 5818-5824 holds.
- reverse_caller_reservation_record (tools_helpers.rs:360): single-consume keyed by record removal; no
  gen-gate on crash path (correct — respawn gen never matches pre-crash record). RESISTS.

## CLASS-S GATE (B) — HONEST + NON-WEAKENING. self-test + scan EXIT=0.
- Wave-25 header relabel is ACCURATE: explicitly "BEST-EFFORT DEFENSE-IN-DEPTH", "NOT exhaustive",
  autoref method-name CLASS-A residual "CONSCIOUSLY ACCEPTED", type-system guard = committed convergent
  fix. NOT a do-not-report per task.
- 5 CLAIMED-covered axes ALL verified HIT via real scan_file (isolated probes):
  (1) inline X.method(  (2) &mut<recv>.X borrow + deref &mut *state.X + paren &mut (*state).X +
  std::mem::take/replace/swap  (3) X: ref mut destructure (let/if-let/match)  (4) accessor body
  &mut self.X  (5) whole-state-alias s.X.insert(. Plus agnostic .ceiling= closes the wave-23 receiver-
  alias ceiling bypass (HIT). Bare-token markers (suspend_all(, threshold_value=) survive aliasing (HIT).
- NEGATIVE controls correct (no FP): &state.X read alias, X: ref shared, X: _ ignore, .ceiling() reader.
- NON-WEAKENING proven: real-tree tallies IDENTICAL wave-22 parent f29937089 vs HEAD
  (HIT2 GOVHIT0 GOVFN30 FC28 FNDEF1152 SCANNED61). Wave-23/24/25 strictly ADDED markers/fixtures.
- FALSIFIABLE proven: transiently deleting the agnostic `.ceiling=` marker ⇒ self-test FAILS with precise
  diagnostic. Not vacuous. Reverted; tree clean.
- Self-test fixtures (64-78+) each have a real `! grep -q '^HIT...fixture$'` (positive) or
  `grep -q` (negative) assertion. Genuinely consumed.

## VERDICT: No exploitable economic break. Gate honest + non-weakening. self-test=0, scan=0, tree clean.
Tests: 179 supervisor + 45 actor-saga + 2 wave-23 PreparingA recovery — all green.
