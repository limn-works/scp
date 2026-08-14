---
name: saga-code-1911-threading-review
description: Review of #1911 — thread SCP-SAGA-* codes structurally through saga FSM, delete saga_code_from_message string-parse
metadata:
  type: project
---

# #1911 saga-code structural threading — COMPLETE

Worktree pr saga-code-1911 @35be7185f; 4 files (scp-runtime only, ZERO ffi/bindings — confirmed name-only). Three-dot diff.

**Verdict: COMPLETE.** All 20 Prepare-axis reject sites carry structural code via `saga_reject!` macro (embeds code + `SCP-SAGA-{code}:` prefix from ONE literal). Supervisor-axis 13051/52/53; actor prepare_a 13010/11/23/24; prepare_b 13012/13/14/15/16/17/18/19/20/21/25/26/27. `saga_code_from_message` fully deleted (grep crates/ = 0: fn + doc + its unit test gone).

Mailbox protocol wired end-to-end: SagaPhaseMessage::PrepareA/B reply → `Result<PrepareAOutcome/PrepareBOutcome, ContextError>`; actor handlers reply `Ok(Rejected(SagaReject))` on SUCCESS channel (policy reject) vs `Err(ContextError)` (codeless infra); dispatch_xctx_prepare_a/_b match Prepared/Rejected; run_saga_fsm returns `Result<(),SagaReject>`; run_saga Err arm builds `RunSagaError{error:rej.error, needs_repair, saga_code:rej.code}`; lift_run_saga_error reads `saga_code.unwrap_or(13067)` (no parse). `From<ContextError> for SagaReject` (code None→13067) used ONLY by `?` infra paths (timeout, journal, commit-exhaustion, resolve). RunSagaError gained saga_code; all 10 constructions (1 prod + 9 test) set it. No stale `Result<PreparedAFields/BFields,ContextError>` reply shapes remain. misrouted<T> generic — works for both outcome types.

Tests pass: 45 saga.rs + 4 lift. New mutation-resistant `lift_reads_saga_code_structurally_not_from_message` (message embeds bogus 99999, structural 13013 wins; None+13050-message→13067).

**Non-regression verified:** Commit-axis codes 13030-13064 + NeedsRepair/Busy 13065/66 NOT Prepare-axis — out of scope, untouched. Commit failures always route through reached_needs_repair→13065 (lift short-circuits on needs_repair before reading code), in BOTH old and new code — so deleting the message-parse does NOT downgrade commit codes. 13050 caller-membership gate constructs `SagaError::Aborted{code:13050}` directly at public boundary BEFORE FSM (never via RunSagaError/lift) — correctly untouched.

**Observation (NOT a #1911 gap):** 4 converted Prepare-B codes 13012/13015/13016/13021 have ZERO test coverage (1 occurrence each = reject site only, on main AND HEAD). Pre-existing gap; reject sites ARE correctly wired with structural code; PR's own ~14-test criterion met exactly. Worth a follow-up to backfill structural-code asserts, but does not make this change incomplete.
