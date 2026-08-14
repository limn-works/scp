# SCP-121: Prepare-phase ActorBusy -> ParticipantUnavailable (SCP-SAGA-13068)

Branch `fix/121-mailbox-saturated-saga-terminal`, tip a32f3a723 (review base 5a67b771d, 6 commits). CLEAN review.

## What the change does
`lift_run_saga_error` (supervisor.rs ~5690): transient Prepare-phase `ContextError::ActorBusy`
now maps to fieldless unit `SagaAbortReason::ParticipantUnavailable` + code 13068, instead of
`Aborted{Rejected,13067}`. Hoisted `fallback_code = saga_code.unwrap_or(13067)`; match order:
needs_repair short-circuit -> ActorBusy(_)=>(ParticipantUnavailable,13068) -> RateLimited(fallback)
-> _=>(Rejected,fallback). FFI decompose fold: `ParticipantUnavailable | Rejected => None` (exhaustive,
no wildcard, closed). Was MailboxSaturated, renamed to ParticipantUnavailable in commit 124f890eb (rename complete, zero leftovers).

## Why it's correct (verified)
- Scoping: ActorBusy reaching the lift with needs_repair==false comes ONLY from Prepare-phase mailbox
  sends (dispatch_xctx_prepare_a/b via handle.send). All 3 ActorBusy constructions live in
  actor/handle.rs send paths (closed inbox / full-30s / dropped reply) — none in actor handlers. All transient.
- Commit-phase ActorBusy: FSM Err(commit) arm ALWAYS sets reached_needs_repair=true (xctx always Some
  for xctx saga) -> lift short-circuits to NeedsRepair. Guard test pins ordering.
- SagaBusy participant-set overlap: mapped to SagaError::Busy in start_cross_context...saga BEFORE the
  lift (try_reserve_context_set). Never reaches the ActorBusy arm.
- fallback_code preserves prior code exactly for RateLimited/Rejected/coded rejects (test asserts 13023/13013/13067).
- ActorBusy ignoring saga_code (always 13068) is safe: no coded ActorBusy reject exists (saga_reject! has
  only single-String + RateLimited forms; grep confirms no ActorBusy site). All saga-path ActorBusy is codeless (From<ContextError>, code=None).
- 13068 unique, within registered 13000-13999 band. Spec §06 + ADR-049 §91 + sdk-common.md registry row all aligned (artifact flow honored).
- Integration test determinism: closed channel (dropped rx) -> send returns immediately Ok(Err(closed)),
  NO 30s wait. Caller stays live (gates+Prepare-A pass), target handle overwritten with dead handle in
  supervisor.actors; lookup clones it; clone shares closed Sender. No hang/flake.
- SDK binding diffs (py/ts/swift/kt) are DOC-COMMENT ONLY (no signature/behavior change).

## Documented-not-bug limitation
SEND_TIMEOUT(30s) == PHASE_TIMEOUT(30s): a transiently-FULL-but-open mailbox may surface as generic
Prepare TransportTimeout (Rejected/13067) instead of 13068. Pre-existing, honestly documented on the
variant rustdoc + spec, follow-ups #1967 (retryability signal) + #1968 (timeout race). Both outcomes are
clean "neither side committed" aborts; only the retryability hint differs.

## ENV GOTCHA
Worktree `.claude/worktrees/saga-121` was checked out at DETACHED HEAD 1620de983 (main tip), NOT the
branch tip a32f3a723 the prompt named. `git diff 5a67b771d HEAD` was polluted by unrelated main commits
(falsely showed Kotlin toolInvokeCrossContextSaga removal). Correct diff = `git diff 5a67b771d a32f3a723`.
Plain `grep` of working tree also misleads — use `git grep <sha>` / `git show <sha>:path`. ALWAYS rev-parse HEAD first.
