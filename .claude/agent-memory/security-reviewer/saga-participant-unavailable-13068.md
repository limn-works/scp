# Saga ParticipantUnavailable / 13068 relabel (fix/121, HEAD 124f890eb) -- 2026-06-30 -- CLEAN

Review of cumulative diff `5a67b771d..HEAD` on branch `fix/121-mailbox-saturated-saga-terminal`.
Change: Prepare-phase `ContextError::ActorBusy` lifts to retryable
`SagaAbortReason::ParticipantUnavailable` + code `SCP-SAGA-13068` (was `_ => Rejected` /
`unwrap_or(13067)`). §6.2.4 cross-context tool-invocation saga. NO security findings.

## Why it's safe (evidence, supervisor.rs unless noted)
- **No budget bypass.** Anti-griefing budget consumed at INITIATION, NOT refunded on this abort.
  run_saga tail drains Prepare-A reservation via `void_external_and_consume` (5497-5508) →
  tools_helpers.rs:259-263 voids ONLY external payment escrow (nothing committed), sets
  `needs_hard_rate_limit_refund=false`. Hard-rate-limit budget stays consumed
  (tools_helpers.rs:302-318 "initiation consumes budget, no terminal refunds it"). Retries are
  budget-gated + self-limiting. Relabel is post-hoc in lift AFTER run_saga returns (5652-5654);
  never touches economy path. Attacker gains nothing (could already loop-invoke); only honest-
  caller behavior changes.
- **No new oracle.** message = error.to_string() computed once (5694), byte-identical across all
  arms; only reason+code reclassified (5713-5727). ActorBusy arm reachable ONLY after BOTH
  authorize-before-reserve gates pass: is_member (5533, rej 13050) + has_established_tool_interface
  (5557, rej 13062), both BEFORE reservation. Such a caller already holds approved interface →
  already knows target exists. 13068 leaks nothing new.
- **No infinite retry.** Self-limited by per-retry budget + conservative None back-off (never
  Some(0), saga_errors.rs:114-120). Retry re-enters entry fn → re-runs BOTH gates + re-reserves +
  re-charges Prepare-A: fully-gated fresh saga, no auth fast-path.
- **No code fabrication.** 13068 only in structural `ContextError::ActorBusy(_)=>` arm (5714),
  grep-unique, registered sdk-common.md:118 + ADR-049:91 in gated 13000-13999 band. §3a overlap
  ActorBusy intercepted as Busy/13066 at 5638-5645 BEFORE run_saga (never reaches lift).
  needs_repair short-circuit (5695-5697) BEFORE reason match → commit-phase ActorBusy →
  NeedsRepair, never mislabeled retryable (test pins it). ActorBusy carries no saga_code (not a
  saga_reject! site) so forcing 13068 overrides nothing.

## Observations (non-blocking)
- Retryability lives in numeric CODE not in SagaErrorKind: both ParticipantUnavailable AND Rejected
  decompose to identical `Aborted{retry_after_ms:None}` (saga_errors.rs:117-118). Consumer must
  compare code string 13068 vs 13067. Availability footgun, not security (conservative default =
  treat as non-retryable if code ignored). Recurring pattern (also prior 13068 saga review).
- Escrow-void-on-abort refunds external payment but NOT anti-griefing budget = correct + pre-existing,
  unchanged here.

## GOTCHA (cost me time)
Bash cwd = worktree saga-121 (relative paths grep the worktree). But Read with absolute
`/Users/alec/Developer/limn/scp/crates/...` reads the MAIN worktree (different HEAD → line numbers
diverge ~200 lines). ALWAYS Read via the worktree path
`/Users/alec/Developer/limn/scp/.claude/worktrees/saga-121/crates/...`.
