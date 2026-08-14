# SCP-SAGA-13068 MailboxSaturated retryable terminal (#121, commit 693d94a1c)

Reviewed 2026-06-30, branch fix/121-mailbox-saturated-saga-terminal. Light security
review of mapping Prepare-phase `ContextError::ActorBusy` -> retryable
`SagaAbortReason::MailboxSaturated`/code 13068 (was generic Rejected/13067).
VERDICT: no security findings; one minor observation.

Key facts verified in `crates/scp-runtime/.../supervisor/supervisor.rs`:
- §3a per-participant-context-set overlap is resolved BEFORE `run_saga`: generic
  `start_saga` maps reservation reject to raw `ContextError::ActorBusy` (line ~5402,
  returns `?`); cross-context entry maps it to `SagaError::Busy` (line ~5637, returns
  `?`). Neither reaches `lift_run_saga_error`. So the ONLY ActorBusy that reaches the
  new 13068 arm is a genuine participant-actor mailbox send failure (full/closed) in
  Prepare. The synthesized `actor_busy` in `try_reserve_context_set` (~5910) is a
  SagaReserveReject field, never fed to the lift on the xctx path.
- Commit-phase ActorBusy CANNOT reach the 13068 arm: `commit_with_retry` Err arm
  sets `reached_needs_repair = true` (~7003) -> `needs_repair` short-circuit (~5699)
  -> NeedsRepair/13065. So "retryable" never lands on a partially-committed saga ->
  no once-only-tool double-execution via retry. This is the load-bearing safety claim
  and it holds.
- Budget accounting is reason-agnostic: Prepare-A escrow void/refund happens in
  `run_saga` tail (~5809 void_external_and_consume) regardless of final label; the
  label is applied post-hoc in the lift. MailboxSaturated does NOT create a
  budget-bypassing free retry — each retry is a fresh initiation re-consuming the
  anti-griefing per-caller budget. No DoS amplification beyond pre-existing
  RateLimited{None} behavior; retry_after_ms is None never Some(0) (no tight loop).
- Info-disclosure parity: 13068 only observable to a caller that passed gate1
  `is_member` (~5531) + gate2 `has_established_tool_interface` (~5555), both BEFORE
  reservation/Prepare-B. Target-mailbox liveness signal is bounded to an
  already-authorized counterparty — same prerequisite as 13062/13050/13053. Closed
  inbox and full inbox both map to 13068 (conflated) — REDUCES oracle granularity
  (good).
- 13068 unique (13050-13062 specific rejects, 13065 repair, 13066 busy, 13067
  fallback). Structural variant match, never synthesized for non-ActorBusy.
  `decompose_saga_error` reason match is exhaustive (no wildcard) -> future reasons
  force a compile error.

OBSERVATION (not a vuln): a permanently-closed/terminated target maps to retryable
13068; if the established-interface record lingers, an authorized caller can
self-fund a bounded retry loop until interface teardown yields a permanent reject.
Self-limiting + caller-funded; conservative None back-off. Acknowledged in commit.
