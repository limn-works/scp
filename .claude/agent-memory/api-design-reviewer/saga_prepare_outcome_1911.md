---
name: saga-prepare-outcome-1911
description: Saga actor reply-payload convention — ...Outcome enum + ...Reply channel-alias; structural SagaReject code carriage replacing string parse (#1911)
metadata:
  type: project
---

Issue #1911 (saga-code worktree) reshaped §6.2.4 cross-context-tool saga FSM internal reply types in `crates/scp-runtime/src/context/actor/`.

**Established convention for actor saga-phase reply payloads (commands.rs):**
- Each phase defines a `...Outcome` payload type (enum or struct) carried on the mailbox SUCCESS channel.
- The mailbox `send` reply channel is HARDCODED `oneshot::Sender<Result<T, ContextError>>` — a fixed constraint. So a policy reject that needs to carry structured data rides the `Ok` channel as a typed variant, NOT `Err`.
- Commit phases factor the channel into a named alias: `CommitBReserveReply = oneshot::Sender<Result<CommitBReserveOutcome, ContextError>>` and reference it in the `SagaPhaseMessage` variant. The Prepare phases (added in #1911) did NOT add `PrepareAReply`/`PrepareBReply` aliases — they repeat the full `oneshot::Sender<Result<PrepareAOutcome, ContextError>>` inline in the variant + handler signature. Minor consistency/DRY gap; the alias pattern is the sibling norm.

**SagaReject design (the substance of #1911):** `SagaReject { code: Option<u16>, error: ContextError }` carries the canonical `SCP-SAGA-13xxx` discriminant STRUCTURALLY off the reject path, replacing the deleted `saga_code_from_message` string parser. `code: None` (set by `From<ContextError>`) = codeless infra failure → lifts to generic `13067`. The `saga_reject!` macro (2 arms: single-String tuple variant + RateLimited struct variant) single-sources the code literal into BOTH `code: Some($code)` and the `SCP-SAGA-{code}:` message prefix so they cannot drift. Message prefix is now NON-load-bearing (lift reads `code` structurally), so a divergent prefix is cosmetic, not a correctness bug.

**Settled, do NOT re-flag (per #1962 follow-up):** the `From<ContextError> for SagaReject` impl (codeless()-constructor alternative judged a lateral trade) and the typed-`SagaRejectCode`-enum-instead-of-`Option<u16>` idea. Both recorded as future considerations.

Verdict was APPROVED — structural carriage is strictly better than string parsing and aligns with the agent-first/structural-data tenet.
