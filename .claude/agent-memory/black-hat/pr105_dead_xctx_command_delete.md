---
name: pr105-dead-xctx-command-delete
description: Review of commit 621933fe7 (chore/105-pr6a) deleting dead InitiateCrossContextToolInvocation command + reply_saga_deferred; SAFE, docs accurate
metadata:
  type: project
---

# Commit 621933fe7 — delete dead InitiateCrossContextToolInvocation + scrub docs

**Verdict: SAFE. Dead code provably dead. Docs accurate. No findings.**

Deletes `ToolsCommand::InitiateCrossContextToolInvocation` (NotImplemented mailbox
variant) + orphan `reply_saga_deferred` helper; scrubs ADR-049 + DEFERRED-commit-11
docs; re-exports `SagaSigningKeys` from supervisor/mod.rs.

## Why dead (proven)
- On main: variant appears 4× = 1 def + 3 match arms (all `{ reply, .. }` destructure,
  NONE construct). Zero construction sites repo-wide (rust/py/ts/swift/kt).
- `ToolsCommand` has NO `#[derive(Serialize/Deserialize)]` — in-memory mailbox enum,
  no serialized-by-index persistence risk.
- Post-delete: 0 refs to either symbol; scp-runtime lib compiles clean.

## Doc claims all TRUE
- (a) saga off-mailbox due to borrowed non-`'static` `SagaSigningKeys<'a>`
  (target/caller `&'a ed25519_dalek::SigningKey`, supervisor.rs:889) while executor
  F is `Send + 'static` (5316-17). Precise: the KEYS block it, not the executor.
- (b) `invoke_tool_with_economy` (9686): F/Fut have NO Send, NO 'static bound — distinct reason.
- (c) forward FSM DOES append journal: start_cross_context_tool_invocation_saga(5309)
  → run_saga(5440) → run_saga_fsm(6464) appends Initiated/PreparingA/PreparingB/
  Committing (6473/6484/6515/6548). NOT recovery-only. append_journal helper @8017.
- (d) only FFI export deferred: ALL callers of start_cross...saga (15895-17607) are
  inside `#[cfg(test)] mod tests` (opens @11013/11027). No production caller →
  journal empty → recovery correctly "inert in production today."

## SagaSigningKeys re-export
- Load-bearing: rustdoc `[SagaSigningKeys](crate::context::supervisor::SagaSigningKeys)`
  links in commands.rs/tools.rs/supervisor.rs resolve ONLY via this re-export
  (inner `supervisor::supervisor` mod not re-exported at context level).
- No collision (only 1 symbol named SagaSigningKeys). rustdoc under CI flags
  (--document-private-items + testing features) = 0 errors, no SagaSigningKeys problem.

## Bonus improvement
- tools_command_context_id: `_ => None` → explicit `Placeholder { .. } => None`
  (exhaustive-by-name; future variant forces compiler decision). Good defensive change.

## actor saga.rs handler
- Only processes Prepare-A/Prepare-B/Commit/Abort PHASE messages (supervisor-sent
  per-context legs), NOT saga initiation. Confirms "produced supervisor-side."
