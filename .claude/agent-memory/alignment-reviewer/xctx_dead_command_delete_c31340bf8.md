---
name: xctx-dead-command-delete-c31340bf8
description: ALIGNED review of c31340bf8 (PR-6a, FIFTH sibling) — same dead-command delete as 621933fe7 PLUS resolves 2 residuals that sibling missed
metadata:
  type: project
---

# PR-6a dead xctx command delete @ `c31340bf8` (branch chore/105-pr6a, worktree agent-ab98dbae24687e41d) — ALIGNED, ship, 0 findings

FIFTH sibling of [[xctx-dead-command-delete-489ea9f60]] / [[pr6a-dead-xctx-command-delete-489ea9f60]] / the `621933fe7` pass (see MEMORY.md). Substance of the delete is IDENTICAL to `621933fe7` — re-verified core claims below — but `c31340bf8` STRICTLY IMPROVES on it with exactly 2 deltas (`git diff 621933fe7 c31340bf8` = 2 files, +4/-4):

1. **DEFERRED-commit-11:214 exit-criterion FIXED**: was `reply_saga_deferred` placeholder name → now `reply_not_implemented`. This was a RESIDUAL phantom on 621933fe7 — handlers/standing.rs uses `reply_not_implemented` (standing.rs:40/198) and never had a `reply_saga_deferred`. `c31340bf8` is the FIRST sibling where the standing exit-criterion correctly names the live helper. (This was the task's explicit check.)
2. **supervisor/mod.rs re-export COMPLETED**: 621933fe7 re-exported only `SagaSigningKeys`; c31340bf8 adds `CrossContextToolInvocationRequest` too. BOTH are params of the `pub` producer → both needed for a cross-crate FFI caller; neither was exported on origin/main.

CORE (re-verified at c31340bf8, all hold):
- `reply_saga_deferred` + `InitiateCrossContextToolInvocation` grep-EMPTY across crates/ + bindings/ + all SDK langs; only survivors = 2 past-tense documenting lines DEFERRED-commit-11:83 (RESOLVED banner) + :109 (narrative). No live placeholder.
- Producer `start_cross_context_tool_invocation_saga` (supervisor.rs:5309) takes `SagaSigningKeys<'_>` (def:889, borrowed `&ed25519_dalek::SigningKey`, non-`'static`) → never mailbox-able. ZERO callers in scp-ffi/ or bindings/; all live callers #[cfg(test)] in supervisor.rs → FFI export is the genuine deferral (ADR-049 §3a). PRESERVED.
- FSM appends on forward path: run_saga_fsm (6464) → append_journal for Initiated/PreparingA/PreparingB×2/NeedsRepair. ADR-049:65 accurate.
- §6.2.4 saga produced supervisor-side, NOT mailbox; two DISTINCT off-mailbox reasons correctly separated (borrowed-keys saga vs no-`Send` economy closure).
- No scope bleed: Gap-1 standing `StandingCommand::InitiateStandingPairCreate` placeholder + Gap-3/4/5 "Current placeholder" + ContextMigration text all untouched.
- Bonus: tools-command context-id extractor `_ => None` → explicit `ToolsCommand::Placeholder { .. } => None` (exhaustiveness hardening after variant removal).

GOTCHA: main-repo working dir was ALREADY detached HEAD (prior review bouncing 489ea9f60↔c31340bf8 per reflog); the `chore/fuzz-pin-nightly` branch is in its OWN worktree. Did all reads via `git show c31340bf8:`.

LESSON: re-reviewing a reworked sibling of an already-ALIGNED commit → diff the two commits FIRST (`git diff <prior> <this>`); a 0-finding sibling can still carry a residual the prior pass missed. Here the standing exit-criterion `reply_saga_deferred`→`reply_not_implemented` rename + the second re-export were the entire value-add of the new commit. When a task explicitly names a string the doc "should now" contain, that string is often the precise thing the latest rework fixed.
