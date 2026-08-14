---
name: dead-xctx-command-delete-489ea9f60
description: Architecture review of commit 489ea9f60 (3rd sibling) deleting dead ToolsCommand::InitiateCrossContextToolInvocation — architecturally SOUND; 1 NEW broken intra-doc link (SagaSigningKeys path) introduced, warning-only not CI-blocking
metadata:
  type: project
---

# Delete dead `InitiateCrossContextToolInvocation` xctx command @ `489ea9f60` — ARCHITECTURALLY SOUND, 1 doc-link nit

Commit `489ea9f60` on `chore/105-pr6a-delete-dead-xctx-command` (worktree `agent-ab98dbae24687e41d`), base `f0cbad57e` (PR#1906 journal-swap). THIRD sibling of `3dc875afb` / `49adc0be9` (neither is ancestor — all 3 are reworked siblings off the same base).

**Why:** Continuation of §6.2.4 saga-cleanup line. The actor-mailbox variant was a vestige of the pre-saga design; the real producer is `Supervisor::start_cross_context_tool_invocation_saga` (supervisor.rs:5309).

**How to apply:** This rework is the one to ship. Architecture verdict APPROVED.

## Verified facts
- Variant had ZERO non-test callers / construction sites. Deletion complete across ALL 4 sites (commands.rs def, handlers/tools.rs dispatch, actor/mod.rs skeleton, supervisor.rs reply_tools_not_registered) + orphaned `reply_saga_deferred` helper. grep `InitiateCrossContextToolInvocation`/`reply_saga_deferred` over crates/ = 0.
- No SDK wrapper / bridge / capability-matrix / pipeline_wiring / test ever referenced it (never had an FFI export — correct, FFI export is the genuinely-still-deferred piece pending ADR-049 §3a per-set gating). Scope-complete at every layer.
- `tools_command_context_id` `_ => None` → explicit `ToolsCommand::Placeholder { .. } => None` is a REAL exhaustiveness improvement: 5 remaining variants (Placeholder + 4 hard-rate/economy w/ context_id), now future-variant-safe (clippy::match_wildcard_for_single_variants). Consistent with the explicit-Placeholder arms already in reply_tools_not_registered / actor skeleton.
- Doc technical claims VERIFIED ACCURATE: `SagaSigningKeys<'a>` = `&'a ed25519_dalek::SigningKey` borrowed refs (supervisor.rs:889) → non-`'static`, cannot move into `'static` mailbox. `start_cross_context_tool_invocation_saga` `F: ... + Send + 'static` (executor IS Send+'static — the keys are what block it). `invoke_tool_with_economy` `F: FnOnce(...) -> Fut` with NO Send bound (the "distinct reason"). The rewrite correctly DISENTANGLES two reasons the prior phantom docs conflated.
- ADR Gap 2 RESOLVED banner (line 83) matches Gap 3/4 convention exactly (blockquote, bold STATUS(date), "present-tense text below ... retained for historical provenance only").
- **PRIOR-SIBLING PERSISTENT FINDING NOW FIXED:** the `dispatch_tools_command` doc (supervisor.rs:4648-4658) — byte-identical phantom "saga-initiator returns NotImplemented during commit-11 window" text that BOTH 3dc875afb and 49adc0be9 reviews flagged as un-swept — IS rewritten in this commit. Resolved.
- clippy -p scp-runtime --all-targets clean (0 warnings). Test build OK.

## FINDING (MINOR, NEW, non-blocking, warning-only)
3 NET-NEW broken intra-doc links introduced by this commit, all to `crate::context::supervisor::SagaSigningKeys`:
- commands.rs:2202, handlers/tools.rs:22, supervisor.rs:4651.
Root cause: `SagaSigningKeys` is `pub` in inner `supervisor::supervisor` (`pub mod supervisor;`) but is NOT in the `pub use supervisor::{...}` re-export block in `supervisor/mod.rs:142-146` (which re-exports Supervisor, SagaInput, MessageSigner, etc. — hence `crate::context::supervisor::Supervisor` resolves but `...::SagaSigningKeys` does not). origin/main had 0 of these links → net-new, attributable to this commit. Mildly ironic: the commit removes phantom provenance yet introduces a dangling doc path.
Fix: either `crate::context::supervisor::supervisor::SagaSigningKeys` (double-supervisor, the resolvable canonical path — same shape the commit already uses correctly for `Supervisor::start_cross_context_tool_invocation_saga` at supervisor.rs:4649) OR add `SagaSigningKeys` to the mod.rs re-export block.
NOT CI-blocking: neither docs.yml (`cargo doc --document-private-items`) nor ci.yml line 565 sets `RUSTDOCFLAGS=-D warnings` → warning, not error. (The bare `[Supervisor::start_cross_context_tool_invocation_saga]` unresolved links are PRE-EXISTING on main — 2 in commands.rs, 1 in tools.rs — not this commit's fault.)
