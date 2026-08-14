---
name: dead-xctx-command-delete-621933fe7
description: ALIGNED review of 621933fe7 — delete dead InitiateCrossContextToolInvocation actor command + scrub phantom-deferred docs; re-export SagaSigningKeys
metadata:
  type: project
---

Commit `621933fe7` (branch chore/105-pr6a-delete-dead-xctx-command, worktree agent-ab98dbae24687e41d, base f0cbad57e = PR#1906 durable-journal-swap). 7 files +56/-102. **ALIGNED, ship, 0 findings.**

**Why:** Deletes the dead `ToolsCommand::InitiateCrossContextToolInvocation` mailbox variant (returned `NotImplemented`) + its `reply_saga_deferred`/`ack_not_impl` handlers in 3 sites (handlers/tools.rs dispatch+fn, actor/mod.rs ack_not_impl, supervisor.rs reply_tools_not_registered). The variant was phantom provenance: it represented a "deferral" that never existed — the §6.2.4 cross-context tool-invocation saga is produced SUPERVISOR-SIDE by `Supervisor::start_cross_context_tool_invocation_saga` (supervisor.rs:5309), NEVER over the actor mailbox.

**How to apply / verified facts (all grounded at HEAD):**
- `SagaSigningKeys<'a>` (supervisor.rs:889) holds `target/caller: &'a ed25519_dalek::SigningKey` — borrowed non-`'static` refs (capabilities, off-wire). The saga method's executor IS `F: FnOnce->Fut + Send + 'static` (5316). So the diff's asymmetry claim is EXACT: executor is Send+'static but the borrowed signing keys can't cross a 'static mailbox → saga stays off mailbox.
- DISTINCT reason for `invoke_tool_with_economy` (9686): `F: FnOnce->Fut` with NO Send bound at all. Diff correctly states the two methods are off-mailbox for DIFFERENT reasons (borrowed-keys vs no-Send).
- NO production caller: all 10 `start_cross_context_tool_invocation_saga` call sites (15895+) are inside `mod tests` (#[cfg(test)] @11013, mod tests @11027). Deferred piece = FFI export only, per ADR-049 §3a (lines 73-94: per-participant-set gating prereq + channel-auth caller_did binding prereq). §6.2.4 spec heading exists (06-cross-context-communication.md:240).
- ADR-049:65 rewrite ACCURATE: old text said producer = `handlers/tools.rs reply_saga_deferred`; new text says FSM already appends on forward Prepare/Commit path, deferred = the producer's caller (FFI export). Surrounding paras (journal-swap-landed :63, serialization :67) unchanged.
- DEFERRED Gap-2: RESOLVED banner (:83) + "Resolution." rewrite (:107) + item-2 list rewrite (:214, now names only handlers/standing.rs for the surviving standing-pair placeholder, explicitly says NO tools handler).
- SCOPE CONTAINED: Gap 1 (standing) + ContextMigration UNTOUCHED. The standing.rs `reply_saga_deferred` line (DEFERRED:214) is the surviving Gap-1 placeholder — intentionally out of scope. `git grep ContextMigration` in diff = empty.
- `SagaSigningKeys` re-export added to supervisor/mod.rs `pub use` (was NOT exported before — grep -c origin/main = 0). NECESSARY completion: new intra-doc links `[SagaSigningKeys](crate::context::supervisor::SagaSigningKeys)` in commands.rs:2202 + tools.rs:22 require the path to resolve.
- BONUS mechanical win: `tools_command_context_id` match (supervisor.rs:10604) went `_ => None` → `ToolsCommand::Placeholder { .. } => None` — now exhaustive WITHOUT wildcard, so a future ToolsCommand variant forces a compile error here (type-system enforcement, aligns w/ tenet).
- Code+test grep for both deleted symbols EMPTY (crates/, bindings/, tests/). Only doc hits = RESOLVED banner + dead-variant-documentation lines.

**LESSON:** dead-NotImplemented-variant deletion that scrubs "deferred" docs → (1) verify the "deferral" was phantom: the real producer path exists elsewhere (supervisor-side) and the variant never had a live consumer; (2) verify the type-level REASON the doc gives for off-mailbox (borrowed-lifetime keys vs missing Send bound) against the actual struct/fn bounds — these are easy to conflate; (3) confirm the deletion makes a downstream match exhaustive-without-wildcard (a positive enforcement gain); (4) a new re-export is justified when rewritten rustdoc adds intra-doc links needing the path; (5) when a doc-grep hits the OLD text, you're reading the wrong tree — grep `<sha>:` committed tree, not the main-repo working dir, when the worktree differs.
