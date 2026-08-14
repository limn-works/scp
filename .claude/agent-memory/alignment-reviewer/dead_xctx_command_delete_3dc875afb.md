---
name: dead-xctx-command-delete-3dc875afb
description: Review of commit 3dc875afb deleting dead InitiateCrossContextToolInvocation command + stale deferred docs — ALIGNED, 1 residual phantom-provenance comment
metadata:
  type: project
---

# Delete dead `InitiateCrossContextToolInvocation` command @ `3dc875afb` (branch chore/105-pr6a-delete-dead-xctx-command, worktree agent-ab98dbae..., base f0cbad57e = PR#1906 journal-swap) — ALIGNED, ship, 1 NEEDS-DISCUSSION (non-blocking)

Deletes vestigial `ToolsCommand::InitiateCrossContextToolInvocation` (4 NotImplemented match-arms: commands.rs def, handlers/tools.rs, actor/mod.rs, supervisor.rs reply) + orphaned `reply_saga_deferred` helper + stale "SAGA WIRING DEFERRED" module doc + 2 "saga-initiator variant" refs in reply_{tools,broadcast}_not_registered. 4 files +10/-77. Replaced `_ => None` with explicit `ToolsCommand::Placeholder` arm in tools_command_context_id (exhaustive, clippy::match_wildcard_for_single_variants).

**Why ALIGNED:** DEFERRED-commit-11-saga-use-cases.md:1-3 `**Status:** RESOLVED (commit 11.5)`; Gap 2 (xctx tool invoke transport) RESOLVED by §6.2.4 (line 265). Deleted variant's present-tense "deferred/NotImplemented pending FFI export" doc-comments contradicted the RESOLVED artifact = phantom provenance per artifact-flow invariant. Code-must-match-resolved-artifact ⇒ delete correct.

**Verified no capability lost:** parent tree f0cbad57e has variant in EXACTLY 5 places — enum def (commands.rs:2304) + 4 match-arms. ZERO construction/send sites (never dispatched). Real producer `Supervisor::start_cross_context_tool_invocation_saga` (supervisor.rs:5304) UNTOUCHED — all 4 supervisor.rs diff hunks at 4717-10610, none inside producer body. Rewritten doc-comment claims VERIFIED: producer sig (5310-5313) `executor: F: FnOnce(Value)->Fut` + `signing_keys: SagaSigningKeys<'_>` (lifetime-borrow struct @889) = both genuinely non-Send, cannot cross mailbox. §6.2.4 (06-xctx:240-242) supervisor-minted SagaId, Prepare/Commit on actors. ADR-049 §3a:81 (FFI export MUST NOT ship pre per-set-gating), §3a:94 (channel-auth caller_did forward obligation) = FFI export genuinely still deferred.

**FINDING (NEEDS DISCUSSION, non-blocking):** supervisor.rs:4648-4650 `dispatch_tools_command` doc-header STILL says "The cross-context saga-initiator variant returns ContextError::NotImplemented during the commit-11 window — see DEFERRED-commit-11..." — SAME phantom-provenance class the commit scrubbed, but on the dispatch-FN header (scrub missed it; targeted only the variant's own comments + 2 reply_*_not_registered headers). The named variant was deleted by THIS commit; DEFERRED doc is RESOLVED; "commit-11 window" describes an eliminated state. Recommend reword (saga produced directly via start_..._saga, no mailbox leg; FFI export deferred per ADR-049 §3a) + drop "commit-11 window".

**NOT a finding:** commands.rs:2191-2200 enum-doc is ACCURATE — says §6.2.4 saga *is wired* via start_..._saga, "what remains deferred is its FFI export, pending per-participant-set saga gating (ADR-049 §3a)" — matches resolved-but-FFI-deferred reality. Trailing "and the actor-mailbox path for this method" slightly imprecise post-deletion but subject is invoke_tool_with_economy's permanent non-Send exclusion (true).

LESSON: a "delete dead command + scrub its stale deferred docs" commit can MISS a phantom-provenance comment on the DISPATCH FN that *routes* the deleted variant (its header narrates the variant's now-eliminated NotImplemented state) — after such a scrub, grep the whole module for the deferral vocabulary ("saga-initiator", "commit-11 window", "deferred", the DEFERRED doc filename), not just the deleted variant's own doc-comments. Distinguish ACCURATE "saga wired, FFI export still deferred per §3a" notes (keep) from STALE "variant returns NotImplemented during the commit-N window" notes (scrub) — the resolved-but-FFI-deferred state is real and may legitimately remain documented.
