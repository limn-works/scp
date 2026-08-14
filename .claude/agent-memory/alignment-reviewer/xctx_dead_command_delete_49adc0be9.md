---
name: xctx-dead-command-delete-49adc0be9
description: Review of commit 49adc0be9 (branch chore/105-pr6a-delete-dead-xctx-command) deleting dead ToolsCommand::InitiateCrossContextToolInvocation + stale "deferred" docs — NEEDS DISCUSSION, 1 MINOR (missed stale doc-comment on dispatch_tools_command)
metadata:
  type: project
---

Commit `49adc0be9` on `chore/105-pr6a-delete-dead-xctx-command` (worktree agent-ab98dbae24687e41d). 4 files +10/-77. Deletes vestigial `ToolsCommand::InitiateCrossContextToolInvocation` mailbox variant (commands.rs) + its 3 match-arms (handlers/tools.rs dispatch, actor/mod.rs skeleton-dispatch, supervisor.rs reply_tools_not_registered) + orphaned `reply_saga_deferred` helper (tools.rs) + rewrites stale "deferred" doc-comments. Continuation of the §6.2.4 saga-cleanup line ([[xctx-saga-624-review-f29937089]], [[saga-journal-swap-a1fbe0df4]]).

VERDICT: NEEDS DISCUSSION — 1 MINOR (one stale doc-comment the commit message CLAIMED was handled but missed).

VERIFIED ALIGNED:
- DEFERRED-commit-11-saga-use-cases.md **Status: RESOLVED** (line 1-3). §6.2.4 saga produced by `Supervisor::start_cross_context_tool_invocation_saga` (exists supervisor.rs:5212). Deleted "SAGA WIRING DEFERRED"/"commit-11 window" doc-comments WERE phantom provenance (cited RESOLVED ADR as live deferral) → deletion correct.
- Deleted variant had ZERO construction sites at origin/main (git grep "InitiateCrossContextToolInvocation {" → only the enum DEFINITION commands.rs:2304; the 3 other hits are match-arms `{ reply, .. }`). Pure dead match-arm, no sender. NO capability lost; real producer untouched.
- Rewritten tools.rs MODULE doc (lines 17-29) ACCURATE: "saga produced directly by start_cross_context_tool_invocation_saga — does not cross the actor mailbox, because its executor and saga signing keys are non-Send." Matches spec §6.2.4 ("generic executor cannot cross the mailbox per ADR-049 §3", line 287) + ADR-049 §3a (signing keys / deferred FFI surface).
- Rewritten `reply_tools_not_registered` doc ("placeholder variant keeps its own typed reply") ACCURATE — remaining ToolsCommand = Placeholder + 4 context economy variants.
- Rewritten `reply_broadcast_not_registered` doc DROPS "the saga-initiator variant" — CORRECT: BroadcastCommand has NO InitiateBroadcastHostingHandshake at this commit (broadcast saga already cut upstream, PR#1898 [[bcast-hosting-saga-cut-385a35c5b]]); that phrase was ITSELF stale. Not a regression.
- `tools_command_context_id` `_ => None` → explicit `ToolsCommand::Placeholder { .. } => None` — exhaustive, clippy::match_wildcard_for_single_variants. Sound.
- ADR-049 §3a (line 69-92): FFI export `start_cross_context_tool_invocation_saga` is STILL DEFERRED (hard prereq: per-participant-set gating must replace supervisor-wide AtomicBool first). So in-core producer = wired/real; FFI export = legitimately deferred. The distinction the docs must preserve.

FINDING (MINOR — phantom provenance NOT fully swept): supervisor.rs:4648-4650 — the `dispatch_tools_command` doc-comment (~4642) is BYTE-IDENTICAL between origin/main and 49adc0be9 (untouched), and STILL reads: "The cross-context **saga-initiator variant** returns NotImplemented **during the commit-11 window** — see DEFERRED-commit-11-saga-use-cases.md." This is the exact phantom-provenance class the commit set out to delete: names the now-deleted variant, implies live deferral, cites the RESOLVED ADR. The COMMIT MESSAGE claims it rewrote stale refs in "two doc-comments (reply_tools_not_registered, reply_broadcast_not_registered)" and the review brief expected `dispatch_tools_command` rewritten too — it was MISSED. Recommend rewrite to match the tools.rs module-doc framing (saga produced in-core by start_cross_context_tool_invocation_saga, does not cross mailbox — non-Send executor/keys; FFI export deferred per ADR-049 §3a per-set gating).

NOT findings (deliberately left): standing.rs reply_saga_deferred (Gap 1 standing single-context-async) still deferred — out of scope. commands.rs:2199 "deferred is its FFI export, pending per-participant-set saga gating (ADR-049 §3a)" is ACCURATE (FFI export genuinely deferred). commands.rs:2189/tools.rs:259 "commit 11"/"commit 12" refs are about the Placeholder variant lifecycle, not the saga — accurate.

LESSON: when a cleanup commit's MESSAGE enumerates which doc-comments it rewrote, grep the COMMIT (`git show <sha>:file`, NOT the worktree — base differed here, giving false reply_saga_deferred hits in broadcast.rs) for the SAME stale pattern in sibling doc-comments on related fns. A delete-the-dead-variant PR must sweep EVERY doc that referenced the variant by role ("saga-initiator variant"), including the dispatch-method doc one scope-level up from the deleted match-arm. The producer-exists / FFI-export-deferred distinction (ADR-049 §3a) is the load-bearing line every rewritten doc must keep.
