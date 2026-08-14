---
name: pr6a-dead-xctx-command-cut-301a1ac07
description: PR-6a @ 301a1ac07 — delete dead InitiateCrossContextToolInvocation actor command + scrub phantom-provenance deferred docs; ALIGNED ship 0 findings
metadata:
  type: project
---

# PR-6a dead xctx-tool command cut @ `301a1ac07` (review checkout /tmp/scp-pr6a-review-E, base origin/main, 1 commit past f0cbad57e = journal swap #1906) — ALIGNED, ship, 0 findings

7 files +57/-103. Deletes dead `ToolsCommand::InitiateCrossContextToolInvocation` (NotImplemented mailbox variant) + `reply_saga_deferred` helper across all 3 match sites (handlers/tools.rs dispatch, actor/mod.rs ack, supervisor.rs reply_tools_not_registered); re-exports `CrossContextToolInvocationRequest`+`SagaSigningKeys` from supervisor/mod.rs (NEITHER on origin/main — genuine new surface for deferred FFI export); rewrites DEFERRED-commit-11 Gap-2 RESOLVED banner + ADR-049 §3b "producer's-caller" correction + item-2 narrative to minimal claims.

**Why:** prior docs were phantom-provenance — described a mailbox transport leg that no longer needs to exist (the §6.2.4 saga is produced supervisor-side, not over the mailbox, because `SagaSigningKeys<'a>` is borrowed/non-'static and can't enter a 'static mailbox msg).

**How to apply:** this is the doc-honesty companion to [[saga-journal-swap-a1fbe0df4]] / journal-swap line. The Gap-2 saga remaining deferrals = FFI export (ADR-049 §3a) + cross-node transport (co-resident-only today). Future passes on this saga should preserve BOTH.

VERIFIED (banner accuracy = load-bearing):
- NO `CrossContextToolInvoke` struct/enum in code (grep): all hits are event-log variant `CrossContextToolInvoked` (different identifier) OR doc-prose spec wire-envelope. Real carrier = `CrossContextToolInvocationRequest` (supervisor.rs:850). DEFERRED doc:97 itself introduces `CrossContextToolInvoke` as hypothetical "A new envelope type (e.g. ...)" — banner correctly tags it "historical provenance only."
- Produced supervisor-side: `start_cross_context_tool_invocation_saga` (supervisor.rs:5309), sig takes `signing_keys: SagaSigningKeys<'_>` (borrowed) while `executor: F: ...+Send+'static` — exactly substantiates "keys keep it off mailbox; executor is itself Send+'static." `SagaSigningKeys<'a>` @889. The SEPARATE reason invoke_tool_with_economy is off-mailbox = its executor carries NO Send bound. Both docs now state these as DISTINCT constraints (prior text conflated).
- Co-resident-only: aborts "...is not a co-resident actor (cross-node child-bridge transport is future work)" @ 6679/6717/6944/7038/7109. supervisor.rs:5278 "This saga has NO production caller yet" + channel-auth caller_did forward-obligation block (5276-5296) PRESERVED.
- Banner makes NO "implemented" sub-feature claim; lists FFI-export+cross-node as tracked deferrals.
- .docs/ deleted-variant hits = ONLY the 2 intended deletion-documenting lines (DEFERRED:83 banner, :109 Resolution). No surviving doc treats variant/reply_saga_deferred as live.
- Narrowed match supervisor.rs:10604 `_ => None` → exhaustive `ToolsCommand::Placeholder{..}=>None` (5-variant enum: Placeholder/TryConsumeHardRateLimit/Refund/Reserve/Settle) — MECHANICALLY enforces future-variant compile error. const fn.
- No Gap-1/standing/ContextMigration scope bleed: item-2 rewrite correctly keeps `reply_not_implemented` in handlers/standing.rs:263, only removes false tools.rs-also-had-a-placeholder claim. `cargo check -p scp-runtime --features testing` CLEAN (no dead-import/unreachable warns).

GOTCHA: diff hunk-context line @10604 shows `ConsumeHardRateLimit` but actual variant is `TryConsumeHardRateLimit` — diff context artifact, not a defect; real arm names match enum + compile.

LESSON: a "delete the dead deferred placeholder + fix the docs that described it" PR → (1) grep crates/ for the deleted variant+helper = must be EMPTY; (2) for each "X is wire envelope, not code" claim, grep and confirm the only code hits are a SIMILAR-NAMED-BUT-DIFFERENT identifier (here Invoked vs Invoke vs InvocationRequest); (3) confirm any newly re-exported type was NOT already exported on base (else redundant); (4) verify the "off-mailbox because non-'static borrowed keys" claim against the actual struct lifetime param + method signature (executor Send+'static vs keys borrowed = TWO distinct reasons, don't let docs conflate); (5) a `_ => None`→named-arm narrowing is a mechanical-enforcement WIN, verify it's exhaustive not just renamed.
