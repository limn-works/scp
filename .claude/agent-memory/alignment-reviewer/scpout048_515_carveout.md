---
name: scpout048-515-carveout
description: SCP-OUT-048 §5.4.5:515 remote-receiver gap-cancel carve-out (commit 8d5da1912, closes #2204) — ALIGNED; resolves the long-tracked :515-vs-:547 contradiction
metadata:
  type: project
---

The MEDIUM I tracked across every SCP-OUT-048 pass (browser gap-path surfaces StreamGap but §5.4.5:515 literally mandated a signed OutletCancel a remote invoker structurally cannot mint) is now RESOLVED upstream by spec edit, not deferred.

Commit `8d5da1912` (worktree /Users/alec/Developer/limn/scp-wt-048), title "docs(spec): reconcile §5.4.5:515 with :547 — remote-receiver gap-cancel carve-out (closes #2204)". Three files: 05-contexts.md (+new "Co-located vs. remote receiver (cancel locus)" block at :517-519), outlet.json (story note #2204-landed/#2203-deferred), outlet-stream-session.ts (code comment repointed from brittle :515/:547/:485 line-nums to section-title anchors + #2203).

**Why ALIGNED (artifact-flow-correct, NOT code-driving-spec):** :515 (Ordering-and-gaps receiver MUST) and :536/:547 (Cancel signature, round-7: next_seq is runtime-derived, "never caller-supplied") were JOINTLY UNSATISFIABLE for a remote (ADR-057 browser) receiver — an internal spec contradiction between two clauses of the SAME section, where the higher-authority security invariant (:547) logically constrains :515. SCP-OUT-048 code merely EXPOSED it (first remote-receiver impl). Fix flows top-down (:547 canonical → resolves :515), documents already-true behavior (no behavior change). This is exactly the CLAUDE.md invariant path ("code reveals spec is wrong → fix spec first") + No-deferral. Landing in-slice is invariant-correct; it's its own atomic docs commit so my earlier "make it a deliberate separate edit, don't bundle" concern is honored in substance (separate commit, same branch).

**Verified consistent:** carve-out cites real symbols — StreamSessionHandle::current_next_emission_seq (dispatch.rs:910), SCP-OUTLET-6131 (CODE_EXECUTION_CREDIT, slug incl execution.stream-gap), SCP-OUTLET-6133 (credit-stall), stream_credit_stall_secs (:485), escrow/slot release (:560). Co-located bullet matches native drains (python outlets.py:660 calls _send_cancel = signed OutletCancel path); remote bullet matches browser (outlet-stream-session.ts:471 surfaces 6131, markClosed, no cancel-sign). #2204 (spec-gap issue) correctly closed; #2203 (Option-B active browser cancel — a genuine out-of-fence FEATURE) correctly stays open, coherent (not a cut corner).

**No line-drift:** carve-out inserted AT :517, so :513/:515 unchanged — the ~15 existing `§5.4.5:515` line-number citations in invoke.rs/outlet.json/25-test-vectors still resolve correctly. OBS only: those remaining brittle line-num cites are pre-existing tech-debt vs the stale-doc lesson (broad, out of this edit's scope; not currently stale).
