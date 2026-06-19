---
name: adr051-causal-dag-review
description: ADR-051 causal-DAG application-event ordering + median clock review (2026-06-18) — CHANGES-NEEDED, 1 residual unqualified PaymentReceipt claim
metadata:
  type: project
---

# ADR-051 Causal-DAG Application-Event Ordering — Alignment Review (2026-06-18)

Worktree `agent-aaf1b56ed9b9a3581`. Edit set = UNCOMMITTED (vs HEAD): new `.docs/adrs/ADR-051-causal-dag-application-event-ordering.md` + phase-2.md (ADR-011 amendment, exclusion taxonomy rewritten into 2 categories), 07 (§7.3.1/§7.3.2/§7.3.7), 09 (§9.8.3/§9.8.5 + §9.9.3 DAG-leaf extension), 19 (§19.6/§19.6.1/§19.7/design-principle 4/wire-table), 25 (Vector 32: 76→75).

**Verdict: CHANGES-NEEDED** — one residual unqualified claim; everything else coherent.

## The finding (BLOCKER-lite, single line)
`.docs/specs/19-economic-governance.md:593` — SDK API gloss: "`paymentHistory` retrieves receipts from the context's **event log**." Pre-existing, NOT touched by the diff. Under the new category-2 classification `PaymentReceipt` is a per-payee local `ContextEvent` until ADR-051 (canonical Merkle leaf only thereafter). The diff carefully qualified the exact same claim at lines 211, 306, 324, 333, 429 but missed 593. Fix: qualify (e.g. "retrieves receipts from the context's local `ContextEvent` stream — a convergent Merkle leaf under ADR-051").
- Line 469 (cost-provenance "part of the provenance chain") is fine — provenance via signed DataProvenance/paymentReceiptId, not a Merkle claim.

## Observation (for the implementation program, not a doc blocker)
ADR-051 §6 line70 pins the clock unit at `u64` **milliseconds**; existing §23.16.1 `ConsistencyCheckpoint.timestamp` is `u64` **Unix seconds**. ADR defers the wire change (§23 correctly NOT edited), so no current contradiction, but the impl step must not silently conflate sec-`timestamp` with the ms receive-time clock.

## What was verified CLEAN
1. Taxonomy = 75: enum in phase-2.md has exactly 75 variants; Vector 32 says 75; PseudonymAnnounced correctly NOT a variant (only in exclusion prose). MessageSent/ToolInvoked/PaymentReceived/PaymentCaptureFailed REMAIN enum variants (correct — they become canonical leaves in end-state; exclusion is about Merkle-*append*, not enum membership).
2. §9.8.3 reconciliation correct: convergent commit-chain → same-parent=fork; application events → DAG, concurrent branches normal/not-fork; (epoch,gen,timestamp) demoted to delivery/display hint. Matches ADR-051 line 21 exactly.
3. Three-subsystem coherence: NO "all three equally" over-claim. participation-suspension (§7.3.7)=only clock consumer; tool_invocation_count (§7.3.2)=count not clock; SenderVelocity (§19.7)=payer self-meters locally. Consistent across ADR §7, phase-2 amendment lines155-159, 07:199, 19:315.
4. Cross-refs all resolve: §23.16.1 (23-sync:318), §23.16.4 (ContextSnapshot; the "anti-spam state wiped on import" gloss matches the §23.16.4 "Signed vs wiped fields" subsection at 23-sync:494 — correct), §23.16.8, §19.6.1, §9.9.2 cadence "50 events/10 min" matches 09:797, §9.3, §23.7, §7.7, §5.7, §9.10.4.
5. No `#NNNN` issue-refs ADDED (the 5 pre-existing ones in phase-2.md:780/1632 + 09:382/399/426 are all outside the changed hunks).
6. ADR-049 in `git diff origin/main` is PRIOR substrate work, NOT this uncommitted edit set.

## Reusable pattern
When a reclassification narrows a "recorded in event log" claim across a spec, the SDK-API-surface gloss section (here §19's `SCP.Economy.*` summary block) is the easy miss — it restates the property in passing, far from the type-def/flow-step the editor focused on. grep the whole file for "event log" + the type name, not just the sections named in the task.
