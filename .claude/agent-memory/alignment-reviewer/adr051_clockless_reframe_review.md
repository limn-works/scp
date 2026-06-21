---
name: adr051-clockless-reframe-review
description: ADR-051 clockless reframe (2026-06-19) re-review — CHANGES-NEEDED, single stale "median clock" in phase-2.md:912
metadata:
  type: project
---

# ADR-051 Clockless Reframe Re-Review (2026-06-19) — CHANGES-NEEDED

Branch `feat/eventlog-unification-phase2-substrate` (worktree agent-aaf1b56ed9b9a3581). Same edit set as my 2026-06-18 review ([[adr051_causal_dag_review]]) but the convergent-velocity CLOCK was CUT ENTIRELY. ADR retitled "Causal-DAG Application-Event Ordering"; clockless; velocity=local flow control (per-member throttle on receiver's own clock); durable suspension=governance consequence (ADR-031) where commit IS execution AND record.

**Verdict: CHANGES-NEEDED — exactly ONE stale clock reference.**

`.docs/adrs/phase-2.md:912-913` (exclusion-taxonomy §2 prose): "**ADR-051 (causal-DAG application-event ordering + median clock)** gives them a convergent canonical order". The "+ median clock" is a current-mechanism claim that contradicts: ADR title, ADR §6/line 30 ("There is no convergent clock"), ADR rejected-alternatives line 77 (median clock REJECTED), spec 07:728, spec 19:485 (all "no convergent velocity clock"). Self-contradicts within the SAME sentence — next clause (913-915) describes the clockless DAG-linearization mechanism. FIX: delete "+ median clock".

**Everything else CLEAN:**
- All other median/multi-vantage/receiver-quorum/honest-majority/beacon references confined to REJECTED-alternatives (ADR:77) or "there is no convergent clock" negating framing. "Receiver's own clock" = local throttle (ADR:64). Permitted.
- frontierRoot correctly RETAINED as §9.9.3 DAG-frontier equivocation field (NOT a clock); equal-frontierRoot/equal-merkleRoot test; SCP-CHECKPOINT-V2 versioned preimage. spec 09:813 DAG-leaf extension + 09:823 convergent-log requirement coherent.
- CHECKPOINT-V1 (interim, spec 25:412 / 09:1608) vs V2 (ADR-051 end-state with frontierRoot) correctly distinguished.
- `anchored` coherent: interim=false (local ContextEvent), end-state=true (convergent under L2 DAG); spec 07:214, 19:446, ADR §6/Security-req-6.
- taxonomy=75 consistently (25:363).
- No NEW #NNNN added to phase-2 (diff +lines have none). #586/#269/#290/#352/#346 all pre-existing unchanged lines. ADR's #1535 is a docs ref (unblocks-#1535), acceptable in ADR prose.
- Cross-refs resolve: §23.16.8, §7.3.7 (07:708), §19.7 (19:487), ADR-031 (phase-N heading convention).
- POSITIVE DELTA from 2026-06-18: prior residual 19:593 `paymentHistory` "retrieves receipts from the context's event log" NOW FIXED (19:594 qualified "per-payee ContextEvents in the interim; convergent Merkle leaves under ADR-051").

GOTCHA: worktree is at `.claude/worktrees/agent-aaf1b56ed9b9a3581/` — review TARGET is the worktree file, NOT main repo. Bash cwd = worktree; Read with `/Users/alec/Developer/limn/scp/.docs/...` hits MAIN (no median). Always read worktree absolute path. grep -c "median" main=0, worktree=1.
