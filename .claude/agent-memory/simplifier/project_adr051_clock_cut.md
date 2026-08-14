---
name: adr051-clock-cut
description: ADR-051 cut the convergent velocity clock; design converged but two mechanical defects (one stale clock ref, one stale-base regression of #1826) must clear first
metadata:
  type: project
---

ADR-051 (causal-DAG application-event ordering) settled the long-contentious "convergent velocity clock" by CUTTING it entirely (2026-06-19). Final design: causal-DAG application ordering (convergent order + count + audit) = L1/L2; velocity = local per-member throttle (§23.16.8); suspensions = governance commits (ADR-031) where the commit IS both execution and durable record. Governing theorem: "a derived record is automatic AND convergent iff its trigger input is convergent." The execute/record split the old clock served was a phantom.

**Why:** repeated review passes kept generating findings on the clock mechanism; the right move was to recognize the whole approach was non-convergent and reframe, not add another clock construction.

**How to apply:** the cut is the correct simplification — do NOT suggest deferring L2 (DAG count + frontierRoot + KAT). frontierRoot is load-bearing for §9.9.3 soundness once app events re-enter the canonical log; tool_invocation_count needs a convergent COUNT (no time axis). L2 is already phased behind step-1 exclusion, which is the correct disposition. Only residual at review time: ONE stale "+ median clock" string at phase-2.md exclusion-taxonomy §2 contradicting the ADR it cites.

Related: [[stale-base-reverts-merged-enforcement-simplification]].
