---
name: adr051-receiver-median-clock-simplification
description: ADR-051 round-2 review — clock simplified node-cut → 3-vantage receiver-median + anchored real fields; APPROVE
metadata:
  type: project
---

# ADR-051 Receiver-Median-Clock Simplification Review (2026-06-19) — APPROVE

UNCOMMITTED edit set on branch (worktree agent-aaf1b56ed9b9a3581) refining the ADR-051 round-1 set ([[adr051_causal_dag_review]]). This round SIMPLIFIED the convergent clock: cut the "node" vantage (4→3), made the **receiver-quorum median the value** (not one of several equal inputs), demoted sender/relay to **consistency lower-bound floors (early-direction only, never raise the value — closes the `max()`-clamp upward-lever C02)**, and made `anchored` a real struct field (not a comment).

**Why:** ADR-011 amendment excludes per-author application events (`MessageSent`/`ToolInvoked`/`PaymentReceived`/`PaymentCaptureFailed`) from the convergent Merkle log; ADR-051 re-admits them via causal-DAG ordering + a convergent clock. Round-1 had a node vantage + `max()` clamp that a colluding sender+relay could weaponize to push an event late and dodge a rate window.

**How to apply:** future ADR-051 reviews verify the clock is consistently "receiver-quorum median bounded by sender/relay consistency floors" everywhere and that sender/relay are NEVER described as value inputs or as able to raise the value.

## Verified CLEAN this round
- "node" vantage / "four-vantage" / `max()` clamp confined to ADR-051:101 REJECTED-alternatives entry ONLY. No stragglers in phase-2 / §7.3.7(07:728) / §9.9.3(09:813) / §19.7(19:485) / §7.3.1(07:123).
- Clock phrasing consistent across ADR-051 §6+Decision, phase-2:939-944, §07:728, §09:813, §19:485.
- New real fields present + consistent: `tool_invocation_count_anchored: bool` (§7.3.2 ParticipationProfile, 07:214) and `anchored: bool` (§19 PaymentReceipt, 19:446). ADR §6 #6 mandates machine-readable boolean (not comment) + §25 conformance vector asserting consumer down-weights `anchored=false`.
- Taxonomy = **75** (was 76 round-1; only §25:363 references the count — `git show HEAD` confirms 76→75). Live enum count in phase-2 = 75 variants. (Round-1 had a Vector32/Vector32 75-vs-76 mismatch; resolved this round.)
- §9.8.3(09:728): commit-chain single-parent fork vs DAG-concurrent-shared-frontier ("concurrent branches are normal, not a fork") correct.
- No "all three equally" / equal-weight clock over-claim anywhere.
- No `#NNNN` issue-refs on ADDED lines (`git diff | grep ^+ | grep #NNNN` empty). Pre-existing refs untouched.
- ADR-051 "lifted" sequencing list (§7.3.1/§7.3.2/§7.3.7/§9.8.3/§9.8.5/§19.7) — every listed section carries interim qualification in this edit set.
- Cross-refs resolve: "exclusion taxonomy §2"→phase-2:905 labeled category 2; §23.16.1→23-sync:318; §7.3.7/§19.7/§9.9.3 anchors exist.
- **Round-1 residual now FIXED:** §19:593→594 `paymentHistory` "retrieves receipts from event log" now qualified ("per-payee ContextEvents in interim; convergent Merkle leaves under ADR-051").

## Non-findings (verified correct, not flags)
- §07:420 / §07:476 `ChallengeVerification` "recorded in the context's event log" — UNqualified but CORRECT: attestation-class (verifier-produced), explicitly in the convergent stream per this round's own taxonomy ("...access, **attestation**, provenance"). Not per-author application activity → no ADR-051 qualification needed.

## Observation (not a finding)
ADR §6 receive-attestation binds `receive_time_ms` (u64 ms) + sender stamp u64 ms; existing §23.16.1/§23.16 checkpoint+snapshot canonical hashes use `timestamp` 8-byte BE u64 without a documented unit (wall clock). Unit reconciliation is an impl-program detail the ADR explicitly defers (§Costs: "the `ConsistencyCheckpoint` structure (§23.16.1)" in the breadth list); not a contradiction introduced this round.

VERDICT: APPROVE. 0 blocking, 0 material, 0 doc-precision findings this round.
