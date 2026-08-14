---
name: adr051-convergent-time-dag
description: ADR-051 causal-DAG ordering + checkpoint-carried median clock review — model SOUND, wire substrate INCOMPLETE (frontierRoot/ms-time outside signature)
metadata:
  type: project
---

# ADR-051: Causal-DAG App-Event Ordering + Convergent Time (review 2026-06-18)

Verdict: CHANGES-NEEDED. Model is sound; spec-level wire substrate lags the prose.

**Why:** Closes ADR-011 interim gap — MessageSent/ToolInvoked/PaymentReceived are per-author
(non-convergent), stranding tool_invocation_count (§7.3.2), economic velocity (§19.7),
velocity-suspension consequence (§7.3.7). ADR-051 makes order convergent (causal DAG +
deterministic linearization) and time convergent (median-of-member-receive-times on checkpoints).

**How to apply:** When this lands as code, verify the BLOCKING items below are closed first.

## Model = SOUND (5 questions all pass on the model)
- Q1 median via MANDATORY periodic checkpoints defeats selective-withholding: sample for E =
  earliest checkpoint whose frontierRoot covers E; can't drop E's sample without dropping whole
  periodic checkpoint (= suppression per §9.9.2). Set-membership manip ≠ value-robustness; correctly distinguished.
- Q2 cut closure SOUND + observation-order-independent: "closed iff EVERY member in MLS-membership-set
  as of cut's epoch has signed checkpoint covering F". Set predicate = commutative. all-members-or-nothing
  (no partial median = no false-equiv) + bounded-liveness-window→local-throttle fallback (no DoS). Membership-set itself anchored to convergent commit log.
- Q3 frontierRoot (SET of head hashes) is correct fix over scalar eventCount (not derivable from count). Equal-frontier/equal-root test sound GIVEN frontierRoot authenticated+canonical. Commit prefix stays on position (2-honest guarantee untouched, DAG test purely additive).
- Q4 trust bound stated EXEMPLARY: honest-MAJORITY for clock, "strictly weaker than §9.9.3 2-honest", scoped to soft anti-spam only, durable Sybil resistance via §9.3 not 2-honest. even-N=lower-of-two + u64 ms = integer-exact determinism (correct algorithm).
- Q5 per-author rule scoped to COUNT axis is correct AND complete: scope note at ADR:47 explicitly says it does NOT cover cross-author TIMING (that's §6 honest-majority). count-axis closed by construction; time-axis under honest-majority; no gap/double-claim.

## BLOCKING (wire substrate not amended — "enforce mechanically not prose")
1. §23.16.1 (23-sync-and-offline-strategy.md:318-332) NOT amended. Still no frontierRoot field,
   no ms receive-time, and signed preimage "SCP-CHECKPOINT-V1:" (line 332) frozen ending at
   `timestamp (8-byte BE u64)`. frontierRoot + ms-sample MUST go INSIDE a bumped V2 preimage —
   else unauthenticated (BroadcastEnvelope-class "field outside signature" defect).
2. UNIT MISMATCH: ADR §6/req4 = u64 MILLISECONDS; existing checkpoint timestamp = u64 Unix SECONDS
   (23:329; 09:802 shows DateTime). Must add DISTINCT receive_time_ms field + state median is over
   ms field not legacy seconds. As-is ambiguous → non-convergent median.

## HIGH
- "covers F"/"covers E" predicate UNDEFINED/uncomputable: it's causal-reachability, but checkpoint
  commits only to 32-byte frontierRoot, not the heads. Verifier can't compute reachability from a root.
  Need head-hash list propagated (authenticated) OR redefine covers as set-inclusion. Interacts with frontierRoot canonicalization (define: SHA-256 over sorted-by-hash length-prefixed head list).

## MEDIUM
- §1 bounded-buffer REJECTION window vs ADR:38 suppression-signal: relay delaying backfill can push
  honest member past rejection window → rejects real leaf → false suppression mark. Must attribute
  rejection-due-to-non-backfill to relay/transport, never the referencing author.

## LOW
- ADR:42 tie-break key = SHA-256(0x00‖rmp_serde(Event)) = SAME as RFC6962 leaf hash. State it IS the
  canonical leaf hash by definition (don't recompute a second subtly-different digest).
- Add cut-closure-boundary KAT (N-1 unclosed→local; Nth→closes→median) to req5 — the all-members
  predicate is the order-independence linchpin and most likely silent cross-impl divergence point.

## Key file lines
- ADR-051-causal-dag-application-event-ordering.md (the new ADR)
- 23-sync-and-offline-strategy.md:318-332 (UN-amended wire format — the gap)
- 09-security-model.md:802 (legacy DateTime), :813 (prose DAG-leaf extension paragraph)
- 25-test-vectors.md: taxonomy 76→75 (PseudonymAnnounced removal already reflected)
