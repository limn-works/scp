# ADR-051 Causal-DAG Ordering + Median Clock -- Security Review (2026-06-18)

Reviewed: ADR-051 + spec edits (phase-2.md, specs 07/09/19/25). MODEL/DOC review, no impl yet.
Verdict: APPROVE. No HIGH/CRITICAL. Three LOW normative-precision items for impl program.

## What it does
- Application events (MessageSent/ToolInvoked/PaymentReceived) are non-convergent today
  (per-author, no global order) -> excluded from canonical Merkle log in interim.
- ADR-051 end state: orders them via causal DAG (validated head-refs: must-resolve +
  must-include-frontier) + deterministic linearization (ascending canonical leaf hash).
- Convergent clock = MEDIAN of member receive-times over a CLOSED cut, samples carried by
  the mandatory periodic §9.9.3 ConsistencyCheckpoint (not an optional stream).

## Trust bound is HONEST
- §9.9.3 = "requires only two honest members" (09-security-model.md:827). Confirmed.
- ADR-051 §6 clock = honest-MAJORITY-of-attesters; explicitly labeled "strictly weaker"
  than 2-honest. No overclaim. Scoped to soft anti-spam; durable Sybil resistance delegated
  to §9.3 (admission/device attestation) which exists (09:162).

## Denominator is unshrinkable by relay (the key hardening)
- Cut "closed" iff EVERY member in MLS-membership-set AS OF cut's epoch has signed checkpoint
  covering F (ADR-051:62). All-members predicate => relay withholding a checkpoint makes cut
  FAIL TO CLOSE -> no durable consequence (local-throttle fallback), NEVER partial/subset median.
  Fail-safe direction correct throughout.

## Defense in depth correct
- Local throttle on member's OWN receiver clock, independent of median. "Attacker biasing
  median degrades only durable record, never live spam defense" (ADR-051:83). Maps to §23.16.4
  local anti-spam state, wiped-on-import (17-persistence:338) => velocity genuinely local.

## anchored flag = mechanical interim posture (req 6)
- Machine-readable anchored/proof-presence flag so consumers (earned-capacity §9.3, reputation,
  pricing) distinguish anchored vs unanchored. Replaces prose-only reliance. GOOD.

## THREE LOW items for impl program
1. Denominator phrasing: pin to MLS ratchet-tree membership at the epoch the cut CLOSES in
   (req 2). "as of cut's epoch" is right anchor; ensure KAT inherits exact phrasing (join/leave
   concurrent with closure could split denominator otherwise).
2. anchored flag needs a §25 CONFORMANCE VECTOR asserting consumers BRANCH on it (refuse/
   down-weight anchored=false). Flag set-but-never-read is the CLAUDE.md failure mode. Req 6
   names consumers but doesn't require the branch be tested.
3. frontierRoot + receive-time MUST be inside the SIGNED checkpoint preimage (else relay splices
   old sig onto tampered timestamp -> median bias). AND frontierRoot must be SHA-256 over a
   SORTED+DEDUP head-hash SET (set needs canonical ordering or honest members false-positive
   equivocation). Pin both in req 2/4 KAT (partial-observation snapshot already in req 5a).

## Pattern notes
- Checkpoint now multi-purpose (commit-prefix equivoc + DAG-frontier equivoc + clock sample);
  receive-time became security-relevant governance input -> signed-preimage coverage is the linchpin.
- Reusing mandatory checkpoint as sample carrier is a SECURITY IMPROVEMENT vs rejected optional
  per-event attestation stream (closes selective-omission/set-membership median manipulation).
