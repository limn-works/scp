---
name: adr051-convergent-clock
description: Black-hat findings on ADR-051 causal-DAG ordering + median-of-receive-times convergent clock + cut closure + equivocation (2026-06-18 spec review)
metadata:
  type: project
---

# ADR-051 Convergent Clock / Cut / Equivocation — Black-Hat Findings

File: `.docs/adrs/ADR-051-causal-dag-application-event-ordering.md` (+ diffs to phase-2.md, specs 07/09/19/25).
Construction: app events = causal DAG, deterministic linearization (ascending leaf hash tie-break); convergent time = median of member receive-times carried by §9.9.3 checkpoints; cut closes only when every current MLS member checkpointed past frontier F; unclosable → no durable consequence (local-throttle fallback); honest-majority-of-attesters trust bound.

**Why:** independent adversarial review requested by Alec.
**How to apply:** if ADR-051 implementation lands, verify these were fixed; reuse the offender-as-closer and value-axis arguments for any future member-derived-clock design.

## CRITICAL findings
- **BLACK-051-001 — "mandatory checkpoint" has no spec basis.** ADR line 69 hinges on checkpoints being "mandatory and periodic (§9.9.2 cadence)" so withholding the sample = visible suppression. But §9.9.2 (09-security-model.md:787,797) makes checkpoints "recommended" and heartbeats "SHOULD" — NO MUST. Heartbeat (the suppression-watched msg) carries NO frontierRoot/receive-time; checkpoint (sample-bearing) is a DIFFERENT object. Spammer can heartbeat normally + omit/lag its checkpoint → sample absent → cut unclosable → no durable consequence, WITHOUT tripping suppression. The central withholding fix is unsupported by its own cited spec.
- **BLACK-051-002 — median value axis unguarded; "value-resistant median" asserted not built.** ADR lines 69/102 imply the median is value-resistant. It is not: checkpoint `timestamp` is self-reported wall-clock; signature authenticates authorship not truthfulness. Even-N lower-of-two rule (line 70) gives a SINGLE backdating member the clock at N=2. Threshold-crossing (framing a victim into suspension) needs only a minority of outliers near the cliff, not a majority. Small-context floor numeric value undefined → unevaluable.

## HIGH
- **BLACK-051-003 — closure denominator gameable by membership churn.** "All current MLS members as of cut's epoch" undefined under MLS churn (each Commit advances epoch). Join-before-close → denominator +1 uncheckpointed → DoS/evasion. Leave-before-close evaluated at differing local times → honest members get different denominators/medians → FALSE EQUIVOCATION. Denominator must be frozen to commit-epoch boundary ≤ F. ADR asks the question but only answers the honest-liveness case.
- **BLACK-051-004 — offender-as-required-closer.** Suspension target is ALSO a required closer. Rational spammer never checkpoints the cut that punishes it → unilateral veto of the strongest durable consequence, while heartbeating live. Fallback (local throttle) = pre-ADR status quo on demand. Closure must not need offender cooperation.

## MEDIUM
- **BLACK-051-005 — bounded-buffer reject is wall-clock = false-equivocation lever.** §1 "reject if no backfill within window" depends on relay-controlled delivery timing. Relay delays head H to member A (rejects E) but not B (linearizes E) → honest members diverge at equal frontier. Converts allowed relay delay (§3) into forbidden ordering divergence. Eviction must be a convergent-state predicate, not a timer.
- **BLACK-051-006 — must-include-frontier self-attested, only "detectable later."** Under-reference + go quiet/leave/rotate → omission never exposed; manufactured concurrency perturbs which cut the event lands in before detection. Gate durable consequence on corroborated cut.
- **BLACK-051-007 — KAT mandate omits closure-predicate + buffer-eviction vectors.** Req 5 pins partial-observation linearization, even-N median, consequence leaf — good — but NOT churn-during-cut closure or delayed-backfill reject/accept, the two timing/membership-dependent decisions most likely to diverge native↔WASM. Fixed-input triple can't catch timing-order divergence.
- **BLACK-051-008 — anchored=false secures producer only.** Req 6 flag exists but consumers (§9.3 capacity, reputation, pricing) not mechanically forbidden from trusting unanchored facts. Make consumer rejection a conformance rule.

## What genuinely resists
- Per-author-aggregate count rule (§2) — leaf-hash tie-break truly count-axis-irrelevant. Scope note (doesn't cover timing axis) honest.
- No-partial-median rule (§5) — correct GIVEN well-defined denominator (flaw is denominator, not this rule).
- Integer clock unit + deterministic tie rule — correct for native↔WASM reproducibility.
- Rejection of relay-ingest/beacon clocks — impossibility argument sound; member-median is least-bad; honest-majority price paid openly.
- Checkpoint-carried-sample IDEA is right; gap is normative (SHOULD vs MUST) + heartbeat/checkpoint decoupling, not conceptual.
