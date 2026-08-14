---
name: adr051-causal-dag-median-clock
description: Adversarial analysis of ADR-051 causal-DAG app-event ordering + median-receive-time clock; attack surfaces in median manipulation, stable-cut gaming, frontier validation, interim posture
metadata:
  type: project
---

# ADR-051 Causal-DAG + Median Clock — Attack Surfaces

File: .docs/adrs/ADR-051-causal-dag-application-event-ordering.md (model decision, not yet code).
Touches: phase-2.md (ADR-011 amendment exclusion taxonomy), §07.3.2/§07.3.7, §09.9.3, §19.7, §25.

**Why:** velocity/rate consequences + tool_invocation_count + economic pricing need convergent count AND convergent clock. ADR picks causal-DAG (count/order) + median-of-member-receive-time (clock).

## Residual attack surfaces (ADR underspecifies — these are normative gaps for the impl program)
1. **Stable-cut membership = median membership.** ADR §6 medians over a "causally-stable cut" of attestations but never defines the attester set N or a *mandatory-attestation* rule. A member that WITHHOLDS its attestation removes itself from the median set → moves median. Selective attestation (attest events that suppress my rate, withhold events that would inflate it) is a directional median shift with ZERO Sybils. THE core flaw.
2. **Stable-cut definition is the convergence pivot.** If two honest members compute the cut over different attestation subsets they get different medians → different consequence leaf → FALSE equivocation positive (or masks a real one). ADR never pins "cut closes when M-of-N attestations observed." Undefined closure = native↔WASM divergence vector + relay can hold back one attestation to keep cut open forever (liveness DoS on durable consequence).
3. **Median robustness math is asserted, not bounded.** "minority lying shifts median only marginally" true for VALUE-perturbation but FALSE for SET-membership perturbation (withholding) and for small N (the small-context floor admits this only for 2-3). For N=5 with floor passed, 2 colluders + withholding can swing median across a threshold bucket boundary (10/50/200 per-min steps in §19.7 are coarse — a small median shift crosses a 10x price step).
4. **must-include-frontier is unfalsifiable for genuine concurrency.** Author claims "I hadn't seen X" → indistinguishable from true network skew. Validation only catches refs that CONTRADICT the author's own later chain. A spammer keeps its own chain internally consistent while never referencing others' heads = permanently "concurrent" = its events scatter across linearization, but per-author-aggregate rule (§2) makes count still its own, so this dodges ORDER not COUNT. Real risk: stalling OTHERS' linearization via dangling/forward refs (buffer-unresolved = unbounded buffer / liveness).
5. **Frontier-bound equivocation: relay drives honest members to different frontiers.** Relay withholds different app-events to A vs B so their frontiers never coincide → equal-frontier comparison never triggers → equivocation detection silently disabled for app leaves (the commit prefix still works). ADR §5 assumes a cut "both members have fully observed" exists; relay controls delivery so can prevent coincidence. This converts a detection into a liveness-gated detection.
6. **Interim (step 1) posture.** velocity local-only, non-durable, "MUST NOT be relied on as security control." Honest but the GAP: tool_invocation_count and PaymentReceived provenance carry NO Merkle proof in interim → a member can lie about its own tool count / payment history with no equivocation catch (per-author, local). Repudiation window is the entire pre-ADR-051 period. Bounded by being documented, NOT by mechanism.
7. **Native↔WASM.** ADR mandates §25 KAT for (a) linearization (b) median (c) consequence leaf. Mandate necessary but NOT sufficient: median over FLOATING-POINT or non-integer-ms clocks diverges; tie in median (even N) needs a pinned rule (lower-of-two? mean? — undefined). Linearization buffer eviction order under partial observation is impl-defined unless KAT pins the OBSERVED-DAG snapshot exactly.

## Per-author-aggregate rule (§2) — does it close tie-grind blame-shift?
Mostly yes for COUNT (A's count is A's own, reorder vs B irrelevant). Residual: the median CLOCK is cross-author (median over ALL members' attestations incl. B's). So A's *rate* = A's count ÷ window-derived-from-everyone's-clock. B (colluder) shifts the shared clock → changes A's DENOMINATOR. Per-author rule isolates numerator, NOT denominator. Cross-author dependency survives in the time axis.
