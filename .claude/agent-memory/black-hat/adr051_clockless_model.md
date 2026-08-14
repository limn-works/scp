---
name: adr051-clockless-model
description: ADR-051 clockless causal-DAG model adversarial review — clock cut entirely; velocity=local throttle, suspension=governance commit. Findings on the governance seam.
metadata:
  type: project
---

# ADR-051 Clockless Model (review 2026-06-19)

The convergent velocity clock (prior C02 clamp-lever, BLACK-051-01 author-future-dates-sender) is **CUT**. New model:
- Velocity = local flow-control throttle (per-member, receiver-clock, non-convergent, never a leaf). Live spam defense.
- Durable suspension = governance commit (ADR-031); "execute=record=commit".
- Causal-DAG ordering + frontierRoot retained (DAG is step-2 future program, deferred).

**Why:** clock attacks no longer apply — there is no clock to clamp/forge. Confirmed sound: prior clock surface gone.

**How to apply:** the clock attacks are dead. New attack surface is the GOVERNANCE SEAM, not the clock.

## Findings

### BLACK-051C-01 (stale provenance, real defect) — phase-2.md:912
ADR-011 amendment still calls it "ADR-051 (causal-DAG application-event ordering **+ median clock**)". ADR-051 explicitly REJECTS the median clock (Alternatives, line 77). Downstream artifact describes a model the upstream ADR rejects = phantom provenance. Fix: drop "+ median clock".

### BLACK-051C-02 (the real hole the cut MOVED, not closed) — MEDIUM/HIGH
"Suspension = governance commit, execute=record=commit" is only sound when the governance model will actually commit. Per 05-contexts.md:406 + :468: **SingleAdmin auto-executes only the ADMIN's proposal**; a non-admin's auto-proposed SuspendCapability is just a proposal the admin can ignore/reject.
- **Spammer-is-admin:** in a SingleAdmin context the admin spams; members throttle locally (live defense holds) but NO durable suspension ever commits because only the admin commits and they won't suspend themselves. The clockless model has NO durable consequence here. The old soft velocity record at least produced a (relay-vetoable) record. Net: durable accountability for an admin-spammer is LOST.
- **Threshold/Majority/Unanimity:** auto-proposed suspension needs quorum. A lone honest member throttled by a spammer cannot reach quorum alone; spammer's Sybil allies vote it down. Live throttle still protects each member, but the convergent RECORD ("this DID was suspended for spamming") may never form.

This is the honest answer to question 4: cutting the clock LOST the (soft, relay-vetoable) durable velocity record in exactly the cases where governance won't commit (admin-spammer, sub-quorum honest minority). The ADR frames suspension-commit as always available; it is conditional on governance cooperation. Defensible (the live throttle is the real defense and is zero-trust), but the ADR overstates "convergent-by-construction, no honest-majority dependency" — the SUSPENSION RECORD does depend on governance cooperation.

### BLACK-051C-03 (spurious-suspension / mechanical-trigger is a private observation) — MEDIUM
"trigger is mechanical, not governance-discretion" — but the trigger is "sustained LOCAL throttling," a per-receiver non-convergent private observation. A malicious member can claim sustained throttling that never happened and auto-propose suspension of an innocent. In SingleAdmin a malicious admin can thus suspend anyone citing "spam" with no convergent evidence (local throttle state is explicitly non-convergent and wiped on import, §23.16.8). The "mechanical trigger" is mechanical only inside the proposer's own SDK — unverifiable by others. So the commit is convergent but its JUSTIFICATION is not. This is inherent to any rate-based consequence without a clock; the ADR should acknowledge the proposer-trust the trigger carries rather than implying the whole chain is trustless-mechanical.

### Not gaps (correctly deferred)
- frontierRoot absent from §23.16.1 wire format = correct (DAG is step-2 forward program; ADR-051 "Implementation and sequencing" scopes it).
- anchored=false interim plumbing is consistent across 07/19.

### DAG residuals (step-2, prior-vetted) — unchanged
must-include-frontier + per-author-aggregate rule neutralize leaf-hash tie-break ordering. No new head-ref/linearization hole introduced by clock removal.
