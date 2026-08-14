---
name: adr051-causal-dag-ordering
description: Adversarial findings on ADR-051 causal-DAG application-event ordering + ADR-011 interim exclusion of MessageSent/ToolInvoked
metadata:
  type: project
---

# ADR-051 Causal-DAG Ordering — Adversarial Findings

File: `.docs/adrs/ADR-051-causal-dag-application-event-ordering.md` (NEW, Accepted-model)
Companion diffs: phase-2.md (ADR-011 amendment), §07.3.2/§07.3.7, §09.9.3 convergent-log requirement, §19.7, §25 (76→75 variants).

**Why:** ADR-051 makes MessageSent/ToolInvoked convergent canonical Merkle leaves via causal DAG (heads-reference + leaf-hash tie-break linearization). Interim (ADR-011 amendment) excludes them as local ContextEvents; velocity consequences/economic pricing/tool-count computed locally until ADR-051 lands.

**How to apply:** These are SPEC-LEVEL gaps the model does not acknowledge. When ADR-051 implementation PRs land, verify each is closed.

## Findings (model does NOT acknowledge these)
- **BLACK-DAG-01 (HIGH): eventCount/merkleRoot binding broken by DAG.** §9.9.3 test = equal count → equal root. DAG linearizes over OBSERVED events. Two honest members at same total count but different observed DAG subsets produce different roots = FALSE-POSITIVE equivocation. ADR claims "count tolerance heuristic" covers it but the cryptographic equal-count test is explicitly un-loosenable (§9.9.3). The count is no longer a proxy for "same prefix" once order depends on observation set. NEEDS: checkpoint must commit to a DAG-frontier/head-set, not a scalar count.
- **BLACK-DAG-02 (HIGH): relay withhold induces honest-looking divergence.** Relay selectively delivers app events so members linearize different orders at coincidentally-equal counts → looks like equivocation (false alarm) OR masks real equivocation by keeping counts unequal. ADR §38 hand-waves "only delays convergence."
- **BLACK-DAG-03 (MED): tie-break grindable.** Concurrent events ordered by leaf-hash ascending. Author controls content → can grind nonce/timestamp to make own leaf sort before/after a target, manipulating which message "counts first" for a velocity threshold crossing at a boundary, or which of two concurrent consequence-triggering messages linearizes first.
- **BLACK-DAG-04 (HIGH): forged/omitted head refs fork order.** Malicious author omits heads it actually saw (claims to have seen less) → its events linearize as concurrent everywhere, maximizing tie-break control; or references non-existent/private heads. ADR has NO head-reference VALIDATION rule (must be previously-observed real leaves; must include all known heads). Without "you must reference all current heads you've seen," authors freely choose causal position.
- **BLACK-DAG-05 (HIGH interim): velocity-consequence evasion + repudiation in the gap.** Interim MessageSent is local-only, no Merkle record. Attacker spams to one relay/subset, velocity enforced locally and divergently per member (split-brain — ADR-011 admits "computed locally per instance"). Suspension state diverges; offender repudiates (no durable record). ADR-051 §51 claims end-state fixes this but interim is live indefinitely.
- **BLACK-DAG-06 (MED): divergent derivation native vs WASM.** Auto-derived consequence leaf "every member mints identical leaf at identical position." Requires byte-identical DAG linearization + rule eval across Rust/WASM (separate impls per ADR-034). Float/rate math, timestamp handling, tie-break compare must be bit-exact. No KAT vector specified for DAG linearization or consequence derivation (§25 carries NO MessageSent/ToolInvoked leaf at all).
- **BLACK-DAG-07 (MED): consequence input includes timestamps?** Velocity = msgs/min needs a time window. Timestamps are author-asserted (untrusted, §antispam SenderVelocityTracker accepts arbitrary ts). If derivation uses asserted timestamps, convergent-but-forgeable; if uses DAG position only, "per minute" is undefined. ADR never says what the convergent time basis is.

## Exclusions analysis (Q4)
- Moving MessageReceived/EquivocationDetected/PseudonymAnnounced to local-only is SOUND for §9.9.3 (these were always per-receiver/non-convergent; durable append would itself break convergence). No accountability lost: EquivocationDetected tier-(a) is local-by-design; tier-(b) EquivocationAlert is the durable governance artifact and is unaffected. MessageReceived had zero durable consumers. This part RESISTS attack.
