# Check the Accepted ADR before overruling a reviewer

## The criterion

A finding that contradicts a rule the spec states is checked against the Accepted upstream ADR **before anyone rules on it**. The reviewer who wrote the finding, and whoever decides whether to accept it, each open the ADR the spec cites and read the clause the finding disputes. A written reason for refusing the finding is not a substitute for that read: the reason is an argument about the spec, and the ADR is the artifact that governs the spec.

This is the artifact-flow invariant in `CLAUDE.md` applied to review triage. The flow runs plans → specs → ADRs → stories → source code, and upstream governs downstream. A finding says the downstream artifact is wrong; the upstream artifact is where the answer already lives.

## The instance

On 2026-09-02 the inquisitor filed a finding against the fork-precedence rule in `09-security-model.md` §9.7.4.2: a suffix whose commitment-revealing event also carries the standing root's signature should outrank one that does not. The orchestrator refused it, wrote a reason, and recorded the refusal as a decision. It never opened ADR-063, the inception-derived identity key-event log, which had carried that two-tier order since its acceptance.

Eight review rounds then ran against the version the orchestrator had written. Every reviewer in those rounds checked the spec text against the plan of record, and the plan carried the orchestrator's version, so every round confirmed a rule the Accepted ADR contradicted. The refusal propagated because the checking procedure could not see past the artifact that carried the error.

Alec settled the question on 2026-09-07 in the finding's favour — "Root wins sounds like a good solution" — with the reason "If an attacker has the root, it's GG. What would you gain by trying to optimize against that case?" Pass 17 of the spec rebuild then re-amended ADR-063 back to the order it had held from acceptance, and rewrote six sites in the spec and the ADR that had been built on the refused version.

## The fix

Three procedural rules, in the order a review round applies them.

1. **A reviewer that files a finding against a spec rule cites the upstream artifact it read.** Where the ADR states the rule, the finding says so and quotes it, which converts the finding from a proposal into a report of a spec that drifted from its ADR. Where no ADR states the rule, the finding says that too, which tells the orchestrator that a genuine design question is open.
2. **Whoever rules on the finding opens the ADR before writing the ruling.** A refusal that does not name the upstream artifact it checked is not a ruling; it is an opinion about downstream text.
3. **A rule that turns out to contradict its Accepted ADR is not patched in the spec.** The ADR either governs, in which case the spec changes, or the ADR is itself wrong, in which case a dated amendment to the ADR comes first and the spec follows. Fixing the spec alone leaves the two artifacts disagreeing and hands the next reviewer the same trap.

## Why it recurs

A review round is cheap to run against the plan of record and expensive to run against the full provenance chain, so a round drifts toward checking the artifact nearest to hand. That drift is invisible while the plan and the ADR agree, and it becomes an eight-round error the moment they diverge. The cost is paid once, at the moment a finding disputes a rule — which is exactly the moment the chain is worth retracing.
