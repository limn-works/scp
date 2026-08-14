---
name: participation-anchoring-premise
description: RESOLVED on c3c-ts — §7.3.2 anchoring claim tightened to match the dormant runtime (committer-local until ADR-051). Runtime dormancy itself still holds; re-check on any trust/event-log change.
metadata:
  type: project
---

# Participation-fact anchoring vs. receive-side replication dormancy

> **UPDATE (c3c-ts review, commit f851f89a5 "docs(trust): align §7.3.2 anchoring
> claim with code").** The spec overstatement I flagged is RESOLVED — the
> artifact-flow-correct way. §7.3.2 now reads: membership/role/governance facts
> are "convergent-by-construction: each becomes Merkle-verifiable … once
> receive-side replication lands (ADR-051). Today the runtime emits these leaves
> committer-side only (receive-side replication is dormant), so a non-committer's
> locally-derived record is committer-local rather than independently
> Merkle-verifiable until ADR-051." §09 and the ADR-011 amendment got the same
> treatment, and `attestation_count` is now an explicit credential-layer
> exception (NOT Merkle-anchored, verifier-relative). The runtime dormancy ITSELF
> is unchanged (verified: the "receive-side append path is currently dormant"
> comments persist at lifecycle_helpers.rs ~388/545/1024/1403,
> governance_helpers.rs ~162/4382). So the re-check trigger below still stands —
> only the spec/code DIVERGENCE is closed. Also retired: the old algorithm
> counted `AttestationPublished` events — a phantom EventType variant that never
> existed in the taxonomy (confirmed: no such variant in scp-event-log;
> `AttestationRevoked` exists only as a `TrustError`, not an EventType).

# Participation-fact anchoring vs. receive-side replication dormancy

On branch `c3c-ts` (ParticipationFacts / subject-bearing-leaf work), spec §7.3.2 was
edited to assert the 6 convergent-derived facts (participation_duration via
MemberJoined/Left, governance_actions_by/against, role_progression, context_creation)
are "Merkle-anchored today … verifiable against the relevant context's Merkle root."

**The runtime contradicts this.** Every membership/role/governance leaf is emitted ONLY
on the commit/execute path (governance_helpers.rs, lifecycle_helpers.rs,
broadcast_helpers.rs — all committer/self paths). There is NO receive-side handler that
re-appends these leaves on non-committers. The code's own comments say so, repeatedly and
consistently: "the receive-side append path is currently dormant, so this leaf is
committer-appended-only and is NOT yet replicated to other members" (lifecycle_helpers.rs
~379, ~1013, ~1393; governance_helpers.rs ~4372). Cross-member convergence is the forward
step under ADR-051 (and tracked via the native↔WASM equivocation gap #1540 / catch-up
#1535 / runtime-eventlog-not-RFC6962 finding).

**Consequence:** TODAY all of these facts are committer-local. A non-committing agent
computing the same subject's record gets a different (or zero) answer — i.e. they are
*verifier-relative right now*, exactly the property `attestation_count` is flagged for and
`tool_invocation_count_anchored:false` signals. The PR flags two of the three
non-convergent fact classes but presents the membership/role/governance class as
already-convergent.

**Why:** the dormancy is pre-existing (not introduced by this PR), but the PR actively
edited §7.3.2 to *assert* anchoring rather than tighten the claim to match the code. Per
the artifact-flow invariant, when code reveals a spec overstatement the spec must be
corrected down, not the code stretched up.

**How to apply:** On any change touching participation records, event-log convergence, or
the anchoring taxonomy, re-verify whether receive-side membership/role/governance leaf
replication has landed. Until it has, "Merkle-anchored today / verifiable by any agent"
is overstated for the membership-derived facts. The honest framing: convergent-BY-
CONSTRUCTION, Merkle-verifiable once receive-side replication lands (ADR-051); today
committer-local. Distinguish the two unanchored *reasons*: membership = commit-ordered but
not-yet-replicated (a wiring gap); tool_invocation = not-yet-convergent-until-DAG (an
ordering gap, ADR-051). See [[finding_runtime_eventlog_not_rfc6962]] in user auto-memory.
