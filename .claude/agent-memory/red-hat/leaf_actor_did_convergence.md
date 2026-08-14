---
name: leaf-actor-did-convergence
description: Assessment of fix/leaf-actor-did-convergence (executor stamping, system-leaf sentinels, WASM quorum reorder) — no exploitable chain; 3 adjacent convergence/forgery flags
metadata:
  type: project
---

# Branch fix/leaf-actor-did-convergence (HEAD d7216140b) — 2026-06-22

Reviewed diff origin/main(b5b0eb02c)...HEAD. Three changes: (1) constant system-leaf actor_did sentinels "system:timer"/"system:close"/"system:saga", (2) WASM quorum-execute reorder, (3) executor_did (voter, not proposer) stamping on GovernanceActionExecuted + all per-action leaves.

**Why:** native↔WASM Merkle-leaf byte-convergence so cross-member equivocation detection isn't blinded by honest-but-divergent serialization.
**How to apply:** when reviewing future governance/event-log convergence slices, these are the adjacent open items.

## No exploitable chain in the diff
- Sentinels disjoint from valid DID namespace (did:method:id validation) — no impersonation either way.
- executor_did is provenance-stamp-only; per-action dispatch authorizes against CONTEXT CEILING (e.g. ceiling.contains(MemberBan)), not actor_did. Entry-point auth (member_has_capability GovernanceVote at governance_helpers.rs:3354 + suspended-reject :3338) unchanged.
- Receive-side leaf append is DORMANT (committer-appended-only) — forged local leaves don't replicate to honest members. This bounds impact of every forgery concern.

## Adjacent flags (NOT introduced by diff)
- **A (MEDIUM, task #205): consequence-subject divergence.** Native evaluates consequence rules against proposal.proposer_did (governance_helpers.rs:4360/4392/4443); WASM against initiator_did=executor (manager.rs:3001). Consequences can suspend/ban (consequence.rs EnforcementSeverity). Same commit → honest native+WASM members suspend DIFFERENT members → divergent state. The leaf converges but the enforcement subject does not.
- **B (MEDIUM, task #206): WASM per-action leaf parity unverified.** Native stamps executor on ALL per-action leaves; WASM only confirmed on the GovernanceActionExecuted leaf.
- **C (LOW now, HIGH if receive-side append enabled): governance_execute FFI forgery primitive.** scp-ffi/src/context.rs:3045 (also NAPI context.rs:2771, UniFFI bridge.rs:9531) deserializes caller-supplied GovernanceProposal; handle_execute_governance_action_actor (governance.rs:666-682) sets executor_did=proposal.proposer_did (caller-controlled); only gate is execute_governance_action requiring proposal.status==Approved — ALSO a caller JSON field. No sig/quorum/approvals re-verify. Local-only today; becomes leaf-forgery if receive-side append (planned ADR-051) lands without verification.

## LOW correctness (in diff)
- WASM reorder leaves proposal Approved-in-resolved with action unapplied on execute failure (manager.rs:4194-4213); not retryable (removed from pending). Liveness regression, not security. Execute failure ~unreachable for non-MLS actions.

## Pattern
Convergence slices stamp leaf actor_did but the CONSEQUENCE/ENFORCEMENT subject is a separate field that lags. Always check both leaf-stamp AND downstream enforcement-subject when reviewing native↔WASM parity.
