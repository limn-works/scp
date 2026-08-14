---
name: governance-vote-guard-ordering
description: SCP-1900 PR-2a governance vote guard-vs-verify ordering invariant + the PR-2a engine refactor split (precheck_vote / push_and_resolve / build_unsigned_vote)
metadata:
  type: project
---

# Governance vote ordering invariant (SCP-1900 PR-2a)

**Required native order in ALL 3 vote engines** (multisig.rs ThresholdEngine, majority.rs MajorityVoteEngine, unanimity.rs UnanimityEngine), scp-protocol/src/context/governance/:

eligibility(NotEligible/UnknownVoter) → proposal-exists(ProposalNotFound) → pending(ProposalNotPending) → deadline → has_voted dedup(AlreadyVoted) → [sign → resolve key → verify_vote(InvalidSignature)] → push to approvals/rejections → emit VoteCast → resolve tally → append events.

GUARDS run BEFORE sign/verify. verify runs BEFORE push (no unverified vote is ever counted).

**Why:** a double vote must be caught as AlreadyVoted regardless of which key signed the 2nd attempt. ADR-039 shared-DID persona: same DID votes with human key then agent key 0xCC; DID resolves only to human key, so agent-signed 2nd vote fails verify — but dedup must fire first. Regression test: scp-runtime crypto::agent_binding_tests::tests::one_did_cannot_cast_two_governance_votes (asserts AlreadyVoted | ProposalNotPending, NOT InvalidSignature).

**The refactor (commit 824d7a61e, fixed PR-2a 62bb7d73e regression):** PR-2a had merged guards+push+resolve into one `record_vote_and_resolve` called AFTER sign/verify → reordered guards after verify. Fix split each engine's helper into two inherent methods:
- `precheck_vote(&self/&mut self, ...) -> Result<PrecheckOutcome, _>`: eligibility→exists→pending→deadline→dedup. Returns `super::PrecheckOutcome` enum (mod.rs, pub(super)): `Proceed` | `Resolved((status, events))`.
- `push_and_resolve(&mut self, ..., signed_vote, vote, ctx)`: push + VoteCast + resolve. Post-verify part.

**Majority subtlety (PRESERVE):** original majority `approve` treated PAST-DEADLINE not as error but `return self.resolve(...)` (auto-resolve) BEFORE sign/verify, and dedup only ran `if !expired`. So majority's `precheck_vote` takes `&mut self` and returns `PrecheckOutcome::Resolved(self.resolve(...))` on past-deadline (no vote recorded, no signing). multisig/unanimity treat past-deadline as `VotingWindowExpired` error (precheck `&self`, only ever returns Proceed).

Signed approve/reject: precheck (match Resolved→return) → sign → resolve key → verify? → push_and_resolve.
ingest_approve/ingest_reject (TrustedVoteIngest, ADR-034 keyless): precheck → `super::build_unsigned_vote(voter, vote, now)` → push_and_resolve. NO sign/verify. `build_unsigned_vote` is pub(super) free fn in mod.rs (SignedVote with signature: Vec::new()). TrustedVoteIngest stays a required trait; push_and_resolve is NOT a public trait method (keeps the inject-arbitrary-unsigned-vote surface closed).

## Flaky full-workspace tests (NOT governance-related, pass in isolation)
- scp-testing::fullstack fullstack_three_party_group — MLS 3-party timing; FAIL under full parallel load, PASS isolated (0.27s)
- scp-runtime context::supervisor::supervisor::tests::kp_actor_poisons_after_budget — 24-48s actor budget/poison; FAIL under load, PASS isolated
Both fail only in `cargo nextest run --workspace` heavy-parallel runs; re-run isolated to confirm green.
