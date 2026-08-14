---
name: trustedvoteingest-pr2a-engine-9f9f059ef
description: PR-2a keyless TrustedVoteIngest engine slice review (commit 9f9f059ef) — GO, zero findings; signature-before-count + native-unreachability proven
metadata:
  type: project
---

# TrustedVoteIngest PR-2a engine slice (9f9f059ef) — 2026-06-27 — GO, ZERO FINDINGS

Worktree `.claude/worktrees/1900-pr2a-engine`. Commit only touches lib.rs + multisig.rs + unanimity.rs (fail-loud ProposalNotFound on impossible-None push, restrict re-export, clarify unreachable arms). The keyless trait itself landed earlier in range (62bb7d73e~1..).

**Why GO:**
- SIGNATURE-BEFORE-COUNT proven all 3 engines: every signed caller does sign_vote -> resolve key (ok_or UnknownVoter) -> verify_vote (map_err InvalidSignature) STRICTLY before the single shared sink `push_and_resolve`. Majority approve/reject (maj.rs:545-568,585-608). Multisig/unanimity propose verify proposer_vote before building proposal+insert+resolve (mul.rs:360-390, una.rs:343-373); approve/reject same order. `push_and_resolve` does NO verify by design — it's the post-verify tally; safe because every signed caller verifies first and ingest_* supplies empty-sig BY CONTRACT.
- Majority `propose` records NO implicit vote (approvals: Vec::new()); multisig/unanimity DO (vec![proposer_vote], verified).
- PrecheckOutcome::Resolved only carries majority past-deadline auto-resolve (records NO vote, no sign). multisig/unanimity precheck return VotingWindowExpired (Err) past-deadline; their Resolved arm is genuinely unreachable (comment is accurate). Either way Resolved never counts an unverified vote.
- NATIVE UNREACHABLE: `pub trait TrustedVoteIngest` standalone — no supertrait on GovernanceEngine, no blanket impl, no downcast/dyn Any on engines. Runtime stores Box<dyn GovernanceEngine> and only ever calls .propose/.approve/.reject (governance_helpers.rs:3399,3722-3724). The only two non-impl `use TrustedVoteIngest` are both inside #[cfg(test)] mods. Trait has ZERO production callers repo-wide.
- RE-EXPORT precise: scp-core facade now explicit list omits EXACTLY TrustedVoteIngest (verified by comm-diff of mod.rs pub surface vs lib.rs list — one omission, no internal leak, no public symbol accidentally dropped).
- EMPTY-SIG BLAST RADIUS: verify_vote rejects empty sig (try_into [u8;64] on empty Vec -> VerificationFailed; test verify_vote_rejects_empty_signature mod.rs:3256). verify_proposal_votes loops verify_vote so empty-sig => reject. CRUCIALLY: ingest_* has NO caller yet (PR-2a is engine-only; WASM wiring not in this slice), so empty-sig votes are not produced in production at all today — latent until wiring lands. Runtime never calls verify_proposal_votes outside tests and never matches Approved outside tests on this path.
- DOC INVARIANT correct + scoped: GovernanceProposal::status doc says Approved=>all-verified holds for SIGNED path only, explicitly NOT for TrustedVoteIngest; trait doc states no-verify/empty-sig, caller contract (identity==voter, holds governance:vote, proposal scoping), residual risk (same-origin caller can fabricate) + §9.9.3 equivocation/Merkle-divergence compensating control. Sufficient.

**Native verified-Approved guarantee: PRESERVED.** Native cannot name or reach ingest_*; runs only sign+verify path.

GOTCHA: Read tool stale in this worktree — used `git show 9f9f059ef:<path>`. Bash cwd resets; cd into worktree path each call.
