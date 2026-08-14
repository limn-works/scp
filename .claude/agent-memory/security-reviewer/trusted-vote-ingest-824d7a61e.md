# TrustedVoteIngest keyless governance path (824d7a61e) — 2026-06-27

Commit "fix(governance): run vote guards before signature verification; dedup unsigned-vote build".
Worktree 1900-pr2a-engine. Files: scp-protocol/src/context/governance/{mod,majority,multisig,unanimity}.rs.

VERDICT: GO. Native verified-Approved guarantee PRESERVED. Zero blocking findings.

## Design as implemented
- Signed path (approve/reject/propose, all 3 engines): precheck_vote (guards: eligibility/exists/pending/deadline/AlreadyVoted) -> sign_vote -> resolve key via KeyResolver -> verify_vote (verify_strict) -> push_and_resolve (tally). verify is STRICTLY before push_and_resolve in every engine. propose signs+verifies proposer's implicit approval before insert (Threshold/Unanimity/SingleAdmin); Majority propose records NO proposer vote (starts empty).
- Majority PrecheckOutcome::Resolved short-circuit (past-deadline) records NO vote and runs resolve() over EXISTING already-verified votes only — cannot inject unverified vote. Threshold/Unanimity precheck returns VotingWindowExpired past-deadline (never Resolved).
- Keyless TrustedVoteIngest::ingest_approve/reject: same precheck -> build_unsigned_vote (signature Vec::new()) -> SAME push_and_resolve. No sign, no verify.

## Reachability (point 2) — native CANNOT reach keyless
- TrustedVoteIngest referenced ONLY inside scp-protocol/.../governance/ (impls + #[cfg(test)] use). grep across crates/: zero hits in scp-runtime/scp-core/scp-ffi.
- NOT a supertrait of GovernanceEngine, no blanket impl, NOT in the curated `context::` re-export prelude (context/mod.rs:35-41 exports GovernanceEngine but deliberately omits TrustedVoteIngest). It IS `pub trait` so reachable as scp_protocol::context::governance::TrustedVoteIngest, but native runtime imports via context::{...} and never names it.
- Native dispatches Box<dyn GovernanceEngine> (state.rs, class_s.rs, timeout.rs); ingest_* not in the vtable.

## Blast radius (point 3)
- Native execute precondition: governance_helpers.rs:4898-4923 execute_governance_action resolves proposal from cell's OWN engine.get_proposal() (never caller-supplied) and trusts status==Approved. A native engine only reaches Approved via signed path => invariant holds for every proposal a native node executes.
- verify_proposal_votes: callers are ALL tests (mod.rs tests + per-engine tampered-sig tests). Not on any live native execute/import path. NOTE: an empty-sig vote would FAIL verify_proposal_votes (64-byte try_into fails) — so if/when wired for import of foreign proposals it correctly rejects ingested votes. Good.
- export_import.rs:1583 Approved fixture is test-only determinism harness, not a live trust-deserialized-status path.
- Cross-platform residual: WASM keyless quorum is compensated by §9.9.3 equivocation/Merkle convergence (honest signed native rejects unverifiable vote, roots diverge). Documented honestly in the trait doc.

## Doc/contract (point 4) — correctly scoped
- GovernanceProposal::status invariant (mod.rs:1027-1041) explicitly scoped "signed path only" and states it does NOT hold for TrustedVoteIngest.
- TrustedVoteIngest doc (mod.rs:1547-1607) states NO sig verification, empty sig, caller MUST authenticate identity==voter + governance:vote in THIS context + proposal_id scoping; enumerates residual risk + compensating control.

## Error-oracle (point 5)
- precheck ordering is eligibility(NotEligible) -> exists(ProposalNotFound) -> pending -> deadline -> AlreadyVoted, BEFORE sign/verify. A non-member gets NotEligible without any signature work; signature validity of a non-member is never probed. ProposalNotFound leaks existence to an eligible-or-not caller but this is pre-existing and same for both paths; no NEW oracle introduced by this change. Guard-before-verify actually REDUCES oracle surface (ineligible/double-vote no longer reach InvalidSignature).

GOTCHA: bash cwd resets; use full worktree path /Users/alec/Developer/limn/scp/.claude/worktrees/1900-pr2a-engine or git show.
