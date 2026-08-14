---
name: wasm-keyless-governance-removal
description: Slice-2 WASM-cut commit acbcb7795 removes keyless TrustedVoteIngest path; restores unconditional Approved⟹verified governance invariant (now TRUE)
metadata:
  type: project
---

Commit acbcb7795 (worktree cut-wasm-2, branch removing WASM bridge): deleted dead keyless governance path + reverted GovernanceProposal::status doc-comment.

**Why:** WASM bridge removal (ADR-055 — browser TS is now remote thin client, FFI = 3 targets not 4) made the keyless `TrustedVoteIngest`/`ingest_approve`/`ingest_reject`/`ingest_proposal`/`build_unsigned_vote` path dead code. That path fed empty-signature (`Vec::new()`) votes through the shared tally with NO verification — it was the SOLE exception to the "Approved ⟹ all vote sigs verified" invariant.

**Verdict: GO. Restored unconditional invariant is now CRYPTOGRAPHICALLY TRUE.**

Governance engines (scp-protocol/src/context/governance/): SingleAdmin (mod.rs), Majority (majority.rs), Multisig (multisig.rs), Unanimity (unanimity.rs).

All vote-insertion sites traced, every one gated on verify_vote BEFORE the vote enters approvals/rejections:
- majority approve/reject: verify_vote @559/599 before push_and_resolve (inserts @421/423)
- multisig approve/reject: verify @466/509 before push_and_resolve (@302/303); proposer_vote verify @373 (@388)
- unanimity approve/reject: verify @448/491 before push_and_resolve (@285/286); proposer_vote verify @356 (@371)
- SingleAdmin propose: verify @1619 BEFORE struct sets status:Approved @1632 (admin_vote @1635)
- resolve/precheck auto-resolution (majority 246/289, multisig 161, unanimity 142) only COUNT already-stored votes (len()), never insert — so they inherit the verified-only invariant.
- mls_integration.rs:542/545 approved_proposal w/ status:Approved is inside `mod tests` (NOT production).

push_and_resolve now reachable ONLY from signed record_*_vote (keyless ingest_* callers gone). No `.approvals.push` / `proposals.insert` outside verified path or tests.

Signed crypto chain INTACT, nothing weakened:
- sign_vote (mod.rs:218): compute_vote_hash + ed25519 sign, domain-separated.
- verify_vote (mod.rs:248): verify_strict; REJECTS empty sig (try_into::<[u8;64]> fails on Vec::new()).
- verify_proposal_votes (mod.rs:290): post-deserialization re-check, iterates ALL approvals+rejections, resolves key per voter, calls verify_vote. Now a COMPLETE guarantee — no empty-sig votes can exist in any proposal.

Doc revert (mod.rs:1006-1017) accurately states the now-true unconditional invariant — does not over/under-claim. Removal symmetric across all 4 engines + tests deleted. 1253 lines deleted, 11 added.

GOTCHA: bare `cargo test -p scp-protocol` may need `--features testing` (hex did:key gated) — pattern seen in scp-event-log.
