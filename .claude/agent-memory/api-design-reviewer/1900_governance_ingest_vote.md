---
name: governance-ingest-vote-1900
description: Design review of GovernanceEngine::ingest_vote (PR #1900 PR-2, native↔WASM governance convergence SCP #1877) — verdict NEEDS REVISION, three DOA-class fixes
metadata:
  type: project
---

PR #1900 PR-2 (SCP #1877): proposed adding a keyless `ingest_vote` to the shared `GovernanceEngine` trait so WASM (ADR-034, no signing keys) and native share one tally. Reviewed READ-ONLY 2026-06-27. Verdict: NEEDS REVISION.

**Three required changes (1 & 3 are DOA-class):**
1. Proposed `ingest_vote(.., now: u64, context: &GovernanceContext)` — DROP `now`. `GovernanceContext` ALREADY carries `now` (mod.rs:1079); approve/reject read `context.now` for both sign_vote timestamp AND deadline checks. A separate `now` param lets caller pass two conflicting values → silently breaks the byte-identical leaf convergence the PR exists for.
2. Single `VoteType` param breaks the established two-method surface (approve/reject). WASM already has two entry points (approve_governance_proposal/reject_governance_proposal, manager.rs:5174/5323). Split into `ingest_approve`/`ingest_reject`.
3. **Trust-boundary footgun**: placing the unsigned path on `GovernanceEngine` exposes it on ALL native key-holding engines (SingleAdmin/Majority/Threshold/Unanimity), letting a native caller skip sign_vote+verify_vote. Would make GovernanceProposal's documented "Approved ⟹ all sigs verified" invariant (mod.rs:988-994) FALSE by construction. Verb prefix + doc-comment ≠ enforcement.

**Preferred design**: separate `TrustedVoteIngest` trait with `ingest_approve`/`ingest_reject` (params `&ProposalId, &DID, &GovernanceContext` — mirrors withdraw_vote/remove_departed_voter), implemented ONLY by keyless engines. Box<dyn GovernanceEngine> then has no ingest_* in scope → key-holder literally cannot reach it. Share the TALLY (quorum/dedup/deadline/status/events) via a private helper both approve and ingest_approve call — that's the real convergence goal, achieved without converging the trust model. WASM-only is correct per ADR-034; record as ADR-cited capability-matrix exemption, not an empty cell.

**Key facts**: every native engine holds a `KeyResolver` and signs+verifies every vote (majority.rs:386-478). WASM today reimplements tally inline with `signature: Vec::new()` (manager.rs:5239) — that reimpl must actually be RETIRED by this PR, else it's "half-done."

This resolves Q2 (default-impl vs forced): the separate-trait design dissolves it — keyless engines impl explicitly (no default), native engines don't impl at all. `ingest_` verb is fine; trust signal must ride the trait boundary, not the name.
