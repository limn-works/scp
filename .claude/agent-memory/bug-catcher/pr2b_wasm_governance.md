### #1900 PR-2b WASM governance engine adoption (f4e4d7c52) — review

Commit: WASM adopts shared TrustedVoteIngest engine (ingest_proposal/ingest_approve/ingest_reject).
Transient engine rebuilt per-op (engines not Clone/Serialize), seeded from WASM's own stored
proposal, vote tallied, result mirrored back + persisted.

CLEAN: ingest_proposal (3 engines: majority/multisig/unanimity) — frozen-set check on proposer_did,
DuplicateProposal on existing id, verbatim insert (consumes by value, no borrow issue). Terminal stays
terminal (later ingest_* → ProposalNotPending). proposal_status_label exhaustive (6 variants).
post_status.clone() borrow-correct. validate_imported_governance_and_member_sets caps members +
voters + signers BEFORE resolve_governance_config consumes them. Old validate_imported_governance_sets
fully removed, no dangling refs.

### FINDING (MEDIUM) — past-deadline majority auto-resolve: WASM records the vote, native does not
manager.rs approve_governance_proposal ~5882-5895 (and reject ~6043-6052): the new vote is pushed
onto proposal.approvals/rejections UNCONDITIONALLY whenever the proposal is still pending, BEFORE the
terminal-status check. But majority precheck_vote (scp-protocol majority.rs ~382) auto-resolves a
past-deadline vote WITHOUT recording it (returns PrecheckOutcome::Resolved, vote never pushed into
engine's owned proposal). Native's source-of-truth IS the engine's owned proposal
(governance_helpers.rs vote_on_proposal_inner — no separate vote mirroring), so native's persisted
resolved proposal does NOT carry the past-deadline vote; WASM's DOES.
Observable via get_proposal (full approvals/rejections list surfaced verbatim). Native↔WASM divergence
in persisted proposal vote set — exactly the §9.9.3 convergence class FIX A is closing. Majority-only
(threshold/unanimity precheck returns VotingWindowExpired=Err past deadline, so the `?` propagates and
the push never runs). FIX A tests assert status but NOT stored.approvals/rejections.len(), so unguarded
and untested. Fix: only push the vote if the engine actually recorded it — i.e. push only when
post_status is non-terminal OR (better) gate the push on whether precheck proceeded vs auto-resolved.
Simplest correct: skip the push when the proposal is being moved to resolved via the past-deadline
auto-resolve branch (engine didn't count it).

Known-filed (do not re-raise): #1926 reject-execute divergence, #1927 import caps.
