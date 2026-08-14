# PR2A Governance precheck/push_and_resolve split + TrustedVoteIngest (commit 9f9f059ef)

VERDICT: GO. No exploitable vote-counting / tally / bypass found. Clean extract-method refactor.

## What the refactor did
- Each engine (majority/multisig/unanimity) splits vote into `precheck_vote` (guards →
  PrecheckOutcome::{Proceed,Resolved}) + `push_and_resolve` (push vote + tally).
- Signed path: precheck → sign_vote → resolve key → verify_vote → push_and_resolve.
  verify is STRICTLY before push (majority.rs:553-566, multisig/unanimity analogous). Confirmed.
- Keyless `TrustedVoteIngest` (ingest_approve/reject): precheck → build_unsigned_vote
  (empty sig) → push_and_resolve. NO verify by design (ADR-034 WASM no-key custody).
- scp-core/lib.rs: facade re-export changed from `*` glob to explicit list OMITTING
  `TrustedVoteIngest` only. Verified: diff of full pub-symbol set vs re-export list =
  ONLY TrustedVoteIngest omitted, zero accidental drops.

## Attacks PROVEN closed (probes written, all passed)
1. Forged sig on signed path NOT counted (InvalidSignature, approvals.len()==0).
2. Native CANNOT call ingest_* on Box<dyn GovernanceEngine> — E0599 confirmed by
   compiling test target with the bypass uncommented. TrustedVoteIngest is a SEPARATE
   trait (not supertrait of GovernanceEngine), no blanket impl, no downcast/Any, 3
   concrete impls only. scp-runtime uses Box<dyn GovernanceEngine> exclusively.
3. Majority past-deadline auto-resolve CANNOT flip to Approved: precheck returns
   Resolved(resolve()) WITHOUT recording the late vote; resolve sees only honest votes
   (1/3 = 3333bps < 5000 quorum → InsufficientParticipation). No double-resolve on terminal.
4. Quorum boundary exact (2 of 4 NOT majority, 3 of 4 is). Ingest tallies frozen
   eligible_voter_dids, not context membership.
5. ingest-resolved Approved proposal FAILS verify_proposal_votes (empty sigs) — this is
   the §9.9.3 equivocation compensating control. Signed vs ingest reach IDENTICAL status.

## KEY OBSERVATION (not a vuln, but note)
- TrustedVoteIngest is DEAD CODE at this commit: NO caller in workspace. WASM bridge has
  ZERO governance/vote wiring (grep clean). Doc claims "WASM bridge uses this path" but it
  doesn't yet. Trait + impls + tests exist; wiring is future. proposer implicit vote
  (multisig/unanimity `approvals: vec![proposer_vote]`) is SIGNED+verified at propose time,
  so no keyless implicit-vote injection even when wired.
- multisig/unanimity precheck_vote take &self (immutable, only Proceed/Err); the Resolved
  arm is genuinely unreachable for them (documented). Majority precheck takes &mut self
  for the past-deadline resolve.

## Build/test status
- scp-protocol lib: 339 governance tests pass (330 orig + 9 probes).
- scp-core + scp-runtime build clean with facade change (disk-full flake unrelated).
