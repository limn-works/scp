# PR-2b WASM polish/hardening (manager.rs) — landed f4e4d7c52

Worktree `.claude/worktrees/1900-pr2b-wasm`, branch `wasm/1900-pr2b-engine-adoption`.
TOOL GOTCHA: agent default cwd IS the worktree; `cd /Users/alec/Developer/limn/scp`
jumps to the MAIN repo (separate checkout on `main`) — git diff there shows NOTHING.
Read/Edit tools were STALE on this 15k-line file; use sed/grep + python heredoc.

## FIX A — approve/reject returned status mismatched stored resolved status
- `approve_governance_proposal` hardcoded `"Pending"` in its tail; only `meets_quorum`
  returned `"Approved"`. A past-deadline approve on Majority below the 5000-bps floor
  resolves (engine precheck auto-resolves WITHOUT recording the vote, majority.rs:380)
  to `Rejected{InsufficientParticipation}` and STORES it (proposal.status=post_status)
  but RETURNED "Pending". Real legibility bug.
- `reject_governance_proposal` only special-cased `Rejected{..}` → "Rejected", else
  "Pending". A past-deadline reject whose at-deadline tally is approvals>rejections with
  quorum met resolves to `Approved` (majority.rs:288) → returned "Pending" (wrong).
- FIX: added `proposal_status_label(&ProposalStatus)->&'static str` single-source helper
  (also refactored withdraw + get_proposal inline matches to it). Both approve/reject
  tails now: if `!Pending` move pending→resolved + return actual label. Reject path NEVER
  executes even when tally is Approved (rejecter is not an executor).
- Engine fact: past-deadline vote does NOT error (majority.rs:334); resolve() runs on
  ALREADY-RECORDED votes, new vote dropped.

## FIX B/C/D — imported member set
- `role_state.members` (HashSet<String>, roles.rs:1496 pub) was per-DID-validated on import
  (import_context loop) but NOT capped; only live add_member capped at WASM_MEMBER_CAP=10_000.
- Renamed `validate_imported_governance_sets`→`validate_imported_governance_and_member_sets`,
  added members cap+per-DID-validate FIRST, re-pointed doc (the old "replays carried votes
  O(proposals×votes×voters)" justification was stale — replay deleted in FIX 1).
- Moved the call OUT of validate_imported_antispam_state (ran AFTER resolve_governance_config)
  and INTO import_context BEFORE resolve (replacing the redundant member loop). Now the cap is
  a true gate ahead of resolve/build. Also moved an orphaned antispam doc block to its fn.

## FIX E — clarity
- Renamed test `pr2b_majority_fixed_floor_resolves_at_native_boundary` →
  `pr2b_majority_absolute_majority_boundary_matches_native`: it exercises the EARLY-APPROVE
  absolute-majority bar (`approvals*2>eligible`, pre-deadline), NOT the deadline participation
  floor. Two distinct bars.
- "PROTOCOL-FIXED constant" comments corrected: ADR-031 `min_participation_bps` is CONFIGURABLE
  (range (0,10000]), default 5000; not wired configurable on EITHER bridge (native hardcodes
  default in MajorityVoteEngine::new(voters,86_400,5000,..)). Convergence requires lockstep if
  ever wired.

## Tests added
- pr2b_approve_past_deadline_reports_resolved_rejected_status (force voting_deadline=1, approve
  2nd voter → Rejected{InsufficientParticipation}; assert returned==stored label, moved to
  resolved, no executed leaf).
- pr2b_reject_past_deadline_reports_resolved_approved_status (2 approvals+1 rejection recorded,
  past deadline, 4th reject → Approved tally; assert "Approved", NO execution).
- validate_governance_and_member_sets_rejects_members_over_cap / _rejects_invalid_member_did.
- Test seam: child `mod tests` reads/mutates PRIVATE fields contexts/pending_proposals/
  resolved_proposals + pub voting_deadline. Native test clock = real SystemTime (~1.7e9s), so
  voting_deadline=1 = far past.

## Verify (light, per task — orchestrator runs heavy CI)
- cargo fmt --all --check clean; clippy wasm32 + native --all-targets -D warnings clean
  (caught: post_status move→clone; 2× collapsible_if; iter_on_single_items in a test).
- governance 27, import 10, pr2b 15, validate 65, manager:: 157 — all pass.
