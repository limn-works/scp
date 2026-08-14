# SEC-1866 — governance direct-execute quorum-bypass fix (c9db30486)

Branch fix/1866-direct-execute-trust. Reviewed `a632c731a..HEAD`. VERDICT: CLEAN (no real defects).

## What it does
`execute_governance_action` was reworked from taking a caller-supplied
`proposal: &GovernanceProposal` + `executor_did: &DID` to taking
`proposal_id: &ProposalId` + `executor_did: Option<&DID>`. Re-fetches the
authoritative proposal from `state.governance.engine.get_proposal(proposal_id)`
(engine only sets Approved at genuine quorum). `ExecuteGovernanceActionPayload`
changed `proposal` → `proposal_id` (kept `context_id` so routing intact).
All 4 bridges + 4 SDK wrappers updated. WASM dropped `action_json`. New
`#[cfg(feature="testing")]` `TestInsertMember` seam.

## Pre-fix bypass (why it mattered)
- NAPI `context_execute_governance_action_on` minted a RANDOM proposal_id and
  fabricated a fully `ProposalStatus::Approved` proposal from caller action,
  executed with NO engine involvement. PyO3/UniFFI deserialized a caller
  proposal JSON and trusted its status. Both = quorum bypass. Now closed.

## Verification performed
- Both internal callers (propose_governance_action_inner SingleAdmin auto-exec
  L3139, vote_on_proposal_inner quorum path L3455) pass Some(proposer)/Some(voter)
  → byte-identical executor attribution to before. Proposal is engine-tracked
  (multisig propose L307 inserts; approve inserts) so re-fetch always finds it.
- `executor_did.unwrap_or(&proposal.proposer_did)` — None only on direct FFI
  path; resolves to tracked proposer (not caller DID). Correct, no wrong-leaf.
- check_commit_fault moved to top (before status/context checks) — read-only,
  only reorders error precedence, no correctness impact.
- parse_proposal_id (PyO3 L1400) / parse_napi_proposal_id / parse_uniffi_proposal_id
  all handle bad hex + wrong length (try_into [u8;32]). Correct.
- `identity_did` accepted by all bridges but DROPPED (not in payload). This is
  BY DESIGN: WASM doc explicitly states "Authorization is NOT a per-member
  execute-time capability check" — safety = Approved status + replay guard +
  propose-time auth + per-action ceiling gate. NOT a bug. NAPI/UniFFI use
  `let _ = &identity_did;` without validate_did (PyO3+WASM do validate) — minor
  cosmetic inconsistency only, identity_did is unused so no security gap.
- TestInsertMember properly testing-gated at all 5 layers (command variant,
  supervisor method, handlers::messaging dispatch arm, actor mod ack_not_impl
  fallback, handler fn). dispatch_command takes explicit context_id arg so
  ignored `context_id: _` field is fine. No prod leak.
- AST assertions in pipeline_wiring.rs: extract_fn_signature uses first
  `fn execute_governance_action(` — only ONE such def in MANAGER_SRC concat
  (governance_helpers.rs); `handle_execute_governance_action_actor` doesn't
  collide (different name after `fn `). Correct target.
- consequence-subject native-vs-WASM divergence is PRE-EXISTING (task #205),
  not introduced; native used executor_did for consequences before+after.

## Tests run (ALL PASS)
- scp-runtime --features testing: governance_integration direct_execute (3)
- scp-ffi-wasm: manager direct_execute (3 — run natively, wasm32 getrandom
  toolchain failure unrelated)
- scp-testing pipeline_wiring: AST assertions (60 total, incl 2 new)
- scp-ffi --features allow_in_memory_custody: direct_execute (2)
- scp-testing fullstack: direct_execute (2 — genuine multi-node majority quorum)
- clippy -p scp-ffi-napi -p scp-ffi-uniffi --all-targets w/ CI features: clean
KATs are substantive (not tautological): forgery tests snapshot membership
before/after; genuine tests drive real 2/3 Majority quorum + replay guard.

## LESSON (process)
- The Read tool and Bash `cd` resolved to the MAIN repo
  (/Users/alec/Developer/limn/scp, on b321248e1) NOT the worktree
  (.claude/worktrees/sec-1866 on c9db30486) when I gave a main-repo abs path.
  First Read of governance_helpers.rs showed STALE main-branch content (old
  signature at L3757). ALWAYS use the full worktree path
  `/Users/alec/Developer/limn/scp/.claude/worktrees/sec-1866/...` for Read, and
  default-cwd Bash (no cd) runs in the worktree. Cross-check `git show HEAD:file`
  against Read output when line numbers disagree with the diff.
