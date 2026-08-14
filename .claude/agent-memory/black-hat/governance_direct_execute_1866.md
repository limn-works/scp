# Governance direct-execute quorum-bypass fix (#1866, FINAL HEAD 08222318c)

## FINAL pass (08222318c) — CLEAN, both prior MEDIUMs CLOSED, no new exploitable finding
- Prior 2 MEDIUMs both resolved by commits 9b0f52ac5..08222318c:
  - identity_did MEDIUM: param now REMOVED entirely (not just `let _=`) from all 4
    bridges + all 4 SDK wrappers. Uniform `(handle, proposal_id_hex)`. Removed no
    authz (none existed; authz = propose-time + per-action ceiling in dispatch).
  - WASM malformed-hex MEDIUM: `validate_proposal_id_hex` (common/validate.rs) +
    `parse_proposal_id_bytes` (wasm/manager.rs) replace `hex::decode().unwrap_or_default()`
    + truncate/zero-pad. Strict 32-byte everywhere. Boundary rejects malformed via
    ScpWasmError::proposal_id → SCP-CTX-2040 (matches native PyO3/UniFFI/NAPI surface).
    Applied to execute/propose/approve/reject/withdraw/get_proposal.
- Consequence-subject convergence (task #205) RESOLVED on direct path: WASM bridge
  resolves proposer via proposal_proposer_did, passes it for BOTH initiator_did
  (consequence subject, dispatch_consequences_for_subject l.3242-45) AND executor_did
  (leaf actor_did). Native: executor_did.unwrap_or(&proposal.proposer_did) (helper
  l.4551) → leaf actor=proposer; consequence subject = proposal.proposer_did. Both
  platforms direct-execute: leaf actor=proposer, subject=proposer. Converged.
- proposal_proposer_did reads SAME pending.or_else(resolved) keyed by same id, in
  SAME with_manager closure; WASM single-threaded RefCell ⇒ no TOCTOU/divergence
  between proposer-for-leaf and proposal-actually-dispatched.
- Strict hex can't open new path: bridge validates hex FIRST (early return); the
  in-execute parse_proposal_id_bytes runs only AFTER require_proposal_approved +
  tracked lookup succeed ⇒ malformed id never reaches a tracked Approved proposal.
  executed_proposals replay keyed by raw hex string, unchanged. Rollback on dispatch
  err intact (l.3163-68).
- pipeline_wiring assertion STRENGTHENED (not weakened): now positively asserts WASM
  context_execute_governance signature has NO identity_did AND NO action_json AND has
  proposal_id_hex (extract_fn_signature on source). Closed-by-construction.
- Last 3 commits (8ff63571a/abf28753b/08222318c) VERIFIED doc/comment-only: filtering
  all comment/blank/file-header lines from 3834898f0..HEAD leaves ZERO changed lines.
- ALREADY FILED (not re-reported): #1871 (conflict-freeze dead code), #1872 (14d replay TTL).

# Governance direct-execute quorum-bypass fix (#1866, commit c9db30486)

## What the bug was (pre-fix, CRITICAL — confirmed real)
- NAPI bridge `context_execute_governance_action_on`: took caller `action_json` +
  `proposer_did`, GENERATED A RANDOM proposal_id, fabricated a fully `Approved`
  GovernanceProposal with EMPTY approvals, executed it. Total quorum bypass, no
  engine involvement. Worst case.
- TS WASM SDK path: same shape — `generateProposalIdHex()` + `actionJson`.
- PyO3/UniFFI: accepted caller-supplied full `GovernanceProposal` JSON (incl.
  caller-set status=Approved) → execute trusted it.

## The fix (sound)
- `execute_governance_action(state, deps, ctx, proposal_id: &ProposalId, executor_did: Option<&DID>)`
  in governance_helpers.rs. Resolves proposal via `state.governance.engine.get_proposal(proposal_id).cloned()`,
  rejects untracked ("not tracked"), rejects non-Approved, context_id match,
  replay guard (class_s.executed_proposals), check_commit_fault. executor=None →
  tracked proposer (never caller DID).
- 3 native callers all source id from engine state (propose auto-exec Some(proposer),
  vote quorum Some(voter), direct-execute handler None).
- All 4 bridges converge to `(handle, identity_did, proposal_id_hex)`. WASM dropped action_json.
- WASM manager resolves BOTH action + created_at from tracked proposal
  (pending_proposals.or_else(resolved_proposals)); no action param. Action
  substitution structurally impossible.
- pipeline_wiring AST assertions: native sig has `proposal_id: &ProposalId` and
  NOT `proposal: &GovernanceProposal`; body has `engine`+`get_proposal(proposal_id)`+`not tracked`;
  WASM surface has no `action_json`. Positive/closed-by-construction.

## Residual findings (NOT bypasses)
- `identity_did` (caller) is format-validated on PyO3/WASM but NOT on UniFFI/NAPI
  (`let _ = &identity_did`). Decorative everywhere — no per-caller GovernanceExecute
  capability check exists ANYWHERE (no such capability in codebase). Pre-fix had
  none either; not a regression. Authorization is at propose-time + per-action
  ceiling gate in dispatch. LOW.
- WASM keys proposals by raw hex STRING; tolerates malformed/short/long via
  `hex::decode(...).unwrap_or_default()` + truncate/zero-pad at propose AND execute.
  3 native bridges strictly require exactly 32 bytes (try_into). Cross-bridge
  input-validation divergence + potential §9.9.3 leaf-byte divergence source.
  NOT a quorum bypass (still need genuinely tracked Approved proposal). MEDIUM convergence.

## Test seam (clean)
- TestInsertMember / MessagingCommand::TestInsertMember: `#[cfg(feature="testing")]`
  at all 4 sites (command, supervisor method, dispatch arm, legacy actor mod ack).
  Pure role-state insert, no MLS. Never compiled into prod, never reachable from FFI.

## GOTCHA: diff base in prompt was wrong
- Prompt said `a632c731a..HEAD`. The sec-1866 worktree HEAD = c9db30486 (the fix).
  a632c731a is c9db's PARENT (PR #1865). Correct review base = c9db30486^..c9db30486.
  When bash cwd resets to main repo it reads b321248e1 (feat/actor-2c) — STALE,
  lacks the fix. ALWAYS run git from the worktree path or it reads main's branch.
