# Governance direct-execute quorum-bypass fix (#1866) — c9db30486 — CLEAN

Reviewed `git diff a632c731a..HEAD` on branch fix/1866-direct-execute-trust.

## Vuln (pre-fix)
`governance_execute(handle, proposal_json)` took a caller-supplied full
`GovernanceProposal` JSON including `status: Approved` + arbitrary `action`.
Runtime trusted it → caller could fabricate an approved proposal / substitute
an action with zero quorum. WASM equivalently took caller `action_json`.

## Fix (VERIFIED CLOSED)
- Payload `ExecuteGovernanceActionPayload` now carries ONLY `proposal_id`
  (`ProposalId = [u8;32]`). No proposal/action/status/proposer field exists.
- `execute_governance_action(state, deps, ctx, proposal_id: &ProposalId,
  executor_did: Option<&DID>)` resolves the proposal from
  `state.governance.engine.get_proposal(proposal_id)` — engine only sets
  `Approved` at genuine quorum w/ Ed25519 vote verification. Untracked id →
  PermissionDenied "not tracked". Re-checks `Approved`, context match, replay.
- `executor_did.unwrap_or(&proposal.proposer_did)` — attribution always
  engine-sourced; `None` path (direct-execute) uses TRACKED proposer, never
  caller. Only 3 callers: propose-inner Some(proposer), vote-inner Some(voter),
  actor handler None. No stray None.
- All 4 bridges unified to `(handle, identity_did, proposal_id_hex)`. WASM
  dropped `action_json`; resolves both action AND proposer from tracked
  proposal (`tracked.action.clone()`). parsers reject non-hex/wrong-len, no panic.

## Authz model (BY DESIGN, symmetric native↔WASM, §9.9.3)
Execution is NOT gated by an execute-time per-member capability check.
Safety = propose-time authz + Approved status + replay guard
(executed_proposals) + per-action context-ceiling gate. `identity_did` is the
authenticated caller / consequence subject, deliberately NOT capability-checked
at execute and NOT threaded into payload. This is intentional and identical on
native + WASM. NOT a regression — pre-fix had no execute-time check either.

## OBSERVATION (minor, non-blocking, NOT a vuln)
DID-validation asymmetry on execute path: PyO3 calls `validate::validate_did
(identity_did)`; NAPI + UniFFI do `let _ = &identity_did;` (no validate_did).
Harmless because identity_did is discarded (never used for attribution/authz),
but inconsistent. Cosmetic only.

## check_commit_fault reorder
Moved BEFORE engine lookup. Read-only `&PerContextState`, no side effects →
strictly fail-closed, safe.

## Coverage
Forgery-reject + genuine-quorum-execute + replay-reject KATs at runtime
(governance_integration.rs ~2516-2640), PyO3 (context.rs tests), and WASM
(manager.rs tests). Native↔WASM reject identical forgeries (untracked id).
All 4 engine types (SingleAdmin/threshold/majority/unanimity) genuine flow tested.
TestInsertMember seam is `#[cfg(feature="testing")]` — never in prod/FFI.

No secret/error-leak/replay regression. Errors only echo the requested hex id
(public) and status enum. CLEAN.
