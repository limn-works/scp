---
name: pr1866-direct-execute-quorum-bypass
description: #1866 governance direct-execute quorum-bypass fix assessment — original CRITICAL forgery, fix is sound, no new exploitable chain
metadata:
  type: project
---

# #1866 Direct-Execute Governance Quorum-Bypass Fix (branch fix/1866-direct-execute-trust, 8ff63571a)

## Original vulnerability (CRITICAL, now closed)
Pre-fix (`a632c731a`), ALL native bridges (NAPI/PyO3/UniFFI) `context_execute_governance_action_on`
took `(handle, action_json, proposer_did)`, minted a RANDOM proposal_id (OsRng), and constructed
`GovernanceProposal { status: ProposalStatus::Approved, action: <caller-supplied>, approvals: Vec::new() }`
handed verbatim to the runtime via `ExecuteGovernanceActionPayload { proposal }`. Runtime trusted
`payload.proposal` directly. Result: any holder of a context handle could execute ANY governance
action (ban, ChangeRole, TransferAdmin, ModifyCeiling) with ZERO approvals, no signature, no quorum.
Quorum bypass + action forgery in one call. (napi/src/context.rs old line 2753-2758, mirror in pyo3/uniffi.)

WASM was NOT vulnerable to the fabrication: pre-fix WASM execute already had `require_proposal_approved`
+ tracked-proposal lookup, so a fresh random id failed the status gate. WASM's TS SDK generated a
random id but it would be rejected. (Real bypass was native-only.)

## Fix (sound)
- Payload now `ExecuteGovernanceActionPayload { context_id, proposal_id }` — id only.
- `execute_governance_action` (governance_helpers.rs ~4499) resolves proposal via
  `state.governance.engine.get_proposal(proposal_id)`; rejects untracked (PermissionDenied "not tracked");
  requires `status == Approved` (engine sets this only at verified quorum); context_id match; replay via
  executed_proposals; executor resolved from `proposal.proposer_did` (None arg on direct path).
- All 4 bridges: strict `[u8;32]` hex parse (CTX-2040). WASM adds `validate_proposal_id_hex` +
  `parse_proposal_id_bytes` replacing old `hex::decode(..).unwrap_or_default()` zero-pad.
- Propose-time auth unchanged & still gates: `propose_governance_action_inner` checks GovernancePropose
  cap (checked path), engine signs+verifies, only Checked propose reachable from FFI.

## Trust chain rests on
Engine `Approved` status = quorum-verified. The by-id execute trusts engine state. Sound on native
(real engines, sign_vote, KeyResolver). WASM quorum path uses empty `signature: Vec::new()` votes
(NEVER verified) — PRE-EXISTING WASM trust model (ADR-034), NOT introduced by #1866, out of scope.

## Tests are genuine (not passing for wrong reason)
- governance_integration.rs: real ThresholdEngine/Majority/Unanimity, sign_vote, multi-voter quorum
  (ac3: Alice 1/2 propose + Bob vote → 2/2 → auto-execute via by-id).
- fullstack.rs: genuine propose→approve→quorum then by-id replay-rejected; forgery (untracked id) rejected.
- TestInsertMember seam fully `#[cfg(feature="testing")]`-gated (command variant, handler, supervisor method).

## Verdict: CRITICAL quorum-bypass CLOSED. One residual MEDIUM stands at HEAD 8ff63571a.
- **RED-1101 (MEDIUM, CONFIRMED at HEAD) — conflict-freeze bypass via direct-execute.**
  `execute_governance_action` (governance_helpers.rs ~4499) checks ONLY status==Approved + ctx + replay.
  NO freeze / invalidated_by_conflict check. handler handle_execute_governance_action_actor (governance.rs
  ~657) explicitly comments "NO executor capability check... unprivileged finalization step."
  During a same-sequence conflict freeze (detect_and_handle_conflicts Ordering::Equal sets
  governance.freeze=(a,b,start) and DEFERS both — neither executed), BOTH proposals are status==Approved
  in the engine and neither is in executed_proposals (loser only marked executed by execute_resolve_conflict
  ~2197). Any member holding a context handle can call governance_execute(handle, a) AND (handle, b) to
  run BOTH mutually-exclusive approved actions, defeating conflict serialization (unilateral winner select +
  double-apply). All 4 bridges funnel through this fn. Fix: re-check freeze + invalidated_by_conflict
  inside execute_governance_action.
- **RED-1102 (LOW) — no execute-time capability/membership check on direct path** (by design per comment;
  enables RED-1101). Consider gating to context membership at minimum.
- WASM empty-signature quorum votes (pre-existing, ADR-034 reduced trust) — by-id now depends on it but unchanged.
- Pre-existing 14-day replay window past marker TTL = #1872 (already filed, do not re-report).
