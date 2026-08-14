---
name: pr1866-direct-execute-quorum
description: Red-team assessment of #1866 governance direct-execute quorum-bypass fix (commit c9db30486)
metadata:
  type: project
---

# #1866 Direct-Execute Quorum-Bypass Fix Assessment (2026-06-22, commit c9db30486)

The fix: `execute_governance_action` now takes `proposal_id` (+ Option executor DID for
internal callers) instead of a caller-supplied `GovernanceProposal`. Resolves authoritative
proposal from `state.governance.engine.get_proposal(id)`, checks status==Approved + context_id
+ replay (`executed_proposals`). Quorum bypass + action substitution are CLOSED — caller can no
longer fabricate an Approved proposal. Native majority/multisig engines verify Ed25519 vote sigs
before setting Approved (majority.rs:437,530,470). WASM keeps its pre-existing string-DID vote
trust model (empty sigs) — unchanged by this fix, consistent with ADR-034 single-trusted-process.

## FINAL confirmation (2026-06-23, HEAD 08222318c, diff a632c731a..08222318c)
Full #1866 fix re-reviewed end to end. VERDICT: NO new exploitable chain. APPROVED.
- All 4 bridge surfaces (PyO3 governance_execute, NAPI context_execute_governance_action_on,
  UniFFI governance_execute, WASM context_execute_governance) take ONLY (handle, proposal_id_hex).
  No caller action / status / identity at ANY layer. NAPI's old fabricate-random-id+Approved-proposal
  path DELETED. TS WASM internal path's generateProposalIdHex()+actionJson DELETED.
- All 4 SDK wrappers (Py/Swift/Kotlin/TS) take only proposal id.
- Runtime `execute_governance_action` resolves proposal from `state.governance.engine.get_proposal(id)`
  (per-context engine — context-scoped, no cross-context id collision). executor_did = Option; None on
  direct path → defaults to TRACKED proposal.proposer_did. Status check uses engine's own status.
- All 4 hex parsers strict (hex::decode + try_into::<[u8;32]>); WASM via validate_proposal_id_hex →
  SCP-CTX-2040, matching native. Zero-pad/truncate path GONE.
- RED-1101: CONFIRMED false positive / dead code, filed #1871 — do NOT re-raise.
- RED-1102 misleading-comment facet: FIXED this diff (08222318c + abf28753b comment sweep). Docstrings
  now correctly state direct-execute has NO per-member capability check by design (quorum is the
  authority). The "any member can finalize an already-Approved proposal" semantic is intentional and
  documented; not a new chain.
- TestInsertMember seam: still #[cfg(feature="testing")] across command/handler/actor-stub/supervisor.
  Unreachable in production. No regression.
- #205 (consequence-subject divergence) + #206 (WASM per-action leaf parity) out of scope, filed.

## Residual findings (pre-final, retained for history)

- **RED-1101 (MEDIUM) — conflict-freeze bypass via direct-execute.** [RESOLVED as #1871 — dead code]
  `execute_governance_action` (governance_helpers.rs ~4525) checks ONLY status==Approved + ctx +
  replay. It does NOT consult `state.governance.freeze` or `invalidated_by_conflict`. The quorum
  auto-execute path (vote_on_proposal_inner ~3446) gates on `!in_freeze && !invalidated_by_conflict`.
  During a same-sequence conflict freeze, BOTH conflicting proposals are status==Approved in the
  engine and neither is in `executed_proposals` yet (loser only marked executed at ResolveConflict,
  ~2200). So any caller with a context handle can `governance_execute` either/both frozen proposals,
  defeating conflict-resolution serialization (unilateral winner selection + double-apply of
  mutually-exclusive approved actions). actions_conflict matrix: ChangeRole/RemoveMember/Suspend*/
  Revoke*/Restore* on same DID, ModifyCeiling/Threshold/Pruning/Reconfigure/RotateContentKeys.
  NOT a quorum bypass (both actions WERE approved) — it's a freeze/ordering-control bypass.
  Fix: re-check freeze + conflict-invalidation inside execute_governance_action (all bridges
  funnel through it). Affects native PyO3/UniFFI/NAPI (all call same fn).

- **RED-1102 (LOW) — no execute-time capability/membership check on direct path; misleading comment.**
  handlers/governance.rs:~669 comment says "executor is the authenticated caller (capability check)"
  but NO capability check exists. ExecuteGovernanceActionPayload carries only context_id+proposal_id;
  PyO3 drops `identity_did` entirely (context.rs:3041 validate_did format-only, never used).
  Low impact alone (only Approved proposals run, once each) but it's the enabler for RED-1101 and any
  future freeze-like deferred-execution gate. Fix: thread caller DID + require membership/governance
  capability, or document that direct-execute is intentionally any-member.

## Confirmed SAFE
- TestInsertMember seam: `#[cfg(feature="testing")]` at command/supervisor/handler/dispatch. FFI
  `testing` feature → scp-core/testing → scp-runtime/testing. NOT in `default=["server"]`; only CI
  passes --features testing. NAPI "testing unconditional" comment refers to scp-platform/testing, NOT
  the bridge's own testing feature. WASM test seams all `#[cfg(test)]`. Unreachable in production.
- Forged/untracked proposal_id: rejected PermissionDenied (engine never tracked it). KAT-covered.
- Action substitution: structurally impossible (no action field in payload; WASM resolves action
  from tracked proposal, manager.rs ~3104).
- Malformed hex: native all use hex::decode + try_into::<[u8;32]> (strict 32-byte, case-insensitive),
  consistent across PyO3/NAPI/UniFFI. WASM keys by hex STRING (case-sensitive) — divergence but not a
  bypass.
- Replay: executed_proposals guard, atomic check-and-mark before dispatch, rollback on dispatch err.
- Pending/withdrawn proposal: status!=Approved → rejected.
