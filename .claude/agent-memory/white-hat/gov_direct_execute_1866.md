---
name: gov-direct-execute-1866
description: Defensive review of #1866 governance direct-execute by-id fix (quorum bypass closure) — freeze/conflict-loser gate gap
metadata:
  type: project
---

# #1866 Governance Direct-Execute By-Id (branch fix/1866-direct-execute-trust, c9db30486)

Fix replaces caller-supplied proposal/action/status with execute-by-id: `execute_governance_action(state, deps, context_id, proposal_id: &ProposalId, executor_did: Option<&DID>)` resolves authoritative proposal from `state.governance.engine.get_proposal(id)`, rejects untracked + non-Approved. Engine is sole status authority (governance/mod.rs L12 "callers cannot set status directly").

**Why:** closes quorum-bypass + action-substitution across all 4 FFI bridges.

**How to apply when reviewing follow-ups:**

## CORE PROPERTY: SOUND
No-execution-without-engine-Approved is enforced by construction on every bridge. Forgery/untracked/Pending/Rejected/Invalidated/Withdrawn all fail-closed (PermissionDenied). Replay guarded by `executed_proposals` (TTL-evicted, rollback on dispatch failure). KATs pin forgery-rejection + no-state-change + single-exec + replay on native + cross-bridge fullstack.

## P1 GAP: direct-execute skips conflict-loser / freeze gate (asymmetric vs quorum path)
- governance_helpers.rs `execute_governance_action` (~L4525-4612) checks: commit-fault, tracked, Approved, context-id, replay. Does NOT check `state.governance.freeze` NOR `invalidated_by_conflict`.
- Quorum path `vote_on_proposal_inner` (~L3446-3463) gates inline execute on `!in_freeze && !invalidated_by_conflict`.
- Conflict resolution (`detect_and_handle_conflicts` ~L617) removes loser from runtime `approved_proposals` map ONLY; engine's stored `proposal.status` stays `Approved` forever. So a conflict-LOSER proposal: engine=Approved, not in executed_proposals → direct-execute `governance_execute(handle, did, loser_id)` APPLIES it. Quorum path would have refused.
- Freeze comment (L594-608) says freeze is "NOT an authorization control, a liveness safety valve" → freeze-skip is LOW. But conflict-loser-skip lets a member force-apply a proposal quorum-conflict-resolution rejected → real defense gap.
- No KAT covers conflict-loser direct-execute.
- FIX (bounded): in execute_governance_action, after Approved check, reject if `state.governance.approved_proposals` does not contain proposal_id (positive whitelist — the runtime's own "currently-applicable approved set"), OR explicitly reject conflict-loser + in-freeze. Add KAT.

## Cross-bridge divergence (pre-existing, widened): WASM has NO conflict detection
- WASM manager.rs: `governance_freeze` only ever set false; no `detect_and_handle_conflicts` analogue; conflict-loser invalidation ONLY via manual `ResolveConflict` action (writes loser into executed_proposals). Native auto-detects on approve. Native↔WASM already diverge on conflicts independent of #1866.

## P2: direct-execute has no per-caller capability check
- PyO3 governance_execute: `identity_did` validated for format but NOT passed to runtime; payload carries only proposal_id; executor resolved server-side from tracked proposer. Any handle-holder executes any tracked-Approved proposal. Intentional (already passed quorum) but identity_did is cosmetic/misleading on this path — could be removed or actually enforced as membership check.
