---
name: sec-1866-direct-execute-trust
description: SEC-1866 governance direct-execute quorum-bypass fix — by-id resolution from quorum-validated engine; SOUND
metadata:
  type: project
---

# SEC-1866 direct-execute trust boundary (commit 8ff63571a)

VERDICT: SOUND. Closes the direct-execute quorum bypass. No blocking findings.

**Core change:** `execute_governance_action` (governance_helpers.rs ~4500) signature changed
`proposal: &GovernanceProposal` + `executor_did: &DID` → `proposal_id: &ProposalId` + `executor_did: Option<&DID>`.
Resolves authoritative proposal via `state.governance.engine.get_proposal(proposal_id).cloned()`;
untracked id → `PermissionDenied("governance proposal not tracked")`. `executor_did.unwrap_or(&proposal.proposer_did)`.
Direct-execute (actor handler governance.rs:661) passes `None` → executor = tracked proposer.

**Why Approved is a sound quorum proxy:** all 4 engines (majority/multisig-threshold/unanimity/SingleAdmin)
verify each vote's Ed25519 sig via `verify_vote(proposal_id, signed_vote, DID-resolved key)` in record_vote/approve/reject
BEFORE recording, and only set `ProposalStatus::Approved` at genuine quorum (majority.rs:442 verify, 246/289/469 set).

**Snapshot restore = fresh engine:** `restore_governance_engine_from_snapshot` (state.rs:1514) reconstructs
ONLY config (signers/threshold/voters/window) via `Engine::new()`. All 4 engines init `proposals: HashMap::new()`
(majority 125, multisig 107, mod 1516, unanimity 97). NO proposal-restore path anywhere. So post-restore every
get_proposal(id)→None → reject. A previously-Approved id cannot be replayed across respawn. STRENGTHENING.

**Native↔WASM convergence (§9.9.3):**
- Native `finalize_governance_action` (3529) ALWAYS stamps leaf executor_did = `proposal.proposer_did` (3570/3583/3595),
  and dispatches consequences for `proposal.proposer_did` (3640-3645/3673) + action target (3646-3660/3694).
- WASM `execute_governance_action` (manager.rs committed HEAD 3077) signature dropped `action` param; resolves
  `tracked_action` from pending/resolved_proposals; leaf actor_did = executor_did (bridge passes proposer);
  consequence subject = initiator_did (bridge passes proposer) + target_did. MATCHES native exactly.
- WASM bridge `context_execute_governance` (context.rs) now takes ONLY (handle, proposal_id_hex). Resolves
  `proposal_proposer_did` from tracked state (manager.rs:4756), passes proposer for BOTH initiator+executor.
  No caller DID, no action_json — action substitution structurally impossible.

**Strict hex parse:** `validate_proposal_id_hex` (common/validate.rs:541) = hex::decode + try_into::<[u8;32]> →
matches native PyO3 `parse_proposal_id` (ffi/src/context.rs:1400, SCP-CTX-2040). WASM `parse_proposal_id_bytes`
(manager.rs) replaces old `hex::decode().unwrap_or_default()` zero-pad that could mint a DIVERGENT leaf proposal_id.
`ScpWasmError::proposal_id` (error.rs:149) → SCP-CTX-2040 matches native bridges (not generic VALID-7000).
PROTECTS #1865 leaf parity (shared scp_event_log::payload::GovernanceActionExecutedPayload unchanged both sides).

**WASM no-key-resolver (ADR-034) limitation:** WASM votes have empty sigs (signature: vec![]) — Approved set by
local vote-count tracking, NOT Ed25519 verification. This is unchanged by the fix (tracked-status authority both
before+after); fix only removes action-substitution + caller-DID-injection facets = strengthening. Equivocation
detection at §9.9.3 catches divergent WASM member. ACCEPTABLE DOCUMENTED LIMITATION, not regression.

**LOW (doc only):** `ExecuteGovernanceActionPayload` doc-comment (commands.rs:1071) says "plus the authenticated
executor DID" but struct has NO executor field (only context_id + proposal_id). Stale comment; behavior correct.
