---
name: sec-1866-direct-execute-trust
description: Adversarial confirmation of #1866 governance direct-execute quorum-bypass fix (abf28753b) — no new exploitable issues
metadata:
  type: project
---

# #1866 Governance direct-execute trust boundary — adversarial pass (CLEAN)

Range `a632c731a..abf28753b`. Direct-execute now takes ONLY a proposal_id; the
authoritative proposal/action/status/executor are resolved from the actor's own
quorum-validated engine. Closed the quorum-bypass + action-substitution +
spoofed-executor + forged-id facets.

**Why:** prior NAPI direct-execute generated a RANDOM proposal_id via OsRng and
accepted a caller-supplied proposal+action — fully forgeable. Now structurally impossible.

## Trust boundary (verified solid)
- Native `execute_governance_action` (governance_helpers.rs ~4499): resolves via
  `engine.get_proposal(proposal_id)`, rejects untracked, checks status==Approved,
  checks `proposal.context_id == context_id` (no cross-context injection), replay
  guard via `executed_proposals` (insert-before-dispatch, rollback on err), all in
  single linear actor sequence (no TOCTOU). executor_did=None on direct path →
  resolved from tracked `proposal.proposer_did`.
- Engine keys by proposal_id; stored proposal.proposal_id == key → replay marker consistent.
- WASM manager.execute_governance_action: bridge surface `context_execute_governance(handle, proposal_id_hex)` only — NO action_json param → action substitution structurally impossible. action+created_at resolved from tracked proposal; require_proposal_approved requires Approved; replay via executed_proposals.
- WASM consequence subject = initiator_did = resolved proposer (manager.rs:3244) → converges with native proposer subject (governance_helpers.rs:4382/4414). Task #205 converged.
- Strict 32-byte hex everywhere: PyO3 parse_proposal_id (CTX-2040), NAPI parse_napi_proposal_id (CTX-2040), UniFFI parse_uniffi_proposal_id (CTX-2040), WASM validate_proposal_id_hex + parse_proposal_id_bytes (CTX-2040 via ScpWasmError::proposal_id). Replaced WASM's old hex::decode().unwrap_or_default()+zeropad (would mint divergent all-zero id).
- All 4 SDK wrappers take only proposalIdHex — no silently-dropped executor/action.

## Test seam (not exploitable)
- `TestInsertMember` (commands.rs / supervisor.rs:9694 / messaging.rs:200) fully
  `#[cfg(feature="testing")]`; non-testing actor arm = ack_not_impl. Mirrors existing
  SeedPeerPseudonym seam. Never in prod, never reachable from FFI.

## Already filed (do NOT re-report): #1871 (conflict freeze Equal arm dead), #1872 (14d replay TTL).

VERDICT: No NEW exploitable issue found.
