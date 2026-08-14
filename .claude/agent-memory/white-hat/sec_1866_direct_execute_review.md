---
name: sec-1866-direct-execute-review
description: Defensive review of #1866 governance direct-execute quorum-bypass fix (by-id resolution across all bridges)
metadata:
  type: project
---

# #1866 Direct-Execute Quorum-Bypass Fix — Defensive Review (2026-06-23)

Diff: a632c731a..abf28753b. ASSESSMENT: defenses adequate. No NEW gaps.

## The fix (closed-by-construction)
- `ExecuteGovernanceActionPayload` now carries ONLY `proposal_id: ProposalId` + `context_id`.
  The `proposal: GovernanceProposal` field is DELETED. There is no field to inject a forged
  Approved proposal/action/status/executor into. This is the core structural close.
- Native `execute_governance_action(state, deps, ctx, proposal_id: &ProposalId, executor_did: Option<&DID>)`
  resolves the authoritative proposal via `state.governance.engine.get_proposal(proposal_id)`.
  Missing → PermissionDenied("not tracked"). Status != Approved → PermissionDenied. ctx mismatch → denied.
  Replay marker uses `proposal.proposal_id` (engine value, not caller). Rollback on dispatch err.
- Direct-execute handler (handlers/governance.rs:680) passes `None` → executor resolved to
  `proposal.proposer_did`. Two internal callers pass `Some(proposer)` (auto-exec) / `Some(voter)`
  (quorum) with `&proposal.proposal_id`. No path lets caller inject executor DID on direct path.
- 4 bridges (PyO3, NAPI×2, UniFFI) take only `(handle, proposal_id_hex)`; strict 32-byte hex parse
  (parse_proposal_id / parse_napi_proposal_id / parse_uniffi_proposal_id / validate_proposal_id_hex).
  Old NAPI generated a RANDOM proposal_id + ran arbitrary action — that was the bypass; deleted.
- 4 SDK wrappers (TS/Swift/Kotlin/Py) take only proposalIdHex. No action/identity param.
- WASM: `context_execute_governance(handle, proposal_id_hex)` — no action_json. Manager resolves
  action AND proposer from tracked proposal. `require_proposal_approved` checks resolved||pending
  for Approved (pending never holds Approved — it's moved to resolved at quorum). Strict
  parse_proposal_id_bytes for the leaf. Encode-payload-before-emit fail-closed.

## Fail-closed verified on every path
unknown id → denied; Pending → denied (status check); withdrawn/rejected → denied; replay →
executed_proposals marker → denied; malformed hex → CTX-2040 at boundary (uniform across bridges);
encode failure → Err before leaf/emit (native + WASM).

## Convergence
Native + WASM both dispatch consequences for proposer (initiator) + action target. Both stamp
GovernanceActionExecuted actor_did = executor (proposer on direct path). Leaf timestamp = signed
proposal.created_at on both. KAT-pinned + signature-pinned (pipeline_wiring.rs positive assertions:
must take proposal_id:&ProposalId, must NOT take proposal:&GovernanceProposal, must call
engine.get_proposal). Behavioral KATs: forgery-rejected, no-state-change, genuine-once-then-replay.

## test_insert_member seam — SAFE
New TestInsertMember command/supervisor method/handler all `#[cfg(feature="testing")]`. scp-runtime
has NO default=[testing]; FFI bridges default=["server"], testing opt-in. Never compiled into
shipped artifact, never reachable from any bridge. mod.rs ack_not_impl fallback. Same pattern as
existing seed_peer_pseudonym seam.

## Out of scope (already filed, confirmed pre-existing)
#1871 conflict-resolution loser stays Approved; #1872 14-day replay-marker TTL. Task #205
consequence-subject convergence is a tracked follow-up, NOT a gap in this fix.
