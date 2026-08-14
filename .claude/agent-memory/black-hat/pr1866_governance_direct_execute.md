---
name: pr1866-governance-direct-execute
description: PR #1866 governance direct-execute quorum-bypass fix — reviewed clean; closed attack surface + 2 non-exploitable notes
metadata:
  type: project
---

# PR #1866 — Direct-execute quorum-bypass fix (REVIEWED CLEAN)

Branch fix/1866-direct-execute-trust, base a632c731a, HEAD 3834898f0.

**What it closed (worst pre-fix vector):** NAPI `context_execute_governance_action_on` took caller `action_json`+`proposer_did`, minted a RANDOM proposal id, fabricated a fully `ProposalStatus::Approved` GovernanceProposal from caller data, dispatched with ZERO engine involvement = total quorum bypass. PyO3/UniFFI same via caller-supplied `proposal_json` (caller controlled `status` field). WASM via `action_json`. All four now reduced to a single id lookup.

**Fix shape (uniform across 4 bridges + 4 SDKs):** `(handle, proposal_id_hex)` only. Native `execute_governance_action` resolves proposal via `state.governance.engine.get_proposal(proposal_id)`; status checked against engine's own status (Approved only at signature-verified quorum); executor derived from tracked `proposal.proposer_did` when `None`. Payload `ExecuteGovernanceActionPayload` carries only `proposal_id` now.

**Verified closed:** quorum bypass, action substitution (structurally impossible — no action param), forgery (untracked id → PermissionDenied/CTX_2041), replay (executed_proposals guard, proven by real 2/3 quorum integration test), misattribution/spoofed-executor (WASM passes proposer for BOTH initiator_did + executor_did, matches native consequence subject = proposer — closed task #205 convergence), malformed-id (4 strict parsers all → SCP-CTX-2040), no TOCTOU (synchronous with_manager borrow, WASM single-threaded). pipeline_wiring AST pins are positive/closed-by-construction.

**TestInsertMember seam:** `#[cfg(feature="testing")]` at every layer, only mutates role_state/membership, never FFI-reachable, never touches execute path. Sound.

**Non-exploitable notes:**
1. STALE doc comment manager.rs:3061-3068 — still says "Direct-FFI: initiator_did == caller" but bridge now passes proposer for both. Could mislead future maintainer into reintroducing caller-subject. (clarity only)
2. PRE-EXISTING 14-day replay window (state.rs:73 EXECUTED_PROPOSALS_TTL_SECS): engine `proposals` map retains Approved proposal indefinitely; after executed_proposals TTL evicts, by-id re-execute passes status+empty-replay → re-dispatches. NOT introduced by #1866 (same guard pre-fix). Out of scope; worth follow-up to evict from engine map.
