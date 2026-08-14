---
name: governance-direct-execute-byid
description: SCP-1866 fix c9db30486 — direct-execute governance quorum-bypass closed by executing by tracked proposal_id; trust-boundary soundness verified
metadata:
  type: project
---

# Governance direct-execute by-id (SCP-1866, fix c9db30486, branch fix/1866-direct-execute-trust)

SOUND. Closes a real quorum-bypass + action-substitution vector. APPROVE.

**Bug (pre-fix):** `ExecuteGovernanceActionPayload` carried a full caller-constructed `GovernanceProposal` (action + status=Approved). Runtime dispatched it with zero quorum involvement across every FFI bridge.

**Fix:** payload now carries only `proposal_id: ProposalId` (+ `Option<&DID>` executor for internal callers). `execute_governance_action` (governance_helpers.rs ~4499) resolves the authoritative proposal from `state.governance.engine.get_proposal(id)` and rejects untracked (PermissionDenied "not tracked") or non-Approved.

**Why `engine.get_proposal(id).status==Approved` is a sound proxy for verified quorum:**
- Engine `proposals` map is PRIVATE to each engine; only mutated by trait methods `propose`/`approve`/`reject`/`resolve`/`withdraw_vote`.
- Every Approved transition is gated by `verify_vote` = Ed25519 `verify_strict` against DID-resolved key (governance/mod.rs:248-262). Majority approve() verifies sig BEFORE push (majority.rs:438-447); resolve() sets Approved only from `approvals.len()` (signature-verified entries). SingleAdmin auto-approve verifies admin vote sig before status=Approved (mod.rs:1580-1593).
- All engines create proposals as `Pending` (majority:366, multisig:285, unanimity:268, SingleAdmin is the only auto-Approve and it verifies).
- `state.governance.engine` is `pub(crate)` (state.rs:1146) — no external write path.
- RESTORE path is safe: `restore_governance_engine_from_snapshot` (state.rs:1874) builds a FRESH engine with EMPTY proposal map — no proposal rehydration. Post-restart, get_proposal(old_id)→None → direct-execute fails closed. (Snapshot only restores `executed_proposals` replay cache, not engine proposals.)

**Replay protection intact:** `check_commit_fault` moved earlier (fail-close before lookup, strictly safer). `executed_proposals.contains_key` rejects re-exec; marker inserted pre-dispatch with rollback on dispatch failure + TTL retain. Replay KAT asserts single-exec + reject.

**#1865 convergence preserved:** leaf `created_at` still = `proposal.created_at` (SIGNED value); leaf `actor_did` = executor = `unwrap_or(&proposal.proposer_did)` for direct path — IDENTICAL attribution to pre-fix. Only the proposal SOURCE changed (caller→engine), strictly stronger. Added `proposal.context_id != context_id` check is belt-and-suspenders (engine is per-context; cross-ctx id→None anyway).

**WASM asymmetry (ADR-034) — acceptable documented limitation, NOT a regression:**
- WASM votes carry `signature: Vec::new()` (manager.rs:482,750,4242,4440,4587); status=Approved set from vote-COUNT quorum with NO sig verification (no key resolver per ADR-034).
- BUT the fix's WASM path (manager.rs:3046 execute_governance_action) resolves BOTH the action to dispatch AND leaf timestamp from the manager's OWN tracked proposal (pending_proposals/resolved_proposals via require_proposal_approved + tracked lookup ~3103) — never caller-supplied. Action substitution structurally impossible on WASM too.
- WASM tracked-status is the best available authority in-environment; fix is no weaker than WASM's pre-existing voting and REMOVES the caller-Approved bypass on WASM as well.

**FFI surfaces all by-id (no caller action at execute):** PyO3 `governance_execute(handle,identity_did,proposal_id_hex)` (context.rs:3033) builds payload with only proposal_id. UniFFI `governance_execute` (bridge.rs:9500). NAPI `context_execute_governance_action`. WASM `context_execute_governance`. `action_json` remains only on `governance_propose` (correct — goes through verifying engine).

**Tests:** PyO3 KAT `direct_execute_rejects_untracked_proposal_id` (context.rs:6314) + `direct_execute_rejection_does_not_mutate_state`. Native-runtime + cross-bridge fullstack KATs. pipeline_wiring.rs positive assertions pin by-id on native+WASM.

**Test seam:** `Supervisor::test_insert_member` / `MessagingCommand::TestInsertMember` — `#[cfg(feature="testing")]`, never in prod, never FFI-reachable. Records member directly (bypasses MLS Welcome) for single-node multi-member export tests. Benign.
