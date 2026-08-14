---
name: slice45-governance-convergence
description: Red-team assessment of WASM governance-execute authorization convergence (per-member check removed, ceiling gate added) + executor-DID stamping + convergent ContextClosed deadline, branch fix/leaf-actor-did-convergence (b5b0eb02c..501a44f6a)
metadata:
  type: project
---

# Slice45 actor-did convergence assessment (2026-06-22)

Branch fix/leaf-actor-did-convergence, range b5b0eb02c..501a44f6a (HEAD 501a44f6a).

**Verdict: NO exploitable privilege-escalation chain. The convergence change is faithful to native.**

## What changed
- WASM `execute_governance_action` (manager.rs:3041): REMOVED per-member capability check at execute time. Added `require_proposal_approved` (status==Approved precondition) + per-action CONTEXT-CEILING gate in `dispatch_governance_action` (manager.rs:3224, `dispatch_ceiling_capability`).
- Executor-DID stamping: `GovernanceActionExecuted` leaf actor_did is now the COMMITTING member (quorum-crossing voter / proposer on auto-execute / proposal.proposer_did on direct-FFI), not initiator/proposer. Native mirrored (governance_helpers.rs: dispatch/finalize/execute now take `executor_did`).
- WASM_PROPOSAL_TTL_MS: 24h -> 14 days, matching native EXECUTED_PROPOSALS_TTL_SECS (state.rs:73 = 14*24*60*60). Confirmed match.
- Shared sentinels: scp-event-log/src/system_actors.rs (new) — SYSTEM_TIMER_ACTOR "system:timer", SYSTEM_CLOSE_ACTOR "system:close", SYSTEM_SAGA_ACTOR "system:saga", SYSTEM_CONSEQUENCE_ACTOR "system". Both bridges reference.
- Convergent ContextClosed/Expired leaf timestamp = creation_timestamp_secs.saturating_add(ttl) (manager.rs:6412, 5491). ExtendTtl uses saturating_add (overflow-safe).
- Pending->resolved rollback on dispatch failure (retriable), fail-closed payload encode.

## Why faithful (verified against native)
- Native `execute_governance_action` (governance_helpers.rs:4477) gates ONLY on status==Approved + context-id + replay (executed_proposals) + commit-fault. NO per-member action-capability check. WASM now matches.
- Native per-action ceiling gates (ceiling.contains, NOT member role) exist for EXACTLY: SuspendCapability/SuspendAccess/RevokeAccess/RestoreAccess (member:ban), RegisterTool (tool:register), CreateChildContext (context_child:create), EstablishToolInterface (tool:interface). WASM dispatch_ceiling_capability mirrors all 5/8 classes exhaustively (no wildcard). Verified ChangeRole/TransferAdmin/AddMember/AddSigner/ModifyThreshold/ResetMember have NO native ceiling gate -> WASM returns None correctly.
- Authorization is at PROPOSE time: governance:propose (WASM manager.rs:4170) + governance:vote (4386/4542), restricted to admin/moderator roles in member_has_capability (4170-584). Quorum IS the authority for non-ceiling-gated actions — by design (ADR-031). WASM == native.
- Integration tests are REAL (not dead-ref): governance_quorum_voter_without_action_capability_mints_one_leaf (line 579) + governance_action_executed_leaf_stamps_executor_not_proposer (492) exercise actual behavior.

## Latent / low-severity notes (NOT exploitable today)
- **Stale comment** (context.rs:768): "initiator_did remains the AUTH SUBJECT (capability checked inside execute_governance_action)" is FALSE — nothing checks initiator_did's capability anymore. Misleading, not a vuln.
- **Action substitution (pre-existing, NOT this diff)**: WASM direct-execute (context.rs:773) dispatches caller-supplied `action_json`, while replay/status keyed on proposal_id. Native binds action to the signed proposal object (payload.proposal.action). The action_json param predates this diff. Worth a separate look but out of scope.
- **creation_timestamp_secs verbatim on snapshot import** (manager.rs:6250): comment claims forged-future creation "only shortens effective deadline (fail-safe)" — direction is WRONG (future creation = LATER leaf timestamp). BUT WASM has NO context-TTL deadline gate consuming creation_timestamp_secs (is_expired at 380 is for SESSIONS only; handle_ttl_expiry is timer-driven externally). So no lifetime extension in WASM. Native computes deadline from its own authenticated state, not peer snapshots. Anti-replay timestamps (nonces, executed_proposals) ARE clamped .min(now) — sound. Forged snapshot only corrupts attacker's own local leaf; leaves are committer-appended-only (receive-side dormant) so no cross-member propagation. Latent §9.9.3 risk when receive-side replication lands.
- **Pre-existing convergence gap**: WASM governance CloseContext dispatch (manager.rs:3303) sets state "closing" but emits NO ContextClosing leaf; native execute_close_context (governance_helpers.rs:1485) DOES emit ContextClosing. Event-count divergence on governance-close path. Pre-existing, not this diff.
- **14d replay window**: low-volume context (<10k executed proposals) executed marker effectively never expires (retain only runs at WASM_PROPOSAL_CAP). Resolved-vs-executed differing eviction (oldest-by-created_at vs time-at-capacity) could theoretically leave a resolved-Approved proposal whose executed marker evicted -> replay duplicate leaf. Requires precise control of 10k+ proposals over 14d. Convergent with native (same structure). Negligible.

## Controls that hold
- Propose-time capability gate (admin/moderator only for governance:propose).
- Exhaustive non-wildcard dispatch_ceiling_capability match (compile-error on new variant — closed by construction).
- Anti-replay timestamp clamp on snapshot import (.min(now)).
- executed_proposals replay guard + rollback-on-failure (no double-execute).
- Shared sentinel consts (single source of truth, byte-parity by construction).
- Fail-closed payload encode (no divergent empty-payload leaf).
