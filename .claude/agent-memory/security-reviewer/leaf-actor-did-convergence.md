# fix/leaf-actor-did-convergence (d7216140b + 428e130c5) -- 2026-06-22 -- CLEAN

Two-commit diff vs origin/main b5b0eb02c. Aligns native↔WASM durable-leaf actor_did for
§9.9.3 cross-bridge Merkle convergence + reorders WASM quorum-execute. ZERO security findings.

## Change summary
- System-leaf sentinels aligned: ContextExpired="system:timer", ContextClosed="system:close",
  CrossContextDivergenceMarker "" -> "system:saga". Native already had timer/close on origin/main
  (convergence TARGET); WASM aligned to native; native saga.rs changed "" -> "system:saga".
- GovernanceActionExecuted leaf actor_did: proposer -> EXECUTOR. Threaded executor_did through
  execute_governance_action / dispatch_governance_action / finalize_governance_action (native,
  governance_helpers.rs). Quorum path passes voter_did; auto-execute/SingleAdmin + direct-execute
  handler pass proposer_did. dispatch_governance_action `let actor = executor_did.as_ref()` now
  stamps per-action leaves (RoleAssigned etc.) with executor too.
- WASM reorder (manager.rs ~4053, ~4183): pending->resolved (status=Approved) BEFORE
  execute_governance_action, so its pending-or-resolved created_at lookup still finds the proposal.

## Why clean
- executor_did NOT a new trust source. voter_did is caller-supplied alongside signing_key in
  VoteOnProposalPayload (commands.rs:1033) -- SAME existing trust model as proposer_did. voter gated
  by member_has_capability(voter_did, GovernanceVote) before use (native gh:3354, wasm:4105) AND
  re-checked member_has_capability(executor, required_capability_for_action) inside WASM
  execute_governance_action (manager.rs:2872). Strengthening vs old proposer-stamp (proposer only
  had propose cap, never re-checked for action's required cap at quorum exec).
- actor_did is leaf ATTRIBUTION only, never an authz subject. Per-action execute_* helpers gate on
  ceiling+membership, pass actor_did straight to append_context_event. No capability bypass.
- WASM reorder does NOT open double-execute/replay window. Replay guard =
  executed_proposals.contains_key(pid) checked+set atomically inside execute_governance_action,
  independent of pending/resolved location. WASM single-threaded, no interleave. Reorder was
  NECESSARY: execute's created_at lookup is pending.or_else(resolved); old order left it in pending,
  new order in resolved -- same created_at, same convergent leaf ts.
- "system:*" sentinels CANNOT impersonate a member DID: DID validation requires starts_with("did:")
  + >=3 colon parts (wasm manager.rs:893; native validate_did same). "system:timer" etc. fail the
  did: prefix -> namespace disjoint. A member can never register "system:timer".
- Consequence-SUBJECT + participation-record correctly STILL use proposal.proposer_did (gh ~4358,
  ~4453), NOT executor -- distinct semantic, intentionally untouched (task #205 follow-up =
  converge consequence-subject cross-bridge; out of THIS diff scope).

## Out-of-diff observations (pre-existing, not regressions)
- governance_logic.rs:30 CONSEQUENCE_ACTOR_DID="system" and governance_helpers.rs:334 "system"
  (bare, no colon) -- different sentinel shape from the colon-namespaced ones; still did:-disjoint
  so no impersonation. Not part of this convergence pass.
- Vote trust model: voter_did/signing_key both caller-supplied; engine binds eligibility via
  membership/eligible_voter_dids, not by verifying signing_key.verifying_key == resolved(voter_did)
  on the live FFI path. Pre-existing whole-protocol property (matches proposer path), not introduced.

Files: governance_helpers.rs, actor/handlers/governance.rs, actor/handlers/saga.rs, ttl.rs (tests),
wasm/manager.rs, wasm/consequence.rs (tests), tests/governance_integration.rs (tests).
~60% of diff is test code (cross-impl parity + non-vacuity controls).
