---
name: ADR-049 Phase 2A.8 governance migration — multi-commit ladder pattern
description: Pattern for migrating very large helper-domain modules (governance_helpers.rs ~6K LOC) from supervisor-shape to actor-shape across multiple incremental commits with safe intermediate states.
type: project
---

ADR-049 Phase 2A.8 (governance domain, ~6,053 LOC, 63 functions) is too large for a single-session migration like prior 2A.x domains. The pattern landed across multiple commits on `worktree-agent-a136528bd28369b46` (HEAD `89249ce72`):

1. **Scaffold commit (`6efe9e8a3`, --no-verify WIP)**: bulk-copy `governance_helpers.rs` → `governance_helpers_legacy.rs` with every function renamed `_legacy` (script: word-boundary regex on the 63 fn names; collisions on `migration_state` (struct field) + `get_proposal`/`list_proposals` (engine trait methods) hand-fixed). Repoint shim handler `dispatch_from_shim`, supervisor passthroughs, lifecycle/messaging-legacy callers to `_legacy` variants. Add `governance_helpers_legacy.rs` to `pipeline_wiring.rs` MANAGER_SRC.

2. **Strip commit (`25116dcf2`)**: delete every now-duplicate function from live `governance_helpers.rs`. Keep only `check_commit_fault_marker` (the one externally-referenced live symbol from `messaging_helpers.rs:482`). File goes from 6053 to 41 LOC. Build clippy-clean — no dead code because nothing references the deleted live functions.

3. **Migration commits (`522a1545d`, `89249ce72`)**: incrementally add actor-shape helpers back to `governance_helpers.rs`. Each commit migrates an entry-point + transitive helpers + wires the actor-shape `handlers::governance::dispatch` arm. The dispatch function uses a hybrid pattern: migrated variants take `(&mut PerContextState, &ActorDeps, ...)` directly; unmigrated variants escape through `deps.supervisor.shim_supervisor()` to drive `dispatch_inner` → `governance_helpers_legacy::*_legacy`. Removed at Phase 2A finalization.

**Why:** A single 6K-LOC migration commit is infeasible within session budget. The ladder shape keeps each commit's diff manageable, the build green at every step, the tests passing, and the orchestrator can dispatch continuation sessions to migrate remaining functions one entry-point at a time.

**How to apply:** When dispatching a continuation for governance_helpers Phase 2A.8:
- HEAD `89249ce72` has 8 of 14 entry points on actor-shape (get_proposal, list_proposals, migration_state, tombstone_migrated_context, acknowledge_commit_fault, withdraw_governance_vote, apply_pending_ceiling_modification, apply_pending_economic_policy_change). Plus transitive helpers: build_governance_context, governance_event_label, check_commit_fault_marker.
- 6 entry points still escape to legacy: execute_governance_action, propose_governance_action_inner, propose_governance_action_checked, vote_on_proposal_inner, approve_governance_proposal, reject_governance_proposal.
- ~30 transitive `execute_*` helpers + finalize_governance_action + dispatch_governance_action et al. are still in `_legacy.rs` only.
- 5 supervisor-scoped helpers (start_governance_timeout_task, evaluate_periodic_consequences, process_pending_commits, compute_commit_retry_outcomes, apply_commit_retry_outcomes) inherently iterate the contexts DashMap; they STAY supervisor-shape and remain in `_legacy.rs` — there is no actor-shape twin for them.
- Promoted `messaging_helpers::persist_state_best_effort` and `build_snapshot_from_state` to `pub` so governance actor-shape persistence path can reuse them. Other domain migrations should expect to do the same when they need persistence.
- Plan rule against `#[allow(dead_code)]` is honored throughout; no module-level allow added.

**Continuation order (cheapest first):** approve_governance_proposal, reject_governance_proposal (both 10-line shells over vote_on_proposal_inner). Then vote_on_proposal_inner (medium; calls build_governance_context [done], detect_and_handle_conflicts [need], execute_governance_action [the megastructure]). Then propose_governance_action_inner. Then execute_governance_action + 28-helper dispatch chain (the heaviest). Then propose_governance_action and propose_governance_action_checked.
