---
name: ADR-049 Phase 2A.8 governance migration — multi-commit ladder pattern
description: Pattern for migrating very large helper-domain modules (governance_helpers.rs ~6K LOC) from supervisor-shape to actor-shape across multiple incremental commits with safe intermediate states.
type: project
---

ADR-049 Phase 2A.8 (governance domain, ~6,053 LOC, 63 functions) migration COMPLETE on `worktree-agent-a6ab8bf08c82e8ce9` (HEAD `12a788004`). Multi-commit ladder pattern landed across 7 commits:

1. **Scaffold commit (`6efe9e8a3`, --no-verify WIP)**: bulk-copy `governance_helpers.rs` → `governance_helpers_legacy.rs` with every function renamed `_legacy`.
2. **Strip commit (`25116dcf2`)**: delete every now-duplicate function from live `governance_helpers.rs` (file: 6053 → 41 LOC).
3. **Migration commits (`522a1545d`, `89249ce72`)**: 8 of 14 entry points migrated (read paths + simple mutations).
4. **Continuation A (`5f4e7aa06`)**: 28 `execute_*` per-action leaf helpers + transitive helpers (`fail_close_remove_member`, `try_broadcast_commit_or_enqueue`, `detect_and_handle_conflicts`, `check_and_resolve_expired_freezes`, `check_commit_fault`).
5. **Continuation B (`bf41141a2`)**: 4 dispatch orchestrators + `finalize_governance_action` + `execute_governance_action` entry point + handler arm wiring.
6. **Continuation C (`70ebd41b8`)**: 6 final entry points (`propose_governance_action_inner` + checked, `vote_on_proposal_inner` + checked + approve/reject) + 5 handler arm wirings + `Placeholder` direct-arm + 24 functions demoted from `async` to `pub fn` + clippy cleanup.
7. **Doc cleanup (`12a788004`)**: `dispatch_state` doc removed obsolete `shim_supervisor()` escape language.

**Why:** A single 6K-LOC migration commit is infeasible within session budget. The ladder shape keeps each commit's diff manageable, the build green at every step, the tests passing, and the orchestrator can dispatch continuation sessions to migrate remaining functions one entry-point at a time.

**Key design decisions discovered during migration:**
- 5 supervisor-scoped helpers stay in `_legacy.rs` only (`start_governance_timeout_task`, `evaluate_periodic_consequences`, `process_pending_commits`, `compute_commit_retry_outcomes`, `apply_commit_retry_outcomes`) — they iterate the contexts `DashMap` and have no actor-shape twin until Phase 2A finalization.
- `propose_governance_action`, `vote_on_proposal`, `translate_timeout_events` (unchecked test-only variants) NOT migrated — production callers always route through checked variants; supervisor passthroughs (`Supervisor::propose_governance_action`, `Supervisor::vote_on_proposal`) keep calling `_legacy` until 2A finalization. Documented as comments in actor-shape file rather than added as `cfg(test)` dead code.
- TTL cross-call: `execute_extend_ttl` switched from `ttl_close_helpers_legacy::spawn_ttl_timer_legacy(supervisor, ...)` to `ttl_close_helpers::start_ttl_timer(state, deps, ..., handle)` (Phase 2A.6 Option B).
- Lifecycle cross-calls (`drain_and_deliver_sender_keys`, `create_context`) reach via `deps.supervisor.shim_supervisor()` until Phase 2A.9.
- `try_broadcast_commit_or_enqueue` signature changed from `operation: CommitOperation` to `operation: &CommitOperation` (clippy `needless_pass_by_value`).
- `actor_check_proposer_eligibility` inlined here instead of reusing `governance_logic::check_proposer_eligibility` because the shared helper takes legacy `&mut state::PerContextState`, which the actor cannot construct from `actor::state::PerContextState`. Inlines the same pending-removal + SingleAdmin bypass + participation gate + earned-capacity gate.
- `finalize_governance_action` reuses `enforce_triggered_consequences_split` + `event_log_entries_for_consequences_split` (Phase 2A.7 split-borrow helpers in `governance_logic.rs`) so consequence enforcement runs from actor-owned state without cloning the entire pipeline.
- 24 of the 33 migrated helpers are sync `pub fn` (no awaits inside actor-owned state). Truly async are: `tombstone_migrated_context`, `withdraw_governance_vote`, `apply_pending_*`, `dispatch_governance_action`, `dispatch_context_governance_action`, `execute_governance_action`, `propose_governance_action_*`, `vote_on_proposal_inner`, `approve/reject_governance_proposal` — they await `state.handle.transition_to(...)` and/or other dispatch-chain async calls.

**`actor/handlers/governance.rs::dispatch_state` final shape:** every governance variant takes `(state, deps, ...)` directly. Only `Placeholder` (no-op handshake reserved for mailbox tests) returns `NotImplemented` synchronously. The `dispatch_inner` shim and `dispatch_from_shim` remain as the supervisor-passthrough fallback (still calls `governance_helpers_legacy::*_legacy`) — both deleted at Phase 2A finalization.

**Commit ladder summary (`12a788004` HEAD, 7 commits, 3833 lines added, 175 removed):**
```
12a788004 docs(governance-handler): dispatch_state doc — shim escape removed
70ebd41b8 refactor(actor): 6 entry points (propose/vote/approve/reject)
bf41141a2 refactor(actor): execute_governance_action + dispatch chain + finalize
5f4e7aa06 refactor(actor): 28 execute_* leaf helpers + transitive
89249ce72 (prior) refactor(actor): withdraw + apply_pending_*
522a1545d (prior) refactor(actor): 5 read/lightweight entry points
25116dcf2 (prior) refactor(actor): strip live governance_helpers.rs
6efe9e8a3 (prior) wip(actor): scaffold governance_helpers_legacy.rs
```
