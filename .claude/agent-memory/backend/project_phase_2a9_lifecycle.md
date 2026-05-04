---
name: Phase 2A.9 lifecycle migration COMPLETE
description: ADR-049 actor-per-context Phase 2A.9 lifecycle_helpers.rs migration — pattern, scope decisions, branch + HEAD
type: project
---

Phase 2A.9 of ADR-049 actor-per-context migration COMPLETE — `lifecycle_helpers.rs` (2407 LOC, 22 functions) end-to-end migrated to actor-shape.

**Why:** Continuation of the multi-month refactor from `Mutex<PerContextState>` lock-and-call to actor-per-context (`tokio::spawn`'d task owning `&mut PerContextState`). 9 of 10 helper domains now migrated; only one remains for full Phase 2A completion.

**How to apply:** When migrating a new helper domain, follow this pattern. The lifecycle migration is the canonical example for domains where state lives in the legacy contexts `DashMap` (i.e. the helper bodies own `manager_methods::insert_context` / `lock_context`):

1. **Phase 2A.6 TTL "Option B" pattern wins**: actor-shape thin wrappers delegate to `_legacy` bodies via `deps.supervisor.shim_supervisor()` escape. Actor-shape signatures exist for handler-uniformity; full per-actor state ownership lands at Phase 2A finalization.

2. **Per-context state-bearing helpers** (e.g. `export_context`, `leave_context`, `close_context`, `drain_and_deliver_sender_keys`): take `(state: &mut PerContextState, deps: &ActorDeps, ...)` for symmetry. State unused in body — body delegates to `_legacy::*_legacy(supervisor.as_ref(), ...)`.

3. **Bootstrap entry points** (`create_context`, `restore_context`, `import_context`): take `(deps: &ActorDeps, ...)` — NO `&mut state` parameter because no actor exists for the context being created until the legacy body's `manager_methods::insert_context` registers it.

4. **Designated-legacy supervisor-scoped iteration helpers** (`restore_all_contexts`, `flush_all_contexts(_sync)`, `shutdown_all_contexts(_sync)`): live ONLY in `_legacy.rs`. Inherently iterate the `DashMap`; no actor twin possible.

5. **Transitive helpers with no caller**: do NOT create actor-shape twins. The transitives (`finalize_create`, `join_context_membership`, `capture_join_payment`, `close_context_with_key`, `load_persisted_context_state`) are body-implementation details of the outer entries. Because the actor-shape outer wrappers delegate fully to `_legacy` bodies (which compose the transitives internally), the transitives have no caller until finalization replaces delegation with direct composition. Live ONLY in `_legacy.rs` to avoid `dead_code` warnings.

6. **Handler shape**: TWO entry points side-by-side: `dispatch(state, deps, cmd)` for actor mailbox path + `dispatch_from_shim(supervisor, cmd)` for supervisor direct-shim. Both exhaustively match all command variants. Actor-shape calls actor-shape `lifecycle_helpers::*`; shim calls `lifecycle_helpers_legacy::*_legacy` + `queries_helpers::*` directly.

7. **`lifecycle_command_context_id`** governs routing: returns `None` for major Create/Join/Leave/Close/Import/Restore variants — those go through direct-shim. Returns `Some(ctx_id)` for Export + 3 access-key variants — those route via actor mailbox.

8. **Pipeline-wiring**: add `<domain>_helpers_legacy.rs` to `MANAGER_SRC` `include_str!` list in `crates/scp-testing/tests/integration/pipeline_wiring.rs`.

**Branch:** `worktree-agent-ad909983ae64d8b5a`. **HEAD:** `e3d6c2315`. **5 commits:** scaffold legacy → convert live → wire dispatch → pipeline_wiring + fmt → ttl-close-legacy doc fix. **Diff:** +3393/-2487, 11 files. All 5 acceptance commands pass; lifecycle test suite 39/39 pass; whitelist failures unchanged (6 in scp-runtime lib).

**Remaining for Phase 2A:** 1 helper domain (queries_helpers) per Phase 2A continuation list. Not in scope for Phase 2A.9.
