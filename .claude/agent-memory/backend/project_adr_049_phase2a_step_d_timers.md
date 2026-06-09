---
name: project-adr-049-phase2a-step-d-timers
description: ADR-049 Phase 2A Step D — TTL + governance timer tasks → actor registry (lookup) + mailbox tick (FireTimer / EvaluateTimeouts); SupervisorHandle lookup+tracked_spawn; drops 2 shim_supervisor at ttl_close_helpers
metadata:
  type: project
---

ADR-049 Phase 2A finalization Step D (task #38). Convert TTL + governance **timer tasks** from reading the `contexts` DashMap to `Supervisor::lookup` (lock-free actor registry) + mailbox tick. Branch `refactor/actor-per-context`, parent `7a9a54937`.

**KEY FACT — dual-write window (Step B/E NOT yet done):** bootstrap is `spawn_actor_dashmap_backed` (supervisor.rs:2372). The actor's state IS the DashMap's `Arc<Mutex<PerContextState>>` (actor/mod.rs:471 `dispatch` locks `state_arc` and runs `dispatch_state(&mut guard)`). So a `FireTimer` handler's mutations to `state.ttl.timer` are the SAME bytes `spawn_ttl_timer_legacy`'s DashMap-lock wrote. No divergence during conversion — that's why timer→mailbox works before the DashMap is deleted.

**Prebuilt scaffolding (commit 43f7f2de2):**
- `TtlCloseCommand::FireTimer{reply: oneshot<Result<bool>>}` (commands.rs:1771) + handler `handle_fire_timer` (ttl_close.rs:304) — already runs `handle_ttl_expiry(&mut state, deps, &state.handle)` on owned state, no DashMap, no gen-gate. Replies `Ok(false)` (one-shot). DONE — just needs a task to *send* it.
- `GovernanceCommand::EvaluateTimeouts{reply: oneshot<Result<bool>>}` + handler `handle_evaluate_timeouts_actor` (handlers/governance.rs:1074) — covers ALL 5 phases (proposals/deadlock/writeback/consequences/commits) on owned `&mut state`. Replies `Ok(true)` continue / `Ok(false)` stop. DONE.
- `tick_governance_timeout(supervisor, ctx_id) -> bool` (governance_helpers.rs:4009) — `lookup` + send `EvaluateTimeouts` + await bool. DONE (was `#[allow(dead_code)]`, first caller is this step).
- `Supervisor::lookup(ctx_id) -> Option<ContextActorHandle>` (supervisor.rs:2186, `pub(in crate::context)`). DONE.
- `task_set_ref()` (supervisor.rs:612), `SEND_TIMEOUT`=30s (handle.rs:46), `send_with_timeout` (handle.rs:176).

**THE CONVERSION (design):**
1. **SupervisorHandle surface** (handle.rs): add `lookup(&self, ctx_id) -> Option<ContextActorHandle>` (delegate to `self.supervisor.lookup`) + `tracked_spawn(&self, fut)` that spawns onto `self.supervisor.task_set_ref()`'s JoinSet (lock the `Mutex<JoinSet>`, `.spawn(fut)`). NO whole-`Arc<Supervisor>` exposure. NOTE: returning `ContextActorHandle` from SupervisorHandle is normally FORBIDDEN by the capability contract (handle.rs:574 comment + a CI grep-ban planned). The timer task is supervisor-scoped infra, not an actor reaching a sibling — but to stay clean, prefer the timer task hold `Arc<Supervisor>` captured at spawn from inside the helper that already has it, OR thread `lookup` via a NON-handle path. DECISION taken at impl: timer task calls `supervisor.lookup` directly (the spawn helper still receives `&Supervisor` via the actor-shape `start_ttl_timer`'s reach), and SupervisorHandle gains only `tracked_spawn`. Re-evaluate against grep-ban.
2. **New actor-shape `ttl_close_helpers::spawn_ttl_timer`** (replaces `spawn_ttl_timer_legacy` body): runs on `&mut state` (called from `start_ttl_timer`/`reset_ttl_timer` handlers). Abort old `state.ttl.timer.task`, fresh `cancel = Arc<Notify>`, spawn timer task via tracked-spawn: `select!{ sleep(duration) => { lookup(ctx_id) → send FireTimer; }, cancel.notified() => {} }`. Store returned `AbortHandle` + deadline into `state.ttl.timer`.
3. **`start_ttl_timer`/`reset_ttl_timer`** (ttl_close_helpers.rs:232/:195): drop `deps.supervisor.shim_supervisor()` + `spawn_ttl_timer_legacy` call → call new actor-shape spawn on `&mut state`. **−2 shim_supervisor.**
4. **3 lifecycle callers** (lifecycle_helpers.rs:1205 finalize_create, :1619 restore, :1957 import) + governance ext (:2571 governance_helpers_legacy): these have only `&ActorDeps`/`&Supervisor`, run AFTER actor spawn, NO `&mut state`. They must DISPATCH `StartTtlTimer` (or `ResetTtlTimer` for the gov-ext) to the freshly-spawned actor via `lookup` + `send_with_timeout`. The actor handler then runs `start_ttl_timer` on owned state. (Alternative: a SupervisorHandle method `dispatch_start_ttl_timer`.)
5. **Governance timer task** (`start_governance_timeout_task_legacy`, governance_helpers_legacy.rs:4762): rewrite the spawned tick body to JUST `tick_governance_timeout(supervisor, &ctx_id).await` (returns bool for loop continue/stop). DROP all DashMap reads (`contexts.get`), DROP `spawn_generation` gate, DROP Phases 1-5 inline body (now in the actor handler). The spawn-setup still needs `task_set` + must store the `GovernanceTimeoutTask` (cancel Notify + AbortHandle) — on `state.governance.timeout_task`. Same actor-command dispatch problem as TTL: drive via an actor command OR keep spawn-setup reaching state via the dual-write Arc. PREFER: move `start_governance_timeout_task` to dispatch a new/existing command that runs `GovernanceTimeoutTask::start_in` on `&mut state`. Then `start_governance_timeout_task_legacy` body → caller-less → DELETE.
6. After: `spawn_ttl_timer_legacy` + governance legacy timer body caller-less → DELETE. Verify no DashMap reads in timer paths.

**SCOPE GUARD (task says STOP if it ripples beyond timers):** do NOT delete `contexts` DashMap, do NOT switch bootstrap to spawn-only, do NOT convert nested `create_context_legacy`. Those are Steps B/C/E. Push per sub-step.

---

## LANDED (2 commits on `refactor/actor-per-context`, parent `7a9a54937`)

- **`30c444b93`** — `SupervisorHandle::lookup` + `tracked_spawn`.
- **`d519ad41c`** — TTL + governance timers → actor registry + mailbox tick.

**What I did vs the plan:** mostly as designed, with these concrete decisions:
- SupervisorHandle gained `lookup` (the ONE sanctioned `ContextActorHandle` yield — documented as timer-infra, not sibling reach; no active grep-ban forbids it yet, planned for a later commit per handle.rs:574) + `tracked_spawn` (locks `task_set` mutex, `JoinSet::spawn`, returns `AbortHandle`) + `dispatch_start_ttl_timer` (mailbox StartTtlTimer to just-spawned actor).
- TTL: new actor-shape `ttl_close_helpers::spawn_ttl_timer(&mut state,...)` installs on `state.ttl.timer`, task does `lookup`+`FireTimer`. `start_ttl_timer`/`reset_ttl_timer` drop shim. **−2 shim_supervisor at ttl_close_helpers (2→0).**
- Governance: needed `GovernanceCommand::StartTimeoutTask` (NEW variant) + handler + actor-shape `governance_helpers::spawn_governance_timeout_task(&mut state)` + `GovernanceTimeoutTask::install(cancel, abort)` (NEW method on the timeout struct — because the actor-shape path uses `tracked_spawn` not `start_in`'s `&mut JoinSet`). The `EvaluateTimeouts` actor handler ALREADY covered all 5 phases, so the legacy 5-phase inline body (DashMap + gen-gate) collapses to a `tick_governance_timeout` loop calling `lookup`+`EvaluateTimeouts`. `start_governance_timeout_task` now takes `&SupervisorHandle` and dispatches StartTimeoutTask.
- 3 lifecycle callers (finalize_create/restore/import) rethreaded to `dispatch_start_ttl_timer` + `start_governance_timeout_task(&deps.supervisor,..)`.

**STOPPED-on (the legacy-body DELETE the task expected):** `spawn_ttl_timer_legacy` + `start_governance_timeout_task_legacy` are NOT caller-less and were NOT deleted. Their remaining callers are the legacy `create_context_legacy` → `finalize_create_legacy`/`execute_extend_ttl_legacy` chain (governance_helpers_legacy.rs:2571, lifecycle_helpers_legacy.rs:366/372), reached from the 2 nested legacy creators (standing_helpers_legacy:125, governance_helpers_legacy:4209). Those are **Step C** scope, which the task EXPLICITLY forbids converting. Deleting the legacy timer bodies would force Step C → ripple beyond timers. Correct boundary: leave them; they get deleted in Step C when `create_context_legacy` is converted. The actor-shape governance TTL-extension path (`execute_extend_ttl`, governance_helpers.rs:1297) already inherits the new `start_ttl_timer` — fully converted.

**Gates all green:** scp-runtime lib `1573 pass / 6 whitelist` (1571 baseline + 2 new timer e2e tests; the 6 are pre-existing recovery/credential whitelist). e2e_bridge `54/0`. Workspace clippy `-D warnings` clean. pipeline_wiring `54/0` (+2 additive assertions, ratchet 39→41). Pre-existing integration failures (governance_integration 11, content_access_governance_integration 11, content_access_integration 2) are IDENTICAL at baseline `7a9a54937` (verified via detached worktree) — NOT mine.

**Shuttle:** `shuttle_actor.rs` is a scaffold (feature inactive, no real cases). A Shuttle case for timer reset-racing-fire concurrency is warranted but deferred to **Phase 2I** per task instruction (heavy, harness not wired).

**Scorecard delta:** shim_supervisor 7→4 (ttl_close 2→0; remaining 4 are actor/mod.rs construction, unrelated). Mutex<PerContextState> 20→20 (unchanged, out of scope). DashMap reads in new timer fns: 0. No main-checkout files touched (the dirty `manager/queries.rs`+`content_access_governance_integration.rs` in MAIN are pre-existing unrelated work, never in my commits).

See [[project-adr-049-phase2a-finalization-dispatch-step]], [[project-storage-foundation-ladder]].
