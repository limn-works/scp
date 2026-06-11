---
name: project-adr049-phase2b-watchdog
description: ADR-049 Phase 2B per-actor watchdog/respawn/poison — design as built + two non-obvious gotchas (respawn-Active-transition bug, dead-handle-lingering test race)
metadata:
  type: project
---

Phase 2B of ADR-049 actor-per-context: per-actor watchdog + 3-crashes-in-60s respawn budget + poison. Branch `feat/actor-2b-watchdog-respawn` off main (HEAD 35f694595). 4 commits.

**Why:** Pre-change `spawn_actor_with_state` dropped the actor JoinHandle (supervisor.rs), so a panic was silently swallowed and the context wedged (every later send → ActorBusy). ADR-049 §10 mandates a watchdog that detects panics, logs payload-free (key-material safety), enforces a budget, and respawns from snapshot.

**How to apply (design as built):**
- `spawn_actor_with_state(self: &Arc<Self>)` now derives `owning_did` (local_dids min, else `DID(ctx_id)` seed) and delegates to `spawn_actor_with_watchdog`, which KEEPS the JoinHandle and starts the watchdog. Every spawn path (create/import/restore/respawn) is watched uniformly.
- `spawn_actor_watchdog_task` is a FREE fn (not inline `tokio::spawn`) — REQUIRED to break the self-referential async opaque-type cycle (`spawn_actor_with_watchdog → actor_watchdog → respawn_from_snapshot → restore_context → spawn_actor_with_state`). Inline spawn = "fetching the hidden types of an opaque inside of the defining scope is not supported". Don't try `Box::pin`/`dyn+Send` at the call site — only the free-fn boundary works.
- `actor_watchdog`: Ok / non-panic JoinError = no crash, no respawn. Panic → record crash, log PAYLOAD-FREE (`is_panic()` bool ONLY; never `into_panic()`/`payload()`/`{:?}` on JoinError), then poison-and-despawn (budget) or respawn. `panic_location="unknown"` hardcoded — a global last-location store would be racy across threads/Supervisors AND a mutable global (forbidden); ADR-049 §10 floor accepts "unknown".
- Poison surfacing: `lookup_miss_error(ctx_id, msg)` → ContextPoisoned vs ContextNotRegistered, wired into messaging/governance/ttl_close `ok_or_else` + lifecycle direct arms.
- CrashWindow pure methods take `now_ms` PARAM (no clock inside) → unit-testable without clock.

**GOTCHA 1 (real bug found by test):** `respawn_from_snapshot` must `handle.transition_to(Active)` BEFORE calling `restore_context` — `restore_context` does NOT transition the handle itself (the RestoreContext direct dispatch arm transitions externally). Without it the respawned context is stuck in `Creating` (responsive but never Active).

**GOTCHA 2 (test race):** a just-crashed actor's handle LINGERS in the `actors` registry until the watchdog's `respawn_from_snapshot` despawns it. So `wait_until(lookup().is_some())` matches the DEAD handle → next panic lands on a closed mailbox and never crashes. Watchdog tests MUST wait on a RESPONSIVE actor (`read_context_state == Active` via mailbox), not a bare registry lookup. See [[feedback-read-tool-stale-verify-with-awk]] for the general "verify behavior not surface" theme.

Test seam: `LifecycleControlCommand::TestInducePanic` is `#[cfg(feature="testing")]` and handled in `actor/mod.rs` `dispatch_state` (NOT in `handlers/*.rs`, so the new `scripts/check-handler-no-panic.sh` ban stays green). The handler + skeleton matches get gated no-op arms for exhaustiveness.

Panic-redaction test (the security regression test) captures tracing via a hand-rolled `tracing::Subscriber` set as PROCESS-GLOBAL default once (`std::sync::Once`) — the watchdog logs on a tokio worker thread, so a thread-local `set_default` would miss it. No `tracing-subscriber` dep added.

Gates all green: CI-exact clippy (0 warnings workspace), check-error-codes (SCP-CTX-2134/2135), check-handler-no-panic (new, wired into ci.yml next to deleted-primitives), no-mutable-globals, block-in-place, deleted-primitives. scp-runtime+scp-protocol nextest 4934/4934.
