---
name: adr049-contextinner-arcswap-cas
description: ADR-049 Decision-12 ContextHandle RwLock->ArcSwap<ContextState> + CAS transition_to + try_read_state deletion — auth-gate/fail-open/key-coherence review, ZERO findings
metadata:
  type: project
---

# ADR-049 Decision-12: ContextHandle lifecycle cell RwLock -> ArcSwap + CAS (2026-07-06) — ZERO FINDINGS

Branch chore/adr049-contextinner-arcswap; commits 4de63ce09 (base refactor), 82673db6d (CAS + try_read_state delete), 57dc18f03/427b01e1f (docs). Second-zero fresh security angle on a concurrency change touching authorization-gate reads.

**Change:** `ContextHandle.inner: Arc<tokio::sync::RwLock<ContextInner>>` -> `Arc<arc_swap::ArcSwap<ContextState>>`. `state()`/`transition_to()` became SYNC. `transition_to` is a compare-and-swap retry loop (`compare_and_swap` + `std::ptr::eq` on deref'd guards = arc_swap's documented success idiom; `current` guard pins allocation => no ABA). `try_read_state()` (was `try_read().ok()`, None=lock-contended) DELETED; gates migrated to infallible `state()`.

**Cell is the lifecycle AUTH gate:** `require_active`/`require_migrating_out` (context/state.rs:2114/2124) gate send/broadcast/governance; import-replaceability gate (actor/handlers/lifecycle_control.rs:118); governance-timeout loop (actor/handlers/governance.rs:1153).

**Threading facts (load-bearing):**
- ALL require_active call sites run INSIDE actor command handlers => gate-read + gated-action serialized w.r.t. all ACTOR writes (TTL-expiry/close/finalize all dispatched onto actor loop). Single-threaded command processing = atomic w.r.t. actor's own writes.
- ONLY off-actor SHARED-cell writer = napi `context_finalize_close_on` (scp-ffi/napi/src/context.rs:4242) `transition_to(&Closing)` on persisted core_handle. Flips state only, DESTROYS NO KEYS (destruction on actor Closing->Closed).
- pyo3 context.rs:2506/3099/3350 + uniffi bridge.rs:10046../11135-6 `transition_to(&Active)` are on FRESHLY-CONSTRUCTED throwaway `ContextHandle::new()` (own independent cell) — NOT the actor's shared cell. Cannot resurrect Active.

**Q1 TOCTOU:** window IDENTICAL to old RwLock (neither holds lock across action). Only cross-thread slip = napi Active->Closing, benign (keys live in Closing; real authority = MLS membership+caps). Lock-free load is MORE precise (no spurious deny from old try_read lock-collision).
**Q2 CAS race fail-closed:** FSM edges into Active only from Creating/Poisoned/MigratingOut (state_machine.rs:60-76). Racing shared-cell writers never target Active. CAS loser re-validates against LIVE state; from Expired/Closing the retry target is invalid => Err, no store. No reachable stale-Active. Stress test shuttle_actor.rs:102 context_handle_cas_stress asserts exactly-one-winner/no-invalid-edge/no-torn-read; FAILs old blind-store (3 winners).
**Q3 try_read_state delete:** old None arm was coincidental fail-closed (contention->deny), never load-bearing. New reads committed state; never converts deny->allow beyond what a non-contended read already reached. Governance-timeout None was liveness-retry not security.
**Q4 key coherence:** key destruction only on actor loop = same thread as gated crypto action, cannot interleave. Off-actor napi writes only Closing (keys live). Expired/Closing->Active invalid => cell can't read Active after keys destroyed. No window.

**Non-blocking obs:** (1) CAS loop unbounded but livelock unreachable (tiny writer set, FSM is DAG w/ terminal sinks). (2) require_active doc (state.rs:2113) "no concurrent close/TTL can interleave between check and mutation" — true for actor-origin writes (serialization), could misread as covering off-actor finalize; predates change; 1-line clarify nice-to-have.
