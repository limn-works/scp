---
name: saga-pending-class-s-slice3a
description: ADR-049 §6.2.4 slice-3a made actor saga_pending Class-S; live branch uses HashMap not the parked-branch Option, and has no last_committed_saga
metadata:
  type: project
---

ADR-049 §6.2.4 slice-3a: made the actor-side `saga_pending` slot Class S (sync-persisted, fail-closed) per ADR-049 §9 line 144. Committed on branch `feat/actor-2c-6.2.4-xctx-saga` (base `81dba400`, my commit `ad26f4db1`).

**Why:** staged cross-context saga evidence must survive an actor crash so a future §6.2.4 Prepare/Commit/Abort handler (slices 3b+) can replay it; otherwise a crash between Prepare and Commit orphans the supervisor SagaJournal's reservation linkage (wedged saga).

**How to apply / the non-obvious trap:** A "proven pattern" commit (`87b166872`, parked branch `feat/actor-2c-3b-standing-dispatch`) implemented this against an OLDER lineage where:
- `PerContextState.saga_pending` was `Option<(SagaId, SagaPreparedState)>`
- there was a `last_committed_saga: Option<SagaId>` field

The LIVE branch had diverged: `saga_pending` is `HashMap<SagaId, SagaPreparedState>` and `last_committed_saga` does NOT exist. So I adapted, not ported:
- `ContextSnapshot` field became `HashMap<SagaId, SagaPreparedStateSnapshot>`.
- did NOT invent `last_committed_saga` (no producer/consumer on this branch — would be fabricated state).
- the Class-S gate marker is the CALL-STYLE `saga_pending.insert(` / `saga_pending.remove(` (the real HashMap mutation the handlers will use), NOT the parked branch's assignment `saga_pending=` (which would be dead coverage here). The gate cuts off at the first column-0 `#[cfg(test)]`, so test `.insert(` calls aren't flagged.

**Mirror design (preserves §9.4.3 non-derive barrier):** live `SagaPreparedState` keeps no Serialize/Deserialize; snapshot carries a NEW `SagaPreparedStateSnapshot` enum with its own public-field payload structs (StandingPairCreateSnapshot / CrossContextToolInvocationSnapshot / BroadcastHostingHandshakeSnapshot) — did NOT reuse the `pub(in crate::context)` journal `*Wire` mirrors (keeps journal-evidence surface crate-internal vs the fully-pub ContextSnapshot surface). `from_prepared`/`into_prepared`, exhaustive match.

**Snapshot-builder sites wired (this branch has 5 LIVE + drop/test sites):** shared helper `messaging_helpers::saga_pending_snapshot(state)` called from: canonical `build_snapshot_from_state` (messaging_helpers), and the 3 DUPLICATE `build_snapshot_from_state` copies (broadcast_helpers, trust_recovery_helpers, ttl_close_helpers), plus `manager_methods::snapshot_context(ctx)`. DROP-to-empty: `strip_snapshot_for_public` (export), lifecycle import path, supervisor/persistence/store test fixtures. REHYDRATE: lifecycle `restore_context` (same-node crash recovery). The sync-persist seam (`persist_state_fail_closed` → `build_snapshot_for_persist` → `build_snapshot_from_state`) already existed — adding the field to the canonical builder gave fail-closed persist for free.

See [[adr049-dyn-to-concrete-test-crypto-swap]] for the related ADR-049 actor/test-crypto context.
