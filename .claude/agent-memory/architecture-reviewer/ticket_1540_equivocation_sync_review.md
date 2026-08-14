---
name: ticket-1540-equivocation-sync-review
description: Architecture review of #1540 checkpoint-equivocation-sync — SyncPhaseDriver message threading, DrainEquivocationAlerts command, EquivocationDetected roots field, queue_drain honesty
metadata:
  type: project
---

Reviewed branch `feat/1540-checkpoint-equivocation-sync` (5 changed surfaces). Verdict APPROVE — clean trait evolution, sound event-log evolution, honest docs. Builds clean (scp-protocol/runtime/ffi-common), unit tests pass.

**Why:** This is the equivocation-sync companion to the #1540 reconnection driver (see [[ticket-1540-reconnection-driver]]). Builds on RelayActorSyncDriver (FFI/SDK-layer send-only transport, ADR-029 addendum + ADR-049 actor reconciliation).

**How to apply:** Verified architectural facts to reuse on future #1540-adjacent reviews:

- **SyncPhaseDriver message threading** (hours_offline.rs:54): `epoch_reconciliation` and `sender_key_reacquire` now take `messages: &[BufferedMessage]` (Phase-1 buffer). `execute_tier1` (hours_offline.rs:1051) retrieves once in Phase 1, threads same buffer by-ref into Phases 2+4 — eliminates the triple-relay-refetch. Both impls (prod `RelayActorSyncDriver` reconnect.rs:214, test `MockSyncDriver` hours_offline.rs:2513) genuinely consume the buffer. `sender_key_reacquire` re-feeds via `supervisor.deliver_commit_blob` (idempotent re-delivery). Clean trait evolution, all impls updated.

- **queue_drain is HONESTLY documented as no-op end-to-end** (reconnect.rs:469-491): doc states all 3 bridges call `reconnect_contexts_no_drain` (drain callback=None), AND the producer `store::queue::enqueue_message` has no production caller, so nothing to drain. Follow-up scope (wire offline-enqueue producer) is explicit. This is the corrected version of the earlier [[ticket-1540-reconnection-driver]] FINDING about the dormant Phase-6 queue drain — now the doc no longer overstates.

- **DrainEquivocationAlerts** (commands.rs:278, MessagingCommand): distinct mailbox message, NOT overloading total `DrainEvents`. Rationale documented: total drain would silently discard application traffic (messages/MemberJoined) buffered during catch-up. `ReceiveBuffer::drain_equivocation_alerts` (membership.rs:1021) is a non-destructive partition that explicitly PRESERVES `dropped_since_last_consume` overflow counter (pulling alerts ≠ consumer consumption). Correct mailbox granularity + state encapsulation; buffer lives in PerContextState behind actor (ADR-049 invariant respected). Driver reaches it via Supervisor::drain_equivocation_alerts (supervisor.rs:5810), never directly.

- **ContextEvent::EquivocationDetected roots fields** (membership.rs:757): added `local_merkle_root: [u8;32]` + `remote_merkle_root: [u8;32]` to EXISTING variant (variant itself predates #1540). Struct-variant field addition — all match sites use `{ .. }` so backward-compatible (webhook.rs:657, state.rs:1393). Emit site (queries_helpers.rs:917 `record_equivocation_if_fresh`) populates REAL roots (not zeros), persists forensic payload to event log, idempotent replay defense keyed `(event_count, timestamp)` per remote sender DID. No DOA.

- **append_context_event_with_payload** (builder.rs:193): DEFAULT trait method delegating to pre-existing `append_event(.., payload: Option<&Value>)`. No impl updates needed — cleanest possible evolution.

- **Integration checklist satisfied:** context_reconnect exported PyO3/UniFFI/NAPI + 4 SDK wrappers; capability-matrix + bridge-aliases updated with documented WASM exemption (ADR-034: no Supervisor/tokio/relay-QUERY in WASM; WASM reconnects via JS-driven context_decrypt_message path). Matches [[lesson_capability_matrix_exemptions_required]] pattern.

- **Issue-number hygiene clean:** no `#1216/#1534/#1535/#1540` in crates/bindings/scripts source; §-spec (§9.9.3, §23.x) and ADR refs preserved. This was a known prior gap on the sibling ticket — now fixed.
