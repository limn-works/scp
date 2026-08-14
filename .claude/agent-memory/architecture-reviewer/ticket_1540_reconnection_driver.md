---
name: ticket-1540-reconnection-driver
description: #1540 reconnection driver at FFI/SDK layer (RelayActorSyncDriver), ADR-029 addendum reconciling ReconnectionCoordinator with ADR-049 actor model; verified facts + the Phase-6 queue-drain dormancy and issue-ref-in-code findings
metadata:
  type: project
---

#1540 placed the reconnection driver (`RelayActorSyncDriver` in `crates/scp-ffi/common/src/reconnect.rs`) at the FFI/SDK layer, composing `TransportManager` (relay retrieval) + actor `Supervisor` (state via mailbox). Recorded as an ADR-029 addendum in `.docs/adrs/phase-6.md:1620`.

**Why:** ADR-049 made the actor's `ContextTransportProvider` send-only; buffered-message retrieval is owned by `TransportManager` at the relay-client layer. So the driver must live at the FFI layer, same as `context_subscribe`.

**Verified-correct facts (architecture sound):**
- Driver reaches actor state ONLY via Supervisor passthroughs (local_mls_epoch, needs_reconnect, build_local_checkpoint, compare_remote_checkpoint, clear_needs_reconnect, issue_mls_update, deliver_commit_blob) — never widens the transport provider. No DOA widening.
- New actor commands have correct mailbox granularity: queries (LocalMlsEpoch/NeedsReconnect) read-only; lifecycle (ClearNeedsReconnect/IssueMlsUpdate) and messaging (BuildLocalCheckpoint/CompareRemoteCheckpoint) mutating, each with soft-default unknown-context fallthrough + ack_not_impl legacy guards.
- `ConsistencyCheckpoint` UNIFIED: the scp-protocol duplicate struct + pure `compare_checkpoints` free fn (carried the #1216 `epoch is None ⇒ FullyCaughtUp` defect) DELETED; sync/mod.rs now `pub use scp_event_log::checkpoint::ConsistencyCheckpoint`. Runtime `compare_remote_checkpoint` is the single comparison path; keys equivocation strictly on equal-count-different-root (§9.9.3) with membership+signature guards first. scp-protocol still compiles wasm32 (verified).
- `send_checkpoint` is `pub fn` BUT in `pub(crate) mod messaging_helpers` ⇒ effectively crate-private. `BuildLocalCheckpoint` builds+broadcasts inside one actor turn so the FFI driver never needs it cross-crate. The `[cross-layer: pub-crate-visibility] send_checkpoint` exemption (check-cross-layer.sh syntactic pub-fn scan can't see the pub(crate) mod) is LEGITIMATE.
- deviation (b) build+broadcast-in-actor-turn: SOUND.
- All 4 SDK wrappers + capability matrix entry + bridge-aliases (3 bridges + WASM exemption w/ ADR-034 reason) present. Pipeline assertions are REAL call-site (`fn_body_contains`), not dead string searches.

**Findings (CHANGES-NEEDED):**
1. **Phase-6 queue drain is dormant in ALL THREE bridges** — PyO3/NAPI/UniFFI all call `reconnect_contexts_no_drain` (drain=None ⇒ queue_drain hook returns (0,0)). `ReconnectionCoordinator::drain_context_queue` exists and is real, but NO bridge calls it. Root cause: `enqueue_message` (store/queue.rs) has ZERO production callers — the offline-send-enqueue PRODUCER was never wired (pre-existing ADR-029 gap, phase-6.md:1289 `queue/{context_id}/{seq:020d}`). So deviation (a) is architecturally OK for what exists, BUT reconnect.rs doc comment OVERSTATES reality ("bridge surface drains it directly via ReconnectionCoordinator::drain_context_queue after execute returns") — no bridge does. Phase 6 is wired-but-unreachable. Per CLAUDE.md no-deferral, the missing enqueue producer is a completeness gap to own or explicitly scope.
2. **Issue numbers in source comments** — #1540/#1535/#1534/#1216 appear in reconnect.rs, supervisor.rs, queries_helpers.rs, commands.rs, bridge context.rs, pipeline_wiring.rs doc/line comments. Violates project rule [[feedback-no-issue-refs-in-code]] (PR/commit only). Mechanical fix.

**Minor:** `Behind` arm carries "#1535 owns the fetch+proof" deferral comment — but the `Behind` behavior itself is unchanged/complete from pre-#1540; only the comment is new. Acceptable as a named seam EXCEPT for the embedded issue ref (finding 2).
