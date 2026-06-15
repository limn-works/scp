---
name: project-1533-heartbeat-loop
description: "#1533 close heartbeat send/recv loop — bridge live-subscribe-loop reality (only napi has one), corrected send-side design, seam map"
metadata:
  type: project
---

# #1533 — Close the heartbeat send/receive loop

Branch `feat/1533-heartbeat-loop` off origin/main `53b6f1d47` (worktree). Issue #1533 = HeartbeatMonitor (`crates/scp-transport/src/heartbeat.rs`) built but `record_heartbeat_received` had ZERO prod callers + no heartbeat ever sent.

**Why:** spec §9.9.2 (`.docs/specs/09-security-model.md:787`) "the SDK SHOULD send periodic heartbeat envelopes" — suppression detection defense.

**How to apply:** when wiring transport-lifecycle features into bridges, FIRST verify which bridges actually have the lifecycle hook. Do not assume symmetry.

## CRITICAL bridge-subscribe reality (verified, contradicts task premise)
The task assumed napi+pyo3+uniffi all have a live relay subscribe loop to attach the periodic heartbeat scheduler + `record_heartbeat_received`. THEY DO NOT:
- **napi** (`crates/scp-ffi/napi/src/context.rs:1224 context_subscribe_on`): ONLY bridge with a live `transport_mgr.subscribe(...)` + `TransportEvent::Envelope` + `MessagingCommand::DeliverIncoming` loop. Suppression-drain task lifecycle precedent: `spawn_suppression_scoring_task` (at transport_connect, NOT subscribe).
- **pyo3**: NO live relay subscribe loop. Receives via `PyMessageReceiver` draining actor buffer (`drain_and_deliver`) + relay ingestion through `scp_ffi_common::reconnect` driver. No per-context live loop to host a scheduler.
- **uniffi** (`crates/scp-ffi/uniffi/src/bridge.rs:9387 context_subscribe`): STUB — calls `listener.on_complete()` immediately; comment "full transport wiring connects this listener to the message pipeline in integration stories." Capability matrix: swift subscribe=false (exemption "not yet exposed as public API"). kotlin/python subscribe=true = the *recv API exists*, NOT a live relay loop.
- **wasm**: ADR-034 constrained, no native subscribe/custody.

So the periodic heartbeat SEND scheduler + `record_heartbeat_received` call can only attach to the napi live loop. pyo3/uniffi/wasm get the core/command surface + (uniffi) trait method, but no scheduler until their live-subscribe transport loops exist (separate, deferred work).

## Send-side corrected design (task §"CORRECTED DESIGN" — actor has NO signer)
ActorDeps.key_resolver = PUBLIC keys only; KeyCustody signer not mailbox-addressable (`actor/state.rs:991` "caller signs outside the actor"). So periodic SEND originates at bridge subscribe path (holds signing_key/custody), routed through a `SendHeartbeat` actor command (key passed per-call like SendMessage). NOT an actor-internal timer.

## Seam map (verified line anchors at base 53b6f1d47)
- Core helper: `send_heartbeat` mirrors `send_checkpoint` (`crates/scp-runtime/src/context/messaging_helpers.rs:1294`). EMPTY payload, sequence=0, `MessageType::Heartbeat`, broadcast-vs-encrypted routing identical, best-effort. `send_checkpoint` takes `&PerContextState` (immutable).
- `deliver_incoming` (`messaging_helpers.rs:1002`) returns `Result<Option<(Vec<u8>,String)>>`; ConsistencyCheckpoint dispatched at :1084 BEFORE sequence tracker → returns Ok(None). Heartbeat must classify in the SAME spot. Refactor return → `DeliverOutcome { Application((Vec<u8>,String)), Heartbeat, Handled }`.
- Blast radius of return change: `handle_deliver_incoming` + `DeliverIncomingReply` (`actor/handlers/messaging.rs:272`, `actor/commands.rs:59`), `Supervisor::deliver_commit_blob` (`supervisor/supervisor.rs:5620`), napi loop (`context.rs:1495`). reconnect driver in scp-ffi-common uses deliver_commit_blob.
- MessageType enum (`crates/scp-protocol/src/envelope/inner/mod.rs:38`): Content=0..ConsistencyCheckpoint=4 (highest). `as_discriminator_byte` :82 exhaustive. RESERVE Heartbeat=5.
- Command pattern: `SendMessagePayload`/`SigningKeyBytes` (`actor/commands.rs:129,457`); `handle_send_pseudonym_announcement` (`actor/handlers/messaging.rs:360`) = closest analog (signing key, no payload). Supervisor wrapper precedent: `send_message` (`supervisor.rs:6389`).
- Transport: `TransportAdapter` trait (`crates/scp-transport/src/traits.rs:162`) — add `record_heartbeat_received` default no-op + Box blanket impl (:250). `NativeRelayAdapter::record_heartbeat_received` already exists (`native/adapter.rs:371`). Manager forwarder fans out to all adapters (delete/unsubscribe pattern, `manager.rs:702`).
- Per-profile interval: reuse `maybe_start_heartbeat` mapping (`native/adapter.rs:248`): Server/Desktop 60s, Mobile 120s, Constrained OFF.
- Pipeline: existing `b3_heartbeat_monitor_instantiated` (`pipeline_wiring.rs:1124`). ADD `b3_heartbeat_send_receive_loop_wired` (do NOT weaken existing).
